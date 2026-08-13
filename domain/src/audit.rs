use std::{error::Error, fmt, str::FromStr};

use time::OffsetDateTime;

use crate::{
    AuditEventId, AuditOperationId, CredentialId, DeploymentPosture, EndpointAddress, EndpointId,
    PrincipalId,
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
    ///
    /// `System` names automated product activity, `LocalOperator` names the
    /// local user at the product console, and `User` names a signed-in
    /// product principal (§16). A `User`-actor event always carries the
    /// acting principal's identity in the audit context, and the
    /// `audit_events` schema pairs the two with a CHECK constraint, so the
    /// actor category and the principal id cannot drift apart.
    pub enum AuditActor for "actor" {
        System => "system",
        LocalOperator => "local-operator",
        User => "user",
    }
}

stable_audit_codes! {
    /// A product permission checked before the audited action.
    ///
    /// `ExecuteOperations` is the permission checked before a persisted
    /// [`Operation`](crate::Operation) is executed (§13.1). It is distinct
    /// from `ManageEndpoints` and `RefreshEndpoints` because §16.1 grants
    /// device-operation execution to roles that cannot manage endpoints or
    /// credentials; an audit record must show which product activity was
    /// authorized, not a closest-sounding neighbor.
    pub enum ProductPermission for "product permission" {
        ManageEndpoints => "manage-endpoints",
        RefreshEndpoints => "refresh-endpoints",
        ExecuteOperations => "execute-operations",
        ManageCredentials => "manage-credentials",
        ManageUsers => "manage-users",
        ManageBackups => "manage-backups",
        ManageSiteSettings => "manage-site-settings",
        // The 0.7.0 center console permissions (audit follow-up F3): binding
        // management (register/revoke — Administrator only, §16.1) and
        // center operation dispatch (Administrator and Operator).
        ManageCenterBindings => "manage-center-bindings",
        DispatchCenterOperations => "dispatch-center-operations",
        // The authentication lifecycle permission behind sign-in, sign-out,
        // and password changes (§16.2): those actions are authorized by
        // presenting valid credentials, not by a product role, and the
        // audit record must be able to name the authorization it observed.
        Authenticate => "authenticate",
    }
}

stable_audit_codes! {
    /// A stable product action represented by an audit operation.
    ///
    /// `ExecuteOperation` covers every execution of a persisted
    /// [`Operation`](crate::Operation) (§13.1): the audited action is the
    /// execution itself, and the typed [`AuditRedfishOperation`] recorded
    /// beside it names the §7.5 write family the execution dispatched.
    /// Keeping the write executions a separate action from the discovery
    /// actions — `EnrollEndpoint`, `RefreshEndpoint`, `ImportEndpoints` — is
    /// the §16.3 accountability point: a viewer must be able to distinguish
    /// an action that only reads from one that changes the managed endpoint.
    pub enum AuditAction for "action" {
        EnrollEndpoint => "enroll-endpoint",
        RefreshEndpoint => "refresh-endpoint",
        ImportEndpoints => "import-endpoints",
        ExecuteOperation => "execute-operation",
        Login => "login",
        Logout => "logout",
        ChangePassword => "change-password",
        ManageUsers => "manage-users",
        ManageSessions => "manage-sessions",
        ManageTotp => "manage-totp",
        ManageBackups => "manage-backups",
        ManageSettings => "manage-settings",
        // The 0.7.0 center console actions (audit follow-up F3): registering
        // one site's binding (which issues the one-time binding code),
        // revoking one site's binding, and dispatching one §15.6 operation
        // offer to a bound site. The dispatch is a separate action from the
        // edge's `ExecuteOperation` because the center never executes
        // anything — it offers, and the site decides (§15.6).
        RegisterSiteBinding => "register-site-binding",
        RevokeSiteBinding => "revoke-site-binding",
        DispatchCenterOperation => "dispatch-center-operation",
    }
}

impl AuditAction {
    /// Whether the action names a subject distinct from its actor (S3-4).
    ///
    /// `ChangePassword` names the principal whose credential the action
    /// changes — the administrator-issued password set records the user
    /// whose credential was replaced — and is the only action of the
    /// current vocabulary that may carry a target principal
    /// (`AuditOperationContext::with_target_principal`). The `audit_events`
    /// schema CHECK (`ck_audit_events_target_principal`) pins the same rule
    /// on persisted rows, and the persistence read-back treats a stored
    /// target under any other action as corrupt.
    #[must_use]
    pub const fn names_distinct_target_principal(self) -> bool {
        matches!(self, Self::ChangePassword)
    }
}

stable_audit_codes! {
    /// The public typed Redfish operation used by a product action.
    ///
    /// The write operations mirror the §7.5 command families compiled in
    /// [`crate::RedfishCommand`], with the same granularity decisions. The
    /// three reset families are independent variants because they target
    /// different CSDL resources whose action sets diverge — the decision
    /// that also keeps [`crate::SystemCommand::Reset`],
    /// [`crate::ManagerCommand::Reset`], and [`crate::ChassisCommand::Reset`]
    /// separate. The three Secure Boot writes are separate because their
    /// accountability differs: enabling Secure Boot, disabling it, and
    /// resetting its key sets are materially different security-relevant
    /// actions an audit reader must not conflate. Creating and deleting an
    /// event subscription are separate for the same reason: one adds a
    /// delivery target, the other removes one.
    ///
    /// `PollRemoteTask` names the Task-resource polling that a write
    /// returning `202 Accepted` starts (§13.6). Polling is a Redfish
    /// operation of its own even though it never changes a resource, so the
    /// vocabulary must be able to name it when a monitor-recorded audit fact
    /// describes the poll.
    ///
    /// `UpdateFirmware` names the §14.3 firmware update submission: the
    /// operation that uploads a previously validated artifact to the target
    /// `UpdateService`. It is the audit name of the
    /// [`UpdateCommand::StartUpdate`](crate::UpdateCommand::StartUpdate)
    /// write family, so an audit reader can distinguish a firmware submission
    /// from every other §7.5 write.
    ///
    /// The five account writes are separate because their accountability
    /// differs: creating an account, changing its role, changing its
    /// password, renaming it, and deleting it are materially different
    /// security-relevant actions an audit reader must not conflate — the
    /// same granularity decision that keeps the Secure Boot writes separate.
    ///
    /// `ManagerResetToDefaults` is separate from `ResetManager` for the same
    /// reason the three reset families are separate: a factory-defaults
    /// wipe is materially different from a restart, and an audit reader
    /// must not conflate them. `PowerSupplyReset` names the power-supply
    /// reset behind the `Chassis` family. `LogClear` names the log-service
    /// clear, `ControlUpdate` the control write, and `UpdateServicePatch`
    /// the `UpdateService` property patch — the patch is separate from
    /// `UpdateFirmware` because patching the service configuration and
    /// submitting firmware are materially different actions.
    ///
    /// The seven telemetry writes are separate for the same reason: enabling
    /// or disabling the telemetry service, creating, updating, or deleting a
    /// metric definition, and creating, updating, or deleting a metric report
    /// definition are materially different actions an audit reader must not
    /// conflate — the same granularity decision that keeps the account writes
    /// separate.
    pub enum AuditRedfishOperation for "Redfish operation" {
        None => "none",
        ProbeCoreCapabilities => "probe-core-capabilities",
        ReadCoreResources => "read-core-resources",
        CreateAccount => "create-account",
        UpdateAccount => "update-account",
        UpdateAccountPassword => "update-account-password",
        UpdateAccountUserName => "update-account-user-name",
        DeleteAccount => "delete-account",
        ResetSystem => "reset-system",
        ResetManager => "reset-manager",
        ManagerResetToDefaults => "manager-reset-to-defaults",
        ResetChassis => "reset-chassis",
        PowerSupplyReset => "power-supply-reset",
        SetBootSourceOverride => "set-boot-source-override",
        SecureBootEnable => "secure-boot-enable",
        SecureBootDisable => "secure-boot-disable",
        SecureBootResetKeys => "secure-boot-reset-keys",
        CreateEventSubscription => "create-event-subscription",
        DeleteEventSubscription => "delete-event-subscription",
        LogClear => "log-clear",
        ControlUpdate => "control-update",
        SetTelemetryEnabled => "set-telemetry-enabled",
        CreateMetricDefinition => "create-metric-definition",
        UpdateMetricDefinition => "update-metric-definition",
        DeleteMetricDefinition => "delete-metric-definition",
        CreateMetricReportDefinition => "create-metric-report-definition",
        UpdateMetricReportDefinition => "update-metric-report-definition",
        DeleteMetricReportDefinition => "delete-metric-report-definition",
        UpdateFirmware => "update-firmware",
        UpdateServicePatch => "update-service-patch",
        OemSystemConfigProfile => "oem-system-config-profile",
        OemDebugToken => "oem-debug-token",
        OemPowerSmoothing => "oem-power-smoothing",
        PollRemoteTask => "poll-remote-task",
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
        EndpointImportRowFailed => "endpoint-import-row-failed",
        // The 0.7.0 center console failures (audit follow-up F3): a center
        // write could not be completed because the center store failed, and
        // a §15.6 dispatch was refused by the center (unknown endpoint,
        // endpoint outside the site, unknown target, undecodable command,
        // or the persisted role re-check).
        CenterStoreFailed => "center-store-failed",
        CenterRequestRefused => "center-request-refused",
        // A sign-in attempt failed: an unknown or disabled principal, a
        // wrong password, a wrong or replayed TOTP code, or a rate-limited
        // refusal (§16.2 "登录失败限速").
        AuthenticationFailed => "authentication-failed",
        // A password change or administrator-issued password set succeeded,
        // but the mandatory §16.2 session revocation failed — the change is
        // not rolled back, and the audit records which step actually failed
        // (B3, security batch). `AuthenticationFailed` would name the wrong
        // fact: the presented credential was accepted; the revocation of
        // the old sessions is the step that failed.
        SessionRevocationFailed => "session-revocation-failed",
        // The §13.3 step 2 capability pre-flight proved the endpoint cannot
        // serve the write: the required capability is not compiled, not
        // advertised, schema-incompatible, or read-only. The refusal is a
        // fact about the endpoint's capability, not about redfish
        // discovery, so it is audited under its own kind (audit follow-up
        // E3-4), mirroring the `FailureKind::CapabilityUnsupported`
        // classification of the same refusal.
        CapabilityUnsupported => "capability-unsupported",
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
    actor_principal_id: Option<PrincipalId>,
    /// The principal a `User`-actor action changes, when the action names a
    /// subject distinct from the actor (S3-4): the administrator-issued
    /// password set records the user whose credential it replaced.
    target_principal_id: Option<PrincipalId>,
}

impl AuditOperationContext {
    /// Creates one semantically consistent audit operation context for a
    /// non-principal actor.
    ///
    /// This is the pre-0.6 constructor surface: the actor is `System` or
    /// `LocalOperator`, so the context carries no principal identity. It is
    /// exactly [`AuditOperationContext::try_new_with_actor_principal`] with a
    /// `None` principal, which the consistency rule therefore refuses for a
    /// `User` actor.
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
        Self::try_new_with_actor_principal(
            operation_id,
            actor,
            origin,
            target,
            parameters,
            permission,
            action,
            redfish_operation,
            None,
        )
    }

    /// Creates one semantically consistent audit operation context.
    ///
    /// The accepted combinations are exactly the pairs of a product action
    /// and its typed Redfish operation. The check is an exhaustive match on
    /// the operation type, so adding an operation type fails to compile
    /// until its action is decided here — the §7.5 exhaustiveness rule
    /// applied to the audit vocabulary.
    ///
    /// A `User` actor must name the acting principal (and the schema CHECK
    /// pins the same rule), so a `User` actor with `None`, or any other actor
    /// with `Some`, is refused with [`AuditOperationContextError`].
    ///
    /// An execution context — [`AuditAction::ExecuteOperation`] with a §7.5
    /// write operation type or [`AuditRedfishOperation::PollRemoteTask`] —
    /// targets the endpoint that receives the write and checks
    /// [`ProductPermission::ExecuteOperations`]. Its parameter summary stays
    /// [`AuditParameterSummary::EndpointRefresh`] for this iteration: the
    /// summary vocabulary is projected per-variant by the persistence crate,
    /// which is not extended here, so `EndpointRefresh` is the closest legal
    /// summary until an operation-scoped summary lands together with its
    /// persistence projection. The permission, action, and operation-type
    /// fields are truthful.
    ///
    /// # Errors
    ///
    /// Returns [`AuditOperationContextError`] when the target, parameter
    /// summary, permission, typed Redfish operation, or the actor's
    /// principal identity does not match the product action.
    //
    // The consistency matrix grows with the §7.5 operation vocabulary, so
    // the line budget is exceeded by the family count, not by a design
    // choice; the lint is scoped here like the argument count above.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    pub fn try_new_with_actor_principal(
        operation_id: AuditOperationId,
        actor: AuditActor,
        origin: DeploymentPosture,
        target: AuditTarget,
        parameters: AuditParameterSummary,
        permission: ProductPermission,
        action: AuditAction,
        redfish_operation: AuditRedfishOperation,
        actor_principal_id: Option<PrincipalId>,
    ) -> Result<Self, AuditOperationContextError> {
        if (actor == AuditActor::User) != actor_principal_id.is_some() {
            return Err(AuditOperationContextError);
        }
        let consistent = match redfish_operation {
            // Enrollment probes the capabilities of the endpoint address.
            AuditRedfishOperation::ProbeCoreCapabilities => matches!(
                (&target, parameters, permission, action),
                (
                    AuditTarget::EndpointAddress(_),
                    AuditParameterSummary::EndpointEnrollment { .. },
                    ProductPermission::ManageEndpoints,
                    AuditAction::EnrollEndpoint,
                )
            ),
            // Refresh reads the core resources of the managed endpoint.
            AuditRedfishOperation::ReadCoreResources => matches!(
                (&target, parameters, permission, action),
                (
                    AuditTarget::Endpoint(_),
                    AuditParameterSummary::EndpointRefresh,
                    ProductPermission::RefreshEndpoints,
                    AuditAction::RefreshEndpoint,
                )
            ),
            // A CSV import changes no Redfish resource at all.
            AuditRedfishOperation::None => matches!(
                (&target, parameters, permission, action),
                (
                    AuditTarget::Product,
                    AuditParameterSummary::CsvEndpointImport { .. },
                    ProductPermission::ManageEndpoints,
                    AuditAction::ImportEndpoints,
                ) | (
                    // The §16.2 authentication lifecycle: sign-in, sign-out,
                    // and password changes are authorized by presenting
                    // credentials (the `Authenticate` permission), never by a
                    // product role. The parameter summary stays the closest
                    // legal shape — every authentication event has no
                    // credential, trust, or row-count columns, exactly like
                    // `EndpointRefresh` — so the summary vocabulary is not
                    // extended for them.
                    AuditTarget::Product,
                    AuditParameterSummary::EndpointRefresh,
                    ProductPermission::Authenticate,
                    AuditAction::Login | AuditAction::Logout | AuditAction::ChangePassword,
                ) | (
                    // The §16.1 user-management actions. Session and TOTP
                    // management are part of account administration, so they
                    // share the `ManageUsers` permission: an auditor reading
                    // the event sees which user-administration domain was
                    // touched, not a closest-sounding neighbor.
                    AuditTarget::Product,
                    AuditParameterSummary::EndpointRefresh,
                    ProductPermission::ManageUsers,
                    AuditAction::ManageUsers
                        | AuditAction::ManageSessions
                        | AuditAction::ManageTotp,
                ) | (
                    AuditTarget::Product,
                    AuditParameterSummary::EndpointRefresh,
                    ProductPermission::ManageBackups,
                    AuditAction::ManageBackups,
                ) | (
                    AuditTarget::Product,
                    AuditParameterSummary::EndpointRefresh,
                    ProductPermission::ManageSiteSettings,
                    AuditAction::ManageSettings,
                ) | (
                    // The 0.7.0 center console binding management (audit
                    // follow-up F3): registering one site issues its
                    // one-time binding code, revoking one site's binding
                    // ends its access — both are center-wide actions with
                    // no endpoint target and no Redfish operation.
                    AuditTarget::Product,
                    AuditParameterSummary::EndpointRefresh,
                    ProductPermission::ManageCenterBindings,
                    AuditAction::RegisterSiteBinding | AuditAction::RevokeSiteBinding,
                ) | (
                    // The §15.6 center dispatch: the offer targets the
                    // projected endpoint that receives the command on the
                    // site, exactly like the edge's `ExecuteOperation`
                    // targets the managed endpoint. The parameter summary
                    // stays the closest legal shape — the center dispatches
                    // a typed command and the summary vocabulary is
                    // projected per-variant by the persistence crate, which
                    // is not extended here.
                    AuditTarget::Endpoint(_),
                    AuditParameterSummary::EndpointRefresh,
                    ProductPermission::DispatchCenterOperations,
                    AuditAction::DispatchCenterOperation,
                )
            ),
            // Every §7.5 write family and the §13.6 remote-task polling is
            // the execution of one persisted operation against the managed
            // endpoint that receives the request.
            AuditRedfishOperation::CreateAccount
            | AuditRedfishOperation::UpdateAccount
            | AuditRedfishOperation::UpdateAccountPassword
            | AuditRedfishOperation::UpdateAccountUserName
            | AuditRedfishOperation::DeleteAccount
            | AuditRedfishOperation::ResetSystem
            | AuditRedfishOperation::ResetManager
            | AuditRedfishOperation::ManagerResetToDefaults
            | AuditRedfishOperation::ResetChassis
            | AuditRedfishOperation::PowerSupplyReset
            | AuditRedfishOperation::SetBootSourceOverride
            | AuditRedfishOperation::SecureBootEnable
            | AuditRedfishOperation::SecureBootDisable
            | AuditRedfishOperation::SecureBootResetKeys
            | AuditRedfishOperation::CreateEventSubscription
            | AuditRedfishOperation::DeleteEventSubscription
            | AuditRedfishOperation::LogClear
            | AuditRedfishOperation::ControlUpdate
            | AuditRedfishOperation::SetTelemetryEnabled
            | AuditRedfishOperation::CreateMetricDefinition
            | AuditRedfishOperation::UpdateMetricDefinition
            | AuditRedfishOperation::DeleteMetricDefinition
            | AuditRedfishOperation::CreateMetricReportDefinition
            | AuditRedfishOperation::UpdateMetricReportDefinition
            | AuditRedfishOperation::DeleteMetricReportDefinition
            | AuditRedfishOperation::UpdateFirmware
            | AuditRedfishOperation::UpdateServicePatch
            | AuditRedfishOperation::OemSystemConfigProfile
            | AuditRedfishOperation::OemDebugToken
            | AuditRedfishOperation::OemPowerSmoothing
            | AuditRedfishOperation::PollRemoteTask => matches!(
                (&target, parameters, permission, action),
                (
                    AuditTarget::Endpoint(_),
                    AuditParameterSummary::EndpointRefresh,
                    ProductPermission::ExecuteOperations,
                    AuditAction::ExecuteOperation,
                )
            ),
        };
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
            actor_principal_id,
            target_principal_id: None,
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

    /// Returns the acting principal, when the actor is a product user.
    ///
    /// The value is `Some` exactly when the actor is [`AuditActor::User`];
    /// the schema CHECK constraint pins the same rule on persisted rows.
    #[must_use]
    pub const fn actor_principal_id(&self) -> Option<PrincipalId> {
        self.actor_principal_id
    }

    /// Names the principal a `User`-actor action changes (S3-4).
    ///
    /// The administrator-issued password set is audited under the acting
    /// administrator as actor and the user whose credential was replaced as
    /// the target — an audit reader must see both who acted and who the
    /// action was about. The value is `None` for every other action of the
    /// current vocabulary: it is attached by the web handler at the one
    /// site that names a distinct subject, after the constructor's
    /// consistency matrix has checked the action shape.
    ///
    /// # The shape contract
    ///
    /// Only an action where [`AuditAction::names_distinct_target_principal`]
    /// is true — [`AuditAction::ChangePassword`], the one S3-4 action of the
    /// current vocabulary — may carry a target principal. The method stays
    /// infallible because its only production caller attaches the target
    /// exactly at that one action; the `audit_events` schema CHECK
    /// (`ck_audit_events_target_principal`) refuses any persisted row that
    /// attaches one elsewhere, and the persistence read-back treats such a
    /// stored row as corrupt.
    #[must_use]
    pub fn with_target_principal(mut self, target_principal_id: PrincipalId) -> Self {
        self.target_principal_id = Some(target_principal_id);
        self
    }

    /// Returns the principal the action changes, when the action names one.
    #[must_use]
    pub const fn target_principal_id(&self) -> Option<PrincipalId> {
        self.target_principal_id
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

impl fmt::Display for AuditSequence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
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

    // The pinned vocabulary pairs grow with every added operation code, so
    // the line-count lint is scoped here like the family enumeration tests.
    #[allow(clippy::too_many_lines)]
    #[test]
    fn stable_vocabularies_round_trip_without_dynamic_text() {
        assert_codes(&[
            AuditActor::System,
            AuditActor::LocalOperator,
            AuditActor::User,
        ]);
        assert_codes(&[
            ProductPermission::ManageEndpoints,
            ProductPermission::RefreshEndpoints,
            ProductPermission::ExecuteOperations,
            ProductPermission::ManageCredentials,
            ProductPermission::ManageUsers,
            ProductPermission::ManageBackups,
            ProductPermission::ManageSiteSettings,
            ProductPermission::Authenticate,
        ]);
        assert_codes(&[
            AuditAction::EnrollEndpoint,
            AuditAction::RefreshEndpoint,
            AuditAction::ImportEndpoints,
            AuditAction::ExecuteOperation,
            AuditAction::Login,
            AuditAction::Logout,
            AuditAction::ChangePassword,
            AuditAction::ManageUsers,
            AuditAction::ManageSessions,
            AuditAction::ManageTotp,
            AuditAction::ManageBackups,
            AuditAction::ManageSettings,
        ]);
        assert_codes(&[
            AuditRedfishOperation::None,
            AuditRedfishOperation::ProbeCoreCapabilities,
            AuditRedfishOperation::ReadCoreResources,
            AuditRedfishOperation::CreateAccount,
            AuditRedfishOperation::UpdateAccount,
            AuditRedfishOperation::UpdateAccountPassword,
            AuditRedfishOperation::UpdateAccountUserName,
            AuditRedfishOperation::DeleteAccount,
            AuditRedfishOperation::ResetSystem,
            AuditRedfishOperation::ResetManager,
            AuditRedfishOperation::ManagerResetToDefaults,
            AuditRedfishOperation::ResetChassis,
            AuditRedfishOperation::PowerSupplyReset,
            AuditRedfishOperation::SetBootSourceOverride,
            AuditRedfishOperation::SecureBootEnable,
            AuditRedfishOperation::SecureBootDisable,
            AuditRedfishOperation::SecureBootResetKeys,
            AuditRedfishOperation::CreateEventSubscription,
            AuditRedfishOperation::DeleteEventSubscription,
            AuditRedfishOperation::LogClear,
            AuditRedfishOperation::ControlUpdate,
            AuditRedfishOperation::SetTelemetryEnabled,
            AuditRedfishOperation::CreateMetricDefinition,
            AuditRedfishOperation::UpdateMetricDefinition,
            AuditRedfishOperation::DeleteMetricDefinition,
            AuditRedfishOperation::CreateMetricReportDefinition,
            AuditRedfishOperation::UpdateMetricReportDefinition,
            AuditRedfishOperation::DeleteMetricReportDefinition,
            AuditRedfishOperation::UpdateFirmware,
            AuditRedfishOperation::UpdateServicePatch,
            AuditRedfishOperation::OemSystemConfigProfile,
            AuditRedfishOperation::OemDebugToken,
            AuditRedfishOperation::OemPowerSmoothing,
            AuditRedfishOperation::PollRemoteTask,
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
            AuditFailure::EndpointImportRowFailed,
            AuditFailure::AuthenticationFailed,
            AuditFailure::SessionRevocationFailed,
            AuditFailure::CapabilityUnsupported,
        ]);
        assert_eq!(
            "unknown".parse::<AuditAction>(),
            Err(AuditCodeParseError::new("action"))
        );
        assert_eq!(
            "unknown".parse::<AuditRedfishOperation>(),
            Err(AuditCodeParseError::new("Redfish operation"))
        );
        assert_eq!(
            "unknown".parse::<ProductPermission>(),
            Err(AuditCodeParseError::new("product permission"))
        );
    }

    #[test]
    fn new_execute_codes_are_pinned_as_the_stable_wire_contract() {
        // The round-trip test alone would not catch a renamed code: a code
        // that parses back to itself is consistent by definition. Persisted
        // audit rows keep the code they were written under, so the codes
        // added for operation execution are pinned as exact literals — the
        // same contract the §7.5 command vocabulary pins.
        for (operation, expected) in [
            (AuditRedfishOperation::CreateAccount, "create-account"),
            (AuditRedfishOperation::UpdateAccount, "update-account"),
            (
                AuditRedfishOperation::UpdateAccountPassword,
                "update-account-password",
            ),
            (
                AuditRedfishOperation::UpdateAccountUserName,
                "update-account-user-name",
            ),
            (AuditRedfishOperation::DeleteAccount, "delete-account"),
            (AuditRedfishOperation::ResetSystem, "reset-system"),
            (AuditRedfishOperation::ResetManager, "reset-manager"),
            (
                AuditRedfishOperation::ManagerResetToDefaults,
                "manager-reset-to-defaults",
            ),
            (AuditRedfishOperation::ResetChassis, "reset-chassis"),
            (
                AuditRedfishOperation::PowerSupplyReset,
                "power-supply-reset",
            ),
            (
                AuditRedfishOperation::SetBootSourceOverride,
                "set-boot-source-override",
            ),
            (
                AuditRedfishOperation::SecureBootEnable,
                "secure-boot-enable",
            ),
            (
                AuditRedfishOperation::SecureBootDisable,
                "secure-boot-disable",
            ),
            (
                AuditRedfishOperation::SecureBootResetKeys,
                "secure-boot-reset-keys",
            ),
            (
                AuditRedfishOperation::CreateEventSubscription,
                "create-event-subscription",
            ),
            (
                AuditRedfishOperation::DeleteEventSubscription,
                "delete-event-subscription",
            ),
            (AuditRedfishOperation::LogClear, "log-clear"),
            (AuditRedfishOperation::ControlUpdate, "control-update"),
            (
                AuditRedfishOperation::SetTelemetryEnabled,
                "set-telemetry-enabled",
            ),
            (
                AuditRedfishOperation::CreateMetricDefinition,
                "create-metric-definition",
            ),
            (
                AuditRedfishOperation::UpdateMetricDefinition,
                "update-metric-definition",
            ),
            (
                AuditRedfishOperation::DeleteMetricDefinition,
                "delete-metric-definition",
            ),
            (
                AuditRedfishOperation::CreateMetricReportDefinition,
                "create-metric-report-definition",
            ),
            (
                AuditRedfishOperation::UpdateMetricReportDefinition,
                "update-metric-report-definition",
            ),
            (
                AuditRedfishOperation::DeleteMetricReportDefinition,
                "delete-metric-report-definition",
            ),
            (
                AuditRedfishOperation::UpdateServicePatch,
                "update-service-patch",
            ),
            (AuditRedfishOperation::PollRemoteTask, "poll-remote-task"),
        ] {
            assert_eq!(operation.as_str(), expected);
            assert_eq!(expected.parse(), Ok(operation));
        }
        assert_eq!(AuditAction::ExecuteOperation.as_str(), "execute-operation");
        assert_eq!(
            "execute-operation".parse(),
            Ok(AuditAction::ExecuteOperation)
        );
        assert_eq!(
            ProductPermission::ExecuteOperations.as_str(),
            "execute-operations"
        );
        assert_eq!(
            "execute-operations".parse(),
            Ok(ProductPermission::ExecuteOperations)
        );
    }

    #[test]
    fn product_user_vocabulary_codes_are_pinned_as_the_stable_wire_contract() {
        // The same literal-pinning argument as the execute codes: persisted
        // rows keep the codes they were written under, so the codes added for
        // the product user milestone are pinned as exact literals.
        for (action, expected) in [
            (AuditAction::Login, "login"),
            (AuditAction::Logout, "logout"),
            (AuditAction::ChangePassword, "change-password"),
            (AuditAction::ManageUsers, "manage-users"),
            (AuditAction::ManageSessions, "manage-sessions"),
            (AuditAction::ManageTotp, "manage-totp"),
            (AuditAction::ManageBackups, "manage-backups"),
            (AuditAction::ManageSettings, "manage-settings"),
        ] {
            assert_eq!(action.as_str(), expected);
            assert_eq!(expected.parse(), Ok(action));
        }
        for (permission, expected) in [
            (ProductPermission::ManageCredentials, "manage-credentials"),
            (ProductPermission::ManageUsers, "manage-users"),
            (ProductPermission::ManageBackups, "manage-backups"),
            (
                ProductPermission::ManageSiteSettings,
                "manage-site-settings",
            ),
            (ProductPermission::Authenticate, "authenticate"),
        ] {
            assert_eq!(permission.as_str(), expected);
            assert_eq!(expected.parse(), Ok(permission));
        }
        let (failure, expected) = (AuditFailure::AuthenticationFailed, "authentication-failed");
        assert_eq!(failure.as_str(), expected);
        assert_eq!(expected.parse(), Ok(failure));
        let (failure, expected) = (
            AuditFailure::SessionRevocationFailed,
            "session-revocation-failed",
        );
        assert_eq!(failure.as_str(), expected);
        assert_eq!(expected.parse(), Ok(failure));
        assert_eq!(AuditActor::User.as_str(), "user");
        assert_eq!("user".parse(), Ok(AuditActor::User));
    }

    #[test]
    fn contexts_can_name_a_distinct_target_principal() -> Result<(), Box<dyn Error>> {
        // S3-4: the administrator-issued password set is audited under the
        // acting administrator as actor and the user whose credential was
        // replaced as the target, so an audit reader sees both who acted
        // and who the action was about.
        let actor = PrincipalId::generate();
        let target = PrincipalId::generate();
        let context = AuditOperationContext::try_new_with_actor_principal(
            AuditOperationId::generate(),
            AuditActor::User,
            DeploymentPosture::Site,
            AuditTarget::Product,
            AuditParameterSummary::EndpointRefresh,
            ProductPermission::Authenticate,
            AuditAction::ChangePassword,
            AuditRedfishOperation::None,
            Some(actor),
        )?;
        assert_eq!(
            context.target_principal_id(),
            None,
            "the constructor must not invent a target"
        );
        let context = context.with_target_principal(target);
        assert_eq!(context.actor_principal_id(), Some(actor));
        assert_eq!(context.target_principal_id(), Some(target));
        // The shape contract: only the action that names a subject distinct
        // from its actor may carry a target principal, and the schema CHECK
        // (`ck_audit_events_target_principal`) pins the same rule on
        // persisted rows, so the domain side names the one allowed action.
        assert!(context.action().names_distinct_target_principal());
        // The target is operation-level metadata: it rides every event of
        // the operation, started and terminal alike.
        let now = OffsetDateTime::now_utc();
        let started = AuditEvent::started(context.clone(), now);
        let terminal = AuditSequence::FIRST.next()?;
        let succeeded = AuditEvent::succeeded(context, terminal, now)?;
        assert_eq!(started.context().target_principal_id(), Some(target));
        assert_eq!(succeeded.context().target_principal_id(), Some(target));
        // A distinct target is never implied for an action that names no
        // subject distinct from its actor.
        let login = AuditOperationContext::try_new_with_actor_principal(
            AuditOperationId::generate(),
            AuditActor::User,
            DeploymentPosture::Site,
            AuditTarget::Product,
            AuditParameterSummary::EndpointRefresh,
            ProductPermission::Authenticate,
            AuditAction::Login,
            AuditRedfishOperation::None,
            Some(actor),
        )?;
        assert_eq!(login.target_principal_id(), None);
        assert!(!login.action().names_distinct_target_principal());
        for action in [
            AuditAction::EnrollEndpoint,
            AuditAction::ExecuteOperation,
            AuditAction::ManageUsers,
            AuditAction::RegisterSiteBinding,
        ] {
            assert!(
                !action.names_distinct_target_principal(),
                "{action} names no subject distinct from its actor"
            );
        }
        Ok(())
    }

    #[test]
    fn user_actor_contexts_bind_the_acting_principal() -> Result<(), Box<dyn Error>> {
        let principal_id = PrincipalId::generate();
        let principal_execution = |actor_principal_id| {
            AuditOperationContext::try_new_with_actor_principal(
                AuditOperationId::generate(),
                AuditActor::User,
                DeploymentPosture::Site,
                AuditTarget::Endpoint(EndpointId::generate()),
                AuditParameterSummary::EndpointRefresh,
                ProductPermission::ExecuteOperations,
                AuditAction::ExecuteOperation,
                AuditRedfishOperation::ResetSystem,
                actor_principal_id,
            )
        };
        let context = principal_execution(Some(principal_id))?;

        assert_eq!(context.actor(), AuditActor::User);
        assert_eq!(context.actor_principal_id(), Some(principal_id));
        assert_eq!(
            principal_execution(None),
            Err(AuditOperationContextError),
            "a User actor must name the acting principal"
        );
        assert_eq!(
            AuditOperationContext::try_new_with_actor_principal(
                AuditOperationId::generate(),
                AuditActor::System,
                DeploymentPosture::Site,
                AuditTarget::Endpoint(EndpointId::generate()),
                AuditParameterSummary::EndpointRefresh,
                ProductPermission::ExecuteOperations,
                AuditAction::ExecuteOperation,
                AuditRedfishOperation::ResetSystem,
                Some(principal_id),
            ),
            Err(AuditOperationContextError),
            "a non-User actor must not carry a principal identity"
        );
        // The user-vocabulary actions are constructible through the context
        // since the 0.6 authentication slice: the consistency matrix accepts
        // every product action whose shape the 0.6 schema CHECKs pin, and
        // the two are extended together.
        let management = AuditOperationContext::try_new_with_actor_principal(
            AuditOperationId::generate(),
            AuditActor::User,
            DeploymentPosture::Site,
            AuditTarget::Product,
            AuditParameterSummary::EndpointRefresh,
            ProductPermission::ManageUsers,
            AuditAction::ManageUsers,
            AuditRedfishOperation::None,
            Some(principal_id),
        )?;
        assert_eq!(management.action(), AuditAction::ManageUsers);
        assert_eq!(management.permission(), ProductPermission::ManageUsers);
        // The pre-0.6 constructor surface stays principal-free.
        let legacy = AuditOperationContext::try_new(
            AuditOperationId::generate(),
            AuditActor::System,
            DeploymentPosture::Site,
            AuditTarget::Product,
            AuditParameterSummary::csv_endpoint_import(1)?,
            ProductPermission::ManageEndpoints,
            AuditAction::ImportEndpoints,
            AuditRedfishOperation::None,
        )?;
        assert_eq!(legacy.actor_principal_id(), None);
        Ok(())
    }

    #[test]
    fn authentication_and_management_contexts_pin_their_shapes() -> Result<(), Box<dyn Error>> {
        // The §16.2 authentication lifecycle and the §16.1 user-management
        // actions are the 0.6 authentication slice's audit vocabulary: each
        // action constructs with exactly its permission, and a foreign
        // permission is refused so an audit record can never conflate the
        // authorization it observed.
        let principal_id = PrincipalId::generate();
        for (permission, action) in [
            (ProductPermission::Authenticate, AuditAction::Login),
            (ProductPermission::Authenticate, AuditAction::Logout),
            (ProductPermission::Authenticate, AuditAction::ChangePassword),
            (ProductPermission::ManageUsers, AuditAction::ManageUsers),
            (ProductPermission::ManageUsers, AuditAction::ManageSessions),
            (ProductPermission::ManageUsers, AuditAction::ManageTotp),
            (ProductPermission::ManageBackups, AuditAction::ManageBackups),
            (
                ProductPermission::ManageSiteSettings,
                AuditAction::ManageSettings,
            ),
        ] {
            let context = AuditOperationContext::try_new_with_actor_principal(
                AuditOperationId::generate(),
                AuditActor::User,
                DeploymentPosture::Site,
                AuditTarget::Product,
                AuditParameterSummary::EndpointRefresh,
                permission,
                action,
                AuditRedfishOperation::None,
                Some(principal_id),
            )?;
            assert_eq!(context.action(), action);
            assert_eq!(context.permission(), permission);
            assert!(matches!(context.target(), AuditTarget::Product));
            assert_eq!(context.redfish_operation(), AuditRedfishOperation::None);
        }
        // A management action under the wrong permission is refused.
        assert_eq!(
            AuditOperationContext::try_new_with_actor_principal(
                AuditOperationId::generate(),
                AuditActor::User,
                DeploymentPosture::Site,
                AuditTarget::Product,
                AuditParameterSummary::EndpointRefresh,
                ProductPermission::ManageUsers,
                AuditAction::Login,
                AuditRedfishOperation::None,
                Some(principal_id),
            ),
            Err(AuditOperationContextError)
        );
        assert_eq!(
            AuditOperationContext::try_new_with_actor_principal(
                AuditOperationId::generate(),
                AuditActor::User,
                DeploymentPosture::Site,
                AuditTarget::Product,
                AuditParameterSummary::EndpointRefresh,
                ProductPermission::Authenticate,
                AuditAction::ManageUsers,
                AuditRedfishOperation::None,
                Some(principal_id),
            ),
            Err(AuditOperationContextError)
        );
        // A write operation type never describes an authentication action.
        assert_eq!(
            AuditOperationContext::try_new_with_actor_principal(
                AuditOperationId::generate(),
                AuditActor::User,
                DeploymentPosture::Site,
                AuditTarget::Product,
                AuditParameterSummary::EndpointRefresh,
                ProductPermission::Authenticate,
                AuditAction::Login,
                AuditRedfishOperation::ResetSystem,
                Some(principal_id),
            ),
            Err(AuditOperationContextError)
        );
        Ok(())
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

    /// The §7.5 write operation types plus remote-task polling.
    ///
    /// Kept next to [`AuditOperationContext::try_new`]'s exhaustive check so
    /// the two lists stay reviewable together.
    const EXECUTE_OPERATIONS: [AuditRedfishOperation; 27] = [
        AuditRedfishOperation::CreateAccount,
        AuditRedfishOperation::UpdateAccount,
        AuditRedfishOperation::UpdateAccountPassword,
        AuditRedfishOperation::UpdateAccountUserName,
        AuditRedfishOperation::DeleteAccount,
        AuditRedfishOperation::ResetSystem,
        AuditRedfishOperation::ResetManager,
        AuditRedfishOperation::ManagerResetToDefaults,
        AuditRedfishOperation::ResetChassis,
        AuditRedfishOperation::PowerSupplyReset,
        AuditRedfishOperation::SetBootSourceOverride,
        AuditRedfishOperation::SecureBootEnable,
        AuditRedfishOperation::SecureBootDisable,
        AuditRedfishOperation::SecureBootResetKeys,
        AuditRedfishOperation::CreateEventSubscription,
        AuditRedfishOperation::DeleteEventSubscription,
        AuditRedfishOperation::LogClear,
        AuditRedfishOperation::ControlUpdate,
        AuditRedfishOperation::SetTelemetryEnabled,
        AuditRedfishOperation::CreateMetricDefinition,
        AuditRedfishOperation::UpdateMetricDefinition,
        AuditRedfishOperation::DeleteMetricDefinition,
        AuditRedfishOperation::CreateMetricReportDefinition,
        AuditRedfishOperation::UpdateMetricReportDefinition,
        AuditRedfishOperation::DeleteMetricReportDefinition,
        AuditRedfishOperation::UpdateServicePatch,
        AuditRedfishOperation::PollRemoteTask,
    ];

    #[test]
    fn execute_contexts_accept_every_write_operation_type() -> Result<(), Box<dyn Error>> {
        for operation in EXECUTE_OPERATIONS {
            let context = execute_context(operation)?;
            assert_eq!(context.action(), AuditAction::ExecuteOperation);
            assert_eq!(context.permission(), ProductPermission::ExecuteOperations);
            assert_eq!(context.redfish_operation(), operation);
            assert!(matches!(context.target(), AuditTarget::Endpoint(_)));
            assert!(matches!(
                context.parameters(),
                AuditParameterSummary::EndpointRefresh
            ));
        }
        Ok(())
    }

    #[test]
    fn execute_contexts_reject_metadata_describing_other_actions() -> Result<(), Box<dyn Error>> {
        // A write operation type is rejected when any other field still
        // describes the action it used to borrow from.
        for (permission, action, operation) in [
            (
                ProductPermission::RefreshEndpoints,
                AuditAction::RefreshEndpoint,
                AuditRedfishOperation::ResetSystem,
            ),
            (
                ProductPermission::RefreshEndpoints,
                AuditAction::ExecuteOperation,
                AuditRedfishOperation::ResetSystem,
            ),
            (
                ProductPermission::ExecuteOperations,
                AuditAction::RefreshEndpoint,
                AuditRedfishOperation::ResetSystem,
            ),
            (
                ProductPermission::ExecuteOperations,
                AuditAction::ExecuteOperation,
                AuditRedfishOperation::ProbeCoreCapabilities,
            ),
            (
                ProductPermission::ExecuteOperations,
                AuditAction::ExecuteOperation,
                AuditRedfishOperation::ReadCoreResources,
            ),
            (
                ProductPermission::ExecuteOperations,
                AuditAction::ExecuteOperation,
                AuditRedfishOperation::None,
            ),
        ] {
            assert_eq!(
                AuditOperationContext::try_new(
                    AuditOperationId::generate(),
                    AuditActor::System,
                    DeploymentPosture::Site,
                    AuditTarget::Endpoint(EndpointId::generate()),
                    AuditParameterSummary::EndpointRefresh,
                    permission,
                    action,
                    operation,
                ),
                Err(AuditOperationContextError)
            );
        }
        // An execution targets the endpoint that receives the write, so a
        // product-level target is rejected for it.
        for operation in [
            AuditRedfishOperation::ResetSystem,
            AuditRedfishOperation::PollRemoteTask,
        ] {
            assert_eq!(
                AuditOperationContext::try_new(
                    AuditOperationId::generate(),
                    AuditActor::System,
                    DeploymentPosture::Site,
                    AuditTarget::Product,
                    AuditParameterSummary::EndpointRefresh,
                    ProductPermission::ExecuteOperations,
                    AuditAction::ExecuteOperation,
                    operation,
                ),
                Err(AuditOperationContextError)
            );
        }
        // A CSV summary cannot describe an endpoint write execution.
        let csv_summary = AuditParameterSummary::csv_endpoint_import(1)?;
        assert_eq!(
            AuditOperationContext::try_new(
                AuditOperationId::generate(),
                AuditActor::System,
                DeploymentPosture::Site,
                AuditTarget::Endpoint(EndpointId::generate()),
                csv_summary,
                ProductPermission::ExecuteOperations,
                AuditAction::ExecuteOperation,
                AuditRedfishOperation::ResetSystem,
            ),
            Err(AuditOperationContextError)
        );
        Ok(())
    }

    #[test]
    fn execution_events_flow_through_the_existing_construction_paths() -> Result<(), Box<dyn Error>>
    {
        let context = execute_context(AuditRedfishOperation::ResetSystem)?;
        let now = OffsetDateTime::now_utc();

        let started = AuditEvent::started(context.clone(), now);
        assert_eq!(started.sequence(), AuditSequence::FIRST);
        assert_eq!(started.outcome().kind(), AuditOutcomeKind::Started);

        let terminal_sequence = AuditSequence::FIRST.next()?;
        let succeeded = AuditEvent::succeeded(context.clone(), terminal_sequence, now)?;
        assert_eq!(
            succeeded.outcome().verification(),
            Some(AuditVerification::Confirmed)
        );
        assert!(succeeded.outcome().is_terminal());

        let failed = AuditEvent::failed(
            context.clone(),
            terminal_sequence,
            AuditFailure::RedfishDiscoveryFailed,
            AuditFailureVerification::Inconclusive,
            now,
        )?;
        assert_eq!(
            failed.outcome().failure(),
            Some(AuditFailure::RedfishDiscoveryFailed)
        );

        // A stored event rehydrates through try_from_parts with its
        // operation type intact.
        let rehydrated = AuditEvent::try_from_parts(
            succeeded.id(),
            context.clone(),
            succeeded.sequence(),
            succeeded.outcome(),
            succeeded.occurred_at(),
        )?;
        assert_eq!(rehydrated, succeeded);
        assert_eq!(
            rehydrated.context().redfish_operation(),
            AuditRedfishOperation::ResetSystem
        );

        // Executions have no progress milestone yet, so a progress event is
        // rejected rather than recorded with a milestone that belongs to
        // another action; the milestone lands with the monitoring audit.
        assert_eq!(
            AuditEvent::progress(
                context,
                terminal_sequence,
                AuditProgress::EndpointCreated,
                now,
            ),
            Err(AuditEventError::InvalidProgress)
        );
        Ok(())
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

    fn execute_context(
        operation: AuditRedfishOperation,
    ) -> Result<AuditOperationContext, AuditOperationContextError> {
        AuditOperationContext::try_new(
            AuditOperationId::generate(),
            AuditActor::System,
            DeploymentPosture::Site,
            AuditTarget::Endpoint(EndpointId::generate()),
            AuditParameterSummary::EndpointRefresh,
            ProductPermission::ExecuteOperations,
            AuditAction::ExecuteOperation,
            operation,
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
