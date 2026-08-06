#![forbid(unsafe_code)]
#![cfg_attr(
    all(not(target_arch = "wasm32"), target_env = "msvc"),
    allow(linker_messages)
)]

#[cfg(any(target_arch = "wasm32", test))]
use std::{collections::BTreeSet, fmt};

#[cfg(any(target_arch = "wasm32", test))]
use rutilus_api::{
    AboutResponse, AuditEventResponse, AuditQueryResponse, CoreResourceDetailsResponse,
    CoreResourceResponse, CredentialInventoryResponse, CredentialSummaryResponse,
    EndpointCsvImportResponse, EndpointCsvImportRowResponse, EndpointCsvImportRowStatusResponse,
    EndpointEnrollmentResponse, EndpointInventoryResponse, EndpointResourceInventoryResponse,
    EndpointResourceSnapshotResponse, EndpointTrustChallengeResponse,
    EndpointTrustChallengeStateResponse, EndpointTrustExpectationRequest, ResourceStatusResponse,
    TlsTrustModeResponse,
};
#[cfg(any(target_arch = "wasm32", test))]
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

#[cfg(any(target_arch = "wasm32", test))]
const PRODUCT_ID: &str = "rutilus";

#[cfg(any(target_arch = "wasm32", test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConsoleLoadFailure {
    ProductMetadata,
    EndpointInventory,
    EndpointResources,
}

#[cfg(any(target_arch = "wasm32", test))]
#[derive(Clone, Debug, Eq, PartialEq)]
struct ConsoleData {
    about: AboutResponse,
    inventory: EndpointInventoryResponse,
    resources: Vec<EndpointResourceInventoryResponse>,
}

#[cfg(any(target_arch = "wasm32", test))]
#[derive(Clone, Debug, Eq, PartialEq)]
enum ConsoleLoadState {
    Loading,
    Ready(ConsoleData),
    Failed(ConsoleLoadFailure),
}

#[cfg(any(target_arch = "wasm32", test))]
impl ConsoleLoadState {
    fn accepted(
        about: AboutResponse,
        inventory: EndpointInventoryResponse,
        resources: Vec<EndpointResourceInventoryResponse>,
    ) -> Self {
        if about.product() != PRODUCT_ID {
            return Self::Failed(ConsoleLoadFailure::ProductMetadata);
        }
        if !resource_endpoints_match(&inventory, &resources) {
            return Self::Failed(ConsoleLoadFailure::EndpointResources);
        }
        Self::Ready(ConsoleData {
            about,
            inventory,
            resources,
        })
    }

    const fn status_message(&self) -> &'static str {
        match self {
            Self::Loading => "Starting the local management console...",
            Self::Ready(_) => "Authenticated local inventory",
            Self::Failed(ConsoleLoadFailure::ProductMetadata) => {
                "The local console could not verify product metadata."
            }
            Self::Failed(ConsoleLoadFailure::EndpointInventory) => {
                "The endpoint inventory is temporarily unavailable."
            }
            Self::Failed(ConsoleLoadFailure::EndpointResources) => {
                "Core resource details are temporarily unavailable."
            }
        }
    }

    const fn is_ready(&self) -> bool {
        matches!(self, Self::Ready(_))
    }

    const fn is_loading(&self) -> bool {
        matches!(self, Self::Loading)
    }

    fn product_version_text(&self) -> String {
        match self {
            Self::Ready(data) => data.about.product_version().to_owned(),
            Self::Loading | Self::Failed(_) => String::new(),
        }
    }

    fn nv_redfish_baseline_text(&self) -> String {
        match self {
            Self::Ready(data) => data.about.nv_redfish_baseline().to_owned(),
            Self::Loading | Self::Failed(_) => String::new(),
        }
    }

    fn endpoint_count_text(&self) -> String {
        let count = match self {
            Self::Ready(data) => data.inventory.endpoints().len(),
            Self::Loading | Self::Failed(_) => 0,
        };
        match count {
            1 => "1 managed endpoint".to_owned(),
            _ => format!("{count} managed endpoints"),
        }
    }

    fn has_empty_inventory(&self) -> bool {
        matches!(self, Self::Ready(data) if data.inventory.endpoints().is_empty())
    }

    fn endpoint_cards(&self) -> Vec<EndpointCardProjection> {
        match self {
            Self::Ready(data) => data
                .inventory
                .endpoints()
                .iter()
                .filter_map(|endpoint| {
                    data.resources
                        .iter()
                        .find(|resources| {
                            resources.endpoint().endpoint_id() == endpoint.identity().endpoint_id()
                        })
                        .map(EndpointCardProjection::from)
                })
                .collect(),
            Self::Loading | Self::Failed(_) => Vec::new(),
        }
    }
}

#[cfg(any(target_arch = "wasm32", test))]
fn resource_endpoints_match(
    inventory: &EndpointInventoryResponse,
    resources: &[EndpointResourceInventoryResponse],
) -> bool {
    let expected = inventory
        .endpoints()
        .iter()
        .map(|endpoint| endpoint.identity().endpoint_id())
        .collect::<BTreeSet<_>>();
    let actual = resources
        .iter()
        .map(|resource| resource.endpoint().endpoint_id())
        .collect::<BTreeSet<_>>();
    expected.len() == inventory.endpoints().len()
        && actual.len() == resources.len()
        && expected == actual
        && inventory.endpoints().iter().all(|summary| {
            resources
                .iter()
                .any(|resource| resource.endpoint() == summary.identity())
        })
}

#[cfg(any(target_arch = "wasm32", test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ResourceCountsProjection {
    systems: u64,
    chassis: u64,
    managers: u64,
}

#[cfg(any(target_arch = "wasm32", test))]
#[derive(Clone, Debug, Eq, PartialEq)]
struct EndpointCardProjection {
    display_name: String,
    address: String,
    trust_label: &'static str,
    snapshot_label: String,
    resource_counts: Option<ResourceCountsProjection>,
    resources: Vec<CoreResourceCardProjection>,
}

#[cfg(any(target_arch = "wasm32", test))]
impl From<&EndpointResourceInventoryResponse> for EndpointCardProjection {
    fn from(endpoint: &EndpointResourceInventoryResponse) -> Self {
        let identity = endpoint.endpoint();
        let trust_label = match identity.tls_trust_mode() {
            TlsTrustModeResponse::SystemCa => "System CA",
            TlsTrustModeResponse::PinnedCertificate => "Pinned certificate",
        };
        let (snapshot_label, resource_counts, resources) = match endpoint.snapshot() {
            EndpointResourceSnapshotResponse::AwaitingFirstRefresh => {
                ("Awaiting first refresh".to_owned(), None, Vec::new())
            }
            EndpointResourceSnapshotResponse::Current {
                generation,
                observed_at,
                resources,
            } => (
                format!(
                    "Generation {} · observed {}",
                    generation.get(),
                    format_observed_at(observed_at)
                ),
                Some(count_core_resources(resources)),
                resources
                    .iter()
                    .map(CoreResourceCardProjection::from)
                    .collect(),
            ),
        };
        Self {
            display_name: identity.display_name().to_owned(),
            address: identity.address().to_owned(),
            trust_label,
            snapshot_label,
            resource_counts,
            resources,
        }
    }
}

#[cfg(any(target_arch = "wasm32", test))]
fn format_observed_at(observed_at: &OffsetDateTime) -> String {
    match observed_at.format(&Rfc3339) {
        Ok(formatted) => formatted,
        Err(_) => observed_at.to_string(),
    }
}

#[cfg(any(target_arch = "wasm32", test))]
fn count_core_resources(resources: &[CoreResourceResponse]) -> ResourceCountsProjection {
    let mut counts = ResourceCountsProjection {
        systems: 0,
        chassis: 0,
        managers: 0,
    };
    for resource in resources {
        match resource.resource() {
            CoreResourceDetailsResponse::ServiceRoot { .. } => {}
            CoreResourceDetailsResponse::System { .. } => counts.systems += 1,
            CoreResourceDetailsResponse::Chassis { .. } => counts.chassis += 1,
            CoreResourceDetailsResponse::Manager { .. } => counts.managers += 1,
        }
    }
    counts
}

#[cfg(any(target_arch = "wasm32", test))]
#[derive(Clone, Debug, Eq, PartialEq)]
struct ResourceFactProjection {
    label: &'static str,
    value: String,
}

#[cfg(any(target_arch = "wasm32", test))]
#[derive(Clone, Debug, Eq, PartialEq)]
struct CoreResourceCardProjection {
    type_label: &'static str,
    name: String,
    description: Option<String>,
    source: String,
    facts: Vec<ResourceFactProjection>,
}

#[cfg(any(target_arch = "wasm32", test))]
impl From<&CoreResourceResponse> for CoreResourceCardProjection {
    fn from(resource: &CoreResourceResponse) -> Self {
        let mut facts = vec![ResourceFactProjection {
            label: "Redfish ID",
            value: resource.common().id().to_owned(),
        }];
        let type_label = match resource.resource() {
            CoreResourceDetailsResponse::ServiceRoot {
                vendor,
                product,
                redfish_version,
            } => {
                push_fact(&mut facts, "Vendor", vendor.as_deref());
                push_fact(&mut facts, "Product", product.as_deref());
                push_fact(&mut facts, "Redfish version", redfish_version.as_deref());
                "Service Root"
            }
            CoreResourceDetailsResponse::System {
                system_type,
                manufacturer,
                model,
                part_number,
                serial_number,
                sku,
                host_name,
                bios_version,
                power_state,
                status,
            } => {
                push_fact(&mut facts, "System type", system_type.as_deref());
                push_hardware_facts(
                    &mut facts,
                    manufacturer.as_deref(),
                    model.as_deref(),
                    part_number.as_deref(),
                    serial_number.as_deref(),
                );
                push_fact(&mut facts, "SKU", sku.as_deref());
                push_fact(&mut facts, "Host name", host_name.as_deref());
                push_fact(&mut facts, "BIOS version", bios_version.as_deref());
                push_fact(&mut facts, "Power state", power_state.as_deref());
                push_status_facts(&mut facts, status.as_ref());
                "System"
            }
            CoreResourceDetailsResponse::Chassis {
                chassis_type,
                manufacturer,
                model,
                part_number,
                serial_number,
                sku,
                asset_tag,
                power_state,
                status,
            } => {
                push_fact(&mut facts, "Chassis type", Some(chassis_type));
                push_hardware_facts(
                    &mut facts,
                    manufacturer.as_deref(),
                    model.as_deref(),
                    part_number.as_deref(),
                    serial_number.as_deref(),
                );
                push_fact(&mut facts, "SKU", sku.as_deref());
                push_fact(&mut facts, "Asset tag", asset_tag.as_deref());
                push_fact(&mut facts, "Power state", power_state.as_deref());
                push_status_facts(&mut facts, status.as_ref());
                "Chassis"
            }
            CoreResourceDetailsResponse::Manager {
                manager_type,
                manufacturer,
                model,
                part_number,
                serial_number,
                firmware_version,
                version,
                power_state,
                status,
            } => {
                push_fact(&mut facts, "Manager type", manager_type.as_deref());
                push_hardware_facts(
                    &mut facts,
                    manufacturer.as_deref(),
                    model.as_deref(),
                    part_number.as_deref(),
                    serial_number.as_deref(),
                );
                push_fact(&mut facts, "Firmware version", firmware_version.as_deref());
                push_fact(&mut facts, "Version", version.as_deref());
                push_fact(&mut facts, "Power state", power_state.as_deref());
                push_status_facts(&mut facts, status.as_ref());
                "Manager"
            }
        };
        Self {
            type_label,
            name: resource.common().name().to_owned(),
            description: resource.common().description().map(str::to_owned),
            source: resource.source().odata_id().to_owned(),
            facts,
        }
    }
}

#[cfg(any(target_arch = "wasm32", test))]
fn push_hardware_facts(
    facts: &mut Vec<ResourceFactProjection>,
    manufacturer: Option<&str>,
    model: Option<&str>,
    part_number: Option<&str>,
    serial_number: Option<&str>,
) {
    push_fact(facts, "Manufacturer", manufacturer);
    push_fact(facts, "Model", model);
    push_fact(facts, "Part number", part_number);
    push_fact(facts, "Serial number", serial_number);
}

#[cfg(any(target_arch = "wasm32", test))]
fn push_status_facts(
    facts: &mut Vec<ResourceFactProjection>,
    status: Option<&ResourceStatusResponse>,
) {
    if let Some(status) = status {
        push_fact(facts, "State", status.state());
        push_fact(facts, "Health", status.health());
        push_fact(facts, "Health rollup", status.health_rollup());
    }
}

#[cfg(any(target_arch = "wasm32", test))]
fn push_fact(facts: &mut Vec<ResourceFactProjection>, label: &'static str, value: Option<&str>) {
    if let Some(value) = value {
        facts.push(ResourceFactProjection {
            label,
            value: value.to_owned(),
        });
    }
}

#[cfg(any(target_arch = "wasm32", test))]
/// One of the top-level console sections reachable from the navigation bar.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConsoleView {
    Overview,
    Credentials,
    AddEndpoint,
    Import,
    Audit,
}

#[cfg(any(target_arch = "wasm32", test))]
impl ConsoleView {
    const ALL: [ConsoleView; 5] = [
        Self::Overview,
        Self::Credentials,
        Self::AddEndpoint,
        Self::Import,
        Self::Audit,
    ];

    const fn label(self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Credentials => "Credentials",
            Self::AddEndpoint => "Add endpoint",
            Self::Import => "Import",
            Self::Audit => "Audit",
        }
    }
}

#[cfg(any(target_arch = "wasm32", test))]
/// Maximum Unicode scalar values accepted for one credential label.
const MAX_CREDENTIAL_NAME_CHARS: usize = 128;
#[cfg(any(target_arch = "wasm32", test))]
/// Maximum Unicode scalar values accepted for one BMC account name.
const MAX_CREDENTIAL_USERNAME_CHARS: usize = 256;
#[cfg(any(target_arch = "wasm32", test))]
/// Maximum UTF-8 bytes accepted for one BMC password.
const MAX_CREDENTIAL_PASSWORD_BYTES: usize = 4 * 1024;
#[cfg(any(target_arch = "wasm32", test))]
/// Maximum Unicode scalar values accepted for one endpoint display name.
const MAX_ENDPOINT_DISPLAY_NAME_CHARS: usize = 128;

#[cfg(any(target_arch = "wasm32", test))]
/// Client-side draft of a reusable BMC credential. The password only enters
/// through a password input and its `Debug` rendering stays redacted.
#[derive(Clone, Eq, PartialEq)]
struct CredentialDraft {
    name: String,
    username: String,
    password: String,
}

#[cfg(any(target_arch = "wasm32", test))]
impl CredentialDraft {
    const fn new() -> Self {
        Self {
            name: String::new(),
            username: String::new(),
            password: String::new(),
        }
    }

    /// Mirrors the application boundary rules so an invalid draft is rejected
    /// before any secret is transmitted.
    fn validate(&self) -> Result<(), CredentialDraftError> {
        let name = self.name.trim();
        if name.is_empty() {
            return Err(CredentialDraftError::NameRequired);
        }
        if name.chars().any(char::is_control) {
            return Err(CredentialDraftError::NameControlCharacter);
        }
        if name.chars().count() > MAX_CREDENTIAL_NAME_CHARS {
            return Err(CredentialDraftError::NameTooLong);
        }
        if self.username.trim().is_empty() {
            return Err(CredentialDraftError::UsernameRequired);
        }
        if self.username.chars().any(char::is_control) {
            return Err(CredentialDraftError::UsernameControlCharacter);
        }
        if self.username.chars().count() > MAX_CREDENTIAL_USERNAME_CHARS {
            return Err(CredentialDraftError::UsernameTooLong);
        }
        if self.password.is_empty() {
            return Err(CredentialDraftError::PasswordRequired);
        }
        if self.password.len() > MAX_CREDENTIAL_PASSWORD_BYTES {
            return Err(CredentialDraftError::PasswordTooLarge);
        }
        Ok(())
    }
}

#[cfg(any(target_arch = "wasm32", test))]
impl fmt::Debug for CredentialDraft {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialDraft")
            .field("name", &self.name)
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .finish()
    }
}

#[cfg(any(target_arch = "wasm32", test))]
/// Why a credential draft cannot be submitted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CredentialDraftError {
    NameRequired,
    NameControlCharacter,
    NameTooLong,
    UsernameRequired,
    UsernameControlCharacter,
    UsernameTooLong,
    PasswordRequired,
    PasswordTooLarge,
}

#[cfg(any(target_arch = "wasm32", test))]
impl CredentialDraftError {
    const fn message(self) -> &'static str {
        match self {
            Self::NameRequired => "A credential name is required.",
            Self::NameControlCharacter => "The credential name cannot contain control characters.",
            Self::NameTooLong => "The credential name cannot exceed 128 characters.",
            Self::UsernameRequired => "A BMC username is required.",
            Self::UsernameControlCharacter => "The username cannot contain control characters.",
            Self::UsernameTooLong => "The username cannot exceed 256 characters.",
            Self::PasswordRequired => "A password is required.",
            Self::PasswordTooLarge => "The password cannot exceed 4 KiB.",
        }
    }
}

#[cfg(any(target_arch = "wasm32", test))]
/// Why a candidate endpoint address cannot start trust observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EndpointAddressDraftError {
    Required,
    HttpsRequired,
    HostRequired,
    Whitespace,
    EmbeddedCredentials,
    QueryOrFragmentNotAllowed,
}

#[cfg(any(target_arch = "wasm32", test))]
impl EndpointAddressDraftError {
    const fn message(self) -> &'static str {
        match self {
            Self::Required => "An endpoint address is required.",
            Self::HttpsRequired => "The endpoint address must use https://.",
            Self::HostRequired => "The endpoint address must include a host.",
            Self::Whitespace => "The endpoint address cannot contain whitespace.",
            Self::EmbeddedCredentials => "The endpoint address must not embed credentials.",
            Self::QueryOrFragmentNotAllowed => {
                "The endpoint address must not contain a query or fragment."
            }
        }
    }
}

#[cfg(any(target_arch = "wasm32", test))]
/// Client-side mirror of the domain HTTPS address rules; the server remains
/// authoritative during trust observation.
fn endpoint_address_draft_error(value: &str) -> Result<(), EndpointAddressDraftError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(EndpointAddressDraftError::Required);
    }
    let Some(rest) = trimmed.strip_prefix("https://") else {
        return Err(EndpointAddressDraftError::HttpsRequired);
    };
    if trimmed.contains(char::is_whitespace) {
        return Err(EndpointAddressDraftError::Whitespace);
    }
    if trimmed.contains('@') {
        return Err(EndpointAddressDraftError::EmbeddedCredentials);
    }
    if trimmed.contains(['?', '#']) {
        return Err(EndpointAddressDraftError::QueryOrFragmentNotAllowed);
    }
    let host = rest.split('/').next().unwrap_or_default();
    if host.is_empty() {
        return Err(EndpointAddressDraftError::HostRequired);
    }
    Ok(())
}

#[cfg(any(target_arch = "wasm32", test))]
/// Why an endpoint display name cannot be submitted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DisplayNameDraftError {
    Required,
    ControlCharacter,
    TooLong,
}

#[cfg(any(target_arch = "wasm32", test))]
impl DisplayNameDraftError {
    const fn message(self) -> &'static str {
        match self {
            Self::Required => "A display name is required.",
            Self::ControlCharacter => "The display name cannot contain control characters.",
            Self::TooLong => "The display name cannot exceed 128 characters.",
        }
    }
}

#[cfg(any(target_arch = "wasm32", test))]
/// Client-side mirror of the domain display-name rules.
fn display_name_draft_error(value: &str) -> Result<(), DisplayNameDraftError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(DisplayNameDraftError::Required);
    }
    if trimmed.chars().any(char::is_control) {
        return Err(DisplayNameDraftError::ControlCharacter);
    }
    if trimmed.chars().count() > MAX_ENDPOINT_DISPLAY_NAME_CHARS {
        return Err(DisplayNameDraftError::TooLong);
    }
    Ok(())
}

#[cfg(any(target_arch = "wasm32", test))]
/// Client-side draft of the final enrollment inputs: a display name plus the
/// selected or freshly created credential.
#[derive(Clone, Debug, Eq, PartialEq)]
struct EnrollmentDraft {
    display_name: String,
    credential: Option<CredentialSummaryResponse>,
}

#[cfg(any(target_arch = "wasm32", test))]
impl EnrollmentDraft {
    const fn new() -> Self {
        Self {
            display_name: String::new(),
            credential: None,
        }
    }

    fn validate(&self) -> Result<(), EnrollmentDraftError> {
        display_name_draft_error(&self.display_name).map_err(EnrollmentDraftError::DisplayName)?;
        if self.credential.is_none() {
            return Err(EnrollmentDraftError::CredentialRequired);
        }
        Ok(())
    }
}

#[cfg(any(target_arch = "wasm32", test))]
/// Why the final enrollment inputs cannot be submitted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EnrollmentDraftError {
    DisplayName(DisplayNameDraftError),
    CredentialRequired,
}

#[cfg(any(target_arch = "wasm32", test))]
impl EnrollmentDraftError {
    const fn message(self) -> &'static str {
        match self {
            Self::DisplayName(error) => error.message(),
            Self::CredentialRequired => "Select or create a credential before enrolling.",
        }
    }
}

#[cfg(any(target_arch = "wasm32", test))]
/// The credential-free TLS observation shown before any credential is
/// selected or transmitted to a BMC.
#[derive(Clone, Debug, Eq, PartialEq)]
struct TrustChallengeProjection {
    address: String,
    fingerprint_sha256: String,
    observed_at: OffsetDateTime,
    state: EndpointTrustChallengeStateResponse,
}

#[cfg(any(target_arch = "wasm32", test))]
impl TrustChallengeProjection {
    fn from_response(response: &EndpointTrustChallengeResponse) -> Self {
        Self {
            address: response.address().to_owned(),
            fingerprint_sha256: response.fingerprint_sha256().to_owned(),
            observed_at: response.observed_at(),
            state: response.state(),
        }
    }

    const fn is_system_ca_trusted(&self) -> bool {
        matches!(
            self.state,
            EndpointTrustChallengeStateResponse::SystemCaTrusted
        )
    }

    const fn state_label(&self) -> &'static str {
        match self.state {
            EndpointTrustChallengeStateResponse::SystemCaTrusted => "Verified by system CA roots",
            EndpointTrustChallengeStateResponse::ExplicitPinRequired => {
                "Not trusted by system CA roots; an explicit pin is required"
            }
        }
    }

    fn observed_at_text(&self) -> String {
        format_observed_at(&self.observed_at)
    }

    /// The trust policy derived from the observed challenge: system CA trust
    /// when the identity already verifies, otherwise an explicit pin of the
    /// exact observed fingerprint.
    fn expectation(&self) -> EndpointTrustExpectationRequest {
        match self.state {
            EndpointTrustChallengeStateResponse::SystemCaTrusted => {
                EndpointTrustExpectationRequest::system_ca()
            }
            EndpointTrustChallengeStateResponse::ExplicitPinRequired => {
                EndpointTrustExpectationRequest::pinned_certificate(self.fingerprint_sha256.clone())
            }
        }
    }
}

#[cfg(any(target_arch = "wasm32", test))]
/// The staged trust-first onboarding flow. Every transition is driven by a
/// server response; no credential is transmitted before the trust step.
#[derive(Clone, Debug, Eq, PartialEq)]
enum OnboardingStep {
    Address,
    Challenge(TrustChallengeProjection),
    Credential {
        address: String,
        trust: EndpointTrustExpectationRequest,
    },
    Enrolled(EndpointEnrollmentResponse),
}

#[cfg(any(target_arch = "wasm32", test))]
impl OnboardingStep {
    const fn is_address(&self) -> bool {
        matches!(self, Self::Address)
    }

    const fn is_challenge(&self) -> bool {
        matches!(self, Self::Challenge(_))
    }

    const fn is_credential(&self) -> bool {
        matches!(self, Self::Credential { .. })
    }

    const fn is_enrolled(&self) -> bool {
        matches!(self, Self::Enrolled(_))
    }

    fn challenge_projection(&self) -> Option<&TrustChallengeProjection> {
        match self {
            Self::Challenge(projection) => Some(projection),
            Self::Address | Self::Credential { .. } | Self::Enrolled(_) => None,
        }
    }

    fn credential_plan(&self) -> Option<(&str, &EndpointTrustExpectationRequest)> {
        match self {
            Self::Credential { address, trust } => Some((address, trust)),
            Self::Address | Self::Challenge(_) | Self::Enrolled(_) => None,
        }
    }

    const fn enrollment(&self) -> Option<&EndpointEnrollmentResponse> {
        match self {
            Self::Enrolled(enrollment) => Some(enrollment),
            Self::Address | Self::Challenge(_) | Self::Credential { .. } => None,
        }
    }
}

#[cfg(any(target_arch = "wasm32", test))]
/// Why a trust-first onboarding step could not be completed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OnboardingFailure {
    TrustObservation,
    TrustExpectationRejected,
    CredentialsUnavailable,
    CredentialCreateRejected,
    EnrollmentRejected,
}

#[cfg(any(target_arch = "wasm32", test))]
impl OnboardingFailure {
    const fn message(self) -> &'static str {
        match self {
            Self::TrustObservation => {
                "The TLS identity could not be observed. Check that the address is reachable over HTTPS."
            }
            Self::TrustExpectationRejected => {
                "The confirmed trust policy could not be verified. The observed certificate may have changed."
            }
            Self::CredentialsUnavailable => "The credential inventory is temporarily unavailable.",
            Self::CredentialCreateRejected => "The credential could not be created.",
            Self::EnrollmentRejected => {
                "The endpoint could not be enrolled with the selected credential."
            }
        }
    }
}

#[cfg(any(target_arch = "wasm32", test))]
/// Human label for an already-declared trust expectation.
fn trust_mode_label(trust: &EndpointTrustExpectationRequest) -> &'static str {
    if trust.fingerprint_sha256().is_some() {
        "Pinned certificate"
    } else {
        "System CA"
    }
}

/// One independent result of a CSV import, projected for the report table.
#[cfg(any(target_arch = "wasm32", test))]
#[derive(Clone, Debug, Eq, PartialEq)]
struct CsvImportRowProjection {
    record_number: u64,
    address: String,
    status_label: &'static str,
    is_success: bool,
    detail: Option<String>,
}

#[cfg(any(target_arch = "wasm32", test))]
impl From<&EndpointCsvImportRowResponse> for CsvImportRowProjection {
    fn from(row: &EndpointCsvImportRowResponse) -> Self {
        let (status_label, is_success, detail) = match row.status() {
            EndpointCsvImportRowStatusResponse::Enrolled => (
                "Enrolled",
                true,
                row.endpoint_id().map(|endpoint_id| endpoint_id.to_string()),
            ),
            EndpointCsvImportRowStatusResponse::TlsProbeFailed => {
                ("TLS probe failed", false, row.message().map(str::to_owned))
            }
            EndpointCsvImportRowStatusResponse::TrustRejected => {
                ("Trust rejected", false, row.message().map(str::to_owned))
            }
            EndpointCsvImportRowStatusResponse::EnrollmentFailed => {
                ("Enrollment failed", false, row.message().map(str::to_owned))
            }
        };
        Self {
            record_number: row.record_number(),
            address: row.address().to_owned(),
            status_label,
            is_success,
            detail,
        }
    }
}

/// The server-provided report of one CSV import submission.
#[cfg(any(target_arch = "wasm32", test))]
#[derive(Clone, Debug, Eq, PartialEq)]
struct CsvImportReportProjection {
    total_rows: u64,
    succeeded_count: u64,
    failed_count: u64,
    rows: Vec<CsvImportRowProjection>,
}

#[cfg(any(target_arch = "wasm32", test))]
impl CsvImportReportProjection {
    fn from_response(response: &EndpointCsvImportResponse) -> Self {
        Self {
            total_rows: response.total_rows(),
            succeeded_count: response.succeeded_count(),
            failed_count: response.failed_count(),
            rows: response
                .rows()
                .iter()
                .map(CsvImportRowProjection::from)
                .collect(),
        }
    }

    fn summary_text(&self) -> String {
        format!(
            "{} of {} rows enrolled; {} failed",
            self.succeeded_count, self.total_rows, self.failed_count
        )
    }
}

#[cfg(any(target_arch = "wasm32", test))]
/// The lazy-loading state of the credential inventory section.
#[derive(Clone, Debug, Eq, PartialEq)]
enum CredentialsListState {
    Idle,
    Loading,
    Ready(CredentialInventoryResponse),
    Failed,
}

#[cfg(any(target_arch = "wasm32", test))]
impl CredentialsListState {
    const fn is_ready(&self) -> bool {
        matches!(self, Self::Ready(_))
    }

    const fn is_failed(&self) -> bool {
        matches!(self, Self::Failed)
    }

    fn has_empty_inventory(&self) -> bool {
        matches!(
            self,
            Self::Ready(inventory) if inventory.credentials().is_empty()
        )
    }

    fn count_text(&self) -> String {
        let count = match self {
            Self::Ready(inventory) => inventory.credentials().len(),
            Self::Idle | Self::Loading | Self::Failed => 0,
        };
        match count {
            1 => "1 stored credential".to_owned(),
            _ => format!("{count} stored credentials"),
        }
    }

    fn credential_cards(&self) -> Vec<CredentialCardProjection> {
        match self {
            Self::Ready(inventory) => inventory
                .credentials()
                .iter()
                .map(CredentialCardProjection::from)
                .collect(),
            Self::Idle | Self::Loading | Self::Failed => Vec::new(),
        }
    }
}

#[cfg(any(target_arch = "wasm32", test))]
/// Secret-free credential metadata projected for one list card.
#[derive(Clone, Debug, Eq, PartialEq)]
struct CredentialCardProjection {
    name: String,
    username: String,
    credential_id: String,
    created_at_text: String,
    updated_at_text: String,
}

#[cfg(any(target_arch = "wasm32", test))]
impl From<&CredentialSummaryResponse> for CredentialCardProjection {
    fn from(credential: &CredentialSummaryResponse) -> Self {
        Self {
            name: credential.name().to_owned(),
            username: credential.username().to_owned(),
            credential_id: credential.credential_id().to_string(),
            created_at_text: format_observed_at(&credential.created_at()),
            updated_at_text: format_observed_at(&credential.updated_at()),
        }
    }
}

#[cfg(any(target_arch = "wasm32", test))]
/// The lazy-loading state of credentials available during enrollment.
#[derive(Clone, Debug, Eq, PartialEq)]
enum OnboardingCredentialsState {
    Idle,
    Loading,
    Ready(CredentialInventoryResponse),
    Failed,
}

#[cfg(any(target_arch = "wasm32", test))]
impl OnboardingCredentialsState {
    const fn is_failed(&self) -> bool {
        matches!(self, Self::Failed)
    }

    fn has_empty_inventory(&self) -> bool {
        matches!(
            self,
            Self::Ready(inventory) if inventory.credentials().is_empty()
        )
    }

    fn ready_credentials(&self) -> Option<Vec<CredentialSummaryResponse>> {
        match self {
            Self::Ready(inventory) => Some(inventory.credentials().to_vec()),
            Self::Idle | Self::Loading | Self::Failed => None,
        }
    }
}

#[cfg(any(target_arch = "wasm32", test))]
/// The progression of one credential creation submission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CreateCredentialState {
    Idle,
    InFlight,
    Created,
    Failed(&'static str),
}

#[cfg(any(target_arch = "wasm32", test))]
/// The progression of one CSV import submission.
#[derive(Clone, Debug, Eq, PartialEq)]
enum ImportState {
    Idle,
    InFlight,
    Ready(CsvImportReportProjection),
    Failed(ImportFailure),
}

#[cfg(any(target_arch = "wasm32", test))]
/// Why a CSV import could not be completed or reported.
#[derive(Clone, Debug, Eq, PartialEq)]
enum ImportFailure {
    FileUnreadable,
    FileEmpty,
    Unavailable,
    MalformedReport,
    Rejected { status: u16 },
}

#[cfg(any(target_arch = "wasm32", test))]
impl ImportFailure {
    fn message(&self) -> String {
        match self {
            Self::FileUnreadable => "The selected file could not be read.".to_owned(),
            Self::FileEmpty => "The selected file is empty.".to_owned(),
            Self::Unavailable => "The import service is temporarily unavailable.".to_owned(),
            Self::MalformedReport => "The server response could not be read.".to_owned(),
            Self::Rejected { status } => {
                format!("The server rejected the import request (HTTP {status}).")
            }
        }
    }
}

/// The lazy-loading state of the bounded audit query section.
#[cfg(any(target_arch = "wasm32", test))]
#[derive(Clone, Debug, Eq, PartialEq)]
enum AuditListState {
    Idle,
    Loading,
    Ready(AuditQueryResponse),
    Failed,
}

#[cfg(any(target_arch = "wasm32", test))]
impl AuditListState {
    const fn is_ready(&self) -> bool {
        matches!(self, Self::Ready(_))
    }

    const fn is_failed(&self) -> bool {
        matches!(self, Self::Failed)
    }

    const fn is_loading(&self) -> bool {
        matches!(self, Self::Loading)
    }

    fn has_empty_events(&self) -> bool {
        matches!(self, Self::Ready(query) if query.events().is_empty())
    }

    fn count_text(&self) -> String {
        let count = match self {
            Self::Ready(query) => query.events().len(),
            Self::Idle | Self::Loading | Self::Failed => 0,
        };
        match count {
            1 => "1 audit event".to_owned(),
            _ => format!("{count} audit events"),
        }
    }

    fn event_cards(&self) -> Vec<AuditEventCardProjection> {
        match self {
            Self::Ready(query) => query
                .events()
                .iter()
                .map(AuditEventCardProjection::from)
                .collect(),
            Self::Idle | Self::Loading | Self::Failed => Vec::new(),
        }
    }
}

/// One immutable, secret-free audit event projected for a list card.
#[cfg(any(target_arch = "wasm32", test))]
#[derive(Clone, Debug, Eq, PartialEq)]
struct AuditEventCardProjection {
    occurred_at_text: String,
    actor: String,
    action: String,
    target_kind: String,
    target_identifier: Option<String>,
    outcome_kind: String,
    outcome_detail: Option<String>,
    sequence: u32,
    operation_id: String,
    message: String,
}

#[cfg(any(target_arch = "wasm32", test))]
impl From<&AuditEventResponse> for AuditEventCardProjection {
    fn from(event: &AuditEventResponse) -> Self {
        let outcome = event.outcome();
        let outcome_detail = outcome
            .failure()
            .or_else(|| outcome.verification())
            .or_else(|| outcome.progress())
            .map(str::to_owned);
        Self {
            occurred_at_text: format_observed_at(&event.occurred_at()),
            actor: event.actor().to_owned(),
            action: event.action().to_owned(),
            target_kind: event.target().kind().to_owned(),
            target_identifier: event.target().identifier().map(str::to_owned),
            outcome_kind: outcome.kind().to_owned(),
            outcome_detail,
            sequence: event.sequence(),
            operation_id: event.operation_id().to_string(),
            message: event.message().to_owned(),
        }
    }
}

#[cfg(target_arch = "wasm32")]
mod browser {
    use gloo_net::http::Request;
    use leptos::{
        mount::mount_to_body,
        prelude::*,
        wasm_bindgen::{JsCast, JsValue},
        web_sys::{Blob, Event, HtmlInputElement},
    };
    use rutilus_api::{
        AboutResponse, AuditQueryResponse, BeginEndpointTrustRequest, ConfirmEndpointTrustRequest,
        CreateCredentialRequest, CredentialInventoryResponse, CredentialSummaryResponse,
        EndpointCsvImportRequest, EndpointCsvImportResponse, EndpointEnrollmentResponse,
        EndpointInventoryResponse, EndpointResourceInventoryResponse,
        EndpointTrustChallengeResponse, EndpointTrustExpectationRequest, EnrollEndpointRequest,
        TrustedEndpointResponse,
    };
    use wasm_bindgen::prelude::wasm_bindgen;
    use wasm_bindgen_futures::{JsFuture, spawn_local};

    use super::{
        AuditEventCardProjection, AuditListState, ConsoleLoadFailure, ConsoleLoadState,
        ConsoleView, CoreResourceCardProjection, CreateCredentialState, CredentialCardProjection,
        CredentialDraft, CredentialDraftError, CredentialsListState, CsvImportReportProjection,
        EndpointAddressDraftError, EndpointCardProjection, EnrollmentDraft, EnrollmentDraftError,
        ImportFailure, ImportState, OnboardingCredentialsState, OnboardingFailure, OnboardingStep,
        TrustChallengeProjection, endpoint_address_draft_error, trust_mode_label,
    };

    #[wasm_bindgen(start)]
    pub fn start() {
        mount_to_body(|| view! { <ProductShell /> });
    }

    #[component]
    fn ProductShell() -> impl IntoView {
        let (state, set_state) = signal(ConsoleLoadState::Loading);
        spawn_local(async move {
            set_state.set(fetch_console().await);
        });
        let (view, set_view) = signal(ConsoleView::Overview);

        let on_refresh_inventory = move |_| {
            set_state.set(ConsoleLoadState::Loading);
            spawn_local(async move {
                set_state.set(fetch_console().await);
            });
        };

        view! {
            <main id="app" aria-live="polite">
                <header class="product-header">
                    <div>
                        <p class="eyebrow">"Local Redfish management"</p>
                        <h1>"Rutilus"</h1>
                        <p id="status">{move || state.with(ConsoleLoadState::status_message)}</p>
                    </div>
                    <dl id="build" hidden=move || !state.with(ConsoleLoadState::is_ready)>
                        <div>
                            <dt>"Product"</dt>
                            <dd id="product-version">
                                {move || state.with(ConsoleLoadState::product_version_text)}
                            </dd>
                        </div>
                        <div>
                            <dt>"nv-redfish"</dt>
                            <dd id="redfish-version">
                                {move || state.with(ConsoleLoadState::nv_redfish_baseline_text)}
                            </dd>
                        </div>
                    </dl>
                </header>

                <nav class="view-nav" aria-label="Console sections">
                    {ConsoleView::ALL
                        .iter()
                        .map(|candidate| {
                            let candidate = *candidate;
                            let class = move || {
                                if view.get() == candidate {
                                    "view-nav-item is-active"
                                } else {
                                    "view-nav-item"
                                }
                            };
                            view! {
                                <button
                                    type="button"
                                    class=class
                                    on:click=move |_| set_view.set(candidate)
                                >
                                    {candidate.label()}
                                </button>
                            }
                        })
                        .collect_view()}
                </nav>

                <section
                    class="inventory"
                    hidden=move || {
                        view.get() != ConsoleView::Overview
                            || !state.with(ConsoleLoadState::is_ready)
                    }
                >
                    <div class="inventory-heading">
                        <div>
                            <p class="section-label">"Inventory"</p>
                            <h2>{move || state.with(ConsoleLoadState::endpoint_count_text)}</h2>
                        </div>
                        <p>"Latest complete Redfish resource generations"</p>
                    </div>
                    <div class="inventory-actions">
                        <button
                            type="button"
                            class="btn"
                            disabled=move || state.with(ConsoleLoadState::is_loading)
                            on:click=on_refresh_inventory
                        >
                            "Refresh inventory"
                        </button>
                    </div>
                    <p
                        class="empty-inventory"
                        hidden=move || !state.with(ConsoleLoadState::has_empty_inventory)
                    >
                        "No endpoints are managed yet. Add a trusted BMC endpoint to begin."
                    </p>
                    <div class="endpoint-grid">
                        {move || {
                            state
                                .with(ConsoleLoadState::endpoint_cards)
                                .into_iter()
                                .map(|card| view! { <EndpointCard card=card /> })
                                .collect_view()
                        }}
                    </div>
                </section>

                <CredentialsView view=view />
                <AddEndpointView view=view />
                <ImportView view=view />
                <AuditView view=view />
            </main>
        }
    }

    #[component]
    fn EndpointCard(card: EndpointCardProjection) -> impl IntoView {
        let systems = card.resource_counts.map_or(0, |counts| counts.systems);
        let chassis = card.resource_counts.map_or(0, |counts| counts.chassis);
        let managers = card.resource_counts.map_or(0, |counts| counts.managers);
        let awaiting_refresh = card.resource_counts.is_none();
        let status_dot_class = if awaiting_refresh {
            "status-dot status-dot-waiting"
        } else {
            "status-dot"
        };
        let resources = card.resources;

        view! {
            <article class="endpoint-card">
                <div class="endpoint-title">
                    <div>
                        <h3>{card.display_name}</h3>
                        <p class="endpoint-address">{card.address}</p>
                    </div>
                    <span class="trust-badge">{card.trust_label}</span>
                </div>
                <div class="snapshot-heading">
                    <span class=status_dot_class aria-hidden="true"></span>
                    <span>{card.snapshot_label}</span>
                </div>
                <p class="awaiting-refresh" hidden=!awaiting_refresh>
                    "No resource counts are published until a complete refresh succeeds."
                </p>
                <dl class="resource-counts" hidden=awaiting_refresh>
                    <div>
                        <dt>"Systems"</dt>
                        <dd>{systems}</dd>
                    </div>
                    <div>
                        <dt>"Chassis"</dt>
                        <dd>{chassis}</dd>
                    </div>
                    <div>
                        <dt>"Managers"</dt>
                        <dd>{managers}</dd>
                    </div>
                </dl>
                <section class="core-resources" hidden=awaiting_refresh>
                    <div class="core-resources-heading">
                        <h4>"Core resources"</h4>
                        <span>{resources.len()}</span>
                    </div>
                    <div class="core-resource-grid">
                        {resources
                            .into_iter()
                            .map(|resource| view! { <CoreResourceCard resource=resource /> })
                            .collect_view()}
                    </div>
                </section>
            </article>
        }
    }

    #[component]
    fn CoreResourceCard(resource: CoreResourceCardProjection) -> impl IntoView {
        let CoreResourceCardProjection {
            type_label,
            name,
            description,
            source,
            facts,
        } = resource;
        let has_description = description.is_some();
        let description = description.unwrap_or_default();
        let source_title = source.clone();

        view! {
            <article class="core-resource-card">
                <div class="core-resource-title">
                    <div>
                        <p class="resource-type">{type_label}</p>
                        <h5>{name}</h5>
                    </div>
                </div>
                <p class="resource-description" hidden=!has_description>{description}</p>
                <dl class="resource-facts">
                    {facts
                        .into_iter()
                        .map(|fact| {
                            view! {
                                <div>
                                    <dt>{fact.label}</dt>
                                    <dd>{fact.value}</dd>
                                </div>
                            }
                        })
                        .collect_view()}
                </dl>
                <p class="resource-source" title=source_title>
                    <span>"Source"</span>
                    <code>{source}</code>
                </p>
            </article>
        }
    }

    async fn fetch_console() -> ConsoleLoadState {
        let Some(about) = fetch_about().await else {
            return ConsoleLoadState::Failed(ConsoleLoadFailure::ProductMetadata);
        };
        if about.product() != super::PRODUCT_ID {
            return ConsoleLoadState::Failed(ConsoleLoadFailure::ProductMetadata);
        }
        let Some(inventory) = fetch_inventory().await else {
            return ConsoleLoadState::Failed(ConsoleLoadFailure::EndpointInventory);
        };
        let Some(resources) = fetch_resource_inventories(&inventory).await else {
            return ConsoleLoadState::Failed(ConsoleLoadFailure::EndpointResources);
        };
        ConsoleLoadState::accepted(about, inventory, resources)
    }

    async fn fetch_about() -> Option<AboutResponse> {
        let response = Request::get("/api/v1/about")
            .header("Accept", "application/json")
            .send()
            .await
            .ok()?;
        if !response.ok() {
            return None;
        }
        response.json::<AboutResponse>().await.ok()
    }

    async fn fetch_inventory() -> Option<EndpointInventoryResponse> {
        let response = Request::get("/api/v1/endpoints")
            .header("Accept", "application/json")
            .send()
            .await
            .ok()?;
        if !response.ok() {
            return None;
        }
        response.json::<EndpointInventoryResponse>().await.ok()
    }

    async fn fetch_resource_inventories(
        inventory: &EndpointInventoryResponse,
    ) -> Option<Vec<EndpointResourceInventoryResponse>> {
        let mut resources = Vec::with_capacity(inventory.endpoints().len());
        for endpoint in inventory.endpoints() {
            let path = format!(
                "/api/v1/endpoints/{}/resources",
                endpoint.identity().endpoint_id()
            );
            let response = Request::get(&path)
                .header("Accept", "application/json")
                .send()
                .await
                .ok()?;
            if !response.ok() {
                return None;
            }
            resources.push(
                response
                    .json::<EndpointResourceInventoryResponse>()
                    .await
                    .ok()?,
            );
        }
        Some(resources)
    }

    #[component]
    fn CredentialsView(view: ReadSignal<ConsoleView>) -> impl IntoView {
        let active = move || view.get() == ConsoleView::Credentials;
        let (list_state, set_list_state) = signal(CredentialsListState::Idle);
        let (list_triggered, set_list_triggered) = signal(false);
        let (draft, set_draft) = signal(CredentialDraft::new());
        let (draft_error, set_draft_error) = signal(None::<CredentialDraftError>);
        let (create_state, set_create_state) = signal(CreateCredentialState::Idle);

        Effect::new(move |_| {
            if active() && !list_triggered.get() {
                set_list_triggered.set(true);
                set_list_state.set(CredentialsListState::Loading);
                spawn_local(async move {
                    let state = match fetch_credentials().await {
                        Some(inventory) => CredentialsListState::Ready(inventory),
                        None => CredentialsListState::Failed,
                    };
                    set_list_state.set(state);
                });
            }
        });

        let on_refresh = move |_| {
            set_list_state.set(CredentialsListState::Loading);
            spawn_local(async move {
                let state = match fetch_credentials().await {
                    Some(inventory) => CredentialsListState::Ready(inventory),
                    None => CredentialsListState::Failed,
                };
                set_list_state.set(state);
            });
        };

        let on_changed = Callback::new(move |()| {
            set_create_state.set(CreateCredentialState::Idle);
        });

        let on_submit = Callback::new(move |()| {
            if let Err(error) = draft.get().validate() {
                set_draft_error.set(Some(error));
                return;
            }
            set_draft_error.set(None);
            set_create_state.set(CreateCredentialState::InFlight);
            let submitted = draft.get();
            spawn_local(async move {
                let created = post_credential(&submitted).await.is_some();
                if created {
                    set_draft.set(CredentialDraft::new());
                    set_draft_error.set(None);
                }
                set_create_state.set(if created {
                    CreateCredentialState::Created
                } else {
                    CreateCredentialState::Failed(
                        "The credential could not be created. Check the fields and try again.",
                    )
                });
                if created {
                    set_list_state.set(CredentialsListState::Loading);
                    let state = match fetch_credentials().await {
                        Some(inventory) => CredentialsListState::Ready(inventory),
                        None => CredentialsListState::Failed,
                    };
                    set_list_state.set(state);
                }
            });
        });

        view! {
            <section class="view-section" hidden=move || !active()>
                <div class="inventory-heading">
                    <div>
                        <p class="section-label">"Protected BMC access"</p>
                        <h2>{move || list_state.get().count_text()}</h2>
                    </div>
                    <p>"Reusable credentials never leave this device unencrypted."</p>
                </div>
                <p
                    class="empty-inventory"
                    hidden=move || {
                        !list_state.get().is_ready()
                            || !list_state.get().has_empty_inventory()
                    }
                >
                    "No credentials are stored yet. Create the first one below."
                </p>
                <div class="resource-list">
                    {move || {
                        list_state
                            .get()
                            .credential_cards()
                            .into_iter()
                            .map(|card| view! { <CredentialCard card=card /> })
                            .collect_view()
                    }}
                </div>
                <div class="inventory-actions">
                    <button
                        type="button"
                        class="btn"
                        hidden=move || {
                            !list_state.get().is_ready() && !list_state.get().is_failed()
                        }
                        on:click=on_refresh
                    >
                        "Refresh"
                    </button>
                </div>
                <p class="form-error" hidden=move || !list_state.get().is_failed()>
                    "The credential inventory is temporarily unavailable."
                </p>
                <CredentialCreatePanel
                    draft=draft
                    set_draft=set_draft
                    error=draft_error
                    set_error=set_draft_error
                    create_state=create_state
                    on_changed=on_changed
                    on_submit=on_submit
                />
            </section>
        }
    }

    #[component]
    fn CredentialCreatePanel(
        draft: ReadSignal<CredentialDraft>,
        set_draft: WriteSignal<CredentialDraft>,
        error: ReadSignal<Option<CredentialDraftError>>,
        set_error: WriteSignal<Option<CredentialDraftError>>,
        create_state: ReadSignal<CreateCredentialState>,
        on_changed: Callback<()>,
        on_submit: Callback<()>,
    ) -> impl IntoView {
        view! {
            <div class="form-panel create-panel">
                <p class="section-label">"Create credential"</p>
                <CredentialDraftForm
                    draft=draft
                    set_draft=set_draft
                    error=error
                    set_error=set_error
                    field_id_prefix="new-credential"
                    submit_label="Create credential"
                    submit_disabled=move || create_state.get() == CreateCredentialState::InFlight
                    on_changed=on_changed
                    on_submit=on_submit
                />
                <p
                    class="inline-status"
                    hidden=move || create_state.get() != CreateCredentialState::InFlight
                >
                    "Creating the credential..."
                </p>
                <p
                    class="inline-status success"
                    hidden=move || create_state.get() != CreateCredentialState::Created
                >
                    "Credential created."
                </p>
                <p
                    class="inline-status error"
                    hidden=move || {
                        !matches!(create_state.get(), CreateCredentialState::Failed(_))
                    }
                >
                    {move || match create_state.get() {
                        CreateCredentialState::Failed(message) => message,
                        _ => "",
                    }}
                </p>
            </div>
        }
    }

    #[component]
    fn CredentialDraftForm(
        draft: ReadSignal<CredentialDraft>,
        set_draft: WriteSignal<CredentialDraft>,
        error: ReadSignal<Option<CredentialDraftError>>,
        set_error: WriteSignal<Option<CredentialDraftError>>,
        field_id_prefix: &'static str,
        submit_label: &'static str,
        submit_disabled: impl Fn() -> bool + Send + 'static,
        on_changed: Callback<()>,
        on_submit: Callback<()>,
    ) -> impl IntoView {
        let name_id = format!("{field_id_prefix}-name");
        let username_id = format!("{field_id_prefix}-username");
        let password_id = format!("{field_id_prefix}-password");

        let name_error = move || match error.get() {
            Some(
                error @ (CredentialDraftError::NameRequired
                | CredentialDraftError::NameControlCharacter
                | CredentialDraftError::NameTooLong),
            ) => error.message(),
            _ => "",
        };
        let username_error = move || match error.get() {
            Some(
                error @ (CredentialDraftError::UsernameRequired
                | CredentialDraftError::UsernameControlCharacter
                | CredentialDraftError::UsernameTooLong),
            ) => error.message(),
            _ => "",
        };
        let password_error = move || match error.get() {
            Some(
                error @ (CredentialDraftError::PasswordRequired
                | CredentialDraftError::PasswordTooLarge),
            ) => error.message(),
            _ => "",
        };

        let on_name_input = move |event| {
            let value = event_target_value(&event);
            set_draft.update(|draft| draft.name = value);
            set_error.set(draft.get().validate().err());
            on_changed.run(());
        };
        let on_username_input = move |event| {
            let value = event_target_value(&event);
            set_draft.update(|draft| draft.username = value);
            set_error.set(draft.get().validate().err());
            on_changed.run(());
        };
        let on_password_input = move |event| {
            let value = event_target_value(&event);
            set_draft.update(|draft| draft.password = value);
            set_error.set(draft.get().validate().err());
            on_changed.run(());
        };

        view! {
            <div class="form-grid">
                <div class="form-field">
                    <label for=name_id.clone()>"Name"</label>
                    <input
                        id=name_id.clone()
                        class="form-input"
                        type="text"
                        autocomplete="off"
                        prop:value=move || draft.get().name
                        on:input=on_name_input
                    />
                    <p class="form-error" hidden=move || name_error().is_empty()>
                        {move || name_error()}
                    </p>
                </div>
                <div class="form-field">
                    <label for=username_id.clone()>"Username"</label>
                    <input
                        id=username_id.clone()
                        class="form-input"
                        type="text"
                        autocomplete="off"
                        prop:value=move || draft.get().username
                        on:input=on_username_input
                    />
                    <p class="form-error" hidden=move || username_error().is_empty()>
                        {move || username_error()}
                    </p>
                </div>
                <div class="form-field">
                    <label for=password_id.clone()>"Password"</label>
                    <input
                        id=password_id.clone()
                        class="form-input"
                        type="password"
                        autocomplete="new-password"
                        prop:value=move || draft.get().password
                        on:input=on_password_input
                    />
                    <p class="form-error" hidden=move || password_error().is_empty()>
                        {move || password_error()}
                    </p>
                </div>
                <div class="form-actions">
                    <button
                        type="button"
                        class="btn btn-primary"
                        disabled=submit_disabled
                        on:click=move |_| on_submit.run(())
                    >
                        {submit_label}
                    </button>
                </div>
            </div>
        }
    }

    #[component]
    fn CredentialCard(card: CredentialCardProjection) -> impl IntoView {
        let CredentialCardProjection {
            name,
            username,
            credential_id,
            created_at_text,
            updated_at_text,
        } = card;
        view! {
            <article class="credential-card">
                <div class="credential-title">
                    <div>
                        <h3>{name}</h3>
                        <p class="credential-username">{username}</p>
                    </div>
                    <code class="credential-id" title=credential_id.clone()>
                        {credential_id.clone()}
                    </code>
                </div>
                <dl class="resource-facts">
                    <div>
                        <dt>"Created"</dt>
                        <dd>{created_at_text}</dd>
                    </div>
                    <div>
                        <dt>"Updated"</dt>
                        <dd>{updated_at_text}</dd>
                    </div>
                </dl>
            </article>
        }
    }

    #[component]
    fn AddEndpointView(view: ReadSignal<ConsoleView>) -> impl IntoView {
        let active = move || view.get() == ConsoleView::AddEndpoint;
        let (step, set_step) = signal(OnboardingStep::Address);
        let (failure, set_failure) = signal(None::<OnboardingFailure>);

        view! {
            <section class="view-section" hidden=move || !active()>
                <div class="inventory-heading">
                    <div>
                        <p class="section-label">"Onboarding"</p>
                        <h2>"Add endpoint"</h2>
                    </div>
                    <p>"Trust is established before any credential is transmitted."</p>
                </div>
                <p class="form-error" hidden=move || failure.get().is_none()>
                    {move || failure.get().map_or("", OnboardingFailure::message)}
                </p>
                <OnboardingAddressPanel step=step set_step=set_step set_failure=set_failure />
                <OnboardingChallengePanel step=step set_step=set_step set_failure=set_failure />
                <OnboardingCredentialPanel step=step set_step=set_step set_failure=set_failure />
                <OnboardingEnrolledPanel step=step set_step=set_step />
            </section>
        }
    }

    #[component]
    fn OnboardingAddressPanel(
        step: ReadSignal<OnboardingStep>,
        set_step: WriteSignal<OnboardingStep>,
        set_failure: WriteSignal<Option<OnboardingFailure>>,
    ) -> impl IntoView {
        let (draft, set_draft) = signal(String::new());
        let (error, set_error) = signal(None::<EndpointAddressDraftError>);
        let (in_flight, set_in_flight) = signal(false);

        let on_input = move |event| {
            set_draft.set(event_target_value(&event));
            set_error.set(endpoint_address_draft_error(&draft.get()).err());
            set_failure.set(None);
        };

        let on_begin = Callback::new(move |()| {
            if let Err(error) = endpoint_address_draft_error(&draft.get()) {
                set_error.set(Some(error));
                return;
            }
            set_error.set(None);
            set_failure.set(None);
            set_in_flight.set(true);
            let address = draft.get();
            spawn_local(async move {
                let outcome = match begin_endpoint_trust(&address).await {
                    Some(challenge) => {
                        set_step.set(OnboardingStep::Challenge(
                            TrustChallengeProjection::from_response(&challenge),
                        ));
                        None
                    }
                    None => Some(OnboardingFailure::TrustObservation),
                };
                set_failure.set(outcome);
                set_in_flight.set(false);
            });
        });

        view! {
            <div class="form-panel" hidden=move || !step.get().is_address()>
                <div class="form-field">
                    <label for="endpoint-address">"Endpoint address"</label>
                    <input
                        id="endpoint-address"
                        class="form-input"
                        type="text"
                        autocomplete="off"
                        placeholder="https://bmc.example.test"
                        prop:value=move || draft.get()
                        on:input=on_input
                    />
                    <p class="form-error" hidden=move || error.get().is_none()>
                        {move || error.get().map_or("", EndpointAddressDraftError::message)}
                    </p>
                </div>
                <p class="form-hint">
                    "Rutilus first observes the TLS identity without credentials. No secret is sent before trust is confirmed."
                </p>
                <div class="form-actions">
                    <button
                        type="button"
                        class="btn btn-primary"
                        disabled=move || in_flight.get()
                        on:click=move |_| on_begin.run(())
                    >
                        "Observe TLS identity"
                    </button>
                </div>
            </div>
        }
    }

    #[component]
    fn OnboardingChallengePanel(
        step: ReadSignal<OnboardingStep>,
        set_step: WriteSignal<OnboardingStep>,
        set_failure: WriteSignal<Option<OnboardingFailure>>,
    ) -> impl IntoView {
        let (in_flight, set_in_flight) = signal(false);
        let challenge = move || step.get().challenge_projection().cloned();
        let state_class = move || {
            if challenge().is_some_and(|challenge| challenge.is_system_ca_trusted()) {
                "trust-state trust-state-ok"
            } else {
                "trust-state trust-state-warn"
            }
        };

        let on_confirm = Callback::new(move |()| {
            let step_snapshot = step.get();
            let Some(projection) = step_snapshot.challenge_projection() else {
                return;
            };
            let projection = projection.clone();
            let address = projection.address.clone();
            let expectation = projection.expectation();
            set_failure.set(None);
            set_in_flight.set(true);
            spawn_local(async move {
                let outcome = match confirm_endpoint_trust(&address, &expectation).await {
                    Some(()) => {
                        set_step.set(OnboardingStep::Credential {
                            address,
                            trust: expectation,
                        });
                        None
                    }
                    None => Some(OnboardingFailure::TrustExpectationRejected),
                };
                set_failure.set(outcome);
                set_in_flight.set(false);
            });
        });

        let on_back = Callback::new(move |()| {
            set_step.set(OnboardingStep::Address);
            set_failure.set(None);
            set_in_flight.set(false);
        });

        view! {
            <div class="form-panel" hidden=move || !step.get().is_challenge()>
                <div class="fingerprint-panel">
                    <p class="section-label">"TLS identity observed"</p>
                    <dl class="resource-facts">
                        <div>
                            <dt>"Address"</dt>
                            <dd>{move || challenge().map(|challenge| challenge.address)}</dd>
                        </div>
                        <div>
                            <dt>"Observed at"</dt>
                            <dd>{move || challenge().map(|challenge| challenge.observed_at_text())}</dd>
                        </div>
                    </dl>
                    <p class=state_class>
                        <span class="status-dot status-dot-waiting" aria-hidden="true"></span>
                        {move || challenge().map_or("", |challenge| challenge.state_label())}
                    </p>
                    <p class="section-label">"SHA-256 fingerprint"</p>
                    <code class="fingerprint-block">
                        {move || challenge().map(|challenge| challenge.fingerprint_sha256)}
                    </code>
                </div>
                <p class="form-hint">
                    "No credential has been sent to this device. Confirm the identity to record the trust decision before authentication."
                </p>
                <div class="form-actions">
                    <button
                        type="button"
                        class="btn"
                        disabled=move || in_flight.get()
                        on:click=move |_| on_back.run(())
                    >
                        "Back"
                    </button>
                    <button
                        type="button"
                        class="btn btn-primary"
                        disabled=move || in_flight.get()
                        on:click=move |_| on_confirm.run(())
                    >
                        "Confirm trust and continue"
                    </button>
                </div>
            </div>
        }
    }

    #[component]
    fn OnboardingCredentialPanel(
        step: ReadSignal<OnboardingStep>,
        set_step: WriteSignal<OnboardingStep>,
        set_failure: WriteSignal<Option<OnboardingFailure>>,
    ) -> impl IntoView {
        let (choice_state, set_choice_state) = signal(OnboardingCredentialsState::Idle);
        let (choice_triggered, set_choice_triggered) = signal(false);
        let (enrollment_draft, set_enrollment_draft) = signal(EnrollmentDraft::new());
        let (enrollment_error, set_enrollment_error) = signal(None::<EnrollmentDraftError>);
        let (create_mode, set_create_mode) = signal(false);
        let (in_flight, set_in_flight) = signal(false);

        Effect::new(move |_| {
            if step.get().is_credential() && !choice_triggered.get() {
                set_choice_triggered.set(true);
                set_choice_state.set(OnboardingCredentialsState::Loading);
                spawn_local(async move {
                    let state = match fetch_credentials().await {
                        Some(inventory) => OnboardingCredentialsState::Ready(inventory),
                        None => OnboardingCredentialsState::Failed,
                    };
                    if state.is_failed() {
                        set_failure.set(Some(OnboardingFailure::CredentialsUnavailable));
                    }
                    set_choice_state.set(state);
                });
            }
        });

        let on_display_name_input = move |event| {
            set_enrollment_draft.update(|draft| {
                draft.display_name = event_target_value(&event);
            });
            set_enrollment_error.set(enrollment_draft.get().validate().err());
        };

        let on_select = Callback::new(move |summary: CredentialSummaryResponse| {
            set_enrollment_draft.update(|draft| draft.credential = Some(summary));
            set_enrollment_error.set(None);
        });

        let on_inventory_changed = Callback::new(move |()| {
            set_choice_state.set(OnboardingCredentialsState::Loading);
            spawn_local(async move {
                let state = match fetch_credentials().await {
                    Some(inventory) => OnboardingCredentialsState::Ready(inventory),
                    None => OnboardingCredentialsState::Failed,
                };
                set_choice_state.set(state);
            });
        });

        let on_enroll = Callback::new(move |()| {
            let draft = enrollment_draft.get();
            if let Err(error) = draft.validate() {
                set_enrollment_error.set(Some(error));
                return;
            }
            set_enrollment_error.set(None);
            let step_snapshot = step.get();
            let Some((address, trust)) = step_snapshot.credential_plan() else {
                return;
            };
            let address = address.to_owned();
            let trust = trust.clone();
            let Some(credential) = draft.credential else {
                return;
            };
            set_failure.set(None);
            set_in_flight.set(true);
            spawn_local(async move {
                let outcome =
                    match enroll_endpoint(&draft.display_name, &address, &trust, &credential).await
                    {
                        Some(enrollment) => {
                            set_step.set(OnboardingStep::Enrolled(enrollment));
                            None
                        }
                        None => Some(OnboardingFailure::EnrollmentRejected),
                    };
                set_failure.set(outcome);
                set_in_flight.set(false);
            });
        });

        let on_back = Callback::new(move |()| {
            set_step.set(OnboardingStep::Address);
            set_failure.set(None);
            set_in_flight.set(false);
        });

        view! {
            <div class="form-panel" hidden=move || !step.get().is_credential()>
                <div class="fingerprint-panel">
                    <p class="section-label">"Established trust"</p>
                    <p class="endpoint-address">
                        {move || {
                            step.get()
                                .credential_plan()
                                .map(|(address, _)| address.to_owned())
                        }}
                    </p>
                    <span class="trust-badge">
                        {move || {
                            step.get()
                                .credential_plan()
                                .map_or("", |(_, trust)| trust_mode_label(trust))
                        }}
                    </span>
                </div>
                <div class="form-field">
                    <label for="enroll-display-name">"Display name"</label>
                    <input
                        id="enroll-display-name"
                        class="form-input"
                        type="text"
                        autocomplete="off"
                        prop:value=move || enrollment_draft.get().display_name
                        on:input=on_display_name_input
                    />
                    <p
                        class="form-error"
                        hidden=move || {
                            !matches!(
                                enrollment_error.get(),
                                Some(EnrollmentDraftError::DisplayName(_))
                            )
                        }
                    >
                        {move || match enrollment_error.get() {
                            Some(EnrollmentDraftError::DisplayName(error)) => error.message(),
                            _ => "",
                        }}
                    </p>
                </div>
                <p class="section-label">"Credential"</p>
                <p class="form-hint">
                    "Choose an existing credential or create a new one. Credentials are encrypted before they are stored."
                </p>
                <div class="credential-choice-grid">
                    {move || {
                        let Some(credentials) = choice_state.get().ready_credentials() else {
                            return Vec::new();
                        };
                        let selected = enrollment_draft.get().credential;
                        credentials
                            .into_iter()
                            .map(|summary| {
                                let card = CredentialCardProjection::from(&summary);
                                let is_selected = selected.as_ref() == Some(&summary);
                                let class = if is_selected {
                                    "credential-choice is-selected"
                                } else {
                                    "credential-choice"
                                };
                                view! {
                                    <button
                                        type="button"
                                        class=class
                                        on:click=move |_| on_select.run(summary.clone())
                                    >
                                        <span class="credential-choice-name">{card.name}</span>
                                        <span class="credential-choice-username">
                                            {card.username}
                                        </span>
                                    </button>
                                }
                            })
                            .collect_view()
                    }}
                </div>
                <div class="form-actions">
                    <button
                        type="button"
                        class="btn"
                        hidden=move || {
                            create_mode.get()
                                || choice_state.get().has_empty_inventory()
                        }
                        on:click=move |_| set_create_mode.set(true)
                    >
                        "Create a new credential"
                    </button>
                </div>
                <div
                    class="form-panel create-panel"
                    hidden=move || {
                        !(create_mode.get() || choice_state.get().has_empty_inventory())
                    }
                >
                    <InlineCredentialCreate
                        dismissible=move || !choice_state.get().has_empty_inventory()
                        set_create_mode=set_create_mode
                        on_selected=on_select
                        on_inventory_changed=on_inventory_changed
                        on_failed=Callback::new(move |()| {
                            set_failure.set(Some(OnboardingFailure::CredentialCreateRejected));
                        })
                    />
                </div>
                <div class="form-actions">
                    <button
                        type="button"
                        class="btn"
                        disabled=move || in_flight.get()
                        on:click=move |_| on_back.run(())
                    >
                        "Back"
                    </button>
                    <button
                        type="button"
                        class="btn btn-primary"
                        disabled=move || {
                            in_flight.get()
                                || enrollment_draft.get().validate().is_err()
                        }
                        on:click=move |_| on_enroll.run(())
                    >
                        "Enroll endpoint"
                    </button>
                </div>
                <p
                    class="form-error"
                    hidden=move || {
                        !matches!(
                            enrollment_error.get(),
                            Some(EnrollmentDraftError::CredentialRequired)
                        )
                    }
                >
                    {EnrollmentDraftError::CredentialRequired.message()}
                </p>
            </div>
        }
    }

    #[component]
    fn InlineCredentialCreate(
        dismissible: impl Fn() -> bool + Send + 'static,
        set_create_mode: WriteSignal<bool>,
        on_selected: Callback<CredentialSummaryResponse>,
        on_inventory_changed: Callback<()>,
        on_failed: Callback<()>,
    ) -> impl IntoView {
        let (draft, set_draft) = signal(CredentialDraft::new());
        let (error, set_error) = signal(None::<CredentialDraftError>);
        let (create_state, set_create_state) = signal(CreateCredentialState::Idle);

        let on_changed = Callback::new(move |()| {
            set_create_state.set(CreateCredentialState::Idle);
        });

        let on_submit = Callback::new(move |()| {
            if let Err(error) = draft.get().validate() {
                set_error.set(Some(error));
                return;
            }
            set_error.set(None);
            set_create_state.set(CreateCredentialState::InFlight);
            let submitted = draft.get();
            spawn_local(async move {
                let created = if let Some(summary) = post_credential(&submitted).await {
                    on_selected.run(summary);
                    true
                } else {
                    on_failed.run(());
                    false
                };
                if created {
                    set_draft.set(CredentialDraft::new());
                    set_error.set(None);
                    set_create_mode.set(false);
                    on_inventory_changed.run(());
                    set_create_state.set(CreateCredentialState::Created);
                }
            });
        });

        view! {
            <div>
                <p class="section-label">"New credential"</p>
                <CredentialDraftForm
                    draft=draft
                    set_draft=set_draft
                    error=error
                    set_error=set_error
                    field_id_prefix="inline-credential"
                    submit_label="Create and select"
                    submit_disabled=move || create_state.get() == CreateCredentialState::InFlight
                    on_changed=on_changed
                    on_submit=on_submit
                />
                <p
                    class="inline-status success"
                    hidden=move || create_state.get() != CreateCredentialState::Created
                >
                    "Credential created and selected."
                </p>
                <div class="form-actions" hidden=move || !dismissible()>
                    <button
                        type="button"
                        class="btn"
                        on:click=move |_| set_create_mode.set(false)
                    >
                        "Cancel"
                    </button>
                </div>
            </div>
        }
    }

    #[component]
    fn OnboardingEnrolledPanel(
        step: ReadSignal<OnboardingStep>,
        set_step: WriteSignal<OnboardingStep>,
    ) -> impl IntoView {
        let enrollment = move || step.get().enrollment().cloned();

        let on_add_another = Callback::new(move |()| {
            set_step.set(OnboardingStep::Address);
        });

        view! {
            <div class="form-panel" hidden=move || !step.get().is_enrolled()>
                <p class="section-label">"Enrollment complete"</p>
                <h3>"Endpoint enrolled"</h3>
                <p class="form-hint">
                    "The first complete core-resource refresh succeeded during enrollment."
                </p>
                <dl class="resource-facts">
                    <div>
                        <dt>"Endpoint ID"</dt>
                        <dd>{move || enrollment().map(|e| e.endpoint_id().to_string())}</dd>
                    </div>
                    <div>
                        <dt>"Initial generation"</dt>
                        <dd>{move || enrollment().map(|e| e.initial_generation().get().to_string())}</dd>
                    </div>
                    <div>
                        <dt>"Systems"</dt>
                        <dd>{move || enrollment().map(|e| e.resource_counts().systems().to_string())}</dd>
                    </div>
                    <div>
                        <dt>"Chassis"</dt>
                        <dd>{move || enrollment().map(|e| e.resource_counts().chassis().to_string())}</dd>
                    </div>
                    <div>
                        <dt>"Managers"</dt>
                        <dd>{move || enrollment().map(|e| e.resource_counts().managers().to_string())}</dd>
                    </div>
                </dl>
                <div class="form-actions">
                    <button
                        type="button"
                        class="btn btn-primary"
                        on:click=move |_| on_add_another.run(())
                    >
                        "Add another endpoint"
                    </button>
                </div>
            </div>
        }
    }

    #[component]
    fn ImportView(view: ReadSignal<ConsoleView>) -> impl IntoView {
        let active = move || view.get() == ConsoleView::Import;
        let (file_name, set_file_name) = signal(None::<String>);
        let (csv_text, set_csv_text) = signal(None::<String>);
        let (file_error, set_file_error) = signal(None::<ImportFailure>);
        let (import_state, set_import_state) = signal(ImportState::Idle);

        let on_file_change = move |event: Event| {
            let Some(input) = event
                .target()
                .and_then(|target| target.dyn_into::<HtmlInputElement>().ok())
            else {
                return;
            };
            let Some(file) = input_files(&input) else {
                return;
            };
            set_file_error.set(None);
            set_import_state.set(ImportState::Idle);
            let file_name = selected_file_name(&file);
            let future = JsFuture::from(file.text());
            spawn_local(async move {
                let text = match future.await {
                    Ok(value) => value.as_string(),
                    Err(_) => None,
                };
                match text {
                    Some(text) if !text.trim().is_empty() => {
                        set_file_name.set(Some(file_name));
                        set_csv_text.set(Some(text));
                    }
                    Some(_) => set_file_error.set(Some(ImportFailure::FileEmpty)),
                    None => set_file_error.set(Some(ImportFailure::FileUnreadable)),
                }
            });
        };

        let on_import = move |_| {
            let Some(csv) = csv_text.get() else {
                return;
            };
            set_file_error.set(None);
            set_import_state.set(ImportState::InFlight);
            spawn_local(async move {
                let state = match post_endpoint_csv_import(&csv).await {
                    Ok(report) => ImportState::Ready(report),
                    Err(failure) => ImportState::Failed(failure),
                };
                set_import_state.set(state);
            });
        };

        view! {
            <section class="view-section" hidden=move || !active()>
                <div class="inventory-heading">
                    <div>
                        <p class="section-label">"Bulk onboarding"</p>
                        <h2>"Import endpoints"</h2>
                    </div>
                    <p>"One row per BMC: display_name, address, credential_id, tls_sha256"</p>
                </div>
                <div class="form-panel">
                    <div class="form-field">
                        <label for="import-file">"CSV file"</label>
                        <input
                            id="import-file"
                            class="form-input"
                            type="file"
                            accept=".csv,text/csv"
                            on:change=on_file_change
                        />
                    </div>
                    <p class="form-hint" hidden=move || file_name.get().is_none()>
                        {move || {
                            file_name
                                .get()
                                .map_or_else(String::new, |name| format!("Selected: {name}"))
                        }}
                    </p>
                    <p class="form-error" hidden=move || file_error.get().is_none()>
                        {move || {
                            file_error
                                .get()
                                .map_or_else(String::new, |failure| failure.message())
                        }}
                    </p>
                    <div class="form-actions">
                        <button
                            type="button"
                            class="btn btn-primary"
                            disabled=move || {
                                csv_text.get().is_none()
                                    || matches!(import_state.get(), ImportState::InFlight)
                            }
                            on:click=on_import
                        >
                            "Import CSV"
                        </button>
                    </div>
                </div>
                <div
                    class="form-panel result-panel"
                    hidden=move || !matches!(import_state.get(), ImportState::Ready(_))
                >
                    <p class="section-label">"Import report"</p>
                    <p class="inline-status success">
                        {move || match import_state.get() {
                            ImportState::Ready(report) => report.summary_text(),
                            _ => String::new(),
                        }}
                    </p>
                    <table class="results-table">
                        <thead>
                            <tr>
                                <th>"Row"</th>
                                <th>"Address"</th>
                                <th>"Result"</th>
                                <th>"Detail"</th>
                            </tr>
                        </thead>
                        <tbody>
                            {move || {
                                let ImportState::Ready(report) = import_state.get() else {
                                    return Vec::new();
                                };
                                report
                                    .rows
                                    .into_iter()
                                    .map(|row| {
                                        let result_class = if row.is_success {
                                            "result-success"
                                        } else {
                                            "result-failure"
                                        };
                                        view! {
                                            <tr>
                                                <td>{row.record_number}</td>
                                                <td class="result-address">{row.address}</td>
                                                <td class=result_class>{row.status_label}</td>
                                                <td class="result-detail">
                                                    {move || row.detail.clone()}
                                                </td>
                                            </tr>
                                        }
                                    })
                                    .collect_view()
                            }}
                        </tbody>
                    </table>
                </div>
                <p
                    class="form-error"
                    hidden=move || !matches!(import_state.get(), ImportState::Failed(_))
                >
                    {move || match import_state.get() {
                        ImportState::Failed(failure) => failure.message(),
                        _ => String::new(),
                    }}
                </p>
            </section>
        }
    }

    #[component]
    fn AuditView(view: ReadSignal<ConsoleView>) -> impl IntoView {
        let active = move || view.get() == ConsoleView::Audit;
        let (state, set_state) = signal(AuditListState::Idle);
        let (triggered, set_triggered) = signal(false);

        Effect::new(move |_| {
            if active() && !triggered.get() {
                set_triggered.set(true);
                set_state.set(AuditListState::Loading);
                spawn_local(async move {
                    let state = match fetch_audit().await {
                        Some(query) => AuditListState::Ready(query),
                        None => AuditListState::Failed,
                    };
                    set_state.set(state);
                });
            }
        });

        let on_refresh = move |_| {
            set_state.set(AuditListState::Loading);
            spawn_local(async move {
                let state = match fetch_audit().await {
                    Some(query) => AuditListState::Ready(query),
                    None => AuditListState::Failed,
                };
                set_state.set(state);
            });
        };

        view! {
            <section class="view-section" hidden=move || !active()>
                <div class="inventory-heading">
                    <div>
                        <p class="section-label">"Compliance"</p>
                        <h2>{move || state.get().count_text()}</h2>
                    </div>
                    <p>"Immutable secret-free records, newest first"</p>
                </div>
                <p
                    class="empty-inventory"
                    hidden=move || {
                        !state.get().is_ready()
                            || !state.get().has_empty_events()
                    }
                >
                    "No audit events have been recorded yet."
                </p>
                <div class="resource-list">
                    {move || {
                        state
                            .get()
                            .event_cards()
                            .into_iter()
                            .map(|card| view! { <AuditEventCard card=card /> })
                            .collect_view()
                    }}
                </div>
                <div class="inventory-actions">
                    <button
                        type="button"
                        class="btn"
                        disabled=move || state.get().is_loading()
                        hidden=move || {
                            !state.get().is_ready() && !state.get().is_failed()
                        }
                        on:click=on_refresh
                    >
                        "Refresh"
                    </button>
                </div>
                <p class="form-error" hidden=move || !state.get().is_failed()>
                    "The audit log is temporarily unavailable."
                </p>
            </section>
        }
    }

    #[component]
    fn AuditEventCard(card: AuditEventCardProjection) -> impl IntoView {
        let AuditEventCardProjection {
            occurred_at_text,
            actor,
            action,
            target_kind,
            target_identifier,
            outcome_kind,
            outcome_detail,
            sequence,
            operation_id,
            message,
        } = card;
        let outcome_class = match outcome_kind.as_str() {
            "succeeded" => "result-success",
            "failed" => "result-failure",
            _ => "result-neutral",
        };

        view! {
            <article class="credential-card">
                <div class="credential-title">
                    <div>
                        <h3>{action}</h3>
                        <p class="credential-username">
                            {occurred_at_text}
                            <span class="audit-actor">" · "{actor}</span>
                        </p>
                    </div>
                    <span class="trust-badge">{outcome_kind}</span>
                </div>
                <p class="audit-message">{message}</p>
                <dl class="resource-facts">
                    <div>
                        <dt>"Target"</dt>
                        <dd>{target_kind}</dd>
                    </div>
                    <div>
                        <dt>"Target ID"</dt>
                        <dd>{target_identifier}</dd>
                    </div>
                    <div>
                        <dt>"Outcome"</dt>
                        <dd class=outcome_class>{outcome_detail}</dd>
                    </div>
                    <div>
                        <dt>"Sequence"</dt>
                        <dd>{sequence}</dd>
                    </div>
                    <div>
                        <dt>"Operation"</dt>
                        <dd>{operation_id}</dd>
                    </div>
                </dl>
            </article>
        }
    }

    async fn fetch_audit() -> Option<AuditQueryResponse> {
        let response = Request::get("/api/v1/audit")
            .header("Accept", "application/json")
            .send()
            .await
            .ok()?;
        if !response.ok() {
            return None;
        }
        response.json::<AuditQueryResponse>().await.ok()
    }

    async fn fetch_credentials() -> Option<CredentialInventoryResponse> {
        let response = Request::get("/api/v1/credentials")
            .header("Accept", "application/json")
            .send()
            .await
            .ok()?;
        if !response.ok() {
            return None;
        }
        response.json::<CredentialInventoryResponse>().await.ok()
    }

    async fn post_credential(draft: &CredentialDraft) -> Option<CredentialSummaryResponse> {
        let request = CreateCredentialRequest::new(
            draft.name.trim().to_owned(),
            draft.username.clone(),
            draft.password.clone().into(),
        );
        let response = Request::post("/api/v1/credentials")
            .json(&request)
            .ok()?
            .send()
            .await
            .ok()?;
        if !response.ok() {
            return None;
        }
        response.json::<CredentialSummaryResponse>().await.ok()
    }

    async fn begin_endpoint_trust(address: &str) -> Option<EndpointTrustChallengeResponse> {
        let request = BeginEndpointTrustRequest::new(address.to_owned());
        let response = Request::post("/api/v1/endpoints/trust")
            .json(&request)
            .ok()?
            .send()
            .await
            .ok()?;
        if !response.ok() {
            return None;
        }
        response.json::<EndpointTrustChallengeResponse>().await.ok()
    }

    async fn confirm_endpoint_trust(
        address: &str,
        trust: &EndpointTrustExpectationRequest,
    ) -> Option<()> {
        let request = ConfirmEndpointTrustRequest::new(address.to_owned(), trust.clone());
        let response = Request::post("/api/v1/endpoints/trust/expect")
            .json(&request)
            .ok()?
            .send()
            .await
            .ok()?;
        if !response.ok() {
            return None;
        }
        response
            .json::<TrustedEndpointResponse>()
            .await
            .ok()
            .map(|_| ())
    }

    async fn enroll_endpoint(
        display_name: &str,
        address: &str,
        trust: &EndpointTrustExpectationRequest,
        credential: &CredentialSummaryResponse,
    ) -> Option<EndpointEnrollmentResponse> {
        let request = EnrollEndpointRequest::new(
            display_name.to_owned(),
            address.to_owned(),
            trust.clone(),
            credential.credential_id(),
        );
        let response = Request::post("/api/v1/endpoints")
            .json(&request)
            .ok()?
            .send()
            .await
            .ok()?;
        if !response.ok() {
            return None;
        }
        response.json::<EndpointEnrollmentResponse>().await.ok()
    }

    async fn post_endpoint_csv_import(
        csv: &str,
    ) -> Result<CsvImportReportProjection, ImportFailure> {
        let request = EndpointCsvImportRequest::new(csv.to_owned());
        let response = Request::post("/api/v1/endpoints/import")
            .json(&request)
            .map_err(|_| ImportFailure::Unavailable)?
            .send()
            .await
            .map_err(|_| ImportFailure::Unavailable)?;
        if !response.ok() {
            return Err(ImportFailure::Rejected {
                status: response.status(),
            });
        }
        let report = response
            .json::<EndpointCsvImportResponse>()
            .await
            .map_err(|_| ImportFailure::MalformedReport)?;
        Ok(CsvImportReportProjection::from_response(&report))
    }

    /// Reads the first selected file of a file input as a `Blob`.
    ///
    /// The workspace `web-sys` feature set does not enable the `FileList` and
    /// `File` types, so the minimal property access is bound locally. A `File`
    /// is a `Blob`, which the enabled feature set already covers.
    fn input_files(input: &HtmlInputElement) -> Option<Blob> {
        let files = input_files_list(input)?;
        let first = files.item(0);
        if !first.is_object() {
            return None;
        }
        first.dyn_into::<Blob>().ok()
    }

    /// Opaque handle to a browser `FileList` selection.
    #[wasm_bindgen]
    extern "C" {
        #[wasm_bindgen(typescript_type = "HTMLInputElement")]
        type FileInputHandle;

        #[wasm_bindgen(
            method,
            structural,
            getter,
            js_class = "HTMLInputElement",
            js_name = "files"
        )]
        fn files(this: &FileInputHandle) -> JsValue;

        #[wasm_bindgen(typescript_type = "FileList")]
        type FileListHandle;

        #[wasm_bindgen(method, structural, js_class = "FileList", js_name = "item")]
        fn item(this: &FileListHandle, index: u32) -> JsValue;

        #[wasm_bindgen(typescript_type = "File")]
        type FileHandle;

        #[wasm_bindgen(method, structural, getter, js_class = "File", js_name = "name")]
        fn name(this: &FileHandle) -> String;
    }

    fn input_files_list(input: &HtmlInputElement) -> Option<FileListHandle> {
        let files = input.unchecked_ref::<FileInputHandle>().files();
        if !files.is_object() {
            return None;
        }
        files.dyn_into::<FileListHandle>().ok()
    }

    fn selected_file_name(file: &Blob) -> String {
        file.unchecked_ref::<FileHandle>().name()
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use serde_json::json;

    use super::*;

    fn about(product: &str) -> AboutResponse {
        AboutResponse::new(
            product.to_owned(),
            "0.1.0-test".to_owned(),
            "0.13.0-test".to_owned(),
        )
    }

    fn inventory() -> Result<EndpointInventoryResponse, serde_json::Error> {
        serde_json::from_value(json!({
            "endpoints": [
                {
                    "identity": {
                        "endpoint_id": "01989abc-def0-7abc-8def-0123456789ab",
                        "display_name": "Rack A BMC",
                        "address": "https://192.0.2.10/",
                        "tls_trust_mode": "system_ca",
                        "created_at": "2026-08-05T09:10:11Z",
                        "updated_at": "2026-08-05T09:10:11Z"
                    },
                    "snapshot": { "state": "awaiting_first_refresh" }
                },
                {
                    "identity": {
                        "endpoint_id": "01989abc-def0-7abc-8def-0123456789ac",
                        "display_name": "Rack B BMC",
                        "address": "https://192.0.2.11/",
                        "tls_trust_mode": "pinned_certificate",
                        "created_at": "2026-08-05T09:10:11Z",
                        "updated_at": "2026-08-05T09:12:13Z"
                    },
                    "snapshot": {
                        "state": "current",
                        "details": {
                            "generation": 7,
                            "last_successful_refresh_at": "2026-08-05T09:12:13Z",
                            "resource_counts": {
                                "systems": 1,
                                "chassis": 1,
                                "managers": 1
                            }
                        }
                    }
                }
            ]
        }))
    }

    fn resource_inventories() -> Result<Vec<EndpointResourceInventoryResponse>, serde_json::Error> {
        resource_inventories_with_current_address("https://192.0.2.11/")
    }

    fn resource_inventories_with_current_address(
        current_address: &str,
    ) -> Result<Vec<EndpointResourceInventoryResponse>, serde_json::Error> {
        serde_json::from_value(json!([
            {
                "endpoint": {
                    "endpoint_id": "01989abc-def0-7abc-8def-0123456789ab",
                    "display_name": "Rack A BMC",
                    "address": "https://192.0.2.10/",
                    "tls_trust_mode": "system_ca",
                    "created_at": "2026-08-05T09:10:11Z",
                    "updated_at": "2026-08-05T09:10:11Z"
                },
                "snapshot": { "state": "awaiting_first_refresh" }
            },
            {
                "endpoint": {
                    "endpoint_id": "01989abc-def0-7abc-8def-0123456789ac",
                    "display_name": "Rack B BMC",
                    "address": current_address,
                    "tls_trust_mode": "pinned_certificate",
                    "created_at": "2026-08-05T09:10:11Z",
                    "updated_at": "2026-08-05T09:12:13Z"
                },
                "snapshot": {
                    "state": "current",
                    "details": {
                        "generation": 7,
                        "observed_at": "2026-08-05T09:12:13Z",
                        "resources": [
                            service_root_resource(),
                            system_resource(),
                            chassis_resource(),
                            manager_resource()
                        ]
                    }
                }
            }
        ]))
    }

    fn service_root_resource() -> serde_json::Value {
        json!({
            "source": {
                "resource_id": "01989abc-def0-7abc-8def-0123456789d0",
                "odata_id": "/redfish/v1",
                "odata_type": "#ServiceRoot.v1_15_0.ServiceRoot",
                "etag": "W/\"root-7\""
            },
            "common": {
                "id": "RootService",
                "name": "Root Service",
                "description": "Redfish service root"
            },
            "resource": {
                "resource_type": "service_root",
                "details": {
                    "vendor": "Vendor A",
                    "product": "BMC Platform",
                    "redfish_version": "1.20.0"
                }
            }
        })
    }

    fn system_resource() -> serde_json::Value {
        json!({
            "source": {
                "resource_id": "01989abc-def0-7abc-8def-0123456789d1",
                "odata_id": "/redfish/v1/Systems/1",
                "odata_type": "#ComputerSystem.v1_20_0.ComputerSystem",
                "etag": "W/\"system-7\""
            },
            "common": {
                "id": "1",
                "name": "Compute One",
                "description": "Primary compute system"
            },
            "resource": {
                "resource_type": "system",
                "details": {
                    "system_type": "Physical",
                    "manufacturer": "Vendor A",
                    "model": "Model S",
                    "part_number": "SYS-PART-1",
                    "serial_number": "SYS-1",
                    "sku": "SYS-SKU-1",
                    "host_name": "compute-1",
                    "bios_version": "2.3.4",
                    "power_state": "On",
                    "status": {
                        "state": "Enabled",
                        "health": "OK",
                        "health_rollup": "Warning"
                    }
                }
            }
        })
    }

    fn chassis_resource() -> serde_json::Value {
        json!({
            "source": {
                "resource_id": "01989abc-def0-7abc-8def-0123456789d2",
                "odata_id": "/redfish/v1/Chassis/1",
                "odata_type": "#Chassis.v1_25_0.Chassis",
                "etag": null
            },
            "common": {
                "id": "1",
                "name": "Main Chassis",
                "description": null
            },
            "resource": {
                "resource_type": "chassis",
                "details": {
                    "chassis_type": "RackMount",
                    "manufacturer": "Vendor A",
                    "model": "Model C",
                    "part_number": "CHA-PART-1",
                    "serial_number": "CHA-1",
                    "sku": "CHA-SKU-1",
                    "asset_tag": "RACK-B-01",
                    "power_state": "On",
                    "status": {
                        "state": "Enabled",
                        "health": "OK",
                        "health_rollup": "OK"
                    }
                }
            }
        })
    }

    fn manager_resource() -> serde_json::Value {
        json!({
            "source": {
                "resource_id": "01989abc-def0-7abc-8def-0123456789d3",
                "odata_id": "/redfish/v1/Managers/1",
                "odata_type": "#Manager.v1_20_0.Manager",
                "etag": null
            },
            "common": {
                "id": "1",
                "name": "BMC Manager",
                "description": "Primary management controller"
            },
            "resource": {
                "resource_type": "manager",
                "details": {
                    "manager_type": "BMC",
                    "manufacturer": "Vendor A",
                    "model": "Model M",
                    "part_number": "MGR-PART-1",
                    "serial_number": "MGR-1",
                    "firmware_version": "4.5.6",
                    "version": "1.2.3",
                    "power_state": "On",
                    "status": {
                        "state": "Enabled",
                        "health": "OK",
                        "health_rollup": null
                    }
                }
            }
        })
    }

    #[test]
    fn projects_loading_ready_and_typed_failures_without_dynamic_error_text()
    -> Result<(), Box<dyn Error>> {
        let loading = ConsoleLoadState::Loading;
        let ready =
            ConsoleLoadState::accepted(about(PRODUCT_ID), inventory()?, resource_inventories()?);
        let metadata_failed = ConsoleLoadState::Failed(ConsoleLoadFailure::ProductMetadata);
        let inventory_failed = ConsoleLoadState::Failed(ConsoleLoadFailure::EndpointInventory);
        let resources_failed = ConsoleLoadState::Failed(ConsoleLoadFailure::EndpointResources);

        assert_eq!(
            loading.status_message(),
            "Starting the local management console..."
        );
        assert!(!loading.is_ready());
        assert!(ready.is_ready());
        assert_eq!(ready.status_message(), "Authenticated local inventory");
        assert_eq!(ready.product_version_text(), "0.1.0-test");
        assert_eq!(ready.nv_redfish_baseline_text(), "0.13.0-test");
        assert_eq!(ready.endpoint_count_text(), "2 managed endpoints");
        assert!(!ready.has_empty_inventory());
        assert_eq!(
            metadata_failed.status_message(),
            "The local console could not verify product metadata."
        );
        assert_eq!(
            inventory_failed.status_message(),
            "The endpoint inventory is temporarily unavailable."
        );
        assert_eq!(
            resources_failed.status_message(),
            "Core resource details are temporarily unavailable."
        );
        assert!(metadata_failed.endpoint_cards().is_empty());
        Ok(())
    }

    #[test]
    fn projects_only_complete_resource_generations() -> Result<(), Box<dyn Error>> {
        let state =
            ConsoleLoadState::accepted(about(PRODUCT_ID), inventory()?, resource_inventories()?);
        let cards = state.endpoint_cards();
        let waiting = cards.first().ok_or("waiting endpoint must exist")?;
        let current = cards.get(1).ok_or("current endpoint must exist")?;

        assert_eq!(waiting.display_name, "Rack A BMC");
        assert_eq!(waiting.trust_label, "System CA");
        assert_eq!(waiting.snapshot_label, "Awaiting first refresh");
        assert_eq!(waiting.resource_counts, None);
        assert_eq!(current.address, "https://192.0.2.11/");
        assert_eq!(current.trust_label, "Pinned certificate");
        assert_eq!(
            current.snapshot_label,
            "Generation 7 · observed 2026-08-05T09:12:13Z"
        );
        assert_eq!(
            current.resource_counts,
            Some(ResourceCountsProjection {
                systems: 1,
                chassis: 1,
                managers: 1,
            })
        );
        assert!(waiting.resources.is_empty());
        assert_eq!(current.resources.len(), 4);
        let system = current
            .resources
            .iter()
            .find(|resource| resource.type_label == "System")
            .ok_or("system resource must exist")?;
        assert_eq!(system.name, "Compute One");
        assert_eq!(system.source, "/redfish/v1/Systems/1");
        assert!(system.facts.contains(&ResourceFactProjection {
            label: "Manufacturer",
            value: "Vendor A".to_owned(),
        }));
        assert!(system.facts.contains(&ResourceFactProjection {
            label: "BIOS version",
            value: "2.3.4".to_owned(),
        }));
        assert!(system.facts.contains(&ResourceFactProjection {
            label: "Health",
            value: "OK".to_owned(),
        }));
        Ok(())
    }

    #[test]
    fn accepts_empty_inventory_and_rejects_a_different_product_identity() {
        let empty = ConsoleLoadState::accepted(
            about(PRODUCT_ID),
            EndpointInventoryResponse::new(Vec::new()),
            Vec::new(),
        );
        assert!(empty.is_ready());
        assert!(empty.has_empty_inventory());
        assert_eq!(empty.endpoint_count_text(), "0 managed endpoints");
        assert_eq!(
            ConsoleLoadState::accepted(
                about("different-product"),
                EndpointInventoryResponse::new(Vec::new()),
                Vec::new()
            ),
            ConsoleLoadState::Failed(ConsoleLoadFailure::ProductMetadata)
        );
    }

    #[test]
    fn rejects_missing_or_duplicate_endpoint_resource_responses() -> Result<(), Box<dyn Error>> {
        assert_eq!(
            ConsoleLoadState::accepted(about(PRODUCT_ID), inventory()?, Vec::new()),
            ConsoleLoadState::Failed(ConsoleLoadFailure::EndpointResources)
        );

        let mut resources = resource_inventories()?;
        let duplicate = resources
            .first()
            .ok_or("first endpoint resources must exist")?
            .clone();
        let second = resources
            .get_mut(1)
            .ok_or("second endpoint resources must exist")?;
        *second = duplicate;
        assert_eq!(
            ConsoleLoadState::accepted(about(PRODUCT_ID), inventory()?, resources),
            ConsoleLoadState::Failed(ConsoleLoadFailure::EndpointResources)
        );
        assert_eq!(
            ConsoleLoadState::accepted(
                about(PRODUCT_ID),
                inventory()?,
                resource_inventories_with_current_address("https://192.0.2.99/")?
            ),
            ConsoleLoadState::Failed(ConsoleLoadFailure::EndpointResources)
        );
        Ok(())
    }

    #[test]
    fn credential_draft_validation_mirrors_application_boundaries() {
        let valid = CredentialDraft {
            name: "Rack administrators".to_owned(),
            username: "administrator".to_owned(),
            password: "correct horse battery staple".to_owned(),
        };
        assert_eq!(valid.validate(), Ok(()));

        assert_eq!(
            CredentialDraft {
                name: "   ".to_owned(),
                ..valid.clone()
            }
            .validate(),
            Err(CredentialDraftError::NameRequired)
        );
        assert_eq!(
            CredentialDraft {
                name: "Bad\u{1}Name".to_owned(),
                ..valid.clone()
            }
            .validate(),
            Err(CredentialDraftError::NameControlCharacter)
        );
        assert_eq!(
            CredentialDraft {
                name: "界".repeat(MAX_CREDENTIAL_NAME_CHARS + 1),
                ..valid.clone()
            }
            .validate(),
            Err(CredentialDraftError::NameTooLong)
        );
        assert_eq!(
            CredentialDraft {
                username: "  ".to_owned(),
                ..valid.clone()
            }
            .validate(),
            Err(CredentialDraftError::UsernameRequired)
        );
        assert_eq!(
            CredentialDraft {
                username: "bad\u{1}user".to_owned(),
                ..valid.clone()
            }
            .validate(),
            Err(CredentialDraftError::UsernameControlCharacter)
        );
        assert_eq!(
            CredentialDraft {
                username: "u".repeat(MAX_CREDENTIAL_USERNAME_CHARS + 1),
                ..valid.clone()
            }
            .validate(),
            Err(CredentialDraftError::UsernameTooLong)
        );
        assert_eq!(
            CredentialDraft {
                password: String::new(),
                ..valid.clone()
            }
            .validate(),
            Err(CredentialDraftError::PasswordRequired)
        );
        assert_eq!(
            CredentialDraft {
                password: "x".repeat(MAX_CREDENTIAL_PASSWORD_BYTES + 1),
                ..valid.clone()
            }
            .validate(),
            Err(CredentialDraftError::PasswordTooLarge)
        );

        let rendered = format!("{valid:?}");
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains("correct horse battery staple"));
    }

    #[test]
    fn endpoint_address_draft_validation_mirrors_domain_rules() {
        assert_eq!(
            endpoint_address_draft_error("https://bmc.example.test:8443/redfish"),
            Ok(())
        );
        assert_eq!(
            endpoint_address_draft_error(""),
            Err(EndpointAddressDraftError::Required)
        );
        assert_eq!(
            endpoint_address_draft_error("   "),
            Err(EndpointAddressDraftError::Required)
        );
        assert_eq!(
            endpoint_address_draft_error("http://bmc.example.test"),
            Err(EndpointAddressDraftError::HttpsRequired)
        );
        assert_eq!(
            endpoint_address_draft_error("https://"),
            Err(EndpointAddressDraftError::HostRequired)
        );
        assert_eq!(
            endpoint_address_draft_error("https:///redfish"),
            Err(EndpointAddressDraftError::HostRequired)
        );
        assert_eq!(
            endpoint_address_draft_error("https://bmc.example.test/red fish"),
            Err(EndpointAddressDraftError::Whitespace)
        );
        assert_eq!(
            endpoint_address_draft_error("https://admin:secret@bmc.example.test"),
            Err(EndpointAddressDraftError::EmbeddedCredentials)
        );
        assert_eq!(
            endpoint_address_draft_error("https://bmc.example.test?raw=true"),
            Err(EndpointAddressDraftError::QueryOrFragmentNotAllowed)
        );
        assert_eq!(
            endpoint_address_draft_error("https://bmc.example.test#console"),
            Err(EndpointAddressDraftError::QueryOrFragmentNotAllowed)
        );
    }

    #[test]
    fn trust_challenge_projection_derives_the_exact_expectation() -> Result<(), Box<dyn Error>> {
        let observed_at = OffsetDateTime::parse("2026-08-05T10:11:12Z", &Rfc3339)?;
        let fingerprint =
            "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"
                .to_owned();
        let challenge =
            TrustChallengeProjection::from_response(&EndpointTrustChallengeResponse::new(
                "https://bmc.example.test/".to_owned(),
                fingerprint.clone(),
                observed_at,
                EndpointTrustChallengeStateResponse::ExplicitPinRequired,
            ));

        assert_eq!(challenge.address, "https://bmc.example.test/");
        assert_eq!(challenge.fingerprint_sha256, fingerprint);
        assert_eq!(challenge.observed_at_text(), "2026-08-05T10:11:12Z");
        assert!(!challenge.is_system_ca_trusted());
        assert_eq!(
            challenge.state_label(),
            "Not trusted by system CA roots; an explicit pin is required"
        );
        assert_eq!(
            challenge.expectation(),
            EndpointTrustExpectationRequest::pinned_certificate(fingerprint.clone())
        );

        let trusted =
            TrustChallengeProjection::from_response(&EndpointTrustChallengeResponse::new(
                "https://bmc.example.test/".to_owned(),
                fingerprint,
                observed_at,
                EndpointTrustChallengeStateResponse::SystemCaTrusted,
            ));
        assert!(trusted.is_system_ca_trusted());
        assert_eq!(trusted.state_label(), "Verified by system CA roots");
        assert_eq!(
            trusted.expectation(),
            EndpointTrustExpectationRequest::system_ca()
        );
        Ok(())
    }

    #[test]
    fn onboarding_steps_and_enrollment_drafts_reject_incomplete_inputs()
    -> Result<(), Box<dyn Error>> {
        let draft = EnrollmentDraft {
            display_name: "Rack A BMC".to_owned(),
            credential: Some(serde_json::from_value(json!({
                "credential_id": "01989abc-def0-7abc-8def-0123456789ce",
                "name": "Rack administrators",
                "username": "administrator",
                "created_at": "2026-08-05T10:12:13Z",
                "updated_at": "2026-08-05T10:12:13Z"
            }))?),
        };
        assert_eq!(draft.validate(), Ok(()));
        assert_eq!(
            EnrollmentDraft {
                display_name: String::new(),
                ..draft.clone()
            }
            .validate(),
            Err(EnrollmentDraftError::DisplayName(
                DisplayNameDraftError::Required
            ))
        );
        assert_eq!(
            EnrollmentDraft {
                display_name: "界".repeat(MAX_ENDPOINT_DISPLAY_NAME_CHARS + 1),
                ..draft.clone()
            }
            .validate(),
            Err(EnrollmentDraftError::DisplayName(
                DisplayNameDraftError::TooLong
            ))
        );
        assert_eq!(
            EnrollmentDraft {
                credential: None,
                ..draft
            }
            .validate(),
            Err(EnrollmentDraftError::CredentialRequired)
        );

        let trust = EndpointTrustExpectationRequest::system_ca();
        let step = OnboardingStep::Credential {
            address: "https://192.0.2.10/".to_owned(),
            trust: trust.clone(),
        };
        assert!(step.is_credential());
        assert!(!step.is_address());
        assert!(!step.is_challenge());
        assert!(!step.is_enrolled());
        assert_eq!(
            step.credential_plan(),
            Some(("https://192.0.2.10/", &trust))
        );
        assert_eq!(step.challenge_projection(), None);
        assert_eq!(step.enrollment(), None);
        assert_eq!(OnboardingStep::Address.credential_plan(), None);
        assert_eq!(trust_mode_label(&trust), "System CA");
        assert_eq!(
            trust_mode_label(&EndpointTrustExpectationRequest::pinned_certificate(
                "AA:BB".to_owned()
            )),
            "Pinned certificate"
        );
        Ok(())
    }

    #[test]
    fn import_report_projection_preserves_every_row_outcome() -> Result<(), Box<dyn Error>> {
        let report = serde_json::from_value::<EndpointCsvImportResponse>(json!({
            "total_rows": 2,
            "succeeded_count": 1,
            "failed_count": 1,
            "rows": [
                {
                    "record_number": 2,
                    "address": "https://good.example.test/",
                    "status": "enrolled",
                    "endpoint_id": "01989abc-def0-7abc-8def-0123456789d4",
                    "message": null
                },
                {
                    "record_number": 3,
                    "address": "https://pin.example.test/",
                    "status": "trust_rejected",
                    "endpoint_id": null,
                    "message": "observed TLS certificate does not match the expected Pin"
                }
            ]
        }))?;
        let projection = CsvImportReportProjection::from_response(&report);

        assert_eq!(projection.total_rows, 2);
        assert_eq!(projection.succeeded_count, 1);
        assert_eq!(projection.failed_count, 1);
        assert_eq!(projection.summary_text(), "1 of 2 rows enrolled; 1 failed");
        let enrolled = projection.rows.first().ok_or("enrolled row must exist")?;
        assert!(enrolled.is_success);
        assert_eq!(enrolled.status_label, "Enrolled");
        assert_eq!(enrolled.record_number, 2);
        assert_eq!(
            enrolled.detail,
            Some("01989abc-def0-7abc-8def-0123456789d4".to_owned())
        );
        let rejected = projection.rows.get(1).ok_or("rejected row must exist")?;
        assert!(!rejected.is_success);
        assert_eq!(rejected.status_label, "Trust rejected");
        assert_eq!(
            rejected.detail,
            Some("observed TLS certificate does not match the expected Pin".to_owned())
        );
        Ok(())
    }

    #[test]
    fn audit_query_projection_renders_secret_free_event_cards() -> Result<(), Box<dyn Error>> {
        let query = serde_json::from_value::<AuditQueryResponse>(json!({
            "events": [
                {
                    "occurred_at": "2026-08-05T09:10:11Z",
                    "actor": "local-operator",
                    "action": "import-endpoints",
                    "target": { "kind": "product", "identifier": null },
                    "outcome": {
                        "kind": "failed",
                        "progress": null,
                        "failure": "endpoint-import-row-failed",
                        "verification": "rejected"
                    },
                    "sequence": 6,
                    "operation_id": "01989abc-def0-7abc-8def-0123456789e0",
                    "message": "CSV import completed with row failures"
                },
                {
                    "occurred_at": "2026-08-05T09:09:00Z",
                    "actor": "local-operator",
                    "action": "credential-created",
                    "target": {
                        "kind": "credential",
                        "identifier": "01989abc-def0-7abc-8def-0123456789ce"
                    },
                    "outcome": {
                        "kind": "succeeded",
                        "progress": null,
                        "failure": null,
                        "verification": null
                    },
                    "sequence": 5,
                    "operation_id": "01989abc-def0-7abc-8def-0123456789e1",
                    "message": "Credential stored encrypted"
                }
            ]
        }))?;
        let state = AuditListState::Ready(query);
        assert!(state.is_ready());
        assert!(!state.is_failed());
        assert_eq!(state.count_text(), "2 audit events");
        let cards = state.event_cards();
        let failed = cards.first().ok_or("failed event card must exist")?;
        assert_eq!(failed.occurred_at_text, "2026-08-05T09:10:11Z");
        assert_eq!(failed.actor, "local-operator");
        assert_eq!(failed.action, "import-endpoints");
        assert_eq!(failed.target_kind, "product");
        assert_eq!(failed.target_identifier, None);
        assert_eq!(failed.outcome_kind, "failed");
        assert_eq!(
            failed.outcome_detail,
            Some("endpoint-import-row-failed".to_owned())
        );
        assert_eq!(failed.sequence, 6);
        assert_eq!(failed.operation_id, "01989abc-def0-7abc-8def-0123456789e0");
        let created = cards.get(1).ok_or("created event card must exist")?;
        assert_eq!(created.outcome_kind, "succeeded");
        assert_eq!(created.outcome_detail, None);
        assert_eq!(
            created.target_identifier,
            Some("01989abc-def0-7abc-8def-0123456789ce".to_owned())
        );
        assert_eq!(AuditListState::Idle.event_cards().len(), 0);
        assert_eq!(AuditListState::Idle.count_text(), "0 audit events");
        assert!(AuditListState::Ready(AuditQueryResponse::new(Vec::new())).has_empty_events());
        assert!(AuditListState::Failed.is_failed());
        assert!(AuditListState::Loading.is_loading());
        Ok(())
    }

    #[test]
    fn credential_inventory_projection_produces_secret_free_cards() -> Result<(), Box<dyn Error>> {
        let inventory = serde_json::from_value::<CredentialInventoryResponse>(json!({
            "credentials": [
                {
                    "credential_id": "01989abc-def0-7abc-8def-0123456789ce",
                    "name": "Rack administrators",
                    "username": "administrator",
                    "created_at": "2026-08-05T10:12:13Z",
                    "updated_at": "2026-08-05T10:12:13Z"
                }
            ]
        }))?;
        let state = CredentialsListState::Ready(inventory.clone());
        assert!(state.is_ready());
        assert!(!state.is_failed());
        assert!(!state.has_empty_inventory());
        assert_eq!(state.count_text(), "1 stored credential");
        let cards = state.credential_cards();
        let card = cards.first().ok_or("credential card must exist")?;
        assert_eq!(card.name, "Rack administrators");
        assert_eq!(card.username, "administrator");
        assert_eq!(card.credential_id, "01989abc-def0-7abc-8def-0123456789ce");
        assert_eq!(card.created_at_text, "2026-08-05T10:12:13Z");
        assert_eq!(
            CredentialsListState::Idle.count_text(),
            "0 stored credentials"
        );
        let empty = CredentialsListState::Ready(CredentialInventoryResponse::new(Vec::new()));
        assert!(empty.has_empty_inventory());
        assert_eq!(empty.count_text(), "0 stored credentials");
        Ok(())
    }

    #[test]
    fn onboarding_credential_choices_expose_only_ready_inventories() -> Result<(), Box<dyn Error>> {
        let inventory = serde_json::from_value::<CredentialInventoryResponse>(json!({
            "credentials": [
                {
                    "credential_id": "01989abc-def0-7abc-8def-0123456789ce",
                    "name": "Rack administrators",
                    "username": "administrator",
                    "created_at": "2026-08-05T10:12:13Z",
                    "updated_at": "2026-08-05T10:12:13Z"
                }
            ]
        }))?;
        assert_eq!(OnboardingCredentialsState::Idle.ready_credentials(), None);
        assert_eq!(
            OnboardingCredentialsState::Ready(inventory.clone()).ready_credentials(),
            Some(inventory.credentials().to_vec())
        );
        assert!(!OnboardingCredentialsState::Ready(inventory).has_empty_inventory());
        assert!(
            OnboardingCredentialsState::Ready(CredentialInventoryResponse::new(Vec::new()))
                .has_empty_inventory()
        );
        assert!(OnboardingCredentialsState::Failed.is_failed());
        Ok(())
    }

    #[test]
    fn import_failures_render_distinct_static_messages() {
        assert_eq!(
            ImportFailure::FileUnreadable.message(),
            "The selected file could not be read."
        );
        assert_eq!(
            ImportFailure::FileEmpty.message(),
            "The selected file is empty."
        );
        assert_eq!(
            ImportFailure::Unavailable.message(),
            "The import service is temporarily unavailable."
        );
        assert_eq!(
            ImportFailure::MalformedReport.message(),
            "The server response could not be read."
        );
        assert_eq!(
            ImportFailure::Rejected { status: 422 }.message(),
            "The server rejected the import request (HTTP 422)."
        );
    }

    #[test]
    fn draft_validation_errors_render_static_messages() {
        let fresh = CredentialDraft::new();
        assert_eq!(fresh.validate(), Err(CredentialDraftError::NameRequired));
        assert_eq!(
            CredentialDraftError::NameRequired.message(),
            "A credential name is required."
        );
        assert_eq!(
            CredentialDraftError::NameControlCharacter.message(),
            "The credential name cannot contain control characters."
        );
        assert_eq!(
            CredentialDraftError::NameTooLong.message(),
            "The credential name cannot exceed 128 characters."
        );
        assert_eq!(
            CredentialDraftError::UsernameRequired.message(),
            "A BMC username is required."
        );
        assert_eq!(
            CredentialDraftError::UsernameControlCharacter.message(),
            "The username cannot contain control characters."
        );
        assert_eq!(
            CredentialDraftError::UsernameTooLong.message(),
            "The username cannot exceed 256 characters."
        );
        assert_eq!(
            CredentialDraftError::PasswordRequired.message(),
            "A password is required."
        );
        assert_eq!(
            CredentialDraftError::PasswordTooLarge.message(),
            "The password cannot exceed 4 KiB."
        );
        assert_eq!(
            EndpointAddressDraftError::Required.message(),
            "An endpoint address is required."
        );
        assert_eq!(
            EndpointAddressDraftError::HttpsRequired.message(),
            "The endpoint address must use https://."
        );
        assert_eq!(
            EndpointAddressDraftError::HostRequired.message(),
            "The endpoint address must include a host."
        );
        assert_eq!(
            EndpointAddressDraftError::Whitespace.message(),
            "The endpoint address cannot contain whitespace."
        );
        assert_eq!(
            EndpointAddressDraftError::EmbeddedCredentials.message(),
            "The endpoint address must not embed credentials."
        );
        assert_eq!(
            EndpointAddressDraftError::QueryOrFragmentNotAllowed.message(),
            "The endpoint address must not contain a query or fragment."
        );
        assert_eq!(
            DisplayNameDraftError::Required.message(),
            "A display name is required."
        );
        assert_eq!(
            DisplayNameDraftError::ControlCharacter.message(),
            "The display name cannot contain control characters."
        );
        assert_eq!(
            DisplayNameDraftError::TooLong.message(),
            "The display name cannot exceed 128 characters."
        );
        let fresh_enrollment = EnrollmentDraft::new();
        assert_eq!(
            fresh_enrollment.validate(),
            Err(EnrollmentDraftError::DisplayName(
                DisplayNameDraftError::Required
            ))
        );
        assert_eq!(
            EnrollmentDraftError::DisplayName(DisplayNameDraftError::TooLong).message(),
            "The display name cannot exceed 128 characters."
        );
        assert_eq!(
            EnrollmentDraftError::CredentialRequired.message(),
            "Select or create a credential before enrolling."
        );
    }

    #[test]
    fn onboarding_and_import_states_cover_every_phase() -> Result<(), Box<dyn Error>> {
        let observed_at = OffsetDateTime::parse("2026-08-05T10:11:12Z", &Rfc3339)?;
        let challenge =
            TrustChallengeProjection::from_response(&EndpointTrustChallengeResponse::new(
                "https://bmc.example.test/".to_owned(),
                "AA:BB".to_owned(),
                observed_at,
                EndpointTrustChallengeStateResponse::ExplicitPinRequired,
            ));
        let step = OnboardingStep::Challenge(challenge.clone());
        assert!(step.is_challenge());
        assert_eq!(step.challenge_projection(), Some(&challenge));
        let enrollment = serde_json::from_value::<EndpointEnrollmentResponse>(json!({
            "endpoint_id": "01989abc-def0-7abc-8def-0123456789d4",
            "initial_generation": 1,
            "resource_counts": { "systems": 1, "chassis": 0, "managers": 1 }
        }))?;
        let enrolled = OnboardingStep::Enrolled(enrollment.clone());
        assert!(enrolled.is_enrolled());
        assert_eq!(enrolled.enrollment(), Some(&enrollment));
        assert_eq!(
            OnboardingFailure::TrustObservation.message(),
            "The TLS identity could not be observed. Check that the address is reachable over HTTPS."
        );
        assert_eq!(
            OnboardingFailure::TrustExpectationRejected.message(),
            "The confirmed trust policy could not be verified. The observed certificate may have changed."
        );
        assert_eq!(
            OnboardingFailure::CredentialsUnavailable.message(),
            "The credential inventory is temporarily unavailable."
        );
        assert_eq!(
            OnboardingFailure::CredentialCreateRejected.message(),
            "The credential could not be created."
        );
        assert_eq!(
            OnboardingFailure::EnrollmentRejected.message(),
            "The endpoint could not be enrolled with the selected credential."
        );

        assert_eq!(
            CredentialsListState::Loading.count_text(),
            "0 stored credentials"
        );
        assert!(CredentialsListState::Failed.is_failed());
        assert!(
            OnboardingCredentialsState::Loading
                .ready_credentials()
                .is_none()
        );
        assert!(OnboardingCredentialsState::Failed.is_failed());

        assert!(matches!(
            CreateCredentialState::Idle,
            CreateCredentialState::Idle
        ));
        assert!(matches!(
            CreateCredentialState::InFlight,
            CreateCredentialState::InFlight
        ));
        assert!(matches!(
            CreateCredentialState::Created,
            CreateCredentialState::Created
        ));
        assert!(matches!(
            CreateCredentialState::Failed("boom"),
            CreateCredentialState::Failed(_)
        ));
        assert_ne!(ImportState::Idle, ImportState::InFlight);
        assert!(matches!(ImportState::InFlight, ImportState::InFlight));
        let empty_report = CsvImportReportProjection::from_response(
            &EndpointCsvImportResponse::new(0, 0, 0, Vec::new()),
        );
        assert!(matches!(
            ImportState::Ready(empty_report),
            ImportState::Ready(_)
        ));
        assert!(matches!(
            ImportState::Failed(ImportFailure::Unavailable),
            ImportState::Failed(_)
        ));
        Ok(())
    }

    #[test]
    fn console_views_and_loading_state_expose_static_labels() {
        assert_eq!(
            ConsoleView::ALL,
            [
                ConsoleView::Overview,
                ConsoleView::Credentials,
                ConsoleView::AddEndpoint,
                ConsoleView::Import,
                ConsoleView::Audit,
            ]
        );
        assert_eq!(ConsoleView::Overview.label(), "Overview");
        assert_eq!(ConsoleView::Credentials.label(), "Credentials");
        assert_eq!(ConsoleView::AddEndpoint.label(), "Add endpoint");
        assert_eq!(ConsoleView::Import.label(), "Import");
        assert_eq!(ConsoleView::Audit.label(), "Audit");

        assert!(ConsoleLoadState::Loading.is_loading());
        assert!(
            !ConsoleLoadState::accepted(
                about(PRODUCT_ID),
                EndpointInventoryResponse::new(Vec::new()),
                Vec::new()
            )
            .is_loading()
        );
    }
}
