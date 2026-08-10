#![forbid(unsafe_code)]

use std::{fmt, num::NonZeroU64};

// The §7.5 typed write vocabulary is part of the wire contract: the operation
// DTOs carry `RedfishCommand` and its payloads, so consumers of this crate
// must be able to name those types (E0603 otherwise). The re-export mirrors
// the domain's own surface exactly.
pub use rutilus_domain::{
    BootCommand, BootSource, BootSourceOverrideEnabled, BootSourceOverrideMode, ChassisCommand,
    CreateSubscription, DeleteSubscription, EraseToken, EraseType, EventCommand,
    EventDestinationProtocol, EventType, ManagerCommand, NvidiaDebugTokenCommand,
    NvidiaPowerSmoothingCommand, NvidiaSystemConfigProfileCommand, OemCommand, ProfileFile,
    ProfileId, RedfishCommand, ResetKeysType, ResetType, SecureBootCommand, SetBootSourceOverride,
    StartUpdate, SystemCommand, TokenData, TokenType, UpdateCommand,
};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use time::OffsetDateTime;
use uuid::Uuid;

/// Stable health states exposed by the same-origin product API.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthStatus {
    Ok,
}

/// Minimal process health projection shared by Axum and the browser client.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HealthResponse {
    status: HealthStatus,
}

impl HealthResponse {
    #[must_use]
    pub const fn healthy() -> Self {
        Self {
            status: HealthStatus::Ok,
        }
    }

    #[must_use]
    pub const fn status(self) -> HealthStatus {
        self.status
    }
}

/// Immutable build identity displayed by every product posture.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AboutResponse {
    product: String,
    product_version: String,
    nv_redfish_baseline: String,
}

impl AboutResponse {
    #[must_use]
    pub const fn new(
        product: String,
        product_version: String,
        nv_redfish_baseline: String,
    ) -> Self {
        Self {
            product,
            product_version,
            nv_redfish_baseline,
        }
    }

    #[must_use]
    pub fn product(&self) -> &str {
        &self.product
    }

    #[must_use]
    pub fn product_version(&self) -> &str {
        &self.product_version
    }

    #[must_use]
    pub fn nv_redfish_baseline(&self) -> &str {
        &self.nv_redfish_baseline
    }
}

/// The explicit TLS trust decision retained for a managed endpoint.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsTrustModeResponse {
    SystemCa,
    PinnedCertificate,
}

/// Credential-free input for observing one BMC TLS identity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BeginEndpointTrustRequest {
    address: String,
}

impl BeginEndpointTrustRequest {
    #[must_use]
    pub const fn new(address: String) -> Self {
        Self { address }
    }

    #[must_use]
    pub fn address(&self) -> &str {
        &self.address
    }
}

/// The only safe next states after a credential-free TLS observation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointTrustChallengeStateResponse {
    SystemCaTrusted,
    ExplicitPinRequired,
}

/// A secret-free TLS identity challenge shown before any credential is
/// selected or transmitted to a BMC.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointTrustChallengeResponse {
    address: String,
    fingerprint_sha256: String,
    #[serde(with = "time::serde::rfc3339")]
    observed_at: OffsetDateTime,
    state: EndpointTrustChallengeStateResponse,
}

impl EndpointTrustChallengeResponse {
    #[must_use]
    pub const fn new(
        address: String,
        fingerprint_sha256: String,
        observed_at: OffsetDateTime,
        state: EndpointTrustChallengeStateResponse,
    ) -> Self {
        Self {
            address,
            fingerprint_sha256,
            observed_at,
            state,
        }
    }

    #[must_use]
    pub fn address(&self) -> &str {
        &self.address
    }

    #[must_use]
    pub fn fingerprint_sha256(&self) -> &str {
        &self.fingerprint_sha256
    }

    #[must_use]
    pub const fn observed_at(&self) -> OffsetDateTime {
        self.observed_at
    }

    #[must_use]
    pub const fn state(&self) -> EndpointTrustChallengeStateResponse {
        self.state
    }
}

/// Trust policy explicitly declared before the authenticated enrollment pass
/// begins. The server re-observes TLS without credentials and verifies this
/// exact expectation before resolving the selected credential.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum EndpointTrustExpectationRequest {
    SystemCa,
    PinnedCertificate { fingerprint_sha256: String },
}

impl EndpointTrustExpectationRequest {
    #[must_use]
    pub const fn system_ca() -> Self {
        Self::SystemCa
    }

    #[must_use]
    pub const fn pinned_certificate(fingerprint_sha256: String) -> Self {
        Self::PinnedCertificate { fingerprint_sha256 }
    }

    #[must_use]
    pub fn fingerprint_sha256(&self) -> Option<&str> {
        match self {
            Self::SystemCa => None,
            Self::PinnedCertificate { fingerprint_sha256 } => Some(fingerprint_sha256),
        }
    }
}

/// A plaintext credential accepted only by the authenticated local product
/// boundary. Serialization is required by the WASM client, while `Debug`
/// remains permanently redacted.
pub struct CreateCredentialRequest {
    name: String,
    username: String,
    password: SecretString,
}

impl CreateCredentialRequest {
    #[must_use]
    pub const fn new(name: String, username: String, password: SecretString) -> Self {
        Self {
            name,
            username,
            password,
        }
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn username(&self) -> &str {
        &self.username
    }

    #[must_use]
    pub fn into_parts(self) -> (String, String, SecretString) {
        (self.name, self.username, self.password)
    }
}

impl Serialize for CreateCredentialRequest {
    fn serialize<SerializerType>(
        &self,
        serializer: SerializerType,
    ) -> Result<SerializerType::Ok, SerializerType::Error>
    where
        SerializerType: Serializer,
    {
        #[derive(Serialize)]
        struct WireCredentialRequest<'a> {
            name: &'a str,
            username: &'a str,
            password: &'a str,
        }

        WireCredentialRequest {
            name: &self.name,
            username: &self.username,
            password: self.password.expose_secret(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for CreateCredentialRequest {
    fn deserialize<DeserializerType>(
        deserializer: DeserializerType,
    ) -> Result<Self, DeserializerType::Error>
    where
        DeserializerType: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireCredentialRequest {
            name: String,
            username: String,
            password: String,
        }

        let wire = WireCredentialRequest::deserialize(deserializer)?;
        Ok(Self::new(wire.name, wire.username, wire.password.into()))
    }
}

impl fmt::Debug for CreateCredentialRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CreateCredentialRequest")
            .field("name", &self.name)
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .finish()
    }
}

/// Secret-free reusable credential metadata.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialSummaryResponse {
    credential_id: Uuid,
    name: String,
    username: String,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    updated_at: OffsetDateTime,
}

impl CredentialSummaryResponse {
    #[must_use]
    pub const fn new(
        credential_id: Uuid,
        name: String,
        username: String,
        created_at: OffsetDateTime,
        updated_at: OffsetDateTime,
    ) -> Self {
        Self {
            credential_id,
            name,
            username,
            created_at,
            updated_at,
        }
    }

    #[must_use]
    pub const fn credential_id(&self) -> Uuid {
        self.credential_id
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn username(&self) -> &str {
        &self.username
    }

    #[must_use]
    pub const fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    #[must_use]
    pub const fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }
}

/// Stable secret-free inventory of reusable BMC credentials.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialInventoryResponse {
    credentials: Vec<CredentialSummaryResponse>,
}

impl CredentialInventoryResponse {
    #[must_use]
    pub const fn new(credentials: Vec<CredentialSummaryResponse>) -> Self {
        Self { credentials }
    }

    #[must_use]
    pub fn credentials(&self) -> &[CredentialSummaryResponse] {
        &self.credentials
    }
}

/// Validated-by-the-server input for the trust-first, credentialed portion of
/// endpoint enrollment.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollEndpointRequest {
    display_name: String,
    address: String,
    trust: EndpointTrustExpectationRequest,
    credential_id: Uuid,
}

impl EnrollEndpointRequest {
    #[must_use]
    pub const fn new(
        display_name: String,
        address: String,
        trust: EndpointTrustExpectationRequest,
        credential_id: Uuid,
    ) -> Self {
        Self {
            display_name,
            address,
            trust,
            credential_id,
        }
    }

    #[must_use]
    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    #[must_use]
    pub fn address(&self) -> &str {
        &self.address
    }

    #[must_use]
    pub const fn trust(&self) -> &EndpointTrustExpectationRequest {
        &self.trust
    }

    #[must_use]
    pub const fn credential_id(&self) -> Uuid {
        self.credential_id
    }
}

/// A successfully created endpoint and its mandatory first complete refresh.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointEnrollmentResponse {
    endpoint_id: Uuid,
    initial_generation: NonZeroU64,
    resource_counts: CoreResourceCountsResponse,
}

impl EndpointEnrollmentResponse {
    #[must_use]
    pub const fn new(
        endpoint_id: Uuid,
        initial_generation: NonZeroU64,
        resource_counts: CoreResourceCountsResponse,
    ) -> Self {
        Self {
            endpoint_id,
            initial_generation,
            resource_counts,
        }
    }

    #[must_use]
    pub const fn endpoint_id(&self) -> Uuid {
        self.endpoint_id
    }

    #[must_use]
    pub const fn initial_generation(&self) -> NonZeroU64 {
        self.initial_generation
    }

    #[must_use]
    pub const fn resource_counts(&self) -> CoreResourceCountsResponse {
        self.resource_counts
    }
}

/// Stable endpoint identity and trust metadata exposed without credentials or
/// certificate material.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointIdentityResponse {
    endpoint_id: Uuid,
    display_name: String,
    address: String,
    tls_trust_mode: TlsTrustModeResponse,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    updated_at: OffsetDateTime,
}

impl EndpointIdentityResponse {
    #[must_use]
    pub const fn new(
        endpoint_id: Uuid,
        display_name: String,
        address: String,
        tls_trust_mode: TlsTrustModeResponse,
        created_at: OffsetDateTime,
        updated_at: OffsetDateTime,
    ) -> Self {
        Self {
            endpoint_id,
            display_name,
            address,
            tls_trust_mode,
            created_at,
            updated_at,
        }
    }

    #[must_use]
    pub const fn endpoint_id(&self) -> Uuid {
        self.endpoint_id
    }

    #[must_use]
    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    #[must_use]
    pub fn address(&self) -> &str {
        &self.address
    }

    #[must_use]
    pub const fn tls_trust_mode(&self) -> TlsTrustModeResponse {
        self.tls_trust_mode
    }

    #[must_use]
    pub const fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    #[must_use]
    pub const fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }
}

/// Counts from one latest complete core-resource Generation.
///
/// The three fields deliberately cover only the 0.1 management triad
/// (Systems, Chassis, Managers). The 0.2 resource families (Processors,
/// Memory, and later Storage, Network, Accounts) are presented through the
/// typed resource-inventory API instead of this summary, so the endpoint
/// card remains a stable three-line overview while new families ship
/// without changing the counts wire shape.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CoreResourceCountsResponse {
    systems: u64,
    chassis: u64,
    managers: u64,
}

impl CoreResourceCountsResponse {
    #[must_use]
    pub const fn new(systems: u64, chassis: u64, managers: u64) -> Self {
        Self {
            systems,
            chassis,
            managers,
        }
    }

    #[must_use]
    pub const fn systems(self) -> u64 {
        self.systems
    }

    #[must_use]
    pub const fn chassis(self) -> u64 {
        self.chassis
    }

    #[must_use]
    pub const fn managers(self) -> u64 {
        self.managers
    }
}

/// Whether an endpoint awaits its first successful refresh or has a current
/// complete resource Generation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "state",
    content = "details",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum EndpointSnapshotSummaryResponse {
    AwaitingFirstRefresh,
    Current {
        generation: NonZeroU64,
        #[serde(with = "time::serde::rfc3339")]
        last_successful_refresh_at: OffsetDateTime,
        resource_counts: CoreResourceCountsResponse,
    },
}

impl EndpointSnapshotSummaryResponse {
    #[must_use]
    pub const fn current(
        generation: NonZeroU64,
        last_successful_refresh_at: OffsetDateTime,
        resource_counts: CoreResourceCountsResponse,
    ) -> Self {
        Self::Current {
            generation,
            last_successful_refresh_at,
            resource_counts,
        }
    }
}

/// One secret-free managed endpoint summary.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointSummaryResponse {
    identity: EndpointIdentityResponse,
    snapshot: EndpointSnapshotSummaryResponse,
}

impl EndpointSummaryResponse {
    #[must_use]
    pub const fn new(
        identity: EndpointIdentityResponse,
        snapshot: EndpointSnapshotSummaryResponse,
    ) -> Self {
        Self { identity, snapshot }
    }

    #[must_use]
    pub const fn identity(&self) -> &EndpointIdentityResponse {
        &self.identity
    }

    #[must_use]
    pub const fn snapshot(&self) -> EndpointSnapshotSummaryResponse {
        self.snapshot
    }
}

/// Stable response envelope for the managed endpoint inventory.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointInventoryResponse {
    endpoints: Vec<EndpointSummaryResponse>,
}

impl EndpointInventoryResponse {
    #[must_use]
    pub const fn new(endpoints: Vec<EndpointSummaryResponse>) -> Self {
        Self { endpoints }
    }

    #[must_use]
    pub fn endpoints(&self) -> &[EndpointSummaryResponse] {
        &self.endpoints
    }
}

/// Stable source metadata for one immutable Redfish resource observation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CoreResourceSourceResponse {
    resource_id: Uuid,
    odata_id: String,
    odata_type: Option<String>,
    etag: Option<String>,
}

impl CoreResourceSourceResponse {
    #[must_use]
    pub const fn new(
        resource_id: Uuid,
        odata_id: String,
        odata_type: Option<String>,
        etag: Option<String>,
    ) -> Self {
        Self {
            resource_id,
            odata_id,
            odata_type,
            etag,
        }
    }

    #[must_use]
    pub const fn resource_id(&self) -> Uuid {
        self.resource_id
    }

    #[must_use]
    pub fn odata_id(&self) -> &str {
        &self.odata_id
    }

    #[must_use]
    pub fn odata_type(&self) -> Option<&str> {
        self.odata_type.as_deref()
    }

    #[must_use]
    pub fn etag(&self) -> Option<&str> {
        self.etag.as_deref()
    }
}

/// Stable fields shared by every core Redfish resource.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CoreResourceCommonResponse {
    id: String,
    name: String,
    description: Option<String>,
}

impl CoreResourceCommonResponse {
    #[must_use]
    pub const fn new(id: String, name: String, description: Option<String>) -> Self {
        Self {
            id,
            name,
            description,
        }
    }

    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }
}

/// Original typed Redfish status values retained for unified and source-aware
/// presentation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceStatusResponse {
    state: Option<String>,
    health: Option<String>,
    health_rollup: Option<String>,
}

impl ResourceStatusResponse {
    #[must_use]
    pub const fn new(
        state: Option<String>,
        health: Option<String>,
        health_rollup: Option<String>,
    ) -> Self {
        Self {
            state,
            health,
            health_rollup,
        }
    }

    #[must_use]
    pub fn state(&self) -> Option<&str> {
        self.state.as_deref()
    }

    #[must_use]
    pub fn health(&self) -> Option<&str> {
        self.health.as_deref()
    }

    #[must_use]
    pub fn health_rollup(&self) -> Option<&str> {
        self.health_rollup.as_deref()
    }
}

/// The §0.5.0 NVIDIA `Truststore` metadata of the `SystemConfigProfile`
/// chain-root document: the presence of each certificate-store link
/// (`NvidiaCertificates` / `OemCertificates`), never the certificate
/// payloads behind them (the sensitive surface is deferred to a later
/// slice).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OemNvidiaSystemConfigProfileTruststoreResponse {
    nvidia_certificates: Option<bool>,
    oem_certificates: Option<bool>,
}

impl OemNvidiaSystemConfigProfileTruststoreResponse {
    #[must_use]
    pub const fn new(nvidia_certificates: Option<bool>, oem_certificates: Option<bool>) -> Self {
        Self {
            nvidia_certificates,
            oem_certificates,
        }
    }

    /// Whether the `NvidiaCertificates` link was present.
    #[must_use]
    pub const fn nvidia_certificates(&self) -> Option<bool> {
        self.nvidia_certificates
    }

    /// Whether the `OemCertificates` link was present.
    #[must_use]
    pub const fn oem_certificates(&self) -> Option<bool> {
        self.oem_certificates
    }
}

/// Feature-specific, explicitly tagged core Redfish resource fields.
///
/// `PartialEq` (not `Eq`) is deliberate: the Sensor and Control variants
/// carry numeric readings (`f64`, matching the compiled `Edm.Decimal` type of
/// nv-redfish 0.13), and `f64` cannot implement `Eq`.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(
    tag = "resource_type",
    content = "details",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum CoreResourceDetailsResponse {
    ServiceRoot {
        vendor: Option<String>,
        product: Option<String>,
        redfish_version: Option<String>,
    },
    System {
        system_type: Option<String>,
        manufacturer: Option<String>,
        model: Option<String>,
        part_number: Option<String>,
        serial_number: Option<String>,
        sku: Option<String>,
        host_name: Option<String>,
        bios_version: Option<String>,
        power_state: Option<String>,
        status: Option<ResourceStatusResponse>,
    },
    Chassis {
        chassis_type: String,
        manufacturer: Option<String>,
        model: Option<String>,
        part_number: Option<String>,
        serial_number: Option<String>,
        sku: Option<String>,
        asset_tag: Option<String>,
        power_state: Option<String>,
        status: Option<ResourceStatusResponse>,
    },
    Manager {
        manager_type: Option<String>,
        manufacturer: Option<String>,
        model: Option<String>,
        part_number: Option<String>,
        serial_number: Option<String>,
        firmware_version: Option<String>,
        version: Option<String>,
        power_state: Option<String>,
        status: Option<ResourceStatusResponse>,
    },
    /// One §0.5.0 OEM family member projected from the typed Redfish
    /// Dell-attributes schema (`DellAttributes_v1`, nv-redfish-schema 0.13,
    /// `oem-dell-attributes` feature).
    ///
    /// The manager's Dell `DellAttributes` document is the only Dell OEM
    /// surface nv-redfish 0.13 compiles (§11.5: an OEM surface is projected
    /// only when upstream strongly types it), and the details are the five
    /// Dell iDRAC identity attributes the product pins on that document.
    /// Each value is `None` when the endpoint did not publish the attribute
    /// key. The rest of the vendor-specific dynamic attribute bag stays out —
    /// exactly like the `Bios` family keeps its `Attributes` bag out — because
    /// the bag is unbounded and untyped by key.
    OemDell {
        server_model: Option<String>,
        server_service_tag: Option<String>,
        server_generation: Option<String>,
        server_bmc_mac_address: Option<String>,
        server_name: Option<String>,
    },
    /// One §0.5.0 OEM family member projected from the typed Redfish
    /// Supermicro `SysLockdown` schema (`SysLockdown_v1`, nv-redfish-schema
    /// 0.13, `oem-supermicro` feature).
    ///
    /// The manager's `SysLockdown` document is one of the two Supermicro OEM
    /// surfaces nv-redfish 0.13 compiles (§11.5: an OEM surface is projected
    /// only when upstream strongly types it), and the details are the
    /// document's only substantive typed field. The compiled schema models no
    /// `Id` / `Name` / `Description`, so the common identity is the resource's
    /// own `@odata.id` final segment (the Redfish `Id` per DSP0266), never a
    /// product-invented label.
    OemSmcSysLockdown { sys_lockdown_enabled: Option<bool> },
    /// One §0.5.0 OEM family member projected from the typed Redfish
    /// Supermicro `KcsInterface` schema (`KCSInterface_v1`, nv-redfish-schema
    /// 0.13, `oem-supermicro` feature).
    ///
    /// The manager's `KCSInterface` document is the second Supermicro OEM
    /// surface nv-redfish 0.13 compiles (§11.5), and `privilege` is the
    /// vendor's enum spelling verbatim (e.g. `Administrator`, `DisableKCS`).
    /// The compiled schema models no `Id` / `Name` / `Description`, so the
    /// common identity is the resource's own `@odata.id` final segment (the
    /// Redfish `Id` per DSP0266), never a product-invented label.
    OemSmcKcsInterface { privilege: Option<String> },
    /// One §0.5.0 OEM family member projected from the typed Redfish NVIDIA
    /// `SystemConfigProfile` schema (`NvidiaSystemConfigProfile`,
    /// nv-redfish-schema 0.13, `oem-nvidia-profiles` feature).
    ///
    /// The chain-root document of the `ComputerSystem`'s `Oem.Nvidia` segment
    /// is the first member of the NVIDIA system-config-profile chain; the
    /// whole chain shares the single family code
    /// `nvidia-system-config-profile` because the chain root decides whether
    /// the chain exists at all (§11.5: an OEM surface is projected only when
    /// upstream strongly types it). The details are the `Truststore`
    /// metadata: the presence of each certificate-store link, never the
    /// certificate payloads behind them (the sensitive surface is deferred).
    OemNvidiaSystemConfigProfile {
        truststore: Option<OemNvidiaSystemConfigProfileTruststoreResponse>,
    },
    /// One §0.5.0 OEM family member projected from the typed Redfish NVIDIA
    /// `SystemConfigProfileStatus` schema (`NvidiaSystemConfigProfileStatus`,
    /// nv-redfish-schema 0.13, `oem-nvidia-profiles` feature).
    ///
    /// The status singleton of the system-config-profile chain; the details
    /// are the compiled status fields — the `PendingList.Activation` text,
    /// the numeric `ActiveProfileIndex` / `BmcProfileVersion` /
    /// `DefaultProfileIndex` indices, and the `FactoryResetStatus` text —
    /// each `None` when the endpoint did not publish the property.
    OemNvidiaSystemConfigProfileStatus {
        pending_list_activation: Option<String>,
        active_profile_index: Option<i64>,
        bmc_profile_version: Option<i64>,
        factory_reset_status: Option<String>,
        default_profile_index: Option<i64>,
    },
    /// One §0.5.0 OEM family member projected from the typed Redfish NVIDIA
    /// `SystemProfile` schema (`NvidiaSystemProfile`, nv-redfish-schema 0.13,
    /// `oem-nvidia-profiles` feature).
    ///
    /// One member of the system-config-profile collection; the details are
    /// the compiled metadata fields (`Default`, `Owner`, `UUID`, the numeric
    /// `Version`, and `ProfileName`). The profile file behind the member's
    /// `ProfileFile` navigation is its own chain document and its own
    /// variant.
    OemNvidiaSystemProfile {
        default: Option<bool>,
        owner: Option<String>,
        uuid: Option<String>,
        version: Option<i64>,
        profile_name: Option<String>,
    },
    /// One §0.5.0 OEM family member projected from the typed Redfish NVIDIA
    /// `SystemProfileFile` schema (`NvidiaSystemProfileFile`,
    /// nv-redfish-schema 0.13, `oem-nvidia-profiles` feature).
    ///
    /// The profile file document behind one profile member's `ProfileFile`
    /// navigation; the details are the compiled `Metadata` fields (`Activate`,
    /// `Delete`, `OriginProfileUUID`, `More_Profiles`, `ProjectName`,
    /// `UUID`) and the base64 `Profile` content, kept verbatim (§12.3).
    OemNvidiaSystemProfileFile {
        metadata_activate: Option<bool>,
        metadata_delete: Option<bool>,
        metadata_origin_profile_uuid: Option<String>,
        metadata_more_profiles: Option<bool>,
        metadata_project_name: Option<String>,
        metadata_uuid: Option<String>,
        profile: Option<String>,
    },
    /// One §0.5.0 OEM family member projected from the typed Redfish NVIDIA
    /// `NvidiaPowerComplianceManager` schema (`NvidiaPowerComplianceManager`,
    /// nv-redfish-schema 0.13, `oem-nvidia-power-management` feature).
    ///
    /// The chain-root document of the `Manager`'s `Oem.Nvidia` segment is the
    /// first member of the NVIDIA power-compliance chain; the whole chain
    /// shares the single family code `nvidia-power-compliance` because the
    /// chain root decides whether the chain exists at all (§11.5: an OEM
    /// surface is projected only when upstream strongly types it). The
    /// details are the compiled `ManagerType` enumeration spelling (e.g.
    /// `PowerManager`), verbatim per §12.3.
    OemNvidiaPowerCompliance { manager_type: Option<String> },
    /// One §0.5.0 OEM family member projected from the typed Redfish NVIDIA
    /// `NvidiaPowerDomain` schema (`NvidiaPowerDomain`, nv-redfish-schema
    /// 0.13, `oem-nvidia-power-management` feature).
    ///
    /// One member of the compliance manager's `PowerDomains` collection; the
    /// details are the compiled scalar fields — the numeric `Value`, the
    /// `Type` / `Unit` enumerations, and the `SensorReadingType` /
    /// `SensorImpl` sensor enumerations — each verbatim per §12.3.
    OemNvidiaPowerDomain {
        value: Option<i64>,
        r#type: Option<String>,
        unit: Option<String>,
        sensor_reading_type: Option<String>,
        sensor_impl: Option<String>,
    },
    /// One §0.5.0 OEM family member projected from the typed Redfish NVIDIA
    /// `NvidiaPowerPolicy` schema (`NvidiaPowerPolicy`, nv-redfish-schema
    /// 0.13, `oem-nvidia-power-management` feature).
    ///
    /// The `ACLossPolicy` / `PSUCompliancePolicy` singleton of the
    /// power-compliance chain (one variant for both, they share the compiled
    /// schema); the details are the compiled scalar fields — the
    /// `AutoDeassertPowerBrake` boolean, the numeric `Min` / `Max`
    /// thresholds, the `Type` / `Unit` enumerations, and the `PolicyActions`
    /// enumeration — each verbatim per §12.3. The `DwellTime` duration stays
    /// out of the strictly projectable field set.
    OemNvidiaPowerPolicy {
        auto_deassert_power_brake: Option<bool>,
        min: Option<i64>,
        max: Option<i64>,
        r#type: Option<String>,
        unit: Option<String>,
        policy_actions: Option<String>,
    },
    /// One §0.5.0 OEM family member projected from the typed Redfish NVIDIA
    /// `NvidiaManagedEntityGroup` schema (`NvidiaManagedEntityGroup`,
    /// nv-redfish-schema 0.13, `oem-nvidia-power-management` feature).
    ///
    /// One member of the compliance manager's `ManagedEntityGroups`
    /// collection; the details are the compiled `CurrentManagedEntityId`
    /// text. The group's `ManagedEntities` navigation belongs to the
    /// managed-entity family.
    OemNvidiaManagedEntityGroup {
        current_managed_entity_id: Option<String>,
    },
    /// One §0.5.0 OEM family member projected from the typed Redfish NVIDIA
    /// `NvidiaPowerStateGroup` schema (`NvidiaPowerStateGroup`,
    /// nv-redfish-schema 0.13, `oem-nvidia-power-management` feature).
    ///
    /// The `PowerStateGroup` document of the power-compliance chain; the
    /// details are the compiled scalar fields — the `PscId` text and the
    /// numeric `GeneratedWatts` / `NumberOfPscs` / `NumberOfLocalPsus`. The
    /// `PowerShelfControllers` / `PowerSupplies` collection members are their
    /// own chain documents and their own variants.
    OemNvidiaPowerStateGroup {
        psc_id: Option<String>,
        generated_watts: Option<i64>,
        number_of_pscs: Option<i64>,
        number_of_local_psus: Option<i64>,
    },
    /// One §0.5.0 OEM family member projected from the typed Redfish NVIDIA
    /// `NvidiaPscState` schema (`NvidiaPscState`, nv-redfish-schema 0.13,
    /// `oem-nvidia-power-management` feature).
    ///
    /// One member of the power state group's `PowerShelfControllers`
    /// collection; the details are the compiled scalar fields — the `PscId`
    /// text, the numeric `NumOfOperationalPsus` /
    /// `MillisecondsSinceLastHeartbeat`, the `PowerBrakeAssert` boolean, and
    /// the `Status` enumeration — each verbatim per §12.3.
    OemNvidiaPscState {
        psc_id: Option<String>,
        num_of_operational_psus: Option<i64>,
        power_brake_assert: Option<bool>,
        milliseconds_since_last_heartbeat: Option<i64>,
        status: Option<String>,
    },
    /// One §0.5.0 OEM family member projected from the typed Redfish NVIDIA
    /// `NvidiaPsuState` schema (`NvidiaPsuState`, nv-redfish-schema 0.13,
    /// `oem-nvidia-power-management` feature).
    ///
    /// One member of the power state group's `PowerSupplies` collection; the
    /// details are the compiled scalar fields — the `PsuId` text and the
    /// `Presence` / `Input1Active` / `Input2Active` booleans — each verbatim
    /// per §12.3.
    OemNvidiaPsuState {
        psu_id: Option<String>,
        presence: Option<bool>,
        input1active: Option<bool>,
        input2active: Option<bool>,
    },
    /// One §0.5.0 OEM family member projected from the typed Redfish NVIDIA
    /// `NvidiaPsuRedundancy` schema (`NvidiaPsuRedundancy`,
    /// nv-redfish-schema 0.13, `oem-nvidia-power-management` feature).
    ///
    /// The `PSURedundancy` singleton of the power-compliance chain; the
    /// details are the compiled scalar fields — the `MaxNumSupported` /
    /// `MinNumNeeded` texts and the `RedundancySetting` enumeration — each
    /// verbatim per §12.3.
    OemNvidiaPsuRedundancy {
        max_num_supported: Option<String>,
        min_num_needed: Option<String>,
        redundancy_setting: Option<String>,
    },
    /// One §0.5.0 OEM family member projected from the typed Redfish NVIDIA
    /// `NvidiaManagedEntity` schema (`NvidiaManagedEntity`,
    /// nv-redfish-schema 0.13, `oem-nvidia-power-management` feature).
    ///
    /// One member of a group member's `ManagedEntities` collection, the
    /// chain of the managed-entity family under the single family code
    /// `nvidia-managed-entity` (the chain's entry navigation is the
    /// compliance manager's `ManagedEntityGroups` chain, whose presence
    /// decides whether the chain exists at all). The details are the
    /// compiled scalar fields — the `TransportProtocol` enumeration, the
    /// `IPv4Address` / `IPv6Address` address texts, and the numeric `Port` —
    /// each verbatim per §12.3.
    OemNvidiaManagedEntity {
        transport_protocol: Option<String>,
        ipv4_address: Option<String>,
        ipv6_address: Option<String>,
        port: Option<i64>,
    },
    /// One §0.5.0 OEM family member projected from the typed Redfish Lenovo
    /// `LenovoSecurityService` schema (`LenovoSecurityService`,
    /// nv-redfish-schema 0.13, `oem-lenovo` feature).
    ///
    /// The manager's `SecurityService` document is the Lenovo OEM surface
    /// nv-redfish 0.13 compiles on the `Manager` (§11.5: an OEM surface is
    /// projected only when upstream strongly types it), read through the
    /// `Security` navigation of the `Oem.Lenovo` segment. `fw_rollback` is
    /// the vendor's enum spelling verbatim (e.g. `Enabled`, `Disabled`, or
    /// `UnsupportedValue` for a value this build cannot classify), per §12.3;
    /// the compiled schema models it inside the `Configurator` segment and
    /// the upstream wrapper collapses that nesting onto its single
    /// `fw_rollback()` accessor, so the wire carries the flattened value.
    OemLenovoSecurityService { fw_rollback: Option<String> },
    /// One §2.1 `processors` family member projected from the typed Redfish
    /// processor schema. `total_cores` stays numeric so the console can
    /// render a core count without re-parsing text.
    Processor {
        processor_type: Option<String>,
        socket: Option<String>,
        manufacturer: Option<String>,
        model: Option<String>,
        total_cores: Option<u64>,
        status: Option<ResourceStatusResponse>,
    },
    /// One §2.1 `memory` family member projected from the typed Redfish
    /// memory schema. `capacity_mib` stays numeric so the console can render
    /// a capacity without re-parsing text.
    Memory {
        memory_device_type: Option<String>,
        capacity_mib: Option<u64>,
        manufacturer: Option<String>,
        model: Option<String>,
        status: Option<ResourceStatusResponse>,
    },
    /// One §2.1 `storages` family member projected from the typed Redfish
    /// storage schema (`Storage_v1`, nv-redfish-schema 0.13).
    ///
    /// `controller_count` and `drive_count` are derived from the
    /// `StorageControllers` and `Drives` collection navigations, which the
    /// typed schema always provides, and stay numeric so the console renders
    /// counts without re-parsing text. A `storage_type` field was considered
    /// but does not exist in `Storage_v1`, so it stays out of this strictly
    /// projectable field set.
    Storage {
        controller_count: Option<u64>,
        drive_count: Option<u64>,
        status: Option<ResourceStatusResponse>,
    },
    /// One §2.1 `network-adapters` family member projected from the typed
    /// Redfish network-adapter schema (`NetworkAdapter_v1`, nv-redfish-schema
    /// 0.13).
    ///
    /// Fields are the direct `Manufacturer`, `Model`, and `Status` properties
    /// of the adapter resource. A `firmware_version` field was considered but
    /// exists only as `Controllers[].FirmwarePackageVersion`, so it stays out
    /// of this strictly projectable field set.
    NetworkAdapter {
        manufacturer: Option<String>,
        model: Option<String>,
        status: Option<ResourceStatusResponse>,
    },
    /// One §2.1 `ethernet-interfaces` family member projected from the typed
    /// Redfish ethernet-interface schema (`EthernetInterface_v1`,
    /// nv-redfish-schema 0.13).
    ///
    /// Fields are the direct `MACAddress`, `SpeedMbps`, `InterfaceEnabled`,
    /// and `Status` properties; `speed_mbps` stays numeric so the console
    /// renders the link speed without re-parsing text.
    EthernetInterface {
        mac_address: Option<String>,
        speed_mbps: Option<u64>,
        interface_enabled: Option<bool>,
        status: Option<ResourceStatusResponse>,
    },
    /// One §2.1 `accounts` family member projected from the typed Redfish
    /// manager-account schema (`ManagerAccount_v1`, nv-redfish-schema 0.13;
    /// the feature compiles no separate `Account_v1` resource type).
    ///
    /// Fields are the direct `Enabled`, `RoleId`, and `Locked` properties of
    /// the account. `UserName` was considered but duplicates the common
    /// identity surface of `CoreResourceCommonResponse`. Unlike the 0.1 triad
    /// and the Processor/Memory/Storage/Network families, `ManagerAccount_v1`
    /// declares no `Status` property, so there is no status field for the
    /// console to render — a never-populated uniform status would break the
    /// strict `deny_unknown_fields` alignment with the infra payload.
    Account {
        enabled: Option<bool>,
        role_id: Option<String>,
        locked: Option<bool>,
    },
    /// One §2.1 `bios` family member projected from the typed Redfish BIOS
    /// schema (`Bios_v1`, nv-redfish-schema 0.13).
    ///
    /// Only metadata is projected: `AttributeRegistry` names the registry that
    /// defines the attribute set. The `Attributes` bag itself is deliberately
    /// not projected — it is a vendor-specific dynamic property map of
    /// unbounded size, so carrying it would swamp the console with raw
    /// settings and defeat the strict `deny_unknown_fields` alignment with
    /// the infra payload. `Bios_v1` declares no `Status` property, so this
    /// family carries no status field either.
    Bios { attribute_registry: Option<String> },
    /// One §2.1 `boot-options` family member projected from the typed Redfish
    /// boot-option schema (`BootOption_v1`, nv-redfish-schema 0.13).
    ///
    /// Fields are the direct `DisplayName`, `BootOptionEnabled`, and
    /// `UefiDevicePath` properties. `BootOptionEnabled` is a plain Boolean in
    /// the schema (not an enumeration), so it stays a bool; the `Alias` boot
    /// source enumeration and the `BootOptionReference` handle stay out of
    /// this first strictly projectable field set. `BootOption_v1` declares no
    /// `Status` property, so this family carries no status field either.
    BootOption {
        display_name: Option<String>,
        boot_option_enabled: Option<bool>,
        uefi_device_path: Option<String>,
    },
    /// One §2.1 `secure-boot` family member projected from the typed Redfish
    /// secure-boot schema (`SecureBoot_v1`, nv-redfish-schema 0.13).
    ///
    /// `secure_boot_enable` is the direct `SecureBootEnable` Boolean and
    /// `secure_boot_mode` the `SecureBootMode` enumeration (`Disabled`,
    /// `Enabled`, `AuditMode`, `DeployedMode`, `SetupMode`, `UserMode`)
    /// retained as a string so the console renders it without re-parsing text.
    /// `SecureBootCurrentBoot` was considered but mirrors `SecureBootMode`
    /// for the current boot. `SecureBoot_v1` declares no `Status` property,
    /// so this family carries no status field either.
    SecureBoot {
        secure_boot_enable: Option<bool>,
        secure_boot_mode: Option<String>,
    },
    /// One §2.1 `power` family member projected from the typed Redfish power
    /// schema (`Power_v1`, nv-redfish-schema 0.13).
    ///
    /// The `Power` resource itself declares no `Status` property and no
    /// reading or metadata properties in `Power_v1`: consumption and capacity
    /// readings (`PowerConsumedWatts`, `PowerCapacityWatts`) exist only on the
    /// `PowerSupply` type, which belongs to the separate §2.1 `power-supplies`
    /// family. The variant therefore carries no details — a never-populated
    /// uniform field would break the strict `deny_unknown_fields` alignment
    /// with the infra payload.
    Power {},
    /// One §2.1 `thermal` family member projected from the typed Redfish
    /// thermal schema (`Thermal_v1`, nv-redfish-schema 0.13).
    ///
    /// Only `Status` exists on the `Thermal` resource itself. A
    /// `temperature_celsius` field was considered, but `TemperatureCelsius`
    /// exists only on members of the `Temperatures` collection, and
    /// `fan_speed_rpm` likewise only on `Fans` members, so neither belongs in
    /// this strictly projectable field set.
    Thermal {
        status: Option<ResourceStatusResponse>,
    },
    /// One §2.1 `sensors` family member projected from the typed Redfish
    /// sensor schema (`Sensor_v1`, nv-redfish-schema 0.13).
    ///
    /// Fields are the direct `Reading`, `ReadingUnits`, and `ReadingType`
    /// properties. A `sensor_type` field was considered, but `Sensor_v1`
    /// declares no `SensorType` property: `ReadingType` is the enumeration
    /// that names the measured quantity (`Temperature`, `Power`, `Voltage`,
    /// ...), retained as a string so the console renders it without
    /// re-parsing text. `reading` stays numeric (`Edm.Decimal` compiles to
    /// `f64` in nv-redfish 0.13) so the console renders the value without
    /// re-parsing text.
    Sensor {
        reading: Option<f64>,
        reading_units: Option<String>,
        reading_type: Option<String>,
        status: Option<ResourceStatusResponse>,
    },
    /// One §2.1 `controls` family member projected from the typed Redfish
    /// control schema (`Control_v1`, nv-redfish-schema 0.13).
    ///
    /// Fields are the direct `ControlType` and `SetPoint` properties.
    /// `ControlType` is an enumeration retained as a string so the console
    /// renders it without re-parsing text; `set_point` stays numeric
    /// (`Edm.Decimal` compiles to `f64` in nv-redfish 0.13).
    Control {
        control_type: Option<String>,
        set_point: Option<f64>,
        status: Option<ResourceStatusResponse>,
    },
    /// One §2.1 `log-services` family member projected from the typed Redfish
    /// log-service schema (`LogService_v1`, nv-redfish-schema 0.13).
    ///
    /// Fields are the direct `ServiceEnabled` and `MaxNumberOfRecords`
    /// properties and the `Status` property; `max_log_entries` stays numeric
    /// so the console renders the retention bound without re-parsing text. A
    /// `log_entry_count` field was considered, but `LogService_v1` declares no
    /// direct entry-count property (counts live on the linked
    /// `LogEntryCollection`), so it stays out of this strictly projectable
    /// field set. Log entries are themselves separate `LogEntry` resources in
    /// that collection, so this round projects `LogService` metadata only;
    /// reading entries is deferred to a later iteration.
    LogService {
        service_enabled: Option<bool>,
        max_log_entries: Option<u64>,
        status: Option<ResourceStatusResponse>,
    },
    /// One §2.1 `manager-network-protocol` family member projected from the
    /// typed Redfish manager-network-protocol schema
    /// (`ManagerNetworkProtocol_v1`, nv-redfish-schema 0.13).
    ///
    /// Only top-level metadata is projected: the `HostName`, `FQDN`, and
    /// `Status` properties. A `protocol_enabled` field was considered, but
    /// `ProtocolEnabled` is not a top-level property — each protocol's
    /// settings (`HTTP`, `HTTPS`, `SSH`, and others) live in its own nested
    /// `Protocol` object, and the protocol set grows with every schema
    /// release — so a per-protocol projection is deferred to a later
    /// iteration.
    ManagerNetworkProtocol {
        host_name: Option<String>,
        fqdn: Option<String>,
        status: Option<ResourceStatusResponse>,
    },
    /// One §2.1 `host-interfaces` family member projected from the typed
    /// Redfish host-interface schema (`HostInterface_v1`,
    /// nv-redfish-schema 0.13).
    ///
    /// Fields are the direct `InterfaceEnabled` and `Status` properties. A
    /// `host_name` field was considered, but `HostInterface_v1` declares no
    /// host-name property (host identity lives in the linked
    /// `HostEthernetInterfaces` and `ManagerEthernetInterface` resources), so
    /// it stays out of this strictly projectable field set.
    HostInterface {
        interface_enabled: Option<bool>,
        status: Option<ResourceStatusResponse>,
    },
    /// One §2.1 `pcie-devices` family member projected from the typed Redfish
    /// PCIe-device schema (`PCIeDevice_v1`, nv-redfish-schema 0.13).
    ///
    /// Fields are the direct `DeviceType`, `Manufacturer`, `Model`, and
    /// `Status` properties. `device_type` is the `DeviceType` enumeration
    /// (`SingleFunction`, `MultiFunction`, `Simulated`, `Retimer`) retained as
    /// a string so the console renders it without re-parsing text. A
    /// `slot_type` field was considered, but `SlotType` entered
    /// `PCIeDevice_v1` only in `v1_9_0` and older devices may never expose it,
    /// so it stays out of this strictly projectable field set.
    PcieDevice {
        device_type: Option<String>,
        manufacturer: Option<String>,
        model: Option<String>,
        status: Option<ResourceStatusResponse>,
    },
    /// One §2.1 `assembly` family member projected from the typed Redfish
    /// assembly schema (`Assembly_v1` `AssemblyData`, nv-redfish-schema 0.13).
    ///
    /// Fields are the direct `Producer` and `Status` properties of the
    /// `AssemblyData` member (`Status` appears since `v1_1_0`). An
    /// `assembly_type` field was considered, but `Assembly_v1` declares no
    /// `AssemblyType` property anywhere in nv-redfish-schema 0.13 — the type
    /// of an assembly is expressed through the `PhysicalContext` property
    /// added in `v1_2_0` — so it stays out of this strictly projectable
    /// field set.
    Assembly {
        producer: Option<String>,
        status: Option<ResourceStatusResponse>,
    },
    /// One `software-inventory` family member under the §2.1 `update-service`
    /// feature, projected from the typed Redfish software-inventory schema
    /// (`SoftwareInventory_v1`, nv-redfish-schema 0.13).
    ///
    /// Fields are the direct `SoftwareId`, `Version`, `ReleaseDate`, and
    /// `Status` properties. `release_date` stays an RFC 3339 timestamp
    /// because `ReleaseDate` is `Edm.DateTimeOffset` in the schema, so the
    /// console renders the release date without re-parsing text.
    SoftwareInventory {
        software_id: Option<String>,
        version: Option<String>,
        #[serde(with = "time::serde::rfc3339::option")]
        release_date: Option<OffsetDateTime>,
        status: Option<ResourceStatusResponse>,
    },
    /// One §2.1 `event-service` family member projected from the typed Redfish
    /// event-service schema (`EventService_v1`, nv-redfish-schema 0.13).
    ///
    /// Fields are the direct `ServiceEnabled` and `Status` properties.
    /// `DeliveryRetryAttempts` and `DeliveryRetryIntervalSeconds` were
    /// considered, but this round projects service posture only: the retry
    /// policy governs event delivery rather than a console-rendered surface.
    /// Subscriptions are themselves separate `EventSubscription` resources in
    /// the linked collection, so they are not folded into this variant.
    EventService {
        service_enabled: Option<bool>,
        status: Option<ResourceStatusResponse>,
    },
    /// One subscription under the §2.1 `event-service` family, projected from
    /// the typed Redfish event-destination schema (`EventDestination_v1`,
    /// nv-redfish-schema 0.13; DMTF models subscriptions as `EventDestination`
    /// resources, and the nv-redfish 0.13 compile surface exposes the
    /// subscription read surface through the `EventService` `Subscriptions`
    /// navigation).
    ///
    /// Fields are the direct `Destination`, `Protocol`, `Context`, and
    /// `EventTypes` properties and the `Status` property (present since
    /// `v1_6_0`). `protocol` is the `EventDestinationProtocol` enumeration
    /// (`Redfish`, `Kafka`, `SNMPv1`..`SNMPv3`, `SMTP`, `SyslogTLS`..`SyslogRELP`,
    /// `OEM`) retained as a string so the console renders it without
    /// re-parsing text; `event_types` mirrors the `EventTypes` array of
    /// `EventType` values. `HttpHeaders` and the `MessageIds`/`RegistryPrefixes`/
    /// `ResourceTypes` filters were considered but stay out of this first
    /// strictly projectable field set.
    EventSubscription {
        destination: Option<String>,
        protocol: Option<String>,
        context: Option<String>,
        event_types: Option<Vec<String>>,
        status: Option<ResourceStatusResponse>,
    },
    /// One §2.1 `telemetry-service` family member projected from the typed
    /// Redfish telemetry-service schema (`TelemetryService_v1`,
    /// nv-redfish-schema 0.13).
    ///
    /// Only `Status` is projected this round. The compiled `TelemetryService`
    /// type also exposes `service_enabled` (`ServiceEnabled`, `Edm.Boolean`)
    /// and the service-capacity fields `MaxReports`, `MinCollectionInterval`,
    /// `SupportedCollectionFunctions`, and `SupportedTelemetryDataTypes`, but
    /// the product defers them: the service-enabled posture and the telemetry
    /// capability fields belong to the 0.4.0 telemetry-history iteration, and
    /// projecting them now would widen this strictly projectable field set
    /// ahead of the infra payload that must feed it.
    TelemetryService {
        status: Option<ResourceStatusResponse>,
    },
    /// One metric definition under the §2.1 `telemetry-service` family,
    /// projected from the typed Redfish metric-definition schema
    /// (`MetricDefinition_v1`, nv-redfish-schema 0.13).
    ///
    /// Fields are the direct `MetricType` and `Units` properties. `metric_type`
    /// is the `MetricType` enumeration (`Numeric`, `Discrete`, `Gauge`,
    /// `Counter`, `Countdown`, `String`) retained as a string so the console
    /// renders it without re-parsing text. `MetricDefinition_v1` declares no
    /// `Status` property, so this family carries no status field either.
    /// `MetricDataType`, `Precision`, `MinReadingRange`, `MaxReadingRange`,
    /// and the calculation properties describe measurement semantics that the
    /// telemetry-history iteration will render, and stay out of this first
    /// strictly projectable field set.
    MetricDefinition {
        units: Option<String>,
        metric_type: Option<String>,
    },
    /// One metric report under the §2.1 `telemetry-service` family, projected
    /// from the typed Redfish metric-report schema (`MetricReport_v1`,
    /// nv-redfish-schema 0.13).
    ///
    /// `metric_values_count` is derived from the length of the `MetricValues`
    /// array and `metric_values` carries the timestamped readings themselves —
    /// the current-value surface of the 0.4.0 telemetry-history iteration,
    /// which the Telemetry view renders (the resource card shows only the
    /// latest reading). Both stay optional for backward compatibility: the
    /// count is absent when the report carries no value array, and the
    /// readings are absent for snapshots persisted by the 0.2.0 iteration,
    /// which projected only the derived count. `MetricReport_v1` declares no
    /// `Status` property (the report instead carries `Timestamp` and
    /// `Context` metadata), so this family carries no status field either.
    MetricReport {
        metric_values_count: Option<u64>,
        metric_values: Option<Vec<MetricValueResponse>>,
    },
    /// One §2.1 `task-service` family member projected from the typed Redfish
    /// task-service schema (`TaskService_v1`, nv-redfish-schema 0.13).
    ///
    /// Fields are the direct `ServiceEnabled`, `CompletedTaskOverWritePolicy`,
    /// and `Status` properties. `completed_task_overwrite_policy` is the
    /// `OverWritePolicy` enumeration (`Manual`, `Oldest`) retained as a string
    /// so the console renders it without re-parsing text. `DateTime` and
    /// `LifeCycleEventOnTaskStateChange` were considered but describe service
    /// plumbing rather than a console-rendered surface.
    TaskService {
        service_enabled: Option<bool>,
        completed_task_overwrite_policy: Option<String>,
        status: Option<ResourceStatusResponse>,
    },
    /// One task under the §2.1 `task-service` family, projected from the typed
    /// Redfish task schema (`Task_v1`, nv-redfish-schema 0.13).
    ///
    /// Fields are the direct `TaskState`, `TaskStatus`, `PercentComplete`,
    /// `StartTime`, and `EndTime` properties. `task_state` is the `TaskState`
    /// enumeration (`New`, `Starting`, `Running`, `Suspended`, `Interrupted`,
    /// `Pending`, `Stopping`, `Completed`, `Killed`, `Exception`, `Service`,
    /// `Cancelling`, `Cancelled`) and `task_status` the `Resource.Health`
    /// enumeration, both retained as strings so the console renders them
    /// without re-parsing text. `start_time` and `end_time` stay RFC 3339
    /// timestamps because both are `Edm.DateTimeOffset` in the schema, and
    /// `percent_complete` stays numeric (`Edm.Int64`, present since `v1_6_0`).
    /// `Messages` and the `Payload`/`TaskMonitor` links were considered but
    /// stay out of this first strictly projectable field set.
    Task {
        task_state: Option<String>,
        task_status: Option<String>,
        percent_complete: Option<u64>,
        #[serde(with = "time::serde::rfc3339::option")]
        start_time: Option<OffsetDateTime>,
        #[serde(with = "time::serde::rfc3339::option")]
        end_time: Option<OffsetDateTime>,
    },
}

/// One timestamped reading of a `MetricReport`, retained without
/// normalization loss: `timestamp` keeps the RFC 3339 instant of the compiled
/// `Edm.DateTimeOffset` type and `value` the original text of the compiled
/// `Edm.String` type (the DMTF schema represents numeric readings as
/// strings, so a numeric projection would lose the non-numeric boolean and
/// array representations).
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MetricValueResponse {
    #[serde(with = "time::serde::rfc3339::option")]
    timestamp: Option<OffsetDateTime>,
    value: Option<String>,
}

impl MetricValueResponse {
    #[must_use]
    pub const fn new(timestamp: Option<OffsetDateTime>, value: Option<String>) -> Self {
        Self { timestamp, value }
    }

    #[must_use]
    pub const fn timestamp(&self) -> Option<OffsetDateTime> {
        self.timestamp
    }

    #[must_use]
    pub fn value(&self) -> Option<&str> {
        self.value.as_deref()
    }
}

/// One read-only core Redfish resource in a complete refresh Generation.
///
/// `PartialEq` (not `Eq`) because the details enum carries `f64` readings.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CoreResourceResponse {
    source: CoreResourceSourceResponse,
    common: CoreResourceCommonResponse,
    resource: CoreResourceDetailsResponse,
}

impl CoreResourceResponse {
    #[must_use]
    pub const fn new(
        source: CoreResourceSourceResponse,
        common: CoreResourceCommonResponse,
        resource: CoreResourceDetailsResponse,
    ) -> Self {
        Self {
            source,
            common,
            resource,
        }
    }

    #[must_use]
    pub const fn source(&self) -> &CoreResourceSourceResponse {
        &self.source
    }

    #[must_use]
    pub const fn common(&self) -> &CoreResourceCommonResponse {
        &self.common
    }

    #[must_use]
    pub const fn resource(&self) -> &CoreResourceDetailsResponse {
        &self.resource
    }
}

/// Whether an endpoint awaits its first refresh or exposes one complete typed
/// core-resource Generation.
///
/// `PartialEq` (not `Eq`) because the resource details carry `f64` readings.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(
    tag = "state",
    content = "details",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum EndpointResourceSnapshotResponse {
    AwaitingFirstRefresh,
    Current {
        generation: NonZeroU64,
        #[serde(with = "time::serde::rfc3339")]
        observed_at: OffsetDateTime,
        resources: Vec<CoreResourceResponse>,
    },
}

impl EndpointResourceSnapshotResponse {
    #[must_use]
    pub const fn current(
        generation: NonZeroU64,
        observed_at: OffsetDateTime,
        resources: Vec<CoreResourceResponse>,
    ) -> Self {
        Self::Current {
            generation,
            observed_at,
            resources,
        }
    }
}

/// Stable endpoint identity and its latest core-resource snapshot state.
///
/// `PartialEq` (not `Eq`) because the resource details carry `f64` readings.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointResourceInventoryResponse {
    endpoint: EndpointIdentityResponse,
    snapshot: EndpointResourceSnapshotResponse,
}

impl EndpointResourceInventoryResponse {
    #[must_use]
    pub const fn new(
        endpoint: EndpointIdentityResponse,
        snapshot: EndpointResourceSnapshotResponse,
    ) -> Self {
        Self { endpoint, snapshot }
    }

    #[must_use]
    pub const fn endpoint(&self) -> &EndpointIdentityResponse {
        &self.endpoint
    }

    #[must_use]
    pub const fn snapshot(&self) -> &EndpointResourceSnapshotResponse {
        &self.snapshot
    }
}

/// The §12.4 Advanced Diagnostics view of one stored resource snapshot.
///
/// The view is read-only by construction: every field comes from the latest
/// complete refresh Generation, and §12.4 forbids changing Method, submitting
/// arbitrary JSON, and bypassing the normal permission and task model, so this
/// contract carries no request surface. `typed_payload` carries the persisted
/// `TypedPayloadJson` verbatim — the honest representation of the decoded
/// read-only response (§9.4), including any OEM Namespace sections and Task
/// URI the decoded payload itself retains.
///
/// Decode-error paths and `ExtendedInfo` are deliberately absent: a member
/// whose typed decoding failed was skipped at refresh time without leaving a
/// record, so no diagnostics can be fabricated for resources that never
/// entered the snapshot store.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceDiagnosticsResponse {
    endpoint_id: Uuid,
    odata_uri: String,
    odata_type: Option<String>,
    etag: Option<String>,
    feature: String,
    generation: NonZeroU64,
    typed_payload: serde_json::Value,
}

impl ResourceDiagnosticsResponse {
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        endpoint_id: Uuid,
        odata_uri: String,
        odata_type: Option<String>,
        etag: Option<String>,
        feature: String,
        generation: NonZeroU64,
        typed_payload: serde_json::Value,
    ) -> Self {
        Self {
            endpoint_id,
            odata_uri,
            odata_type,
            etag,
            feature,
            generation,
            typed_payload,
        }
    }

    #[must_use]
    pub const fn endpoint_id(&self) -> Uuid {
        self.endpoint_id
    }

    #[must_use]
    pub fn odata_uri(&self) -> &str {
        &self.odata_uri
    }

    #[must_use]
    pub fn odata_type(&self) -> Option<&str> {
        self.odata_type.as_deref()
    }

    #[must_use]
    pub fn etag(&self) -> Option<&str> {
        self.etag.as_deref()
    }

    #[must_use]
    pub fn feature(&self) -> &str {
        &self.feature
    }

    #[must_use]
    pub const fn generation(&self) -> NonZeroU64 {
        self.generation
    }

    #[must_use]
    pub const fn typed_payload(&self) -> &serde_json::Value {
        &self.typed_payload
    }
}

/// The final capability state exposed by the same-origin product API.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityStateResponse {
    Supported,
    ReadOnly,
    Unauthorized,
    TemporarilyUnavailable,
    SchemaIncompatible,
    NotAdvertised,
    NotCompiled,
}

/// The §2.4 capability-ledger classification of one entry.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityClassificationResponse {
    UserFacing,
    Infrastructure,
    LegacyCompatibility,
    Internal,
}

/// The §12.2 Endpoint page that presents one capability entry.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UiLocationResponse {
    Overview,
    Systems,
    Chassis,
    Managers,
    Assembly,
    Processors,
    Memory,
    Pcie,
    Network,
    Power,
    Thermal,
    Sensors,
    Bios,
    Boot,
    SecureBoot,
    Storage,
    Accounts,
    Logs,
    Events,
    Telemetry,
    Update,
    Tasks,
    Oem,
    Diagnostics,
    Infrastructure,
}

/// One capability-ledger entry for a managed endpoint.
///
/// `state` and `observed_at` are both present or both absent: `None` means the
/// endpoint has no observation for this capability yet, which is never
/// disguised as a `not_advertised` probe result.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityEntryResponse {
    capability: String,
    upstream_feature: String,
    classification: CapabilityClassificationResponse,
    ui_location: UiLocationResponse,
    state: Option<CapabilityStateResponse>,
    #[serde(with = "time::serde::rfc3339::option")]
    observed_at: Option<OffsetDateTime>,
}

impl CapabilityEntryResponse {
    #[must_use]
    pub const fn new(
        capability: String,
        upstream_feature: String,
        classification: CapabilityClassificationResponse,
        ui_location: UiLocationResponse,
        state: Option<CapabilityStateResponse>,
        observed_at: Option<OffsetDateTime>,
    ) -> Self {
        Self {
            capability,
            upstream_feature,
            classification,
            ui_location,
            state,
            observed_at,
        }
    }

    #[must_use]
    pub fn capability(&self) -> &str {
        &self.capability
    }

    #[must_use]
    pub fn upstream_feature(&self) -> &str {
        &self.upstream_feature
    }

    #[must_use]
    pub const fn classification(&self) -> CapabilityClassificationResponse {
        self.classification
    }

    #[must_use]
    pub const fn ui_location(&self) -> UiLocationResponse {
        self.ui_location
    }

    #[must_use]
    pub const fn state(&self) -> Option<CapabilityStateResponse> {
        self.state
    }

    #[must_use]
    pub const fn observed_at(&self) -> Option<OffsetDateTime> {
        self.observed_at
    }
}

/// Stable envelope for one endpoint's complete §2.1 capability ledger.
///
/// `entries` always contains all 30 standard capabilities in design-document
/// order, even when none has been observed yet, so the UI can show a reason
/// for every feature instead of hiding it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointCapabilityInventoryResponse {
    endpoint_id: Uuid,
    entries: Vec<CapabilityEntryResponse>,
}

impl EndpointCapabilityInventoryResponse {
    #[must_use]
    pub const fn new(endpoint_id: Uuid, entries: Vec<CapabilityEntryResponse>) -> Self {
        Self {
            endpoint_id,
            entries,
        }
    }

    #[must_use]
    pub const fn endpoint_id(&self) -> Uuid {
        self.endpoint_id
    }

    #[must_use]
    pub fn entries(&self) -> &[CapabilityEntryResponse] {
        &self.entries
    }
}

/// Binds a predeclared trust policy to the address that must satisfy it. The
/// server re-observes TLS without credentials and verifies this exact
/// expectation before any credential is selected or transmitted.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConfirmEndpointTrustRequest {
    address: String,
    trust: EndpointTrustExpectationRequest,
}

impl ConfirmEndpointTrustRequest {
    #[must_use]
    pub const fn new(address: String, trust: EndpointTrustExpectationRequest) -> Self {
        Self { address, trust }
    }

    #[must_use]
    pub fn address(&self) -> &str {
        &self.address
    }

    #[must_use]
    pub const fn trust(&self) -> &EndpointTrustExpectationRequest {
        &self.trust
    }
}

/// A confirmed, address-bound TLS decision established without credentials.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedEndpointResponse {
    address: String,
    tls_trust_mode: TlsTrustModeResponse,
    #[serde(with = "time::serde::rfc3339")]
    trusted_at: OffsetDateTime,
}

impl TrustedEndpointResponse {
    #[must_use]
    pub const fn new(
        address: String,
        tls_trust_mode: TlsTrustModeResponse,
        trusted_at: OffsetDateTime,
    ) -> Self {
        Self {
            address,
            tls_trust_mode,
            trusted_at,
        }
    }

    #[must_use]
    pub fn address(&self) -> &str {
        &self.address
    }

    #[must_use]
    pub const fn tls_trust_mode(&self) -> TlsTrustModeResponse {
        self.tls_trust_mode
    }

    #[must_use]
    pub const fn trusted_at(&self) -> OffsetDateTime {
        self.trusted_at
    }
}

/// A declared trust policy did not match the credential-free TLS observation.
///
/// Fingerprints are public certificate material, never secrets.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrustRejectedResponse {
    expected_fingerprint_sha256: Option<String>,
    observed_fingerprint_sha256: String,
}

impl TrustRejectedResponse {
    #[must_use]
    pub const fn new(
        expected_fingerprint_sha256: Option<String>,
        observed_fingerprint_sha256: String,
    ) -> Self {
        Self {
            expected_fingerprint_sha256,
            observed_fingerprint_sha256,
        }
    }

    #[must_use]
    pub fn expected_fingerprint_sha256(&self) -> Option<&str> {
        self.expected_fingerprint_sha256.as_deref()
    }

    #[must_use]
    pub fn observed_fingerprint_sha256(&self) -> &str {
        &self.observed_fingerprint_sha256
    }
}

/// A secret-free human-readable operation failure for the local console.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorResponse {
    message: String,
}

impl ErrorResponse {
    #[must_use]
    pub const fn new(message: String) -> Self {
        Self { message }
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

/// One endpoint CSV import document submitted as a JSON-encoded string.
///
/// Credential material is deliberately not representable in the interchange
/// format itself.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointCsvImportRequest {
    csv: String,
}

impl EndpointCsvImportRequest {
    #[must_use]
    pub const fn new(csv: String) -> Self {
        Self { csv }
    }

    #[must_use]
    pub fn csv(&self) -> &str {
        &self.csv
    }
}

/// The independent terminal status of one imported endpoint row.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointCsvImportRowStatusResponse {
    Enrolled,
    TlsProbeFailed,
    TrustRejected,
    EnrollmentFailed,
}

/// One independent, secret-free result inside an endpoint CSV import.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointCsvImportRowResponse {
    record_number: u64,
    address: String,
    status: EndpointCsvImportRowStatusResponse,
    endpoint_id: Option<Uuid>,
    message: Option<String>,
}

impl EndpointCsvImportRowResponse {
    #[must_use]
    pub const fn new(
        record_number: u64,
        address: String,
        status: EndpointCsvImportRowStatusResponse,
        endpoint_id: Option<Uuid>,
        message: Option<String>,
    ) -> Self {
        Self {
            record_number,
            address,
            status,
            endpoint_id,
            message,
        }
    }

    #[must_use]
    pub const fn record_number(&self) -> u64 {
        self.record_number
    }

    #[must_use]
    pub fn address(&self) -> &str {
        &self.address
    }

    #[must_use]
    pub const fn status(&self) -> EndpointCsvImportRowStatusResponse {
        self.status
    }

    #[must_use]
    pub const fn endpoint_id(&self) -> Option<Uuid> {
        self.endpoint_id
    }

    #[must_use]
    pub fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }
}

/// Per-row results for one endpoint CSV import, complete or partial.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointCsvImportResponse {
    total_rows: u64,
    succeeded_count: u64,
    failed_count: u64,
    rows: Vec<EndpointCsvImportRowResponse>,
}

impl EndpointCsvImportResponse {
    #[must_use]
    pub const fn new(
        total_rows: u64,
        succeeded_count: u64,
        failed_count: u64,
        rows: Vec<EndpointCsvImportRowResponse>,
    ) -> Self {
        Self {
            total_rows,
            succeeded_count,
            failed_count,
            rows,
        }
    }

    #[must_use]
    pub const fn total_rows(&self) -> u64 {
        self.total_rows
    }

    #[must_use]
    pub const fn succeeded_count(&self) -> u64 {
        self.succeeded_count
    }

    #[must_use]
    pub const fn failed_count(&self) -> u64 {
        self.failed_count
    }

    #[must_use]
    pub fn rows(&self) -> &[EndpointCsvImportRowResponse] {
        &self.rows
    }
}

/// Secret-free input that refreshes several managed endpoints in one bounded
/// batch.
///
/// `endpoint_ids` is a list of managed endpoint UUIDs; the non-empty,
/// duplicate-free, bounded, and managed-endpoint checks happen in the
/// application batch-refresh use case so the wire contract stays a pure
/// projection, exactly like the operation submission request.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RefreshEndpointsRequest {
    endpoint_ids: Vec<Uuid>,
}

impl RefreshEndpointsRequest {
    #[must_use]
    pub const fn new(endpoint_ids: Vec<Uuid>) -> Self {
        Self { endpoint_ids }
    }

    /// Returns the endpoint UUIDs in submission order.
    #[must_use]
    pub fn endpoint_ids(&self) -> &[Uuid] {
        &self.endpoint_ids
    }
}

/// The independent terminal status of one endpoint inside a refresh batch.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointRefreshStatusResponse {
    /// The endpoint's complete resource Generation committed and its
    /// capability snapshot was replaced.
    Refreshed,
    /// The endpoint refresh failed for a classified reason; the last complete
    /// snapshot is retained (§9.5).
    Failed,
    /// The endpoint disappeared between the batch pre-check and its refresh.
    NotFound,
}

/// One independent, secret-free result inside an endpoint refresh batch.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointRefreshResultResponse {
    endpoint_id: Uuid,
    status: EndpointRefreshStatusResponse,
    generation: Option<u64>,
    snapshot_count: Option<u64>,
    message: Option<String>,
}

impl EndpointRefreshResultResponse {
    #[must_use]
    pub const fn new(
        endpoint_id: Uuid,
        status: EndpointRefreshStatusResponse,
        generation: Option<u64>,
        snapshot_count: Option<u64>,
        message: Option<String>,
    ) -> Self {
        Self {
            endpoint_id,
            status,
            generation,
            snapshot_count,
            message,
        }
    }

    #[must_use]
    pub const fn endpoint_id(&self) -> Uuid {
        self.endpoint_id
    }

    #[must_use]
    pub const fn status(&self) -> EndpointRefreshStatusResponse {
        self.status
    }

    /// Returns the committed Generation of a `refreshed` result.
    #[must_use]
    pub const fn generation(&self) -> Option<u64> {
        self.generation
    }

    /// Returns the number of committed snapshots of a `refreshed` result.
    #[must_use]
    pub const fn snapshot_count(&self) -> Option<u64> {
        self.snapshot_count
    }

    /// Returns the classified failure detail of a `failed` result.
    #[must_use]
    pub fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }
}

/// Per-endpoint results for one refresh batch.
///
/// The response is complete for the submitted list: every endpoint appears
/// exactly once, `total` equals the submitted count, and `failed_count`
/// counts every result that is not `refreshed` (including `not_found`).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BatchRefreshResponse {
    total: u64,
    succeeded_count: u64,
    failed_count: u64,
    results: Vec<EndpointRefreshResultResponse>,
}

impl BatchRefreshResponse {
    #[must_use]
    pub const fn new(
        total: u64,
        succeeded_count: u64,
        failed_count: u64,
        results: Vec<EndpointRefreshResultResponse>,
    ) -> Self {
        Self {
            total,
            succeeded_count,
            failed_count,
            results,
        }
    }

    #[must_use]
    pub const fn total(&self) -> u64 {
        self.total
    }

    #[must_use]
    pub const fn succeeded_count(&self) -> u64 {
        self.succeeded_count
    }

    #[must_use]
    pub const fn failed_count(&self) -> u64 {
        self.failed_count
    }

    #[must_use]
    pub fn results(&self) -> &[EndpointRefreshResultResponse] {
        &self.results
    }
}

/// The stable, secret-free target of one audit event.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditTargetResponse {
    kind: String,
    identifier: Option<String>,
}

impl AuditTargetResponse {
    #[must_use]
    pub const fn new(kind: String, identifier: Option<String>) -> Self {
        Self { kind, identifier }
    }

    #[must_use]
    pub fn kind(&self) -> &str {
        &self.kind
    }

    #[must_use]
    pub fn identifier(&self) -> Option<&str> {
        self.identifier.as_deref()
    }
}

/// The stable, secret-free lifecycle outcome of one audit event.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditOutcomeResponse {
    kind: String,
    progress: Option<String>,
    failure: Option<String>,
    verification: Option<String>,
}

impl AuditOutcomeResponse {
    #[must_use]
    pub const fn new(
        kind: String,
        progress: Option<String>,
        failure: Option<String>,
        verification: Option<String>,
    ) -> Self {
        Self {
            kind,
            progress,
            failure,
            verification,
        }
    }

    #[must_use]
    pub fn kind(&self) -> &str {
        &self.kind
    }

    #[must_use]
    pub fn progress(&self) -> Option<&str> {
        self.progress.as_deref()
    }

    #[must_use]
    pub fn failure(&self) -> Option<&str> {
        self.failure.as_deref()
    }

    #[must_use]
    pub fn verification(&self) -> Option<&str> {
        self.verification.as_deref()
    }
}

/// One immutable, secret-free audit event for the local console.
///
/// All values are stable product codes or validated identity data; no
/// credential, token, or certificate material can be represented.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditEventResponse {
    #[serde(with = "time::serde::rfc3339")]
    occurred_at: OffsetDateTime,
    actor: String,
    action: String,
    target: AuditTargetResponse,
    outcome: AuditOutcomeResponse,
    sequence: u32,
    operation_id: Uuid,
    message: String,
}

impl AuditEventResponse {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub const fn new(
        occurred_at: OffsetDateTime,
        actor: String,
        action: String,
        target: AuditTargetResponse,
        outcome: AuditOutcomeResponse,
        sequence: u32,
        operation_id: Uuid,
        message: String,
    ) -> Self {
        Self {
            occurred_at,
            actor,
            action,
            target,
            outcome,
            sequence,
            operation_id,
            message,
        }
    }

    #[must_use]
    pub const fn occurred_at(&self) -> OffsetDateTime {
        self.occurred_at
    }

    #[must_use]
    pub fn actor(&self) -> &str {
        &self.actor
    }

    #[must_use]
    pub fn action(&self) -> &str {
        &self.action
    }

    #[must_use]
    pub const fn target(&self) -> &AuditTargetResponse {
        &self.target
    }

    #[must_use]
    pub const fn outcome(&self) -> &AuditOutcomeResponse {
        &self.outcome
    }

    #[must_use]
    pub const fn sequence(&self) -> u32 {
        self.sequence
    }

    #[must_use]
    pub const fn operation_id(&self) -> Uuid {
        self.operation_id
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

/// Stable envelope for a bounded, newest-first audit query.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditQueryResponse {
    events: Vec<AuditEventResponse>,
}

impl AuditQueryResponse {
    #[must_use]
    pub const fn new(events: Vec<AuditEventResponse>) -> Self {
        Self { events }
    }

    #[must_use]
    pub fn events(&self) -> &[AuditEventResponse] {
        &self.events
    }
}

/// One persisted BMC event for the local console (§14.4).
///
/// All values are stable product codes or the BMC-reported fields, kept
/// verbatim: the raw Redfish `MessageId`, the product severity code (see
/// [`EventResponse::severity`]), the original `Message` text when the BMC
/// provided one, the BMC's own event timestamp, and the product-side receive
/// time — so the viewer always sees the two clocks side by side. No
/// credential, token, or certificate material can be represented.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EventResponse {
    id: Uuid,
    endpoint_id: Uuid,
    message_id: String,
    severity: String,
    message: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    event_timestamp: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    observed_at: OffsetDateTime,
}

impl EventResponse {
    #[must_use]
    pub const fn new(
        id: Uuid,
        endpoint_id: Uuid,
        message_id: String,
        severity: String,
        message: Option<String>,
        event_timestamp: OffsetDateTime,
        observed_at: OffsetDateTime,
    ) -> Self {
        Self {
            id,
            endpoint_id,
            message_id,
            severity,
            message,
            event_timestamp,
            observed_at,
        }
    }

    #[must_use]
    pub const fn id(&self) -> Uuid {
        self.id
    }

    /// Returns the source endpoint (§14.4 记录事件来源).
    #[must_use]
    pub const fn endpoint_id(&self) -> Uuid {
        self.endpoint_id
    }

    /// Returns the raw Redfish `MessageId`, exactly as the BMC reported it.
    #[must_use]
    pub fn message_id(&self) -> &str {
        &self.message_id
    }

    /// Returns the stable product severity code.
    ///
    /// The vocabulary is the three Redfish `Event_v1` CSDL severities with
    /// the product's stable lowercase spellings: `ok`, `warning`, and
    /// `critical`. An event whose severity this build cannot classify is
    /// refused at ingestion, so the console never renders an unknown code.
    #[must_use]
    pub fn severity(&self) -> &str {
        &self.severity
    }

    /// Returns the original Redfish `Message` text, when the BMC provided
    /// one.
    #[must_use]
    pub fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }

    /// Returns the BMC's own event timestamp.
    #[must_use]
    pub const fn event_timestamp(&self) -> OffsetDateTime {
        self.event_timestamp
    }

    /// Returns when the product received the event.
    #[must_use]
    pub const fn observed_at(&self) -> OffsetDateTime {
        self.observed_at
    }
}

/// Stable envelope for a bounded, newest-first event query (§14.4).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EventListResponse {
    events: Vec<EventResponse>,
}

impl EventListResponse {
    #[must_use]
    pub const fn new(events: Vec<EventResponse>) -> Self {
        Self { events }
    }

    #[must_use]
    pub fn events(&self) -> &[EventResponse] {
        &self.events
    }
}

/// One telemetry series with the aggregates of the §14.4 current-value
/// surface.
///
/// `series_key` is the product's stable series identity text (the report
/// identity the sampler derived; see the domain `SeriesKey` doc), `sample_count`
/// the size of the bounded history the persistence maintains, and
/// `latest_value`/`latest_observed_at` the newest retained sample — both
/// present or both absent, since a series created by an upsert whose append
/// failed has no samples yet. The product is deliberately not a general-purpose
/// time-series database (§14.4): this is the whole series surface, bounded by
/// the retention policy.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetrySeriesResponse {
    series_id: Uuid,
    endpoint_id: Uuid,
    series_key: String,
    sample_count: u64,
    latest_value: Option<f64>,
    #[serde(with = "time::serde::rfc3339::option")]
    latest_observed_at: Option<OffsetDateTime>,
}

impl TelemetrySeriesResponse {
    #[must_use]
    pub const fn new(
        series_id: Uuid,
        endpoint_id: Uuid,
        series_key: String,
        sample_count: u64,
        latest_value: Option<f64>,
        latest_observed_at: Option<OffsetDateTime>,
    ) -> Self {
        Self {
            series_id,
            endpoint_id,
            series_key,
            sample_count,
            latest_value,
            latest_observed_at,
        }
    }

    #[must_use]
    pub const fn series_id(&self) -> Uuid {
        self.series_id
    }

    #[must_use]
    pub const fn endpoint_id(&self) -> Uuid {
        self.endpoint_id
    }

    #[must_use]
    pub fn series_key(&self) -> &str {
        &self.series_key
    }

    #[must_use]
    pub const fn sample_count(&self) -> u64 {
        self.sample_count
    }

    #[must_use]
    pub const fn latest_value(&self) -> Option<f64> {
        self.latest_value
    }

    #[must_use]
    pub const fn latest_observed_at(&self) -> Option<OffsetDateTime> {
        self.latest_observed_at
    }
}

/// Stable envelope for the telemetry series query (§14.4).
///
/// `PartialEq` (not `Eq`) because the series items carry `f64` readings.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetrySeriesListResponse {
    series: Vec<TelemetrySeriesResponse>,
}

impl TelemetrySeriesListResponse {
    #[must_use]
    pub const fn new(series: Vec<TelemetrySeriesResponse>) -> Self {
        Self { series }
    }

    #[must_use]
    pub fn series(&self) -> &[TelemetrySeriesResponse] {
        &self.series
    }
}

/// One persisted telemetry reading for the local console (§14.4).
///
/// `observed_at` is the product clock's sampling time — the ordering and
/// bounded-history key — and `bmc_timestamp` optionally preserves the BMC's
/// own `MetricValue.Timestamp` beside it, exactly like the events model
/// keeps the two clocks side by side. The value is finite by construction
/// (the domain refuses non-finite readings).
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetrySampleResponse {
    series_id: Uuid,
    #[serde(with = "time::serde::rfc3339")]
    observed_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    bmc_timestamp: Option<OffsetDateTime>,
    value: f64,
}

impl TelemetrySampleResponse {
    #[must_use]
    pub const fn new(
        series_id: Uuid,
        observed_at: OffsetDateTime,
        bmc_timestamp: Option<OffsetDateTime>,
        value: f64,
    ) -> Self {
        Self {
            series_id,
            observed_at,
            bmc_timestamp,
            value,
        }
    }

    #[must_use]
    pub const fn series_id(&self) -> Uuid {
        self.series_id
    }

    /// Returns when the product's sampler took this reading.
    #[must_use]
    pub const fn observed_at(&self) -> OffsetDateTime {
        self.observed_at
    }

    /// Returns the BMC's own `MetricValue.Timestamp`, when the source
    /// reported one.
    #[must_use]
    pub const fn bmc_timestamp(&self) -> Option<OffsetDateTime> {
        self.bmc_timestamp
    }

    #[must_use]
    pub const fn value(&self) -> f64 {
        self.value
    }
}

/// Stable envelope for a bounded, newest-first sample query (§14.4).
///
/// `PartialEq` (not `Eq`) because the sample items carry `f64` readings.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetrySampleListResponse {
    samples: Vec<TelemetrySampleResponse>,
}

impl TelemetrySampleListResponse {
    #[must_use]
    pub const fn new(samples: Vec<TelemetrySampleResponse>) -> Self {
        Self { samples }
    }

    #[must_use]
    pub fn samples(&self) -> &[TelemetrySampleResponse] {
        &self.samples
    }
}

/// The stable §13.1 product source of one persisted operation.
///
/// The three wire values mirror the domain source codes exactly, so the
/// console echoes the source it submitted and never sees an unknown one.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationSourceResponse {
    /// A write submitted from a standalone local GUI.
    Standalone,
    /// A write submitted from a site GUI.
    Site,
    /// A write dispatched by the Center.
    Center,
}

/// The §13.2 lifecycle phase of one persisted operation.
///
/// The wire values are `snake_case` by console contract and match the domain's
/// stable codes in every phase except the asynchronous acceptance phase,
/// which the domain codes `waiting-remote` (its persistence vocabulary) and
/// the console wire carries as `waiting_remote`; the Web projection
/// translates between the two vocabularies in both directions.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationStateResponse {
    /// Persisted but not yet picked up for pre-flight checks (§13.3 step 6).
    Queued,
    /// Pre-flight checks are in progress (§13.3 steps 1–5).
    Validating,
    /// The typed Redfish method call is being dispatched (§13.3 step 7).
    Running,
    /// An asynchronous BMC Task is being monitored (§13.3 step 8, §13.6).
    WaitingRemote,
    /// The target is being re-read and the result verified (§13.3 steps 9–10).
    Verifying,
    /// Verification confirmed the expected result (§13.3 step 11).
    Succeeded,
    /// A provable failure ended the operation.
    Failed,
    /// The final result cannot currently be proven (§13.5).
    Unknown,
    /// The product proved that the operation stopped.
    Cancelled,
}

/// Secret-free input that converts one typed Redfish write into a persisted
/// operation (§13.1).
///
/// `source` is optional and defaults to `standalone`; the accepted values are
/// the three §13.1 sources (`standalone`, `site`, `center`). `targets` is a
/// list of managed endpoint UUIDs; the non-empty check happens in the
/// application submission use case so the wire contract stays a pure
/// projection. `command` is the domain's own typed write surface (§7.5),
/// serialized with its canonical serde shape — the §9.4 typed-payload rule
/// applied to the API boundary, so the wire command is exactly the persisted
/// command.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateOperationRequest {
    source: Option<String>,
    targets: Vec<Uuid>,
    command: RedfishCommand,
}

impl CreateOperationRequest {
    /// Constructs a submission request; `None` source means `standalone`.
    #[must_use]
    pub const fn new(source: Option<String>, targets: Vec<Uuid>, command: RedfishCommand) -> Self {
        Self {
            source,
            targets,
            command,
        }
    }

    /// Returns the requested source, defaulting to `standalone` at the
    /// boundary when absent.
    #[must_use]
    pub fn source(&self) -> Option<&str> {
        self.source.as_deref()
    }

    /// Returns the target endpoint UUIDs in submission order.
    #[must_use]
    pub fn targets(&self) -> &[Uuid] {
        &self.targets
    }

    /// Returns the typed write command the operation must execute.
    #[must_use]
    pub const fn command(&self) -> &RedfishCommand {
        &self.command
    }
}

/// One object an operation acts on, bound to the endpoint that receives the
/// Redfish request (§13.1).
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationTargetResponse {
    target_id: Uuid,
    endpoint_id: Uuid,
}

impl OperationTargetResponse {
    #[must_use]
    pub const fn new(target_id: Uuid, endpoint_id: Uuid) -> Self {
        Self {
            target_id,
            endpoint_id,
        }
    }

    #[must_use]
    pub const fn target_id(self) -> Uuid {
        self.target_id
    }

    #[must_use]
    pub const fn endpoint_id(self) -> Uuid {
        self.endpoint_id
    }
}

/// One persisted operation projection for the console (§13.1).
///
/// The command echoes the submitted typed write in its canonical serde shape,
/// so the console renders exactly what will be dispatched (§13.3 step 7).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationResponse {
    operation_id: Uuid,
    source: OperationSourceResponse,
    targets: Vec<OperationTargetResponse>,
    command: RedfishCommand,
    state: OperationStateResponse,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    updated_at: OffsetDateTime,
}

impl OperationResponse {
    #[must_use]
    pub const fn new(
        operation_id: Uuid,
        source: OperationSourceResponse,
        targets: Vec<OperationTargetResponse>,
        command: RedfishCommand,
        state: OperationStateResponse,
        created_at: OffsetDateTime,
        updated_at: OffsetDateTime,
    ) -> Self {
        Self {
            operation_id,
            source,
            targets,
            command,
            state,
            created_at,
            updated_at,
        }
    }

    #[must_use]
    pub const fn operation_id(&self) -> Uuid {
        self.operation_id
    }

    #[must_use]
    pub const fn source(&self) -> OperationSourceResponse {
        self.source
    }

    #[must_use]
    pub fn targets(&self) -> &[OperationTargetResponse] {
        &self.targets
    }

    /// Returns the typed write command of the operation.
    #[must_use]
    pub const fn command(&self) -> &RedfishCommand {
        &self.command
    }

    #[must_use]
    pub const fn state(&self) -> OperationStateResponse {
        self.state
    }

    #[must_use]
    pub const fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    #[must_use]
    pub const fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }
}

/// The acknowledgement of one multi-target batch submission (§13.7).
///
/// A batch is one parent record plus one ordinary single-target child
/// operation per submitted endpoint. `targets` echoes the submitted endpoint
/// UUIDs in submission order and `child_operation_ids` carries one
/// `OperationId` per target in the same order, so the console can pair every
/// endpoint with the operation record that will execute and report its write;
/// the children are ordinary persisted operations with their own lifecycle,
/// listed and executed exactly like single submissions. `command` echoes the
/// typed write every child will dispatch (§13.3 step 7).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BatchOperationResponse {
    batch_id: Uuid,
    source: OperationSourceResponse,
    command: RedfishCommand,
    targets: Vec<Uuid>,
    child_operation_ids: Vec<Uuid>,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
}

impl BatchOperationResponse {
    #[must_use]
    pub const fn new(
        batch_id: Uuid,
        source: OperationSourceResponse,
        command: RedfishCommand,
        targets: Vec<Uuid>,
        child_operation_ids: Vec<Uuid>,
        created_at: OffsetDateTime,
    ) -> Self {
        Self {
            batch_id,
            source,
            command,
            targets,
            child_operation_ids,
            created_at,
        }
    }

    #[must_use]
    pub const fn batch_id(&self) -> Uuid {
        self.batch_id
    }

    #[must_use]
    pub const fn source(&self) -> OperationSourceResponse {
        self.source
    }

    /// Returns the typed write command every child operation dispatches.
    #[must_use]
    pub const fn command(&self) -> &RedfishCommand {
        &self.command
    }

    /// Returns the submitted endpoint UUIDs in submission order.
    #[must_use]
    pub fn targets(&self) -> &[Uuid] {
        &self.targets
    }

    /// Returns one child `OperationId` per target, in the same order as
    /// [`Self::targets`].
    #[must_use]
    pub fn child_operation_ids(&self) -> &[Uuid] {
        &self.child_operation_ids
    }

    #[must_use]
    pub const fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }
}

/// Stable envelope for one operation listing, optionally filtered by state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationListResponse {
    operations: Vec<OperationResponse>,
}

impl OperationListResponse {
    #[must_use]
    pub const fn new(operations: Vec<OperationResponse>) -> Self {
        Self { operations }
    }

    #[must_use]
    pub fn operations(&self) -> &[OperationResponse] {
        &self.operations
    }
}

/// The derived §13.7 lifecycle phase of one batch, as console vocabulary.
///
/// The six wire values mirror the domain batch-state codes exactly, so the
/// console renders the verdict the server derived from the children — a batch
/// state is never computed client-side.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchOperationStateResponse {
    /// Every child operation is still `Queued`; nothing has started.
    Queued,
    /// At least one child is still in flight; children may already have
    /// finished.
    Running,
    /// Every child operation succeeded.
    Succeeded,
    /// At least one child failed provably (a partial failure never becomes an
    /// overall success).
    Failed,
    /// At least one child ended `Unknown` and no child failed.
    Unknown,
    /// Every child operation was cancelled.
    Cancelled,
}

/// The §13.7 outcome buckets of one batch's completed children.
///
/// `total` counts every child, including the ones still in flight, which are
/// counted in no bucket; `unsupported` counts the classified
/// capability-unsupported failures, separated from ordinary `failed` by the
/// server-side failure classification.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BatchOutcomeCountsResponse {
    succeeded: usize,
    failed: usize,
    unknown: usize,
    unsupported: usize,
    cancelled: usize,
    total: usize,
}

impl BatchOutcomeCountsResponse {
    #[must_use]
    pub const fn new(
        succeeded: usize,
        failed: usize,
        unknown: usize,
        unsupported: usize,
        cancelled: usize,
        total: usize,
    ) -> Self {
        Self {
            succeeded,
            failed,
            unknown,
            unsupported,
            cancelled,
            total,
        }
    }

    #[must_use]
    pub const fn succeeded(self) -> usize {
        self.succeeded
    }

    #[must_use]
    pub const fn failed(self) -> usize {
        self.failed
    }

    #[must_use]
    pub const fn unknown(self) -> usize {
        self.unknown
    }

    #[must_use]
    pub const fn unsupported(self) -> usize {
        self.unsupported
    }

    #[must_use]
    pub const fn cancelled(self) -> usize {
        self.cancelled
    }

    #[must_use]
    pub const fn total(self) -> usize {
        self.total
    }
}

/// One batch's derived summary projection for the console (§13.7).
///
/// The state and the outcome buckets are server-derived facts: the console
/// renders them as-is and never infers a batch verdict from the children.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BatchSummaryResponse {
    batch_id: Uuid,
    source: OperationSourceResponse,
    command: RedfishCommand,
    state: BatchOperationStateResponse,
    outcomes: BatchOutcomeCountsResponse,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
}

impl BatchSummaryResponse {
    #[must_use]
    pub const fn new(
        batch_id: Uuid,
        source: OperationSourceResponse,
        command: RedfishCommand,
        state: BatchOperationStateResponse,
        outcomes: BatchOutcomeCountsResponse,
        created_at: OffsetDateTime,
    ) -> Self {
        Self {
            batch_id,
            source,
            command,
            state,
            outcomes,
            created_at,
        }
    }

    #[must_use]
    pub const fn batch_id(&self) -> Uuid {
        self.batch_id
    }

    #[must_use]
    pub const fn source(&self) -> OperationSourceResponse {
        self.source
    }

    /// Returns the typed write command every child operation dispatches.
    #[must_use]
    pub const fn command(&self) -> &RedfishCommand {
        &self.command
    }

    /// Returns the derived batch verdict.
    #[must_use]
    pub const fn state(&self) -> BatchOperationStateResponse {
        self.state
    }

    /// Returns the outcome buckets of the batch's children.
    #[must_use]
    pub const fn outcomes(&self) -> BatchOutcomeCountsResponse {
        self.outcomes
    }

    #[must_use]
    pub const fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }
}

/// Stable envelope for one batch listing in acceptance order (§13.7).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BatchListResponse {
    batches: Vec<BatchSummaryResponse>,
}

impl BatchListResponse {
    #[must_use]
    pub const fn new(batches: Vec<BatchSummaryResponse>) -> Self {
        Self { batches }
    }

    #[must_use]
    pub fn batches(&self) -> &[BatchSummaryResponse] {
        &self.batches
    }
}

/// One batch's full report: the derived summary plus every child operation
/// (§13.7).
///
/// The children are ordinary operation projections in target order, so the
/// console can pair every endpoint with the operation record that executed
/// its write; the batch verdict and the outcome buckets stay server-derived.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BatchDetailResponse {
    batch_id: Uuid,
    source: OperationSourceResponse,
    command: RedfishCommand,
    state: BatchOperationStateResponse,
    outcomes: BatchOutcomeCountsResponse,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    children: Vec<OperationResponse>,
}

impl BatchDetailResponse {
    #[must_use]
    pub const fn new(
        batch_id: Uuid,
        source: OperationSourceResponse,
        command: RedfishCommand,
        state: BatchOperationStateResponse,
        outcomes: BatchOutcomeCountsResponse,
        created_at: OffsetDateTime,
        children: Vec<OperationResponse>,
    ) -> Self {
        Self {
            batch_id,
            source,
            command,
            state,
            outcomes,
            created_at,
            children,
        }
    }

    #[must_use]
    pub const fn batch_id(&self) -> Uuid {
        self.batch_id
    }

    #[must_use]
    pub const fn source(&self) -> OperationSourceResponse {
        self.source
    }

    /// Returns the typed write command every child operation dispatches.
    #[must_use]
    pub const fn command(&self) -> &RedfishCommand {
        &self.command
    }

    /// Returns the derived batch verdict.
    #[must_use]
    pub const fn state(&self) -> BatchOperationStateResponse {
        self.state
    }

    /// Returns the outcome buckets of the batch's children.
    #[must_use]
    pub const fn outcomes(&self) -> BatchOutcomeCountsResponse {
        self.outcomes
    }

    #[must_use]
    pub const fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// Returns the batch's children in target order.
    #[must_use]
    pub fn children(&self) -> &[OperationResponse] {
        &self.children
    }
}

/// The §14.3 lifecycle state of one firmware upload artifact.
///
/// The three wire values mirror the domain state codes exactly, so the
/// console renders an artifact card without translating a persistence
/// vocabulary.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactStateResponse {
    /// Bytes are still being received; no finalize has succeeded yet.
    Uploading,
    /// The complete byte range was received and its SHA-256 verified.
    Ready,
    /// A finalize attempt could not validate the received bytes.
    Failed,
}

/// Declares one firmware artifact before any byte is transferred (§14.3).
///
/// `sha256` is the lowercase hex-encoded digest the complete file must match;
/// the server verifies it when the finalize step reads back the stored file,
/// so a truncated or corrupted upload surfaces as a clean `failed` verdict
/// instead of reaching a BMC.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateArtifactRequest {
    name: String,
    size_bytes: u64,
    sha256: String,
}

impl CreateArtifactRequest {
    #[must_use]
    pub const fn new(name: String, size_bytes: u64, sha256: String) -> Self {
        Self {
            name,
            size_bytes,
            sha256,
        }
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub const fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    #[must_use]
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
}

/// One §9.3 `artifacts` row projected without file content.
///
/// The projection is deliberately secret-free and content-free: the console
/// renders metadata and upload progress, and the file bytes are only ever
/// read back by the server for the finalize checksum.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactResponse {
    artifact_id: Uuid,
    name: String,
    size_bytes: u64,
    sha256: String,
    state: ArtifactStateResponse,
    uploaded_bytes: u64,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    updated_at: OffsetDateTime,
}

impl ArtifactResponse {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub const fn new(
        artifact_id: Uuid,
        name: String,
        size_bytes: u64,
        sha256: String,
        state: ArtifactStateResponse,
        uploaded_bytes: u64,
        created_at: OffsetDateTime,
        updated_at: OffsetDateTime,
    ) -> Self {
        Self {
            artifact_id,
            name,
            size_bytes,
            sha256,
            state,
            uploaded_bytes,
            created_at,
            updated_at,
        }
    }

    #[must_use]
    pub const fn artifact_id(&self) -> Uuid {
        self.artifact_id
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub const fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    #[must_use]
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    #[must_use]
    pub const fn state(&self) -> ArtifactStateResponse {
        self.state
    }

    #[must_use]
    pub const fn uploaded_bytes(&self) -> u64 {
        self.uploaded_bytes
    }

    #[must_use]
    pub const fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    #[must_use]
    pub const fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }
}

/// Stable envelope for the §9.3 artifact inventory.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactListResponse {
    artifacts: Vec<ArtifactResponse>,
}

impl ArtifactListResponse {
    #[must_use]
    pub const fn new(artifacts: Vec<ArtifactResponse>) -> Self {
        Self { artifacts }
    }

    #[must_use]
    pub fn artifacts(&self) -> &[ArtifactResponse] {
        &self.artifacts
    }
}

/// One base64-encoded byte range of an artifact upload (§14.3).
///
/// `data` is RFC 4648 §4 standard base64 with padding; the server decodes it
/// before writing. `offset` must equal the bytes already received, so a
/// client resumes from the last acknowledged progress and the server never
/// has to merge a hole.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AppendArtifactChunkRequest {
    offset: u64,
    data: String,
}

impl AppendArtifactChunkRequest {
    #[must_use]
    pub const fn new(offset: u64, data: String) -> Self {
        Self { offset, data }
    }

    #[must_use]
    pub const fn offset(&self) -> u64 {
        self.offset
    }

    #[must_use]
    pub fn data(&self) -> &str {
        &self.data
    }
}

/// The upload progress of one artifact after a chunk append.
///
/// The client resumes from `uploaded_bytes`: the next chunk must carry exactly
/// that offset, which makes an interrupted upload recoverable by re-running
/// the remaining chunks.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactProgressResponse {
    artifact_id: Uuid,
    uploaded_bytes: u64,
    size_bytes: u64,
}

impl ArtifactProgressResponse {
    #[must_use]
    pub const fn new(artifact_id: Uuid, uploaded_bytes: u64, size_bytes: u64) -> Self {
        Self {
            artifact_id,
            uploaded_bytes,
            size_bytes,
        }
    }

    #[must_use]
    pub const fn artifact_id(&self) -> Uuid {
        self.artifact_id
    }

    #[must_use]
    pub const fn uploaded_bytes(&self) -> u64 {
        self.uploaded_bytes
    }

    #[must_use]
    pub const fn size_bytes(&self) -> u64 {
        self.size_bytes
    }
}

/// A finalize attempt that could not validate the received bytes (§14.3).
///
/// Carries the artifact's terminal `failed` projection plus the exact reason
/// so the console can explain why verification did not pass in one round
/// trip, without a follow-up read.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactFinalizeFailureResponse {
    artifact: ArtifactResponse,
    reason: String,
}

impl ArtifactFinalizeFailureResponse {
    #[must_use]
    pub const fn new(artifact: ArtifactResponse, reason: String) -> Self {
        Self { artifact, reason }
    }

    #[must_use]
    pub const fn artifact(&self) -> &ArtifactResponse {
        &self.artifact
    }

    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

/// The §14.2 static-grouping input: a group name declared before creation.
///
/// The server parses and validates the name against the domain `GroupName`
/// rules; an invalid name is rejected with 400 and a duplicate name with 409,
/// so the console never submits a name the product cannot persist (§9.3
/// `groups`).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateGroupRequest {
    name: String,
}

impl CreateGroupRequest {
    #[must_use]
    pub const fn new(name: String) -> Self {
        Self { name }
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// One §9.3 `groups` row projected for the §12.1 Groups navigation and the
/// §14.2 static-group filter.
///
/// `member_endpoint_ids` lists the managed endpoints currently in the group
/// in deterministic product order. Timestamps stay RFC 3339 so the console
/// renders group age and last change without re-parsing text.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GroupResponse {
    group_id: Uuid,
    name: String,
    member_endpoint_ids: Vec<Uuid>,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    updated_at: OffsetDateTime,
}

impl GroupResponse {
    #[must_use]
    pub const fn new(
        group_id: Uuid,
        name: String,
        member_endpoint_ids: Vec<Uuid>,
        created_at: OffsetDateTime,
        updated_at: OffsetDateTime,
    ) -> Self {
        Self {
            group_id,
            name,
            member_endpoint_ids,
            created_at,
            updated_at,
        }
    }

    #[must_use]
    pub const fn group_id(&self) -> Uuid {
        self.group_id
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn member_endpoint_ids(&self) -> &[Uuid] {
        &self.member_endpoint_ids
    }

    #[must_use]
    pub const fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    #[must_use]
    pub const fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }
}

/// Stable envelope for the complete static-group inventory (§12.1).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GroupListResponse {
    groups: Vec<GroupResponse>,
}

impl GroupListResponse {
    #[must_use]
    pub const fn new(groups: Vec<GroupResponse>) -> Self {
        Self { groups }
    }

    #[must_use]
    pub fn groups(&self) -> &[GroupResponse] {
        &self.groups
    }
}

/// The §14.2 tag-assignment input binding one managed endpoint to one tag
/// name.
///
/// The server parses and validates `tag_name` against the domain `TagName`
/// rules and rejects unknown endpoints with 404. Assignment is an idempotent
/// create-or-keep operation, so re-assigning the same name to the same
/// endpoint succeeds and returns the existing binding (§9.3 `tags`).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssignTagRequest {
    endpoint_id: Uuid,
    tag_name: String,
}

impl AssignTagRequest {
    #[must_use]
    pub const fn new(endpoint_id: Uuid, tag_name: String) -> Self {
        Self {
            endpoint_id,
            tag_name,
        }
    }

    #[must_use]
    pub const fn endpoint_id(&self) -> Uuid {
        self.endpoint_id
    }

    #[must_use]
    pub fn tag_name(&self) -> &str {
        &self.tag_name
    }
}

/// One §9.3 tag binding projected for the §14.2 tag filter.
///
/// A tag binds exactly one tag name to one managed endpoint. The tag model
/// carries no timestamp (the binding is immutable once assigned, tag.rs), so
/// the wire shape stays `{tag_id, endpoint_id, name}`. `tag_id` names the
/// tag-name row: the same tag name on different endpoints shares the name
/// row while keeping independent bindings.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TagResponse {
    tag_id: Uuid,
    endpoint_id: Uuid,
    name: String,
}

impl TagResponse {
    #[must_use]
    pub const fn new(tag_id: Uuid, endpoint_id: Uuid, name: String) -> Self {
        Self {
            tag_id,
            endpoint_id,
            name,
        }
    }

    #[must_use]
    pub const fn tag_id(&self) -> Uuid {
        self.tag_id
    }

    #[must_use]
    pub const fn endpoint_id(&self) -> Uuid {
        self.endpoint_id
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// Stable envelope for every tag across all managed endpoints (§14.2).
///
/// The console builds the tag filter from this complete union and resolves
/// each tag back to its bound endpoint through `endpoint_id`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TagListResponse {
    tags: Vec<TagResponse>,
}

impl TagListResponse {
    #[must_use]
    pub const fn new(tags: Vec<TagResponse>) -> Self {
        Self { tags }
    }

    #[must_use]
    pub fn tags(&self) -> &[TagResponse] {
        &self.tags
    }
}

/// The §16.1 role of one principal, as spoken on the wire.
///
/// The codes are the stable persistence contract (`role_assignments.role`
/// CHECK constraint), so the wire form and the domain vocabulary never
/// drift.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RoleResponse {
    Administrator,
    Operator,
    Viewer,
}

/// The §16.1 enabled/disabled state of one principal, as spoken on the wire.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalStateResponse {
    Enabled,
    Disabled,
}

/// A credential-presenting sign-in attempt (§16.2).
///
/// The password never leaves the `SecretString` wrapper on its way to the
/// verification boundary; serialization is required by the WASM client,
/// while `Debug` remains permanently redacted. The optional TOTP code is
/// presented when the principal's active authenticator requires the second
/// factor.
pub struct LoginRequest {
    username: String,
    password: SecretString,
    totp_code: Option<String>,
}

impl LoginRequest {
    #[must_use]
    pub fn new(username: String, password: SecretString, totp_code: Option<String>) -> Self {
        Self {
            username,
            password,
            totp_code,
        }
    }

    #[must_use]
    pub fn username(&self) -> &str {
        &self.username
    }

    #[must_use]
    pub fn password(&self) -> &SecretString {
        &self.password
    }

    #[must_use]
    pub fn totp_code(&self) -> Option<&str> {
        self.totp_code.as_deref()
    }
}

impl Serialize for LoginRequest {
    fn serialize<SerializerType>(
        &self,
        serializer: SerializerType,
    ) -> Result<SerializerType::Ok, SerializerType::Error>
    where
        SerializerType: Serializer,
    {
        #[derive(Serialize)]
        struct WireLoginRequest<'a> {
            username: &'a str,
            password: &'a str,
            totp_code: Option<&'a str>,
        }

        WireLoginRequest {
            username: &self.username,
            password: self.password.expose_secret(),
            totp_code: self.totp_code.as_deref(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for LoginRequest {
    fn deserialize<DeserializerType>(
        deserializer: DeserializerType,
    ) -> Result<Self, DeserializerType::Error>
    where
        DeserializerType: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireLoginRequest {
            username: String,
            password: String,
            totp_code: Option<String>,
        }

        let wire = WireLoginRequest::deserialize(deserializer)?;
        Ok(Self::new(
            wire.username,
            wire.password.into(),
            wire.totp_code,
        ))
    }
}

impl fmt::Debug for LoginRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LoginRequest")
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .field("totp_code", &"[REDACTED]")
            .finish()
    }
}

/// The CSRF token of a fresh session (§16.2 "CSRF 防护").
///
/// The session cookie is set by the response itself; the body carries only
/// the CSRF token the client must present with every mutating request. The
/// token is a single-use-per-session secret, so the body never contains the
/// session token itself.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LoginResponse {
    csrf_token: String,
}

impl LoginResponse {
    #[must_use]
    pub const fn new(csrf_token: String) -> Self {
        Self { csrf_token }
    }

    #[must_use]
    pub fn csrf_token(&self) -> &str {
        &self.csrf_token
    }
}

/// The explicit sign-out of the presenting session (§16.2).
///
/// The empty body keeps the wire contract strict: unknown fields are
/// refused, so a client cannot smuggle state into the request.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LogoutRequest {}

/// The first-startup claim of the product (§16.2 "首次启动生成一次性
/// Bootstrap Code").
///
/// The claim binds the one-time code, sets the initial password of the
/// built-in administrator, and — when the optional TOTP pair is present —
/// enrolls and activates a TOTP authenticator: `totp_secret` is the base32
/// secret of the operator's authenticator app and `totp_code` proves
/// possession of it. The two fields stand or fall together; a claim with
/// exactly one of them is rejected at the boundary. Serialization is
/// required by the WASM client, while `Debug` remains permanently redacted.
pub struct BootstrapCompleteRequest {
    code: String,
    password: SecretString,
    totp_secret: Option<String>,
    totp_code: Option<String>,
}

impl BootstrapCompleteRequest {
    #[must_use]
    pub fn new(
        code: String,
        password: SecretString,
        totp_secret: Option<String>,
        totp_code: Option<String>,
    ) -> Self {
        Self {
            code,
            password,
            totp_secret,
            totp_code,
        }
    }

    #[must_use]
    pub fn code(&self) -> &str {
        &self.code
    }

    #[must_use]
    pub fn password(&self) -> &SecretString {
        &self.password
    }

    #[must_use]
    pub fn totp_secret(&self) -> Option<&str> {
        self.totp_secret.as_deref()
    }

    #[must_use]
    pub fn totp_code(&self) -> Option<&str> {
        self.totp_code.as_deref()
    }

    /// Reports whether the optional TOTP pair is complete.
    ///
    /// The two fields stand or fall together: a claim with exactly one of
    /// them cannot be a coherent enrollment.
    #[must_use]
    pub fn has_complete_totp_pair(&self) -> bool {
        self.totp_secret.is_some() == self.totp_code.is_some()
    }
}

impl Serialize for BootstrapCompleteRequest {
    fn serialize<SerializerType>(
        &self,
        serializer: SerializerType,
    ) -> Result<SerializerType::Ok, SerializerType::Error>
    where
        SerializerType: Serializer,
    {
        #[derive(Serialize)]
        struct WireBootstrapCompleteRequest<'a> {
            code: &'a str,
            password: &'a str,
            totp_secret: Option<&'a str>,
            totp_code: Option<&'a str>,
        }

        WireBootstrapCompleteRequest {
            code: &self.code,
            password: self.password.expose_secret(),
            totp_secret: self.totp_secret.as_deref(),
            totp_code: self.totp_code.as_deref(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for BootstrapCompleteRequest {
    fn deserialize<DeserializerType>(
        deserializer: DeserializerType,
    ) -> Result<Self, DeserializerType::Error>
    where
        DeserializerType: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireBootstrapCompleteRequest {
            code: String,
            password: String,
            totp_secret: Option<String>,
            totp_code: Option<String>,
        }

        let wire = WireBootstrapCompleteRequest::deserialize(deserializer)?;
        Ok(Self::new(
            wire.code,
            wire.password.into(),
            wire.totp_secret,
            wire.totp_code,
        ))
    }
}

impl fmt::Debug for BootstrapCompleteRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BootstrapCompleteRequest")
            .field("code", &"[REDACTED]")
            .field("password", &"[REDACTED]")
            .field("totp_secret", &"[REDACTED]")
            .field("totp_code", &"[REDACTED]")
            .finish()
    }
}

/// The session and CSRF tokens of a completed bootstrap claim.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapCompleteResponse {
    csrf_token: String,
}

impl BootstrapCompleteResponse {
    #[must_use]
    pub const fn new(csrf_token: String) -> Self {
        Self { csrf_token }
    }

    #[must_use]
    pub fn csrf_token(&self) -> &str {
        &self.csrf_token
    }
}

/// A signed-in principal changing their own password (§16.2).
///
/// The current password authenticates the request; the new password is
/// hashed for storage as given — the product enforces no password-strength
/// policy. Both values are `SecretString`-wrapped, serialized only for the
/// WASM client, and never echoed by any response.
pub struct SetPasswordRequest {
    current_password: SecretString,
    new_password: SecretString,
}

impl SetPasswordRequest {
    #[must_use]
    pub fn new(current_password: SecretString, new_password: SecretString) -> Self {
        Self {
            current_password,
            new_password,
        }
    }

    #[must_use]
    pub fn current_password(&self) -> &SecretString {
        &self.current_password
    }

    #[must_use]
    pub fn new_password(&self) -> &SecretString {
        &self.new_password
    }
}

impl Serialize for SetPasswordRequest {
    fn serialize<SerializerType>(
        &self,
        serializer: SerializerType,
    ) -> Result<SerializerType::Ok, SerializerType::Error>
    where
        SerializerType: Serializer,
    {
        #[derive(Serialize)]
        struct WireSetPasswordRequest<'a> {
            current_password: &'a str,
            new_password: &'a str,
        }

        WireSetPasswordRequest {
            current_password: self.current_password.expose_secret(),
            new_password: self.new_password.expose_secret(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SetPasswordRequest {
    fn deserialize<DeserializerType>(
        deserializer: DeserializerType,
    ) -> Result<Self, DeserializerType::Error>
    where
        DeserializerType: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireSetPasswordRequest {
            current_password: String,
            new_password: String,
        }

        let wire = WireSetPasswordRequest::deserialize(deserializer)?;
        Ok(Self::new(
            wire.current_password.into(),
            wire.new_password.into(),
        ))
    }
}

impl fmt::Debug for SetPasswordRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SetPasswordRequest")
            .field("current_password", &"[REDACTED]")
            .field("new_password", &"[REDACTED]")
            .finish()
    }
}

/// The identity summary of one authenticated principal.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PrincipalSummaryResponse {
    id: String,
    name: String,
    state: PrincipalStateResponse,
    role: Option<RoleResponse>,
}

impl PrincipalSummaryResponse {
    #[must_use]
    pub fn new(
        id: String,
        name: String,
        state: PrincipalStateResponse,
        role: Option<RoleResponse>,
    ) -> Self {
        Self {
            id,
            name,
            state,
            role,
        }
    }

    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub const fn state(&self) -> PrincipalStateResponse {
        self.state
    }

    #[must_use]
    pub const fn role(&self) -> Option<RoleResponse> {
        self.role
    }
}

/// The session state of the requesting client (§16.2).
///
/// The console decides its first screen from this response: an
/// authenticated caller receives their principal summary, an
/// unauthenticated one receives whether the first-startup bootstrap claim
/// is still pending.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MeResponse {
    authenticated: bool,
    bootstrap_pending: bool,
    principal: Option<PrincipalSummaryResponse>,
}

impl MeResponse {
    #[must_use]
    pub const fn new(
        authenticated: bool,
        bootstrap_pending: bool,
        principal: Option<PrincipalSummaryResponse>,
    ) -> Self {
        Self {
            authenticated,
            bootstrap_pending,
            principal,
        }
    }

    #[must_use]
    pub const fn authenticated(&self) -> bool {
        self.authenticated
    }

    #[must_use]
    pub const fn bootstrap_pending(&self) -> bool {
        self.bootstrap_pending
    }

    #[must_use]
    pub fn principal(&self) -> Option<&PrincipalSummaryResponse> {
        self.principal.as_ref()
    }
}

/// One session row of the §16.2 session administration view.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionSummaryResponse {
    session_id: String,
    principal_id: String,
    principal_name: String,
    created_at: OffsetDateTime,
    last_used_at: OffsetDateTime,
    expires_at: OffsetDateTime,
    revoked_at: Option<OffsetDateTime>,
    current: bool,
}

impl SessionSummaryResponse {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub const fn new(
        session_id: String,
        principal_id: String,
        principal_name: String,
        created_at: OffsetDateTime,
        last_used_at: OffsetDateTime,
        expires_at: OffsetDateTime,
        revoked_at: Option<OffsetDateTime>,
        current: bool,
    ) -> Self {
        Self {
            session_id,
            principal_id,
            principal_name,
            created_at,
            last_used_at,
            expires_at,
            revoked_at,
            current,
        }
    }

    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    #[must_use]
    pub fn principal_id(&self) -> &str {
        &self.principal_id
    }

    #[must_use]
    pub fn principal_name(&self) -> &str {
        &self.principal_name
    }

    #[must_use]
    pub const fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    #[must_use]
    pub const fn last_used_at(&self) -> OffsetDateTime {
        self.last_used_at
    }

    #[must_use]
    pub const fn expires_at(&self) -> OffsetDateTime {
        self.expires_at
    }

    #[must_use]
    pub const fn revoked_at(&self) -> Option<OffsetDateTime> {
        self.revoked_at
    }

    #[must_use]
    pub const fn is_current(&self) -> bool {
        self.current
    }
}

/// The complete session administration listing (§16.2).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionAdminResponse {
    sessions: Vec<SessionSummaryResponse>,
}

impl SessionAdminResponse {
    #[must_use]
    pub const fn new(sessions: Vec<SessionSummaryResponse>) -> Self {
        Self { sessions }
    }

    #[must_use]
    pub fn sessions(&self) -> &[SessionSummaryResponse] {
        &self.sessions
    }
}

/// Revokes one presented session by its stable identity (§16.2).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeSessionRequest {
    session_id: Uuid,
}

impl RevokeSessionRequest {
    #[must_use]
    pub const fn new(session_id: Uuid) -> Self {
        Self { session_id }
    }

    #[must_use]
    pub const fn session_id(&self) -> Uuid {
        self.session_id
    }
}

/// One principal row of the §16.1 user administration view.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UserSummaryResponse {
    id: String,
    name: String,
    state: PrincipalStateResponse,
    role: Option<RoleResponse>,
    created_at: OffsetDateTime,
}

impl UserSummaryResponse {
    #[must_use]
    pub fn new(
        id: String,
        name: String,
        state: PrincipalStateResponse,
        role: Option<RoleResponse>,
        created_at: OffsetDateTime,
    ) -> Self {
        Self {
            id,
            name,
            state,
            role,
            created_at,
        }
    }

    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub const fn state(&self) -> PrincipalStateResponse {
        self.state
    }

    #[must_use]
    pub const fn role(&self) -> Option<RoleResponse> {
        self.role
    }

    #[must_use]
    pub const fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }
}

/// The complete user administration listing (§16.1).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UserAdminResponse {
    users: Vec<UserSummaryResponse>,
}

impl UserAdminResponse {
    #[must_use]
    pub const fn new(users: Vec<UserSummaryResponse>) -> Self {
        Self { users }
    }

    #[must_use]
    pub fn users(&self) -> &[UserSummaryResponse] {
        &self.users
    }
}

/// Creates one product user principal with its §16.1 role.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateUserRequest {
    name: String,
    role: RoleResponse,
}

impl CreateUserRequest {
    #[must_use]
    pub fn new(name: String, role: RoleResponse) -> Self {
        Self { name, role }
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub const fn role(&self) -> RoleResponse {
        self.role
    }
}

/// Transitions one principal's §16.1 enabled/disabled state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SetPrincipalStateRequest {
    state: PrincipalStateResponse,
}

impl SetPrincipalStateRequest {
    #[must_use]
    pub const fn new(state: PrincipalStateResponse) -> Self {
        Self { state }
    }

    #[must_use]
    pub const fn state(&self) -> PrincipalStateResponse {
        self.state
    }
}

/// Reassigns one principal's §16.1 role.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssignRoleRequest {
    role: RoleResponse,
}

impl AssignRoleRequest {
    #[must_use]
    pub const fn new(role: RoleResponse) -> Self {
        Self { role }
    }

    #[must_use]
    pub const fn role(&self) -> RoleResponse {
        self.role
    }
}

/// The lifecycle phase of one site-to-center binding (design D2, D6).
///
/// The wire values are the domain's stable snake-case codes; the raw binding
/// code itself never travels on this wire — it is shown to the operator
/// exactly once at registration ([`CenterBindingRegisterResponse`]) and only
/// the state (and timestamps) are exposed afterwards.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CenterBindingStateResponse {
    /// The site registered and a one-time binding code is outstanding.
    Pending,
    /// The site presented the code and the center recorded the binding.
    Bound,
    /// The binding was revoked; the site must re-register to bind again.
    Revoked,
}

/// One registered site in the center's §15.5 site view.
///
/// The view projects the registered instance, its binding phase, its online
/// presence (one live §15.1 connection), the projected endpoint count, and
/// the newest reported refresh generation as the last-refresh watermark.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CenterSiteResponse {
    site_id: Uuid,
    display_name: String,
    binding: Option<CenterBindingStateResponse>,
    online: bool,
    endpoint_count: u64,
    #[serde(with = "time::serde::rfc3339::option")]
    last_refresh_at: Option<OffsetDateTime>,
}

impl CenterSiteResponse {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub const fn new(
        site_id: Uuid,
        display_name: String,
        binding: Option<CenterBindingStateResponse>,
        online: bool,
        endpoint_count: u64,
        last_refresh_at: Option<OffsetDateTime>,
    ) -> Self {
        Self {
            site_id,
            display_name,
            binding,
            online,
            endpoint_count,
            last_refresh_at,
        }
    }

    #[must_use]
    pub const fn site_id(&self) -> Uuid {
        self.site_id
    }

    #[must_use]
    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    #[must_use]
    pub const fn binding(&self) -> Option<CenterBindingStateResponse> {
        self.binding
    }

    #[must_use]
    pub const fn online(&self) -> bool {
        self.online
    }

    #[must_use]
    pub const fn endpoint_count(&self) -> u64 {
        self.endpoint_count
    }

    #[must_use]
    pub const fn last_refresh_at(&self) -> Option<OffsetDateTime> {
        self.last_refresh_at
    }
}

/// The center's §15.5 site list.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CenterSitesResponse {
    sites: Vec<CenterSiteResponse>,
}

impl CenterSitesResponse {
    #[must_use]
    pub const fn new(sites: Vec<CenterSiteResponse>) -> Self {
        Self { sites }
    }

    #[must_use]
    pub fn sites(&self) -> &[CenterSiteResponse] {
        &self.sites
    }
}

/// One site-to-center binding record as the center exposes it.
///
/// The one-time code is deliberately absent: it is shown exactly once, in the
/// registration acknowledgement ([`CenterBindingRegisterResponse`]), and
/// never again — not even its hash, which stays a persistence-internal fact.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CenterBindingResponse {
    binding_id: Uuid,
    site_id: Uuid,
    state: CenterBindingStateResponse,
    center_url: String,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    expires_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    bound_at: Option<OffsetDateTime>,
}

impl CenterBindingResponse {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub const fn new(
        binding_id: Uuid,
        site_id: Uuid,
        state: CenterBindingStateResponse,
        center_url: String,
        created_at: OffsetDateTime,
        expires_at: Option<OffsetDateTime>,
        bound_at: Option<OffsetDateTime>,
    ) -> Self {
        Self {
            binding_id,
            site_id,
            state,
            center_url,
            created_at,
            expires_at,
            bound_at,
        }
    }

    #[must_use]
    pub const fn binding_id(&self) -> Uuid {
        self.binding_id
    }

    #[must_use]
    pub const fn site_id(&self) -> Uuid {
        self.site_id
    }

    #[must_use]
    pub const fn state(&self) -> CenterBindingStateResponse {
        self.state
    }

    #[must_use]
    pub fn center_url(&self) -> &str {
        &self.center_url
    }

    #[must_use]
    pub const fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    #[must_use]
    pub const fn expires_at(&self) -> Option<OffsetDateTime> {
        self.expires_at
    }

    #[must_use]
    pub const fn bound_at(&self) -> Option<OffsetDateTime> {
        self.bound_at
    }
}

/// Validated-by-the-server input for registering one site (design D2): the
/// display name the center shows and the URL the site must connect to.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CenterBindingRegisterRequest {
    display_name: String,
    center_url: String,
}

impl CenterBindingRegisterRequest {
    #[must_use]
    pub const fn new(display_name: String, center_url: String) -> Self {
        Self {
            display_name,
            center_url,
        }
    }

    #[must_use]
    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    #[must_use]
    pub fn center_url(&self) -> &str {
        &self.center_url
    }
}

/// The one-time acknowledgement of a site registration (design D2).
///
/// The raw binding code travels exactly once, here: the operator hands it to
/// the site, and no later response ever repeats it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CenterBindingRegisterResponse {
    site_id: Uuid,
    binding_id: Uuid,
    code: String,
    #[serde(with = "time::serde::rfc3339")]
    expires_at: OffsetDateTime,
}

impl CenterBindingRegisterResponse {
    #[must_use]
    pub const fn new(
        site_id: Uuid,
        binding_id: Uuid,
        code: String,
        expires_at: OffsetDateTime,
    ) -> Self {
        Self {
            site_id,
            binding_id,
            code,
            expires_at,
        }
    }

    #[must_use]
    pub const fn site_id(&self) -> Uuid {
        self.site_id
    }

    #[must_use]
    pub const fn binding_id(&self) -> Uuid {
        self.binding_id
    }

    /// The one-time binding code; never repeated by any later response.
    #[must_use]
    pub fn code(&self) -> &str {
        &self.code
    }

    /// When the outstanding code stops being usable (D2 TTL).
    #[must_use]
    pub const fn expires_at(&self) -> OffsetDateTime {
        self.expires_at
    }
}

/// Input for revoking the active binding of one site (design D2).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CenterBindingRevokeRequest {
    site_id: Uuid,
}

impl CenterBindingRevokeRequest {
    #[must_use]
    pub const fn new(site_id: Uuid) -> Self {
        Self { site_id }
    }

    #[must_use]
    pub const fn site_id(&self) -> Uuid {
        self.site_id
    }
}

/// One projected remote endpoint of the center's §15.5 endpoint view.
///
/// The view aggregates the site-reported summary: the endpoint identity and
/// display name, its active address, the trust decision, the refresh
/// generation watermark, and the health cut — never credentials, sessions,
/// or certificate material (§15.5).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CenterEndpointViewResponse {
    site_id: Option<Uuid>,
    endpoint_id: Uuid,
    display_name: String,
    address: String,
    health: String,
    refresh_generation: u64,
}

impl CenterEndpointViewResponse {
    #[must_use]
    pub const fn new(
        site_id: Option<Uuid>,
        endpoint_id: Uuid,
        display_name: String,
        address: String,
        health: String,
        refresh_generation: u64,
    ) -> Self {
        Self {
            site_id,
            endpoint_id,
            display_name,
            address,
            health,
            refresh_generation,
        }
    }

    #[must_use]
    pub const fn site_id(&self) -> Option<Uuid> {
        self.site_id
    }

    #[must_use]
    pub const fn endpoint_id(&self) -> Uuid {
        self.endpoint_id
    }

    #[must_use]
    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    #[must_use]
    pub fn address(&self) -> &str {
        &self.address
    }

    #[must_use]
    pub fn health(&self) -> &str {
        &self.health
    }

    #[must_use]
    pub const fn refresh_generation(&self) -> u64 {
        self.refresh_generation
    }
}

/// The center's §15.5 aggregated endpoint view.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CenterEndpointViewListResponse {
    endpoints: Vec<CenterEndpointViewResponse>,
}

impl CenterEndpointViewListResponse {
    #[must_use]
    pub const fn new(endpoints: Vec<CenterEndpointViewResponse>) -> Self {
        Self { endpoints }
    }

    #[must_use]
    pub fn endpoints(&self) -> &[CenterEndpointViewResponse] {
        &self.endpoints
    }
}

/// One center-dispatched operation in the center's tracking view (§15.6).
///
/// The offer facts the operation record does not persist — the target, the
/// actor context, and the offer expiry — come from the durable §15.6 offer
/// envelope, so they are `None` for an operation whose offer is not on
/// record. The wire carries the typed command, never a URL, method, headers,
/// or body.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CenterOperationResponse {
    operation_id: Uuid,
    site_id: Option<Uuid>,
    endpoint_id: Uuid,
    command: RedfishCommand,
    #[serde(default)]
    target: Option<String>,
    state: OperationStateResponse,
    #[serde(default)]
    actor: Option<String>,
    #[serde(with = "time::serde::rfc3339::option")]
    ttl_expires_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
}

impl CenterOperationResponse {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub const fn new(
        operation_id: Uuid,
        site_id: Option<Uuid>,
        endpoint_id: Uuid,
        command: RedfishCommand,
        target: Option<String>,
        state: OperationStateResponse,
        actor: Option<String>,
        ttl_expires_at: Option<OffsetDateTime>,
        created_at: OffsetDateTime,
    ) -> Self {
        Self {
            operation_id,
            site_id,
            endpoint_id,
            command,
            target,
            state,
            actor,
            ttl_expires_at,
            created_at,
        }
    }

    #[must_use]
    pub const fn operation_id(&self) -> Uuid {
        self.operation_id
    }

    #[must_use]
    pub const fn site_id(&self) -> Option<Uuid> {
        self.site_id
    }

    #[must_use]
    pub const fn endpoint_id(&self) -> Uuid {
        self.endpoint_id
    }

    #[must_use]
    pub fn command(&self) -> &RedfishCommand {
        &self.command
    }

    /// The §15.6 target of the offer, when the offer is on record.
    #[must_use]
    pub fn target(&self) -> Option<&str> {
        self.target.as_deref()
    }

    #[must_use]
    pub const fn state(&self) -> OperationStateResponse {
        self.state
    }

    /// The actor context of the offer, when the offer is on record.
    #[must_use]
    pub fn actor(&self) -> Option<&str> {
        self.actor.as_deref()
    }

    /// When the outstanding offer stops being actionable (§15.6).
    #[must_use]
    pub const fn ttl_expires_at(&self) -> Option<OffsetDateTime> {
        self.ttl_expires_at
    }

    #[must_use]
    pub const fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }
}

/// The center's §15.6 operation tracking view.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CenterOperationListResponse {
    operations: Vec<CenterOperationResponse>,
}

impl CenterOperationListResponse {
    #[must_use]
    pub const fn new(operations: Vec<CenterOperationResponse>) -> Self {
        Self { operations }
    }

    #[must_use]
    pub fn operations(&self) -> &[CenterOperationResponse] {
        &self.operations
    }
}

/// The §15.6 center operation submission: the typed command, the target, and
/// the site it is addressed to — and nothing else.
///
/// The wire shape is the §15.6 red line: no URL, no HTTP method, no headers,
/// no JSON body, no script. The center never executes operations; the site
/// re-checks its endpoint, capability, credential, and target state and only
/// an explicit `Accepted` transfers execution responsibility.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CenterOperationSubmitRequest {
    site_id: Uuid,
    endpoint_id: Uuid,
    target: String,
    command: RedfishCommand,
}

impl CenterOperationSubmitRequest {
    #[must_use]
    pub const fn new(
        site_id: Uuid,
        endpoint_id: Uuid,
        target: String,
        command: RedfishCommand,
    ) -> Self {
        Self {
            site_id,
            endpoint_id,
            target,
            command,
        }
    }

    #[must_use]
    pub const fn site_id(&self) -> Uuid {
        self.site_id
    }

    #[must_use]
    pub const fn endpoint_id(&self) -> Uuid {
        self.endpoint_id
    }

    /// The Redfish target of the operation.
    #[must_use]
    pub fn target(&self) -> &str {
        &self.target
    }

    /// The typed write command of the operation (§7.5).
    #[must_use]
    pub const fn command(&self) -> &RedfishCommand {
        &self.command
    }
}

/// The acknowledgement of one dispatched center operation (§15.6): the
/// stable operation id and the moment the offer stops being actionable.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CenterOperationSubmitResponse {
    operation_id: Uuid,
    #[serde(with = "time::serde::rfc3339")]
    ttl_expires_at: OffsetDateTime,
}

impl CenterOperationSubmitResponse {
    #[must_use]
    pub const fn new(operation_id: Uuid, ttl_expires_at: OffsetDateTime) -> Self {
        Self {
            operation_id,
            ttl_expires_at,
        }
    }

    #[must_use]
    pub const fn operation_id(&self) -> Uuid {
        self.operation_id
    }

    #[must_use]
    pub const fn ttl_expires_at(&self) -> OffsetDateTime {
        self.ttl_expires_at
    }
}

#[cfg(test)]
mod tests {
    use std::{error::Error, num::NonZeroU64};

    use rutilus_domain::{ResetType, SecureBootCommand, SystemCommand};
    use serde_json::json;
    use time::format_description::well_known::Rfc3339;
    use uuid::uuid;

    use super::*;

    #[test]
    fn trust_challenge_contract_is_credential_free_and_strict() -> Result<(), Box<dyn Error>> {
        let observed_at = OffsetDateTime::parse("2026-08-05T10:11:12Z", &Rfc3339)?;
        let request = BeginEndpointTrustRequest::new("https://bmc.example.test/".to_owned());
        let challenge = EndpointTrustChallengeResponse::new(
            "https://bmc.example.test/".to_owned(),
            "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"
                .to_owned(),
            observed_at,
            EndpointTrustChallengeStateResponse::ExplicitPinRequired,
        );
        let request_json = serde_json::to_value(&request)?;
        let challenge_json = serde_json::to_value(&challenge)?;

        assert_eq!(request.address(), "https://bmc.example.test/");
        assert_eq!(
            request_json,
            json!({ "address": "https://bmc.example.test/" })
        );
        assert_eq!(
            challenge_json,
            json!({
                "address": "https://bmc.example.test/",
                "fingerprint_sha256": "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99",
                "observed_at": "2026-08-05T10:11:12Z",
                "state": "explicit_pin_required"
            })
        );
        assert_eq!(
            serde_json::from_value::<EndpointTrustChallengeResponse>(challenge_json)?,
            challenge
        );
        assert!(
            serde_json::from_value::<BeginEndpointTrustRequest>(json!({
                "address": "https://bmc.example.test/",
                "username": "must-not-exist-at-this-stage"
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<EndpointTrustChallengeResponse>(json!({
                "address": "https://bmc.example.test/",
                "fingerprint_sha256": "AA",
                "observed_at": "2026-08-05T10:11:12Z",
                "state": "automatically_accepted"
            }))
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn enrollment_contract_requires_an_explicit_trust_policy() -> Result<(), Box<dyn Error>> {
        let credential_id = uuid!("01989abc-def0-7abc-8def-0123456789ce");
        let pinned = EndpointTrustExpectationRequest::pinned_certificate(
            "11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00"
                .to_owned(),
        );
        let request = EnrollEndpointRequest::new(
            "Rack A BMC".to_owned(),
            "https://bmc.example.test/".to_owned(),
            pinned,
            credential_id,
        );
        let encoded = serde_json::to_value(&request)?;

        assert_eq!(request.display_name(), "Rack A BMC");
        assert_eq!(request.address(), "https://bmc.example.test/");
        assert_eq!(request.credential_id(), credential_id);
        assert_eq!(
            request.trust().fingerprint_sha256(),
            Some(
                "11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00"
            )
        );
        assert_eq!(
            encoded,
            json!({
                "display_name": "Rack A BMC",
                "address": "https://bmc.example.test/",
                "trust": {
                    "mode": "pinned_certificate",
                    "fingerprint_sha256": "11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00"
                },
                "credential_id": credential_id
            })
        );
        assert_eq!(
            serde_json::from_value::<EnrollEndpointRequest>(encoded)?,
            request
        );
        assert_eq!(
            serde_json::to_value(EndpointTrustExpectationRequest::system_ca())?,
            json!({ "mode": "system_ca" })
        );
        assert!(
            serde_json::from_value::<EnrollEndpointRequest>(json!({
                "display_name": "Rack A BMC",
                "address": "https://bmc.example.test/",
                "trust": { "mode": "pinned_certificate" },
                "credential_id": credential_id
            }))
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn credential_contract_redacts_requests_and_returns_only_metadata() -> Result<(), Box<dyn Error>>
    {
        let created_at = OffsetDateTime::parse("2026-08-05T10:12:13Z", &Rfc3339)?;
        let credential_id = uuid!("01989abc-def0-7abc-8def-0123456789cf");
        let request = CreateCredentialRequest::new(
            "Rack administrators".to_owned(),
            "administrator".to_owned(),
            "never render this secret".to_owned().into(),
        );
        let encoded_request = serde_json::to_value(&request)?;
        let rendered = format!("{request:?}");
        let response = CredentialInventoryResponse::new(vec![CredentialSummaryResponse::new(
            credential_id,
            "Rack administrators".to_owned(),
            "administrator".to_owned(),
            created_at,
            created_at,
        )]);
        let encoded_response = serde_json::to_string(&response)?;

        assert_eq!(request.name(), "Rack administrators");
        assert_eq!(request.username(), "administrator");
        assert_eq!(
            encoded_request,
            json!({
                "name": "Rack administrators",
                "username": "administrator",
                "password": "never render this secret"
            })
        );
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains("never render this secret"));
        assert!(!encoded_response.contains("password"));
        assert!(!encoded_response.contains("secret"));
        assert_eq!(
            response
                .credentials()
                .first()
                .ok_or("credential metadata must exist")?
                .credential_id(),
            credential_id
        );
        assert!(
            serde_json::from_value::<CreateCredentialRequest>(json!({
                "name": "Rack administrators",
                "username": "administrator",
                "password": "secret",
                "remember": true
            }))
            .is_err()
        );
        let (name, username, password) = request.into_parts();
        assert_eq!(name, "Rack administrators");
        assert_eq!(username, "administrator");
        assert_eq!(password.expose_secret(), "never render this secret");

        let enrollment = EndpointEnrollmentResponse::new(
            uuid!("01989abc-def0-7abc-8def-0123456789d4"),
            NonZeroU64::new(1).ok_or("test Generation must be non-zero")?,
            CoreResourceCountsResponse::new(1, 1, 1),
        );
        assert_eq!(
            serde_json::to_value(enrollment)?,
            json!({
                "endpoint_id": "01989abc-def0-7abc-8def-0123456789d4",
                "initial_generation": 1,
                "resource_counts": { "systems": 1, "chassis": 1, "managers": 1 }
            })
        );
        Ok(())
    }

    #[test]
    fn health_contract_has_one_stable_wire_state() -> Result<(), Box<dyn Error>> {
        let response = HealthResponse::healthy();
        let encoded = serde_json::to_value(response)?;
        let decoded: HealthResponse = serde_json::from_value(encoded.clone())?;

        assert_eq!(response.status(), HealthStatus::Ok);
        assert_eq!(encoded, json!({ "status": "ok" }));
        assert_eq!(decoded, response);
        assert!(serde_json::from_value::<HealthResponse>(json!({ "status": "unknown" })).is_err());
        assert!(
            serde_json::from_value::<HealthResponse>(json!({ "status": "ok", "detail": null }))
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn about_contract_round_trips_without_dynamic_fields() -> Result<(), Box<dyn Error>> {
        let response = AboutResponse::new(
            "rutilus".to_owned(),
            "0.1.0-test".to_owned(),
            "0.13.0-test".to_owned(),
        );
        let encoded = serde_json::to_value(&response)?;
        let decoded: AboutResponse = serde_json::from_value(encoded.clone())?;

        assert_eq!(response.product(), "rutilus");
        assert_eq!(response.product_version(), "0.1.0-test");
        assert_eq!(response.nv_redfish_baseline(), "0.13.0-test");
        assert_eq!(
            encoded,
            json!({
                "product": "rutilus",
                "product_version": "0.1.0-test",
                "nv_redfish_baseline": "0.13.0-test"
            })
        );
        assert_eq!(decoded, response);
        assert!(
            serde_json::from_value::<AboutResponse>(json!({
                "product": "rutilus",
                "product_version": "0.1.0-test",
                "nv_redfish_baseline": "0.13.0-test",
                "unexpected": true
            }))
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn endpoint_inventory_contract_preserves_complete_snapshot_state() -> Result<(), Box<dyn Error>>
    {
        let created_at = OffsetDateTime::parse("2026-08-05T09:10:11Z", &Rfc3339)?;
        let refreshed_at = OffsetDateTime::parse("2026-08-05T09:12:13Z", &Rfc3339)?;
        let identity = EndpointIdentityResponse::new(
            uuid!("01989abc-def0-7abc-8def-0123456789ab"),
            "Rack A BMC".to_owned(),
            "https://192.0.2.10".to_owned(),
            TlsTrustModeResponse::PinnedCertificate,
            created_at,
            refreshed_at,
        );
        let counts = CoreResourceCountsResponse::new(2, 2, 2);
        let response = EndpointInventoryResponse::new(vec![EndpointSummaryResponse::new(
            identity,
            EndpointSnapshotSummaryResponse::current(
                NonZeroU64::new(4).ok_or("test generation must be non-zero")?,
                refreshed_at,
                counts,
            ),
        )]);
        let encoded = serde_json::to_value(&response)?;
        let decoded: EndpointInventoryResponse = serde_json::from_value(encoded.clone())?;

        assert_eq!(decoded, response);
        let endpoint = &decoded.endpoints()[0];
        assert_eq!(endpoint.identity().display_name(), "Rack A BMC");
        assert_eq!(endpoint.identity().address(), "https://192.0.2.10");
        assert_eq!(
            endpoint.identity().tls_trust_mode(),
            TlsTrustModeResponse::PinnedCertificate
        );
        assert_eq!(
            endpoint.identity().endpoint_id(),
            uuid!("01989abc-def0-7abc-8def-0123456789ab")
        );
        assert_eq!(endpoint.identity().created_at(), created_at);
        assert_eq!(endpoint.identity().updated_at(), refreshed_at);
        assert_eq!(
            endpoint.snapshot(),
            EndpointSnapshotSummaryResponse::Current {
                generation: NonZeroU64::new(4).ok_or("test generation must be non-zero")?,
                last_successful_refresh_at: refreshed_at,
                resource_counts: counts,
            }
        );
        assert_eq!(
            encoded,
            json!({
                "endpoints": [{
                    "identity": {
                        "endpoint_id": "01989abc-def0-7abc-8def-0123456789ab",
                        "display_name": "Rack A BMC",
                        "address": "https://192.0.2.10",
                        "tls_trust_mode": "pinned_certificate",
                        "created_at": "2026-08-05T09:10:11Z",
                        "updated_at": "2026-08-05T09:12:13Z"
                    },
                    "snapshot": {
                        "state": "current",
                        "details": {
                            "generation": 4,
                            "last_successful_refresh_at": "2026-08-05T09:12:13Z",
                            "resource_counts": {
                                "systems": 2,
                                "chassis": 2,
                                "managers": 2
                            }
                        }
                    }
                }]
            })
        );
        Ok(())
    }

    #[test]
    fn endpoint_inventory_contract_rejects_ambiguous_or_extended_states() {
        assert!(
            serde_json::from_value::<EndpointInventoryResponse>(json!({
                "endpoints": [{
                    "identity": {
                        "endpoint_id": "01989abc-def0-7abc-8def-0123456789ab",
                        "display_name": "Rack A BMC",
                        "address": "https://192.0.2.10",
                        "tls_trust_mode": "system_ca",
                        "created_at": "2026-08-05T09:10:11Z",
                        "updated_at": "2026-08-05T09:12:13Z"
                    },
                    "snapshot": {
                        "state": "awaiting_first_refresh",
                        "generation": 1
                    }
                }]
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<EndpointInventoryResponse>(json!({
                "endpoints": [{
                    "identity": {
                        "endpoint_id": "not-a-uuid",
                        "display_name": "Rack A BMC",
                        "address": "https://192.0.2.10",
                        "tls_trust_mode": "automatic",
                        "created_at": "not-a-time",
                        "updated_at": "2026-08-05T09:12:13Z"
                    },
                    "snapshot": { "state": "awaiting_first_refresh" }
                }],
                "next_page": null
            }))
            .is_err()
        );
    }

    #[test]
    fn current_snapshot_contract_requires_nonzero_known_details() {
        let zero_generation = json!({
            "state": "current",
            "details": {
                "generation": 0,
                "last_successful_refresh_at": "2026-08-05T09:12:13Z",
                "resource_counts": { "systems": 1, "chassis": 1, "managers": 1 }
            }
        });
        let extended_details = json!({
            "state": "current",
            "details": {
                "generation": 1,
                "last_successful_refresh_at": "2026-08-05T09:12:13Z",
                "resource_counts": {
                    "systems": 1,
                    "chassis": 1,
                    "managers": 1,
                    "unknown": 1
                }
            }
        });

        assert!(
            serde_json::from_value::<EndpointSnapshotSummaryResponse>(zero_generation).is_err()
        );
        assert!(
            serde_json::from_value::<EndpointSnapshotSummaryResponse>(extended_details).is_err()
        );
    }

    #[test]
    fn resource_diagnostics_contract_preserves_the_typed_payload_verbatim()
    -> Result<(), Box<dyn Error>> {
        let response = ResourceDiagnosticsResponse::new(
            uuid!("01989abc-def0-7abc-8def-0123456789ab"),
            "/redfish/v1/Systems/1".to_owned(),
            Some("#ComputerSystem.v1_20_0.ComputerSystem".to_owned()),
            Some("W/\"system-1\"".to_owned()),
            "systems".to_owned(),
            NonZeroU64::new(7).ok_or("test generation must be non-zero")?,
            json!({
                "Id": "1",
                "Name": "System One",
                "Oem": { "Vendor": { "OemFlag": true } }
            }),
        );
        let encoded = serde_json::to_value(&response)?;
        let decoded: ResourceDiagnosticsResponse = serde_json::from_value(encoded.clone())?;

        assert_eq!(decoded, response);
        assert_eq!(
            decoded.endpoint_id(),
            uuid!("01989abc-def0-7abc-8def-0123456789ab")
        );
        assert_eq!(decoded.odata_uri(), "/redfish/v1/Systems/1");
        assert_eq!(
            decoded.odata_type(),
            Some("#ComputerSystem.v1_20_0.ComputerSystem")
        );
        assert_eq!(decoded.etag(), Some("W/\"system-1\""));
        assert_eq!(decoded.feature(), "systems");
        assert_eq!(
            decoded.generation(),
            NonZeroU64::new(7).ok_or("test generation must be non-zero")?
        );
        assert_eq!(
            decoded.typed_payload(),
            &json!({ "Id": "1", "Name": "System One", "Oem": { "Vendor": { "OemFlag": true } } })
        );
        assert_eq!(
            encoded,
            json!({
                "endpoint_id": "01989abc-def0-7abc-8def-0123456789ab",
                "odata_uri": "/redfish/v1/Systems/1",
                "odata_type": "#ComputerSystem.v1_20_0.ComputerSystem",
                "etag": "W/\"system-1\"",
                "feature": "systems",
                "generation": 7,
                "typed_payload": {
                    "Id": "1",
                    "Name": "System One",
                    "Oem": { "Vendor": { "OemFlag": true } }
                }
            })
        );
        assert!(
            serde_json::from_value::<ResourceDiagnosticsResponse>(json!({
                "endpoint_id": "01989abc-def0-7abc-8def-0123456789ab",
                "odata_uri": "/redfish/v1/Systems/1",
                "odata_type": "#ComputerSystem.v1_20_0.ComputerSystem",
                "etag": "W/\"system-1\"",
                "feature": "systems",
                "generation": 7,
                "typed_payload": { "Id": "1" },
                "extended_info": []
            }))
            .is_err(),
            "unknown diagnostics fields must be rejected"
        );
        assert!(
            serde_json::from_value::<ResourceDiagnosticsResponse>(json!({
                "endpoint_id": "01989abc-def0-7abc-8def-0123456789ab",
                "odata_uri": "/redfish/v1/Systems/1",
                "feature": "systems",
                "generation": 0,
                "typed_payload": { "Id": "1" }
            }))
            .is_err(),
            "a zero generation must be rejected like every other refresh snapshot"
        );
        Ok(())
    }

    #[test]
    fn core_resource_contract_preserves_typed_fields_and_source() -> Result<(), Box<dyn Error>> {
        let observed_at = OffsetDateTime::parse("2026-08-05T09:12:13Z", &Rfc3339)?;
        let response = system_resource_response(observed_at)?;
        let encoded = serde_json::to_value(&response)?;
        let decoded: EndpointResourceInventoryResponse = serde_json::from_value(encoded.clone())?;

        assert_eq!(decoded, response);
        assert_eq!(decoded.endpoint().display_name(), "Rack A BMC");
        let EndpointResourceSnapshotResponse::Current { resources, .. } = decoded.snapshot() else {
            return Err("expected a current resource Generation".into());
        };
        let resource = resources.first().ok_or("resource must exist")?;
        assert_eq!(resource.source().odata_id(), "/redfish/v1/Systems/1");
        assert_eq!(
            resource.source().odata_type(),
            Some("#ComputerSystem.v1_20_0.ComputerSystem")
        );
        assert_eq!(resource.source().etag(), Some("W/\"system-1\""));
        assert_eq!(
            resource.source().resource_id(),
            uuid!("01989abc-def0-7abc-8def-0123456789cd")
        );
        assert_eq!(resource.common().id(), "1");
        assert_eq!(resource.common().name(), "System One");
        assert_eq!(
            resource.common().description(),
            Some("Primary compute system")
        );
        assert!(matches!(
            resource.resource(),
            CoreResourceDetailsResponse::System {
                status: Some(status),
                ..
            } if status.state() == Some("Enabled")
                && status.health() == Some("OK")
                && status.health_rollup() == Some("Warning")
        ));
        assert_eq!(encoded, expected_system_resource_json());
        Ok(())
    }

    fn system_resource_response(
        observed_at: OffsetDateTime,
    ) -> Result<EndpointResourceInventoryResponse, &'static str> {
        let endpoint = EndpointIdentityResponse::new(
            uuid!("01989abc-def0-7abc-8def-0123456789ab"),
            "Rack A BMC".to_owned(),
            "https://192.0.2.10/".to_owned(),
            TlsTrustModeResponse::SystemCa,
            observed_at,
            observed_at,
        );
        let status = ResourceStatusResponse::new(
            Some("Enabled".to_owned()),
            Some("OK".to_owned()),
            Some("Warning".to_owned()),
        );
        let resource = CoreResourceResponse::new(
            CoreResourceSourceResponse::new(
                uuid!("01989abc-def0-7abc-8def-0123456789cd"),
                "/redfish/v1/Systems/1".to_owned(),
                Some("#ComputerSystem.v1_20_0.ComputerSystem".to_owned()),
                Some("W/\"system-1\"".to_owned()),
            ),
            CoreResourceCommonResponse::new(
                "1".to_owned(),
                "System One".to_owned(),
                Some("Primary compute system".to_owned()),
            ),
            CoreResourceDetailsResponse::System {
                system_type: Some("Physical".to_owned()),
                manufacturer: Some("Vendor A".to_owned()),
                model: Some("Model S".to_owned()),
                part_number: Some("SYS-PART-1".to_owned()),
                serial_number: Some("SYS-1".to_owned()),
                sku: Some("SYS-SKU-1".to_owned()),
                host_name: Some("compute-1".to_owned()),
                bios_version: Some("2.3.4".to_owned()),
                power_state: Some("On".to_owned()),
                status: Some(status),
            },
        );
        Ok(EndpointResourceInventoryResponse::new(
            endpoint,
            EndpointResourceSnapshotResponse::current(
                NonZeroU64::new(7).ok_or("test Generation must be non-zero")?,
                observed_at,
                vec![resource],
            ),
        ))
    }

    fn expected_system_resource_json() -> serde_json::Value {
        json!({
            "endpoint": {
                "endpoint_id": "01989abc-def0-7abc-8def-0123456789ab",
                "display_name": "Rack A BMC",
                "address": "https://192.0.2.10/",
                "tls_trust_mode": "system_ca",
                "created_at": "2026-08-05T09:12:13Z",
                "updated_at": "2026-08-05T09:12:13Z"
            },
            "snapshot": {
                "state": "current",
                "details": {
                    "generation": 7,
                    "observed_at": "2026-08-05T09:12:13Z",
                    "resources": [{
                        "source": {
                            "resource_id": "01989abc-def0-7abc-8def-0123456789cd",
                            "odata_id": "/redfish/v1/Systems/1",
                            "odata_type": "#ComputerSystem.v1_20_0.ComputerSystem",
                            "etag": "W/\"system-1\""
                        },
                        "common": {
                            "id": "1",
                            "name": "System One",
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
                    }]
                }
            }
        })
    }

    #[test]
    fn core_resource_contract_carries_processor_wire_values() -> Result<(), Box<dyn Error>> {
        let processor = processor_resource();

        assert_eq!(
            serde_json::to_value(&processor)?,
            json!({
                "source": {
                    "resource_id": "01989abc-def0-7abc-8def-0123456789ce",
                    "odata_id": "/redfish/v1/Systems/1/Processors/CPU1",
                    "odata_type": "#Processor.v1_15_0.Processor",
                    "etag": "W/\"cpu-1\""
                },
                "common": {
                    "id": "CPU1",
                    "name": "Processor One",
                    "description": "Primary compute processor"
                },
                "resource": {
                    "resource_type": "processor",
                    "details": {
                        "processor_type": "CPU",
                        "socket": "LGA4189",
                        "manufacturer": "Vendor A",
                        "model": "EPYC Model X",
                        "total_cores": 64,
                        "status": {
                            "state": "Enabled",
                            "health": "OK",
                            "health_rollup": "OK"
                        }
                    }
                }
            })
        );
        assert_eq!(
            serde_json::from_value::<CoreResourceResponse>(serde_json::to_value(&processor)?)?,
            processor
        );
        assert!(
            serde_json::from_value::<CoreResourceDetailsResponse>(json!({
                "resource_type": "processor",
                "details": {
                    "processor_type": null,
                    "socket": null,
                    "manufacturer": null,
                    "model": null,
                    "total_cores": null,
                    "status": null,
                    "arbitrary": true
                }
            }))
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn core_resource_contract_carries_memory_wire_values() -> Result<(), Box<dyn Error>> {
        let memory = memory_resource();

        assert_eq!(
            serde_json::to_value(&memory)?,
            json!({
                "source": {
                    "resource_id": "01989abc-def0-7abc-8def-0123456789cf",
                    "odata_id": "/redfish/v1/Systems/1/Memory/DIMM1",
                    "odata_type": "#Memory.v1_15_0.Memory",
                    "etag": null
                },
                "common": {
                    "id": "DIMM1",
                    "name": "Memory Module One",
                    "description": null
                },
                "resource": {
                    "resource_type": "memory",
                    "details": {
                        "memory_device_type": "DDR4",
                        "capacity_mib": 32768,
                        "manufacturer": "Vendor B",
                        "model": "MEM-32G",
                        "status": null
                    }
                }
            })
        );
        assert_eq!(
            serde_json::from_value::<CoreResourceResponse>(serde_json::to_value(&memory)?)?,
            memory
        );
        assert!(
            serde_json::from_value::<CoreResourceDetailsResponse>(json!({
                "resource_type": "memory",
                "details": {
                    "memory_device_type": null,
                    "capacity_mib": null,
                    "manufacturer": null,
                    "model": null,
                    "status": null,
                    "arbitrary": true
                }
            }))
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn core_resource_contract_carries_oem_dell_wire_values() -> Result<(), Box<dyn Error>> {
        let oem_dell = oem_dell_resource();

        assert_eq!(
            serde_json::to_value(&oem_dell)?,
            json!({
                "source": {
                    "resource_id": "01989abc-def0-7abc-8def-0123456789b1",
                    "odata_id": "/redfish/v1/Managers/1/Oem/Dell/DellAttributes/1",
                    "odata_type": "#DellAttributes.v1_0_0.DellAttributes",
                    "etag": "W/\"dell-attributes-1\""
                },
                "common": {
                    "id": "1",
                    "name": "Dell Attributes",
                    "description": "Dell iDRAC attributes"
                },
                "resource": {
                    "resource_type": "oem_dell",
                    "details": {
                        "server_model": "PowerEdge R750",
                        "server_service_tag": "ABC1234",
                        "server_generation": "16G",
                        "server_bmc_mac_address": "14:18:77:aa:bb:cc",
                        "server_name": "rack-1-server-2"
                    }
                }
            })
        );
        assert_eq!(
            serde_json::from_value::<CoreResourceResponse>(serde_json::to_value(&oem_dell)?)?,
            oem_dell
        );
        assert!(
            serde_json::from_value::<CoreResourceDetailsResponse>(json!({
                "resource_type": "oem_dell",
                "details": {
                    "server_model": null,
                    "server_service_tag": null,
                    "server_generation": null,
                    "server_bmc_mac_address": null,
                    "server_name": null,
                    "arbitrary": true
                }
            }))
            .is_err()
        );
        Ok(())
    }

    fn oem_dell_resource() -> CoreResourceResponse {
        CoreResourceResponse::new(
            CoreResourceSourceResponse::new(
                uuid!("01989abc-def0-7abc-8def-0123456789b1"),
                "/redfish/v1/Managers/1/Oem/Dell/DellAttributes/1".to_owned(),
                Some("#DellAttributes.v1_0_0.DellAttributes".to_owned()),
                Some("W/\"dell-attributes-1\"".to_owned()),
            ),
            CoreResourceCommonResponse::new(
                "1".to_owned(),
                "Dell Attributes".to_owned(),
                Some("Dell iDRAC attributes".to_owned()),
            ),
            CoreResourceDetailsResponse::OemDell {
                server_model: Some("PowerEdge R750".to_owned()),
                server_service_tag: Some("ABC1234".to_owned()),
                server_generation: Some("16G".to_owned()),
                server_bmc_mac_address: Some("14:18:77:aa:bb:cc".to_owned()),
                server_name: Some("rack-1-server-2".to_owned()),
            },
        )
    }

    #[test]
    fn core_resource_contract_carries_oem_smc_wire_values() -> Result<(), Box<dyn Error>> {
        let sys_lockdown = oem_smc_sys_lockdown_resource();
        let kcs_interface = oem_smc_kcs_interface_resource();

        assert_eq!(
            serde_json::to_value(&sys_lockdown)?,
            json!({
                "source": {
                    "resource_id": "01989abc-def0-7abc-8def-0123456789b2",
                    "odata_id": "/redfish/v1/Managers/1/SysLockdown",
                    "odata_type": "#SysLockdown.v1_0_0.SysLockdown",
                    "etag": "W/\"sys-lockdown-1\""
                },
                "common": {
                    "id": "SysLockdown",
                    "name": "SysLockdown",
                    "description": null
                },
                "resource": {
                    "resource_type": "oem_smc_sys_lockdown",
                    "details": {
                        "sys_lockdown_enabled": true
                    }
                }
            })
        );
        assert_eq!(
            serde_json::from_value::<CoreResourceResponse>(serde_json::to_value(&sys_lockdown)?)?,
            sys_lockdown
        );
        assert_eq!(
            serde_json::to_value(&kcs_interface)?,
            json!({
                "source": {
                    "resource_id": "01989abc-def0-7abc-8def-0123456789b3",
                    "odata_id": "/redfish/v1/Managers/1/KCSInterface",
                    "odata_type": "#KCSInterface.v1_0_0.KCSInterface",
                    "etag": "W/\"kcs-interface-1\""
                },
                "common": {
                    "id": "KCSInterface",
                    "name": "KCSInterface",
                    "description": null
                },
                "resource": {
                    "resource_type": "oem_smc_kcs_interface",
                    "details": {
                        "privilege": "Administrator"
                    }
                }
            })
        );
        assert_eq!(
            serde_json::from_value::<CoreResourceResponse>(serde_json::to_value(&kcs_interface)?)?,
            kcs_interface
        );
        assert!(
            serde_json::from_value::<CoreResourceDetailsResponse>(json!({
                "resource_type": "oem_smc_sys_lockdown",
                "details": {
                    "sys_lockdown_enabled": false,
                    "arbitrary": true
                }
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<CoreResourceDetailsResponse>(json!({
                "resource_type": "oem_smc_kcs_interface",
                "details": {
                    "privilege": "User",
                    "arbitrary": true
                }
            }))
            .is_err()
        );
        Ok(())
    }

    fn oem_smc_sys_lockdown_resource() -> CoreResourceResponse {
        CoreResourceResponse::new(
            CoreResourceSourceResponse::new(
                uuid!("01989abc-def0-7abc-8def-0123456789b2"),
                "/redfish/v1/Managers/1/SysLockdown".to_owned(),
                Some("#SysLockdown.v1_0_0.SysLockdown".to_owned()),
                Some("W/\"sys-lockdown-1\"".to_owned()),
            ),
            CoreResourceCommonResponse::new(
                "SysLockdown".to_owned(),
                "SysLockdown".to_owned(),
                None,
            ),
            CoreResourceDetailsResponse::OemSmcSysLockdown {
                sys_lockdown_enabled: Some(true),
            },
        )
    }

    fn oem_smc_kcs_interface_resource() -> CoreResourceResponse {
        CoreResourceResponse::new(
            CoreResourceSourceResponse::new(
                uuid!("01989abc-def0-7abc-8def-0123456789b3"),
                "/redfish/v1/Managers/1/KCSInterface".to_owned(),
                Some("#KCSInterface.v1_0_0.KCSInterface".to_owned()),
                Some("W/\"kcs-interface-1\"".to_owned()),
            ),
            CoreResourceCommonResponse::new(
                "KCSInterface".to_owned(),
                "KCSInterface".to_owned(),
                None,
            ),
            CoreResourceDetailsResponse::OemSmcKcsInterface {
                privilege: Some("Administrator".to_owned()),
            },
        )
    }

    #[test]
    fn core_resource_contract_carries_oem_lenovo_wire_values() -> Result<(), Box<dyn Error>> {
        let security_service = oem_lenovo_security_service_resource();

        // The wire carries the vendor's `FWRollback` enum spelling verbatim
        // per §12.3 (the `Configurator` nesting of the compiled schema
        // collapses onto the wrapper's flattened accessor).
        assert_eq!(
            serde_json::to_value(&security_service)?,
            json!({
                "source": {
                    "resource_id": "01989abc-def0-7abc-8def-0123456789b8",
                    "odata_id": "/redfish/v1/Managers/1/Oem/Lenovo/SecurityService",
                    "odata_type": "#LenovoSecurityService.v1_0_0.LenovoSecurityService",
                    "etag": "W/\"lenovo-security-1\""
                },
                "common": {
                    "id": "SecurityService",
                    "name": "Lenovo Security Service",
                    "description": "Lenovo security service"
                },
                "resource": {
                    "resource_type": "oem_lenovo_security_service",
                    "details": {
                        "fw_rollback": "Enabled"
                    }
                }
            })
        );
        assert_eq!(
            serde_json::from_value::<CoreResourceResponse>(serde_json::to_value(
                &security_service
            )?)?,
            security_service
        );
        // The strict field contract refuses a foreign key, so the wire shape
        // cannot drift from the typed surface.
        assert!(
            serde_json::from_value::<CoreResourceDetailsResponse>(json!({
                "resource_type": "oem_lenovo_security_service",
                "details": {
                    "fw_rollback": "Disabled",
                    "arbitrary": true
                }
            }))
            .is_err()
        );
        Ok(())
    }

    fn oem_lenovo_security_service_resource() -> CoreResourceResponse {
        CoreResourceResponse::new(
            CoreResourceSourceResponse::new(
                uuid!("01989abc-def0-7abc-8def-0123456789b8"),
                "/redfish/v1/Managers/1/Oem/Lenovo/SecurityService".to_owned(),
                Some("#LenovoSecurityService.v1_0_0.LenovoSecurityService".to_owned()),
                Some("W/\"lenovo-security-1\"".to_owned()),
            ),
            CoreResourceCommonResponse::new(
                "SecurityService".to_owned(),
                "Lenovo Security Service".to_owned(),
                Some("Lenovo security service".to_owned()),
            ),
            CoreResourceDetailsResponse::OemLenovoSecurityService {
                fw_rollback: Some("Enabled".to_owned()),
            },
        )
    }

    // The four NVIDIA chain documents are asserted in one test so the wire
    // shapes stay one contract; the four golden assertions exceed the
    // pedantic line budget, so the lint is scoped here exactly like the
    // other OEM contract tests.
    #[allow(clippy::too_many_lines)]
    #[test]
    fn core_resource_contract_carries_oem_nvidia_wire_values() -> Result<(), Box<dyn Error>> {
        let chain_root = oem_nvidia_system_config_profile_resource();
        let status = oem_nvidia_system_config_profile_status_resource();
        let profile = oem_nvidia_system_profile_resource();
        let profile_file = oem_nvidia_system_profile_file_resource();

        // The chain root carries the `Truststore` link-presence metadata;
        // the certificate payloads behind the links stay out.
        assert_eq!(
            serde_json::to_value(&chain_root)?,
            json!({
                "source": {
                    "resource_id": "01989abc-def0-7abc-8def-0123456789b4",
                    "odata_id": "/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile",
                    "odata_type": "#NvidiaSystemConfigProfile.NvidiaSystemConfigProfile",
                    "etag": "W/\"nvidia-scp-1\""
                },
                "common": {
                    "id": "SystemConfigProfile",
                    "name": "NVIDIA System Config Profile",
                    "description": "Profile service"
                },
                "resource": {
                    "resource_type": "oem_nvidia_system_config_profile",
                    "details": {
                        "truststore": {
                            "nvidia_certificates": true,
                            "oem_certificates": false
                        }
                    }
                }
            })
        );
        assert_eq!(
            serde_json::from_value::<CoreResourceResponse>(serde_json::to_value(&chain_root)?)?,
            chain_root
        );
        // The status singleton carries the compiled status fields.
        assert_eq!(
            serde_json::to_value(&status)?,
            json!({
                "source": {
                    "resource_id": "01989abc-def0-7abc-8def-0123456789b5",
                    "odata_id": "/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile/Status",
                    "odata_type": "#NvidiaSystemConfigProfileStatus.NvidiaSystemConfigProfileStatus",
                    "etag": "W/\"nvidia-scp-status-1\""
                },
                "common": {
                    "id": "Status",
                    "name": "System Config Profile Status",
                    "description": "Profile service status"
                },
                "resource": {
                    "resource_type": "oem_nvidia_system_config_profile_status",
                    "details": {
                        "pending_list_activation": "profile-1",
                        "active_profile_index": 1,
                        "bmc_profile_version": 2,
                        "factory_reset_status": "Idle",
                        "default_profile_index": 1
                    }
                }
            })
        );
        assert_eq!(
            serde_json::from_value::<CoreResourceResponse>(serde_json::to_value(&status)?)?,
            status
        );
        // A profile member carries the compiled metadata fields.
        assert_eq!(
            serde_json::to_value(&profile)?,
            json!({
                "source": {
                    "resource_id": "01989abc-def0-7abc-8def-0123456789b6",
                    "odata_id": "/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile/Profiles/1",
                    "odata_type": "#NvidiaSystemProfile.NvidiaSystemProfile",
                    "etag": "W/\"nvidia-profile-1\""
                },
                "common": {
                    "id": "1",
                    "name": "Default Profile",
                    "description": "Factory default profile"
                },
                "resource": {
                    "resource_type": "oem_nvidia_system_profile",
                    "details": {
                        "default": true,
                        "owner": "Nvidia",
                        "uuid": "11111111-2222-3333-4444-555555555555",
                        "version": 1,
                        "profile_name": "default-profile"
                    }
                }
            })
        );
        assert_eq!(
            serde_json::from_value::<CoreResourceResponse>(serde_json::to_value(&profile)?)?,
            profile
        );
        // The profile file carries the metadata and the base64 content
        // verbatim.
        assert_eq!(
            serde_json::to_value(&profile_file)?,
            json!({
                "source": {
                    "resource_id": "01989abc-def0-7abc-8def-0123456789b7",
                    "odata_id": "/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile/Profiles/1/ProfileFile",
                    "odata_type": "#NvidiaSystemProfileFile.NvidiaSystemProfileFile",
                    "etag": "W/\"nvidia-profile-file-1\""
                },
                "common": {
                    "id": "ProfileFile",
                    "name": "Profile File",
                    "description": "Signed profile file"
                },
                "resource": {
                    "resource_type": "oem_nvidia_system_profile_file",
                    "details": {
                        "metadata_activate": true,
                        "metadata_delete": false,
                        "metadata_origin_profile_uuid": "11111111-2222-3333-4444-555555555555",
                        "metadata_more_profiles": false,
                        "metadata_project_name": "BlueField",
                        "metadata_uuid": "11111111-2222-3333-4444-555555555555",
                        "profile": "eyJwcm9maWxlIjogInRlc3QifQ=="
                    }
                }
            })
        );
        assert_eq!(
            serde_json::from_value::<CoreResourceResponse>(serde_json::to_value(&profile_file)?)?,
            profile_file
        );
        // An unknown key is refused under every NVIDIA variant, keeping the
        // strict `deny_unknown_fields` contract.
        for (resource_type, details) in [
            (
                "oem_nvidia_system_config_profile",
                json!({"truststore": {"nvidia_certificates": true}, "arbitrary": true}),
            ),
            (
                "oem_nvidia_system_config_profile_status",
                json!({"active_profile_index": 1, "arbitrary": true}),
            ),
            (
                "oem_nvidia_system_profile",
                json!({"profile_name": "x", "arbitrary": true}),
            ),
            (
                "oem_nvidia_system_profile_file",
                json!({"profile": "x", "arbitrary": true}),
            ),
        ] {
            assert!(
                serde_json::from_value::<CoreResourceDetailsResponse>(json!({
                    "resource_type": resource_type,
                    "details": details
                }))
                .is_err(),
                "{resource_type} must refuse unknown detail fields"
            );
        }
        Ok(())
    }

    fn oem_nvidia_system_config_profile_resource() -> CoreResourceResponse {
        CoreResourceResponse::new(
            CoreResourceSourceResponse::new(
                uuid!("01989abc-def0-7abc-8def-0123456789b4"),
                "/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile".to_owned(),
                Some("#NvidiaSystemConfigProfile.NvidiaSystemConfigProfile".to_owned()),
                Some("W/\"nvidia-scp-1\"".to_owned()),
            ),
            CoreResourceCommonResponse::new(
                "SystemConfigProfile".to_owned(),
                "NVIDIA System Config Profile".to_owned(),
                Some("Profile service".to_owned()),
            ),
            CoreResourceDetailsResponse::OemNvidiaSystemConfigProfile {
                truststore: Some(OemNvidiaSystemConfigProfileTruststoreResponse::new(
                    Some(true),
                    Some(false),
                )),
            },
        )
    }

    fn oem_nvidia_system_config_profile_status_resource() -> CoreResourceResponse {
        CoreResourceResponse::new(
            CoreResourceSourceResponse::new(
                uuid!("01989abc-def0-7abc-8def-0123456789b5"),
                "/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile/Status".to_owned(),
                Some("#NvidiaSystemConfigProfileStatus.NvidiaSystemConfigProfileStatus".to_owned()),
                Some("W/\"nvidia-scp-status-1\"".to_owned()),
            ),
            CoreResourceCommonResponse::new(
                "Status".to_owned(),
                "System Config Profile Status".to_owned(),
                Some("Profile service status".to_owned()),
            ),
            CoreResourceDetailsResponse::OemNvidiaSystemConfigProfileStatus {
                pending_list_activation: Some("profile-1".to_owned()),
                active_profile_index: Some(1),
                bmc_profile_version: Some(2),
                factory_reset_status: Some("Idle".to_owned()),
                default_profile_index: Some(1),
            },
        )
    }

    fn oem_nvidia_system_profile_resource() -> CoreResourceResponse {
        CoreResourceResponse::new(
            CoreResourceSourceResponse::new(
                uuid!("01989abc-def0-7abc-8def-0123456789b6"),
                "/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile/Profiles/1".to_owned(),
                Some("#NvidiaSystemProfile.NvidiaSystemProfile".to_owned()),
                Some("W/\"nvidia-profile-1\"".to_owned()),
            ),
            CoreResourceCommonResponse::new(
                "1".to_owned(),
                "Default Profile".to_owned(),
                Some("Factory default profile".to_owned()),
            ),
            CoreResourceDetailsResponse::OemNvidiaSystemProfile {
                default: Some(true),
                owner: Some("Nvidia".to_owned()),
                uuid: Some("11111111-2222-3333-4444-555555555555".to_owned()),
                version: Some(1),
                profile_name: Some("default-profile".to_owned()),
            },
        )
    }

    fn oem_nvidia_system_profile_file_resource() -> CoreResourceResponse {
        CoreResourceResponse::new(
            CoreResourceSourceResponse::new(
                uuid!("01989abc-def0-7abc-8def-0123456789b7"),
                "/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile/Profiles/1/ProfileFile"
                    .to_owned(),
                Some("#NvidiaSystemProfileFile.NvidiaSystemProfileFile".to_owned()),
                Some("W/\"nvidia-profile-file-1\"".to_owned()),
            ),
            CoreResourceCommonResponse::new(
                "ProfileFile".to_owned(),
                "Profile File".to_owned(),
                Some("Signed profile file".to_owned()),
            ),
            CoreResourceDetailsResponse::OemNvidiaSystemProfileFile {
                metadata_activate: Some(true),
                metadata_delete: Some(false),
                metadata_origin_profile_uuid: Some(
                    "11111111-2222-3333-4444-555555555555".to_owned(),
                ),
                metadata_more_profiles: Some(false),
                metadata_project_name: Some("BlueField".to_owned()),
                metadata_uuid: Some("11111111-2222-3333-4444-555555555555".to_owned()),
                profile: Some("eyJwcm9maWxlIjogInRlc3QifQ==".to_owned()),
            },
        )
    }

    // The nine power-family wire contracts are asserted in one test so the
    // golden JSON and the strict-field contract stay one surface; the nine
    // document projections exceed the pedantic line budget, so the lint is
    // scoped here exactly like the system-config-profile contract test.
    // The `psc_state` / `psu_state` bindings are two letters apart, so the
    // pedantic similar-names lint is scoped off like the line budget.
    #[allow(clippy::too_many_lines, clippy::similar_names)]
    #[test]
    fn core_resource_contract_carries_oem_nvidia_power_wire_values() -> Result<(), Box<dyn Error>> {
        let compliance = oem_nvidia_power_compliance_resource();
        let domain = oem_nvidia_power_domain_resource();
        let policy = oem_nvidia_power_policy_resource();
        let group = oem_nvidia_managed_entity_group_resource();
        let state_group = oem_nvidia_power_state_group_resource();
        let psc_state = oem_nvidia_psc_state_resource();
        let psu_state = oem_nvidia_psu_state_resource();
        let redundancy = oem_nvidia_psu_redundancy_resource();
        let entity = oem_nvidia_managed_entity_resource();

        // The chain root carries the compiled `ManagerType` enumeration
        // spelling verbatim.
        assert_eq!(
            serde_json::to_value(&compliance)?,
            json!({
                "source": {
                    "resource_id": "01989abc-def0-7abc-8def-0123456789c0",
                    "odata_id": "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance",
                    "odata_type": "#NvidiaPowerComplianceManager.v1_0_0.NvidiaPowerComplianceManager",
                    "etag": "W/\"nvidia-pc-1\""
                },
                "common": {
                    "id": "PowerCompliance",
                    "name": "NVIDIA Power Compliance",
                    "description": "Power compliance manager"
                },
                "resource": {
                    "resource_type": "oem_nvidia_power_compliance",
                    "details": {
                        "manager_type": "PowerManager"
                    }
                }
            })
        );
        assert_eq!(
            serde_json::from_value::<CoreResourceResponse>(serde_json::to_value(&compliance)?)?,
            compliance
        );
        // A power domain member carries the compiled scalar fields.
        assert_eq!(
            serde_json::to_value(&domain)?,
            json!({
                "source": {
                    "resource_id": "01989abc-def0-7abc-8def-0123456789c1",
                    "odata_id": "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PowerDomains/1",
                    "odata_type": "#NvidiaPowerDomain.v1_0_0.NvidiaPowerDomain",
                    "etag": "W/\"nvidia-domain-1\""
                },
                "common": {
                    "id": "1",
                    "name": "Power Domain One",
                    "description": "Power comparison domain"
                },
                "resource": {
                    "resource_type": "oem_nvidia_power_domain",
                    "details": {
                        "value": 800,
                        "type": "Above",
                        "unit": "Watts",
                        "sensor_reading_type": "Power",
                        "sensor_impl": "PhysicalSensor"
                    }
                }
            })
        );
        assert_eq!(
            serde_json::from_value::<CoreResourceResponse>(serde_json::to_value(&domain)?)?,
            domain
        );
        // A power policy carries the compiled scalar fields (the enum
        // spellings verbatim).
        assert_eq!(
            serde_json::to_value(&policy)?,
            json!({
                "source": {
                    "resource_id": "01989abc-def0-7abc-8def-0123456789c2",
                    "odata_id": "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/ACLossPolicy",
                    "odata_type": "#NvidiaPowerPolicy.v1_0_0.NvidiaPowerPolicy",
                    "etag": "W/\"nvidia-acloss-1\""
                },
                "common": {
                    "id": "ACLossPolicy",
                    "name": "AC Loss Policy",
                    "description": "AC loss power policy"
                },
                "resource": {
                    "resource_type": "oem_nvidia_power_policy",
                    "details": {
                        "auto_deassert_power_brake": true,
                        "min": 200,
                        "max": 600,
                        "type": "Inclusive",
                        "unit": "Watts",
                        "policy_actions": "AssertPowerBrake"
                    }
                }
            })
        );
        assert_eq!(
            serde_json::from_value::<CoreResourceResponse>(serde_json::to_value(&policy)?)?,
            policy
        );
        // A managed entity group member carries the compiled id text.
        assert_eq!(
            serde_json::to_value(&group)?,
            json!({
                "source": {
                    "resource_id": "01989abc-def0-7abc-8def-0123456789c3",
                    "odata_id": "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/ManagedEntityGroups/1",
                    "odata_type": "#NvidiaManagedEntityGroup.v1_0_0.NvidiaManagedEntityGroup",
                    "etag": "W/\"nvidia-group-1\""
                },
                "common": {
                    "id": "1",
                    "name": "Managed Entity Group One",
                    "description": "BlueField group"
                },
                "resource": {
                    "resource_type": "oem_nvidia_managed_entity_group",
                    "details": {
                        "current_managed_entity_id": "BF1"
                    }
                }
            })
        );
        assert_eq!(
            serde_json::from_value::<CoreResourceResponse>(serde_json::to_value(&group)?)?,
            group
        );
        // The power state group carries the compiled scalar fields.
        assert_eq!(
            serde_json::to_value(&state_group)?,
            json!({
                "source": {
                    "resource_id": "01989abc-def0-7abc-8def-0123456789c4",
                    "odata_id": "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PowerStateGroup",
                    "odata_type": "#NvidiaPowerStateGroup.v1_0_0.NvidiaPowerStateGroup",
                    "etag": "W/\"nvidia-state-group-1\""
                },
                "common": {
                    "id": "PowerStateGroup",
                    "name": "Power State Group",
                    "description": "Power shelf state"
                },
                "resource": {
                    "resource_type": "oem_nvidia_power_state_group",
                    "details": {
                        "psc_id": "PSC1",
                        "generated_watts": 2400,
                        "number_of_pscs": 1,
                        "number_of_local_psus": 2
                    }
                }
            })
        );
        assert_eq!(
            serde_json::from_value::<CoreResourceResponse>(serde_json::to_value(&state_group)?)?,
            state_group
        );
        // A PSC state member carries the compiled scalar fields.
        assert_eq!(
            serde_json::to_value(&psc_state)?,
            json!({
                "source": {
                    "resource_id": "01989abc-def0-7abc-8def-0123456789c5",
                    "odata_id": "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PowerStateGroup/PowerShelfControllers/1",
                    "odata_type": "#NvidiaPscState.v1_0_0.NvidiaPscState",
                    "etag": "W/\"nvidia-psc-1\""
                },
                "common": {
                    "id": "1",
                    "name": "Power Shelf Controller One",
                    "description": "PSC state"
                },
                "resource": {
                    "resource_type": "oem_nvidia_psc_state",
                    "details": {
                        "psc_id": "PSC1",
                        "num_of_operational_psus": 4,
                        "power_brake_assert": false,
                        "milliseconds_since_last_heartbeat": 12,
                        "status": "Operational"
                    }
                }
            })
        );
        assert_eq!(
            serde_json::from_value::<CoreResourceResponse>(serde_json::to_value(&psc_state)?)?,
            psc_state
        );
        // A PSU state member carries the compiled scalar fields.
        assert_eq!(
            serde_json::to_value(&psu_state)?,
            json!({
                "source": {
                    "resource_id": "01989abc-def0-7abc-8def-0123456789c6",
                    "odata_id": "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PowerStateGroup/PowerSupplies/1",
                    "odata_type": "#NvidiaPsuState.v1_0_0.NvidiaPsuState",
                    "etag": "W/\"nvidia-psu-1\""
                },
                "common": {
                    "id": "1",
                    "name": "Power Supply One",
                    "description": "PSU state"
                },
                "resource": {
                    "resource_type": "oem_nvidia_psu_state",
                    "details": {
                        "psu_id": "PSU1",
                        "presence": true,
                        "input1active": true,
                        "input2active": false
                    }
                }
            })
        );
        assert_eq!(
            serde_json::from_value::<CoreResourceResponse>(serde_json::to_value(&psu_state)?)?,
            psu_state
        );
        // The PSU redundancy singleton carries the compiled scalar fields.
        assert_eq!(
            serde_json::to_value(&redundancy)?,
            json!({
                "source": {
                    "resource_id": "01989abc-def0-7abc-8def-0123456789c7",
                    "odata_id": "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PSURedundancy",
                    "odata_type": "#NvidiaPsuRedundancy.v1_0_0.NvidiaPsuRedundancy",
                    "etag": "W/\"nvidia-redundancy-1\""
                },
                "common": {
                    "id": "PSURedundancy",
                    "name": "PSU Redundancy",
                    "description": "PSU redundancy settings"
                },
                "resource": {
                    "resource_type": "oem_nvidia_psu_redundancy",
                    "details": {
                        "max_num_supported": "4",
                        "min_num_needed": "2",
                        "redundancy_setting": "NPlusOne"
                    }
                }
            })
        );
        assert_eq!(
            serde_json::from_value::<CoreResourceResponse>(serde_json::to_value(&redundancy)?)?,
            redundancy
        );
        // A managed entity member carries the compiled scalar fields.
        assert_eq!(
            serde_json::to_value(&entity)?,
            json!({
                "source": {
                    "resource_id": "01989abc-def0-7abc-8def-0123456789c8",
                    "odata_id": "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/ManagedEntityGroups/1/ManagedEntities/1",
                    "odata_type": "#NvidiaManagedEntity.v1_0_0.NvidiaManagedEntity",
                    "etag": "W/\"nvidia-entity-1\""
                },
                "common": {
                    "id": "1",
                    "name": "Managed Entity One",
                    "description": "BlueField managed entity"
                },
                "resource": {
                    "resource_type": "oem_nvidia_managed_entity",
                    "details": {
                        "transport_protocol": "HTTPS",
                        "ipv4_address": "192.0.2.10",
                        "ipv6_address": "2001:db8::10",
                        "port": 443
                    }
                }
            })
        );
        assert_eq!(
            serde_json::from_value::<CoreResourceResponse>(serde_json::to_value(&entity)?)?,
            entity
        );
        // An unknown key is refused under every power-family variant, keeping
        // the strict `deny_unknown_fields` contract.
        for (resource_type, details) in [
            (
                "oem_nvidia_power_compliance",
                json!({"manager_type": "PowerManager", "arbitrary": true}),
            ),
            (
                "oem_nvidia_power_domain",
                json!({"value": 1, "arbitrary": true}),
            ),
            (
                "oem_nvidia_power_policy",
                json!({"min": 1, "arbitrary": true}),
            ),
            (
                "oem_nvidia_managed_entity_group",
                json!({"current_managed_entity_id": "x", "arbitrary": true}),
            ),
            (
                "oem_nvidia_power_state_group",
                json!({"psc_id": "x", "arbitrary": true}),
            ),
            (
                "oem_nvidia_psc_state",
                json!({"psc_id": "x", "arbitrary": true}),
            ),
            (
                "oem_nvidia_psu_state",
                json!({"psu_id": "x", "arbitrary": true}),
            ),
            (
                "oem_nvidia_psu_redundancy",
                json!({"max_num_supported": "x", "arbitrary": true}),
            ),
            (
                "oem_nvidia_managed_entity",
                json!({"port": 1, "arbitrary": true}),
            ),
        ] {
            assert!(
                serde_json::from_value::<CoreResourceDetailsResponse>(json!({
                    "resource_type": resource_type,
                    "details": details
                }))
                .is_err(),
                "{resource_type} must refuse unknown detail fields"
            );
        }
        Ok(())
    }

    fn oem_nvidia_power_compliance_resource() -> CoreResourceResponse {
        CoreResourceResponse::new(
            CoreResourceSourceResponse::new(
                uuid!("01989abc-def0-7abc-8def-0123456789c0"),
                "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance".to_owned(),
                Some(
                    "#NvidiaPowerComplianceManager.v1_0_0.NvidiaPowerComplianceManager".to_owned(),
                ),
                Some("W/\"nvidia-pc-1\"".to_owned()),
            ),
            CoreResourceCommonResponse::new(
                "PowerCompliance".to_owned(),
                "NVIDIA Power Compliance".to_owned(),
                Some("Power compliance manager".to_owned()),
            ),
            CoreResourceDetailsResponse::OemNvidiaPowerCompliance {
                manager_type: Some("PowerManager".to_owned()),
            },
        )
    }

    fn oem_nvidia_power_domain_resource() -> CoreResourceResponse {
        CoreResourceResponse::new(
            CoreResourceSourceResponse::new(
                uuid!("01989abc-def0-7abc-8def-0123456789c1"),
                "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PowerDomains/1".to_owned(),
                Some("#NvidiaPowerDomain.v1_0_0.NvidiaPowerDomain".to_owned()),
                Some("W/\"nvidia-domain-1\"".to_owned()),
            ),
            CoreResourceCommonResponse::new(
                "1".to_owned(),
                "Power Domain One".to_owned(),
                Some("Power comparison domain".to_owned()),
            ),
            CoreResourceDetailsResponse::OemNvidiaPowerDomain {
                value: Some(800),
                r#type: Some("Above".to_owned()),
                unit: Some("Watts".to_owned()),
                sensor_reading_type: Some("Power".to_owned()),
                sensor_impl: Some("PhysicalSensor".to_owned()),
            },
        )
    }

    fn oem_nvidia_power_policy_resource() -> CoreResourceResponse {
        CoreResourceResponse::new(
            CoreResourceSourceResponse::new(
                uuid!("01989abc-def0-7abc-8def-0123456789c2"),
                "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/ACLossPolicy".to_owned(),
                Some("#NvidiaPowerPolicy.v1_0_0.NvidiaPowerPolicy".to_owned()),
                Some("W/\"nvidia-acloss-1\"".to_owned()),
            ),
            CoreResourceCommonResponse::new(
                "ACLossPolicy".to_owned(),
                "AC Loss Policy".to_owned(),
                Some("AC loss power policy".to_owned()),
            ),
            CoreResourceDetailsResponse::OemNvidiaPowerPolicy {
                auto_deassert_power_brake: Some(true),
                min: Some(200),
                max: Some(600),
                r#type: Some("Inclusive".to_owned()),
                unit: Some("Watts".to_owned()),
                policy_actions: Some("AssertPowerBrake".to_owned()),
            },
        )
    }

    fn oem_nvidia_managed_entity_group_resource() -> CoreResourceResponse {
        CoreResourceResponse::new(
            CoreResourceSourceResponse::new(
                uuid!("01989abc-def0-7abc-8def-0123456789c3"),
                "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/ManagedEntityGroups/1"
                    .to_owned(),
                Some("#NvidiaManagedEntityGroup.v1_0_0.NvidiaManagedEntityGroup".to_owned()),
                Some("W/\"nvidia-group-1\"".to_owned()),
            ),
            CoreResourceCommonResponse::new(
                "1".to_owned(),
                "Managed Entity Group One".to_owned(),
                Some("BlueField group".to_owned()),
            ),
            CoreResourceDetailsResponse::OemNvidiaManagedEntityGroup {
                current_managed_entity_id: Some("BF1".to_owned()),
            },
        )
    }

    fn oem_nvidia_power_state_group_resource() -> CoreResourceResponse {
        CoreResourceResponse::new(
            CoreResourceSourceResponse::new(
                uuid!("01989abc-def0-7abc-8def-0123456789c4"),
                "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PowerStateGroup".to_owned(),
                Some("#NvidiaPowerStateGroup.v1_0_0.NvidiaPowerStateGroup".to_owned()),
                Some("W/\"nvidia-state-group-1\"".to_owned()),
            ),
            CoreResourceCommonResponse::new(
                "PowerStateGroup".to_owned(),
                "Power State Group".to_owned(),
                Some("Power shelf state".to_owned()),
            ),
            CoreResourceDetailsResponse::OemNvidiaPowerStateGroup {
                psc_id: Some("PSC1".to_owned()),
                generated_watts: Some(2400),
                number_of_pscs: Some(1),
                number_of_local_psus: Some(2),
            },
        )
    }

    fn oem_nvidia_psc_state_resource() -> CoreResourceResponse {
        CoreResourceResponse::new(
            CoreResourceSourceResponse::new(
                uuid!("01989abc-def0-7abc-8def-0123456789c5"),
                "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PowerStateGroup/PowerShelfControllers/1"
                    .to_owned(),
                Some("#NvidiaPscState.v1_0_0.NvidiaPscState".to_owned()),
                Some("W/\"nvidia-psc-1\"".to_owned()),
            ),
            CoreResourceCommonResponse::new(
                "1".to_owned(),
                "Power Shelf Controller One".to_owned(),
                Some("PSC state".to_owned()),
            ),
            CoreResourceDetailsResponse::OemNvidiaPscState {
                psc_id: Some("PSC1".to_owned()),
                num_of_operational_psus: Some(4),
                power_brake_assert: Some(false),
                milliseconds_since_last_heartbeat: Some(12),
                status: Some("Operational".to_owned()),
            },
        )
    }

    fn oem_nvidia_psu_state_resource() -> CoreResourceResponse {
        CoreResourceResponse::new(
            CoreResourceSourceResponse::new(
                uuid!("01989abc-def0-7abc-8def-0123456789c6"),
                "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PowerStateGroup/PowerSupplies/1"
                    .to_owned(),
                Some("#NvidiaPsuState.v1_0_0.NvidiaPsuState".to_owned()),
                Some("W/\"nvidia-psu-1\"".to_owned()),
            ),
            CoreResourceCommonResponse::new(
                "1".to_owned(),
                "Power Supply One".to_owned(),
                Some("PSU state".to_owned()),
            ),
            CoreResourceDetailsResponse::OemNvidiaPsuState {
                psu_id: Some("PSU1".to_owned()),
                presence: Some(true),
                input1active: Some(true),
                input2active: Some(false),
            },
        )
    }

    fn oem_nvidia_psu_redundancy_resource() -> CoreResourceResponse {
        CoreResourceResponse::new(
            CoreResourceSourceResponse::new(
                uuid!("01989abc-def0-7abc-8def-0123456789c7"),
                "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PSURedundancy".to_owned(),
                Some("#NvidiaPsuRedundancy.v1_0_0.NvidiaPsuRedundancy".to_owned()),
                Some("W/\"nvidia-redundancy-1\"".to_owned()),
            ),
            CoreResourceCommonResponse::new(
                "PSURedundancy".to_owned(),
                "PSU Redundancy".to_owned(),
                Some("PSU redundancy settings".to_owned()),
            ),
            CoreResourceDetailsResponse::OemNvidiaPsuRedundancy {
                max_num_supported: Some("4".to_owned()),
                min_num_needed: Some("2".to_owned()),
                redundancy_setting: Some("NPlusOne".to_owned()),
            },
        )
    }

    fn oem_nvidia_managed_entity_resource() -> CoreResourceResponse {
        CoreResourceResponse::new(
            CoreResourceSourceResponse::new(
                uuid!("01989abc-def0-7abc-8def-0123456789c8"),
                "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/ManagedEntityGroups/1/ManagedEntities/1"
                    .to_owned(),
                Some("#NvidiaManagedEntity.v1_0_0.NvidiaManagedEntity".to_owned()),
                Some("W/\"nvidia-entity-1\"".to_owned()),
            ),
            CoreResourceCommonResponse::new(
                "1".to_owned(),
                "Managed Entity One".to_owned(),
                Some("BlueField managed entity".to_owned()),
            ),
            CoreResourceDetailsResponse::OemNvidiaManagedEntity {
                transport_protocol: Some("HTTPS".to_owned()),
                ipv4_address: Some("192.0.2.10".to_owned()),
                ipv6_address: Some("2001:db8::10".to_owned()),
                port: Some(443),
            },
        )
    }

    fn processor_resource() -> CoreResourceResponse {
        CoreResourceResponse::new(
            CoreResourceSourceResponse::new(
                uuid!("01989abc-def0-7abc-8def-0123456789ce"),
                "/redfish/v1/Systems/1/Processors/CPU1".to_owned(),
                Some("#Processor.v1_15_0.Processor".to_owned()),
                Some("W/\"cpu-1\"".to_owned()),
            ),
            CoreResourceCommonResponse::new(
                "CPU1".to_owned(),
                "Processor One".to_owned(),
                Some("Primary compute processor".to_owned()),
            ),
            CoreResourceDetailsResponse::Processor {
                processor_type: Some("CPU".to_owned()),
                socket: Some("LGA4189".to_owned()),
                manufacturer: Some("Vendor A".to_owned()),
                model: Some("EPYC Model X".to_owned()),
                total_cores: Some(64),
                status: Some(ResourceStatusResponse::new(
                    Some("Enabled".to_owned()),
                    Some("OK".to_owned()),
                    Some("OK".to_owned()),
                )),
            },
        )
    }

    fn memory_resource() -> CoreResourceResponse {
        CoreResourceResponse::new(
            CoreResourceSourceResponse::new(
                uuid!("01989abc-def0-7abc-8def-0123456789cf"),
                "/redfish/v1/Systems/1/Memory/DIMM1".to_owned(),
                Some("#Memory.v1_15_0.Memory".to_owned()),
                None,
            ),
            CoreResourceCommonResponse::new(
                "DIMM1".to_owned(),
                "Memory Module One".to_owned(),
                None,
            ),
            CoreResourceDetailsResponse::Memory {
                memory_device_type: Some("DDR4".to_owned()),
                capacity_mib: Some(32768),
                manufacturer: Some("Vendor B".to_owned()),
                model: Some("MEM-32G".to_owned()),
                status: None,
            },
        )
    }

    #[test]
    fn core_resource_contract_carries_storage_wire_values() -> Result<(), Box<dyn Error>> {
        let storage = storage_resource();

        assert_eq!(
            serde_json::to_value(&storage)?,
            json!({
                "source": {
                    "resource_id": "01989abc-def0-7abc-8def-0123456789d0",
                    "odata_id": "/redfish/v1/Systems/1/Storage/SATA-1",
                    "odata_type": "#Storage.v1_21_0.Storage",
                    "etag": "W/\"storage-1\""
                },
                "common": {
                    "id": "SATA-1",
                    "name": "Storage Subsystem One",
                    "description": "SATA storage subsystem"
                },
                "resource": {
                    "resource_type": "storage",
                    "details": {
                        "controller_count": 2,
                        "drive_count": 6,
                        "status": {
                            "state": "Enabled",
                            "health": "OK",
                            "health_rollup": "OK"
                        }
                    }
                }
            })
        );
        assert_eq!(
            serde_json::from_value::<CoreResourceResponse>(serde_json::to_value(&storage)?)?,
            storage
        );
        assert!(
            serde_json::from_value::<CoreResourceDetailsResponse>(json!({
                "resource_type": "storage",
                "details": {
                    "controller_count": null,
                    "drive_count": null,
                    "status": null,
                    "arbitrary": true
                }
            }))
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn core_resource_contract_carries_network_adapter_wire_values() -> Result<(), Box<dyn Error>> {
        let network_adapter = network_adapter_resource();

        assert_eq!(
            serde_json::to_value(&network_adapter)?,
            json!({
                "source": {
                    "resource_id": "01989abc-def0-7abc-8def-0123456789d1",
                    "odata_id": "/redfish/v1/Chassis/1/NetworkAdapters/1",
                    "odata_type": "#NetworkAdapter.v1_14_0.NetworkAdapter",
                    "etag": null
                },
                "common": {
                    "id": "1",
                    "name": "Network Adapter One",
                    "description": null
                },
                "resource": {
                    "resource_type": "network_adapter",
                    "details": {
                        "manufacturer": "Vendor A",
                        "model": "NA-25G-2P",
                        "status": null
                    }
                }
            })
        );
        assert_eq!(
            serde_json::from_value::<CoreResourceResponse>(serde_json::to_value(
                &network_adapter
            )?)?,
            network_adapter
        );
        assert!(
            serde_json::from_value::<CoreResourceDetailsResponse>(json!({
                "resource_type": "network_adapter",
                "details": {
                    "manufacturer": null,
                    "model": null,
                    "status": null,
                    "arbitrary": true
                }
            }))
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn core_resource_contract_carries_ethernet_interface_wire_values() -> Result<(), Box<dyn Error>>
    {
        let ethernet_interface = ethernet_interface_resource();

        assert_eq!(
            serde_json::to_value(&ethernet_interface)?,
            json!({
                "source": {
                    "resource_id": "01989abc-def0-7abc-8def-0123456789d2",
                    "odata_id": "/redfish/v1/Managers/1/EthernetInterfaces/1",
                    "odata_type": "#EthernetInterface.v1_12_4.EthernetInterface",
                    "etag": "W/\"eth-1\""
                },
                "common": {
                    "id": "1",
                    "name": "Ethernet Interface One",
                    "description": null
                },
                "resource": {
                    "resource_type": "ethernet_interface",
                    "details": {
                        "mac_address": "52:54:00:12:34:56",
                        "speed_mbps": 10000,
                        "interface_enabled": true,
                        "status": {
                            "state": "Enabled",
                            "health": "OK",
                            "health_rollup": "OK"
                        }
                    }
                }
            })
        );
        assert_eq!(
            serde_json::from_value::<CoreResourceResponse>(serde_json::to_value(
                &ethernet_interface
            )?)?,
            ethernet_interface
        );
        assert!(
            serde_json::from_value::<CoreResourceDetailsResponse>(json!({
                "resource_type": "ethernet_interface",
                "details": {
                    "mac_address": null,
                    "speed_mbps": null,
                    "interface_enabled": null,
                    "status": null,
                    "arbitrary": true
                }
            }))
            .is_err()
        );
        Ok(())
    }

    fn storage_resource() -> CoreResourceResponse {
        CoreResourceResponse::new(
            CoreResourceSourceResponse::new(
                uuid!("01989abc-def0-7abc-8def-0123456789d0"),
                "/redfish/v1/Systems/1/Storage/SATA-1".to_owned(),
                Some("#Storage.v1_21_0.Storage".to_owned()),
                Some("W/\"storage-1\"".to_owned()),
            ),
            CoreResourceCommonResponse::new(
                "SATA-1".to_owned(),
                "Storage Subsystem One".to_owned(),
                Some("SATA storage subsystem".to_owned()),
            ),
            CoreResourceDetailsResponse::Storage {
                controller_count: Some(2),
                drive_count: Some(6),
                status: Some(ResourceStatusResponse::new(
                    Some("Enabled".to_owned()),
                    Some("OK".to_owned()),
                    Some("OK".to_owned()),
                )),
            },
        )
    }

    fn network_adapter_resource() -> CoreResourceResponse {
        CoreResourceResponse::new(
            CoreResourceSourceResponse::new(
                uuid!("01989abc-def0-7abc-8def-0123456789d1"),
                "/redfish/v1/Chassis/1/NetworkAdapters/1".to_owned(),
                Some("#NetworkAdapter.v1_14_0.NetworkAdapter".to_owned()),
                None,
            ),
            CoreResourceCommonResponse::new("1".to_owned(), "Network Adapter One".to_owned(), None),
            CoreResourceDetailsResponse::NetworkAdapter {
                manufacturer: Some("Vendor A".to_owned()),
                model: Some("NA-25G-2P".to_owned()),
                status: None,
            },
        )
    }

    #[test]
    fn core_resource_contract_carries_account_wire_values() -> Result<(), Box<dyn Error>> {
        let account = account_resource();

        assert_eq!(
            serde_json::to_value(&account)?,
            json!({
                "source": {
                    "resource_id": "01989abc-def0-7abc-8def-0123456789d7",
                    "odata_id": "/redfish/v1/AccountService/Accounts/admin",
                    "odata_type": "#ManagerAccount.v1_14_1.ManagerAccount",
                    "etag": "W/\"account-1\""
                },
                "common": {
                    "id": "admin",
                    "name": "Administrator Account",
                    "description": "Built-in administrator account"
                },
                "resource": {
                    "resource_type": "account",
                    "details": {
                        "enabled": true,
                        "role_id": "Administrator",
                        "locked": false
                    }
                }
            })
        );
        assert_eq!(
            serde_json::from_value::<CoreResourceResponse>(serde_json::to_value(&account)?)?,
            account
        );
        assert!(
            serde_json::from_value::<CoreResourceDetailsResponse>(json!({
                "resource_type": "account",
                "details": {
                    "enabled": null,
                    "role_id": null,
                    "locked": null,
                    "arbitrary": true
                }
            }))
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn core_resource_contract_carries_bios_wire_values() -> Result<(), Box<dyn Error>> {
        let bios = bios_resource();

        assert_eq!(
            serde_json::to_value(&bios)?,
            json!({
                "source": {
                    "resource_id": "01989abc-def0-7abc-8def-0123456789d8",
                    "odata_id": "/redfish/v1/Systems/1/Bios",
                    "odata_type": "#Bios.v1_2_3.Bios",
                    "etag": "W/\"bios-1\""
                },
                "common": {
                    "id": "BIOS",
                    "name": "BIOS Configuration",
                    "description": null
                },
                "resource": {
                    "resource_type": "bios",
                    "details": {
                        "attribute_registry": "BiosAttributeRegistry.v1_0_0"
                    }
                }
            })
        );
        assert_eq!(
            serde_json::from_value::<CoreResourceResponse>(serde_json::to_value(&bios)?)?,
            bios
        );
        assert!(
            serde_json::from_value::<CoreResourceDetailsResponse>(json!({
                "resource_type": "bios",
                "details": {
                    "attribute_registry": null,
                    "arbitrary": true
                }
            }))
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn core_resource_contract_carries_boot_option_wire_values() -> Result<(), Box<dyn Error>> {
        let boot_option = boot_option_resource();

        assert_eq!(
            serde_json::to_value(&boot_option)?,
            json!({
                "source": {
                    "resource_id": "01989abc-def0-7abc-8def-0123456789d9",
                    "odata_id": "/redfish/v1/Systems/1/BootOptions/PXE-1",
                    "odata_type": "#BootOption.v1_0_6.BootOption",
                    "etag": null
                },
                "common": {
                    "id": "PXE-1",
                    "name": "Network Boot Option",
                    "description": "PXE boot option"
                },
                "resource": {
                    "resource_type": "boot_option",
                    "details": {
                        "display_name": "PXE Network Boot",
                        "boot_option_enabled": true,
                        "uefi_device_path": "PciRoot(0x0)/Pci(0x1C,0x0)/Pci(0x0,0x0)"
                    }
                }
            })
        );
        assert_eq!(
            serde_json::from_value::<CoreResourceResponse>(serde_json::to_value(&boot_option)?)?,
            boot_option
        );
        assert!(
            serde_json::from_value::<CoreResourceDetailsResponse>(json!({
                "resource_type": "boot_option",
                "details": {
                    "display_name": null,
                    "boot_option_enabled": null,
                    "uefi_device_path": null,
                    "arbitrary": true
                }
            }))
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn core_resource_contract_carries_secure_boot_wire_values() -> Result<(), Box<dyn Error>> {
        let secure_boot = secure_boot_resource();

        assert_eq!(
            serde_json::to_value(&secure_boot)?,
            json!({
                "source": {
                    "resource_id": "01989abc-def0-7abc-8def-0123456789da",
                    "odata_id": "/redfish/v1/Systems/1/SecureBoot",
                    "odata_type": "#SecureBoot.v1_1_2.SecureBoot",
                    "etag": "W/\"secure-boot-1\""
                },
                "common": {
                    "id": "SecureBoot",
                    "name": "Secure Boot",
                    "description": null
                },
                "resource": {
                    "resource_type": "secure_boot",
                    "details": {
                        "secure_boot_enable": true,
                        "secure_boot_mode": "DeployedMode"
                    }
                }
            })
        );
        assert_eq!(
            serde_json::from_value::<CoreResourceResponse>(serde_json::to_value(&secure_boot)?)?,
            secure_boot
        );
        assert!(
            serde_json::from_value::<CoreResourceDetailsResponse>(json!({
                "resource_type": "secure_boot",
                "details": {
                    "secure_boot_enable": null,
                    "secure_boot_mode": null,
                    "arbitrary": true
                }
            }))
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn core_resource_contract_carries_power_wire_values() -> Result<(), Box<dyn Error>> {
        let power = power_resource();

        assert_eq!(
            serde_json::to_value(&power)?,
            json!({
                "source": {
                    "resource_id": "01989abc-def0-7abc-8def-0123456789db",
                    "odata_id": "/redfish/v1/Chassis/1/Power",
                    "odata_type": "#Power.v1_7_3.Power",
                    "etag": "W/\"power-1\""
                },
                "common": {
                    "id": "Power",
                    "name": "Power",
                    "description": null
                },
                "resource": {
                    "resource_type": "power",
                    "details": {}
                }
            })
        );
        assert_eq!(
            serde_json::from_value::<CoreResourceResponse>(serde_json::to_value(&power)?)?,
            power
        );
        assert!(
            serde_json::from_value::<CoreResourceDetailsResponse>(json!({
                "resource_type": "power",
                "details": {
                    "arbitrary": true
                }
            }))
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn core_resource_contract_carries_thermal_wire_values() -> Result<(), Box<dyn Error>> {
        let thermal = thermal_resource();

        assert_eq!(
            serde_json::to_value(&thermal)?,
            json!({
                "source": {
                    "resource_id": "01989abc-def0-7abc-8def-0123456789dc",
                    "odata_id": "/redfish/v1/Chassis/1/Thermal",
                    "odata_type": "#Thermal.v1_7_3.Thermal",
                    "etag": null
                },
                "common": {
                    "id": "Thermal",
                    "name": "Thermal",
                    "description": null
                },
                "resource": {
                    "resource_type": "thermal",
                    "details": {
                        "status": {
                            "state": "Enabled",
                            "health": "OK",
                            "health_rollup": "OK"
                        }
                    }
                }
            })
        );
        assert_eq!(
            serde_json::from_value::<CoreResourceResponse>(serde_json::to_value(&thermal)?)?,
            thermal
        );
        assert!(
            serde_json::from_value::<CoreResourceDetailsResponse>(json!({
                "resource_type": "thermal",
                "details": {
                    "status": null,
                    "arbitrary": true
                }
            }))
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn core_resource_contract_carries_sensor_wire_values() -> Result<(), Box<dyn Error>> {
        let sensor = sensor_resource();

        assert_eq!(
            serde_json::to_value(&sensor)?,
            json!({
                "source": {
                    "resource_id": "01989abc-def0-7abc-8def-0123456789dd",
                    "odata_id": "/redfish/v1/Chassis/1/Sensors/Temp1",
                    "odata_type": "#Sensor.v1_12_0.Sensor",
                    "etag": "W/\"sensor-1\""
                },
                "common": {
                    "id": "Temp1",
                    "name": "Inlet Temperature",
                    "description": null
                },
                "resource": {
                    "resource_type": "sensor",
                    "details": {
                        "reading": 33.5,
                        "reading_units": "Cel",
                        "reading_type": "Temperature",
                        "status": {
                            "state": "Enabled",
                            "health": "OK",
                            "health_rollup": "OK"
                        }
                    }
                }
            })
        );
        assert_eq!(
            serde_json::from_value::<CoreResourceResponse>(serde_json::to_value(&sensor)?)?,
            sensor
        );
        assert!(
            serde_json::from_value::<CoreResourceDetailsResponse>(json!({
                "resource_type": "sensor",
                "details": {
                    "reading": null,
                    "reading_units": null,
                    "reading_type": null,
                    "status": null,
                    "arbitrary": true
                }
            }))
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn core_resource_contract_carries_control_wire_values() -> Result<(), Box<dyn Error>> {
        let control = control_resource();

        assert_eq!(
            serde_json::to_value(&control)?,
            json!({
                "source": {
                    "resource_id": "01989abc-def0-7abc-8def-0123456789de",
                    "odata_id": "/redfish/v1/Chassis/1/Controls/FanCtl1",
                    "odata_type": "#Control.v1_7_0.Control",
                    "etag": "W/\"control-1\""
                },
                "common": {
                    "id": "FanCtl1",
                    "name": "Fan Speed Control",
                    "description": null
                },
                "resource": {
                    "resource_type": "control",
                    "details": {
                        "control_type": "Power",
                        "set_point": 500.0,
                        "status": {
                            "state": "Enabled",
                            "health": "OK",
                            "health_rollup": "OK"
                        }
                    }
                }
            })
        );
        assert_eq!(
            serde_json::from_value::<CoreResourceResponse>(serde_json::to_value(&control)?)?,
            control
        );
        assert!(
            serde_json::from_value::<CoreResourceDetailsResponse>(json!({
                "resource_type": "control",
                "details": {
                    "control_type": null,
                    "set_point": null,
                    "status": null,
                    "arbitrary": true
                }
            }))
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn core_resource_contract_carries_log_service_wire_values() -> Result<(), Box<dyn Error>> {
        let log_service = log_service_resource();

        assert_eq!(
            serde_json::to_value(&log_service)?,
            json!({
                "source": {
                    "resource_id": "01989abc-def0-7abc-8def-0123456789df",
                    "odata_id": "/redfish/v1/Managers/1/LogServices/SEL",
                    "odata_type": "#LogService.v1_9_0.LogService",
                    "etag": "W/\"log-service-1\""
                },
                "common": {
                    "id": "SEL",
                    "name": "System Event Log",
                    "description": null
                },
                "resource": {
                    "resource_type": "log_service",
                    "details": {
                        "service_enabled": true,
                        "max_log_entries": 10000,
                        "status": {
                            "state": "Enabled",
                            "health": "OK",
                            "health_rollup": "OK"
                        }
                    }
                }
            })
        );
        assert_eq!(
            serde_json::from_value::<CoreResourceResponse>(serde_json::to_value(&log_service)?)?,
            log_service
        );
        assert!(
            serde_json::from_value::<CoreResourceDetailsResponse>(json!({
                "resource_type": "log_service",
                "details": {
                    "service_enabled": null,
                    "max_log_entries": null,
                    "status": null,
                    "arbitrary": true
                }
            }))
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn core_resource_contract_carries_manager_network_protocol_wire_values()
    -> Result<(), Box<dyn Error>> {
        let manager_network_protocol = manager_network_protocol_resource();

        assert_eq!(
            serde_json::to_value(&manager_network_protocol)?,
            json!({
                "source": {
                    "resource_id": "01989abc-def0-7abc-8def-0123456789e0",
                    "odata_id": "/redfish/v1/Managers/1/NetworkProtocol",
                    "odata_type": "#ManagerNetworkProtocol.v1_12_0.ManagerNetworkProtocol",
                    "etag": null
                },
                "common": {
                    "id": "NetworkProtocol",
                    "name": "Manager Network Protocol",
                    "description": null
                },
                "resource": {
                    "resource_type": "manager_network_protocol",
                    "details": {
                        "host_name": "bmc-rack-a",
                        "fqdn": "bmc-rack-a.example.test",
                        "status": {
                            "state": "Enabled",
                            "health": "OK",
                            "health_rollup": "OK"
                        }
                    }
                }
            })
        );
        assert_eq!(
            serde_json::from_value::<CoreResourceResponse>(serde_json::to_value(
                &manager_network_protocol
            )?)?,
            manager_network_protocol
        );
        assert!(
            serde_json::from_value::<CoreResourceDetailsResponse>(json!({
                "resource_type": "manager_network_protocol",
                "details": {
                    "host_name": null,
                    "fqdn": null,
                    "status": null,
                    "arbitrary": true
                }
            }))
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn core_resource_contract_carries_host_interface_wire_values() -> Result<(), Box<dyn Error>> {
        let host_interface = host_interface_resource();

        assert_eq!(
            serde_json::to_value(&host_interface)?,
            json!({
                "source": {
                    "resource_id": "01989abc-def0-7abc-8def-0123456789e2",
                    "odata_id": "/redfish/v1/Managers/1/HostInterfaces/1",
                    "odata_type": "#HostInterface.v1_3_3.HostInterface",
                    "etag": "W/\"host-interface-1\""
                },
                "common": {
                    "id": "1",
                    "name": "Host Interface One",
                    "description": null
                },
                "resource": {
                    "resource_type": "host_interface",
                    "details": {
                        "interface_enabled": true,
                        "status": {
                            "state": "Enabled",
                            "health": "OK",
                            "health_rollup": "OK"
                        }
                    }
                }
            })
        );
        assert_eq!(
            serde_json::from_value::<CoreResourceResponse>(serde_json::to_value(&host_interface)?)?,
            host_interface
        );
        assert!(
            serde_json::from_value::<CoreResourceDetailsResponse>(json!({
                "resource_type": "host_interface",
                "details": {
                    "interface_enabled": null,
                    "status": null,
                    "arbitrary": true
                }
            }))
            .is_err()
        );
        Ok(())
    }

    fn account_resource() -> CoreResourceResponse {
        CoreResourceResponse::new(
            CoreResourceSourceResponse::new(
                uuid!("01989abc-def0-7abc-8def-0123456789d7"),
                "/redfish/v1/AccountService/Accounts/admin".to_owned(),
                Some("#ManagerAccount.v1_14_1.ManagerAccount".to_owned()),
                Some("W/\"account-1\"".to_owned()),
            ),
            CoreResourceCommonResponse::new(
                "admin".to_owned(),
                "Administrator Account".to_owned(),
                Some("Built-in administrator account".to_owned()),
            ),
            CoreResourceDetailsResponse::Account {
                enabled: Some(true),
                role_id: Some("Administrator".to_owned()),
                locked: Some(false),
            },
        )
    }

    fn bios_resource() -> CoreResourceResponse {
        CoreResourceResponse::new(
            CoreResourceSourceResponse::new(
                uuid!("01989abc-def0-7abc-8def-0123456789d8"),
                "/redfish/v1/Systems/1/Bios".to_owned(),
                Some("#Bios.v1_2_3.Bios".to_owned()),
                Some("W/\"bios-1\"".to_owned()),
            ),
            CoreResourceCommonResponse::new(
                "BIOS".to_owned(),
                "BIOS Configuration".to_owned(),
                None,
            ),
            CoreResourceDetailsResponse::Bios {
                attribute_registry: Some("BiosAttributeRegistry.v1_0_0".to_owned()),
            },
        )
    }

    fn boot_option_resource() -> CoreResourceResponse {
        CoreResourceResponse::new(
            CoreResourceSourceResponse::new(
                uuid!("01989abc-def0-7abc-8def-0123456789d9"),
                "/redfish/v1/Systems/1/BootOptions/PXE-1".to_owned(),
                Some("#BootOption.v1_0_6.BootOption".to_owned()),
                None,
            ),
            CoreResourceCommonResponse::new(
                "PXE-1".to_owned(),
                "Network Boot Option".to_owned(),
                Some("PXE boot option".to_owned()),
            ),
            CoreResourceDetailsResponse::BootOption {
                display_name: Some("PXE Network Boot".to_owned()),
                boot_option_enabled: Some(true),
                uefi_device_path: Some("PciRoot(0x0)/Pci(0x1C,0x0)/Pci(0x0,0x0)".to_owned()),
            },
        )
    }

    fn secure_boot_resource() -> CoreResourceResponse {
        CoreResourceResponse::new(
            CoreResourceSourceResponse::new(
                uuid!("01989abc-def0-7abc-8def-0123456789da"),
                "/redfish/v1/Systems/1/SecureBoot".to_owned(),
                Some("#SecureBoot.v1_1_2.SecureBoot".to_owned()),
                Some("W/\"secure-boot-1\"".to_owned()),
            ),
            CoreResourceCommonResponse::new(
                "SecureBoot".to_owned(),
                "Secure Boot".to_owned(),
                None,
            ),
            CoreResourceDetailsResponse::SecureBoot {
                secure_boot_enable: Some(true),
                secure_boot_mode: Some("DeployedMode".to_owned()),
            },
        )
    }

    fn power_resource() -> CoreResourceResponse {
        CoreResourceResponse::new(
            CoreResourceSourceResponse::new(
                uuid!("01989abc-def0-7abc-8def-0123456789db"),
                "/redfish/v1/Chassis/1/Power".to_owned(),
                Some("#Power.v1_7_3.Power".to_owned()),
                Some("W/\"power-1\"".to_owned()),
            ),
            CoreResourceCommonResponse::new("Power".to_owned(), "Power".to_owned(), None),
            CoreResourceDetailsResponse::Power {},
        )
    }

    fn thermal_resource() -> CoreResourceResponse {
        CoreResourceResponse::new(
            CoreResourceSourceResponse::new(
                uuid!("01989abc-def0-7abc-8def-0123456789dc"),
                "/redfish/v1/Chassis/1/Thermal".to_owned(),
                Some("#Thermal.v1_7_3.Thermal".to_owned()),
                None,
            ),
            CoreResourceCommonResponse::new("Thermal".to_owned(), "Thermal".to_owned(), None),
            CoreResourceDetailsResponse::Thermal {
                status: Some(ResourceStatusResponse::new(
                    Some("Enabled".to_owned()),
                    Some("OK".to_owned()),
                    Some("OK".to_owned()),
                )),
            },
        )
    }

    fn sensor_resource() -> CoreResourceResponse {
        CoreResourceResponse::new(
            CoreResourceSourceResponse::new(
                uuid!("01989abc-def0-7abc-8def-0123456789dd"),
                "/redfish/v1/Chassis/1/Sensors/Temp1".to_owned(),
                Some("#Sensor.v1_12_0.Sensor".to_owned()),
                Some("W/\"sensor-1\"".to_owned()),
            ),
            CoreResourceCommonResponse::new(
                "Temp1".to_owned(),
                "Inlet Temperature".to_owned(),
                None,
            ),
            CoreResourceDetailsResponse::Sensor {
                reading: Some(33.5),
                reading_units: Some("Cel".to_owned()),
                reading_type: Some("Temperature".to_owned()),
                status: Some(ResourceStatusResponse::new(
                    Some("Enabled".to_owned()),
                    Some("OK".to_owned()),
                    Some("OK".to_owned()),
                )),
            },
        )
    }

    fn control_resource() -> CoreResourceResponse {
        CoreResourceResponse::new(
            CoreResourceSourceResponse::new(
                uuid!("01989abc-def0-7abc-8def-0123456789de"),
                "/redfish/v1/Chassis/1/Controls/FanCtl1".to_owned(),
                Some("#Control.v1_7_0.Control".to_owned()),
                Some("W/\"control-1\"".to_owned()),
            ),
            CoreResourceCommonResponse::new(
                "FanCtl1".to_owned(),
                "Fan Speed Control".to_owned(),
                None,
            ),
            CoreResourceDetailsResponse::Control {
                control_type: Some("Power".to_owned()),
                set_point: Some(500.0),
                status: Some(ResourceStatusResponse::new(
                    Some("Enabled".to_owned()),
                    Some("OK".to_owned()),
                    Some("OK".to_owned()),
                )),
            },
        )
    }

    fn log_service_resource() -> CoreResourceResponse {
        CoreResourceResponse::new(
            CoreResourceSourceResponse::new(
                uuid!("01989abc-def0-7abc-8def-0123456789df"),
                "/redfish/v1/Managers/1/LogServices/SEL".to_owned(),
                Some("#LogService.v1_9_0.LogService".to_owned()),
                Some("W/\"log-service-1\"".to_owned()),
            ),
            CoreResourceCommonResponse::new("SEL".to_owned(), "System Event Log".to_owned(), None),
            CoreResourceDetailsResponse::LogService {
                service_enabled: Some(true),
                max_log_entries: Some(10000),
                status: Some(ResourceStatusResponse::new(
                    Some("Enabled".to_owned()),
                    Some("OK".to_owned()),
                    Some("OK".to_owned()),
                )),
            },
        )
    }

    fn manager_network_protocol_resource() -> CoreResourceResponse {
        CoreResourceResponse::new(
            CoreResourceSourceResponse::new(
                uuid!("01989abc-def0-7abc-8def-0123456789e0"),
                "/redfish/v1/Managers/1/NetworkProtocol".to_owned(),
                Some("#ManagerNetworkProtocol.v1_12_0.ManagerNetworkProtocol".to_owned()),
                None,
            ),
            CoreResourceCommonResponse::new(
                "NetworkProtocol".to_owned(),
                "Manager Network Protocol".to_owned(),
                None,
            ),
            CoreResourceDetailsResponse::ManagerNetworkProtocol {
                host_name: Some("bmc-rack-a".to_owned()),
                fqdn: Some("bmc-rack-a.example.test".to_owned()),
                status: Some(ResourceStatusResponse::new(
                    Some("Enabled".to_owned()),
                    Some("OK".to_owned()),
                    Some("OK".to_owned()),
                )),
            },
        )
    }

    fn host_interface_resource() -> CoreResourceResponse {
        CoreResourceResponse::new(
            CoreResourceSourceResponse::new(
                uuid!("01989abc-def0-7abc-8def-0123456789e2"),
                "/redfish/v1/Managers/1/HostInterfaces/1".to_owned(),
                Some("#HostInterface.v1_3_3.HostInterface".to_owned()),
                Some("W/\"host-interface-1\"".to_owned()),
            ),
            CoreResourceCommonResponse::new("1".to_owned(), "Host Interface One".to_owned(), None),
            CoreResourceDetailsResponse::HostInterface {
                interface_enabled: Some(true),
                status: Some(ResourceStatusResponse::new(
                    Some("Enabled".to_owned()),
                    Some("OK".to_owned()),
                    Some("OK".to_owned()),
                )),
            },
        )
    }

    #[test]
    fn core_resource_contract_carries_pcie_device_wire_values() -> Result<(), Box<dyn Error>> {
        let pcie_device = pcie_device_resource();

        assert_eq!(
            serde_json::to_value(&pcie_device)?,
            json!({
                "source": {
                    "resource_id": "01989abc-def0-7abc-8def-0123456789e3",
                    "odata_id": "/redfish/v1/Chassis/1/PCIeDevices/GPU1",
                    "odata_type": "#PCIeDevice.v1_12_0.PCIeDevice",
                    "etag": "W/\"pcie-device-1\""
                },
                "common": {
                    "id": "GPU1",
                    "name": "PCIe Device One",
                    "description": null
                },
                "resource": {
                    "resource_type": "pcie_device",
                    "details": {
                        "device_type": "SingleFunction",
                        "manufacturer": "Vendor C",
                        "model": "PCIE-GEN4-X16",
                        "status": {
                            "state": "Enabled",
                            "health": "OK",
                            "health_rollup": "OK"
                        }
                    }
                }
            })
        );
        assert_eq!(
            serde_json::from_value::<CoreResourceResponse>(serde_json::to_value(&pcie_device)?)?,
            pcie_device
        );
        assert!(
            serde_json::from_value::<CoreResourceDetailsResponse>(json!({
                "resource_type": "pcie_device",
                "details": {
                    "device_type": null,
                    "manufacturer": null,
                    "model": null,
                    "status": null,
                    "arbitrary": true
                }
            }))
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn core_resource_contract_carries_assembly_wire_values() -> Result<(), Box<dyn Error>> {
        let assembly = assembly_resource();

        assert_eq!(
            serde_json::to_value(&assembly)?,
            json!({
                "source": {
                    "resource_id": "01989abc-def0-7abc-8def-0123456789e4",
                    "odata_id": "/redfish/v1/Chassis/1/Assembly",
                    "odata_type": "#Assembly.v1_5_0.Assembly",
                    "etag": "W/\"assembly-1\""
                },
                "common": {
                    "id": "Assembly",
                    "name": "Chassis Assembly",
                    "description": null
                },
                "resource": {
                    "resource_type": "assembly",
                    "details": {
                        "producer": "Vendor D",
                        "status": {
                            "state": "Enabled",
                            "health": "OK",
                            "health_rollup": "OK"
                        }
                    }
                }
            })
        );
        assert_eq!(
            serde_json::from_value::<CoreResourceResponse>(serde_json::to_value(&assembly)?)?,
            assembly
        );
        assert!(
            serde_json::from_value::<CoreResourceDetailsResponse>(json!({
                "resource_type": "assembly",
                "details": {
                    "producer": null,
                    "status": null,
                    "arbitrary": true
                }
            }))
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn core_resource_contract_carries_software_inventory_wire_values() -> Result<(), Box<dyn Error>>
    {
        let software_inventory = software_inventory_resource()?;

        assert_eq!(
            serde_json::to_value(&software_inventory)?,
            json!({
                "source": {
                    "resource_id": "01989abc-def0-7abc-8def-0123456789e5",
                    "odata_id": "/redfish/v1/UpdateService/SoftwareInventory/BIOS",
                    "odata_type": "#SoftwareInventory.v1_7_0.SoftwareInventory",
                    "etag": "W/\"sw-1\""
                },
                "common": {
                    "id": "BIOS",
                    "name": "System BIOS",
                    "description": null
                },
                "resource": {
                    "resource_type": "software_inventory",
                    "details": {
                        "software_id": "BIOS-2026-1",
                        "version": "2.7.0",
                        "release_date": "2026-05-01T00:00:00Z",
                        "status": {
                            "state": "Enabled",
                            "health": "OK",
                            "health_rollup": "OK"
                        }
                    }
                }
            })
        );
        assert_eq!(
            serde_json::from_value::<CoreResourceResponse>(serde_json::to_value(
                &software_inventory
            )?)?,
            software_inventory
        );
        assert!(
            serde_json::from_value::<CoreResourceDetailsResponse>(json!({
                "resource_type": "software_inventory",
                "details": {
                    "software_id": null,
                    "version": null,
                    "release_date": null,
                    "status": null,
                    "arbitrary": true
                }
            }))
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn core_resource_contract_carries_event_service_wire_values() -> Result<(), Box<dyn Error>> {
        let event_service = event_service_resource();

        assert_eq!(
            serde_json::to_value(&event_service)?,
            json!({
                "source": {
                    "resource_id": "01989abc-def0-7abc-8def-0123456789e6",
                    "odata_id": "/redfish/v1/EventService",
                    "odata_type": "#EventService.v1_12_0.EventService",
                    "etag": "W/\"event-service-1\""
                },
                "common": {
                    "id": "EventService",
                    "name": "Event Service",
                    "description": null
                },
                "resource": {
                    "resource_type": "event_service",
                    "details": {
                        "service_enabled": true,
                        "status": {
                            "state": "Enabled",
                            "health": "OK",
                            "health_rollup": "OK"
                        }
                    }
                }
            })
        );
        assert_eq!(
            serde_json::from_value::<CoreResourceResponse>(serde_json::to_value(&event_service)?)?,
            event_service
        );
        assert!(
            serde_json::from_value::<CoreResourceDetailsResponse>(json!({
                "resource_type": "event_service",
                "details": {
                    "service_enabled": null,
                    "status": null,
                    "arbitrary": true
                }
            }))
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn core_resource_contract_carries_event_subscription_wire_values() -> Result<(), Box<dyn Error>>
    {
        let event_subscription = event_subscription_resource();

        assert_eq!(
            serde_json::to_value(&event_subscription)?,
            json!({
                "source": {
                    "resource_id": "01989abc-def0-7abc-8def-0123456789e7",
                    "odata_id": "/redfish/v1/EventService/Subscriptions/1",
                    "odata_type": "#EventDestination.v1_16_0.EventDestination",
                    "etag": "W/\"subscription-1\""
                },
                "common": {
                    "id": "1",
                    "name": "Subscription One",
                    "description": null
                },
                "resource": {
                    "resource_type": "event_subscription",
                    "details": {
                        "destination": "https://subscriber.example.test/events",
                        "protocol": "Redfish",
                        "context": "Rack A",
                        "event_types": ["Alert", "StatusChange"],
                        "status": {
                            "state": "Enabled",
                            "health": "OK",
                            "health_rollup": "OK"
                        }
                    }
                }
            })
        );
        assert_eq!(
            serde_json::from_value::<CoreResourceResponse>(serde_json::to_value(
                &event_subscription
            )?)?,
            event_subscription
        );
        assert!(
            serde_json::from_value::<CoreResourceDetailsResponse>(json!({
                "resource_type": "event_subscription",
                "details": {
                    "destination": null,
                    "protocol": null,
                    "context": null,
                    "event_types": null,
                    "status": null,
                    "arbitrary": true
                }
            }))
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn core_resource_contract_carries_telemetry_service_wire_values() -> Result<(), Box<dyn Error>>
    {
        let telemetry_service = telemetry_service_resource();

        assert_eq!(
            serde_json::to_value(&telemetry_service)?,
            json!({
                "source": {
                    "resource_id": "01989abc-def0-7abc-8def-0123456789e8",
                    "odata_id": "/redfish/v1/TelemetryService",
                    "odata_type": "#TelemetryService.v1_4_0.TelemetryService",
                    "etag": null
                },
                "common": {
                    "id": "TelemetryService",
                    "name": "Telemetry Service",
                    "description": null
                },
                "resource": {
                    "resource_type": "telemetry_service",
                    "details": {
                        "status": {
                            "state": "Enabled",
                            "health": "OK",
                            "health_rollup": "OK"
                        }
                    }
                }
            })
        );
        assert_eq!(
            serde_json::from_value::<CoreResourceResponse>(serde_json::to_value(
                &telemetry_service
            )?)?,
            telemetry_service
        );
        assert!(
            serde_json::from_value::<CoreResourceDetailsResponse>(json!({
                "resource_type": "telemetry_service",
                "details": {
                    "status": null,
                    "arbitrary": true
                }
            }))
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn core_resource_contract_carries_metric_definition_wire_values() -> Result<(), Box<dyn Error>>
    {
        let metric_definition = metric_definition_resource();

        assert_eq!(
            serde_json::to_value(&metric_definition)?,
            json!({
                "source": {
                    "resource_id": "01989abc-def0-7abc-8def-0123456789e9",
                    "odata_id": "/redfish/v1/TelemetryService/MetricDefinitions/1",
                    "odata_type": "#MetricDefinition.v1_3_5.MetricDefinition",
                    "etag": null
                },
                "common": {
                    "id": "1",
                    "name": "Inlet Temperature Definition",
                    "description": null
                },
                "resource": {
                    "resource_type": "metric_definition",
                    "details": {
                        "units": "Cel",
                        "metric_type": "Numeric"
                    }
                }
            })
        );
        assert_eq!(
            serde_json::from_value::<CoreResourceResponse>(serde_json::to_value(
                &metric_definition
            )?)?,
            metric_definition
        );
        assert!(
            serde_json::from_value::<CoreResourceDetailsResponse>(json!({
                "resource_type": "metric_definition",
                "details": {
                    "units": null,
                    "metric_type": null,
                    "arbitrary": true
                }
            }))
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn core_resource_contract_carries_metric_report_wire_values() -> Result<(), Box<dyn Error>> {
        let metric_report = metric_report_resource()?;

        assert_eq!(
            serde_json::to_value(&metric_report)?,
            json!({
                "source": {
                    "resource_id": "01989abc-def0-7abc-8def-0123456789ea",
                    "odata_id": "/redfish/v1/TelemetryService/MetricReports/1",
                    "odata_type": "#MetricReport.v1_5_2.MetricReport",
                    "etag": "W/\"report-1\""
                },
                "common": {
                    "id": "1",
                    "name": "Inlet Temperature Report",
                    "description": null
                },
                "resource": {
                    "resource_type": "metric_report",
                    "details": {
                        "metric_values_count": 2,
                        "metric_values": [
                            {
                                "timestamp": "2026-08-05T10:20:00Z",
                                "value": "31.5"
                            },
                            {
                                "timestamp": "2026-08-05T10:21:00Z",
                                "value": null
                            }
                        ]
                    }
                }
            })
        );
        assert_eq!(
            serde_json::from_value::<CoreResourceResponse>(serde_json::to_value(&metric_report)?)?,
            metric_report
        );
        // The strict decoder rejects both an unknown top-level key and an
        // unknown entry key inside `metric_values` — the entry contract is as
        // strict as the report contract, so a future projection cannot
        // silently widen the wire shape.
        assert!(
            serde_json::from_value::<CoreResourceDetailsResponse>(json!({
                "resource_type": "metric_report",
                "details": {
                    "metric_values_count": null,
                    "arbitrary": true
                }
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<CoreResourceDetailsResponse>(json!({
                "resource_type": "metric_report",
                "details": {
                    "metric_values_count": null,
                    "metric_values": [{"timestamp": null, "value": "100", "arbitrary": true}]
                }
            }))
            .is_err()
        );
        // A report without readings (the 0.2.0 snapshot shape) decodes with
        // `metric_values: None` instead of failing, keeping old wire payloads
        // readable.
        let legacy: CoreResourceDetailsResponse = serde_json::from_value(json!({
            "resource_type": "metric_report",
            "details": {
                "metric_values_count": 12
            }
        }))?;
        assert!(matches!(
            legacy,
            CoreResourceDetailsResponse::MetricReport {
                metric_values_count: Some(12),
                metric_values: None,
            }
        ));
        Ok(())
    }

    #[test]
    fn core_resource_contract_carries_task_service_wire_values() -> Result<(), Box<dyn Error>> {
        let task_service = task_service_resource();

        assert_eq!(
            serde_json::to_value(&task_service)?,
            json!({
                "source": {
                    "resource_id": "01989abc-def0-7abc-8def-0123456789eb",
                    "odata_id": "/redfish/v1/TaskService",
                    "odata_type": "#TaskService.v1_3_0.TaskService",
                    "etag": null
                },
                "common": {
                    "id": "TaskService",
                    "name": "Task Service",
                    "description": null
                },
                "resource": {
                    "resource_type": "task_service",
                    "details": {
                        "service_enabled": true,
                        "completed_task_overwrite_policy": "Oldest",
                        "status": {
                            "state": "Enabled",
                            "health": "OK",
                            "health_rollup": "OK"
                        }
                    }
                }
            })
        );
        assert_eq!(
            serde_json::from_value::<CoreResourceResponse>(serde_json::to_value(&task_service)?)?,
            task_service
        );
        assert!(
            serde_json::from_value::<CoreResourceDetailsResponse>(json!({
                "resource_type": "task_service",
                "details": {
                    "service_enabled": null,
                    "completed_task_overwrite_policy": null,
                    "status": null,
                    "arbitrary": true
                }
            }))
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn core_resource_contract_carries_task_wire_values() -> Result<(), Box<dyn Error>> {
        let task = task_resource()?;

        assert_eq!(
            serde_json::to_value(&task)?,
            json!({
                "source": {
                    "resource_id": "01989abc-def0-7abc-8def-0123456789ec",
                    "odata_id": "/redfish/v1/TaskService/Tasks/1",
                    "odata_type": "#Task.v1_7_4.Task",
                    "etag": "W/\"task-1\""
                },
                "common": {
                    "id": "1",
                    "name": "Firmware Update Task",
                    "description": null
                },
                "resource": {
                    "resource_type": "task",
                    "details": {
                        "task_state": "Running",
                        "task_status": "OK",
                        "percent_complete": 42,
                        "start_time": "2026-08-05T10:20:00Z",
                        "end_time": null
                    }
                }
            })
        );
        assert_eq!(
            serde_json::from_value::<CoreResourceResponse>(serde_json::to_value(&task)?)?,
            task
        );
        assert!(
            serde_json::from_value::<CoreResourceDetailsResponse>(json!({
                "resource_type": "task",
                "details": {
                    "task_state": null,
                    "task_status": null,
                    "percent_complete": null,
                    "start_time": null,
                    "end_time": null,
                    "arbitrary": true
                }
            }))
            .is_err()
        );
        Ok(())
    }

    fn pcie_device_resource() -> CoreResourceResponse {
        CoreResourceResponse::new(
            CoreResourceSourceResponse::new(
                uuid!("01989abc-def0-7abc-8def-0123456789e3"),
                "/redfish/v1/Chassis/1/PCIeDevices/GPU1".to_owned(),
                Some("#PCIeDevice.v1_12_0.PCIeDevice".to_owned()),
                Some("W/\"pcie-device-1\"".to_owned()),
            ),
            CoreResourceCommonResponse::new("GPU1".to_owned(), "PCIe Device One".to_owned(), None),
            CoreResourceDetailsResponse::PcieDevice {
                device_type: Some("SingleFunction".to_owned()),
                manufacturer: Some("Vendor C".to_owned()),
                model: Some("PCIE-GEN4-X16".to_owned()),
                status: Some(ResourceStatusResponse::new(
                    Some("Enabled".to_owned()),
                    Some("OK".to_owned()),
                    Some("OK".to_owned()),
                )),
            },
        )
    }

    fn assembly_resource() -> CoreResourceResponse {
        CoreResourceResponse::new(
            CoreResourceSourceResponse::new(
                uuid!("01989abc-def0-7abc-8def-0123456789e4"),
                "/redfish/v1/Chassis/1/Assembly".to_owned(),
                Some("#Assembly.v1_5_0.Assembly".to_owned()),
                Some("W/\"assembly-1\"".to_owned()),
            ),
            CoreResourceCommonResponse::new(
                "Assembly".to_owned(),
                "Chassis Assembly".to_owned(),
                None,
            ),
            CoreResourceDetailsResponse::Assembly {
                producer: Some("Vendor D".to_owned()),
                status: Some(ResourceStatusResponse::new(
                    Some("Enabled".to_owned()),
                    Some("OK".to_owned()),
                    Some("OK".to_owned()),
                )),
            },
        )
    }

    fn software_inventory_resource() -> Result<CoreResourceResponse, &'static str> {
        let release_date = OffsetDateTime::parse("2026-05-01T00:00:00Z", &Rfc3339)
            .map_err(|_| "test release date must parse")?;
        Ok(CoreResourceResponse::new(
            CoreResourceSourceResponse::new(
                uuid!("01989abc-def0-7abc-8def-0123456789e5"),
                "/redfish/v1/UpdateService/SoftwareInventory/BIOS".to_owned(),
                Some("#SoftwareInventory.v1_7_0.SoftwareInventory".to_owned()),
                Some("W/\"sw-1\"".to_owned()),
            ),
            CoreResourceCommonResponse::new("BIOS".to_owned(), "System BIOS".to_owned(), None),
            CoreResourceDetailsResponse::SoftwareInventory {
                software_id: Some("BIOS-2026-1".to_owned()),
                version: Some("2.7.0".to_owned()),
                release_date: Some(release_date),
                status: Some(ResourceStatusResponse::new(
                    Some("Enabled".to_owned()),
                    Some("OK".to_owned()),
                    Some("OK".to_owned()),
                )),
            },
        ))
    }

    fn event_service_resource() -> CoreResourceResponse {
        CoreResourceResponse::new(
            CoreResourceSourceResponse::new(
                uuid!("01989abc-def0-7abc-8def-0123456789e6"),
                "/redfish/v1/EventService".to_owned(),
                Some("#EventService.v1_12_0.EventService".to_owned()),
                Some("W/\"event-service-1\"".to_owned()),
            ),
            CoreResourceCommonResponse::new(
                "EventService".to_owned(),
                "Event Service".to_owned(),
                None,
            ),
            CoreResourceDetailsResponse::EventService {
                service_enabled: Some(true),
                status: Some(ResourceStatusResponse::new(
                    Some("Enabled".to_owned()),
                    Some("OK".to_owned()),
                    Some("OK".to_owned()),
                )),
            },
        )
    }

    fn event_subscription_resource() -> CoreResourceResponse {
        CoreResourceResponse::new(
            CoreResourceSourceResponse::new(
                uuid!("01989abc-def0-7abc-8def-0123456789e7"),
                "/redfish/v1/EventService/Subscriptions/1".to_owned(),
                Some("#EventDestination.v1_16_0.EventDestination".to_owned()),
                Some("W/\"subscription-1\"".to_owned()),
            ),
            CoreResourceCommonResponse::new("1".to_owned(), "Subscription One".to_owned(), None),
            CoreResourceDetailsResponse::EventSubscription {
                destination: Some("https://subscriber.example.test/events".to_owned()),
                protocol: Some("Redfish".to_owned()),
                context: Some("Rack A".to_owned()),
                event_types: Some(vec!["Alert".to_owned(), "StatusChange".to_owned()]),
                status: Some(ResourceStatusResponse::new(
                    Some("Enabled".to_owned()),
                    Some("OK".to_owned()),
                    Some("OK".to_owned()),
                )),
            },
        )
    }

    fn telemetry_service_resource() -> CoreResourceResponse {
        CoreResourceResponse::new(
            CoreResourceSourceResponse::new(
                uuid!("01989abc-def0-7abc-8def-0123456789e8"),
                "/redfish/v1/TelemetryService".to_owned(),
                Some("#TelemetryService.v1_4_0.TelemetryService".to_owned()),
                None,
            ),
            CoreResourceCommonResponse::new(
                "TelemetryService".to_owned(),
                "Telemetry Service".to_owned(),
                None,
            ),
            CoreResourceDetailsResponse::TelemetryService {
                status: Some(ResourceStatusResponse::new(
                    Some("Enabled".to_owned()),
                    Some("OK".to_owned()),
                    Some("OK".to_owned()),
                )),
            },
        )
    }

    fn metric_definition_resource() -> CoreResourceResponse {
        CoreResourceResponse::new(
            CoreResourceSourceResponse::new(
                uuid!("01989abc-def0-7abc-8def-0123456789e9"),
                "/redfish/v1/TelemetryService/MetricDefinitions/1".to_owned(),
                Some("#MetricDefinition.v1_3_5.MetricDefinition".to_owned()),
                None,
            ),
            CoreResourceCommonResponse::new(
                "1".to_owned(),
                "Inlet Temperature Definition".to_owned(),
                None,
            ),
            CoreResourceDetailsResponse::MetricDefinition {
                units: Some("Cel".to_owned()),
                metric_type: Some("Numeric".to_owned()),
            },
        )
    }

    fn metric_report_resource() -> Result<CoreResourceResponse, &'static str> {
        Ok(CoreResourceResponse::new(
            CoreResourceSourceResponse::new(
                uuid!("01989abc-def0-7abc-8def-0123456789ea"),
                "/redfish/v1/TelemetryService/MetricReports/1".to_owned(),
                Some("#MetricReport.v1_5_2.MetricReport".to_owned()),
                Some("W/\"report-1\"".to_owned()),
            ),
            CoreResourceCommonResponse::new(
                "1".to_owned(),
                "Inlet Temperature Report".to_owned(),
                None,
            ),
            CoreResourceDetailsResponse::MetricReport {
                metric_values_count: Some(2),
                metric_values: Some(vec![
                    MetricValueResponse::new(
                        Some(
                            OffsetDateTime::from_unix_timestamp(1_785_925_200)
                                .map_err(|_| "fixture timestamp must convert")?,
                        ),
                        Some("31.5".to_owned()),
                    ),
                    MetricValueResponse::new(
                        Some(
                            OffsetDateTime::from_unix_timestamp(1_785_925_260)
                                .map_err(|_| "fixture timestamp must convert")?,
                        ),
                        None,
                    ),
                ]),
            },
        ))
    }

    fn task_service_resource() -> CoreResourceResponse {
        CoreResourceResponse::new(
            CoreResourceSourceResponse::new(
                uuid!("01989abc-def0-7abc-8def-0123456789eb"),
                "/redfish/v1/TaskService".to_owned(),
                Some("#TaskService.v1_3_0.TaskService".to_owned()),
                None,
            ),
            CoreResourceCommonResponse::new(
                "TaskService".to_owned(),
                "Task Service".to_owned(),
                None,
            ),
            CoreResourceDetailsResponse::TaskService {
                service_enabled: Some(true),
                completed_task_overwrite_policy: Some("Oldest".to_owned()),
                status: Some(ResourceStatusResponse::new(
                    Some("Enabled".to_owned()),
                    Some("OK".to_owned()),
                    Some("OK".to_owned()),
                )),
            },
        )
    }

    fn task_resource() -> Result<CoreResourceResponse, &'static str> {
        let start_time = OffsetDateTime::parse("2026-08-05T10:20:00Z", &Rfc3339)
            .map_err(|_| "test start time must parse")?;
        Ok(CoreResourceResponse::new(
            CoreResourceSourceResponse::new(
                uuid!("01989abc-def0-7abc-8def-0123456789ec"),
                "/redfish/v1/TaskService/Tasks/1".to_owned(),
                Some("#Task.v1_7_4.Task".to_owned()),
                Some("W/\"task-1\"".to_owned()),
            ),
            CoreResourceCommonResponse::new(
                "1".to_owned(),
                "Firmware Update Task".to_owned(),
                None,
            ),
            CoreResourceDetailsResponse::Task {
                task_state: Some("Running".to_owned()),
                task_status: Some("OK".to_owned()),
                percent_complete: Some(42),
                start_time: Some(start_time),
                end_time: None,
            },
        ))
    }

    fn ethernet_interface_resource() -> CoreResourceResponse {
        CoreResourceResponse::new(
            CoreResourceSourceResponse::new(
                uuid!("01989abc-def0-7abc-8def-0123456789d2"),
                "/redfish/v1/Managers/1/EthernetInterfaces/1".to_owned(),
                Some("#EthernetInterface.v1_12_4.EthernetInterface".to_owned()),
                Some("W/\"eth-1\"".to_owned()),
            ),
            CoreResourceCommonResponse::new(
                "1".to_owned(),
                "Ethernet Interface One".to_owned(),
                None,
            ),
            CoreResourceDetailsResponse::EthernetInterface {
                mac_address: Some("52:54:00:12:34:56".to_owned()),
                speed_mbps: Some(10000),
                interface_enabled: Some(true),
                status: Some(ResourceStatusResponse::new(
                    Some("Enabled".to_owned()),
                    Some("OK".to_owned()),
                    Some("OK".to_owned()),
                )),
            },
        )
    }

    #[test]
    fn core_resource_contract_rejects_unknown_and_ambiguous_states() {
        let extended_resource = json!({
            "source": {
                "resource_id": "01989abc-def0-7abc-8def-0123456789cd",
                "odata_id": "/redfish/v1/Systems/1",
                "odata_type": null,
                "etag": null
            },
            "common": { "id": "1", "name": "System", "description": null },
            "resource": {
                "resource_type": "system",
                "details": {
                    "system_type": null,
                    "manufacturer": null,
                    "model": null,
                    "part_number": null,
                    "serial_number": null,
                    "sku": null,
                    "host_name": null,
                    "bios_version": null,
                    "power_state": null,
                    "status": null,
                    "arbitrary": true
                }
            }
        });
        assert!(serde_json::from_value::<CoreResourceResponse>(extended_resource).is_err());
        assert!(
            serde_json::from_value::<EndpointResourceSnapshotResponse>(json!({
                "state": "awaiting_first_refresh",
                "details": { "resources": [] }
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<CoreResourceDetailsResponse>(json!({
                "resource_type": "unknown",
                "details": {}
            }))
            .is_err()
        );
    }

    #[test]
    fn capability_inventory_contract_serializes_observed_and_unobserved_entries()
    -> Result<(), Box<dyn Error>> {
        let observed_at = OffsetDateTime::parse("2026-08-05T10:12:13Z", &Rfc3339)?;
        let endpoint_id = uuid!("01989abc-def0-7abc-8def-0123456789e1");
        let response = EndpointCapabilityInventoryResponse::new(
            endpoint_id,
            vec![
                CapabilityEntryResponse::new(
                    "accounts".to_owned(),
                    "accounts".to_owned(),
                    CapabilityClassificationResponse::UserFacing,
                    UiLocationResponse::Accounts,
                    Some(CapabilityStateResponse::Supported),
                    Some(observed_at),
                ),
                CapabilityEntryResponse::new(
                    "session-service".to_owned(),
                    "session-service".to_owned(),
                    CapabilityClassificationResponse::Infrastructure,
                    UiLocationResponse::Infrastructure,
                    None,
                    None,
                ),
            ],
        );
        let encoded = serde_json::to_value(&response)?;
        let decoded: EndpointCapabilityInventoryResponse = serde_json::from_value(encoded.clone())?;

        assert_eq!(decoded, response);
        assert_eq!(decoded.endpoint_id(), endpoint_id);
        assert_eq!(decoded.entries()[0].capability(), "accounts");
        assert_eq!(decoded.entries()[0].upstream_feature(), "accounts");
        assert_eq!(
            decoded.entries()[0].classification(),
            CapabilityClassificationResponse::UserFacing
        );
        assert_eq!(
            decoded.entries()[0].ui_location(),
            UiLocationResponse::Accounts
        );
        assert_eq!(
            decoded.entries()[0].state(),
            Some(CapabilityStateResponse::Supported)
        );
        assert_eq!(decoded.entries()[0].observed_at(), Some(observed_at));
        assert_eq!(decoded.entries()[1].state(), None);
        assert_eq!(decoded.entries()[1].observed_at(), None);
        assert_eq!(
            encoded,
            json!({
                "endpoint_id": endpoint_id,
                "entries": [
                    {
                        "capability": "accounts",
                        "upstream_feature": "accounts",
                        "classification": "user_facing",
                        "ui_location": "accounts",
                        "state": "supported",
                        "observed_at": "2026-08-05T10:12:13Z"
                    },
                    {
                        "capability": "session-service",
                        "upstream_feature": "session-service",
                        "classification": "infrastructure",
                        "ui_location": "infrastructure",
                        "state": null,
                        "observed_at": null
                    }
                ]
            })
        );
        Ok(())
    }

    #[test]
    fn capability_inventory_contract_rejects_unknown_values_and_fields() {
        let observed = json!({
            "capability": "accounts",
            "upstream_feature": "accounts",
            "classification": "user_facing",
            "ui_location": "accounts",
            "state": "supported",
            "observed_at": "2026-08-05T10:12:13Z"
        });
        let unobserved = json!({
            "capability": "session-service",
            "upstream_feature": "session-service",
            "classification": "infrastructure",
            "ui_location": "infrastructure",
            "state": null,
            "observed_at": null
        });
        let envelope = json!({
            "endpoint_id": "01989abc-def0-7abc-8def-0123456789e1",
            "entries": [observed.clone(), unobserved.clone()]
        });

        assert!(serde_json::from_value::<EndpointCapabilityInventoryResponse>(envelope).is_ok());
        assert!(
            serde_json::from_value::<CapabilityEntryResponse>(json!({
                "capability": "accounts",
                "upstream_feature": "accounts",
                "classification": "untrusted",
                "ui_location": "accounts",
                "state": null,
                "observed_at": null
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<CapabilityEntryResponse>(json!({
                "capability": "accounts",
                "upstream_feature": "accounts",
                "classification": "user_facing",
                "ui_location": "hidden",
                "state": null,
                "observed_at": null
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<CapabilityEntryResponse>(json!({
                "capability": "accounts",
                "upstream_feature": "accounts",
                "classification": "user_facing",
                "ui_location": "accounts",
                "state": "permanently_broken",
                "observed_at": null
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<CapabilityEntryResponse>(json!({
                "capability": "accounts",
                "upstream_feature": "accounts",
                "classification": "user_facing",
                "ui_location": "accounts",
                "state": "supported",
                "observed_at": "2026-08-05T10:12:13Z",
                "reason": "extra"
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<EndpointCapabilityInventoryResponse>(json!({
                "endpoint_id": "not-a-uuid",
                "entries": [observed]
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<EndpointCapabilityInventoryResponse>(json!({
                "endpoint_id": "01989abc-def0-7abc-8def-0123456789e1",
                "entries": [unobserved],
                "next_page": null
            }))
            .is_err()
        );
    }

    #[test]
    fn trust_confirmation_contract_binds_policy_to_address() -> Result<(), Box<dyn Error>> {
        let request = ConfirmEndpointTrustRequest::new(
            "https://bmc.example.test/".to_owned(),
            EndpointTrustExpectationRequest::pinned_certificate(
                "11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00"
                    .to_owned(),
            ),
        );
        let trusted_at = OffsetDateTime::parse("2026-08-05T10:15:00Z", &Rfc3339)?;
        let confirmed = TrustedEndpointResponse::new(
            "https://bmc.example.test/".to_owned(),
            TlsTrustModeResponse::PinnedCertificate,
            trusted_at,
        );
        let rejected = TrustRejectedResponse::new(
            Some(
                "11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00"
                    .to_owned(),
            ),
            "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"
                .to_owned(),
        );

        assert_eq!(
            serde_json::to_value(&request)?,
            json!({
                "address": "https://bmc.example.test/",
                "trust": {
                    "mode": "pinned_certificate",
                    "fingerprint_sha256": "11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00"
                }
            })
        );
        assert_eq!(
            serde_json::to_value(&confirmed)?,
            json!({
                "address": "https://bmc.example.test/",
                "tls_trust_mode": "pinned_certificate",
                "trusted_at": "2026-08-05T10:15:00Z"
            })
        );
        assert_eq!(
            serde_json::to_value(&rejected)?,
            json!({
                "expected_fingerprint_sha256": "11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00",
                "observed_fingerprint_sha256": "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"
            })
        );
        assert_eq!(request.address(), "https://bmc.example.test/");
        assert_eq!(
            confirmed.tls_trust_mode(),
            TlsTrustModeResponse::PinnedCertificate
        );
        assert_eq!(confirmed.trusted_at(), trusted_at);
        assert_eq!(
            rejected.expected_fingerprint_sha256(),
            Some(
                "11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00"
            )
        );
        assert!(
            serde_json::from_value::<ConfirmEndpointTrustRequest>(json!({
                "address": "https://bmc.example.test/",
                "trust": { "mode": "system_ca" },
                "extra": true
            }))
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn csv_import_contract_returns_independent_row_results() -> Result<(), Box<dyn Error>> {
        let request = EndpointCsvImportRequest::new(
            "display_name,address,credential_id,tls_sha256\nRack A,https://bmc.example.test,01989abc-def0-7abc-8def-0123456789cf,\n"
                .to_owned(),
        );
        let endpoint_id = uuid!("01989abc-def0-7abc-8def-0123456789d5");
        let enrolled = EndpointCsvImportRowResponse::new(
            2,
            "https://bmc.example.test/".to_owned(),
            EndpointCsvImportRowStatusResponse::Enrolled,
            Some(endpoint_id),
            None,
        );
        let rejected = EndpointCsvImportRowResponse::new(
            3,
            "https://other.example.test/".to_owned(),
            EndpointCsvImportRowStatusResponse::TrustRejected,
            None,
            Some("observed TLS certificate AA:BB does not match expected Pin 11:22".to_owned()),
        );
        let response = EndpointCsvImportResponse::new(2, 1, 1, vec![enrolled, rejected]);

        assert_eq!(
            serde_json::to_value(&request)?,
            json!({ "csv": request.csv() })
        );
        assert_eq!(response.total_rows(), 2);
        assert_eq!(response.succeeded_count(), 1);
        assert_eq!(response.failed_count(), 1);
        assert_eq!(response.rows()[0].record_number(), 2);
        assert_eq!(response.rows()[0].endpoint_id(), Some(endpoint_id));
        assert_eq!(
            response.rows()[0].status(),
            EndpointCsvImportRowStatusResponse::Enrolled
        );
        assert_eq!(
            response.rows()[1].status(),
            EndpointCsvImportRowStatusResponse::TrustRejected
        );
        assert_eq!(response.rows()[1].endpoint_id(), None);
        assert!(response.rows()[1].message().is_some());
        assert_eq!(
            serde_json::from_value::<EndpointCsvImportResponse>(serde_json::to_value(&response)?)?,
            response
        );
        assert!(
            serde_json::from_value::<EndpointCsvImportRequest>(json!({ "csv": "", "file": "" }))
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn refresh_batch_contract_returns_independent_per_endpoint_results()
    -> Result<(), Box<dyn Error>> {
        let first = uuid!("01989abc-def0-7abc-8def-0123456789e1");
        let second = uuid!("01989abc-def0-7abc-8def-0123456789e2");
        let missing = uuid!("01989abc-def0-7abc-8def-0123456789e3");
        let request = RefreshEndpointsRequest::new(vec![first, second, missing]);
        let refreshed = EndpointRefreshResultResponse::new(
            first,
            EndpointRefreshStatusResponse::Refreshed,
            Some(9),
            Some(31),
            None,
        );
        let failed = EndpointRefreshResultResponse::new(
            second,
            EndpointRefreshStatusResponse::Failed,
            None,
            None,
            Some("resource read failed: connection refused".to_owned()),
        );
        let not_found = EndpointRefreshResultResponse::new(
            missing,
            EndpointRefreshStatusResponse::NotFound,
            None,
            None,
            None,
        );
        let response = BatchRefreshResponse::new(3, 1, 2, vec![refreshed, failed, not_found]);

        assert_eq!(
            serde_json::to_value(&request)?,
            json!({ "endpoint_ids": [first, second, missing] })
        );
        assert_eq!(
            serde_json::to_value(&response)?,
            json!({
                "total": 3,
                "succeeded_count": 1,
                "failed_count": 2,
                "results": [
                    {
                        "endpoint_id": first,
                        "status": "refreshed",
                        "generation": 9,
                        "snapshot_count": 31,
                        "message": null
                    },
                    {
                        "endpoint_id": second,
                        "status": "failed",
                        "generation": null,
                        "snapshot_count": null,
                        "message": "resource read failed: connection refused"
                    },
                    {
                        "endpoint_id": missing,
                        "status": "not_found",
                        "generation": null,
                        "snapshot_count": null,
                        "message": null
                    }
                ]
            })
        );
        assert_eq!(
            serde_json::from_value::<BatchRefreshResponse>(serde_json::to_value(&response)?)?,
            response
        );
        assert_eq!(response.total(), 3);
        assert_eq!(response.succeeded_count(), 1);
        assert_eq!(response.failed_count(), 2);
        assert_eq!(response.results()[0].endpoint_id(), first);
        assert_eq!(
            response.results()[0].status(),
            EndpointRefreshStatusResponse::Refreshed
        );
        assert_eq!(response.results()[0].generation(), Some(9));
        assert_eq!(response.results()[0].snapshot_count(), Some(31));
        assert_eq!(response.results()[0].message(), None);
        assert_eq!(
            response.results()[1].status(),
            EndpointRefreshStatusResponse::Failed
        );
        assert_eq!(
            response.results()[1].message(),
            Some("resource read failed: connection refused")
        );
        assert_eq!(
            response.results()[2].status(),
            EndpointRefreshStatusResponse::NotFound
        );
        assert!(
            serde_json::from_value::<RefreshEndpointsRequest>(json!({
                "endpoint_ids": [],
                "extra": true
            }))
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn audit_contract_is_secret_free_and_strict() -> Result<(), Box<dyn Error>> {
        let occurred_at = OffsetDateTime::parse("2026-08-05T10:16:00Z", &Rfc3339)?;
        let operation_id = uuid!("01989abc-def0-7abc-8def-0123456789d6");
        let event = AuditEventResponse::new(
            occurred_at,
            "local-operator".to_owned(),
            "enroll-endpoint".to_owned(),
            AuditTargetResponse::new(
                "endpoint-address".to_owned(),
                Some("https://bmc.example.test/".to_owned()),
            ),
            AuditOutcomeResponse::new(
                "started".to_owned(),
                None,
                None,
                None,
            ),
            1,
            operation_id,
            "local-operator enroll-endpoint started for endpoint-address https://bmc.example.test/ (sequence 1)"
                .to_owned(),
        );
        let response = AuditQueryResponse::new(vec![event]);

        assert_eq!(
            serde_json::to_value(&response)?,
            json!({
                "events": [{
                    "occurred_at": "2026-08-05T10:16:00Z",
                    "actor": "local-operator",
                    "action": "enroll-endpoint",
                    "target": {
                        "kind": "endpoint-address",
                        "identifier": "https://bmc.example.test/"
                    },
                    "outcome": {
                        "kind": "started",
                        "progress": null,
                        "failure": null,
                        "verification": null
                    },
                    "sequence": 1,
                    "operation_id": operation_id,
                    "message": "local-operator enroll-endpoint started for endpoint-address https://bmc.example.test/ (sequence 1)"
                }]
            })
        );
        assert_eq!(
            serde_json::from_value::<AuditQueryResponse>(serde_json::to_value(&response)?)?,
            response
        );
        let encoded = serde_json::to_string(&response)?;
        assert!(!encoded.contains("password"));
        assert!(!encoded.contains("secret"));
        assert!(
            serde_json::from_value::<AuditEventResponse>(json!({
                "occurred_at": "2026-08-05T10:16:00Z",
                "actor": "local-operator",
                "action": "enroll-endpoint",
                "target": { "kind": "product", "identifier": null },
                "outcome": { "kind": "started" },
                "sequence": 1,
                "operation_id": operation_id,
                "message": "started",
                "extra": true
            }))
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn operation_error_contract_carries_only_a_message() -> Result<(), Box<dyn Error>> {
        let error = ErrorResponse::new("selected credential was not found".to_owned());

        assert_eq!(
            serde_json::to_value(&error)?,
            json!({ "message": "selected credential was not found" })
        );
        assert_eq!(error.message(), "selected credential was not found");
        assert!(
            serde_json::from_value::<ErrorResponse>(json!({
                "message": "failed",
                "secret": "must not leak"
            }))
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn operation_state_and_source_vocabularies_are_exact() -> Result<(), Box<dyn Error>> {
        // The nine §13.2 phases with their exact console wire values; the
        // Web state filter accepts exactly this vocabulary.
        let states = [
            (OperationStateResponse::Queued, "queued"),
            (OperationStateResponse::Validating, "validating"),
            (OperationStateResponse::Running, "running"),
            (OperationStateResponse::WaitingRemote, "waiting_remote"),
            (OperationStateResponse::Verifying, "verifying"),
            (OperationStateResponse::Succeeded, "succeeded"),
            (OperationStateResponse::Failed, "failed"),
            (OperationStateResponse::Unknown, "unknown"),
            (OperationStateResponse::Cancelled, "cancelled"),
        ];
        for (state, wire) in states {
            assert_eq!(serde_json::to_value(state)?, json!(wire));
            assert_eq!(
                serde_json::from_value::<OperationStateResponse>(json!(wire))?,
                state
            );
        }
        // The domain persistence code is deliberately not a wire value here.
        assert!(serde_json::from_value::<OperationStateResponse>(json!("waiting-remote")).is_err());
        assert!(serde_json::from_value::<OperationStateResponse>(json!("done")).is_err());

        let sources = [
            (OperationSourceResponse::Standalone, "standalone"),
            (OperationSourceResponse::Site, "site"),
            (OperationSourceResponse::Center, "center"),
        ];
        for (source, wire) in sources {
            assert_eq!(serde_json::to_value(source)?, json!(wire));
            assert_eq!(
                serde_json::from_value::<OperationSourceResponse>(json!(wire))?,
                source
            );
        }
        assert!(serde_json::from_value::<OperationSourceResponse>(json!("cluster")).is_err());
        Ok(())
    }

    #[test]
    fn create_operation_contract_round_trips_the_typed_command() -> Result<(), Box<dyn Error>> {
        let endpoint_id = uuid!("01989abc-def0-7abc-8def-0123456789ab");
        let request = CreateOperationRequest::new(
            None,
            vec![endpoint_id],
            RedfishCommand::System(SystemCommand::Reset(ResetType::PowerCycle)),
        );

        assert_eq!(request.source(), None);
        assert_eq!(request.targets(), &[endpoint_id]);
        assert_eq!(
            serde_json::to_value(&request)?,
            json!({
                "source": null,
                "targets": [endpoint_id],
                "command": { "System": { "Reset": "PowerCycle" } }
            })
        );
        assert_eq!(
            serde_json::from_value::<CreateOperationRequest>(serde_json::to_value(&request)?)?,
            request
        );
        assert_eq!(
            serde_json::from_value::<CreateOperationRequest>(json!({
                "source": "center",
                "targets": [endpoint_id],
                "command": { "Boot": {
                    "SetBootSourceOverride": {
                        "source": "Pxe",
                        "enabled": "Once",
                        "mode": "UEFI"
                    }
                } }
            }))?
            .source(),
            Some("center")
        );
        // Unknown request fields and unknown command families are rejected.
        assert!(
            serde_json::from_value::<CreateOperationRequest>(json!({
                "source": "standalone",
                "targets": [endpoint_id],
                "command": { "System": { "Reset": "On" } },
                "remember": true
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<CreateOperationRequest>(json!({
                "source": "standalone",
                "targets": [endpoint_id],
                "command": { "Account": { "Create": {} } }
            }))
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn operation_response_contract_pins_the_wire_projection() -> Result<(), Box<dyn Error>> {
        let observed_at = OffsetDateTime::parse("2026-08-05T10:11:12Z", &Rfc3339)?;
        let operation_id = uuid!("01989abc-def0-7abc-8def-0123456789d1");
        let target_id = uuid!("01989abc-def0-7abc-8def-0123456789d2");
        let endpoint_id = uuid!("01989abc-def0-7abc-8def-0123456789d3");
        let response = OperationResponse::new(
            operation_id,
            OperationSourceResponse::Standalone,
            vec![OperationTargetResponse::new(target_id, endpoint_id)],
            RedfishCommand::System(SystemCommand::Reset(ResetType::PowerCycle)),
            OperationStateResponse::WaitingRemote,
            observed_at,
            observed_at,
        );

        assert_eq!(response.operation_id(), operation_id);
        assert_eq!(response.source(), OperationSourceResponse::Standalone);
        assert_eq!(
            response.targets(),
            &[OperationTargetResponse::new(target_id, endpoint_id)]
        );
        assert_eq!(
            response.command(),
            &RedfishCommand::System(SystemCommand::Reset(ResetType::PowerCycle))
        );
        assert_eq!(response.state(), OperationStateResponse::WaitingRemote);
        assert_eq!(response.created_at(), observed_at);
        assert_eq!(response.updated_at(), observed_at);
        assert_eq!(
            serde_json::to_value(&response)?,
            json!({
                "operation_id": operation_id,
                "source": "standalone",
                "targets": [
                    { "target_id": target_id, "endpoint_id": endpoint_id }
                ],
                "command": { "System": { "Reset": "PowerCycle" } },
                "state": "waiting_remote",
                "created_at": "2026-08-05T10:11:12Z",
                "updated_at": "2026-08-05T10:11:12Z"
            })
        );
        assert_eq!(
            serde_json::from_value::<OperationResponse>(serde_json::to_value(&response)?)?,
            response
        );
        assert!(
            serde_json::from_value::<OperationResponse>(json!({
                "operation_id": operation_id,
                "source": "standalone",
                "targets": [],
                "command": { "System": { "Reset": "On" } },
                "state": "waiting_remote",
                "created_at": "2026-08-05T10:11:12Z",
                "updated_at": "2026-08-05T10:11:12Z",
                "next_page": null
            }))
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn operation_list_envelope_round_trips() -> Result<(), Box<dyn Error>> {
        let observed_at = OffsetDateTime::parse("2026-08-05T10:11:12Z", &Rfc3339)?;
        let operation = OperationResponse::new(
            uuid!("01989abc-def0-7abc-8def-0123456789d4"),
            OperationSourceResponse::Site,
            Vec::new(),
            RedfishCommand::SecureBoot(SecureBootCommand::Enable),
            OperationStateResponse::Succeeded,
            observed_at,
            observed_at,
        );
        let list = OperationListResponse::new(vec![operation]);
        let encoded = serde_json::to_value(&list)?;

        assert_eq!(encoded["operations"][0]["state"], json!("succeeded"));
        assert_eq!(
            encoded["operations"][0]["command"],
            json!({ "SecureBoot": "Enable" })
        );
        assert_eq!(
            serde_json::from_value::<OperationListResponse>(encoded)?,
            list
        );
        assert_eq!(
            serde_json::from_value::<OperationListResponse>(json!({ "operations": [] }))?,
            OperationListResponse::new(Vec::new())
        );
        assert!(
            serde_json::from_value::<OperationListResponse>(json!({
                "operations": [],
                "total": 0
            }))
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn batch_operation_contract_pins_the_submission_acknowledgement() -> Result<(), Box<dyn Error>>
    {
        let observed_at = OffsetDateTime::parse("2026-08-05T10:11:12Z", &Rfc3339)?;
        let batch_id = uuid!("01989abc-def0-7abc-8def-0123456789e1");
        let first_endpoint = uuid!("01989abc-def0-7abc-8def-0123456789ab");
        let second_endpoint = uuid!("01989abc-def0-7abc-8def-0123456789ac");
        let first_child = uuid!("01989abc-def0-7abc-8def-0123456789e2");
        let second_child = uuid!("01989abc-def0-7abc-8def-0123456789e3");
        let response = BatchOperationResponse::new(
            batch_id,
            OperationSourceResponse::Site,
            RedfishCommand::System(SystemCommand::Reset(ResetType::PowerCycle)),
            vec![first_endpoint, second_endpoint],
            vec![first_child, second_child],
            observed_at,
        );

        assert_eq!(response.batch_id(), batch_id);
        assert_eq!(response.source(), OperationSourceResponse::Site);
        assert_eq!(
            response.command(),
            &RedfishCommand::System(SystemCommand::Reset(ResetType::PowerCycle))
        );
        assert_eq!(response.targets(), &[first_endpoint, second_endpoint]);
        assert_eq!(response.child_operation_ids(), &[first_child, second_child]);
        assert_eq!(response.created_at(), observed_at);
        assert_eq!(
            serde_json::to_value(&response)?,
            json!({
                "batch_id": batch_id,
                "source": "site",
                "command": { "System": { "Reset": "PowerCycle" } },
                "targets": [first_endpoint, second_endpoint],
                "child_operation_ids": [first_child, second_child],
                "created_at": "2026-08-05T10:11:12Z"
            })
        );
        assert_eq!(
            serde_json::from_value::<BatchOperationResponse>(serde_json::to_value(&response)?)?,
            response
        );
        // Unknown fields are rejected: the acknowledgement is a strict
        // projection, and the target/child pairing is the only link between
        // the endpoints and their operation records.
        assert!(
            serde_json::from_value::<BatchOperationResponse>(json!({
                "batch_id": batch_id,
                "source": "site",
                "command": { "System": { "Reset": "On" } },
                "targets": [first_endpoint],
                "child_operation_ids": [first_child],
                "created_at": "2026-08-05T10:11:12Z",
                "summary": { "total": 1 }
            }))
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn batch_summary_contract_pins_the_derived_verdict_and_buckets() -> Result<(), Box<dyn Error>> {
        let observed_at = OffsetDateTime::parse("2026-08-05T10:11:12Z", &Rfc3339)?;
        let batch_id = uuid!("01989abc-def0-7abc-8def-0123456789e4");
        let summary = BatchSummaryResponse::new(
            batch_id,
            OperationSourceResponse::Site,
            RedfishCommand::System(SystemCommand::Reset(ResetType::PowerCycle)),
            BatchOperationStateResponse::Failed,
            BatchOutcomeCountsResponse::new(2, 1, 0, 1, 0, 4),
            observed_at,
        );

        assert_eq!(summary.batch_id(), batch_id);
        assert_eq!(summary.source(), OperationSourceResponse::Site);
        assert_eq!(
            summary.command(),
            &RedfishCommand::System(SystemCommand::Reset(ResetType::PowerCycle))
        );
        assert_eq!(summary.state(), BatchOperationStateResponse::Failed);
        assert_eq!(summary.outcomes().succeeded(), 2);
        assert_eq!(summary.outcomes().failed(), 1);
        assert_eq!(summary.outcomes().unsupported(), 1);
        assert_eq!(summary.outcomes().total(), 4);
        assert_eq!(summary.created_at(), observed_at);
        // The state and the buckets serialize with their stable wire shapes:
        // snake_case state codes and the six bucket keys.
        assert_eq!(
            serde_json::to_value(&summary)?,
            json!({
                "batch_id": batch_id,
                "source": "site",
                "command": { "System": { "Reset": "PowerCycle" } },
                "state": "failed",
                "outcomes": {
                    "succeeded": 2,
                    "failed": 1,
                    "unknown": 0,
                    "unsupported": 1,
                    "cancelled": 0,
                    "total": 4
                },
                "created_at": "2026-08-05T10:11:12Z"
            })
        );
        assert_eq!(
            serde_json::from_value::<BatchSummaryResponse>(serde_json::to_value(&summary)?)?,
            summary
        );
        // Unknown fields are rejected, and an unknown batch state code is
        // refused at the wire: the console can never render a verdict this
        // build does not know.
        assert!(
            serde_json::from_value::<BatchSummaryResponse>(json!({
                "batch_id": batch_id,
                "source": "site",
                "command": { "System": { "Reset": "PowerCycle" } },
                "state": "failed",
                "outcomes": {
                    "succeeded": 2,
                    "failed": 1,
                    "unknown": 0,
                    "unsupported": 1,
                    "cancelled": 0,
                    "total": 4
                },
                "created_at": "2026-08-05T10:11:12Z",
                "extra": true
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<BatchSummaryResponse>(json!({
                "batch_id": batch_id,
                "source": "site",
                "command": { "System": { "Reset": "PowerCycle" } },
                "state": "finished",
                "outcomes": {
                    "succeeded": 2,
                    "failed": 1,
                    "unknown": 0,
                    "unsupported": 1,
                    "cancelled": 0,
                    "total": 4
                },
                "created_at": "2026-08-05T10:11:12Z"
            }))
            .is_err()
        );
        Ok(())
    }

    // The contract walk pins every summary field, both envelope shapes, and
    // two strict-deserialization refusals, so the line count is the coverage.
    #[allow(clippy::too_many_lines)]
    #[test]
    fn batch_list_and_detail_contracts_round_trip() -> Result<(), Box<dyn Error>> {
        let observed_at = OffsetDateTime::parse("2026-08-05T10:11:12Z", &Rfc3339)?;
        let batch_id = uuid!("01989abc-def0-7abc-8def-0123456789e5");
        let summary = BatchSummaryResponse::new(
            batch_id,
            OperationSourceResponse::Standalone,
            RedfishCommand::System(SystemCommand::Reset(ResetType::PowerCycle)),
            BatchOperationStateResponse::Running,
            BatchOutcomeCountsResponse::new(1, 0, 0, 0, 0, 2),
            observed_at,
        );
        let list = BatchListResponse::new(vec![summary.clone()]);
        assert_eq!(list.batches(), std::slice::from_ref(&summary));
        assert_eq!(
            serde_json::to_value(&list)?,
            json!({
                "batches": [{
                    "batch_id": batch_id,
                    "source": "standalone",
                    "command": { "System": { "Reset": "PowerCycle" } },
                    "state": "running",
                    "outcomes": {
                        "succeeded": 1,
                        "failed": 0,
                        "unknown": 0,
                        "unsupported": 0,
                        "cancelled": 0,
                        "total": 2
                    },
                    "created_at": "2026-08-05T10:11:12Z"
                }]
            })
        );
        assert_eq!(
            serde_json::from_value::<BatchListResponse>(serde_json::to_value(&list)?)?,
            list
        );
        assert!(
            serde_json::from_value::<BatchListResponse>(json!({
                "batches": [],
                "count": 0
            }))
            .is_err()
        );

        let detail = BatchDetailResponse::new(
            batch_id,
            OperationSourceResponse::Standalone,
            RedfishCommand::System(SystemCommand::Reset(ResetType::PowerCycle)),
            BatchOperationStateResponse::Running,
            BatchOutcomeCountsResponse::new(1, 0, 0, 0, 0, 2),
            observed_at,
            vec![
                OperationResponse::new(
                    uuid!("01989abc-def0-7abc-8def-0123456789e6"),
                    OperationSourceResponse::Standalone,
                    vec![OperationTargetResponse::new(
                        uuid!("01989abc-def0-7abc-8def-0123456789e7"),
                        uuid!("01989abc-def0-7abc-8def-0123456789e8"),
                    )],
                    RedfishCommand::System(SystemCommand::Reset(ResetType::PowerCycle)),
                    OperationStateResponse::Succeeded,
                    observed_at,
                    observed_at,
                ),
                OperationResponse::new(
                    uuid!("01989abc-def0-7abc-8def-0123456789e9"),
                    OperationSourceResponse::Standalone,
                    vec![OperationTargetResponse::new(
                        uuid!("01989abc-def0-7abc-8def-0123456789ea"),
                        uuid!("01989abc-def0-7abc-8def-0123456789eb"),
                    )],
                    RedfishCommand::System(SystemCommand::Reset(ResetType::PowerCycle)),
                    OperationStateResponse::Queued,
                    observed_at,
                    observed_at,
                ),
            ],
        );
        assert_eq!(detail.batch_id(), batch_id);
        assert_eq!(detail.children().len(), 2);
        assert_eq!(
            detail.children()[0].operation_id(),
            uuid!("01989abc-def0-7abc-8def-0123456789e6")
        );
        assert_eq!(detail.children()[1].state(), OperationStateResponse::Queued);
        // The detail is a strict projection of the summary fields plus the
        // children; an unknown field anywhere in the document is rejected.
        assert_eq!(
            serde_json::from_value::<BatchDetailResponse>(serde_json::to_value(&detail)?)?,
            detail
        );
        assert!(
            serde_json::from_value::<BatchDetailResponse>(json!({
                "batch_id": batch_id,
                "source": "standalone",
                "command": { "System": { "Reset": "PowerCycle" } },
                "state": "running",
                "outcomes": {
                    "succeeded": 1,
                    "failed": 0,
                    "unknown": 0,
                    "unsupported": 0,
                    "cancelled": 0,
                    "total": 2
                },
                "created_at": "2026-08-05T10:11:12Z",
                "children": [],
                "summary": {}
            }))
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn artifact_create_and_chunk_contracts_round_trip() -> Result<(), Box<dyn Error>> {
        let request = CreateArtifactRequest::new(
            "firmware.bin".to_owned(),
            6,
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08".to_owned(),
        );
        let chunk = AppendArtifactChunkRequest::new(0, "aGVsbG8=".to_owned());

        assert_eq!(request.name(), "firmware.bin");
        assert_eq!(request.size_bytes(), 6);
        assert_eq!(
            request.sha256(),
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        );
        assert_eq!(chunk.offset(), 0);
        assert_eq!(chunk.data(), "aGVsbG8=");
        assert_eq!(
            serde_json::to_value(&request)?,
            json!({
                "name": "firmware.bin",
                "size_bytes": 6,
                "sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
            })
        );
        assert_eq!(
            serde_json::from_value::<CreateArtifactRequest>(serde_json::to_value(&request)?)?,
            request
        );
        assert_eq!(
            serde_json::to_value(&chunk)?,
            json!({ "offset": 0, "data": "aGVsbG8=" })
        );
        assert!(
            serde_json::from_value::<AppendArtifactChunkRequest>(json!({
                "offset": 0,
                "data": "aGVsbG8=",
                "checksum": "ignored"
            }))
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn artifact_response_contract_pins_the_wire_projection() -> Result<(), Box<dyn Error>> {
        let created_at = OffsetDateTime::parse("2026-08-06T10:11:12Z", &Rfc3339)?;
        let updated_at = OffsetDateTime::parse("2026-08-06T10:12:13Z", &Rfc3339)?;
        let artifact_id = uuid!("01989abc-def0-7abc-8def-0123456789d5");
        let response = ArtifactResponse::new(
            artifact_id,
            "firmware.bin".to_owned(),
            6,
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08".to_owned(),
            ArtifactStateResponse::Uploading,
            2,
            created_at,
            updated_at,
        );
        let progress = ArtifactProgressResponse::new(artifact_id, 2, 6);

        assert_eq!(response.artifact_id(), artifact_id);
        assert_eq!(response.name(), "firmware.bin");
        assert_eq!(response.size_bytes(), 6);
        assert_eq!(response.state(), ArtifactStateResponse::Uploading);
        assert_eq!(response.uploaded_bytes(), 2);
        assert_eq!(response.created_at(), created_at);
        assert_eq!(response.updated_at(), updated_at);
        assert_eq!(
            serde_json::to_value(&response)?,
            json!({
                "artifact_id": artifact_id,
                "name": "firmware.bin",
                "size_bytes": 6,
                "sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
                "state": "uploading",
                "uploaded_bytes": 2,
                "created_at": "2026-08-06T10:11:12Z",
                "updated_at": "2026-08-06T10:12:13Z"
            })
        );
        assert_eq!(
            serde_json::from_value::<ArtifactResponse>(serde_json::to_value(&response)?)?,
            response
        );
        assert_eq!(
            serde_json::to_value(&progress)?,
            json!({
                "artifact_id": artifact_id,
                "uploaded_bytes": 2,
                "size_bytes": 6
            })
        );
        assert_eq!(
            serde_json::from_value::<ArtifactProgressResponse>(serde_json::to_value(&progress)?)?,
            progress
        );
        assert!(
            serde_json::from_value::<ArtifactResponse>(json!({
                "artifact_id": artifact_id,
                "name": "firmware.bin",
                "size_bytes": 6,
                "sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
                "state": "paused",
                "uploaded_bytes": 2,
                "created_at": "2026-08-06T10:11:12Z",
                "updated_at": "2026-08-06T10:12:13Z"
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<ArtifactResponse>(json!({
                "artifact_id": artifact_id,
                "name": "firmware.bin",
                "size_bytes": 6,
                "sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
                "state": "uploading",
                "uploaded_bytes": 2,
                "created_at": "2026-08-06T10:11:12Z",
                "updated_at": "2026-08-06T10:12:13Z",
                "location": "/tmp/firmware.bin"
            }))
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn artifact_states_and_list_envelope_round_trip() -> Result<(), Box<dyn Error>> {
        let created_at = OffsetDateTime::parse("2026-08-06T10:11:12Z", &Rfc3339)?;
        let states = [
            (ArtifactStateResponse::Uploading, "uploading"),
            (ArtifactStateResponse::Ready, "ready"),
            (ArtifactStateResponse::Failed, "failed"),
        ];
        for (state, wire) in states {
            assert_eq!(serde_json::to_value(state)?, json!(wire));
            assert_eq!(
                serde_json::from_value::<ArtifactStateResponse>(json!(wire))?,
                state
            );
        }
        assert!(serde_json::from_value::<ArtifactStateResponse>(json!("aborted")).is_err());

        let list = ArtifactListResponse::new(vec![ArtifactResponse::new(
            uuid!("01989abc-def0-7abc-8def-0123456789d6"),
            "firmware.bin".to_owned(),
            6,
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08".to_owned(),
            ArtifactStateResponse::Ready,
            6,
            created_at,
            created_at,
        )]);
        let encoded = serde_json::to_value(&list)?;

        assert_eq!(encoded["artifacts"][0]["state"], json!("ready"));
        assert_eq!(encoded["artifacts"][0]["uploaded_bytes"], json!(6));
        assert_eq!(
            serde_json::from_value::<ArtifactListResponse>(encoded)?,
            list
        );
        assert_eq!(
            serde_json::from_value::<ArtifactListResponse>(json!({ "artifacts": [] }))?,
            ArtifactListResponse::new(Vec::new())
        );
        assert!(
            serde_json::from_value::<ArtifactListResponse>(json!({
                "artifacts": [],
                "next_page": null
            }))
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn artifact_finalize_failure_contract_carries_reason() -> Result<(), Box<dyn Error>> {
        let created_at = OffsetDateTime::parse("2026-08-06T10:11:12Z", &Rfc3339)?;
        let artifact = ArtifactResponse::new(
            uuid!("01989abc-def0-7abc-8def-0123456789d7"),
            "firmware.bin".to_owned(),
            6,
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08".to_owned(),
            ArtifactStateResponse::Failed,
            6,
            created_at,
            created_at,
        );
        let failure = ArtifactFinalizeFailureResponse::new(
            artifact.clone(),
            "SHA-256 verification failed".to_owned(),
        );

        assert_eq!(failure.artifact(), &artifact);
        assert_eq!(failure.reason(), "SHA-256 verification failed");
        assert_eq!(
            serde_json::to_value(&failure)?,
            json!({
                "artifact": {
                    "artifact_id": "01989abc-def0-7abc-8def-0123456789d7",
                    "name": "firmware.bin",
                    "size_bytes": 6,
                    "sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
                    "state": "failed",
                    "uploaded_bytes": 6,
                    "created_at": "2026-08-06T10:11:12Z",
                    "updated_at": "2026-08-06T10:11:12Z"
                },
                "reason": "SHA-256 verification failed"
            })
        );
        assert_eq!(
            serde_json::from_value::<ArtifactFinalizeFailureResponse>(serde_json::to_value(
                &failure
            )?,)?,
            failure
        );
        Ok(())
    }

    #[test]
    fn event_contract_is_bmc_faithful_and_strict() -> Result<(), Box<dyn Error>> {
        let event_timestamp = OffsetDateTime::parse("2026-08-07T03:21:00Z", &Rfc3339)?;
        let observed_at = OffsetDateTime::parse("2026-08-07T03:21:05Z", &Rfc3339)?;
        let event = EventResponse::new(
            uuid!("0198c1ec-7e10-7f5e-8f2a-123456789001"),
            uuid!("0198c1ec-7e10-7f5e-8f2a-123456789002"),
            "Alert.1.0.PowerSupplyFailure".to_owned(),
            "critical".to_owned(),
            Some("Power supply 1 lost input".to_owned()),
            event_timestamp,
            observed_at,
        );
        let response = EventListResponse::new(vec![event]);

        assert_eq!(
            serde_json::to_value(&response)?,
            json!({
                "events": [{
                    "id": uuid!("0198c1ec-7e10-7f5e-8f2a-123456789001"),
                    "endpoint_id": uuid!("0198c1ec-7e10-7f5e-8f2a-123456789002"),
                    "message_id": "Alert.1.0.PowerSupplyFailure",
                    "severity": "critical",
                    "message": "Power supply 1 lost input",
                    "event_timestamp": "2026-08-07T03:21:00Z",
                    "observed_at": "2026-08-07T03:21:05Z"
                }]
            })
        );
        assert_eq!(
            serde_json::from_value::<EventListResponse>(serde_json::to_value(&response)?)?,
            response
        );
        let encoded = serde_json::to_string(&response)?;
        assert!(!encoded.contains("password"));
        assert!(!encoded.contains("secret"));
        assert!(
            serde_json::from_value::<EventResponse>(json!({
                "id": uuid!("0198c1ec-7e10-7f5e-8f2a-123456789001"),
                "endpoint_id": uuid!("0198c1ec-7e10-7f5e-8f2a-123456789002"),
                "message_id": "Alert.1.0.PowerSupplyFailure",
                "severity": "critical",
                "message": null,
                "event_timestamp": "2026-08-07T03:21:00Z",
                "observed_at": "2026-08-07T03:21:05Z",
                "extra": true
            }))
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn telemetry_series_contract_pins_the_current_value_wire_shape() -> Result<(), Box<dyn Error>> {
        let latest_observed_at = OffsetDateTime::parse("2026-08-07T03:21:00Z", &Rfc3339)?;
        let sampled = TelemetrySeriesResponse::new(
            uuid!("0198c1ec-7e10-7f5e-8f2a-123456789101"),
            uuid!("0198c1ec-7e10-7f5e-8f2a-123456789102"),
            "PowerMetrics/PowerConsumedWatts".to_owned(),
            1440,
            Some(421.5),
            Some(latest_observed_at),
        );
        // A series whose upsert preceded its first successful append has no
        // samples: both latest fields are absent together.
        let empty = TelemetrySeriesResponse::new(
            uuid!("0198c1ec-7e10-7f5e-8f2a-123456789103"),
            uuid!("0198c1ec-7e10-7f5e-8f2a-123456789102"),
            "ThermalMetrics/Temperature".to_owned(),
            0,
            None,
            None,
        );
        let response = TelemetrySeriesListResponse::new(vec![sampled, empty]);

        assert_eq!(
            serde_json::to_value(&response)?,
            json!({
                "series": [
                    {
                        "series_id": uuid!("0198c1ec-7e10-7f5e-8f2a-123456789101"),
                        "endpoint_id": uuid!("0198c1ec-7e10-7f5e-8f2a-123456789102"),
                        "series_key": "PowerMetrics/PowerConsumedWatts",
                        "sample_count": 1440,
                        "latest_value": 421.5,
                        "latest_observed_at": "2026-08-07T03:21:00Z"
                    },
                    {
                        "series_id": uuid!("0198c1ec-7e10-7f5e-8f2a-123456789103"),
                        "endpoint_id": uuid!("0198c1ec-7e10-7f5e-8f2a-123456789102"),
                        "series_key": "ThermalMetrics/Temperature",
                        "sample_count": 0,
                        "latest_value": null,
                        "latest_observed_at": null
                    }
                ]
            })
        );
        assert!(
            serde_json::from_value::<TelemetrySeriesListResponse>(serde_json::to_value(
                &response
            )?)? == response,
            "the series contract must round-trip"
        );
        let encoded = serde_json::to_string(&response)?;
        assert!(!encoded.contains("password"));
        assert!(!encoded.contains("secret"));
        assert!(
            serde_json::from_value::<TelemetrySeriesResponse>(json!({
                "series_id": uuid!("0198c1ec-7e10-7f5e-8f2a-123456789101"),
                "endpoint_id": uuid!("0198c1ec-7e10-7f5e-8f2a-123456789102"),
                "series_key": "PowerMetrics/PowerConsumedWatts",
                "sample_count": 1440,
                "latest_value": null,
                "latest_observed_at": null,
                "extra": true
            }))
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn telemetry_sample_contract_pins_the_two_clock_wire_shape() -> Result<(), Box<dyn Error>> {
        let observed_at = OffsetDateTime::parse("2026-08-07T03:21:00Z", &Rfc3339)?;
        let bmc_reported = OffsetDateTime::parse("2026-08-07T03:20:55Z", &Rfc3339)?;
        let sample = TelemetrySampleResponse::new(
            uuid!("0198c1ec-7e10-7f5e-8f2a-123456789101"),
            observed_at,
            Some(bmc_reported),
            32.5,
        );
        // The BMC clock is optional display metadata: a reading without one
        // serializes the timestamp as null.
        let without_bmc = TelemetrySampleResponse::new(
            uuid!("0198c1ec-7e10-7f5e-8f2a-123456789101"),
            observed_at,
            None,
            33.0,
        );
        let response = TelemetrySampleListResponse::new(vec![sample, without_bmc]);

        assert_eq!(
            serde_json::to_value(&response)?,
            json!({
                "samples": [
                    {
                        "series_id": uuid!("0198c1ec-7e10-7f5e-8f2a-123456789101"),
                        "observed_at": "2026-08-07T03:21:00Z",
                        "bmc_timestamp": "2026-08-07T03:20:55Z",
                        "value": 32.5
                    },
                    {
                        "series_id": uuid!("0198c1ec-7e10-7f5e-8f2a-123456789101"),
                        "observed_at": "2026-08-07T03:21:00Z",
                        "bmc_timestamp": null,
                        "value": 33.0
                    }
                ]
            })
        );
        assert!(
            serde_json::from_value::<TelemetrySampleListResponse>(serde_json::to_value(
                &response
            )?)? == response,
            "the sample contract must round-trip"
        );
        let encoded = serde_json::to_string(&response)?;
        assert!(!encoded.contains("password"));
        assert!(!encoded.contains("secret"));
        assert!(
            serde_json::from_value::<TelemetrySampleResponse>(json!({
                "series_id": uuid!("0198c1ec-7e10-7f5e-8f2a-123456789101"),
                "observed_at": "2026-08-07T03:21:00Z",
                "bmc_timestamp": null,
                "value": 32.5,
                "extra": true
            }))
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn group_contract_pins_name_members_and_timestamps() -> Result<(), Box<dyn Error>> {
        let created_at = OffsetDateTime::parse("2026-08-07T04:00:01Z", &Rfc3339)?;
        let updated_at = OffsetDateTime::parse("2026-08-07T04:00:02Z", &Rfc3339)?;
        let group_id = uuid!("0198c1ec-7e10-7f5e-8f2a-123456789201");
        let first_member = uuid!("0198c1ec-7e10-7f5e-8f2a-123456789202");
        let second_member = uuid!("0198c1ec-7e10-7f5e-8f2a-123456789203");
        let response = GroupResponse::new(
            group_id,
            "Rack A".to_owned(),
            vec![first_member, second_member],
            created_at,
            updated_at,
        );
        let encoded = serde_json::to_value(&response)?;

        assert_eq!(response.group_id(), group_id);
        assert_eq!(response.name(), "Rack A");
        assert_eq!(
            response.member_endpoint_ids(),
            &[first_member, second_member]
        );
        assert_eq!(response.created_at(), created_at);
        assert_eq!(response.updated_at(), updated_at);
        assert_eq!(
            encoded,
            json!({
                "group_id": group_id,
                "name": "Rack A",
                "member_endpoint_ids": [first_member, second_member],
                "created_at": "2026-08-07T04:00:01Z",
                "updated_at": "2026-08-07T04:00:02Z"
            })
        );
        assert_eq!(
            serde_json::from_value::<GroupResponse>(encoded)?,
            response,
            "the group contract must round-trip"
        );
        assert!(
            serde_json::from_value::<GroupResponse>(json!({
                "group_id": group_id,
                "name": "Rack A",
                "member_endpoint_ids": [],
                "created_at": "2026-08-07T04:00:01Z",
                "updated_at": "2026-08-07T04:00:02Z",
                "owner": "must not exist"
            }))
            .is_err(),
            "unknown group fields must be rejected"
        );
        Ok(())
    }

    #[test]
    fn group_request_and_list_envelope_contracts_are_strict() -> Result<(), Box<dyn Error>> {
        let request = CreateGroupRequest::new("Rack A".to_owned());
        assert_eq!(request.name(), "Rack A");
        assert_eq!(serde_json::to_value(&request)?, json!({ "name": "Rack A" }));
        assert_eq!(
            serde_json::from_value::<CreateGroupRequest>(serde_json::to_value(&request)?)?,
            request
        );
        assert!(
            serde_json::from_value::<CreateGroupRequest>(
                json!({ "name": "Rack A", "color": "#f00" })
            )
            .is_err(),
            "unknown group creation fields must be rejected"
        );
        assert!(
            serde_json::from_value::<CreateGroupRequest>(json!({ "rename": "Rack A" })).is_err(),
            "a group creation request without the name field must be rejected"
        );

        let group = GroupResponse::new(
            uuid!("0198c1ec-7e10-7f5e-8f2a-123456789204"),
            "Rack A".to_owned(),
            Vec::new(),
            OffsetDateTime::parse("2026-08-07T04:00:03Z", &Rfc3339)?,
            OffsetDateTime::parse("2026-08-07T04:00:03Z", &Rfc3339)?,
        );
        let list = GroupListResponse::new(vec![group.clone()]);
        assert_eq!(list.groups(), &[group]);
        assert_eq!(
            serde_json::to_value(list)?,
            json!({ "groups": [{
                "group_id": "0198c1ec-7e10-7f5e-8f2a-123456789204",
                "name": "Rack A",
                "member_endpoint_ids": [],
                "created_at": "2026-08-07T04:00:03Z",
                "updated_at": "2026-08-07T04:00:03Z"
            }] })
        );
        Ok(())
    }

    #[test]
    fn tag_contract_binds_name_to_endpoint_and_stays_strict() -> Result<(), Box<dyn Error>> {
        let endpoint_id = uuid!("0198c1ec-7e10-7f5e-8f2a-123456789301");
        let tag_id = uuid!("0198c1ec-7e10-7f5e-8f2a-123456789302");
        let request = AssignTagRequest::new(endpoint_id, "production".to_owned());

        assert_eq!(request.endpoint_id(), endpoint_id);
        assert_eq!(request.tag_name(), "production");
        assert_eq!(
            serde_json::to_value(&request)?,
            json!({ "endpoint_id": endpoint_id, "tag_name": "production" })
        );
        assert_eq!(
            serde_json::from_value::<AssignTagRequest>(serde_json::to_value(&request)?)?,
            request
        );
        assert!(
            serde_json::from_value::<AssignTagRequest>(json!({
                "endpoint_id": endpoint_id,
                "tag_name": "production",
                "color": "#0f0"
            }))
            .is_err(),
            "unknown tag assignment fields must be rejected"
        );

        let response = TagResponse::new(tag_id, endpoint_id, "production".to_owned());
        let encoded = serde_json::to_value(&response)?;
        assert_eq!(response.tag_id(), tag_id);
        assert_eq!(response.endpoint_id(), endpoint_id);
        assert_eq!(response.name(), "production");
        assert_eq!(
            encoded,
            json!({
                "tag_id": tag_id,
                "endpoint_id": endpoint_id,
                "name": "production"
            })
        );
        assert_eq!(
            serde_json::from_value::<TagResponse>(encoded)?,
            response,
            "the tag contract must round-trip"
        );
        assert!(
            serde_json::from_value::<TagResponse>(json!({
                "tag_id": tag_id,
                "endpoint_id": endpoint_id,
                "name": "production",
                "owner": "must not exist"
            }))
            .is_err(),
            "unknown tag fields must be rejected"
        );

        let list = TagListResponse::new(vec![response]);
        assert_eq!(list.tags().len(), 1);
        assert_eq!(
            serde_json::from_value::<TagListResponse>(serde_json::to_value(list)?)?,
            TagListResponse::new(vec![TagResponse::new(
                tag_id,
                endpoint_id,
                "production".to_owned(),
            )])
        );
        Ok(())
    }

    #[test]
    fn authentication_contract_is_secret_safe_and_strict() -> Result<(), Box<dyn Error>> {
        // The sign-in request carries the wrapped password and the optional
        // TOTP code; unknown fields are refused.
        let request = LoginRequest::new(
            "admin".to_owned(),
            "correct horse battery staple".to_owned().into(),
            Some("123456".to_owned()),
        );
        let request_json = serde_json::to_value(&request)?;
        assert_eq!(request.username(), "admin");
        assert_eq!(request.totp_code(), Some("123456"));
        assert_eq!(
            request_json,
            json!({
                "username": "admin",
                "password": "correct horse battery staple",
                "totp_code": "123456"
            })
        );
        assert_eq!(
            serde_json::to_value(serde_json::from_value::<LoginRequest>(request_json)?)?,
            json!({
                "username": "admin",
                "password": "correct horse battery staple",
                "totp_code": "123456"
            })
        );
        assert!(!format!("{request:?}").contains("correct horse battery staple"));
        assert!(
            serde_json::from_value::<LoginRequest>(json!({
                "username": "admin",
                "password": "correct horse battery staple",
                "totp_code": "123456",
                "remember_me": true
            }))
            .is_err(),
            "unknown login fields must be rejected"
        );

        // The login response carries only the CSRF token — never the session
        // token, which lives in the response cookie.
        let response = LoginResponse::new("csrf-value".to_owned());
        assert_eq!(
            serde_json::to_value(&response)?,
            json!({ "csrf_token": "csrf-value" })
        );
        assert_eq!(
            serde_json::from_value::<LoginResponse>(serde_json::to_value(&response)?)?,
            response
        );
        assert!(
            serde_json::from_value::<LoginResponse>(json!({ "session_token": "x" })).is_err(),
            "a session token must never appear in the body"
        );

        // The logout request is an empty, strict body.
        assert_eq!(serde_json::to_value(&LogoutRequest {})?, json!({}));
        assert!(serde_json::from_value::<LogoutRequest>(json!({})).is_ok());
        assert!(
            serde_json::from_value::<LogoutRequest>(json!({ "reason": "bye" })).is_err(),
            "unknown logout fields must be rejected"
        );
        Ok(())
    }

    #[test]
    fn bootstrap_contract_keeps_the_totp_pair_optional_but_paired() -> Result<(), Box<dyn Error>> {
        let plain = BootstrapCompleteRequest::new(
            "ABCD2345EFGH6789JKLM".to_owned(),
            "first product password".to_owned().into(),
            None,
            None,
        );
        assert_eq!(plain.code(), "ABCD2345EFGH6789JKLM");
        assert!(plain.has_complete_totp_pair());
        assert_eq!(
            serde_json::to_value(serde_json::from_value::<BootstrapCompleteRequest>(
                serde_json::to_value(&plain)?
            )?)?,
            serde_json::to_value(&plain)?
        );
        assert!(!format!("{plain:?}").contains("ABCD2345EFGH6789JKLM"));

        // The optional TOTP pair travels together.
        let paired = BootstrapCompleteRequest::new(
            "ABCD2345EFGH6789JKLM".to_owned(),
            "first product password".to_owned().into(),
            Some("JBSWY3DPEHPK3PXP".to_owned()),
            Some("123456".to_owned()),
        );
        assert!(paired.has_complete_totp_pair());
        assert_eq!(paired.totp_secret(), Some("JBSWY3DPEHPK3PXP"));
        assert_eq!(
            serde_json::to_value(serde_json::from_value::<BootstrapCompleteRequest>(
                serde_json::to_value(&paired)?
            )?)?,
            serde_json::to_value(&paired)?
        );

        // A half-present TOTP pair deserializes but reports the incomplete
        // shape, which the claim boundary refuses before any state changes.
        let secret_only = serde_json::from_value::<BootstrapCompleteRequest>(json!({
            "code": "ABCD2345EFGH6789JKLM",
            "password": "first product password",
            "totp_secret": "JBSWY3DPEHPK3PXP"
        }))?;
        assert!(
            !secret_only.has_complete_totp_pair(),
            "a secret without its activation code is an incomplete pair"
        );
        let code_only = serde_json::from_value::<BootstrapCompleteRequest>(json!({
            "code": "ABCD2345EFGH6789JKLM",
            "password": "first product password",
            "totp_code": "123456"
        }))?;
        assert!(
            !code_only.has_complete_totp_pair(),
            "a code without its secret is an incomplete pair"
        );
        assert!(
            serde_json::from_value::<BootstrapCompleteRequest>(json!({
                "code": "ABCD2345EFGH6789JKLM",
                "password": "first product password",
                "totp_secret": "JBSWY3DPEHPK3PXP",
                "totp_code": "123456",
                "remember_me": true
            }))
            .is_err(),
            "unknown bootstrap fields must be rejected"
        );
        Ok(())
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn me_and_admin_contracts_round_trip_with_strict_shapes() -> Result<(), Box<dyn Error>> {
        // The me response carries the authenticated flag, the bootstrap
        // gate, and the optional principal summary.
        let principal = PrincipalSummaryResponse::new(
            "principal-uuid".to_owned(),
            "admin".to_owned(),
            PrincipalStateResponse::Enabled,
            Some(RoleResponse::Administrator),
        );
        let me = MeResponse::new(true, false, Some(principal));
        assert!(me.authenticated());
        assert!(!me.bootstrap_pending());
        assert_eq!(
            me.principal().map(PrincipalSummaryResponse::role),
            Some(Some(RoleResponse::Administrator))
        );
        assert_eq!(
            serde_json::to_value(&me)?,
            json!({
                "authenticated": true,
                "bootstrap_pending": false,
                "principal": {
                    "id": "principal-uuid",
                    "name": "admin",
                    "state": "enabled",
                    "role": "administrator"
                }
            })
        );
        assert_eq!(
            serde_json::from_value::<MeResponse>(serde_json::to_value(&me)?)?,
            me
        );
        assert!(
            serde_json::from_value::<MeResponse>(json!({
                "authenticated": true,
                "bootstrap_pending": false,
                "principal": null,
                "extra": true
            }))
            .is_err(),
            "unknown me fields must be rejected"
        );

        // The session administration rows carry the identity and the
        // lifecycle times, marking the presenting session.
        let session = SessionSummaryResponse::new(
            "session-uuid".to_owned(),
            "principal-uuid".to_owned(),
            "admin".to_owned(),
            OffsetDateTime::parse("2026-08-06T08:00:00Z", &Rfc3339)?,
            OffsetDateTime::parse("2026-08-06T09:00:00Z", &Rfc3339)?,
            OffsetDateTime::parse("2026-08-06T16:00:00Z", &Rfc3339)?,
            None,
            true,
        );
        let sessions = SessionAdminResponse::new(vec![session]);
        assert_eq!(sessions.sessions().len(), 1);
        assert!(sessions.sessions()[0].is_current());
        assert_eq!(
            serde_json::from_value::<SessionAdminResponse>(serde_json::to_value(&sessions)?)?,
            sessions
        );
        assert!(
            serde_json::from_value::<SessionAdminResponse>(json!({
                "sessions": [{
                    "session_id": "session-uuid",
                    "principal_id": "principal-uuid",
                    "principal_name": "admin",
                    "created_at": "2026-08-06T08:00:00Z",
                    "last_used_at": "2026-08-06T09:00:00Z",
                    "expires_at": "2026-08-06T16:00:00Z",
                    "revoked_at": null,
                    "current": true,
                    "device": "must not exist"
                }]
            }))
            .is_err(),
            "unknown session fields must be rejected"
        );

        // The user administration rows carry the role and state codes.
        let user = UserSummaryResponse::new(
            "principal-uuid".to_owned(),
            "operator".to_owned(),
            PrincipalStateResponse::Enabled,
            Some(RoleResponse::Operator),
            OffsetDateTime::parse("2026-08-06T08:00:00Z", &Rfc3339)?,
        );
        let users = UserAdminResponse::new(vec![user]);
        assert_eq!(users.users().len(), 1);
        assert_eq!(
            serde_json::from_value::<UserAdminResponse>(serde_json::to_value(&users)?)?,
            users
        );
        assert!(
            serde_json::from_value::<UserAdminResponse>(json!({
                "users": [{
                    "id": "principal-uuid",
                    "name": "operator",
                    "state": "enabled",
                    "role": "operator",
                    "created_at": "2026-08-06T08:00:00Z",
                    "badge": "must not exist"
                }]
            }))
            .is_err(),
            "unknown user fields must be rejected"
        );

        // The administration write requests are strict and typed.
        let create = CreateUserRequest::new("viewer".to_owned(), RoleResponse::Viewer);
        assert_eq!(
            serde_json::to_value(&create)?,
            json!({ "name": "viewer", "role": "viewer" })
        );
        assert_eq!(
            serde_json::from_value::<CreateUserRequest>(serde_json::to_value(&create)?)?,
            create
        );
        assert!(
            serde_json::from_value::<CreateUserRequest>(json!({ "name": "viewer" })).is_err(),
            "a role is required to create a user"
        );
        let state = SetPrincipalStateRequest::new(PrincipalStateResponse::Disabled);
        assert_eq!(
            serde_json::to_value(&state)?,
            json!({ "state": "disabled" })
        );
        assert_eq!(
            serde_json::from_value::<SetPrincipalStateRequest>(serde_json::to_value(&state)?)?,
            state
        );
        assert!(
            serde_json::from_value::<SetPrincipalStateRequest>(json!({ "state": "suspended" }))
                .is_err(),
            "an unknown principal state must be rejected"
        );
        let role = AssignRoleRequest::new(RoleResponse::Administrator);
        assert_eq!(
            serde_json::to_value(&role)?,
            json!({ "role": "administrator" })
        );
        assert_eq!(
            serde_json::from_value::<AssignRoleRequest>(serde_json::to_value(&role)?)?,
            role
        );
        let revoke = RevokeSessionRequest::new(uuid::uuid!("3b3a6f2e-8c9a-4b1e-9d2f-5a6b7c8d9e0f"));
        assert_eq!(
            serde_json::to_value(&revoke)?,
            json!({ "session_id": "3b3a6f2e-8c9a-4b1e-9d2f-5a6b7c8d9e0f" })
        );
        assert_eq!(
            serde_json::from_value::<RevokeSessionRequest>(serde_json::to_value(&revoke)?)?,
            revoke
        );
        assert!(
            serde_json::from_value::<RevokeSessionRequest>(json!({
                "session_id": "not-a-uuid"
            }))
            .is_err(),
            "an invalid session id must be rejected"
        );
        Ok(())
    }

    #[test]
    fn center_site_view_contract_carries_binding_online_and_refresh_facts()
    -> Result<(), Box<dyn Error>> {
        let site_id = uuid!("01989abc-def0-7abc-8def-0123456789ce");
        let last_refresh_at = OffsetDateTime::parse("2026-08-05T10:11:12Z", &Rfc3339)?;
        let response = CenterSiteResponse::new(
            site_id,
            "Site One".to_owned(),
            Some(CenterBindingStateResponse::Bound),
            true,
            3,
            Some(last_refresh_at),
        );
        let list = CenterSitesResponse::new(vec![response.clone()]);
        let encoded = serde_json::to_value(&list)?;

        assert_eq!(
            encoded,
            json!({
                "sites": [
                    {
                        "site_id": site_id,
                        "display_name": "Site One",
                        "binding": "bound",
                        "online": true,
                        "endpoint_count": 3,
                        "last_refresh_at": "2026-08-05T10:11:12Z"
                    }
                ]
            })
        );
        assert_eq!(
            serde_json::from_value::<CenterSitesResponse>(encoded)?,
            list
        );
        assert_eq!(
            list.sites()[0].binding(),
            Some(CenterBindingStateResponse::Bound)
        );
        assert!(list.sites()[0].online());
        assert_eq!(list.sites()[0].endpoint_count(), 3);

        // A site without a binding serializes the absent facts as null.
        let unbound = CenterSiteResponse::new(site_id, "Site Two".to_owned(), None, false, 0, None);
        assert_eq!(
            serde_json::to_value(&unbound)?,
            json!({
                "site_id": site_id,
                "display_name": "Site Two",
                "binding": null,
                "online": false,
                "endpoint_count": 0,
                "last_refresh_at": null
            })
        );
        // The strict contract refuses unknown fields.
        assert!(
            serde_json::from_value::<CenterSiteResponse>(json!({
                "site_id": site_id,
                "display_name": "Site One",
                "binding": "bound",
                "online": true,
                "endpoint_count": 3,
                "secret": "must-not-travel"
            }))
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn the_binding_contract_shows_the_code_exactly_once() -> Result<(), Box<dyn Error>> {
        let site_id = uuid!("01989abc-def0-7abc-8def-0123456789ce");
        let binding_id = uuid!("11989abc-def0-7abc-8def-0123456789ce");
        let now = OffsetDateTime::parse("2026-08-05T10:11:12Z", &Rfc3339)?;

        // The registration request carries the display name and center URL.
        let request = CenterBindingRegisterRequest::new(
            "Site One".to_owned(),
            "https://center.example:8443".to_owned(),
        );
        assert_eq!(
            serde_json::to_value(&request)?,
            json!({
                "display_name": "Site One",
                "center_url": "https://center.example:8443"
            })
        );
        assert_eq!(
            serde_json::from_value::<CenterBindingRegisterRequest>(serde_json::to_value(
                &request
            )?)?,
            request
        );

        // The acknowledgement shows the raw code once.
        let registered = CenterBindingRegisterResponse::new(
            site_id,
            binding_id,
            "23456789ABCDEFGHJKLM".to_owned(),
            now,
        );
        assert_eq!(
            serde_json::to_value(&registered)?,
            json!({
                "site_id": site_id,
                "binding_id": binding_id,
                "code": "23456789ABCDEFGHJKLM",
                "expires_at": "2026-08-05T10:11:12Z"
            })
        );
        assert_eq!(
            serde_json::from_value::<CenterBindingRegisterResponse>(serde_json::to_value(
                &registered
            )?)?,
            registered
        );

        // The binding record exposes state and timestamps only — never the
        // code and not even its hash.
        let binding = CenterBindingResponse::new(
            binding_id,
            site_id,
            CenterBindingStateResponse::Pending,
            "https://center.example:8443".to_owned(),
            now,
            Some(now),
            None,
        );
        let binding_json = serde_json::to_value(&binding)?;
        assert_eq!(
            binding_json,
            json!({
                "binding_id": binding_id,
                "site_id": site_id,
                "state": "pending",
                "center_url": "https://center.example:8443",
                "created_at": "2026-08-05T10:11:12Z",
                "expires_at": "2026-08-05T10:11:12Z",
                "bound_at": null
            })
        );
        assert!(
            !serde_json::to_string(&binding)?.contains("23456789ABCDEFGHJKLM"),
            "the binding view must not carry the one-time code"
        );
        assert_eq!(
            serde_json::from_value::<CenterBindingResponse>(binding_json)?,
            binding
        );

        // The revoke request names the site.
        let revoke = CenterBindingRevokeRequest::new(site_id);
        assert_eq!(
            serde_json::to_value(&revoke)?,
            json!({ "site_id": site_id })
        );
        assert_eq!(
            serde_json::from_value::<CenterBindingRevokeRequest>(serde_json::to_value(&revoke)?)?,
            revoke
        );
        Ok(())
    }

    #[test]
    fn the_endpoint_view_projects_the_site_reported_summary() -> Result<(), Box<dyn Error>> {
        let site_id = uuid!("01989abc-def0-7abc-8def-0123456789ce");
        let endpoint_id = uuid!("21989abc-def0-7abc-8def-0123456789ce");
        let view = CenterEndpointViewResponse::new(
            Some(site_id),
            endpoint_id,
            "Rack A BMC".to_owned(),
            "https://192.0.2.10/".to_owned(),
            "ok".to_owned(),
            7,
        );
        let list = CenterEndpointViewListResponse::new(vec![view.clone()]);
        let encoded = serde_json::to_value(&list)?;

        assert_eq!(
            encoded,
            json!({
                "endpoints": [
                    {
                        "site_id": site_id,
                        "endpoint_id": endpoint_id,
                        "display_name": "Rack A BMC",
                        "address": "https://192.0.2.10/",
                        "health": "ok",
                        "refresh_generation": 7
                    }
                ]
            })
        );
        assert_eq!(
            serde_json::from_value::<CenterEndpointViewListResponse>(encoded)?,
            list
        );
        assert_eq!(list.endpoints()[0].site_id(), Some(site_id));
        assert_eq!(list.endpoints()[0].health(), "ok");
        assert_eq!(list.endpoints()[0].refresh_generation(), 7);
        assert!(
            serde_json::from_value::<CenterEndpointViewResponse>(json!({
                "site_id": site_id,
                "endpoint_id": endpoint_id,
                "display_name": "Rack A BMC",
                "address": "https://192.0.2.10/",
                "health": "ok",
                "refresh_generation": 7,
                "credential_id": "must-not-travel"
            }))
            .is_err(),
            "the §15.5 view must not accept credential material"
        );
        Ok(())
    }

    #[test]
    fn the_operation_submit_contract_carries_exactly_the_s15_6_set() -> Result<(), Box<dyn Error>> {
        let site_id = uuid!("01989abc-def0-7abc-8def-0123456789ce");
        let endpoint_id = uuid!("31989abc-def0-7abc-8def-0123456789ce");
        let command = RedfishCommand::System(SystemCommand::Reset(ResetType::GracefulShutdown));
        let request = CenterOperationSubmitRequest::new(
            site_id,
            endpoint_id,
            "/redfish/v1/Systems/1".to_owned(),
            command.clone(),
        );
        let encoded = serde_json::to_value(&request)?;

        // The wire shape is exactly the §15.6 set: the typed command, the
        // target, and the site — and nothing else. No URL, no HTTP method,
        // no headers, no JSON body, no script.
        assert_eq!(request.site_id(), site_id);
        assert_eq!(request.endpoint_id(), endpoint_id);
        assert_eq!(request.target(), "/redfish/v1/Systems/1");
        assert_eq!(request.command(), &command);
        let shape = encoded
            .as_object()
            .ok_or("the request must serialize as an object")?;
        assert_eq!(
            shape
                .keys()
                .map(String::as_str)
                .collect::<std::collections::BTreeSet<_>>(),
            std::collections::BTreeSet::from(["site_id", "endpoint_id", "target", "command",])
        );
        assert!(
            !serde_json::to_string(&request)?.contains("url")
                && !serde_json::to_string(&request)?.contains("method")
                && !serde_json::to_string(&request)?.contains("headers")
                && !serde_json::to_string(&request)?.contains("body")
        );
        assert_eq!(
            serde_json::from_value::<CenterOperationSubmitRequest>(encoded)?,
            request
        );
        // A submission that smuggles an HTTP body is refused by the strict
        // contract.
        let mut smuggled = serde_json::to_value(&request)?;
        smuggled.as_object_mut().ok_or("object")?.insert(
            "body".to_owned(),
            json!({ "reset_type": "GracefulShutdown" }),
        );
        assert!(serde_json::from_value::<CenterOperationSubmitRequest>(smuggled).is_err());

        // The operation view carries the tracking facts and the typed
        // command.
        let created_at = OffsetDateTime::parse("2026-08-05T10:11:12Z", &Rfc3339)?;
        let operation = CenterOperationResponse::new(
            uuid!("41989abc-def0-7abc-8def-0123456789ce"),
            Some(site_id),
            endpoint_id,
            command,
            Some("/redfish/v1/Systems/1".to_owned()),
            OperationStateResponse::Queued,
            Some("admin".to_owned()),
            Some(created_at),
            created_at,
        );
        assert_eq!(
            serde_json::from_value::<CenterOperationResponse>(serde_json::to_value(&operation)?)?,
            operation
        );
        assert_eq!(operation.state(), OperationStateResponse::Queued);
        assert_eq!(operation.target(), Some("/redfish/v1/Systems/1"));

        let acknowledgement = CenterOperationSubmitResponse::new(
            uuid!("41989abc-def0-7abc-8def-0123456789ce"),
            created_at,
        );
        assert_eq!(
            serde_json::from_value::<CenterOperationSubmitResponse>(serde_json::to_value(
                &acknowledgement
            )?)?,
            acknowledgement
        );
        Ok(())
    }
}
