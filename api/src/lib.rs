#![forbid(unsafe_code)]

use std::{fmt, num::NonZeroU64};

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

/// Feature-specific, explicitly tagged core Redfish resource fields.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
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
}

/// One read-only core Redfish resource in a complete refresh Generation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
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
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
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
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
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

#[cfg(test)]
mod tests {
    use std::{error::Error, num::NonZeroU64};

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
}
