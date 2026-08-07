#![forbid(unsafe_code)]

use std::{fmt, num::NonZeroU64};

// The §7.5 typed write vocabulary is part of the wire contract: the operation
// DTOs carry `RedfishCommand` and its payloads, so consumers of this crate
// must be able to name those types (E0603 otherwise). The re-export mirrors
// the domain's own surface exactly.
pub use rutilus_domain::{
    BootCommand, BootSource, BootSourceOverrideEnabled, BootSourceOverrideMode, ChassisCommand,
    CreateSubscription, DeleteSubscription, EventCommand, EventDestinationProtocol, EventType,
    ManagerCommand, RedfishCommand, ResetKeysType, ResetType, SecureBootCommand,
    SetBootSourceOverride, StartUpdate, SystemCommand, UpdateCommand,
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
}
