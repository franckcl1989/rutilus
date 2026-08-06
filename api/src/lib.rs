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
}
