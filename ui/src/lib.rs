#![forbid(unsafe_code)]
#![cfg_attr(
    all(not(target_arch = "wasm32"), target_env = "msvc"),
    allow(linker_messages)
)]

#[cfg(any(target_arch = "wasm32", test))]
use std::{collections::BTreeSet, fmt};

#[cfg(any(target_arch = "wasm32", test))]
use rutilus_api::{
    AboutResponse, ArtifactResponse, ArtifactStateResponse, AuditEventResponse, AuditQueryResponse,
    BatchDetailResponse, BatchOperationResponse, BatchOperationStateResponse,
    BatchOutcomeCountsResponse, BatchRefreshResponse, BatchSummaryResponse, BootCommand,
    BootSource, BootSourceOverrideEnabled, BootSourceOverrideMode, CapabilityEntryResponse,
    CapabilityStateResponse, CenterBindingStateResponse, CenterEndpointViewResponse,
    CenterOperationResponse, CenterSiteResponse, ChassisCommand, CoreResourceDetailsResponse,
    CoreResourceResponse, CreateSubscription, CredentialInventoryResponse,
    CredentialSummaryResponse, DeleteSubscription, EndpointCapabilityInventoryResponse,
    EndpointCsvImportResponse, EndpointCsvImportRowResponse, EndpointCsvImportRowStatusResponse,
    EndpointEnrollmentResponse, EndpointInventoryResponse, EndpointRefreshResultResponse,
    EndpointRefreshStatusResponse, EndpointResourceInventoryResponse,
    EndpointResourceSnapshotResponse, EndpointSummaryResponse, EndpointTrustChallengeResponse,
    EndpointTrustChallengeStateResponse, EndpointTrustExpectationRequest, EraseToken, EraseType,
    EventCommand, EventDestinationProtocol, EventListResponse, EventResponse, EventType,
    GroupResponse, ManagerCommand, MetricValueResponse, NvidiaDebugTokenCommand,
    NvidiaPowerSmoothingCommand, NvidiaSystemConfigProfileCommand, OemCommand, OperationResponse,
    OperationSourceResponse, OperationStateResponse, ProfileFile, ProfileId, RedfishCommand,
    ResetKeysType, ResetType, ResourceDiagnosticsResponse, ResourceStatusResponse, RoleResponse,
    SecureBootCommand, SetBootSourceOverride, StartUpdate, SystemCommand, TagListResponse,
    TelemetrySampleListResponse, TelemetrySampleResponse, TelemetrySeriesResponse,
    TlsTrustModeResponse, TokenData, TokenType, UiLocationResponse, UpdateCommand,
};
#[cfg(any(target_arch = "wasm32", test))]
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

// Production wasm builds reach `serde_json` through the leptos re-export:
// leptos is the wasm-only UI dependency that already carries the crate, so
// the manifest stays untouched. Host test builds use the dev-dependency.
#[cfg(target_arch = "wasm32")]
use leptos::serde_json as json;

#[cfg(all(test, not(target_arch = "wasm32")))]
use serde_json as json;

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
#[derive(Clone, Debug, PartialEq)]
struct ConsoleData {
    about: AboutResponse,
    inventory: EndpointInventoryResponse,
    resources: Vec<EndpointResourceInventoryResponse>,
}

#[cfg(any(target_arch = "wasm32", test))]
#[derive(Clone, Debug, PartialEq)]
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
    endpoint_id: String,
    display_name: String,
    address: String,
    trust_label: &'static str,
    snapshot_label: String,
    resource_counts: Option<ResourceCountsProjection>,
    resources: Vec<CoreResourceCardProjection>,
    /// The §12.3 unified vendor of the endpoint, projected from the Service
    /// Root resource the BMC published (absent until a complete refresh
    /// observed one). Drives the §14.2 vendor filter.
    vendor: Option<String>,
    /// The §12.3 unified health of the endpoint: the worst status health
    /// across its System, Chassis, and Manager resources. Drives the §14.2
    /// health filter.
    health_level: HealthLevel,
    /// The raw text of the worst health status (§12.3 keeps the vendor's
    /// original value beside the unified value), absent when no resource
    /// published a health yet.
    health_label: Option<String>,
    /// The §12.2 OEM surface of the endpoint (§11.5): either the honest
    /// `UnsupportedByNvRedfishBaseline` notice or the upstream-typed OEM
    /// resource cards of the latest complete snapshot. Absent until a
    /// complete refresh observed resources, exactly like `resource_counts`.
    oem_section: OemSectionProjection,
}

#[cfg(any(target_arch = "wasm32", test))]
impl From<&EndpointResourceInventoryResponse> for EndpointCardProjection {
    fn from(endpoint: &EndpointResourceInventoryResponse) -> Self {
        let identity = endpoint.endpoint();
        let trust_label = match identity.tls_trust_mode() {
            TlsTrustModeResponse::SystemCa => "System CA",
            TlsTrustModeResponse::PinnedCertificate => "Pinned certificate",
        };
        let (snapshot_label, resource_counts, resources, oem_section) = match endpoint.snapshot() {
            EndpointResourceSnapshotResponse::AwaitingFirstRefresh => (
                "Awaiting first refresh".to_owned(),
                None,
                Vec::new(),
                OemSectionProjection::UnsupportedByNvRedfishBaseline,
            ),
            EndpointResourceSnapshotResponse::Current {
                generation,
                observed_at,
                resources,
            } => {
                let endpoint_id_text = identity.endpoint_id().to_string();
                (
                    format!(
                        "Generation {} · observed {}",
                        generation.get(),
                        format_observed_at(observed_at)
                    ),
                    Some(count_core_resources(resources)),
                    resources
                        .iter()
                        .map(|resource| {
                            CoreResourceCardProjection::from_resource(&endpoint_id_text, resource)
                        })
                        .collect(),
                    OemSectionProjection::of_snapshot(&endpoint_id_text, resources),
                )
            }
        };
        let (vendor, health_level, health_label) = match endpoint.snapshot() {
            EndpointResourceSnapshotResponse::AwaitingFirstRefresh => {
                (None, HealthLevel::Unknown, None)
            }
            EndpointResourceSnapshotResponse::Current { resources, .. } => {
                let health = worst_endpoint_health(resources);
                (
                    endpoint_vendor(resources),
                    aggregate_health(resources),
                    health.map(|(_, raw)| raw.to_owned()),
                )
            }
        };
        Self {
            endpoint_id: identity.endpoint_id().to_string(),
            display_name: identity.display_name().to_owned(),
            address: identity.address().to_owned(),
            trust_label,
            snapshot_label,
            resource_counts,
            resources,
            vendor,
            health_level,
            health_label,
            oem_section,
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
            // The 0.2 resource families mirror the server-side counts
            // contract: they render as cards in the resource list, while the
            // three-line counts summary keeps its 0.1 wire shape. The
            // Power/Thermal/Sensors/Controls telemetry families, the
            // LogServices/ManagerNetworkProtocol/HostInterfaces manager
            // surface, the OemDell / OemSmcSysLockdown / OemSmcKcsInterface /
            // OemNvidia* §11.5 OEM families, the
            // PcieDevice/Assembly/SoftwareInventory read families, and the
            // EventService/EventSubscription/
            // TelemetryService/MetricDefinition/MetricReport/TaskService/Task
            // service families follow the same rule.
            CoreResourceDetailsResponse::ServiceRoot { .. }
            | CoreResourceDetailsResponse::OemDell { .. }
            | CoreResourceDetailsResponse::OemSmcSysLockdown { .. }
            | CoreResourceDetailsResponse::OemSmcKcsInterface { .. }
            | CoreResourceDetailsResponse::OemNvidiaSystemConfigProfile { .. }
            | CoreResourceDetailsResponse::OemNvidiaSystemConfigProfileStatus { .. }
            | CoreResourceDetailsResponse::OemNvidiaSystemProfile { .. }
            | CoreResourceDetailsResponse::OemNvidiaSystemProfileFile { .. }
            | CoreResourceDetailsResponse::OemNvidiaPowerCompliance { .. }
            | CoreResourceDetailsResponse::OemNvidiaPowerDomain { .. }
            | CoreResourceDetailsResponse::OemNvidiaPowerPolicy { .. }
            | CoreResourceDetailsResponse::OemNvidiaManagedEntityGroup { .. }
            | CoreResourceDetailsResponse::OemNvidiaPowerStateGroup { .. }
            | CoreResourceDetailsResponse::OemNvidiaPscState { .. }
            | CoreResourceDetailsResponse::OemNvidiaPsuState { .. }
            | CoreResourceDetailsResponse::OemNvidiaPsuRedundancy { .. }
            | CoreResourceDetailsResponse::OemNvidiaManagedEntity { .. }
            | CoreResourceDetailsResponse::OemLenovoSecurityService { .. }
            | CoreResourceDetailsResponse::Processor { .. }
            | CoreResourceDetailsResponse::Memory { .. }
            | CoreResourceDetailsResponse::Storage { .. }
            | CoreResourceDetailsResponse::NetworkAdapter { .. }
            | CoreResourceDetailsResponse::EthernetInterface { .. }
            | CoreResourceDetailsResponse::Account { .. }
            | CoreResourceDetailsResponse::Bios { .. }
            | CoreResourceDetailsResponse::BootOption { .. }
            | CoreResourceDetailsResponse::SecureBoot { .. }
            | CoreResourceDetailsResponse::Power { .. }
            | CoreResourceDetailsResponse::Thermal { .. }
            | CoreResourceDetailsResponse::Sensor { .. }
            | CoreResourceDetailsResponse::Control { .. }
            | CoreResourceDetailsResponse::LogService { .. }
            | CoreResourceDetailsResponse::ManagerNetworkProtocol { .. }
            | CoreResourceDetailsResponse::HostInterface { .. }
            | CoreResourceDetailsResponse::PcieDevice { .. }
            | CoreResourceDetailsResponse::Assembly { .. }
            | CoreResourceDetailsResponse::SoftwareInventory { .. }
            | CoreResourceDetailsResponse::EventService { .. }
            | CoreResourceDetailsResponse::EventSubscription { .. }
            | CoreResourceDetailsResponse::TelemetryService { .. }
            | CoreResourceDetailsResponse::MetricDefinition { .. }
            | CoreResourceDetailsResponse::MetricReport { .. }
            | CoreResourceDetailsResponse::TaskService { .. }
            | CoreResourceDetailsResponse::Task { .. } => {}
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
    /// The owning endpoint's id; the §12.4 diagnostics drill-down routes on
    /// it, so the card carries it into the panel entry.
    endpoint_id: String,
    /// The stable resource id the backend assigned to this observation; the
    /// §12.4 diagnostics route addresses one resource by this id.
    resource_id: String,
}

#[cfg(any(target_arch = "wasm32", test))]
impl CoreResourceCardProjection {
    /// Projects one typed resource into its card, binding the owning
    /// endpoint id so the card can open the resource's §12.4 diagnostics
    /// panel. The endpoint is not part of the resource response, so it is
    /// threaded in from the surrounding inventory projection instead of a
    /// `From` impl.
    fn from_resource(endpoint_id: &str, resource: &CoreResourceResponse) -> Self {
        let mut facts = vec![ResourceFactProjection {
            label: "Redfish ID",
            value: resource.common().id().to_owned(),
        }];
        let (type_label, family_facts) = card_facts(resource.resource());
        facts.extend(family_facts);
        Self {
            type_label,
            name: resource.common().name().to_owned(),
            description: resource.common().description().map(str::to_owned),
            source: resource.source().odata_id().to_owned(),
            facts,
            endpoint_id: endpoint_id.to_owned(),
            resource_id: resource.source().resource_id().to_string(),
        }
    }
}

/// The §12.2 OEM surface of one endpoint snapshot, in the two legal §11.5
/// forms.
///
/// The section is `Available` exactly when the latest complete snapshot
/// carries upstream-typed OEM resources, which are projected as resource
/// cards through the same [`CoreResourceCardProjection`] surface as every
/// standard family. Otherwise the section shows the honest
/// `UnsupportedByNvRedfishBaseline` notice: the nv-redfish baseline has no
/// strong-typed OEM surface for this endpoint's vendor, and §11.5 forbids
/// inventing one (no raw-JSON writes, vendor URLs, web screens, or private
/// plugins). The placeholder is a real state, not a loading fallback, so it
/// stays visible as long as the boundary holds.
///
/// Switch condition between the two forms: [`Self::of_snapshot`] derives it
/// from the presence of typed OEM resources ([`Self::from_cards`] is the
/// single decision point), and [`oem_resource_card`] is the single extension
/// point that maps each landed OEM family. The api contract has landed the
/// Dell OEM family (`OemDell`, the §0.5.0 `oem-dell-attributes` surface), so
/// Dell endpoints derive the card form while every other vendor keeps the
/// honest §11.5 placeholder; the closed match refuses to compile until each
/// newly landed vendor family gains its arm.
#[cfg(any(target_arch = "wasm32", test))]
#[derive(Clone, Debug, Eq, PartialEq)]
enum OemSectionProjection {
    /// The nv-redfish baseline compiles no strong-typed OEM surface for the
    /// endpoint's vendor (§11.5 second branch): the section renders the
    /// pinned [`OEM_UNSUPPORTED_NOTICE`] instead of fabricating a surface.
    UnsupportedByNvRedfishBaseline,
    /// Upstream-typed OEM resources of the latest complete snapshot,
    /// projected as resource cards (§11.5 first branch).
    Available {
        cards: Vec<CoreResourceCardProjection>,
    },
}

#[cfg(any(target_arch = "wasm32", test))]
impl OemSectionProjection {
    /// Projects the §12.2 OEM section from one complete resource snapshot.
    ///
    /// The section form follows the snapshot: OEM resources projected by
    /// [`oem_resource_card`] render as cards, and their absence (a non-Dell
    /// endpoint, or a Dell endpoint whose manager published no
    /// `DellAttributes` document) derives the §11.5 placeholder form.
    fn of_snapshot(endpoint_id: &str, resources: &[CoreResourceResponse]) -> Self {
        let cards = resources
            .iter()
            .filter_map(|resource| oem_resource_card(endpoint_id, resource))
            .collect::<Vec<_>>();
        Self::from_cards(cards)
    }

    /// Constructs the section from its typed OEM cards; the single switch
    /// condition between the two §11.5 forms. Kept separate from
    /// [`Self::of_snapshot`] so the condition is pinned by tests and the
    /// wasm build cannot drift into a third state.
    fn from_cards(cards: Vec<CoreResourceCardProjection>) -> Self {
        if cards.is_empty() {
            Self::UnsupportedByNvRedfishBaseline
        } else {
            Self::Available { cards }
        }
    }

    /// Reports whether the section renders the data-card form.
    #[must_use]
    const fn is_supported(&self) -> bool {
        matches!(self, Self::Available { .. })
    }

    /// Returns the typed OEM resource cards of the section; the placeholder
    /// form carries none, which the component renders as the notice.
    fn cards(&self) -> Vec<CoreResourceCardProjection> {
        match self {
            Self::UnsupportedByNvRedfishBaseline => Vec::new(),
            Self::Available { cards } => cards.clone(),
        }
    }
}

/// The §11.5 honest notice shown when the nv-redfish baseline has no
/// strong-typed OEM surface for the endpoint's vendor. Pinned so the
/// `UnsupportedByNvRedfishBaseline` rendering cannot drift from the §11.5
/// contract wording.
#[cfg(any(target_arch = "wasm32", test))]
const OEM_UNSUPPORTED_NOTICE: &str =
    "OEM data is not available in the nv-redfish baseline for this vendor";

/// Projects one resource as an OEM section card, or `None` when it belongs
/// to a standard family.
///
/// The closed match over `CoreResourceDetailsResponse` is the single
/// extension point of the §12.2 OEM section: every OEM family the api
/// contract projects gains an arm here — the exhaustive match refuses to
/// compile otherwise — projecting the card through the existing
/// [`CoreResourceCardProjection::from_resource`] path so the family renders
/// with the same card surface as every standard family, and
/// [`OemSectionProjection::of_snapshot`] then derives the card form
/// automatically. The Dell, Supermicro, NVIDIA, and Lenovo families (the
/// §0.5.0 `oem-dell-attributes`, `oem-supermicro`, `oem-nvidia*`, and
/// `oem-lenovo` surfaces) have landed; later vendor families (HPE, ...)
/// extend this match the same way. Standard families and vendors the
/// baseline has not typed stay out, so their endpoints keep the honest
/// §11.5 placeholder.
#[cfg(any(target_arch = "wasm32", test))]
fn oem_resource_card(
    endpoint_id: &str,
    resource: &CoreResourceResponse,
) -> Option<CoreResourceCardProjection> {
    match resource.resource() {
        CoreResourceDetailsResponse::OemDell { .. }
        | CoreResourceDetailsResponse::OemSmcSysLockdown { .. }
        | CoreResourceDetailsResponse::OemSmcKcsInterface { .. }
        | CoreResourceDetailsResponse::OemNvidiaSystemConfigProfile { .. }
        | CoreResourceDetailsResponse::OemNvidiaSystemConfigProfileStatus { .. }
        | CoreResourceDetailsResponse::OemNvidiaSystemProfile { .. }
        | CoreResourceDetailsResponse::OemNvidiaSystemProfileFile { .. }
        | CoreResourceDetailsResponse::OemNvidiaPowerCompliance { .. }
        | CoreResourceDetailsResponse::OemNvidiaPowerDomain { .. }
        | CoreResourceDetailsResponse::OemNvidiaPowerPolicy { .. }
        | CoreResourceDetailsResponse::OemNvidiaManagedEntityGroup { .. }
        | CoreResourceDetailsResponse::OemNvidiaPowerStateGroup { .. }
        | CoreResourceDetailsResponse::OemNvidiaPscState { .. }
        | CoreResourceDetailsResponse::OemNvidiaPsuState { .. }
        | CoreResourceDetailsResponse::OemNvidiaPsuRedundancy { .. }
        | CoreResourceDetailsResponse::OemNvidiaManagedEntity { .. }
        | CoreResourceDetailsResponse::OemLenovoSecurityService { .. } => Some(
            CoreResourceCardProjection::from_resource(endpoint_id, resource),
        ),
        CoreResourceDetailsResponse::ServiceRoot { .. }
        | CoreResourceDetailsResponse::Processor { .. }
        | CoreResourceDetailsResponse::Memory { .. }
        | CoreResourceDetailsResponse::Storage { .. }
        | CoreResourceDetailsResponse::NetworkAdapter { .. }
        | CoreResourceDetailsResponse::EthernetInterface { .. }
        | CoreResourceDetailsResponse::Account { .. }
        | CoreResourceDetailsResponse::Bios { .. }
        | CoreResourceDetailsResponse::BootOption { .. }
        | CoreResourceDetailsResponse::SecureBoot { .. }
        | CoreResourceDetailsResponse::Power { .. }
        | CoreResourceDetailsResponse::Thermal { .. }
        | CoreResourceDetailsResponse::Sensor { .. }
        | CoreResourceDetailsResponse::Control { .. }
        | CoreResourceDetailsResponse::LogService { .. }
        | CoreResourceDetailsResponse::ManagerNetworkProtocol { .. }
        | CoreResourceDetailsResponse::HostInterface { .. }
        | CoreResourceDetailsResponse::PcieDevice { .. }
        | CoreResourceDetailsResponse::Assembly { .. }
        | CoreResourceDetailsResponse::SoftwareInventory { .. }
        | CoreResourceDetailsResponse::EventService { .. }
        | CoreResourceDetailsResponse::EventSubscription { .. }
        | CoreResourceDetailsResponse::TelemetryService { .. }
        | CoreResourceDetailsResponse::MetricDefinition { .. }
        | CoreResourceDetailsResponse::MetricReport { .. }
        | CoreResourceDetailsResponse::TaskService { .. }
        | CoreResourceDetailsResponse::Task { .. }
        | CoreResourceDetailsResponse::System { .. }
        | CoreResourceDetailsResponse::Chassis { .. }
        | CoreResourceDetailsResponse::Manager { .. } => None,
    }
}

/// Projects one resource into its card identity and family facts; the From
/// implementation stays a thin assembly so the per-family projections remain
/// readable and individually testable.
#[cfg(any(target_arch = "wasm32", test))]
fn card_facts(
    resource: &CoreResourceDetailsResponse,
) -> (&'static str, Vec<ResourceFactProjection>) {
    match resource {
        CoreResourceDetailsResponse::ServiceRoot { .. } => service_root_card_facts(resource),
        CoreResourceDetailsResponse::System { .. } => system_card_facts(resource),
        CoreResourceDetailsResponse::Chassis { .. } => chassis_card_facts(resource),
        CoreResourceDetailsResponse::Manager { .. } => manager_card_facts(resource),
        CoreResourceDetailsResponse::OemDell { .. } => oem_dell_card_facts(resource),
        CoreResourceDetailsResponse::OemSmcSysLockdown { .. } => {
            oem_smc_sys_lockdown_card_facts(resource)
        }
        CoreResourceDetailsResponse::OemSmcKcsInterface { .. } => {
            oem_smc_kcs_interface_card_facts(resource)
        }
        CoreResourceDetailsResponse::OemNvidiaSystemConfigProfile { .. } => {
            oem_nvidia_system_config_profile_card_facts(resource)
        }
        CoreResourceDetailsResponse::OemNvidiaSystemConfigProfileStatus { .. } => {
            oem_nvidia_system_config_profile_status_card_facts(resource)
        }
        CoreResourceDetailsResponse::OemNvidiaSystemProfile { .. } => {
            oem_nvidia_system_profile_card_facts(resource)
        }
        CoreResourceDetailsResponse::OemNvidiaSystemProfileFile { .. } => {
            oem_nvidia_system_profile_file_card_facts(resource)
        }
        CoreResourceDetailsResponse::OemNvidiaPowerCompliance { .. } => {
            oem_nvidia_power_compliance_card_facts(resource)
        }
        CoreResourceDetailsResponse::OemNvidiaPowerDomain { .. } => {
            oem_nvidia_power_domain_card_facts(resource)
        }
        CoreResourceDetailsResponse::OemNvidiaPowerPolicy { .. } => {
            oem_nvidia_power_policy_card_facts(resource)
        }
        CoreResourceDetailsResponse::OemNvidiaManagedEntityGroup { .. } => {
            oem_nvidia_managed_entity_group_card_facts(resource)
        }
        CoreResourceDetailsResponse::OemNvidiaPowerStateGroup { .. } => {
            oem_nvidia_power_state_group_card_facts(resource)
        }
        CoreResourceDetailsResponse::OemNvidiaPscState { .. } => {
            oem_nvidia_psc_state_card_facts(resource)
        }
        CoreResourceDetailsResponse::OemNvidiaPsuState { .. } => {
            oem_nvidia_psu_state_card_facts(resource)
        }
        CoreResourceDetailsResponse::OemNvidiaPsuRedundancy { .. } => {
            oem_nvidia_psu_redundancy_card_facts(resource)
        }
        CoreResourceDetailsResponse::OemNvidiaManagedEntity { .. } => {
            oem_nvidia_managed_entity_card_facts(resource)
        }
        CoreResourceDetailsResponse::OemLenovoSecurityService { .. } => {
            oem_lenovo_security_service_card_facts(resource)
        }
        CoreResourceDetailsResponse::Processor { .. } => processor_card_facts(resource),
        CoreResourceDetailsResponse::Memory { .. } => memory_card_facts(resource),
        CoreResourceDetailsResponse::Storage { .. } => storage_card_facts(resource),
        CoreResourceDetailsResponse::NetworkAdapter { .. } => network_adapter_card_facts(resource),
        CoreResourceDetailsResponse::EthernetInterface { .. } => {
            ethernet_interface_card_facts(resource)
        }
        CoreResourceDetailsResponse::Account { .. } => account_card_facts(resource),
        CoreResourceDetailsResponse::Bios { .. } => bios_card_facts(resource),
        CoreResourceDetailsResponse::BootOption { .. } => boot_option_card_facts(resource),
        CoreResourceDetailsResponse::SecureBoot { .. } => secure_boot_card_facts(resource),
        CoreResourceDetailsResponse::Power { .. } => power_card_facts(resource),
        CoreResourceDetailsResponse::Thermal { .. } => thermal_card_facts(resource),
        CoreResourceDetailsResponse::Sensor { .. } => sensor_card_facts(resource),
        CoreResourceDetailsResponse::Control { .. } => control_card_facts(resource),
        CoreResourceDetailsResponse::LogService { .. } => log_service_card_facts(resource),
        CoreResourceDetailsResponse::ManagerNetworkProtocol { .. } => {
            manager_network_protocol_card_facts(resource)
        }
        CoreResourceDetailsResponse::HostInterface { .. } => host_interface_card_facts(resource),
        CoreResourceDetailsResponse::PcieDevice { .. } => pcie_device_card_facts(resource),
        CoreResourceDetailsResponse::Assembly { .. } => assembly_card_facts(resource),
        CoreResourceDetailsResponse::SoftwareInventory { .. } => {
            software_inventory_card_facts(resource)
        }
        CoreResourceDetailsResponse::EventService { .. } => event_service_card_facts(resource),
        CoreResourceDetailsResponse::EventSubscription { .. } => {
            event_subscription_card_facts(resource)
        }
        CoreResourceDetailsResponse::TelemetryService { .. } => {
            telemetry_service_card_facts(resource)
        }
        CoreResourceDetailsResponse::MetricDefinition { .. } => {
            metric_definition_card_facts(resource)
        }
        CoreResourceDetailsResponse::MetricReport { .. } => metric_report_card_facts(resource),
        CoreResourceDetailsResponse::TaskService { .. } => task_service_card_facts(resource),
        CoreResourceDetailsResponse::Task { .. } => task_card_facts(resource),
    }
}

/// Facts for the Service Root card; every optional value renders only when
/// the BMC published it.
///
/// The dispatcher guarantees this receives the `ServiceRoot` variant; the
/// fallback keeps a stable empty facts list instead of panicking if that
/// contract is ever violated.
#[cfg(any(target_arch = "wasm32", test))]
fn service_root_card_facts(
    resource: &CoreResourceDetailsResponse,
) -> (&'static str, Vec<ResourceFactProjection>) {
    let CoreResourceDetailsResponse::ServiceRoot {
        vendor,
        product,
        redfish_version,
    } = resource
    else {
        return ("Service Root", Vec::new());
    };
    let mut facts = Vec::new();
    push_fact(&mut facts, "Vendor", vendor.as_deref());
    push_fact(&mut facts, "Product", product.as_deref());
    push_fact(&mut facts, "Redfish version", redfish_version.as_deref());
    ("Service Root", facts)
}

/// Facts for the System card.
///
/// The dispatcher guarantees this receives the `System` variant; the
/// fallback keeps a stable empty facts list instead of panicking if that
/// contract is ever violated.
#[cfg(any(target_arch = "wasm32", test))]
fn system_card_facts(
    resource: &CoreResourceDetailsResponse,
) -> (&'static str, Vec<ResourceFactProjection>) {
    let CoreResourceDetailsResponse::System {
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
    } = resource
    else {
        return ("System", Vec::new());
    };
    let mut facts = Vec::new();
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
    ("System", facts)
}

/// Facts for the Chassis card.
///
/// The dispatcher guarantees this receives the `Chassis` variant; the
/// fallback keeps a stable empty facts list instead of panicking if that
/// contract is ever violated.
#[cfg(any(target_arch = "wasm32", test))]
fn chassis_card_facts(
    resource: &CoreResourceDetailsResponse,
) -> (&'static str, Vec<ResourceFactProjection>) {
    let CoreResourceDetailsResponse::Chassis {
        chassis_type,
        manufacturer,
        model,
        part_number,
        serial_number,
        sku,
        asset_tag,
        power_state,
        status,
    } = resource
    else {
        return ("Chassis", Vec::new());
    };
    let mut facts = Vec::new();
    push_fact(&mut facts, "Chassis type", Some(chassis_type.as_str()));
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
    ("Chassis", facts)
}

/// Facts for the Manager card.
///
/// The dispatcher guarantees this receives the `Manager` variant; the
/// fallback keeps a stable empty facts list instead of panicking if that
/// contract is ever violated.
#[cfg(any(target_arch = "wasm32", test))]
fn manager_card_facts(
    resource: &CoreResourceDetailsResponse,
) -> (&'static str, Vec<ResourceFactProjection>) {
    let CoreResourceDetailsResponse::Manager {
        manager_type,
        manufacturer,
        model,
        part_number,
        serial_number,
        firmware_version,
        version,
        power_state,
        status,
    } = resource
    else {
        return ("Manager", Vec::new());
    };
    let mut facts = Vec::new();
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
    ("Manager", facts)
}

/// Facts for a §2.1 processor card; part and serial numbers are not part of
/// the processor schema projection, so hardware facts render without them.
///
/// The dispatcher guarantees this receives the `Processor` variant; the
/// fallback keeps a stable empty facts list instead of panicking if that
/// contract is ever violated.
#[cfg(any(target_arch = "wasm32", test))]
fn processor_card_facts(
    resource: &CoreResourceDetailsResponse,
) -> (&'static str, Vec<ResourceFactProjection>) {
    let CoreResourceDetailsResponse::Processor {
        processor_type,
        socket,
        manufacturer,
        model,
        total_cores,
        status,
    } = resource
    else {
        return ("Processor", Vec::new());
    };
    let mut facts = Vec::new();
    push_fact(&mut facts, "Processor type", processor_type.as_deref());
    push_fact(&mut facts, "Socket", socket.as_deref());
    push_hardware_facts(
        &mut facts,
        manufacturer.as_deref(),
        model.as_deref(),
        None,
        None,
    );
    push_u64_fact(&mut facts, "Total cores", *total_cores);
    push_status_facts(&mut facts, status.as_ref());
    ("Processor", facts)
}

/// Facts for a §2.1 memory card; part and serial numbers are not part of the
/// memory schema projection, so hardware facts render without them.
///
/// The dispatcher guarantees this receives the `Memory` variant; the
/// fallback keeps a stable empty facts list instead of panicking if that
/// contract is ever violated.
#[cfg(any(target_arch = "wasm32", test))]
fn memory_card_facts(
    resource: &CoreResourceDetailsResponse,
) -> (&'static str, Vec<ResourceFactProjection>) {
    let CoreResourceDetailsResponse::Memory {
        memory_device_type,
        capacity_mib,
        manufacturer,
        model,
        status,
    } = resource
    else {
        return ("Memory", Vec::new());
    };
    let mut facts = Vec::new();
    push_fact(
        &mut facts,
        "Memory device type",
        memory_device_type.as_deref(),
    );
    push_u64_fact(&mut facts, "Capacity (MiB)", *capacity_mib);
    push_hardware_facts(
        &mut facts,
        manufacturer.as_deref(),
        model.as_deref(),
        None,
        None,
    );
    push_status_facts(&mut facts, status.as_ref());
    ("Memory", facts)
}

/// Facts for a §2.1 storage card; the numeric controller and drive counts
/// come from the typed schema's collections and stay numeric so the card
/// renders them without re-parsing text.
///
/// The dispatcher guarantees this receives the `Storage` variant; the
/// fallback keeps a stable empty facts list instead of panicking if that
/// contract is ever violated.
#[cfg(any(target_arch = "wasm32", test))]
fn storage_card_facts(
    resource: &CoreResourceDetailsResponse,
) -> (&'static str, Vec<ResourceFactProjection>) {
    let CoreResourceDetailsResponse::Storage {
        controller_count,
        drive_count,
        status,
    } = resource
    else {
        return ("Storage", Vec::new());
    };
    let mut facts = Vec::new();
    push_u64_fact(&mut facts, "Controller count", *controller_count);
    push_u64_fact(&mut facts, "Drive count", *drive_count);
    push_status_facts(&mut facts, status.as_ref());
    ("Storage", facts)
}

/// Facts for a §2.1 network-adapter card; part and serial numbers are not
/// part of the network-adapter schema projection, so hardware facts render
/// without them.
///
/// The dispatcher guarantees this receives the `NetworkAdapter` variant; the
/// fallback keeps a stable empty facts list instead of panicking if that
/// contract is ever violated.
#[cfg(any(target_arch = "wasm32", test))]
fn network_adapter_card_facts(
    resource: &CoreResourceDetailsResponse,
) -> (&'static str, Vec<ResourceFactProjection>) {
    let CoreResourceDetailsResponse::NetworkAdapter {
        manufacturer,
        model,
        status,
    } = resource
    else {
        return ("Network adapter", Vec::new());
    };
    let mut facts = Vec::new();
    push_hardware_facts(
        &mut facts,
        manufacturer.as_deref(),
        model.as_deref(),
        None,
        None,
    );
    push_status_facts(&mut facts, status.as_ref());
    ("Network adapter", facts)
}

/// Facts for a §2.1 ethernet-interface card; `speed_mbps` stays numeric so
/// the card renders the link speed without re-parsing text, and the enabled
/// flag renders only when the BMC published it.
///
/// The dispatcher guarantees this receives the `EthernetInterface` variant;
/// the fallback keeps a stable empty facts list instead of panicking if that
/// contract is ever violated.
#[cfg(any(target_arch = "wasm32", test))]
fn ethernet_interface_card_facts(
    resource: &CoreResourceDetailsResponse,
) -> (&'static str, Vec<ResourceFactProjection>) {
    let CoreResourceDetailsResponse::EthernetInterface {
        mac_address,
        speed_mbps,
        interface_enabled,
        status,
    } = resource
    else {
        return ("Ethernet interface", Vec::new());
    };
    let mut facts = Vec::new();
    push_fact(&mut facts, "MAC address", mac_address.as_deref());
    push_u64_fact(&mut facts, "Speed (Mbps)", *speed_mbps);
    push_fact(
        &mut facts,
        "Interface enabled",
        interface_enabled.map(|enabled| if enabled { "Yes" } else { "No" }),
    );
    push_status_facts(&mut facts, status.as_ref());
    ("Ethernet interface", facts)
}

/// Facts for a §2.1 accounts card (a `ManagerAccount`); the enabled and
/// locked flags render only when the BMC published them, and the
/// manager-account schema has no status facts.
///
/// The dispatcher guarantees this receives the `Account` variant; the
/// fallback keeps a stable empty facts list instead of panicking if that
/// contract is ever violated.
#[cfg(any(target_arch = "wasm32", test))]
fn account_card_facts(
    resource: &CoreResourceDetailsResponse,
) -> (&'static str, Vec<ResourceFactProjection>) {
    let CoreResourceDetailsResponse::Account {
        enabled,
        role_id,
        locked,
    } = resource
    else {
        return ("Account", Vec::new());
    };
    let mut facts = Vec::new();
    push_fact(
        &mut facts,
        "Enabled",
        enabled.map(|enabled| if enabled { "Yes" } else { "No" }),
    );
    push_fact(&mut facts, "Role", role_id.as_deref());
    push_fact(
        &mut facts,
        "Locked",
        locked.map(|locked| if locked { "Yes" } else { "No" }),
    );
    ("Account", facts)
}

/// Facts for a §2.1 bios card; only the attribute-registry metadata that
/// names the BIOS attribute set is rendered, because the full attribute
/// bag is a vendor-specific dynamic map of unbounded size.
///
/// The dispatcher guarantees this receives the `Bios` variant; the
/// fallback keeps a stable empty facts list instead of panicking if that
/// contract is ever violated.
#[cfg(any(target_arch = "wasm32", test))]
fn bios_card_facts(
    resource: &CoreResourceDetailsResponse,
) -> (&'static str, Vec<ResourceFactProjection>) {
    let CoreResourceDetailsResponse::Bios { attribute_registry } = resource else {
        return ("BIOS", Vec::new());
    };
    let mut facts = Vec::new();
    push_fact(
        &mut facts,
        "Attribute registry",
        attribute_registry.as_deref(),
    );
    ("BIOS", facts)
}

/// Facts for a §2.1 boot-option card; `boot_option_enabled` stays a Boolean
/// so the card renders the flag without re-parsing text.
///
/// The dispatcher guarantees this receives the `BootOption` variant; the
/// fallback keeps a stable empty facts list instead of panicking if that
/// contract is ever violated.
#[cfg(any(target_arch = "wasm32", test))]
fn boot_option_card_facts(
    resource: &CoreResourceDetailsResponse,
) -> (&'static str, Vec<ResourceFactProjection>) {
    let CoreResourceDetailsResponse::BootOption {
        display_name,
        boot_option_enabled,
        uefi_device_path,
    } = resource
    else {
        return ("Boot option", Vec::new());
    };
    let mut facts = Vec::new();
    push_fact(&mut facts, "Display name", display_name.as_deref());
    push_fact(
        &mut facts,
        "Enabled",
        boot_option_enabled.map(|enabled| if enabled { "Yes" } else { "No" }),
    );
    push_fact(&mut facts, "UEFI device path", uefi_device_path.as_deref());
    ("Boot option", facts)
}

/// Facts for a §2.1 secure-boot card; `secure_boot_mode` stays the original
/// schema enumeration string so the card renders it without re-parsing text.
///
/// The dispatcher guarantees this receives the `SecureBoot` variant; the
/// fallback keeps a stable empty facts list instead of panicking if that
/// contract is ever violated.
#[cfg(any(target_arch = "wasm32", test))]
fn secure_boot_card_facts(
    resource: &CoreResourceDetailsResponse,
) -> (&'static str, Vec<ResourceFactProjection>) {
    let CoreResourceDetailsResponse::SecureBoot {
        secure_boot_enable,
        secure_boot_mode,
    } = resource
    else {
        return ("Secure Boot", Vec::new());
    };
    let mut facts = Vec::new();
    push_fact(
        &mut facts,
        "Secure boot enabled",
        secure_boot_enable.map(|enabled| if enabled { "Yes" } else { "No" }),
    );
    push_fact(&mut facts, "Secure boot mode", secure_boot_mode.as_deref());
    ("Secure Boot", facts)
}

/// Facts for a §2.1 power card. The `Power_v1` projection carries no
/// details (the schema declares no `Status` and no reading or metadata
/// properties of its own), so the card renders the common identity only.
///
/// The dispatcher guarantees this receives the `Power` variant; the
/// fallback keeps a stable empty facts list instead of panicking if that
/// contract is ever violated.
#[cfg(any(target_arch = "wasm32", test))]
fn power_card_facts(
    resource: &CoreResourceDetailsResponse,
) -> (&'static str, Vec<ResourceFactProjection>) {
    let CoreResourceDetailsResponse::Power {} = resource else {
        return ("Power", Vec::new());
    };
    ("Power", Vec::new())
}

/// Facts for a §2.1 thermal card; only the resource-level status values are
/// projectable, because temperature readings exist only on nested
/// `Temperatures` members.
///
/// The dispatcher guarantees this receives the `Thermal` variant; the
/// fallback keeps a stable empty facts list instead of panicking if that
/// contract is ever violated.
#[cfg(any(target_arch = "wasm32", test))]
fn thermal_card_facts(
    resource: &CoreResourceDetailsResponse,
) -> (&'static str, Vec<ResourceFactProjection>) {
    let CoreResourceDetailsResponse::Thermal { status } = resource else {
        return ("Thermal", Vec::new());
    };
    let mut facts = Vec::new();
    push_status_facts(&mut facts, status.as_ref());
    ("Thermal", facts)
}

/// Facts for a §2.1 sensors card; the reading and its UCUM units stay as
/// published so the card renders the sensor without re-parsing text.
///
/// The dispatcher guarantees this receives the `Sensor` variant; the
/// fallback keeps a stable empty facts list instead of panicking if that
/// contract is ever violated.
#[cfg(any(target_arch = "wasm32", test))]
fn sensor_card_facts(
    resource: &CoreResourceDetailsResponse,
) -> (&'static str, Vec<ResourceFactProjection>) {
    let CoreResourceDetailsResponse::Sensor {
        reading_type,
        reading,
        reading_units,
        status,
    } = resource
    else {
        return ("Sensor", Vec::new());
    };
    let mut facts = Vec::new();
    push_fact(&mut facts, "Reading type", reading_type.as_deref());
    push_f64_fact(&mut facts, "Reading", *reading);
    push_fact(&mut facts, "Reading units", reading_units.as_deref());
    push_status_facts(&mut facts, status.as_ref());
    ("Sensor", facts)
}

/// Facts for a §2.1 controls card; the set point stays numeric as published
/// so the card renders the control without re-parsing text.
///
/// The dispatcher guarantees this receives the `Control` variant; the
/// fallback keeps a stable empty facts list instead of panicking if that
/// contract is ever violated.
#[cfg(any(target_arch = "wasm32", test))]
fn control_card_facts(
    resource: &CoreResourceDetailsResponse,
) -> (&'static str, Vec<ResourceFactProjection>) {
    let CoreResourceDetailsResponse::Control {
        control_type,
        set_point,
        status,
    } = resource
    else {
        return ("Control", Vec::new());
    };
    let mut facts = Vec::new();
    push_fact(&mut facts, "Control type", control_type.as_deref());
    push_f64_fact(&mut facts, "Set point", *set_point);
    push_status_facts(&mut facts, status.as_ref());
    ("Control", facts)
}

/// Facts for a §2.1 log-service card; the service-enabled flag renders as
/// Yes/No and the record capacity stays numeric as published so the card
/// renders the log service without re-parsing text.
///
/// The dispatcher guarantees this receives the `LogService` variant; the
/// fallback keeps a stable empty facts list instead of panicking if that
/// contract is ever violated.
#[cfg(any(target_arch = "wasm32", test))]
fn log_service_card_facts(
    resource: &CoreResourceDetailsResponse,
) -> (&'static str, Vec<ResourceFactProjection>) {
    let CoreResourceDetailsResponse::LogService {
        service_enabled,
        max_log_entries,
        status,
    } = resource
    else {
        return ("Log Service", Vec::new());
    };
    let mut facts = Vec::new();
    push_fact(
        &mut facts,
        "Service enabled",
        service_enabled.map(|enabled| if enabled { "Yes" } else { "No" }),
    );
    push_u64_fact(&mut facts, "Max records", *max_log_entries);
    push_status_facts(&mut facts, status.as_ref());
    ("Log Service", facts)
}

/// Facts for a §2.1 manager-network-protocol card; the direct `HostName` and
/// `FQDN` metadata properties render as published (the per-protocol sections
/// stay out of the strictly projectable field set).
///
/// The dispatcher guarantees this receives the `ManagerNetworkProtocol`
/// variant; the fallback keeps a stable empty facts list instead of panicking
/// if that contract is ever violated.
#[cfg(any(target_arch = "wasm32", test))]
fn manager_network_protocol_card_facts(
    resource: &CoreResourceDetailsResponse,
) -> (&'static str, Vec<ResourceFactProjection>) {
    let CoreResourceDetailsResponse::ManagerNetworkProtocol {
        host_name,
        fqdn,
        status,
    } = resource
    else {
        return ("Manager Network Protocol", Vec::new());
    };
    let mut facts = Vec::new();
    push_fact(&mut facts, "Host name", host_name.as_deref());
    push_fact(&mut facts, "FQDN", fqdn.as_deref());
    push_status_facts(&mut facts, status.as_ref());
    ("Manager Network Protocol", facts)
}

/// Facts for a §2.1 host-interface card; the interface-enabled flag renders
/// as Yes/No and the resource-level status values follow. The
/// `HostInterface_v1` schema declares no `HostName` property (host identity
/// lives in the linked host/manager ethernet interfaces), so the card
/// identifies the interface through the common name and the interface state.
///
/// The dispatcher guarantees this receives the `HostInterface` variant; the
/// fallback keeps a stable empty facts list instead of panicking if that
/// contract is ever violated.
#[cfg(any(target_arch = "wasm32", test))]
fn host_interface_card_facts(
    resource: &CoreResourceDetailsResponse,
) -> (&'static str, Vec<ResourceFactProjection>) {
    let CoreResourceDetailsResponse::HostInterface {
        interface_enabled,
        status,
    } = resource
    else {
        return ("Host Interface", Vec::new());
    };
    let mut facts = Vec::new();
    push_fact(
        &mut facts,
        "Interface enabled",
        interface_enabled.map(|enabled| if enabled { "Yes" } else { "No" }),
    );
    push_status_facts(&mut facts, status.as_ref());
    ("Host Interface", facts)
}

/// Facts for a §2.1 pcie-device card; the `DeviceType` enumeration and the
/// direct hardware identifiers render only when the BMC published them.
///
/// The dispatcher guarantees this receives the `PcieDevice` variant; the
/// fallback keeps a stable empty facts list instead of panicking if that
/// contract is ever violated.
#[cfg(any(target_arch = "wasm32", test))]
fn pcie_device_card_facts(
    resource: &CoreResourceDetailsResponse,
) -> (&'static str, Vec<ResourceFactProjection>) {
    let CoreResourceDetailsResponse::PcieDevice {
        device_type,
        manufacturer,
        model,
        status,
    } = resource
    else {
        return ("PCIe device", Vec::new());
    };
    let mut facts = Vec::new();
    push_fact(&mut facts, "Device type", device_type.as_deref());
    push_hardware_facts(
        &mut facts,
        manufacturer.as_deref(),
        model.as_deref(),
        None,
        None,
    );
    push_status_facts(&mut facts, status.as_ref());
    ("PCIe device", facts)
}

/// Facts for a §2.1 assembly card (one `AssemblyData` member); the `Producer`
/// is the only direct hardware identifier the member schema projects, so the
/// card renders it together with the resource-level status.
///
/// The dispatcher guarantees this receives the `Assembly` variant; the
/// fallback keeps a stable empty facts list instead of panicking if that
/// contract is ever violated.
#[cfg(any(target_arch = "wasm32", test))]
fn assembly_card_facts(
    resource: &CoreResourceDetailsResponse,
) -> (&'static str, Vec<ResourceFactProjection>) {
    let CoreResourceDetailsResponse::Assembly { producer, status } = resource else {
        return ("Assembly", Vec::new());
    };
    let mut facts = Vec::new();
    push_fact(&mut facts, "Producer", producer.as_deref());
    push_status_facts(&mut facts, status.as_ref());
    ("Assembly", facts)
}

/// Facts for a `software-inventory` card under the §2.1 `update-service`
/// feature; the typed `ReleaseDate` instant renders as RFC 3339 so the card
/// never re-parses text, and a formatting failure simply omits the fact.
///
/// The dispatcher guarantees this receives the `SoftwareInventory` variant;
/// the fallback keeps a stable empty facts list instead of panicking if that
/// contract is ever violated.
#[cfg(any(target_arch = "wasm32", test))]
fn software_inventory_card_facts(
    resource: &CoreResourceDetailsResponse,
) -> (&'static str, Vec<ResourceFactProjection>) {
    let CoreResourceDetailsResponse::SoftwareInventory {
        software_id,
        version,
        release_date,
        status,
    } = resource
    else {
        return ("Software inventory", Vec::new());
    };
    let mut facts = Vec::new();
    push_fact(&mut facts, "Software ID", software_id.as_deref());
    push_fact(&mut facts, "Version", version.as_deref());
    push_fact(
        &mut facts,
        "Release date",
        release_date
            .as_ref()
            .and_then(|value| value.format(&Rfc3339).ok())
            .as_deref(),
    );
    push_status_facts(&mut facts, status.as_ref());
    ("Software inventory", facts)
}

/// Facts for a §2.1 event-service card; the service-enabled flag renders as
/// Yes/No and the resource-level status follows. The retry-policy fields
/// stay out of the strictly projectable field set, so the card shows the
/// service posture only.
///
/// The dispatcher guarantees this receives the `EventService` variant; the
/// fallback keeps a stable empty facts list instead of panicking if that
/// contract is ever violated.
#[cfg(any(target_arch = "wasm32", test))]
fn event_service_card_facts(
    resource: &CoreResourceDetailsResponse,
) -> (&'static str, Vec<ResourceFactProjection>) {
    let CoreResourceDetailsResponse::EventService {
        service_enabled,
        status,
    } = resource
    else {
        return ("Event Service", Vec::new());
    };
    let mut facts = Vec::new();
    push_fact(
        &mut facts,
        "Service enabled",
        service_enabled.map(|enabled| if enabled { "Yes" } else { "No" }),
    );
    push_status_facts(&mut facts, status.as_ref());
    ("Event Service", facts)
}

/// Facts for one subscription under the §2.1 `event-service` family; the
/// destination, protocol, context, and event-type filters render exactly as
/// published, so the card shows who receives which events and how.
///
/// The dispatcher guarantees this receives the `EventSubscription` variant;
/// the fallback keeps a stable empty facts list instead of panicking if that
/// contract is ever violated.
#[cfg(any(target_arch = "wasm32", test))]
fn event_subscription_card_facts(
    resource: &CoreResourceDetailsResponse,
) -> (&'static str, Vec<ResourceFactProjection>) {
    let CoreResourceDetailsResponse::EventSubscription {
        destination,
        protocol,
        context,
        event_types,
        status,
    } = resource
    else {
        return ("Event subscription", Vec::new());
    };
    let mut facts = Vec::new();
    push_fact(&mut facts, "Destination", destination.as_deref());
    push_fact(&mut facts, "Protocol", protocol.as_deref());
    push_fact(&mut facts, "Context", context.as_deref());
    push_fact(
        &mut facts,
        "Event types",
        event_types
            .as_deref()
            .map(|types| types.join(", "))
            .as_deref(),
    );
    push_status_facts(&mut facts, status.as_ref());
    ("Event subscription", facts)
}

/// Facts for a §2.1 telemetry-service card; the compiled `TelemetryService`
/// type exposes `ServiceEnabled` and the service-capacity fields, but the
/// product defers them to the 0.4.0 telemetry iteration, so the card renders
/// the resource-level status values only this round.
///
/// The dispatcher guarantees this receives the `TelemetryService` variant;
/// the fallback keeps a stable empty facts list instead of panicking if that
/// contract is ever violated.
#[cfg(any(target_arch = "wasm32", test))]
fn telemetry_service_card_facts(
    resource: &CoreResourceDetailsResponse,
) -> (&'static str, Vec<ResourceFactProjection>) {
    let CoreResourceDetailsResponse::TelemetryService { status } = resource else {
        return ("Telemetry Service", Vec::new());
    };
    let mut facts = Vec::new();
    push_status_facts(&mut facts, status.as_ref());
    ("Telemetry Service", facts)
}

/// Facts for one metric definition under the §2.1 `telemetry-service` family;
/// the units and the `MetricType` enumeration render as published, so the
/// card shows what the metric measures and how.
///
/// The dispatcher guarantees this receives the `MetricDefinition` variant;
/// the fallback keeps a stable empty facts list instead of panicking if that
/// contract is ever violated.
#[cfg(any(target_arch = "wasm32", test))]
fn metric_definition_card_facts(
    resource: &CoreResourceDetailsResponse,
) -> (&'static str, Vec<ResourceFactProjection>) {
    let CoreResourceDetailsResponse::MetricDefinition { units, metric_type } = resource else {
        return ("Metric definition", Vec::new());
    };
    let mut facts = Vec::new();
    push_fact(&mut facts, "Units", units.as_deref());
    push_fact(&mut facts, "Metric type", metric_type.as_deref());
    ("Metric definition", facts)
}

/// Facts for one metric report under the §2.1 `telemetry-service` family; the
/// derived metric-values count stays numeric as published, and the latest
/// reading renders as the newest value of the `MetricValues` array. The card
/// stays concise — the full timestamped history belongs to the 0.4.0
/// Telemetry view, not the resource card.
///
/// The dispatcher guarantees this receives the `MetricReport` variant; the
/// fallback keeps a stable empty facts list instead of panicking if that
/// contract is ever violated.
#[cfg(any(target_arch = "wasm32", test))]
fn metric_report_card_facts(
    resource: &CoreResourceDetailsResponse,
) -> (&'static str, Vec<ResourceFactProjection>) {
    let CoreResourceDetailsResponse::MetricReport {
        metric_values_count,
        metric_values,
    } = resource
    else {
        return ("Metric report", Vec::new());
    };
    let mut facts = Vec::new();
    push_u64_fact(&mut facts, "Metric values", *metric_values_count);
    // The latest reading is the newest entry that still carries a value;
    // readings without a value (explicit null) are skipped.
    push_fact(
        &mut facts,
        "Latest value",
        metric_values
            .as_ref()
            .and_then(|values| values.iter().rev().find_map(MetricValueResponse::value)),
    );
    ("Metric report", facts)
}

/// Facts for a §2.1 task-service card; the service-enabled flag renders as
/// Yes/No, the completed-task overwrite policy stays the schema enumeration
/// string, and the resource-level status follows.
///
/// The dispatcher guarantees this receives the `TaskService` variant; the
/// fallback keeps a stable empty facts list instead of panicking if that
/// contract is ever violated.
#[cfg(any(target_arch = "wasm32", test))]
fn task_service_card_facts(
    resource: &CoreResourceDetailsResponse,
) -> (&'static str, Vec<ResourceFactProjection>) {
    let CoreResourceDetailsResponse::TaskService {
        service_enabled,
        completed_task_overwrite_policy,
        status,
    } = resource
    else {
        return ("Task Service", Vec::new());
    };
    let mut facts = Vec::new();
    push_fact(
        &mut facts,
        "Service enabled",
        service_enabled.map(|enabled| if enabled { "Yes" } else { "No" }),
    );
    push_fact(
        &mut facts,
        "Completed task policy",
        completed_task_overwrite_policy.as_deref(),
    );
    push_status_facts(&mut facts, status.as_ref());
    ("Task Service", facts)
}

/// Facts for one task under the §2.1 `task-service` family; the state and
/// status enumeration strings, the numeric completion percentage, and the
/// typed RFC 3339 timeline instants render as published, so the card shows
/// the task progress without re-parsing text.
///
/// The dispatcher guarantees this receives the `Task` variant; the fallback
/// keeps a stable empty facts list instead of panicking if that contract is
/// ever violated.
#[cfg(any(target_arch = "wasm32", test))]
fn task_card_facts(
    resource: &CoreResourceDetailsResponse,
) -> (&'static str, Vec<ResourceFactProjection>) {
    let CoreResourceDetailsResponse::Task {
        task_state,
        task_status,
        percent_complete,
        start_time,
        end_time,
    } = resource
    else {
        return ("Task", Vec::new());
    };
    let mut facts = Vec::new();
    push_fact(&mut facts, "Task state", task_state.as_deref());
    push_fact(&mut facts, "Task status", task_status.as_deref());
    push_u64_fact(&mut facts, "Percent complete", *percent_complete);
    push_fact(
        &mut facts,
        "Start time",
        start_time
            .as_ref()
            .and_then(|value| value.format(&Rfc3339).ok())
            .as_deref(),
    );
    push_fact(
        &mut facts,
        "End time",
        end_time
            .as_ref()
            .and_then(|value| value.format(&Rfc3339).ok())
            .as_deref(),
    );
    ("Task", facts)
}

/// Facts for the Dell OEM card under the §0.5.0 `oem-dell-attributes`
/// family.
///
/// The manager `DellAttributes` document is the only Dell OEM surface
/// nv-redfish 0.13 compiles, and the five projected fields are the iDRAC
/// identity attributes the api contract pins on it. Every optional value
/// renders only when the document published the attribute key, and the
/// vendor's original text is kept verbatim per §12.3.
///
/// The dispatcher guarantees this receives the `OemDell` variant; the
/// fallback keeps a stable empty facts list instead of panicking if that
/// contract is ever violated.
#[cfg(any(target_arch = "wasm32", test))]
fn oem_dell_card_facts(
    resource: &CoreResourceDetailsResponse,
) -> (&'static str, Vec<ResourceFactProjection>) {
    let CoreResourceDetailsResponse::OemDell {
        server_model,
        server_service_tag,
        server_generation,
        server_bmc_mac_address,
        server_name,
    } = resource
    else {
        return ("Dell OEM", Vec::new());
    };
    let mut facts = Vec::new();
    push_fact(&mut facts, "Model", server_model.as_deref());
    push_fact(&mut facts, "Service tag", server_service_tag.as_deref());
    push_fact(&mut facts, "Generation", server_generation.as_deref());
    push_fact(
        &mut facts,
        "BMC MAC address",
        server_bmc_mac_address.as_deref(),
    );
    push_fact(&mut facts, "Server name", server_name.as_deref());
    ("Dell OEM", facts)
}

/// Facts for the Supermicro `SysLockdown` OEM card under the §0.5.0
/// `oem-supermicro` family.
///
/// The manager `SysLockdown` document's only substantive typed field is the
/// `SysLockdownEnabled` boolean, rendered in its canonical wire spelling
/// (`true` / `false`) per §12.3 — the product never reinterprets the vendor
/// value. The optional value renders only when the document published the
/// property.
///
/// The dispatcher guarantees this receives the `OemSmcSysLockdown` variant;
/// the fallback keeps a stable empty facts list instead of panicking if that
/// contract is ever violated.
#[cfg(any(target_arch = "wasm32", test))]
fn oem_smc_sys_lockdown_card_facts(
    resource: &CoreResourceDetailsResponse,
) -> (&'static str, Vec<ResourceFactProjection>) {
    let CoreResourceDetailsResponse::OemSmcSysLockdown {
        sys_lockdown_enabled,
    } = resource
    else {
        return ("Supermicro SysLockdown", Vec::new());
    };
    let mut facts = Vec::new();
    push_fact(
        &mut facts,
        "SysLockdown enabled",
        sys_lockdown_enabled.map(|enabled| if enabled { "true" } else { "false" }),
    );
    ("Supermicro SysLockdown", facts)
}

/// Facts for the Supermicro `KcsInterface` OEM card under the §0.5.0
/// `oem-supermicro` family.
///
/// The manager `KCSInterface` document's `Privilege` value is the vendor's
/// enum spelling kept verbatim per §12.3 (e.g. `Administrator`, `DisableKCS`)
/// — never translated into a product label. The optional value renders only
/// when the document published the property.
///
/// The dispatcher guarantees this receives the `OemSmcKcsInterface` variant;
/// the fallback keeps a stable empty facts list instead of panicking if that
/// contract is ever violated.
#[cfg(any(target_arch = "wasm32", test))]
fn oem_smc_kcs_interface_card_facts(
    resource: &CoreResourceDetailsResponse,
) -> (&'static str, Vec<ResourceFactProjection>) {
    let CoreResourceDetailsResponse::OemSmcKcsInterface { privilege } = resource else {
        return ("Supermicro KCS Interface", Vec::new());
    };
    let mut facts = Vec::new();
    push_fact(&mut facts, "Privilege", privilege.as_deref());
    ("Supermicro KCS Interface", facts)
}

/// Facts for the NVIDIA `SystemConfigProfile` chain-root card under the
/// §0.5.0 `oem-nvidia-profiles` family.
///
/// The `Truststore` metadata renders the presence of each certificate-store
/// link in its canonical wire spelling (`true` / `false`) per §12.3; the
/// certificate payloads behind the links stay out of the product entirely
/// (the sensitive surface is deferred).
///
/// The dispatcher guarantees this receives the
/// `OemNvidiaSystemConfigProfile` variant; the fallback keeps a stable empty
/// facts list instead of panicking if that contract is ever violated.
#[cfg(any(target_arch = "wasm32", test))]
fn oem_nvidia_system_config_profile_card_facts(
    resource: &CoreResourceDetailsResponse,
) -> (&'static str, Vec<ResourceFactProjection>) {
    let CoreResourceDetailsResponse::OemNvidiaSystemConfigProfile { truststore } = resource else {
        return ("NVIDIA System Config Profile", Vec::new());
    };
    let mut facts = Vec::new();
    if let Some(truststore) = truststore {
        push_boolean_fact(
            &mut facts,
            "NVIDIA certificates",
            truststore.nvidia_certificates(),
        );
        push_boolean_fact(
            &mut facts,
            "OEM certificates",
            truststore.oem_certificates(),
        );
    }
    ("NVIDIA System Config Profile", facts)
}

/// Facts for the NVIDIA `SystemConfigProfileStatus` card under the §0.5.0
/// `oem-nvidia-profiles` family.
///
/// The compiled status fields render verbatim per §12.3: the
/// `PendingList.Activation` text, the numeric profile indices, and the
/// `FactoryResetStatus` text. Each optional value renders only when the
/// document published the property.
///
/// The dispatcher guarantees this receives the
/// `OemNvidiaSystemConfigProfileStatus` variant; the fallback keeps a stable
/// empty facts list instead of panicking if that contract is ever violated.
#[cfg(any(target_arch = "wasm32", test))]
fn oem_nvidia_system_config_profile_status_card_facts(
    resource: &CoreResourceDetailsResponse,
) -> (&'static str, Vec<ResourceFactProjection>) {
    let CoreResourceDetailsResponse::OemNvidiaSystemConfigProfileStatus {
        pending_list_activation,
        active_profile_index,
        bmc_profile_version,
        factory_reset_status,
        default_profile_index,
    } = resource
    else {
        return ("NVIDIA Profile Status", Vec::new());
    };
    let mut facts = Vec::new();
    push_fact(
        &mut facts,
        "Pending activation",
        pending_list_activation.as_deref(),
    );
    push_i64_fact(&mut facts, "Active profile index", *active_profile_index);
    push_i64_fact(&mut facts, "BMC profile version", *bmc_profile_version);
    push_fact(
        &mut facts,
        "Factory reset status",
        factory_reset_status.as_deref(),
    );
    push_i64_fact(&mut facts, "Default profile index", *default_profile_index);
    ("NVIDIA Profile Status", facts)
}

/// Facts for the NVIDIA `SystemProfile` card under the §0.5.0
/// `oem-nvidia-profiles` family.
///
/// The compiled metadata fields render verbatim per §12.3: the `Default`
/// boolean in its canonical wire spelling, the `Owner` / `UUID` /
/// `ProfileName` texts, and the numeric `Version`. Each optional value
/// renders only when the document published the property.
///
/// The dispatcher guarantees this receives the `OemNvidiaSystemProfile`
/// variant; the fallback keeps a stable empty facts list instead of
/// panicking if that contract is ever violated.
#[cfg(any(target_arch = "wasm32", test))]
fn oem_nvidia_system_profile_card_facts(
    resource: &CoreResourceDetailsResponse,
) -> (&'static str, Vec<ResourceFactProjection>) {
    let CoreResourceDetailsResponse::OemNvidiaSystemProfile {
        default,
        owner,
        uuid,
        version,
        profile_name,
    } = resource
    else {
        return ("NVIDIA System Profile", Vec::new());
    };
    let mut facts = Vec::new();
    push_boolean_fact(&mut facts, "Default", *default);
    push_fact(&mut facts, "Owner", owner.as_deref());
    push_fact(&mut facts, "UUID", uuid.as_deref());
    push_i64_fact(&mut facts, "Version", *version);
    push_fact(&mut facts, "Profile name", profile_name.as_deref());
    ("NVIDIA System Profile", facts)
}

/// Facts for the NVIDIA `SystemProfileFile` card under the §0.5.0
/// `oem-nvidia-profiles` family.
///
/// The compiled file fields render verbatim per §12.3: the `Metadata`
/// flags and texts plus the base64 `Profile` content, never re-interpreted
/// by the product.
///
/// The dispatcher guarantees this receives the `OemNvidiaSystemProfileFile`
/// variant; the fallback keeps a stable empty facts list instead of
/// panicking if that contract is ever violated.
#[cfg(any(target_arch = "wasm32", test))]
fn oem_nvidia_system_profile_file_card_facts(
    resource: &CoreResourceDetailsResponse,
) -> (&'static str, Vec<ResourceFactProjection>) {
    let CoreResourceDetailsResponse::OemNvidiaSystemProfileFile {
        metadata_activate,
        metadata_delete,
        metadata_origin_profile_uuid,
        metadata_more_profiles,
        metadata_project_name,
        metadata_uuid,
        profile,
    } = resource
    else {
        return ("NVIDIA Profile File", Vec::new());
    };
    let mut facts = Vec::new();
    push_boolean_fact(&mut facts, "Activate", *metadata_activate);
    push_boolean_fact(&mut facts, "Delete", *metadata_delete);
    push_fact(
        &mut facts,
        "Origin profile UUID",
        metadata_origin_profile_uuid.as_deref(),
    );
    push_boolean_fact(&mut facts, "More profiles", *metadata_more_profiles);
    push_fact(&mut facts, "Project name", metadata_project_name.as_deref());
    push_fact(&mut facts, "UUID", metadata_uuid.as_deref());
    push_fact(&mut facts, "Profile", profile.as_deref());
    ("NVIDIA Profile File", facts)
}

/// Facts for the NVIDIA `NvidiaPowerComplianceManager` chain-root card under
/// the §0.5.0 `oem-nvidia-power-management` family.
///
/// The compiled `ManagerType` enumeration renders verbatim per §12.3 (the
/// vendor's wire spelling, e.g. `PowerManager`), never relabeled. The value
/// renders only when the document published the property.
///
/// The dispatcher guarantees this receives the `OemNvidiaPowerCompliance`
/// variant; the fallback keeps a stable empty facts list instead of
/// panicking if that contract is ever violated.
#[cfg(any(target_arch = "wasm32", test))]
fn oem_nvidia_power_compliance_card_facts(
    resource: &CoreResourceDetailsResponse,
) -> (&'static str, Vec<ResourceFactProjection>) {
    let CoreResourceDetailsResponse::OemNvidiaPowerCompliance { manager_type } = resource else {
        return ("NVIDIA Power Compliance", Vec::new());
    };
    let mut facts = Vec::new();
    push_fact(&mut facts, "Manager type", manager_type.as_deref());
    ("NVIDIA Power Compliance", facts)
}

/// Facts for the NVIDIA `NvidiaPowerDomain` card under the §0.5.0
/// `oem-nvidia-power-management` family.
///
/// The compiled scalar fields render verbatim per §12.3: the numeric
/// `Value`, the `Type` / `Unit` / `SensorReadingType` / `SensorImpl`
/// enumeration spellings. Each optional value renders only when the document
/// published the property.
///
/// The dispatcher guarantees this receives the `OemNvidiaPowerDomain`
/// variant; the fallback keeps a stable empty facts list instead of
/// panicking if that contract is ever violated.
#[cfg(any(target_arch = "wasm32", test))]
fn oem_nvidia_power_domain_card_facts(
    resource: &CoreResourceDetailsResponse,
) -> (&'static str, Vec<ResourceFactProjection>) {
    let CoreResourceDetailsResponse::OemNvidiaPowerDomain {
        value,
        r#type,
        unit,
        sensor_reading_type,
        sensor_impl,
    } = resource
    else {
        return ("NVIDIA Power Domain", Vec::new());
    };
    let mut facts = Vec::new();
    push_i64_fact(&mut facts, "Value", *value);
    push_fact(&mut facts, "Type", r#type.as_deref());
    push_fact(&mut facts, "Unit", unit.as_deref());
    push_fact(
        &mut facts,
        "Sensor reading type",
        sensor_reading_type.as_deref(),
    );
    push_fact(&mut facts, "Sensor implementation", sensor_impl.as_deref());
    ("NVIDIA Power Domain", facts)
}

/// Facts for the NVIDIA `NvidiaPowerPolicy` card under the §0.5.0
/// `oem-nvidia-power-management` family (the `ACLossPolicy` and
/// `PSUCompliancePolicy` singletons share one card shape).
///
/// The compiled scalar fields render verbatim per §12.3: the
/// `AutoDeassertPowerBrake` boolean in its canonical wire spelling, the
/// numeric `Min` / `Max` thresholds, the `Type` / `Unit` enumeration
/// spellings, and the `PolicyActions` enumeration spelling. Each optional
/// value renders only when the document published the property.
///
/// The dispatcher guarantees this receives the `OemNvidiaPowerPolicy`
/// variant; the fallback keeps a stable empty facts list instead of
/// panicking if that contract is ever violated.
#[cfg(any(target_arch = "wasm32", test))]
fn oem_nvidia_power_policy_card_facts(
    resource: &CoreResourceDetailsResponse,
) -> (&'static str, Vec<ResourceFactProjection>) {
    let CoreResourceDetailsResponse::OemNvidiaPowerPolicy {
        auto_deassert_power_brake,
        min,
        max,
        r#type,
        unit,
        policy_actions,
    } = resource
    else {
        return ("NVIDIA Power Policy", Vec::new());
    };
    let mut facts = Vec::new();
    push_boolean_fact(
        &mut facts,
        "Auto deassert power brake",
        *auto_deassert_power_brake,
    );
    push_i64_fact(&mut facts, "Min", *min);
    push_i64_fact(&mut facts, "Max", *max);
    push_fact(&mut facts, "Type", r#type.as_deref());
    push_fact(&mut facts, "Unit", unit.as_deref());
    push_fact(&mut facts, "Policy actions", policy_actions.as_deref());
    ("NVIDIA Power Policy", facts)
}

/// Facts for the NVIDIA `NvidiaManagedEntityGroup` card under the §0.5.0
/// `oem-nvidia-power-management` family.
///
/// The compiled `CurrentManagedEntityId` text renders verbatim per §12.3.
/// The value renders only when the document published the property.
///
/// The dispatcher guarantees this receives the `OemNvidiaManagedEntityGroup`
/// variant; the fallback keeps a stable empty facts list instead of
/// panicking if that contract is ever violated.
#[cfg(any(target_arch = "wasm32", test))]
fn oem_nvidia_managed_entity_group_card_facts(
    resource: &CoreResourceDetailsResponse,
) -> (&'static str, Vec<ResourceFactProjection>) {
    let CoreResourceDetailsResponse::OemNvidiaManagedEntityGroup {
        current_managed_entity_id,
    } = resource
    else {
        return ("NVIDIA Managed Entity Group", Vec::new());
    };
    let mut facts = Vec::new();
    push_fact(
        &mut facts,
        "Current managed entity",
        current_managed_entity_id.as_deref(),
    );
    ("NVIDIA Managed Entity Group", facts)
}

/// Facts for the NVIDIA `NvidiaPowerStateGroup` card under the §0.5.0
/// `oem-nvidia-power-management` family.
///
/// The compiled scalar fields render verbatim per §12.3: the `PscId` text
/// and the numeric `GeneratedWatts` / `NumberOfPscs` / `NumberOfLocalPsus`.
/// Each optional value renders only when the document published the
/// property.
///
/// The dispatcher guarantees this receives the `OemNvidiaPowerStateGroup`
/// variant; the fallback keeps a stable empty facts list instead of
/// panicking if that contract is ever violated.
#[cfg(any(target_arch = "wasm32", test))]
fn oem_nvidia_power_state_group_card_facts(
    resource: &CoreResourceDetailsResponse,
) -> (&'static str, Vec<ResourceFactProjection>) {
    let CoreResourceDetailsResponse::OemNvidiaPowerStateGroup {
        psc_id,
        generated_watts,
        number_of_pscs,
        number_of_local_psus,
    } = resource
    else {
        return ("NVIDIA Power State Group", Vec::new());
    };
    let mut facts = Vec::new();
    push_fact(&mut facts, "PSC ID", psc_id.as_deref());
    push_i64_fact(&mut facts, "Generated watts", *generated_watts);
    push_i64_fact(&mut facts, "Number of PSCs", *number_of_pscs);
    push_i64_fact(&mut facts, "Number of local PSUs", *number_of_local_psus);
    ("NVIDIA Power State Group", facts)
}

/// Facts for the NVIDIA `NvidiaPscState` card under the §0.5.0
/// `oem-nvidia-power-management` family.
///
/// The compiled scalar fields render verbatim per §12.3: the `PscId` text,
/// the numeric `NumOfOperationalPsus` / `MillisecondsSinceLastHeartbeat`,
/// the `PowerBrakeAssert` boolean in its canonical wire spelling, and the
/// `Status` enumeration spelling. Each optional value renders only when the
/// document published the property.
///
/// The dispatcher guarantees this receives the `OemNvidiaPscState` variant;
/// the fallback keeps a stable empty facts list instead of panicking if that
/// contract is ever violated.
#[cfg(any(target_arch = "wasm32", test))]
fn oem_nvidia_psc_state_card_facts(
    resource: &CoreResourceDetailsResponse,
) -> (&'static str, Vec<ResourceFactProjection>) {
    let CoreResourceDetailsResponse::OemNvidiaPscState {
        psc_id,
        num_of_operational_psus,
        power_brake_assert,
        milliseconds_since_last_heartbeat,
        status,
    } = resource
    else {
        return ("NVIDIA PSC State", Vec::new());
    };
    let mut facts = Vec::new();
    push_fact(&mut facts, "PSC ID", psc_id.as_deref());
    push_i64_fact(&mut facts, "Operational PSUs", *num_of_operational_psus);
    push_boolean_fact(&mut facts, "Power brake assert", *power_brake_assert);
    push_i64_fact(
        &mut facts,
        "Milliseconds since last heartbeat",
        *milliseconds_since_last_heartbeat,
    );
    push_fact(&mut facts, "Status", status.as_deref());
    ("NVIDIA PSC State", facts)
}

/// Facts for the NVIDIA `NvidiaPsuState` card under the §0.5.0
/// `oem-nvidia-power-management` family.
///
/// The compiled scalar fields render verbatim per §12.3: the `PsuId` text
/// and the `Presence` / `Input1Active` / `Input2Active` booleans in their
/// canonical wire spellings. Each optional value renders only when the
/// document published the property.
///
/// The dispatcher guarantees this receives the `OemNvidiaPsuState` variant;
/// the fallback keeps a stable empty facts list instead of panicking if that
/// contract is ever violated.
#[cfg(any(target_arch = "wasm32", test))]
fn oem_nvidia_psu_state_card_facts(
    resource: &CoreResourceDetailsResponse,
) -> (&'static str, Vec<ResourceFactProjection>) {
    let CoreResourceDetailsResponse::OemNvidiaPsuState {
        psu_id,
        presence,
        input1active,
        input2active,
    } = resource
    else {
        return ("NVIDIA PSU State", Vec::new());
    };
    let mut facts = Vec::new();
    push_fact(&mut facts, "PSU ID", psu_id.as_deref());
    push_boolean_fact(&mut facts, "Presence", *presence);
    push_boolean_fact(&mut facts, "Input 1 active", *input1active);
    push_boolean_fact(&mut facts, "Input 2 active", *input2active);
    ("NVIDIA PSU State", facts)
}

/// Facts for the NVIDIA `NvidiaPsuRedundancy` card under the §0.5.0
/// `oem-nvidia-power-management` family.
///
/// The compiled scalar fields render verbatim per §12.3: the
/// `MaxNumSupported` / `MinNumNeeded` texts and the `RedundancySetting`
/// enumeration spelling. Each optional value renders only when the document
/// published the property.
///
/// The dispatcher guarantees this receives the `OemNvidiaPsuRedundancy`
/// variant; the fallback keeps a stable empty facts list instead of
/// panicking if that contract is ever violated.
#[cfg(any(target_arch = "wasm32", test))]
fn oem_nvidia_psu_redundancy_card_facts(
    resource: &CoreResourceDetailsResponse,
) -> (&'static str, Vec<ResourceFactProjection>) {
    let CoreResourceDetailsResponse::OemNvidiaPsuRedundancy {
        max_num_supported,
        min_num_needed,
        redundancy_setting,
    } = resource
    else {
        return ("NVIDIA PSU Redundancy", Vec::new());
    };
    let mut facts = Vec::new();
    push_fact(
        &mut facts,
        "Max PSUs supported",
        max_num_supported.as_deref(),
    );
    push_fact(&mut facts, "Min PSUs needed", min_num_needed.as_deref());
    push_fact(
        &mut facts,
        "Redundancy setting",
        redundancy_setting.as_deref(),
    );
    ("NVIDIA PSU Redundancy", facts)
}

/// Facts for the NVIDIA `NvidiaManagedEntity` card under the §0.5.0
/// `oem-nvidia-power-management` family.
///
/// The compiled scalar fields render verbatim per §12.3: the
/// `TransportProtocol` enumeration spelling, the `IPv4Address` /
/// `IPv6Address` address texts, and the numeric `Port`. Each optional value
/// renders only when the document published the property.
///
/// The dispatcher guarantees this receives the `OemNvidiaManagedEntity`
/// variant; the fallback keeps a stable empty facts list instead of
/// panicking if that contract is ever violated.
#[cfg(any(target_arch = "wasm32", test))]
fn oem_nvidia_managed_entity_card_facts(
    resource: &CoreResourceDetailsResponse,
) -> (&'static str, Vec<ResourceFactProjection>) {
    let CoreResourceDetailsResponse::OemNvidiaManagedEntity {
        transport_protocol,
        ipv4_address,
        ipv6_address,
        port,
    } = resource
    else {
        return ("NVIDIA Managed Entity", Vec::new());
    };
    let mut facts = Vec::new();
    push_fact(
        &mut facts,
        "Transport protocol",
        transport_protocol.as_deref(),
    );
    push_fact(&mut facts, "IPv4 address", ipv4_address.as_deref());
    push_fact(&mut facts, "IPv6 address", ipv6_address.as_deref());
    push_i64_fact(&mut facts, "Port", *port);
    ("NVIDIA Managed Entity", facts)
}

/// Facts for the Lenovo `SecurityService` OEM card under the §0.5.0
/// `oem-lenovo` family.
///
/// The `FWRollback` value is the vendor's enum spelling kept verbatim per
/// §12.3 (e.g. `Enabled`, `Disabled`, or `UnsupportedValue` for a value this
/// build cannot classify) — never translated into a product label. The
/// optional value renders only when the document published the property.
///
/// The dispatcher guarantees this receives the `OemLenovoSecurityService`
/// variant; the fallback keeps a stable empty facts list instead of panicking
/// if that contract is ever violated.
#[cfg(any(target_arch = "wasm32", test))]
fn oem_lenovo_security_service_card_facts(
    resource: &CoreResourceDetailsResponse,
) -> (&'static str, Vec<ResourceFactProjection>) {
    let CoreResourceDetailsResponse::OemLenovoSecurityService { fw_rollback } = resource else {
        return ("Lenovo Security Service", Vec::new());
    };
    let mut facts = Vec::new();
    push_fact(&mut facts, "Firmware rollback", fw_rollback.as_deref());
    ("Lenovo Security Service", facts)
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
/// Renders one numeric resource fact only when a value exists, keeping the
/// facts list free of placeholder text for absent observations.
fn push_u64_fact(facts: &mut Vec<ResourceFactProjection>, label: &'static str, value: Option<u64>) {
    if let Some(value) = value {
        facts.push(ResourceFactProjection {
            label,
            value: value.to_string(),
        });
    }
}

#[cfg(any(target_arch = "wasm32", test))]
/// Renders one signed numeric resource fact (the NVIDIA profile indices)
/// only when a value exists, keeping the facts list free of placeholder text
/// for absent observations.
fn push_i64_fact(facts: &mut Vec<ResourceFactProjection>, label: &'static str, value: Option<i64>) {
    if let Some(value) = value {
        facts.push(ResourceFactProjection {
            label,
            value: value.to_string(),
        });
    }
}

#[cfg(any(target_arch = "wasm32", test))]
/// Renders one boolean resource fact in its canonical wire spelling
/// (`true` / `false`) only when a value exists, keeping the facts list free
/// of placeholder text for absent observations.
fn push_boolean_fact(
    facts: &mut Vec<ResourceFactProjection>,
    label: &'static str,
    value: Option<bool>,
) {
    if let Some(value) = value {
        facts.push(ResourceFactProjection {
            label,
            value: if value { "true" } else { "false" }.to_owned(),
        });
    }
}

#[cfg(any(target_arch = "wasm32", test))]
/// Renders one decimal resource fact (a telemetry reading or set point) only
/// when a value exists, keeping the facts list free of placeholder text for
/// absent observations.
fn push_f64_fact(facts: &mut Vec<ResourceFactProjection>, label: &'static str, value: Option<f64>) {
    if let Some(value) = value {
        facts.push(ResourceFactProjection {
            label,
            value: value.to_string(),
        });
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
/// The §16.1 role of the signed-in principal, mirrored from the wire.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RoleView {
    Administrator,
    Operator,
    Viewer,
}

#[cfg(any(target_arch = "wasm32", test))]
impl RoleView {
    const fn from_wire(role: RoleResponse) -> Self {
        match role {
            RoleResponse::Administrator => Self::Administrator,
            RoleResponse::Operator => Self::Operator,
            RoleResponse::Viewer => Self::Viewer,
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Administrator => "Administrator",
            Self::Operator => "Operator",
            Self::Viewer => "Viewer",
        }
    }
}

#[cfg(any(target_arch = "wasm32", test))]
/// One of the top-level console sections reachable from the navigation bar.
///
/// `Capabilities` is a per-endpoint drill-down: the navigation entry only
/// appears while a capability target is selected, and entering it from an
/// endpoint card always carries that endpoint's identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConsoleView {
    Overview,
    Groups,
    Credentials,
    AddEndpoint,
    Import,
    Audit,
    Capabilities,
    Operations,
    Events,
    Artifacts,
    Telemetry,
    Diagnostics,
    Users,
    Sessions,
    // The 0.7.0 center console (§12.1 "中心连接", audit follow-up S8):
    // the registered site list with the aggregated endpoint detail, the
    // §15.6 operation tracking with the submit form, and the binding
    // management with the one-time code.
    CenterSites,
    CenterOperations,
    CenterBindings,
}

#[cfg(any(target_arch = "wasm32", test))]
impl ConsoleView {
    const ALL: [ConsoleView; 17] = [
        Self::Overview,
        Self::Groups,
        Self::Credentials,
        Self::AddEndpoint,
        Self::Import,
        Self::Audit,
        Self::Capabilities,
        Self::Operations,
        Self::Events,
        Self::Artifacts,
        Self::Telemetry,
        Self::Diagnostics,
        Self::Users,
        Self::Sessions,
        Self::CenterSites,
        Self::CenterOperations,
        Self::CenterBindings,
    ];

    const fn label(self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Groups => "Groups",
            Self::Credentials => "Credentials",
            Self::AddEndpoint => "Add endpoint",
            Self::Import => "Import",
            Self::Audit => "Audit",
            Self::Capabilities => "Capabilities",
            Self::Operations => "Operations",
            Self::Events => "Events",
            Self::Artifacts => "Artifacts",
            Self::Telemetry => "Telemetry",
            Self::Diagnostics => "Diagnostics",
            Self::Users => "Users",
            Self::Sessions => "Sessions",
            Self::CenterSites => "Center sites",
            Self::CenterOperations => "Center operations",
            Self::CenterBindings => "Center bindings",
        }
    }

    /// Whether this view belongs to the center console surface (audit
    /// follow-up F2/S8): the center views render only on the Center
    /// posture, and every edge view renders only on the Edge postures.
    #[must_use]
    pub const fn is_center_view(self) -> bool {
        matches!(
            self,
            Self::CenterSites | Self::CenterOperations | Self::CenterBindings
        )
    }

    /// Whether the §16.1 role of the signed-in principal may open this
    /// view: the user and session administration views are Administrator
    /// only, the center binding management is Administrator only (the
    /// §16.1 center binding matrix), every other view is open to all three
    /// roles.
    const fn allowed_for(self, role: Option<RoleView>) -> bool {
        match self {
            Self::Users | Self::Sessions | Self::CenterBindings => {
                matches!(role, Some(RoleView::Administrator))
            }
            _ => true,
        }
    }
}

/// One registered site as the center's §15.5 site view projects it.
#[cfg(any(target_arch = "wasm32", test))]
#[derive(Clone, Debug, Eq, PartialEq)]
struct CenterSiteCardProjection {
    site_id: String,
    display_name: String,
    binding: Option<CenterBindingStateView>,
    online: bool,
    endpoint_count: u64,
    last_refresh_at: Option<OffsetDateTime>,
}

/// The binding phase of one registered site (design D2).
#[cfg(any(target_arch = "wasm32", test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CenterBindingStateView {
    Pending,
    Bound,
    Revoked,
}

/// One projected remote endpoint of the center's §15.5 endpoint view.
#[cfg(any(target_arch = "wasm32", test))]
#[derive(Clone, Debug, Eq, PartialEq)]
struct CenterEndpointCardProjection {
    site_id: Option<String>,
    endpoint_id: String,
    display_name: String,
    address: String,
    health: String,
    refresh_generation: u64,
}

#[cfg(any(target_arch = "wasm32", test))]
/// One center-dispatched operation in the center's tracking view (§15.6).
#[cfg(any(target_arch = "wasm32", test))]
#[derive(Clone, Debug, Eq, PartialEq)]
struct CenterOperationCardProjection {
    operation_id: String,
    site_id: Option<String>,
    endpoint_id: String,
    command: String,
    target: Option<String>,
    state: String,
    actor: Option<String>,
    created_at: OffsetDateTime,
}

#[cfg(any(target_arch = "wasm32", test))]
/// The §15.6 dispatch draft of the center operation form: the site, the
/// projected endpoint, the typed command target, and the command-family
/// parameters. The command itself is built by the edge form machinery
/// ([`OperationFormDraft`]'s per-family validation), so the two forms
/// cannot drift apart on what makes a complete command.
#[cfg(any(target_arch = "wasm32", test))]
#[derive(Clone, Debug, Eq, PartialEq)]
struct CenterOperationDraft {
    site_id: String,
    endpoint_id: String,
    target: String,
    family: Option<CommandFamilyView>,
    reset_type: Option<ResetTypeView>,
    boot_source: Option<BootSourceView>,
    boot_enabled: Option<BootEnabledView>,
    boot_mode: Option<BootModeView>,
    secure_boot_action: Option<SecureBootActionView>,
    reset_keys_type: Option<ResetKeysTypeView>,
    event_action: Option<EventActionView>,
    destination: String,
    protocol: Option<EventProtocolView>,
    event_types: Vec<EventTypeView>,
    subscription_id: String,
}

#[cfg(any(target_arch = "wasm32", test))]
impl CenterOperationDraft {
    /// Builds an empty draft: no site, no endpoint, no family.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            site_id: String::new(),
            endpoint_id: String::new(),
            target: String::new(),
            family: None,
            reset_type: None,
            boot_source: None,
            boot_enabled: None,
            boot_mode: None,
            secure_boot_action: None,
            reset_keys_type: None,
            event_action: None,
            destination: String::new(),
            protocol: None,
            event_types: Vec::new(),
            subscription_id: String::new(),
        }
    }

    /// Builds the typed §15.6 submission payload.
    ///
    /// The command validation is the edge form's own: the draft is folded
    /// into an [`OperationFormDraft`] with the chosen endpoint as its
    /// single target, so a family's parameter rules (and their error
    /// messages) are exactly the ones the site console enforces. The
    /// center-specific fields — the site and the target — are validated
    /// here.
    ///
    /// # Errors
    ///
    /// Returns the first invalid field as [`CenterOperationDraftError`].
    pub fn try_build(&self) -> Result<CenterOperationSubmission, CenterOperationDraftError> {
        if self.site_id.trim().is_empty() {
            return Err(CenterOperationDraftError::SiteRequired);
        }
        if self.endpoint_id.trim().is_empty() {
            return Err(CenterOperationDraftError::EndpointRequired);
        }
        if self.target.trim().is_empty() {
            return Err(CenterOperationDraftError::TargetRequired);
        }
        let mut form = OperationFormDraft::new();
        form.selected_endpoint_ids = vec![self.endpoint_id.clone()];
        form.family = self.family;
        form.reset_type = self.reset_type;
        form.boot_source = self.boot_source;
        form.boot_enabled = self.boot_enabled;
        form.boot_mode = self.boot_mode;
        form.secure_boot_action = self.secure_boot_action;
        form.reset_keys_type = self.reset_keys_type;
        form.event_action = self.event_action;
        form.destination.clone_from(&self.destination);
        form.protocol = self.protocol;
        form.event_types.clone_from(&self.event_types);
        form.subscription_id.clone_from(&self.subscription_id);
        let command = form
            .try_build()
            .map_err(CenterOperationDraftError::Command)?;
        let command = build_command(&command).map_err(CenterOperationDraftError::Command)?;
        Ok(CenterOperationSubmission {
            site_id: self.site_id.trim().to_owned(),
            endpoint_id: self.endpoint_id.trim().to_owned(),
            target: self.target.trim().to_owned(),
            command,
        })
    }
}

/// The validated §15.6 submission payload of the center operation form:
/// the wire contract of `CenterOperationSubmitRequest`.
#[cfg(any(target_arch = "wasm32", test))]
#[derive(Clone, Debug, Eq, PartialEq)]
struct CenterOperationSubmission {
    site_id: String,
    endpoint_id: String,
    target: String,
    command: RedfishCommand,
}

/// Why one center operation submission is incomplete.
#[cfg(any(target_arch = "wasm32", test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CenterOperationDraftError {
    SiteRequired,
    EndpointRequired,
    TargetRequired,
    Command(OperationFormError),
}

#[cfg(any(target_arch = "wasm32", test))]
#[cfg(any(target_arch = "wasm32", test))]
impl From<&CenterSiteResponse> for CenterSiteCardProjection {
    fn from(site: &CenterSiteResponse) -> Self {
        Self {
            site_id: site.site_id().to_string(),
            display_name: site.display_name().to_owned(),
            binding: site.binding().map(|binding| match binding {
                CenterBindingStateResponse::Pending => CenterBindingStateView::Pending,
                CenterBindingStateResponse::Bound => CenterBindingStateView::Bound,
                CenterBindingStateResponse::Revoked => CenterBindingStateView::Revoked,
            }),
            online: site.online(),
            endpoint_count: site.endpoint_count(),
            last_refresh_at: site.last_refresh_at(),
        }
    }
}

#[cfg(any(target_arch = "wasm32", test))]
impl From<&CenterEndpointViewResponse> for CenterEndpointCardProjection {
    fn from(endpoint: &CenterEndpointViewResponse) -> Self {
        Self {
            site_id: endpoint.site_id().map(|site| site.to_string()),
            endpoint_id: endpoint.endpoint_id().to_string(),
            display_name: endpoint.display_name().to_owned(),
            address: endpoint.address().to_owned(),
            health: endpoint.health().to_owned(),
            refresh_generation: endpoint.refresh_generation(),
        }
    }
}

#[cfg(any(target_arch = "wasm32", test))]
impl From<&CenterOperationResponse> for CenterOperationCardProjection {
    fn from(operation: &CenterOperationResponse) -> Self {
        let summary = wire_command_summary(operation.command());
        Self {
            operation_id: operation.operation_id().to_string(),
            site_id: operation.site_id().map(|site| site.to_string()),
            endpoint_id: operation.endpoint_id().to_string(),
            command: format!("{} · {}", summary.family, summary.payload),
            target: operation.target().map(str::to_owned),
            state: OperationStateView::from(operation.state())
                .label()
                .to_owned(),
            actor: operation.actor().map(str::to_owned),
            created_at: operation.created_at(),
        }
    }
}

#[cfg(any(target_arch = "wasm32", test))]
/// Why the capability matrix of one endpoint could not be loaded.
///
/// The three variants map the route contract (404, transport/other status,
/// unparseable body) to static copy. A 400 cannot originate from this UI
/// because endpoint ids always come from the local inventory, so it folds
/// into `Unavailable` like 503.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CapabilityLoadFailure {
    /// The route answered 404: the endpoint does not exist in the product.
    EndpointNotFound,
    /// The request failed on the network or the route answered 4xx/5xx.
    Unavailable,
    /// The route answered 200 with a body that violates the shared strict
    /// capability-inventory contract.
    Malformed,
}

#[cfg(any(target_arch = "wasm32", test))]
impl CapabilityLoadFailure {
    const fn message(self) -> &'static str {
        match self {
            Self::EndpointNotFound => "This endpoint no longer exists.",
            Self::Unavailable => "The capability list is temporarily unavailable.",
            Self::Malformed => "The server response could not be parsed.",
        }
    }
}

#[cfg(any(target_arch = "wasm32", test))]
/// The lazy-loading state of one endpoint's capability matrix section.
#[derive(Clone, Debug, Eq, PartialEq)]
enum CapabilityMatrixState {
    Idle,
    Loading,
    Ready(CapabilityMatrixProjection),
    Failed(CapabilityLoadFailure),
}

#[cfg(any(target_arch = "wasm32", test))]
impl CapabilityMatrixState {
    const fn is_ready(&self) -> bool {
        matches!(self, Self::Ready(_))
    }

    const fn is_loading(&self) -> bool {
        matches!(self, Self::Loading)
    }

    const fn is_failed(&self) -> bool {
        matches!(self, Self::Failed(_))
    }

    const fn failure_message(&self) -> &'static str {
        match self {
            Self::Failed(failure) => failure.message(),
            Self::Idle | Self::Loading | Self::Ready(_) => "",
        }
    }

    fn has_empty_matrix(&self) -> bool {
        matches!(self, Self::Ready(matrix) if matrix.groups.is_empty())
    }

    /// One-line summary of the loaded matrix, e.g. "30 capabilities across
    /// 22 pages".
    fn summary_text(&self) -> String {
        match self {
            Self::Ready(matrix) => {
                let entries = matrix
                    .groups
                    .iter()
                    .map(|group| group.entries.len())
                    .sum::<usize>();
                format!(
                    "{entries} capabilities across {} pages",
                    matrix.groups.len()
                )
            }
            Self::Idle | Self::Loading | Self::Failed(_) => String::new(),
        }
    }

    fn groups(&self) -> Vec<CapabilityGroupProjection> {
        match self {
            Self::Ready(matrix) => matrix.groups.clone(),
            Self::Idle | Self::Loading | Self::Failed(_) => Vec::new(),
        }
    }
}

#[cfg(any(target_arch = "wasm32", test))]
/// The endpoint whose capability matrix is shown. Captured at entry time so
/// the header keeps its identity even if the inventory refreshes.
#[derive(Clone, Debug, Eq, PartialEq)]
struct CapabilityTargetProjection {
    endpoint_id: String,
    display_name: String,
    address: String,
}

#[cfg(any(target_arch = "wasm32", test))]
/// The resource whose §12.4 diagnostics panel is shown. Captured at entry
/// time so the panel keeps its identity even if the inventory refreshes;
/// the endpoint and resource ids are the two route parameters.
#[derive(Clone, Debug, Eq, PartialEq)]
struct DiagnosticsTargetProjection {
    endpoint_id: String,
    resource_id: String,
    name: String,
    source: String,
}

#[cfg(any(target_arch = "wasm32", test))]
impl From<&CoreResourceCardProjection> for DiagnosticsTargetProjection {
    /// The card-to-panel entry: every resource card opens exactly its own
    /// resource's panel, never a neighboring resource.
    fn from(card: &CoreResourceCardProjection) -> Self {
        Self {
            endpoint_id: card.endpoint_id.clone(),
            resource_id: card.resource_id.clone(),
            name: card.name.clone(),
            source: card.source.clone(),
        }
    }
}

#[cfg(any(target_arch = "wasm32", test))]
/// Why the §12.4 diagnostics snapshot of one resource could not be loaded.
///
/// The three variants map the route contract (404, transport/other status,
/// unparseable body) to static copy. A 400 cannot originate from this UI
/// because endpoint and resource ids always come from the local inventory,
/// so it folds into `Unavailable` like 503.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DiagnosticsLoadFailure {
    /// The route answered 404: the endpoint or its resource no longer
    /// exists in the product.
    ResourceNotFound,
    /// The request failed on the network or the route answered 4xx/5xx.
    Unavailable,
    /// The route answered 200 with a body that violates the strict shared
    /// diagnostics contract.
    Malformed,
}

#[cfg(any(target_arch = "wasm32", test))]
impl DiagnosticsLoadFailure {
    const fn message(self) -> &'static str {
        match self {
            Self::ResourceNotFound => "This resource no longer exists in the product.",
            Self::Unavailable => "The diagnostics snapshot is temporarily unavailable.",
            Self::Malformed => "The server response could not be parsed.",
        }
    }
}

#[cfg(any(target_arch = "wasm32", test))]
/// The lazy-loading state of one resource's §12.4 diagnostics panel.
#[derive(Clone, Debug, Eq, PartialEq)]
enum DiagnosticsState {
    Idle,
    Loading,
    Ready(DiagnosticsProjection),
    Failed(DiagnosticsLoadFailure),
}

#[cfg(any(target_arch = "wasm32", test))]
impl DiagnosticsState {
    const fn is_ready(&self) -> bool {
        matches!(self, Self::Ready(_))
    }

    const fn is_loading(&self) -> bool {
        matches!(self, Self::Loading)
    }

    const fn is_failed(&self) -> bool {
        matches!(self, Self::Failed(_))
    }

    const fn failure_message(&self) -> &'static str {
        match self {
            Self::Failed(failure) => failure.message(),
            Self::Idle | Self::Loading | Self::Ready(_) => "",
        }
    }

    fn projection(&self) -> Option<DiagnosticsProjection> {
        match self {
            Self::Ready(projection) => Some(projection.clone()),
            Self::Idle | Self::Loading | Self::Failed(_) => None,
        }
    }
}

#[cfg(any(target_arch = "wasm32", test))]
/// The read-only §12.4 diagnostics snapshot of one resource, projected for
/// the panel: every field the route exposes, plus the canonical rendering of
/// the decoded typed payload.
#[derive(Clone, Debug, Eq, PartialEq)]
struct DiagnosticsProjection {
    endpoint_id: String,
    odata_uri: String,
    odata_type: Option<String>,
    etag: Option<String>,
    feature: String,
    generation: String,
    /// The decoded typed payload rendered as pretty-printed JSON. The wire
    /// payload is a typed value, not raw bytes, so there is no original text
    /// to reproduce verbatim; the deterministic 2-space rendering preserves
    /// every field while staying readable and diffable.
    typed_payload_json: String,
}

#[cfg(any(target_arch = "wasm32", test))]
impl From<&ResourceDiagnosticsResponse> for DiagnosticsProjection {
    fn from(diagnostics: &ResourceDiagnosticsResponse) -> Self {
        Self {
            endpoint_id: diagnostics.endpoint_id().to_string(),
            odata_uri: diagnostics.odata_uri().to_owned(),
            odata_type: diagnostics.odata_type().map(str::to_owned),
            etag: diagnostics.etag().map(str::to_owned),
            feature: diagnostics.feature().to_owned(),
            generation: diagnostics.generation().get().to_string(),
            typed_payload_json: format_typed_payload_json(diagnostics.typed_payload()),
        }
    }
}

#[cfg(any(target_arch = "wasm32", test))]
/// Renders the decoded typed payload as deterministic pretty-printed JSON.
///
/// `serde_json::Value` objects sort keys, so the output is canonical for a
/// given payload; `to_string_pretty` cannot fail on an already-valid value,
/// so the error case folds into an empty string that the panel shows as an
/// explicit empty payload rather than a crash.
fn format_typed_payload_json(payload: &json::Value) -> String {
    json::to_string_pretty(payload).unwrap_or_default()
}

#[cfg(any(target_arch = "wasm32", test))]
/// The muted placeholder shown when a BMC did not publish an optional
/// diagnostics field. Absence is information (§12.4 exposes what the BMC
/// published and did not publish), so the row stays visible instead of
/// hiding what is missing. Pinned like the capability `NOT_OBSERVED` label
/// so the rendering decision cannot drift.
const DIAGNOSTICS_ABSENT_FIELD_LABEL: &str = "Not published";

#[cfg(any(target_arch = "wasm32", test))]
/// Renders one optional diagnostics field for the panel: the published
/// value, or the pinned absent-field placeholder. Kept as a pure function
/// (mirroring the capability label helpers) so the placeholder is
/// unit-testable instead of living inline in the wasm component.
fn diagnostics_optional_text(value: Option<&str>) -> String {
    match value {
        Some(value) => value.to_owned(),
        None => DIAGNOSTICS_ABSENT_FIELD_LABEL.to_owned(),
    }
}

#[cfg(any(target_arch = "wasm32", test))]
/// Honest boundary of the §12.4 diagnostics surface, shown as the panel
/// footnote. The wording mirrors the backend contract (api §12.4 view): the
/// payload is the persisted decoded snapshot of the latest complete refresh,
/// and decode-error paths left no record, so no diagnostics can exist for
/// resources that never entered the snapshot store.
const DIAGNOSTICS_FOOTER_NOTE: &str = "Diagnostics show the decoded snapshot of the latest complete refresh; decode-error paths are not persisted and have no diagnostics.";

#[cfg(any(target_arch = "wasm32", test))]
/// Static label for a capability that has never been observed on this
/// endpoint. Kept distinct from the `not_advertised` label so missing data
/// is never disguised as a probe result.
const NOT_OBSERVED_STATE_LABEL: &str = "Not yet observed";

#[cfg(any(target_arch = "wasm32", test))]
const fn capability_state_label(state: CapabilityStateResponse) -> &'static str {
    match state {
        CapabilityStateResponse::Supported => "Supported",
        CapabilityStateResponse::ReadOnly => "Read only",
        CapabilityStateResponse::Unauthorized => "Unauthorized",
        CapabilityStateResponse::TemporarilyUnavailable => "Temporarily unavailable",
        CapabilityStateResponse::SchemaIncompatible => "Schema incompatible",
        CapabilityStateResponse::NotAdvertised => "Not advertised",
        CapabilityStateResponse::NotCompiled => "Not compiled",
    }
}

#[cfg(any(target_arch = "wasm32", test))]
/// Badge styling for one observed state: usable surfaces are ok, advertised
/// but unusable surfaces warn, absent surfaces are off.
const fn capability_state_class(state: CapabilityStateResponse) -> &'static str {
    match state {
        CapabilityStateResponse::Supported | CapabilityStateResponse::ReadOnly => {
            "capability-state capability-ok"
        }
        CapabilityStateResponse::Unauthorized
        | CapabilityStateResponse::TemporarilyUnavailable
        | CapabilityStateResponse::SchemaIncompatible => "capability-state capability-warn",
        CapabilityStateResponse::NotAdvertised | CapabilityStateResponse::NotCompiled => {
            "capability-state capability-off"
        }
    }
}

#[cfg(any(target_arch = "wasm32", test))]
/// One capability-ledger row projected for the matrix: the stable product
/// code, its upstream feature, and the static state badge.
#[derive(Clone, Debug, Eq, PartialEq)]
struct CapabilityEntryProjection {
    product_code: String,
    upstream_feature: String,
    state_label: &'static str,
    state_class: &'static str,
    observed_at_text: Option<String>,
}

#[cfg(any(target_arch = "wasm32", test))]
impl From<&CapabilityEntryResponse> for CapabilityEntryProjection {
    fn from(entry: &CapabilityEntryResponse) -> Self {
        let (state_label, state_class) = match entry.state() {
            Some(state) => (capability_state_label(state), capability_state_class(state)),
            None => (NOT_OBSERVED_STATE_LABEL, "capability-state capability-none"),
        };
        Self {
            product_code: entry.capability().to_owned(),
            upstream_feature: entry.upstream_feature().to_owned(),
            state_label,
            state_class,
            observed_at_text: entry
                .observed_at()
                .map(|observed_at| format_observed_at(&observed_at)),
        }
    }
}

#[cfg(any(target_arch = "wasm32", test))]
/// The §12.2 Endpoint page name for one wire `ui_location` value, matching
/// the design document's navigation list. The mapping is a bijection on the
/// closed `UiLocationResponse` enum, so grouping by page title is exactly
/// grouping by `ui_location`.
fn page_title(ui_location: UiLocationResponse) -> &'static str {
    match ui_location {
        UiLocationResponse::Overview => "Overview",
        UiLocationResponse::Systems => "Systems",
        UiLocationResponse::Chassis => "Chassis",
        UiLocationResponse::Managers => "Managers",
        UiLocationResponse::Assembly => "Assembly",
        UiLocationResponse::Processors => "Processors",
        UiLocationResponse::Memory => "Memory",
        UiLocationResponse::Pcie => "PCIe",
        UiLocationResponse::Network => "Network",
        UiLocationResponse::Power => "Power",
        UiLocationResponse::Thermal => "Thermal",
        UiLocationResponse::Sensors => "Sensors",
        UiLocationResponse::Bios => "BIOS",
        UiLocationResponse::Boot => "Boot",
        UiLocationResponse::SecureBoot => "Secure Boot",
        UiLocationResponse::Storage => "Storage",
        UiLocationResponse::Accounts => "Accounts",
        UiLocationResponse::Logs => "Logs",
        UiLocationResponse::Events => "Events",
        UiLocationResponse::Telemetry => "Telemetry",
        UiLocationResponse::Update => "Update",
        UiLocationResponse::Tasks => "Tasks",
        UiLocationResponse::Oem => "OEM",
        UiLocationResponse::Diagnostics => "Diagnostics",
        UiLocationResponse::Infrastructure => "Infrastructure",
    }
}

#[cfg(any(target_arch = "wasm32", test))]
/// All entries presented on one §12.2 Endpoint page.
#[derive(Clone, Debug, Eq, PartialEq)]
struct CapabilityGroupProjection {
    page_title: &'static str,
    entries: Vec<CapabilityEntryProjection>,
}

#[cfg(any(target_arch = "wasm32", test))]
/// The complete §2.1 capability matrix of one endpoint, grouped by §12.2
/// page in ledger appearance order. The response arrives in ledger order;
/// grouping preserves that stable order instead of re-sorting by page name.
///
/// OEM ledger entries arrive with `ui_location = oem` and group under the
/// §12.2 OEM page exactly like every other entry: the wire contract decides
/// membership, so the page stays honest when the baseline has no OEM
/// capability (the §12.2 rule against blank fake pages) and gains the 14
/// OEM entries the moment the ledger projects them.
#[derive(Clone, Debug, Eq, PartialEq)]
struct CapabilityMatrixProjection {
    groups: Vec<CapabilityGroupProjection>,
}

#[cfg(any(target_arch = "wasm32", test))]
impl From<&EndpointCapabilityInventoryResponse> for CapabilityMatrixProjection {
    fn from(inventory: &EndpointCapabilityInventoryResponse) -> Self {
        let mut groups: Vec<CapabilityGroupProjection> = Vec::new();
        for entry in inventory.entries() {
            let page_title = page_title(entry.ui_location());
            let group_index = if let Some(index) = groups
                .iter()
                .position(|group| group.page_title == page_title)
            {
                index
            } else {
                groups.push(CapabilityGroupProjection {
                    page_title,
                    entries: Vec::new(),
                });
                groups.len() - 1
            };
            groups[group_index]
                .entries
                .push(CapabilityEntryProjection::from(entry));
        }
        Self { groups }
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

/// One endpoint's independent result inside a refresh batch report.
#[cfg(any(target_arch = "wasm32", test))]
#[derive(Clone, Debug, Eq, PartialEq)]
struct RefreshResultRowProjection {
    endpoint_id: String,
    display_name: String,
    status_label: &'static str,
    is_success: bool,
    detail: Option<String>,
}

#[cfg(any(target_arch = "wasm32", test))]
impl RefreshResultRowProjection {
    fn from_row(
        row: &EndpointRefreshResultResponse,
        inventory: &EndpointInventoryResponse,
    ) -> Self {
        let endpoint_id = row.endpoint_id().to_string();
        let (status_label, is_success, detail) = match row.status() {
            EndpointRefreshStatusResponse::Refreshed => (
                "Refreshed",
                true,
                Some(format!(
                    "Generation {} — {} snapshots",
                    row.generation().unwrap_or_default(),
                    row.snapshot_count().unwrap_or_default(),
                )),
            ),
            EndpointRefreshStatusResponse::Failed => {
                ("Failed", false, row.message().map(str::to_owned))
            }
            EndpointRefreshStatusResponse::NotFound => {
                ("Not found", false, row.message().map(str::to_owned))
            }
        };
        Self {
            display_name: endpoint_display_name(inventory, &endpoint_id),
            endpoint_id,
            status_label,
            is_success,
            detail,
        }
    }
}

/// The server-provided report of one refresh batch submission.
#[cfg(any(target_arch = "wasm32", test))]
#[derive(Clone, Debug, Eq, PartialEq)]
struct RefreshBatchReportProjection {
    total: u64,
    succeeded_count: u64,
    failed_count: u64,
    rows: Vec<RefreshResultRowProjection>,
}

#[cfg(any(target_arch = "wasm32", test))]
impl RefreshBatchReportProjection {
    fn from_response(
        response: &BatchRefreshResponse,
        inventory: &EndpointInventoryResponse,
    ) -> Self {
        Self {
            total: response.total(),
            succeeded_count: response.succeeded_count(),
            failed_count: response.failed_count(),
            rows: response
                .results()
                .iter()
                .map(|row| RefreshResultRowProjection::from_row(row, inventory))
                .collect(),
        }
    }

    fn summary_text(&self) -> String {
        format!(
            "{} of {} endpoints refreshed; {} failed",
            self.succeeded_count, self.total, self.failed_count
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

#[cfg(any(target_arch = "wasm32", test))]
/// The progression of one refresh batch submission from the overview.
#[derive(Clone, Debug, Eq, PartialEq)]
enum RefreshBatchState {
    Idle,
    InFlight,
    Ready(RefreshBatchReportProjection),
    Failed(RefreshFailure),
}

#[cfg(any(target_arch = "wasm32", test))]
impl RefreshBatchState {
    const fn is_in_flight(&self) -> bool {
        matches!(self, Self::InFlight)
    }

    const fn is_ready(&self) -> bool {
        matches!(self, Self::Ready(_))
    }
}

#[cfg(any(target_arch = "wasm32", test))]
/// Why a refresh batch could not be completed or reported.
#[derive(Clone, Debug, Eq, PartialEq)]
enum RefreshFailure {
    Unavailable,
    MalformedReport,
    Rejected { status: u16 },
}

#[cfg(any(target_arch = "wasm32", test))]
impl RefreshFailure {
    fn message(&self) -> String {
        match self {
            Self::Unavailable => "The refresh service is temporarily unavailable.".to_owned(),
            Self::MalformedReport => "The server response could not be read.".to_owned(),
            Self::Rejected { status } => {
                format!("The server rejected the refresh request (HTTP {status}).")
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

/// The lazy-loading state of the bounded §14.4 event-history query.
///
/// The server answers `GET /api/v1/events?limit=N` with a bounded list,
/// newest first by the product receive time (`observed_at`) with the event
/// id as tiebreaker — the persistence listing order — with obvious
/// duplicates already removed (§14.4); this view additionally re-establishes
/// that exact newest-first order defensively in
/// [`EventsListState::event_cards`], so a misordered payload can never
/// present an older event above a newer one. The console renders exactly
/// what the bounded query returned — the bound hint shows the returned
/// count, which is smaller than the requested limit while the history is
/// shorter than the bound.
#[cfg(any(target_arch = "wasm32", test))]
#[derive(Clone, Debug, Eq, PartialEq)]
enum EventsListState {
    Idle,
    Loading,
    Ready(EventListResponse),
    Failed,
}

#[cfg(any(target_arch = "wasm32", test))]
impl EventsListState {
    const fn is_ready(&self) -> bool {
        matches!(self, Self::Ready(_))
    }

    const fn is_loading(&self) -> bool {
        matches!(self, Self::Loading)
    }

    const fn is_failed(&self) -> bool {
        matches!(self, Self::Failed)
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
            1 => "1 event".to_owned(),
            _ => format!("{count} events"),
        }
    }

    /// The bounded-query hint: how many events the server actually returned,
    /// which may be fewer than the requested limit when the history is
    /// shorter than the bound.
    fn bound_text(&self) -> String {
        let count = match self {
            Self::Ready(query) => query.events().len(),
            Self::Idle | Self::Loading | Self::Failed => 0,
        };
        match count {
            1 => "Showing the latest 1 event".to_owned(),
            _ => format!("Showing the latest {count} events"),
        }
    }

    /// Static failure copy for the whole-section error state.
    const fn failure_message(&self) -> &'static str {
        match self {
            Self::Failed => "The event history is temporarily unavailable.",
            Self::Idle | Self::Loading | Self::Ready(_) => "",
        }
    }

    fn event_cards(&self) -> Vec<EventCardProjection> {
        match self {
            Self::Ready(query) => {
                let mut events = query.events().to_vec();
                // Why re-sort: the operator reads the card list top-down as a
                // time axis, so the bounded list is re-ordered here by the
                // same key the query itself orders by — receive time
                // (`observed_at`) descending, then event id descending — to
                // make a misordered payload harmless. The stable sort keeps
                // server order for events that tie on both keys.
                events.sort_by(|left, right| {
                    right
                        .observed_at()
                        .cmp(&left.observed_at())
                        .then_with(|| right.id().cmp(&left.id()))
                });
                events.iter().map(EventCardProjection::from).collect()
            }
            Self::Idle | Self::Loading | Self::Failed => Vec::new(),
        }
    }
}

/// Display label for one §14.4 severity code.
///
/// The wire contract is the three stable lowercase codes (`ok`, `warning`,
/// `critical`); the api refuses any other code at ingestion, so this mapping
/// covers the closed vocabulary. The fallback renders the raw code itself,
/// so an unexpected code is shown verbatim (§14.4), never relabeled.
#[cfg(any(target_arch = "wasm32", test))]
fn severity_label(severity: &str) -> String {
    match severity {
        "ok" => "OK".to_owned(),
        "warning" => "Warning".to_owned(),
        "critical" => "Critical".to_owned(),
        _ => severity.to_owned(),
    }
}

/// Badge styling for one severity code: ok is the success color, warning the
/// warn color, and critical the failure color — the same tri-state palette
/// the capability matrix applies. The fallback uses the neutral off palette
/// for a code the build cannot classify. Not `const`: matching on `str`
/// needs const `PartialEq`, which is not stable yet.
#[cfg(any(target_arch = "wasm32", test))]
fn severity_class(severity: &str) -> &'static str {
    match severity {
        "ok" => "event-severity event-ok",
        "warning" => "event-severity event-warn",
        "critical" => "event-severity event-critical",
        _ => "event-severity event-neutral",
    }
}

/// One §14.4 event projected for a history card.
///
/// The `message_id` is the BMC's raw `MessageId` value, displayed verbatim —
/// the design document mandates raw `MessageId` and `Severity` presentation,
/// so the projection never normalizes, localizes, or strips the registry id.
/// The source endpoint appears as its short id (first 8 characters), while
/// the full event id stays available as the card title attribute and in the
/// facts list.
#[cfg(any(target_arch = "wasm32", test))]
#[derive(Clone, Debug, Eq, PartialEq)]
struct EventCardProjection {
    event_id: String,
    endpoint_short_id: String,
    message_id: String,
    severity_label: String,
    severity_class: &'static str,
    message: String,
    event_timestamp_text: String,
    observed_at_text: String,
}

#[cfg(any(target_arch = "wasm32", test))]
impl From<&EventResponse> for EventCardProjection {
    fn from(event: &EventResponse) -> Self {
        let severity = event.severity();
        Self {
            event_id: event.id().to_string(),
            endpoint_short_id: short_endpoint_id(&event.endpoint_id().to_string()),
            message_id: event.message_id().to_owned(),
            severity_label: severity_label(severity),
            severity_class: severity_class(severity),
            // Redfish events may carry no message text; the card then shows
            // no message paragraph instead of a placeholder.
            message: event.message().unwrap_or_default().to_owned(),
            event_timestamp_text: format_observed_at(&event.event_timestamp()),
            observed_at_text: format_observed_at(&event.observed_at()),
        }
    }
}

/// Compact card identity for one endpoint id: its first 8 characters.
///
/// Endpoint ids are UUID v7 strings; the full id stays available in the
/// endpoint inventory while the short form keeps the card list scannable,
/// mirroring the operation-card short id convention.
#[cfg(any(target_arch = "wasm32", test))]
fn short_endpoint_id(endpoint_id: &str) -> String {
    endpoint_id.chars().take(8).collect()
}

/// One reading of the bounded §14.4 history, newest first, pre-formatted.
#[cfg(any(target_arch = "wasm32", test))]
#[derive(Clone, Debug, Eq, PartialEq)]
struct TelemetryReadingProjection {
    observed_at_text: String,
    value_text: String,
}

#[cfg(any(target_arch = "wasm32", test))]
impl From<&TelemetrySampleResponse> for TelemetryReadingProjection {
    fn from(sample: &TelemetrySampleResponse) -> Self {
        Self {
            observed_at_text: format_observed_at(&sample.observed_at()),
            value_text: sample.value().to_string(),
        }
    }
}

/// One telemetry series card: the current value, the bounded-history size,
/// and the newest readings.
///
/// The presentation boundary of §14.4 不把产品变成通用时序数据库: the card
/// renders the current value and a bounded newest-first reading list — no
/// chart, no time-series visualization machinery, exactly the "current value
/// and bounded history" surface the API serves. The full series id stays
/// available as the card title attribute while the header shows the series
/// key and the endpoint's short id.
#[cfg(any(target_arch = "wasm32", test))]
#[derive(Clone, Debug, Eq, PartialEq)]
struct TelemetryCardProjection {
    series_id_title: String,
    endpoint_short_id: String,
    series_key: String,
    /// The newest retained reading, absent when the series has no samples
    /// yet (an upsert whose append failed, or the first tick pending).
    latest_value_text: Option<String>,
    /// The product-clock instant of the newest retained reading, present
    /// exactly when the value is.
    latest_observed_at_text: Option<String>,
    sample_count_text: String,
    history: Vec<TelemetryReadingProjection>,
}

#[cfg(any(target_arch = "wasm32", test))]
impl TelemetryCardProjection {
    /// Projects the series card from the series DTO; the history is attached
    /// by [`Self::with_history`] once the bounded sample query returns.
    fn from_series(series: &TelemetrySeriesResponse) -> Self {
        Self {
            series_id_title: series.series_id().to_string(),
            endpoint_short_id: short_endpoint_id(&series.endpoint_id().to_string()),
            series_key: series.series_key().to_owned(),
            // Absent latest fields render no facts instead of a placeholder
            // (the facts-list precedent).
            latest_value_text: series.latest_value().map(|value| value.to_string()),
            latest_observed_at_text: series
                .latest_observed_at()
                .map(|observed_at| format_observed_at(&observed_at)),
            sample_count_text: series.sample_count().to_string(),
            history: Vec::new(),
        }
    }

    /// Attaches the bounded newest-first history, when the sample query
    /// returned one; a failed or empty query renders the card without a
    /// history list, keeping the current value visible.
    fn with_history(mut self, samples: Option<&TelemetrySampleListResponse>) -> Self {
        if let Some(samples) = samples {
            self.history = samples
                .samples()
                .iter()
                .map(TelemetryReadingProjection::from)
                .collect();
        }
        self
    }
}

/// The lazy-loading state of the §14.4 telemetry view.
///
/// The view fetches the series inventory, then the bounded newest-first
/// history of every series through the per-series sample query. The two
/// query surfaces fail differently: a failed series fetch fails the whole
/// view (there is nothing to render, so the section shows the failure copy),
/// while a failed per-series history fetch degrades to that card alone —
/// the readings list is omitted and the current-value facts stay visible
/// ([`TelemetryCardProjection::with_history`]).
#[cfg(any(target_arch = "wasm32", test))]
#[derive(Clone, Debug, Eq, PartialEq)]
enum TelemetryListState {
    Idle,
    Loading,
    Ready(Vec<TelemetryCardProjection>),
    Failed,
}

#[cfg(any(target_arch = "wasm32", test))]
impl TelemetryListState {
    const fn is_ready(&self) -> bool {
        matches!(self, Self::Ready(_))
    }

    const fn is_loading(&self) -> bool {
        matches!(self, Self::Loading)
    }

    const fn is_failed(&self) -> bool {
        matches!(self, Self::Failed)
    }

    fn has_empty_series(&self) -> bool {
        matches!(self, Self::Ready(cards) if cards.is_empty())
    }

    fn count_text(&self) -> String {
        let count = match self {
            Self::Ready(cards) => cards.len(),
            Self::Idle | Self::Loading | Self::Failed => 0,
        };
        match count {
            1 => "1 series".to_owned(),
            _ => format!("{count} series"),
        }
    }

    /// Static failure copy for the whole-section error state.
    const fn failure_message(&self) -> &'static str {
        match self {
            Self::Failed => "The telemetry history is temporarily unavailable.",
            Self::Idle | Self::Loading | Self::Ready(_) => "",
        }
    }

    fn cards(&self) -> Vec<TelemetryCardProjection> {
        match self {
            Self::Ready(cards) => cards.clone(),
            Self::Idle | Self::Loading | Self::Failed => Vec::new(),
        }
    }
}

/// The §13.2 lifecycle phase of one persisted operation, as display vocabulary.
///
/// The wire contract (the `rutilus-api` operation DTOs) is parsed before this
/// projection exists, so this view type is the UI's own closed vocabulary of
/// the nine phases; the DTO-to-view mapping lives with the fetch layer.
#[cfg(any(target_arch = "wasm32", test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OperationStateView {
    Queued,
    Validating,
    Running,
    WaitingRemote,
    Verifying,
    Succeeded,
    Failed,
    Unknown,
    Cancelled,
}

#[cfg(any(target_arch = "wasm32", test))]
impl OperationStateView {
    /// Static English badge label for one phase.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Queued => "Queued",
            Self::Validating => "Validating",
            Self::Running => "Running",
            Self::WaitingRemote => "Waiting for BMC",
            Self::Verifying => "Verifying",
            Self::Succeeded => "Succeeded",
            Self::Failed => "Failed",
            Self::Unknown => "Unknown",
            Self::Cancelled => "Cancelled",
        }
    }

    /// Semantic badge styling for one phase.
    ///
    /// The four tiers mirror the capability badge vocabulary: `Succeeded` is
    /// the only ok (green) phase; `Failed` is the only error (red) phase;
    /// `Unknown` and `Cancelled` are terminal without a proven result, so
    /// they read as off (gray) instead of red; the five in-flight phases
    /// read as active (blue).
    #[must_use]
    pub const fn class(self) -> &'static str {
        match self {
            Self::Succeeded => "operation-state operation-ok",
            Self::Failed => "operation-state operation-error",
            Self::Unknown | Self::Cancelled => "operation-state operation-off",
            Self::Queued
            | Self::Validating
            | Self::Running
            | Self::WaitingRemote
            | Self::Verifying => "operation-state operation-active",
        }
    }
}

/// Where a persisted operation originated (§13.1), as display vocabulary.
#[cfg(any(target_arch = "wasm32", test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OperationSourceView {
    Standalone,
    Site,
    Center,
}

#[cfg(any(target_arch = "wasm32", test))]
impl OperationSourceView {
    /// Static English label for one operation origin.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Standalone => "Standalone",
            Self::Site => "Site",
            Self::Center => "Center",
        }
    }
}

/// The §7.5 command family chosen in the operation form, as display
/// vocabulary. The three reset families stay separate variants exactly like
/// the domain, because they target different CSDL resources.
#[cfg(any(target_arch = "wasm32", test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CommandFamilyView {
    SystemReset,
    ManagerReset,
    ChassisReset,
    BootOverride,
    SecureBoot,
    EventSubscription,
    FirmwareUpdate,
    Oem,
}

#[cfg(any(target_arch = "wasm32", test))]
impl CommandFamilyView {
    /// Every family in §7.5 order, so the form cannot miss a variant.
    const ALL: [Self; 8] = [
        Self::SystemReset,
        Self::ManagerReset,
        Self::ChassisReset,
        Self::BootOverride,
        Self::SecureBoot,
        Self::EventSubscription,
        Self::FirmwareUpdate,
        Self::Oem,
    ];

    /// The stable §7.5 family code, matching the domain's wire vocabulary.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SystemReset => "system",
            Self::ManagerReset => "manager",
            Self::ChassisReset => "chassis",
            Self::BootOverride => "boot",
            Self::SecureBoot => "secure-boot",
            Self::EventSubscription => "event",
            Self::FirmwareUpdate => "update",
            Self::Oem => "oem",
        }
    }

    /// Static English label for one command family.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::SystemReset => "System reset",
            Self::ManagerReset => "Manager reset",
            Self::ChassisReset => "Chassis reset",
            Self::BootOverride => "Boot source override",
            Self::SecureBoot => "Secure Boot",
            Self::EventSubscription => "Event subscription",
            Self::FirmwareUpdate => "Firmware update",
            Self::Oem => "OEM (NVIDIA)",
        }
    }
}

/// The NVIDIA OEM face chosen in the operation form, as display vocabulary.
///
/// The three faces mirror the domain `OemCommand` exactly and group the nine
/// actions of the §11.5 write surface.
#[cfg(any(target_arch = "wasm32", test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OemFaceView {
    SystemConfigProfile,
    DebugToken,
    PowerSmoothing,
}

#[cfg(any(target_arch = "wasm32", test))]
impl OemFaceView {
    /// Every face in domain order, so the form cannot miss a variant.
    const ALL: [Self; 3] = [
        Self::SystemConfigProfile,
        Self::DebugToken,
        Self::PowerSmoothing,
    ];

    /// Static English label for one OEM face.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::SystemConfigProfile => "System config profile",
            Self::DebugToken => "Debug token",
            Self::PowerSmoothing => "Power smoothing",
        }
    }
}

/// One NVIDIA OEM action selectable in the form, grouped by its face.
#[cfg(any(target_arch = "wasm32", test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OemActionView {
    ProfileUpdate,
    ProfileFactoryReset,
    ProfileActivate,
    TokenGenerate,
    TokenInstall,
    TokenDisable,
    TokenErase,
    PowerActivatePreset,
    PowerApplyOverrides,
}

#[cfg(any(target_arch = "wasm32", test))]
impl OemActionView {
    /// Every action in face order, so the form cannot miss a variant.
    const ALL: [Self; 9] = [
        Self::ProfileUpdate,
        Self::ProfileFactoryReset,
        Self::ProfileActivate,
        Self::TokenGenerate,
        Self::TokenInstall,
        Self::TokenDisable,
        Self::TokenErase,
        Self::PowerActivatePreset,
        Self::PowerApplyOverrides,
    ];

    /// The face one action belongs to.
    #[must_use]
    pub const fn face(self) -> OemFaceView {
        match self {
            Self::ProfileUpdate | Self::ProfileFactoryReset | Self::ProfileActivate => {
                OemFaceView::SystemConfigProfile
            }
            Self::TokenGenerate | Self::TokenInstall | Self::TokenDisable | Self::TokenErase => {
                OemFaceView::DebugToken
            }
            Self::PowerActivatePreset | Self::PowerApplyOverrides => OemFaceView::PowerSmoothing,
        }
    }

    /// Static English label for one OEM action.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::ProfileUpdate => "Update profile",
            Self::ProfileFactoryReset => "Factory reset",
            Self::ProfileActivate => "Activate profile",
            Self::TokenGenerate => "Generate token",
            Self::TokenInstall => "Install token",
            Self::TokenDisable => "Disable token",
            Self::TokenErase => "Erase tokens",
            Self::PowerActivatePreset => "Activate preset profile",
            Self::PowerApplyOverrides => "Apply admin overrides",
        }
    }
}

/// The debug token type argument of an OEM action.
///
/// The member set mirrors the domain `TokenType` exactly, which follows the
/// `nv-redfish-schema` 0.13.0 `NvidiaDebugTokenManagement_v1.xml` `TokenType`
/// enum; the const member-set test keeps this aligned.
// The variant names are the exact CSDL member names; renaming them would
// break the wire contract, so the all-caps acronym spellings stay in the
// `as_str` matches.
#[cfg(any(target_arch = "wasm32", test))]
#[allow(clippy::enum_variant_names)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TokenTypeView {
    Frc,
    Crcs,
    Crdt,
    DebugFirmwareRunning,
    DebugFirmwareUnlock,
    OtpDumpEnable,
    JtagUnlock,
    HardwareUnlock,
    RuntimeDebugUnlock,
    FeatureUnlock,
    Mtdt,
    CcplexArmJtagDebugCont,
    NvJtagControl,
    DiagnosticBoot,
    BpmpFirmwareDebugFs,
    FirmwareDebugKnobs,
    FirewallLifting,
    Verbosity,
    SmaDebugCapability,
    CpldDebugCapability,
}

#[cfg(any(target_arch = "wasm32", test))]
impl TokenTypeView {
    /// Every member in CSDL order.
    const ALL: [Self; 20] = [
        Self::Frc,
        Self::Crcs,
        Self::Crdt,
        Self::DebugFirmwareRunning,
        Self::DebugFirmwareUnlock,
        Self::OtpDumpEnable,
        Self::JtagUnlock,
        Self::HardwareUnlock,
        Self::RuntimeDebugUnlock,
        Self::FeatureUnlock,
        Self::Mtdt,
        Self::CcplexArmJtagDebugCont,
        Self::NvJtagControl,
        Self::DiagnosticBoot,
        Self::BpmpFirmwareDebugFs,
        Self::FirmwareDebugKnobs,
        Self::FirewallLifting,
        Self::Verbosity,
        Self::SmaDebugCapability,
        Self::CpldDebugCapability,
    ];

    /// Returns the exact CSDL member name, which is also the wire value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Frc => "FRC",
            Self::Crcs => "CRCS",
            Self::Crdt => "CRDT",
            Self::DebugFirmwareRunning => "DebugFirmwareRunning",
            Self::DebugFirmwareUnlock => "DebugFirmwareUnlock",
            Self::OtpDumpEnable => "OTPDumpEnable",
            Self::JtagUnlock => "JtagUnlock",
            Self::HardwareUnlock => "HardwareUnlock",
            Self::RuntimeDebugUnlock => "RuntimeDebugUnlock",
            Self::FeatureUnlock => "FeatureUnlock",
            Self::Mtdt => "MTDT",
            Self::CcplexArmJtagDebugCont => "CcplexArmJtagDebugCont",
            Self::NvJtagControl => "NVJtagControl",
            Self::DiagnosticBoot => "DiagnosticBoot",
            Self::BpmpFirmwareDebugFs => "BpmpFirmwareDebugFS",
            Self::FirmwareDebugKnobs => "FirmwareDebugKnobs",
            Self::FirewallLifting => "FirewallLifting",
            Self::Verbosity => "Verbosity",
            Self::SmaDebugCapability => "SMADebugCapability",
            Self::CpldDebugCapability => "CpldDebugCapability",
        }
    }
}

/// The erase scope argument of the OEM erase action.
///
/// The member set mirrors the domain `EraseType` exactly, which follows the
/// `nv-redfish-schema` 0.13.0 `NvidiaDebugTokenManagement_v1.xml` `EraseType`
/// enum.
#[cfg(any(target_arch = "wasm32", test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EraseTypeView {
    EraseAll,
    EraseAllAndRatchetCounterIncreased,
    TokenType,
}

#[cfg(any(target_arch = "wasm32", test))]
impl EraseTypeView {
    /// Every member in CSDL order.
    const ALL: [Self; 3] = [
        Self::EraseAll,
        Self::EraseAllAndRatchetCounterIncreased,
        Self::TokenType,
    ];

    /// Returns the exact CSDL member name, which is also the wire value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EraseAll => "EraseAll",
            Self::EraseAllAndRatchetCounterIncreased => "EraseAllAndRatchetCounterIncreased",
            Self::TokenType => "TokenType",
        }
    }
}

/// The reset action argument used by system, manager, and chassis resets.
///
/// The member set mirrors the domain `ResetType` exactly, which follows the
/// `nv-redfish-schema` 0.13.0 `Resource_v1.xml` `ResetType` enum; the
/// const member-set test keeps this aligned, and the form dropdown offers
/// every member.
// The variant names are the exact CSDL member names; renaming them would
// break the wire contract, so the shared `Force` prefix is accepted.
#[cfg(any(target_arch = "wasm32", test))]
#[allow(clippy::enum_variant_names)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResetTypeView {
    On,
    ForceOff,
    GracefulShutdown,
    GracefulRestart,
    ForceRestart,
    Nmi,
    ForceOn,
    PushPowerButton,
    PowerCycle,
    Suspend,
    Pause,
    Resume,
    FullPowerCycle,
}

#[cfg(any(target_arch = "wasm32", test))]
impl ResetTypeView {
    /// Every member in CSDL order.
    const ALL: [Self; 13] = [
        Self::On,
        Self::ForceOff,
        Self::GracefulShutdown,
        Self::GracefulRestart,
        Self::ForceRestart,
        Self::Nmi,
        Self::ForceOn,
        Self::PushPowerButton,
        Self::PowerCycle,
        Self::Suspend,
        Self::Pause,
        Self::Resume,
        Self::FullPowerCycle,
    ];

    /// Returns the exact CSDL member name, which is also the wire value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::On => "On",
            Self::ForceOff => "ForceOff",
            Self::GracefulShutdown => "GracefulShutdown",
            Self::GracefulRestart => "GracefulRestart",
            Self::ForceRestart => "ForceRestart",
            Self::Nmi => "Nmi",
            Self::ForceOn => "ForceOn",
            Self::PushPowerButton => "PushPowerButton",
            Self::PowerCycle => "PowerCycle",
            Self::Suspend => "Suspend",
            Self::Pause => "Pause",
            Self::Resume => "Resume",
            Self::FullPowerCycle => "FullPowerCycle",
        }
    }
}

/// The boot source selected by a boot source override.
///
/// The member set mirrors the domain `BootSource` exactly, which follows the
/// `nv-redfish-schema` 0.13.0 `ComputerSystem_v1.xml` `BootSource` enum.
// The variant names are the exact CSDL member names; renaming them would
// break the wire contract, so the shared `Uefi` prefix is accepted.
#[cfg(any(target_arch = "wasm32", test))]
#[allow(clippy::enum_variant_names)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BootSourceView {
    None,
    Pxe,
    Floppy,
    Cd,
    Usb,
    Hdd,
    BiosSetup,
    Utilities,
    Diags,
    UefiShell,
    UefiTarget,
    SdCard,
    UefiHttp,
    RemoteDrive,
    UefiBootNext,
    Recovery,
}

#[cfg(any(target_arch = "wasm32", test))]
impl BootSourceView {
    /// Every member in CSDL order.
    const ALL: [Self; 16] = [
        Self::None,
        Self::Pxe,
        Self::Floppy,
        Self::Cd,
        Self::Usb,
        Self::Hdd,
        Self::BiosSetup,
        Self::Utilities,
        Self::Diags,
        Self::UefiShell,
        Self::UefiTarget,
        Self::SdCard,
        Self::UefiHttp,
        Self::RemoteDrive,
        Self::UefiBootNext,
        Self::Recovery,
    ];

    /// Returns the exact CSDL member name, which is also the wire value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "None",
            Self::Pxe => "Pxe",
            Self::Floppy => "Floppy",
            Self::Cd => "Cd",
            Self::Usb => "Usb",
            Self::Hdd => "Hdd",
            Self::BiosSetup => "BiosSetup",
            Self::Utilities => "Utilities",
            Self::Diags => "Diags",
            Self::UefiShell => "UefiShell",
            Self::UefiTarget => "UefiTarget",
            Self::SdCard => "SDCard",
            Self::UefiHttp => "UefiHttp",
            Self::RemoteDrive => "RemoteDrive",
            Self::UefiBootNext => "UefiBootNext",
            Self::Recovery => "Recovery",
        }
    }
}

/// How long a boot source override applies.
#[cfg(any(target_arch = "wasm32", test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BootEnabledView {
    Disabled,
    Once,
    Continuous,
}

#[cfg(any(target_arch = "wasm32", test))]
impl BootEnabledView {
    /// Every member in CSDL order.
    const ALL: [Self; 3] = [Self::Disabled, Self::Once, Self::Continuous];

    /// Returns the exact CSDL member name, which is also the wire value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "Disabled",
            Self::Once => "Once",
            Self::Continuous => "Continuous",
        }
    }
}

/// The boot mode a boot source override applies to; the CSDL member is
/// `UEFI` (all caps), not `Uefi`.
#[cfg(any(target_arch = "wasm32", test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BootModeView {
    Legacy,
    Uefi,
}

#[cfg(any(target_arch = "wasm32", test))]
impl BootModeView {
    /// Every member in CSDL order.
    const ALL: [Self; 2] = [Self::Legacy, Self::Uefi];

    /// Returns the exact CSDL member name, which is also the wire value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Legacy => "Legacy",
            Self::Uefi => "UEFI",
        }
    }
}

/// The key set reset requested from the Secure Boot service.
#[cfg(any(target_arch = "wasm32", test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResetKeysTypeView {
    ResetAllKeysToDefault,
    DeleteAllKeys,
    DeletePk,
}

#[cfg(any(target_arch = "wasm32", test))]
impl ResetKeysTypeView {
    /// Every member in CSDL order.
    const ALL: [Self; 3] = [
        Self::ResetAllKeysToDefault,
        Self::DeleteAllKeys,
        Self::DeletePk,
    ];

    /// Returns the exact CSDL member name, which is also the wire value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ResetAllKeysToDefault => "ResetAllKeysToDefault",
            Self::DeleteAllKeys => "DeleteAllKeys",
            Self::DeletePk => "DeletePK",
        }
    }
}

/// One Secure Boot command selectable in the form; `ResetKeys` carries the
/// key set to reset.
#[cfg(any(target_arch = "wasm32", test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SecureBootActionView {
    Enable,
    Disable,
    ResetKeys(ResetKeysTypeView),
}

#[cfg(any(target_arch = "wasm32", test))]
impl SecureBootActionView {
    /// Static English label for one Secure Boot action.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Enable => "Enable",
            Self::Disable => "Disable",
            Self::ResetKeys(_) => "Reset keys",
        }
    }
}

/// One event subscription action selectable in the form.
#[cfg(any(target_arch = "wasm32", test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EventActionView {
    CreateSubscription,
    DeleteSubscription,
}

#[cfg(any(target_arch = "wasm32", test))]
impl EventActionView {
    /// Every action in §7.5 order.
    const ALL: [Self; 2] = [Self::CreateSubscription, Self::DeleteSubscription];

    /// Static English label for one event action.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::CreateSubscription => "Create subscription",
            Self::DeleteSubscription => "Delete subscription",
        }
    }
}

/// The protocol an event subscription delivers events through.
// The variant names are the exact CSDL member names; renaming them would
// break the wire contract, so the shared `Syslog`/`SNMP` prefixes are
// accepted.
#[cfg(any(target_arch = "wasm32", test))]
#[allow(clippy::enum_variant_names)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EventProtocolView {
    Redfish,
    Kafka,
    Snmpv1,
    Snmpv2c,
    Snmpv3,
    Smtp,
    SyslogTls,
    SyslogTcp,
    SyslogUdp,
    SyslogRelp,
    Oem,
}

#[cfg(any(target_arch = "wasm32", test))]
impl EventProtocolView {
    /// Every member in CSDL order.
    const ALL: [Self; 11] = [
        Self::Redfish,
        Self::Kafka,
        Self::Snmpv1,
        Self::Snmpv2c,
        Self::Snmpv3,
        Self::Smtp,
        Self::SyslogTls,
        Self::SyslogTcp,
        Self::SyslogUdp,
        Self::SyslogRelp,
        Self::Oem,
    ];

    /// Returns the exact CSDL member name, which is also the wire value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Redfish => "Redfish",
            Self::Kafka => "Kafka",
            Self::Snmpv1 => "SNMPv1",
            Self::Snmpv2c => "SNMPv2c",
            Self::Snmpv3 => "SNMPv3",
            Self::Smtp => "SMTP",
            Self::SyslogTls => "SyslogTLS",
            Self::SyslogTcp => "SyslogTCP",
            Self::SyslogUdp => "SyslogUDP",
            Self::SyslogRelp => "SyslogRELP",
            Self::Oem => "OEM",
        }
    }
}

/// The Redfish event type an event subscription requests.
// The variant names are the exact CSDL member names; renaming them would
// break the wire contract, so the shared `Resource` prefix is accepted.
#[cfg(any(target_arch = "wasm32", test))]
#[allow(clippy::enum_variant_names)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EventTypeView {
    StatusChange,
    ResourceUpdated,
    ResourceAdded,
    ResourceRemoved,
    Alert,
    MetricReport,
    Other,
}

#[cfg(any(target_arch = "wasm32", test))]
impl EventTypeView {
    /// Every member in CSDL order.
    const ALL: [Self; 7] = [
        Self::StatusChange,
        Self::ResourceUpdated,
        Self::ResourceAdded,
        Self::ResourceRemoved,
        Self::Alert,
        Self::MetricReport,
        Self::Other,
    ];

    /// Returns the exact CSDL member name, which is also the wire value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StatusChange => "StatusChange",
            Self::ResourceUpdated => "ResourceUpdated",
            Self::ResourceAdded => "ResourceAdded",
            Self::ResourceRemoved => "ResourceRemoved",
            Self::Alert => "Alert",
            Self::MetricReport => "MetricReport",
            Self::Other => "Other",
        }
    }
}

/// The reset target resource family carried by a reset command draft.
///
/// Keeping the reset families in their own type (instead of reusing
/// [`CommandFamilyView`]) makes a reset draft unable to carry a non-reset
/// family in the first place, so no match site ever needs an impossible arm.
#[cfg(any(target_arch = "wasm32", test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResetResourceView {
    System,
    Manager,
    Chassis,
}

#[cfg(any(target_arch = "wasm32", test))]
impl ResetResourceView {
    /// Static English label for one reset target.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::System => "System reset",
            Self::Manager => "Manager reset",
            Self::Chassis => "Chassis reset",
        }
    }
}

/// The typed command assembled from the operation form (§7.5).
///
/// This is the form-side counterpart of the domain `RedfishCommand`: the
/// same six families with the same CSDL member vocabulary.
#[cfg(any(target_arch = "wasm32", test))]
#[derive(Clone, Debug, Eq, PartialEq)]
enum OperationCommandDraft {
    Reset {
        family: ResetResourceView,
        reset_type: ResetTypeView,
    },
    BootOverride {
        source: BootSourceView,
        enabled: BootEnabledView,
        mode: BootModeView,
    },
    SecureBoot(SecureBootActionView),
    Event(EventActionDraft),
    Update(UpdateDraft),
    Oem(OemCommandDraft),
}

/// The NVIDIA OEM command assembled from the operation form (§11.5).
///
/// This is the form-side counterpart of the domain `OemCommand`: the same
/// three faces with the same CSDL action and parameter vocabulary.
#[cfg(any(target_arch = "wasm32", test))]
#[derive(Clone, Debug, Eq, PartialEq)]
enum OemCommandDraft {
    ProfileUpdate {
        profile_file: String,
    },
    ProfileFactoryReset,
    ProfileActivate,
    TokenGenerate {
        token_type: TokenTypeView,
    },
    TokenInstall {
        token_data: String,
    },
    TokenDisable,
    TokenErase {
        erase_type: EraseTypeView,
        token_type: TokenTypeView,
    },
    PowerActivatePreset {
        profile_id: i64,
    },
    PowerApplyOverrides,
}

/// The §14.3 firmware-update payload assembled from the operation form.
///
/// The two fields mirror the domain `UpdateCommand::StartUpdate` payload
/// exactly: the selected artifact id and the optional push URI. `None` means
/// the operation engine reads the artifact from the local store and
/// dispatches it through the default multipart path; `Some` means the engine
/// pushes the artifact bytes to that public URI instead.
#[cfg(any(target_arch = "wasm32", test))]
#[derive(Clone, Debug, Eq, PartialEq)]
struct UpdateDraft {
    artifact_id: String,
    push_uri: Option<String>,
}

/// The event-command payload assembled from the operation form.
#[cfg(any(target_arch = "wasm32", test))]
#[derive(Clone, Debug, Eq, PartialEq)]
enum EventActionDraft {
    /// A subscription that requests no events can never deliver anything, so
    /// the form rejects an empty event type set before submission.
    CreateSubscription {
        destination: String,
        protocol: EventProtocolView,
        event_types: Vec<EventTypeView>,
    },
    /// The `@odata.id` tail segment of the subscription to delete.
    DeleteSubscription { subscription_id: String },
}

/// One-line summary of a typed command for the operation card and the form
/// preview: the family label plus a compact payload description.
#[cfg(any(target_arch = "wasm32", test))]
#[derive(Clone, Debug, Eq, PartialEq)]
struct CommandSummaryProjection {
    family: &'static str,
    payload: String,
}

/// The stable select key of one OEM action, so the form options and the
/// selected value stay one vocabulary.
#[cfg(any(target_arch = "wasm32", test))]
fn oem_action_key(action: OemActionView) -> &'static str {
    match action {
        OemActionView::ProfileUpdate => "profile-update",
        OemActionView::ProfileFactoryReset => "profile-factory-reset",
        OemActionView::ProfileActivate => "profile-activate",
        OemActionView::TokenGenerate => "token-generate",
        OemActionView::TokenInstall => "token-install",
        OemActionView::TokenDisable => "token-disable",
        OemActionView::TokenErase => "token-erase",
        OemActionView::PowerActivatePreset => "power-activate-preset",
        OemActionView::PowerApplyOverrides => "power-apply-overrides",
    }
}

/// Projects one command draft into its one-line card summary.
///
/// The same projection feeds the form preview (what will be submitted) and
/// the operation card (what was submitted), so the two can never disagree on
/// how a command reads.
#[cfg(any(target_arch = "wasm32", test))]
fn command_summary(command: &OperationCommandDraft) -> CommandSummaryProjection {
    match command {
        OperationCommandDraft::Reset { family, reset_type } => CommandSummaryProjection {
            family: family.label(),
            payload: reset_type.as_str().to_owned(),
        },
        OperationCommandDraft::BootOverride {
            source,
            enabled,
            mode,
        } => CommandSummaryProjection {
            family: CommandFamilyView::BootOverride.label(),
            payload: format!(
                "{} · {} · {}",
                source.as_str(),
                enabled.as_str(),
                mode.as_str()
            ),
        },
        OperationCommandDraft::SecureBoot(action) => {
            let payload = match action {
                SecureBootActionView::Enable => "Enable".to_owned(),
                SecureBootActionView::Disable => "Disable".to_owned(),
                SecureBootActionView::ResetKeys(kind) => {
                    format!("Reset keys · {}", kind.as_str())
                }
            };
            CommandSummaryProjection {
                family: CommandFamilyView::SecureBoot.label(),
                payload,
            }
        }
        OperationCommandDraft::Event(action) => {
            let payload = match action {
                EventActionDraft::CreateSubscription {
                    destination,
                    protocol,
                    event_types,
                } => format!(
                    "Create · {} · {} · {}",
                    destination,
                    protocol.as_str(),
                    event_types
                        .iter()
                        .map(|kind| kind.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                EventActionDraft::DeleteSubscription { subscription_id } => {
                    format!("Delete · {subscription_id}")
                }
            };
            CommandSummaryProjection {
                family: CommandFamilyView::EventSubscription.label(),
                payload,
            }
        }
        OperationCommandDraft::Update(update) => {
            // The artifact id renders in the same short form as the artifact
            // card, so the preview and the operation card of a submitted
            // update agree on how the artifact is identified.
            let artifact_short_id = short_sha256(&update.artifact_id);
            let payload = match update.push_uri.as_deref() {
                Some(uri) => format!("Start · {artifact_short_id} · push {uri}"),
                None => format!("Start · {artifact_short_id} · multipart"),
            };
            CommandSummaryProjection {
                family: CommandFamilyView::FirmwareUpdate.label(),
                payload,
            }
        }
        OperationCommandDraft::Oem(draft) => CommandSummaryProjection {
            family: CommandFamilyView::Oem.label(),
            payload: oem_draft_summary(draft),
        },
    }
}

/// One-line payload summary of an NVIDIA OEM command draft.
#[cfg(any(target_arch = "wasm32", test))]
fn oem_draft_summary(draft: &OemCommandDraft) -> String {
    match draft {
        OemCommandDraft::ProfileUpdate { .. } => "Profile · Update".to_owned(),
        OemCommandDraft::ProfileFactoryReset => "Profile · Factory reset".to_owned(),
        OemCommandDraft::ProfileActivate => "Profile · Activate".to_owned(),
        OemCommandDraft::TokenGenerate { token_type } => {
            format!("Token · Generate · {}", token_type.as_str())
        }
        OemCommandDraft::TokenInstall { .. } => "Token · Install".to_owned(),
        OemCommandDraft::TokenDisable => "Token · Disable".to_owned(),
        OemCommandDraft::TokenErase {
            erase_type,
            token_type,
        } => format!(
            "Token · Erase · {} · {}",
            erase_type.as_str(),
            token_type.as_str()
        ),
        OemCommandDraft::PowerActivatePreset { profile_id } => {
            format!("Power smoothing · Activate preset · {profile_id}")
        }
        OemCommandDraft::PowerApplyOverrides => "Power smoothing · Apply overrides".to_owned(),
    }
}

/// Client-side draft of one operation submission (§13.1).
///
/// The user picks one or more endpoints, one command family, and that
/// family's parameters; `try_build` mirrors the domain boundaries (a batch
/// is a list of targets, a subscription needs at least one event type) so an
/// incomplete draft is rejected before any request is sent.
#[cfg(any(target_arch = "wasm32", test))]
#[derive(Clone, Debug, Eq, PartialEq)]
struct OperationFormDraft {
    selected_endpoint_ids: Vec<String>,
    family: Option<CommandFamilyView>,
    reset_type: Option<ResetTypeView>,
    boot_source: Option<BootSourceView>,
    boot_enabled: Option<BootEnabledView>,
    boot_mode: Option<BootModeView>,
    secure_boot_action: Option<SecureBootActionView>,
    reset_keys_type: Option<ResetKeysTypeView>,
    event_action: Option<EventActionView>,
    destination: String,
    protocol: Option<EventProtocolView>,
    event_types: Vec<EventTypeView>,
    subscription_id: String,
    /// The selected §14.3 artifact id. Only ready artifacts are offered by
    /// the form (see [`update_artifact_choices`]), so a filled draft always
    /// names a complete, verified artifact.
    artifact_id: Option<String>,
    /// The optional push URI; empty means the default multipart dispatch of
    /// the locally stored artifact.
    push_uri: String,
    /// The chosen NVIDIA OEM face (grouping the action select).
    oem_face: Option<OemFaceView>,
    /// The chosen NVIDIA OEM action.
    oem_action: Option<OemActionView>,
    /// The JSON profile file content of a profile update.
    profile_file: String,
    /// The token type argument of the debug-token actions.
    token_type: Option<TokenTypeView>,
    /// The Base64 token data of a token installation.
    token_data: String,
    /// The erase scope argument of the token erase action.
    erase_type: Option<EraseTypeView>,
    /// The preset profile id of a power-smoothing activation.
    profile_id: String,
}

#[cfg(any(target_arch = "wasm32", test))]
impl OperationFormDraft {
    /// Builds an empty draft: no targets, no family, no parameters.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            selected_endpoint_ids: Vec::new(),
            family: None,
            reset_type: None,
            boot_source: None,
            boot_enabled: None,
            boot_mode: None,
            secure_boot_action: None,
            reset_keys_type: None,
            event_action: None,
            destination: String::new(),
            protocol: None,
            event_types: Vec::new(),
            subscription_id: String::new(),
            artifact_id: None,
            push_uri: String::new(),
            oem_face: None,
            oem_action: None,
            profile_file: String::new(),
            token_type: None,
            token_data: String::new(),
            erase_type: None,
            profile_id: String::new(),
        }
    }

    /// Reports whether one endpoint is currently a target of the draft.
    #[must_use]
    pub fn is_endpoint_selected(&self, endpoint_id: &str) -> bool {
        self.selected_endpoint_ids
            .iter()
            .any(|id| id == endpoint_id)
    }

    /// Toggles one endpoint in the target list; a batch (§13.7) may carry
    /// several endpoints.
    pub fn toggle_endpoint(&mut self, endpoint_id: String) {
        if let Some(index) = self
            .selected_endpoint_ids
            .iter()
            .position(|id| *id == endpoint_id)
        {
            self.selected_endpoint_ids.remove(index);
        } else {
            self.selected_endpoint_ids.push(endpoint_id);
        }
    }

    /// Builds the typed command draft, rejecting every incomplete form.
    ///
    /// Validation order follows the submission flow: targets first (an
    /// operation without a target could never execute), then the family,
    /// then that family's parameters. The first invalid field wins, exactly
    /// like the credential draft validation.
    ///
    /// # Errors
    ///
    /// Returns the first invalid field as [`OperationFormError`].
    // The validation walks every §7.5 family in order; the pedantic line
    // budget is exceeded by the family count, so the lint is scoped here.
    #[allow(clippy::too_many_lines)]
    pub fn try_build(&self) -> Result<OperationCommandDraft, OperationFormError> {
        if self.selected_endpoint_ids.is_empty() {
            return Err(OperationFormError::EndpointsRequired);
        }
        let Some(family) = self.family else {
            return Err(OperationFormError::FamilyRequired);
        };
        match family {
            CommandFamilyView::SystemReset
            | CommandFamilyView::ManagerReset
            | CommandFamilyView::ChassisReset => {
                let Some(reset_type) = self.reset_type else {
                    return Err(OperationFormError::ResetTypeRequired);
                };
                let family = match family {
                    CommandFamilyView::SystemReset => ResetResourceView::System,
                    CommandFamilyView::ManagerReset => ResetResourceView::Manager,
                    CommandFamilyView::ChassisReset => ResetResourceView::Chassis,
                    CommandFamilyView::BootOverride
                    | CommandFamilyView::SecureBoot
                    | CommandFamilyView::EventSubscription
                    | CommandFamilyView::FirmwareUpdate
                    | CommandFamilyView::Oem => {
                        // Refused rather than fabricated: the reset arm only
                        // ever receives a reset family from the outer match.
                        return Err(OperationFormError::FamilyRequired);
                    }
                };
                Ok(OperationCommandDraft::Reset { family, reset_type })
            }
            CommandFamilyView::BootOverride => {
                let Some(source) = self.boot_source else {
                    return Err(OperationFormError::BootSourceRequired);
                };
                let Some(enabled) = self.boot_enabled else {
                    return Err(OperationFormError::BootEnabledRequired);
                };
                let Some(mode) = self.boot_mode else {
                    return Err(OperationFormError::BootModeRequired);
                };
                Ok(OperationCommandDraft::BootOverride {
                    source,
                    enabled,
                    mode,
                })
            }
            CommandFamilyView::SecureBoot => {
                let Some(action) = self.secure_boot_action else {
                    return Err(OperationFormError::SecureBootActionRequired);
                };
                let action = match action {
                    SecureBootActionView::ResetKeys(_) => {
                        let Some(kind) = self.reset_keys_type else {
                            return Err(OperationFormError::ResetKeysTypeRequired);
                        };
                        SecureBootActionView::ResetKeys(kind)
                    }
                    _ => action,
                };
                Ok(OperationCommandDraft::SecureBoot(action))
            }
            CommandFamilyView::EventSubscription => {
                let Some(action) = self.event_action else {
                    return Err(OperationFormError::EventActionRequired);
                };
                match action {
                    EventActionView::CreateSubscription => {
                        event_destination_draft_error(&self.destination)?;
                        let Some(protocol) = self.protocol else {
                            return Err(OperationFormError::ProtocolRequired);
                        };
                        if self.event_types.is_empty() {
                            return Err(OperationFormError::EventTypesRequired);
                        }
                        Ok(OperationCommandDraft::Event(
                            EventActionDraft::CreateSubscription {
                                destination: self.destination.trim().to_owned(),
                                protocol,
                                event_types: self.event_types.clone(),
                            },
                        ))
                    }
                    EventActionView::DeleteSubscription => {
                        let subscription_id = self.subscription_id.trim();
                        if subscription_id.is_empty() {
                            return Err(OperationFormError::SubscriptionIdRequired);
                        }
                        Ok(OperationCommandDraft::Event(
                            EventActionDraft::DeleteSubscription {
                                subscription_id: subscription_id.to_owned(),
                            },
                        ))
                    }
                }
            }
            CommandFamilyView::FirmwareUpdate => {
                Ok(OperationCommandDraft::Update(self.update_draft()?))
            }
            CommandFamilyView::Oem => {
                let Some(action) = self.oem_action else {
                    return Err(OperationFormError::OemActionRequired);
                };
                let draft = match action {
                    OemActionView::ProfileUpdate => {
                        let profile_file = self.profile_file.trim();
                        if profile_file.is_empty() {
                            return Err(OperationFormError::ProfileFileRequired);
                        }
                        OemCommandDraft::ProfileUpdate {
                            profile_file: profile_file.to_owned(),
                        }
                    }
                    OemActionView::ProfileFactoryReset => OemCommandDraft::ProfileFactoryReset,
                    OemActionView::ProfileActivate => OemCommandDraft::ProfileActivate,
                    OemActionView::TokenGenerate => {
                        let Some(token_type) = self.token_type else {
                            return Err(OperationFormError::TokenTypeRequired);
                        };
                        OemCommandDraft::TokenGenerate { token_type }
                    }
                    OemActionView::TokenInstall => {
                        let token_data = self.token_data.trim();
                        if token_data.is_empty() {
                            return Err(OperationFormError::TokenDataRequired);
                        }
                        OemCommandDraft::TokenInstall {
                            token_data: token_data.to_owned(),
                        }
                    }
                    OemActionView::TokenDisable => OemCommandDraft::TokenDisable,
                    OemActionView::TokenErase => {
                        let Some(erase_type) = self.erase_type else {
                            return Err(OperationFormError::EraseTypeRequired);
                        };
                        let Some(token_type) = self.token_type else {
                            return Err(OperationFormError::TokenTypeRequired);
                        };
                        OemCommandDraft::TokenErase {
                            erase_type,
                            token_type,
                        }
                    }
                    OemActionView::PowerActivatePreset => {
                        let profile_id = self
                            .profile_id
                            .trim()
                            .parse::<i64>()
                            .map_err(|_| OperationFormError::ProfileIdInvalid)?;
                        OemCommandDraft::PowerActivatePreset { profile_id }
                    }
                    OemActionView::PowerApplyOverrides => OemCommandDraft::PowerApplyOverrides,
                };
                Ok(OperationCommandDraft::Oem(draft))
            }
        }
    }

    /// Assembles the §14.3 update payload of a validated draft.
    ///
    /// The artifact selection is required: the operation engine can only
    /// start an update from one complete, verified artifact, and the form
    /// offers only ready artifacts, so an unset id is a missing choice rather
    /// than a bad one. The push URI is optional and checked separately.
    ///
    /// # Errors
    ///
    /// Returns [`OperationFormError::ArtifactRequired`] when no artifact was
    /// chosen and [`OperationFormError::PushUriInvalid`] when the push URI
    /// cannot be an http(s) URL.
    fn update_draft(&self) -> Result<UpdateDraft, OperationFormError> {
        let Some(artifact_id) = self.artifact_id.clone() else {
            return Err(OperationFormError::ArtifactRequired);
        };
        let push_uri = update_push_uri_draft_error(&self.push_uri)?;
        Ok(UpdateDraft {
            artifact_id,
            push_uri,
        })
    }
}

/// Why an operation draft cannot be submitted.
#[cfg(any(target_arch = "wasm32", test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OperationFormError {
    EndpointsRequired,
    FamilyRequired,
    ResetTypeRequired,
    BootSourceRequired,
    BootEnabledRequired,
    BootModeRequired,
    SecureBootActionRequired,
    ResetKeysTypeRequired,
    EventActionRequired,
    DestinationRequired,
    DestinationInvalid,
    ProtocolRequired,
    EventTypesRequired,
    SubscriptionIdRequired,
    ArtifactRequired,
    PushUriInvalid,
    OemActionRequired,
    ProfileFileRequired,
    TokenTypeRequired,
    TokenDataRequired,
    EraseTypeRequired,
    ProfileIdInvalid,
}

#[cfg(any(target_arch = "wasm32", test))]
impl OperationFormError {
    /// Static message shown under the offending field.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::EndpointsRequired => "Select at least one endpoint.",
            Self::FamilyRequired => "Choose a command family.",
            Self::ResetTypeRequired => "Choose a reset type.",
            Self::BootSourceRequired => "Choose a boot source.",
            Self::BootEnabledRequired => "Choose how long the override applies.",
            Self::BootModeRequired => "Choose a boot mode.",
            Self::SecureBootActionRequired => "Choose a Secure Boot action.",
            Self::ResetKeysTypeRequired => "Choose the key set to reset.",
            Self::EventActionRequired => "Choose an event action.",
            Self::DestinationRequired => "A destination URL is required.",
            Self::DestinationInvalid => "The destination must be a URL with a host.",
            Self::ProtocolRequired => "Choose a delivery protocol.",
            Self::EventTypesRequired => "Select at least one event type.",
            Self::SubscriptionIdRequired => "A subscription ID is required.",
            Self::ArtifactRequired => "Choose a ready firmware artifact.",
            Self::PushUriInvalid => "The push URI must be an http(s) URL.",
            Self::OemActionRequired => "Choose an OEM action.",
            Self::ProfileFileRequired => "The profile file JSON is required.",
            Self::TokenTypeRequired => "Choose a token type.",
            Self::TokenDataRequired => "The Base64 token data is required.",
            Self::EraseTypeRequired => "Choose the erase scope.",
            Self::ProfileIdInvalid => "The profile id must be a whole number.",
        }
    }
}

/// Checks one optional firmware push URI (§14.3).
///
/// An empty value means the default dispatch path: the operation engine
/// reads the verified artifact from the local store and pushes it to the BMC
/// as multipart. A filled value must be an http(s) URL that the engine can
/// push the artifact bytes to; any other scheme, a missing host, or embedded
/// whitespace is rejected up front, mirroring the subscription destination
/// draft rules. The server remains authoritative during submission; this
/// check only rejects drafts that could never be a usable push URI.
#[cfg(any(target_arch = "wasm32", test))]
fn update_push_uri_draft_error(value: &str) -> Result<Option<String>, OperationFormError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if trimmed.contains(char::is_whitespace) {
        return Err(OperationFormError::PushUriInvalid);
    }
    let Some((scheme, rest)) = trimmed.split_once("://") else {
        return Err(OperationFormError::PushUriInvalid);
    };
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return Err(OperationFormError::PushUriInvalid);
    }
    let host = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if host.is_empty() {
        return Err(OperationFormError::PushUriInvalid);
    }
    Ok(Some(trimmed.to_owned()))
}

/// Checks one event subscription destination URL.
///
/// The server remains authoritative during submission; this client-side
/// check only rejects drafts that could never be a URL (empty, whitespace,
/// no scheme, no host), mirroring the endpoint-address draft rules.
#[cfg(any(target_arch = "wasm32", test))]
fn event_destination_draft_error(value: &str) -> Result<(), OperationFormError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(OperationFormError::DestinationRequired);
    }
    if trimmed.contains(char::is_whitespace) {
        return Err(OperationFormError::DestinationInvalid);
    }
    let Some(rest) = trimmed.split_once("://") else {
        return Err(OperationFormError::DestinationInvalid);
    };
    let host = rest.1.split(['/', '?', '#']).next().unwrap_or_default();
    if host.is_empty() {
        return Err(OperationFormError::DestinationInvalid);
    }
    Ok(())
}

/// The submission phase of one operation form.
#[cfg(any(target_arch = "wasm32", test))]
#[derive(Clone, Debug, Eq, PartialEq)]
enum OperationSubmitState {
    Idle,
    InFlight,
    Succeeded,
    Failed(&'static str),
}

#[cfg(any(target_arch = "wasm32", test))]
impl OperationSubmitState {
    /// Static message for a rejected submission; the route may have refused
    /// the request or the network may have failed, so the fields are the
    /// only actionable advice.
    const FAILURE_MESSAGE: &'static str =
        "The operation could not be submitted. Check the fields and try again.";

    const fn is_in_flight(&self) -> bool {
        matches!(self, Self::InFlight)
    }

    const fn is_succeeded(&self) -> bool {
        matches!(self, Self::Succeeded)
    }

    const fn failure_message(&self) -> &'static str {
        match self {
            Self::Failed(message) => message,
            Self::Idle | Self::InFlight | Self::Succeeded => "",
        }
    }
}

/// The loading state of the §13 operations list.
#[cfg(any(target_arch = "wasm32", test))]
#[derive(Clone, Debug, Eq, PartialEq)]
enum OperationsListState {
    Loading,
    Ready(Vec<OperationCardProjection>),
    Failed,
}

#[cfg(any(target_arch = "wasm32", test))]
impl OperationsListState {
    const fn is_loading(&self) -> bool {
        matches!(self, Self::Loading)
    }

    const fn is_failed(&self) -> bool {
        matches!(self, Self::Failed)
    }

    const fn is_ready(&self) -> bool {
        matches!(self, Self::Ready(_))
    }

    fn has_empty_list(&self) -> bool {
        matches!(self, Self::Ready(cards) if cards.is_empty())
    }

    /// One-line count heading, e.g. "3 operations".
    fn count_text(&self) -> String {
        let count = match self {
            Self::Ready(cards) => cards.len(),
            Self::Loading | Self::Failed => 0,
        };
        match count {
            1 => "1 operation".to_owned(),
            _ => format!("{count} operations"),
        }
    }

    fn cards(&self) -> Vec<OperationCardProjection> {
        match self {
            Self::Ready(cards) => cards.clone(),
            Self::Loading | Self::Failed => Vec::new(),
        }
    }
}

/// One §13 operation projected for a list card.
#[cfg(any(target_arch = "wasm32", test))]
#[derive(Clone, Debug, Eq, PartialEq)]
struct OperationCardProjection {
    operation_id: String,
    short_id: String,
    source: OperationSourceView,
    target_count: usize,
    state: OperationStateView,
    command: CommandSummaryProjection,
    created_at_text: String,
    updated_at_text: String,
}

#[cfg(any(target_arch = "wasm32", test))]
impl OperationCardProjection {
    /// Static badge label of the current phase.
    #[must_use]
    pub const fn state_label(&self) -> &'static str {
        self.state.label()
    }

    /// Semantic badge styling of the current phase.
    #[must_use]
    pub const fn state_class(&self) -> &'static str {
        self.state.class()
    }

    /// Static label of the operation origin.
    #[must_use]
    pub const fn source_label(&self) -> &'static str {
        self.source.label()
    }
}

/// Compact card identity for one operation id: its first 8 characters.
///
/// Operation ids are UUID v7 strings; the full id stays available as the
/// card title attribute while the short form keeps the card grid scannable.
#[cfg(any(target_arch = "wasm32", test))]
fn short_operation_id(operation_id: &str) -> String {
    operation_id.chars().take(8).collect()
}

/// One endpoint offered as an operation target, projected from the local
/// inventory.
#[cfg(any(target_arch = "wasm32", test))]
#[derive(Clone, Debug, Eq, PartialEq)]
struct OperationEndpointChoice {
    endpoint_id: String,
    display_name: String,
    address: String,
}

/// Projects the endpoint inventory into the operation form's target choices.
#[cfg(any(target_arch = "wasm32", test))]
fn operation_endpoint_choices(
    inventory: &EndpointInventoryResponse,
) -> Vec<OperationEndpointChoice> {
    inventory
        .endpoints()
        .iter()
        .map(|endpoint| {
            let identity = endpoint.identity();
            OperationEndpointChoice {
                endpoint_id: identity.endpoint_id().to_string(),
                display_name: identity.display_name().to_owned(),
                address: identity.address().to_owned(),
            }
        })
        .collect()
}

/// One ready firmware artifact offered by the update form.
#[cfg(any(target_arch = "wasm32", test))]
#[derive(Clone, Debug, Eq, PartialEq)]
struct UpdateArtifactChoice {
    artifact_id: String,
    name: String,
    size_text: String,
}

/// Projects the §14.3 artifact list into the update form's choices.
///
/// Only `ready` artifacts are offered: an uploading artifact has an
/// incomplete byte range, and a failed one was rejected by the finalize
/// verification, so neither can be dispatched to a BMC — the operation
/// engine can only start a firmware update from a complete, verified
/// artifact. The other two states stay visible in the Artifacts view (where
/// uploads resume) but are never selectable here.
#[cfg(any(target_arch = "wasm32", test))]
fn update_artifact_choices(artifacts: &[ArtifactCardProjection]) -> Vec<UpdateArtifactChoice> {
    artifacts
        .iter()
        .filter(|card| card.status == ArtifactStatusView::Ready)
        .map(|card| UpdateArtifactChoice {
            artifact_id: card.artifact_id.clone(),
            name: card.name.clone(),
            size_text: card.size_text.clone(),
        })
        .collect()
}

/// One uploaded or in-flight firmware artifact, projected for a list card.
///
/// `size_bytes` and `uploaded_bytes` stay numeric so the card renders the
/// §0.4.0 resume progress without re-parsing text. The sha-256 field is the
/// declared digest the server verified at finalize; the wire always carries
/// it, even while uploading, because the digest is declared up front.
#[cfg(any(target_arch = "wasm32", test))]
#[derive(Clone, Debug, Eq, PartialEq)]
struct ArtifactCardProjection {
    artifact_id: String,
    short_id: String,
    name: String,
    size_text: String,
    sha256_short: String,
    status: ArtifactStatusView,
    uploaded_bytes: u64,
    size_bytes: u64,
    progress_percent: u8,
    created_at_text: String,
}

#[cfg(any(target_arch = "wasm32", test))]
impl ArtifactCardProjection {
    #[must_use]
    pub const fn is_uploading(&self) -> bool {
        matches!(self.status, ArtifactStatusView::Uploading)
    }

    /// Whether this artifact has every byte and only awaits `finalize`, so a
    /// matching file selection resumes directly into the finalize step.
    #[must_use]
    pub const fn is_completely_uploaded(&self) -> bool {
        self.uploaded_bytes >= self.size_bytes
    }

    #[must_use]
    pub const fn status_label(&self) -> &'static str {
        self.status.label()
    }

    #[must_use]
    pub const fn status_class(&self) -> &'static str {
        self.status.class()
    }
}

/// The §14.3 lifecycle of one artifact as display vocabulary.
///
/// `Uploading` is the only resumable state: the server's `uploaded_bytes`
/// defines the next chunk boundary. `Ready` is terminal and awaits the
/// §14.3 `UpdateService` step; `Failed` is terminal and static.
#[cfg(any(target_arch = "wasm32", test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ArtifactStatusView {
    Uploading,
    Ready,
    Failed,
}

#[cfg(any(target_arch = "wasm32", test))]
impl ArtifactStatusView {
    /// Static English badge label for one artifact lifecycle state.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Uploading => "Uploading",
            Self::Ready => "Ready",
            Self::Failed => "Failed",
        }
    }

    /// Semantic badge styling, following the capability and operation badge
    /// vocabulary: `Ready` is ok (green), `Failed` is error (red), and
    /// `Uploading` is active (blue) because it is in flight and resumable.
    #[must_use]
    pub const fn class(self) -> &'static str {
        match self {
            Self::Uploading => "artifact-state artifact-active",
            Self::Ready => "artifact-state artifact-ok",
            Self::Failed => "artifact-state artifact-error",
        }
    }
}

/// Maps the wire artifact lifecycle state onto the display vocabulary.
#[cfg(any(target_arch = "wasm32", test))]
impl From<ArtifactStateResponse> for ArtifactStatusView {
    fn from(state: ArtifactStateResponse) -> Self {
        match state {
            ArtifactStateResponse::Uploading => Self::Uploading,
            ArtifactStateResponse::Ready => Self::Ready,
            ArtifactStateResponse::Failed => Self::Failed,
        }
    }
}

/// Projects one §9.3 artifact row into its list card.
///
/// The sha-256 short code renders the declared digest — the same digest the
/// server verified at finalize — so a `ready` card and a `failed` card are
/// distinguishable by the same visible hash.
#[cfg(any(target_arch = "wasm32", test))]
impl From<&ArtifactResponse> for ArtifactCardProjection {
    fn from(artifact: &ArtifactResponse) -> Self {
        Self {
            artifact_id: artifact.artifact_id().to_string(),
            short_id: short_sha256(&artifact.artifact_id().to_string()),
            name: artifact.name().to_owned(),
            size_text: format_artifact_size(artifact.size_bytes()),
            sha256_short: short_sha256(artifact.sha256()),
            status: ArtifactStatusView::from(artifact.state()),
            uploaded_bytes: artifact.uploaded_bytes(),
            size_bytes: artifact.size_bytes(),
            progress_percent: upload_progress_percent(
                artifact.uploaded_bytes(),
                artifact.size_bytes(),
            ),
            created_at_text: format_observed_at(&artifact.created_at()),
        }
    }
}

/// The loading state of the §14.3 artifact list.
#[cfg(any(target_arch = "wasm32", test))]
#[derive(Clone, Debug, Eq, PartialEq)]
enum ArtifactsListState {
    Loading,
    Ready(Vec<ArtifactCardProjection>),
    Failed,
}

#[cfg(any(target_arch = "wasm32", test))]
impl ArtifactsListState {
    const fn is_loading(&self) -> bool {
        matches!(self, Self::Loading)
    }

    const fn is_failed(&self) -> bool {
        matches!(self, Self::Failed)
    }

    const fn is_ready(&self) -> bool {
        matches!(self, Self::Ready(_))
    }

    fn has_empty_list(&self) -> bool {
        matches!(self, Self::Ready(cards) if cards.is_empty())
    }

    /// One-line count heading, e.g. "3 artifacts".
    fn count_text(&self) -> String {
        let count = match self {
            Self::Ready(cards) => cards.len(),
            Self::Loading | Self::Failed => 0,
        };
        match count {
            1 => "1 artifact".to_owned(),
            _ => format!("{count} artifacts"),
        }
    }

    fn cards(&self) -> Vec<ArtifactCardProjection> {
        match self {
            Self::Ready(cards) => cards.clone(),
            Self::Loading | Self::Failed => Vec::new(),
        }
    }

    /// The uploading artifact whose name and declared size match a selected
    /// file, if any — the §0.4.0 interrupt-recovery anchor.
    fn resume_candidate(&self, name: &str, size_bytes: u64) -> Option<ArtifactCardProjection> {
        self.cards()
            .into_iter()
            .find(|card| card.is_uploading() && card.name == name && card.size_bytes == size_bytes)
    }
}

/// Why an artifact upload could not be created, appended to, or finalized.
///
/// Every message is either static copy or carries the HTTP status so the
/// console never invents a server-side reason.
#[cfg(any(target_arch = "wasm32", test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ArtifactUploadFailure {
    FileUnreadable,
    FileEmpty,
    CreateRejected { status: u16 },
    ChunkRejected { status: u16 },
    FinalizeRejected { status: u16 },
    Unavailable,
    MalformedResponse,
}

#[cfg(any(target_arch = "wasm32", test))]
impl ArtifactUploadFailure {
    fn message(self) -> String {
        match self {
            Self::FileUnreadable => "The selected file could not be read.".to_owned(),
            Self::FileEmpty => "The selected file is empty.".to_owned(),
            Self::CreateRejected { status } => {
                format!("The server rejected the artifact creation (HTTP {status}).")
            }
            Self::ChunkRejected { status } => {
                format!("The server rejected an upload chunk (HTTP {status}).")
            }
            Self::FinalizeRejected { status } => {
                format!("The server rejected the upload finalize (HTTP {status}).")
            }
            Self::Unavailable => "The artifact store is temporarily unavailable.".to_owned(),
            Self::MalformedResponse => "The server response could not be read.".to_owned(),
        }
    }
}

/// The §0.4.0 progression of one artifact upload submission.
///
/// The file bytes live in the `draft` while the upload runs; the state
/// machine only records which step is in flight so the form disables itself
/// and renders one progress bar. After a page reload the browser no longer
/// holds the file, so `Succeeded`/`Failed` are per-session outcomes and the
/// §0.4.0 resume path re-enters through the list's `uploading` cards.
#[cfg(any(target_arch = "wasm32", test))]
#[derive(Clone, Debug, Eq, PartialEq)]
enum ArtifactUploadState {
    Idle,
    Creating,
    /// The server's acknowledged byte count drives the progress bar; the
    /// chunk index and percentage are derived at render time.
    Uploading {
        artifact_id: String,
        uploaded_bytes: u64,
        total_bytes: u64,
    },
    Finalizing {
        artifact_id: String,
    },
    Succeeded,
    Failed(ArtifactUploadFailure),
}

/// One-line upload status text for the form, e.g. "Uploading chunk 2 of 3 ·
/// 45%". Empty for states the form renders through other elements.
#[cfg(any(target_arch = "wasm32", test))]
fn artifact_upload_status_text(state: &ArtifactUploadState) -> String {
    match state {
        ArtifactUploadState::Idle
        | ArtifactUploadState::Succeeded
        | ArtifactUploadState::Failed(_) => String::new(),
        ArtifactUploadState::Creating => "Creating artifact...".to_owned(),
        ArtifactUploadState::Uploading {
            uploaded_bytes,
            total_bytes,
            ..
        } => {
            let chunk_index = uploaded_bytes / ARTIFACT_CHUNK_BYTES + 1;
            let total_chunks = artifact_chunk_ranges(*total_bytes).len().max(1);
            format!(
                "Uploading chunk {chunk_index} of {total_chunks} · {}%",
                upload_progress_percent(*uploaded_bytes, *total_bytes)
            )
        }
        ArtifactUploadState::Finalizing { .. } => "Verifying the uploaded digest...".to_owned(),
    }
}

#[cfg(any(target_arch = "wasm32", test))]
impl ArtifactUploadState {
    const fn is_in_flight(&self) -> bool {
        matches!(
            self,
            Self::Creating | Self::Uploading { .. } | Self::Finalizing { .. }
        )
    }

    const fn is_failed(&self) -> bool {
        matches!(self, Self::Failed(_))
    }

    const fn is_succeeded(&self) -> bool {
        matches!(self, Self::Succeeded)
    }

    fn failure_message(&self) -> String {
        match self {
            Self::Failed(failure) => failure.message(),
            _ => String::new(),
        }
    }
}

/// One artifact upload chunk: the byte range the client slices out of the
/// file for a single `chunks` request.
#[cfg(any(target_arch = "wasm32", test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ArtifactChunkRange {
    offset: u64,
    length: usize,
}

/// The §0.4.0 per-chunk payload size: 3 MiB, the largest byte range whose
/// base64 encoding fits the server's chunk-text cap.
///
/// The chunk contract caps the base64 *text* of a chunk at 4 MiB characters,
/// and 3 payload bytes expand to exactly 4 base64 characters, so 3 MiB of
/// payload encodes to exactly 4 MiB of text — the largest accepted chunk.
#[cfg(any(target_arch = "wasm32", test))]
const ARTIFACT_CHUNK_BYTES: u64 = 3 * 1024 * 1024;

/// The chunk the client must send next, derived from the server's
/// `uploaded_bytes` count.
///
/// The chunk contract requires `offset` to equal the bytes already received
/// and never to merge a hole, so the resume offset is the server count
/// itself — never rounded to a chunk boundary, because the server may have
/// acknowledged a shorter final append. A file whose `uploaded_bytes` equals
/// its size yields `None`: callers check `is_completely_uploaded` first and
/// jump straight to `finalize`.
#[cfg(any(target_arch = "wasm32", test))]
fn artifact_chunk_range_at(offset: u64, total_bytes: u64) -> Option<ArtifactChunkRange> {
    if offset >= total_bytes {
        return None;
    }
    let length = u64::min(ARTIFACT_CHUNK_BYTES, total_bytes - offset);
    Some(ArtifactChunkRange {
        offset,
        length: usize::try_from(length).ok().unwrap_or(0),
    })
}

/// Splits a file into the strictly ordered chunk ranges of a fresh upload:
/// every chunk except the last is exactly 3 MiB of payload — the largest
/// range whose base64 text fits the server's 4 MiB character cap — and the
/// last chunk is the remainder.
#[cfg(any(target_arch = "wasm32", test))]
fn artifact_chunk_ranges(total_bytes: u64) -> Vec<ArtifactChunkRange> {
    let mut ranges = Vec::new();
    let mut offset = 0;
    while let Some(range) = artifact_chunk_range_at(offset, total_bytes) {
        ranges.push(range);
        offset += range.length as u64;
    }
    ranges
}

/// Upload progress in whole percent, clamped to 0..=100 so a server that
/// reports slightly more than the declared size cannot render an overfull
/// bar.
#[cfg(any(target_arch = "wasm32", test))]
fn upload_progress_percent(uploaded_bytes: u64, total_bytes: u64) -> u8 {
    if total_bytes == 0 {
        return 100;
    }
    let percent = uploaded_bytes.saturating_mul(100) / total_bytes;
    u8::try_from(percent).ok().unwrap_or(100).min(100)
}

/// Human-readable binary size, e.g. "512 B", "1.5 KiB", "4 MiB", "1.2 GiB".
///
/// The decimal is derived from integer remainder arithmetic so a `u64` byte
/// count never loses precision through an `f64` cast.
#[cfg(any(target_arch = "wasm32", test))]
fn format_artifact_size(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    let mut unit_index = 0;
    let mut scaled = bytes;
    while scaled >= 1024 && unit_index + 1 < UNITS.len() {
        scaled /= 1024;
        unit_index += 1;
    }
    if unit_index == 0 {
        return format!("{bytes} B");
    }
    let unit_bytes = 1024_u64.pow(u32::try_from(unit_index).ok().unwrap_or(0));
    let tenths = (bytes % unit_bytes) * 10 / unit_bytes;
    format!("{scaled}.{tenths} {}", UNITS[unit_index])
}

/// Compact card identity for one sha-256 digest: its first 8 characters.
///
/// The full digest stays available in the card body while the short form
/// keeps the card grid scannable, mirroring the operation id convention.
#[cfg(any(target_arch = "wasm32", test))]
fn short_sha256(sha256: &str) -> String {
    sha256.chars().take(8).collect()
}

/// RFC 4648 base64 with padding, standard alphabet.
///
/// Hand-rolled because the workspace does not depend on a base64 crate and
/// this iteration's file budget is limited to `ui/src/lib.rs`; the encoding
/// is host-tested against RFC 4648 vectors. The browser API never sees the
/// encoder — chunks cross the FFI boundary as base64 strings.
#[cfg(any(target_arch = "wasm32", test))]
fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = u32::from(chunk.get(1).copied().unwrap_or(0));
        let b2 = u32::from(chunk.get(2).copied().unwrap_or(0));
        encoded.push(ALPHABET[(b0 >> 2) as usize] as char);
        encoded.push(ALPHABET[((b0 & 0x03) << 4 | b1 >> 4) as usize] as char);
        if chunk.len() >= 2 {
            encoded.push(ALPHABET[((b1 & 0x0F) << 2 | b2 >> 6) as usize] as char);
        } else {
            encoded.push('=');
        }
        if chunk.len() >= 3 {
            encoded.push(ALPHABET[(b2 & 0x3F) as usize] as char);
        } else {
            encoded.push('=');
        }
    }
    encoded
}

/// The 64 round constants of FIPS 180-4 §4.2.2: the fractional parts of the
/// cube roots of the first 64 primes, written as big-endian words.
#[cfg(any(target_arch = "wasm32", test))]
const SHA256_K: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

/// SHA-256 of a byte slice, lowercase hex.
///
/// Hand-rolled from FIPS 180-4 because the `CreateArtifactRequest.sha256`
/// field is required at creation time and the UI crate cannot add the
/// workspace `sha2` dependency within this iteration's file budget. The
/// server independently recomputes and verifies the digest at finalize, so a
/// defective client hash surfaces as a clean `failed` verdict instead of a
/// corrupted BMC flash. Correctness is pinned by the RFC 6234 vectors in the
/// test module.
#[cfg(any(target_arch = "wasm32", test))]
fn sha256_hex(bytes: &[u8]) -> String {
    // The eight initial hash values of FIPS 180-4 §5.3.3: the fractional
    // parts of the square roots of the first eight primes.
    let mut state = [
        0x6a09_e667,
        0xbb67_ae85,
        0x3c6e_f372,
        0xa54f_f53a,
        0x510e_527f,
        0x9b05_688c,
        0x1f83_d9ab,
        0x5be0_cd19,
    ];
    let total_bytes = u64::try_from(bytes.len()).ok().unwrap_or(0);

    // Every full 64-byte block is compressed as it arrives; the remainder
    // and the padded final block are handled below. Padding appends 0x80,
    // then zeros up to 56 bytes, then the big-endian 64-bit bit length, so
    // the padding never spills past one extra block.
    let mut blocks = bytes.chunks_exact(64);
    for block in blocks.by_ref() {
        let schedule = sha256_schedule(block);
        state = sha256_compress(&state, &schedule);
    }
    let remainder = blocks.remainder();

    let mut tail = [0_u8; 128];
    let remaining = remainder.len();
    tail[..remaining].copy_from_slice(remainder);
    tail[remaining] = 0x80;
    if remaining >= 56 {
        let bit_length = total_bytes.wrapping_mul(8);
        tail[120..128].copy_from_slice(&bit_length.to_be_bytes());
        let schedule = sha256_schedule(&tail[..64]);
        state = sha256_compress(&state, &schedule);
        let schedule = sha256_schedule(&tail[64..128]);
        state = sha256_compress(&state, &schedule);
    } else {
        let bit_length = total_bytes.wrapping_mul(8);
        tail[56..64].copy_from_slice(&bit_length.to_be_bytes());
        let schedule = sha256_schedule(&tail[..64]);
        state = sha256_compress(&state, &schedule);
    }

    let mut digest = String::with_capacity(64);
    for word in state {
        // `write!` into a String cannot fail; the `_ =` discards the
        // infallible `fmt::Result`.
        let _ = std::fmt::Write::write_fmt(&mut digest, format_args!("{word:08x}"));
    }
    digest
}

/// Builds the 64-word message schedule from one 64-byte block (FIPS 180-4
/// §6.2.2 step 1): the first 16 words are big-endian bytes, the rest are
/// mixed with the `sigma0` and `sigma1` rotations.
#[cfg(any(target_arch = "wasm32", test))]
fn sha256_schedule(block: &[u8]) -> [u32; 64] {
    let mut schedule = [0_u32; 64];
    for (word_index, word) in schedule.iter_mut().enumerate().take(16) {
        let start = word_index * 4;
        *word = (u32::from(block[start]) << 24)
            | (u32::from(block[start + 1]) << 16)
            | (u32::from(block[start + 2]) << 8)
            | u32::from(block[start + 3]);
    }
    for word_index in 16..64 {
        let w15 = schedule[word_index - 15];
        let w2 = schedule[word_index - 2];
        let sigma0 = w15.rotate_right(7) ^ w15.rotate_right(18) ^ (w15 >> 3);
        let sigma1 = w2.rotate_right(17) ^ w2.rotate_right(19) ^ (w2 >> 10);
        schedule[word_index] = schedule[word_index - 16]
            .wrapping_add(sigma0)
            .wrapping_add(schedule[word_index - 7])
            .wrapping_add(sigma1);
    }
    schedule
}

/// One 64-round compression of the working state (FIPS 180-4 §6.2.2 steps
/// 2–4).
///
/// The working variables follow the FIPS 180-4 notation (`a` through `h`),
/// so the single-character names are deliberate and not ambiguous.
#[cfg(any(target_arch = "wasm32", test))]
#[allow(clippy::similar_names, clippy::many_single_char_names)]
fn sha256_compress(state: &[u32; 8], schedule: &[u32; 64]) -> [u32; 8] {
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for (round, constant) in SHA256_K.iter().enumerate() {
        let sigma1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let choice = (e & f) ^ (!e & g);
        let temp1 = h
            .wrapping_add(sigma1)
            .wrapping_add(choice)
            .wrapping_add(*constant)
            .wrapping_add(schedule[round]);
        let sigma0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let majority = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = sigma0.wrapping_add(majority);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }
    [
        state[0].wrapping_add(a),
        state[1].wrapping_add(b),
        state[2].wrapping_add(c),
        state[3].wrapping_add(d),
        state[4].wrapping_add(e),
        state[5].wrapping_add(f),
        state[6].wrapping_add(g),
        state[7].wrapping_add(h),
    ]
}

/// Maps the wire operation source onto the display vocabulary.
#[cfg(any(target_arch = "wasm32", test))]
impl From<OperationSourceResponse> for OperationSourceView {
    fn from(source: OperationSourceResponse) -> Self {
        match source {
            OperationSourceResponse::Standalone => Self::Standalone,
            OperationSourceResponse::Site => Self::Site,
            OperationSourceResponse::Center => Self::Center,
        }
    }
}

/// Maps the wire operation phase onto the display vocabulary.
#[cfg(any(target_arch = "wasm32", test))]
impl From<OperationStateResponse> for OperationStateView {
    fn from(state: OperationStateResponse) -> Self {
        match state {
            OperationStateResponse::Queued => Self::Queued,
            OperationStateResponse::Validating => Self::Validating,
            OperationStateResponse::Running => Self::Running,
            OperationStateResponse::WaitingRemote => Self::WaitingRemote,
            OperationStateResponse::Verifying => Self::Verifying,
            OperationStateResponse::Succeeded => Self::Succeeded,
            OperationStateResponse::Failed => Self::Failed,
            OperationStateResponse::Unknown => Self::Unknown,
            OperationStateResponse::Cancelled => Self::Cancelled,
        }
    }
}

/// Maps the form reset-type vocabulary onto the domain reset type.
#[cfg(any(target_arch = "wasm32", test))]
fn domain_reset_type(reset_type: ResetTypeView) -> ResetType {
    match reset_type {
        ResetTypeView::On => ResetType::On,
        ResetTypeView::ForceOff => ResetType::ForceOff,
        ResetTypeView::GracefulShutdown => ResetType::GracefulShutdown,
        ResetTypeView::GracefulRestart => ResetType::GracefulRestart,
        ResetTypeView::ForceRestart => ResetType::ForceRestart,
        ResetTypeView::Nmi => ResetType::Nmi,
        ResetTypeView::ForceOn => ResetType::ForceOn,
        ResetTypeView::PushPowerButton => ResetType::PushPowerButton,
        ResetTypeView::PowerCycle => ResetType::PowerCycle,
        ResetTypeView::Suspend => ResetType::Suspend,
        ResetTypeView::Pause => ResetType::Pause,
        ResetTypeView::Resume => ResetType::Resume,
        ResetTypeView::FullPowerCycle => ResetType::FullPowerCycle,
    }
}

/// Maps the form boot-source vocabulary onto the domain boot source.
#[cfg(any(target_arch = "wasm32", test))]
fn domain_boot_source(source: BootSourceView) -> BootSource {
    match source {
        BootSourceView::None => BootSource::None,
        BootSourceView::Pxe => BootSource::Pxe,
        BootSourceView::Floppy => BootSource::Floppy,
        BootSourceView::Cd => BootSource::Cd,
        BootSourceView::Usb => BootSource::Usb,
        BootSourceView::Hdd => BootSource::Hdd,
        BootSourceView::BiosSetup => BootSource::BiosSetup,
        BootSourceView::Utilities => BootSource::Utilities,
        BootSourceView::Diags => BootSource::Diags,
        BootSourceView::UefiShell => BootSource::UefiShell,
        BootSourceView::UefiTarget => BootSource::UefiTarget,
        BootSourceView::SdCard => BootSource::SdCard,
        BootSourceView::UefiHttp => BootSource::UefiHttp,
        BootSourceView::RemoteDrive => BootSource::RemoteDrive,
        BootSourceView::UefiBootNext => BootSource::UefiBootNext,
        BootSourceView::Recovery => BootSource::Recovery,
    }
}

/// Maps the form override-duration vocabulary onto the domain vocabulary.
#[cfg(any(target_arch = "wasm32", test))]
fn domain_boot_enabled(enabled: BootEnabledView) -> BootSourceOverrideEnabled {
    match enabled {
        BootEnabledView::Disabled => BootSourceOverrideEnabled::Disabled,
        BootEnabledView::Once => BootSourceOverrideEnabled::Once,
        BootEnabledView::Continuous => BootSourceOverrideEnabled::Continuous,
    }
}

/// Maps the form boot-mode vocabulary onto the domain vocabulary.
#[cfg(any(target_arch = "wasm32", test))]
fn domain_boot_mode(mode: BootModeView) -> BootSourceOverrideMode {
    match mode {
        BootModeView::Legacy => BootSourceOverrideMode::Legacy,
        BootModeView::Uefi => BootSourceOverrideMode::Uefi,
    }
}

/// Maps the form key-set vocabulary onto the domain vocabulary.
#[cfg(any(target_arch = "wasm32", test))]
fn domain_reset_keys(kind: ResetKeysTypeView) -> ResetKeysType {
    match kind {
        ResetKeysTypeView::ResetAllKeysToDefault => ResetKeysType::ResetAllKeysToDefault,
        ResetKeysTypeView::DeleteAllKeys => ResetKeysType::DeleteAllKeys,
        ResetKeysTypeView::DeletePk => ResetKeysType::DeletePk,
    }
}

/// Maps the form protocol vocabulary onto the domain vocabulary.
#[cfg(any(target_arch = "wasm32", test))]
fn domain_protocol(protocol: EventProtocolView) -> EventDestinationProtocol {
    match protocol {
        EventProtocolView::Redfish => EventDestinationProtocol::Redfish,
        EventProtocolView::Kafka => EventDestinationProtocol::Kafka,
        EventProtocolView::Snmpv1 => EventDestinationProtocol::Snmpv1,
        EventProtocolView::Snmpv2c => EventDestinationProtocol::Snmpv2c,
        EventProtocolView::Snmpv3 => EventDestinationProtocol::Snmpv3,
        EventProtocolView::Smtp => EventDestinationProtocol::Smtp,
        EventProtocolView::SyslogTls => EventDestinationProtocol::SyslogTls,
        EventProtocolView::SyslogTcp => EventDestinationProtocol::SyslogTcp,
        EventProtocolView::SyslogUdp => EventDestinationProtocol::SyslogUdp,
        EventProtocolView::SyslogRelp => EventDestinationProtocol::SyslogRelp,
        EventProtocolView::Oem => EventDestinationProtocol::Oem,
    }
}

/// Maps the form event-type vocabulary onto the domain vocabulary.
#[cfg(any(target_arch = "wasm32", test))]
fn domain_event_type(event_type: EventTypeView) -> EventType {
    match event_type {
        EventTypeView::StatusChange => EventType::StatusChange,
        EventTypeView::ResourceUpdated => EventType::ResourceUpdated,
        EventTypeView::ResourceAdded => EventType::ResourceAdded,
        EventTypeView::ResourceRemoved => EventType::ResourceRemoved,
        EventTypeView::Alert => EventType::Alert,
        EventTypeView::MetricReport => EventType::MetricReport,
        EventTypeView::Other => EventType::Other,
    }
}

/// Builds the typed §7.5 command from a validated form draft.
///
/// The command is the domain's own write surface, so the submission carries
/// exactly what the executor will dispatch (§13.3 step 7). Every form
/// vocabulary member maps to exactly one domain member; the const member-set
/// tests keep the two vocabularies aligned.
#[cfg(any(target_arch = "wasm32", test))]
// The mapping covers every §7.5 family and payload; the pedantic line budget
// is exceeded by the family count, so the lint is scoped here.
#[allow(clippy::too_many_lines)]
fn build_command(command: &OperationCommandDraft) -> Result<RedfishCommand, OperationFormError> {
    match command {
        OperationCommandDraft::Reset { family, reset_type } => {
            let reset_type = domain_reset_type(*reset_type);
            let command = match family {
                ResetResourceView::System => {
                    RedfishCommand::System(SystemCommand::Reset(reset_type))
                }
                ResetResourceView::Manager => {
                    RedfishCommand::Manager(ManagerCommand::Reset(reset_type))
                }
                ResetResourceView::Chassis => {
                    RedfishCommand::Chassis(ChassisCommand::Reset(reset_type))
                }
            };
            Ok(command)
        }
        OperationCommandDraft::BootOverride {
            source,
            enabled,
            mode,
        } => Ok(RedfishCommand::Boot(BootCommand::SetBootSourceOverride(
            SetBootSourceOverride::new(
                domain_boot_source(*source),
                domain_boot_enabled(*enabled),
                domain_boot_mode(*mode),
            ),
        ))),
        OperationCommandDraft::SecureBoot(action) => {
            let command = match action {
                SecureBootActionView::Enable => {
                    RedfishCommand::SecureBoot(SecureBootCommand::Enable)
                }
                SecureBootActionView::Disable => {
                    RedfishCommand::SecureBoot(SecureBootCommand::Disable)
                }
                SecureBootActionView::ResetKeys(kind) => RedfishCommand::SecureBoot(
                    SecureBootCommand::ResetKeys(domain_reset_keys(*kind)),
                ),
            };
            Ok(command)
        }
        OperationCommandDraft::Event(action) => match action {
            EventActionDraft::CreateSubscription {
                destination,
                protocol,
                event_types,
            } => {
                let event_types = event_types
                    .iter()
                    .map(|kind| domain_event_type(*kind))
                    .collect();
                let subscription = CreateSubscription::try_new(
                    destination.clone(),
                    domain_protocol(*protocol),
                    event_types,
                )
                .map_err(|_| OperationFormError::EventTypesRequired)?;
                Ok(RedfishCommand::Event(EventCommand::CreateSubscription(
                    subscription,
                )))
            }
            EventActionDraft::DeleteSubscription { subscription_id } => Ok(RedfishCommand::Event(
                EventCommand::DeleteSubscription(DeleteSubscription::new(subscription_id.clone())),
            )),
        },
        OperationCommandDraft::Update(update) => {
            // The id string parses into the domain's `ArtifactId` wrapper.
            // The API crate re-exports only the command surface, not
            // `ArtifactId`, so the wrapper type is inferred from
            // `StartUpdate::new`'s signature; a non-uuid string is refused
            // as a missing artifact choice because the form can only ever
            // offer server-provided uuids through the ready-only select.
            let artifact_id = update
                .artifact_id
                .parse()
                .map_err(|_| OperationFormError::ArtifactRequired)?;
            Ok(RedfishCommand::Update(UpdateCommand::StartUpdate(
                StartUpdate::new(artifact_id, update.push_uri.clone()),
            )))
        }
        OperationCommandDraft::Oem(draft) => {
            let command = match draft {
                OemCommandDraft::ProfileUpdate { profile_file } => RedfishCommand::Oem(
                    OemCommand::SystemConfigProfile(NvidiaSystemConfigProfileCommand::Update(
                        ProfileFile::new(profile_file.clone()),
                    )),
                ),
                OemCommandDraft::ProfileFactoryReset => RedfishCommand::Oem(
                    OemCommand::SystemConfigProfile(NvidiaSystemConfigProfileCommand::FactoryReset),
                ),
                OemCommandDraft::ProfileActivate => {
                    RedfishCommand::Oem(OemCommand::SystemConfigProfile(
                        NvidiaSystemConfigProfileCommand::ActivateProfile,
                    ))
                }
                OemCommandDraft::TokenGenerate { token_type } => {
                    RedfishCommand::Oem(OemCommand::DebugToken(
                        NvidiaDebugTokenCommand::GenerateToken(domain_token_type(*token_type)),
                    ))
                }
                OemCommandDraft::TokenInstall { token_data } => {
                    RedfishCommand::Oem(OemCommand::DebugToken(
                        NvidiaDebugTokenCommand::InstallToken(TokenData::new(token_data.clone())),
                    ))
                }
                OemCommandDraft::TokenDisable => RedfishCommand::Oem(OemCommand::DebugToken(
                    NvidiaDebugTokenCommand::DisableToken,
                )),
                OemCommandDraft::TokenErase {
                    erase_type,
                    token_type,
                } => RedfishCommand::Oem(OemCommand::DebugToken(
                    NvidiaDebugTokenCommand::EraseToken(EraseToken::new(
                        domain_erase_type(*erase_type),
                        domain_token_type(*token_type),
                    )),
                )),
                OemCommandDraft::PowerActivatePreset { profile_id } => RedfishCommand::Oem(
                    OemCommand::PowerSmoothing(NvidiaPowerSmoothingCommand::ActivatePresetProfile(
                        ProfileId::new(*profile_id),
                    )),
                ),
                OemCommandDraft::PowerApplyOverrides => RedfishCommand::Oem(
                    OemCommand::PowerSmoothing(NvidiaPowerSmoothingCommand::ApplyAdminOverrides),
                ),
            };
            Ok(command)
        }
    }
}

/// Maps the form `TokenTypeView` member onto the domain `TokenType` member.
/// The const member-set tests keep the two vocabularies aligned.
#[cfg(any(target_arch = "wasm32", test))]
fn domain_token_type(value: TokenTypeView) -> TokenType {
    match value {
        TokenTypeView::Frc => TokenType::Frc,
        TokenTypeView::Crcs => TokenType::Crcs,
        TokenTypeView::Crdt => TokenType::Crdt,
        TokenTypeView::DebugFirmwareRunning => TokenType::DebugFirmwareRunning,
        TokenTypeView::DebugFirmwareUnlock => TokenType::DebugFirmwareUnlock,
        TokenTypeView::OtpDumpEnable => TokenType::OtpDumpEnable,
        TokenTypeView::JtagUnlock => TokenType::JtagUnlock,
        TokenTypeView::HardwareUnlock => TokenType::HardwareUnlock,
        TokenTypeView::RuntimeDebugUnlock => TokenType::RuntimeDebugUnlock,
        TokenTypeView::FeatureUnlock => TokenType::FeatureUnlock,
        TokenTypeView::Mtdt => TokenType::Mtdt,
        TokenTypeView::CcplexArmJtagDebugCont => TokenType::CcplexArmJtagDebugCont,
        TokenTypeView::NvJtagControl => TokenType::NvJtagControl,
        TokenTypeView::DiagnosticBoot => TokenType::DiagnosticBoot,
        TokenTypeView::BpmpFirmwareDebugFs => TokenType::BpmpFirmwareDebugFs,
        TokenTypeView::FirmwareDebugKnobs => TokenType::FirmwareDebugKnobs,
        TokenTypeView::FirewallLifting => TokenType::FirewallLifting,
        TokenTypeView::Verbosity => TokenType::Verbosity,
        TokenTypeView::SmaDebugCapability => TokenType::SmaDebugCapability,
        TokenTypeView::CpldDebugCapability => TokenType::CpldDebugCapability,
    }
}

/// Maps the form `EraseTypeView` member onto the domain `EraseType` member.
#[cfg(any(target_arch = "wasm32", test))]
fn domain_erase_type(value: EraseTypeView) -> EraseType {
    match value {
        EraseTypeView::EraseAll => EraseType::EraseAll,
        EraseTypeView::EraseAllAndRatchetCounterIncreased => {
            EraseType::EraseAllAndRatchetCounterIncreased
        }
        EraseTypeView::TokenType => EraseType::TokenType,
    }
}

/// Projects the wire §7.5 command into its one-line card summary.
///
/// This is the response-side counterpart of [`command_summary`]: both render
/// the same family label and payload vocabulary, so the card of a submitted
/// operation reads exactly like the form preview that produced it.
#[cfg(any(target_arch = "wasm32", test))]
// The projection covers every §7.5 family and payload; the pedantic line
// budget is exceeded by the family count, so the lint is scoped here.
#[allow(clippy::too_many_lines)]
fn wire_command_summary(command: &RedfishCommand) -> CommandSummaryProjection {
    match command {
        RedfishCommand::System(SystemCommand::Reset(reset_type)) => CommandSummaryProjection {
            family: ResetResourceView::System.label(),
            payload: reset_type.to_string(),
        },
        RedfishCommand::Manager(ManagerCommand::Reset(reset_type)) => CommandSummaryProjection {
            family: ResetResourceView::Manager.label(),
            payload: reset_type.to_string(),
        },
        RedfishCommand::Chassis(ChassisCommand::Reset(reset_type)) => CommandSummaryProjection {
            family: ResetResourceView::Chassis.label(),
            payload: reset_type.to_string(),
        },
        RedfishCommand::Boot(BootCommand::SetBootSourceOverride(override_value)) => {
            CommandSummaryProjection {
                family: CommandFamilyView::BootOverride.label(),
                payload: format!(
                    "{} · {} · {}",
                    override_value.source(),
                    override_value.enabled(),
                    override_value.mode()
                ),
            }
        }
        RedfishCommand::SecureBoot(SecureBootCommand::Enable) => CommandSummaryProjection {
            family: CommandFamilyView::SecureBoot.label(),
            payload: "Enable".to_owned(),
        },
        RedfishCommand::SecureBoot(SecureBootCommand::Disable) => CommandSummaryProjection {
            family: CommandFamilyView::SecureBoot.label(),
            payload: "Disable".to_owned(),
        },
        RedfishCommand::SecureBoot(SecureBootCommand::ResetKeys(kind)) => {
            CommandSummaryProjection {
                family: CommandFamilyView::SecureBoot.label(),
                payload: format!("Reset keys · {kind}"),
            }
        }
        RedfishCommand::Event(EventCommand::CreateSubscription(subscription)) => {
            CommandSummaryProjection {
                family: CommandFamilyView::EventSubscription.label(),
                payload: format!(
                    "Create · {} · {} · {}",
                    subscription.destination(),
                    subscription.protocol(),
                    subscription
                        .event_types()
                        .iter()
                        .map(EventType::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            }
        }
        RedfishCommand::Event(EventCommand::DeleteSubscription(deletion)) => {
            CommandSummaryProjection {
                family: CommandFamilyView::EventSubscription.label(),
                payload: format!("Delete · {}", deletion.subscription_id()),
            }
        }
        RedfishCommand::Update(UpdateCommand::StartUpdate(payload)) => {
            // The artifact id renders in the same short form as the form
            // preview and the artifact card, so the card of a submitted
            // update agrees with both on how the artifact is identified.
            let artifact_short_id = short_sha256(&payload.artifact_id().to_string());
            let payload_text = match payload.push_uri() {
                Some(uri) => format!("Start · {artifact_short_id} · push {uri}"),
                None => format!("Start · {artifact_short_id} · multipart"),
            };
            CommandSummaryProjection {
                family: CommandFamilyView::FirmwareUpdate.label(),
                payload: payload_text,
            }
        }
        RedfishCommand::Oem(oem) => CommandSummaryProjection {
            family: CommandFamilyView::Oem.label(),
            payload: match oem {
                OemCommand::SystemConfigProfile(NvidiaSystemConfigProfileCommand::Update(_)) => {
                    "Profile · Update".to_owned()
                }
                OemCommand::SystemConfigProfile(NvidiaSystemConfigProfileCommand::FactoryReset) => {
                    "Profile · Factory reset".to_owned()
                }
                OemCommand::SystemConfigProfile(
                    NvidiaSystemConfigProfileCommand::ActivateProfile,
                ) => "Profile · Activate".to_owned(),
                OemCommand::DebugToken(NvidiaDebugTokenCommand::GenerateToken(token_type)) => {
                    format!("Token · Generate · {token_type}")
                }
                OemCommand::DebugToken(NvidiaDebugTokenCommand::InstallToken(_)) => {
                    "Token · Install".to_owned()
                }
                OemCommand::DebugToken(NvidiaDebugTokenCommand::DisableToken) => {
                    "Token · Disable".to_owned()
                }
                OemCommand::DebugToken(NvidiaDebugTokenCommand::EraseToken(erase)) => {
                    format!(
                        "Token · Erase · {} · {}",
                        erase.erase_type(),
                        erase.token_type()
                    )
                }
                OemCommand::PowerSmoothing(NvidiaPowerSmoothingCommand::ActivatePresetProfile(
                    profile_id,
                )) => format!(
                    "Power smoothing · Activate preset · {}",
                    profile_id.profile_id()
                ),
                OemCommand::PowerSmoothing(NvidiaPowerSmoothingCommand::ApplyAdminOverrides) => {
                    "Power smoothing · Apply overrides".to_owned()
                }
            },
        },
    }
}

/// Projects one wire operation onto its list card.
#[cfg(any(target_arch = "wasm32", test))]
impl From<&OperationResponse> for OperationCardProjection {
    fn from(response: &OperationResponse) -> Self {
        let operation_id = response.operation_id().to_string();
        Self {
            short_id: short_operation_id(&operation_id),
            operation_id,
            source: OperationSourceView::from(response.source()),
            target_count: response.targets().len(),
            state: OperationStateView::from(response.state()),
            command: wire_command_summary(response.command()),
            created_at_text: format_observed_at(&response.created_at()),
            updated_at_text: format_observed_at(&response.updated_at()),
        }
    }
}

/// The derived §13.7 lifecycle phase of one batch, as display vocabulary.
///
/// The verdict is a server-derived projection of the children's states and is
/// never computed client-side; this view type is the UI's own closed
/// vocabulary of the six batch phases, with the DTO-to-view mapping living
/// with the fetch layer.
#[cfg(any(target_arch = "wasm32", test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BatchStateView {
    Queued,
    Running,
    Succeeded,
    Failed,
    Unknown,
    Cancelled,
}

#[cfg(any(target_arch = "wasm32", test))]
impl BatchStateView {
    /// Static English badge label for one derived batch phase.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Queued => "Queued",
            Self::Running => "Running",
            Self::Succeeded => "Succeeded",
            Self::Failed => "Failed",
            Self::Unknown => "Unknown",
            Self::Cancelled => "Cancelled",
        }
    }

    /// Semantic badge styling for one derived batch phase.
    ///
    /// The tiers mirror the operation badge vocabulary: `Succeeded` is the
    /// only ok (green) phase, `Failed` the only error (red) phase, `Unknown`
    /// and `Cancelled` are terminal without a proven result (off, gray), and
    /// `Queued`/`Running` are active (blue) because the batch is in flight.
    #[must_use]
    pub const fn class(self) -> &'static str {
        match self {
            Self::Succeeded => "operation-state operation-ok",
            Self::Failed => "operation-state operation-error",
            Self::Unknown | Self::Cancelled => "operation-state operation-off",
            Self::Queued | Self::Running => "operation-state operation-active",
        }
    }
}

/// Maps the wire derived batch verdict onto the display vocabulary.
#[cfg(any(target_arch = "wasm32", test))]
impl From<BatchOperationStateResponse> for BatchStateView {
    fn from(state: BatchOperationStateResponse) -> Self {
        match state {
            BatchOperationStateResponse::Queued => Self::Queued,
            BatchOperationStateResponse::Running => Self::Running,
            BatchOperationStateResponse::Succeeded => Self::Succeeded,
            BatchOperationStateResponse::Failed => Self::Failed,
            BatchOperationStateResponse::Unknown => Self::Unknown,
            BatchOperationStateResponse::Cancelled => Self::Cancelled,
        }
    }
}

/// One §13.7 outcome count chip of a batch card.
#[cfg(any(target_arch = "wasm32", test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BatchOutcomeChip {
    label: &'static str,
    count: usize,
    class: &'static str,
}

/// The §13.7 outcome buckets of one batch card.
///
/// The counts are the server-derived projection rendered verbatim — the
/// client never infers a batch outcome from the children.
#[cfg(any(target_arch = "wasm32", test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BatchOutcomeChips {
    succeeded: usize,
    failed: usize,
    unknown: usize,
    unsupported: usize,
    cancelled: usize,
}

#[cfg(any(target_arch = "wasm32", test))]
impl BatchOutcomeChips {
    /// The five chips in fixed order, so the card rows read the same every
    /// time. `Unsupported` is the classified capability-refusal verdict and
    /// reads as off (gray) like the other non-error terminal buckets: it is a
    /// distinct known outcome, not an ordinary failure the operator would
    /// retry against the same endpoint.
    #[must_use]
    pub const fn chips(self) -> [BatchOutcomeChip; 5] {
        [
            BatchOutcomeChip {
                label: "Succeeded",
                count: self.succeeded,
                class: "operation-state operation-ok",
            },
            BatchOutcomeChip {
                label: "Failed",
                count: self.failed,
                class: "operation-state operation-error",
            },
            BatchOutcomeChip {
                label: "Unknown",
                count: self.unknown,
                class: "operation-state operation-off",
            },
            BatchOutcomeChip {
                label: "Unsupported",
                count: self.unsupported,
                class: "operation-state operation-off",
            },
            BatchOutcomeChip {
                label: "Cancelled",
                count: self.cancelled,
                class: "operation-state operation-off",
            },
        ]
    }
}

/// Maps the wire outcome buckets onto the card chips.
#[cfg(any(target_arch = "wasm32", test))]
impl From<BatchOutcomeCountsResponse> for BatchOutcomeChips {
    fn from(counts: BatchOutcomeCountsResponse) -> Self {
        Self {
            succeeded: counts.succeeded(),
            failed: counts.failed(),
            unknown: counts.unknown(),
            unsupported: counts.unsupported(),
            cancelled: counts.cancelled(),
        }
    }
}

/// One §13.7 batch child row: the endpoint that received the write and the
/// child operation's own §13.2 phase.
#[cfg(any(target_arch = "wasm32", test))]
#[derive(Clone, Debug, Eq, PartialEq)]
struct BatchChildRowProjection {
    endpoint_id: String,
    display_name: String,
    state: OperationStateView,
}

/// One §13.7 batch projected for a list card.
///
/// `children` stays empty until the card's first expand fetches the full
/// report; the card renders the server-derived state and the five outcome
/// chips from the summary alone.
#[cfg(any(target_arch = "wasm32", test))]
#[derive(Clone, Debug, Eq, PartialEq)]
struct BatchCardProjection {
    batch_id: String,
    short_id: String,
    state: BatchStateView,
    command: CommandSummaryProjection,
    created_at_text: String,
    outcomes: BatchOutcomeChips,
    children: Vec<BatchChildRowProjection>,
}

#[cfg(any(target_arch = "wasm32", test))]
impl BatchCardProjection {
    /// Static badge label of the derived batch verdict.
    #[must_use]
    pub const fn state_label(&self) -> &'static str {
        self.state.label()
    }

    /// Semantic badge styling of the derived batch verdict.
    #[must_use]
    pub const fn state_class(&self) -> &'static str {
        self.state.class()
    }
}

/// Projects one wire batch summary onto its list card.
///
/// The state badge and the outcome chips are the server's derived projection
/// rendered verbatim; the children rows are fetched separately on first
/// expand.
#[cfg(any(target_arch = "wasm32", test))]
impl From<&BatchSummaryResponse> for BatchCardProjection {
    fn from(response: &BatchSummaryResponse) -> Self {
        let batch_id = response.batch_id().to_string();
        Self {
            batch_id: batch_id.clone(),
            short_id: short_operation_id(&batch_id),
            state: BatchStateView::from(response.state()),
            command: wire_command_summary(response.command()),
            created_at_text: format_observed_at(&response.created_at()),
            outcomes: BatchOutcomeChips::from(response.outcomes()),
            children: Vec::new(),
        }
    }
}

/// Resolves one endpoint's display name from the loaded inventory.
///
/// The same inventory mapping as the operation form's target choices; an
/// endpoint missing from the inventory falls back to the short endpoint id
/// rather than inventing a name.
#[cfg(any(target_arch = "wasm32", test))]
fn endpoint_display_name(inventory: &EndpointInventoryResponse, endpoint_id: &str) -> String {
    match inventory
        .endpoints()
        .iter()
        .find(|endpoint| endpoint.identity().endpoint_id().to_string() == endpoint_id)
    {
        Some(endpoint) => endpoint.identity().display_name().to_owned(),
        None => short_operation_id(endpoint_id),
    }
}

/// Projects one batch's full report into the card's per-endpoint child rows.
///
/// Each child carries exactly one target, so the row pairs the child's phase
/// with the display name of its endpoint.
#[cfg(any(target_arch = "wasm32", test))]
fn batch_children_projection(
    detail: &BatchDetailResponse,
    inventory: &EndpointInventoryResponse,
) -> Vec<BatchChildRowProjection> {
    detail
        .children()
        .iter()
        .map(|child| {
            let endpoint_id = child
                .targets()
                .first()
                .map(|target| target.endpoint_id().to_string())
                .unwrap_or_default();
            BatchChildRowProjection {
                endpoint_id: endpoint_id.clone(),
                display_name: endpoint_display_name(inventory, &endpoint_id),
                state: OperationStateView::from(child.state()),
            }
        })
        .collect()
}

/// The loading state of the §13.7 batch list.
#[cfg(any(target_arch = "wasm32", test))]
#[derive(Clone, Debug, Eq, PartialEq)]
enum BatchesListState {
    Loading,
    Ready(Vec<BatchCardProjection>),
    Failed,
}

#[cfg(any(target_arch = "wasm32", test))]
impl BatchesListState {
    const fn is_loading(&self) -> bool {
        matches!(self, Self::Loading)
    }

    const fn is_failed(&self) -> bool {
        matches!(self, Self::Failed)
    }

    const fn is_ready(&self) -> bool {
        matches!(self, Self::Ready(_))
    }

    fn has_empty_list(&self) -> bool {
        matches!(self, Self::Ready(cards) if cards.is_empty())
    }

    /// One-line count heading, e.g. "3 batches".
    fn count_text(&self) -> String {
        let count = match self {
            Self::Ready(cards) => cards.len(),
            Self::Loading | Self::Failed => 0,
        };
        match count {
            1 => "1 batch".to_owned(),
            _ => format!("{count} batches"),
        }
    }

    fn cards(&self) -> Vec<BatchCardProjection> {
        match self {
            Self::Ready(cards) => cards.clone(),
            Self::Loading | Self::Failed => Vec::new(),
        }
    }
}

#[cfg(any(target_arch = "wasm32", test))]
/// The §12.3 unified health of one endpoint, ordered from best to worst.
///
/// The ordering drives both the aggregation (an endpoint's level is the
/// worst of its System/Chassis/Manager statuses) and the §14.2 health filter
/// comparisons. `Unknown` ranks lowest because it means "no health observed
/// yet", not "healthy".
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum HealthLevel {
    Unknown,
    Ok,
    Warning,
    Critical,
}

#[cfg(any(target_arch = "wasm32", test))]
/// The canonical §12.3 label of one unified health level, used for the §14.2
/// health filter chips. The endpoint-card badge instead shows the vendor's
/// raw text (§12.3 保留厂商原始值), so the two surfaces stay distinct.
#[must_use]
const fn health_level_label(level: HealthLevel) -> &'static str {
    match level {
        HealthLevel::Unknown => "Unknown",
        HealthLevel::Ok => "OK",
        HealthLevel::Warning => "Warning",
        HealthLevel::Critical => "Critical",
    }
}

#[cfg(any(target_arch = "wasm32", test))]
/// Badge styling of one unified health level; the endpoint card pairs it
/// with the raw text of the worst status.
#[must_use]
const fn health_badge_class(level: HealthLevel) -> &'static str {
    match level {
        HealthLevel::Unknown => "health-badge health-unknown",
        HealthLevel::Ok => "health-badge health-ok",
        HealthLevel::Warning => "health-badge health-warn",
        HealthLevel::Critical => "health-badge health-critical",
    }
}

#[cfg(any(target_arch = "wasm32", test))]
/// Maps one raw Redfish status-health text (§12.3 original value) to the
/// unified §12.3 level.
///
/// An unknown spelling maps to `None`: it neither invents a level nor
/// distorts the aggregation — the resource simply contributes no health, and
/// its raw text stays on the card.
fn health_level_of(health: &str) -> Option<HealthLevel> {
    if health.eq_ignore_ascii_case("ok") {
        Some(HealthLevel::Ok)
    } else if health.eq_ignore_ascii_case("warning") {
        Some(HealthLevel::Warning)
    } else if health.eq_ignore_ascii_case("critical") {
        Some(HealthLevel::Critical)
    } else {
        None
    }
}

#[cfg(any(target_arch = "wasm32", test))]
/// The worst §12.3 health across an endpoint's System, Chassis, and Manager
/// statuses, together with the raw text that produced it.
///
/// Only the 0.1 triad participates: those are the health-carrying resources
/// of the unified endpoint posture (§12.3), while the 0.2 families
/// (Processors, Memory, Storage, ...) publish component health that belongs
/// to the component card, not the endpoint badge.
fn worst_endpoint_health(resources: &[CoreResourceResponse]) -> Option<(HealthLevel, &str)> {
    resources
        .iter()
        .filter_map(|resource| match resource.resource() {
            CoreResourceDetailsResponse::System { status, .. }
            | CoreResourceDetailsResponse::Chassis { status, .. }
            | CoreResourceDetailsResponse::Manager { status, .. } => status.as_ref(),
            _ => None,
        })
        .filter_map(|status| {
            status
                .health()
                .and_then(|health| health_level_of(health).map(|level| (level, health)))
        })
        .max_by_key(|(level, _)| *level)
}

#[cfg(any(target_arch = "wasm32", test))]
/// The unified §12.3 health level of one endpoint's resource set.
fn aggregate_health(resources: &[CoreResourceResponse]) -> HealthLevel {
    worst_endpoint_health(resources).map_or(HealthLevel::Unknown, |(level, _)| level)
}

#[cfg(any(target_arch = "wasm32", test))]
/// The §12.3 unified vendor of one endpoint, from its Service Root resource.
///
/// Only the Service Root publishes the product vendor, so an endpoint
/// awaiting its first refresh has no vendor yet and never matches a §14.2
/// vendor filter until a refresh observed one.
fn endpoint_vendor(resources: &[CoreResourceResponse]) -> Option<String> {
    resources
        .iter()
        .find_map(|resource| match resource.resource() {
            CoreResourceDetailsResponse::ServiceRoot { vendor, .. } => vendor.clone(),
            _ => None,
        })
}

#[cfg(any(target_arch = "wasm32", test))]
/// The §14.2 home-page filter selections, combined with AND semantics.
///
/// Each dimension is optional: an empty selection does not constrain.
/// Within the tag, vendor, and health dimensions the selected values are
/// `ORed` (an endpoint matches the tag dimension when it carries at least one
/// selected tag), and the four dimensions are `ANDed` together — the
/// documented §14.2 combination model. A vendor-less or health-less endpoint
/// matches only when the corresponding dimension is unconstrained.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct OverviewFilterSelections {
    search: String,
    tags: BTreeSet<String>,
    vendors: BTreeSet<String>,
    health: BTreeSet<HealthLevel>,
}

#[cfg(any(target_arch = "wasm32", test))]
impl OverviewFilterSelections {
    /// Whether every dimension is empty, so no card can be filtered out.
    #[must_use]
    fn is_empty(&self) -> bool {
        self.search.trim().is_empty()
            && self.tags.is_empty()
            && self.vendors.is_empty()
            && self.health.is_empty()
    }
}

#[cfg(any(target_arch = "wasm32", test))]
/// Toggles one value in a selection set: present values are removed, absent
/// ones inserted. Keeps the checkbox-chip interactions (Overview filters,
/// group member add) on one pure primitive.
fn toggle_set_membership<T: Ord + Clone>(set: &mut BTreeSet<T>, value: T) {
    if set.contains(&value) {
        set.remove(&value);
    } else {
        set.insert(value);
    }
}

#[cfg(any(target_arch = "wasm32", test))]
/// The distinct §14.2 vendor choices in the loaded endpoint cards, sorted
/// for a stable filter bar.
fn vendor_choices(cards: &[EndpointCardProjection]) -> Vec<String> {
    cards
        .iter()
        .filter_map(|card| card.vendor.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

#[cfg(any(target_arch = "wasm32", test))]
/// The distinct §14.2 health choices present in the loaded endpoint cards,
/// worst-first so the operator reads the critical option before OK.
fn health_choices(cards: &[EndpointCardProjection]) -> Vec<HealthLevel> {
    cards
        .iter()
        .map(|card| card.health_level)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .rev()
        .collect()
}

#[cfg(any(target_arch = "wasm32", test))]
/// Every tag name carried by one endpoint, from the §14.2 tag inventory.
///
/// The inventory maps tag → endpoints (the tag-list surface), so the
/// endpoint-side lookup inverts it; the Overview tag filter uses the result
/// for membership checks.
fn endpoint_tags(endpoint_id: &str, tags: &TagInventoryView) -> BTreeSet<String> {
    tags.tags()
        .iter()
        .filter(|tag| tag.endpoint_ids().iter().any(|id| id == endpoint_id))
        .map(|tag| tag.name().to_owned())
        .collect()
}

#[cfg(any(target_arch = "wasm32", test))]
/// Applies the §14.2 filter bar to the loaded endpoint cards with AND
/// semantics across the four dimensions.
///
/// The filtering is deliberately client-side: the inventory response already
/// carries every managed endpoint, the 200-endpoint scale the console is
/// designed for fits a substring scan per keystroke, and server-side
/// filtering would add a query contract for no latency gain at that scale.
fn apply_overview_filters(
    cards: &[EndpointCardProjection],
    tags: &TagInventoryView,
    selections: &OverviewFilterSelections,
) -> Vec<EndpointCardProjection> {
    let needle = selections.search.trim().to_ascii_lowercase();
    let matches_search = |card: &EndpointCardProjection| {
        needle.is_empty()
            || card.display_name.to_ascii_lowercase().contains(&needle)
            || card.address.to_ascii_lowercase().contains(&needle)
    };
    let matches_tags = |card: &EndpointCardProjection| {
        selections.tags.is_empty()
            || !selections
                .tags
                .is_disjoint(&endpoint_tags(&card.endpoint_id, tags))
    };
    let matches_vendors = |card: &EndpointCardProjection| {
        selections.vendors.is_empty()
            || card
                .vendor
                .as_deref()
                .is_some_and(|vendor| selections.vendors.contains(vendor))
    };
    let matches_health = |card: &EndpointCardProjection| {
        selections.health.is_empty() || selections.health.contains(&card.health_level)
    };
    cards
        .iter()
        .filter(|card| {
            matches_search(card)
                && matches_tags(card)
                && matches_vendors(card)
                && matches_health(card)
        })
        .cloned()
        .collect()
}

// §14.2 grouping projections. The wire DTOs (`GroupResponse`,
// `GroupListResponse`, `TagResponse`, `TagListResponse`) are the shared
// contract of the api crate; the projections below render them without the
// console ever re-parsing text, and the browser fetch layer maps the wire
// shapes straight onto them.

#[cfg(any(target_arch = "wasm32", test))]
/// One §14.2 tag with every endpoint that carries it.
///
/// The endpoint-side mapping (tag → endpoints) is what both the tag list and
/// the Overview tag filter need: the list renders the endpoints under each
/// tag, and the filter inverts the mapping to test membership per endpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
struct TagView {
    name: String,
    endpoint_ids: Vec<String>,
}

#[cfg(any(target_arch = "wasm32", test))]
impl TagView {
    #[must_use]
    pub const fn new(name: String, endpoint_ids: Vec<String>) -> Self {
        Self { name, endpoint_ids }
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn endpoint_ids(&self) -> &[String] {
        &self.endpoint_ids
    }
}

#[cfg(any(target_arch = "wasm32", test))]
/// The §14.2 tag inventory as the console consumes it.
///
/// The wire `TagListResponse` is a flat list of one-name-one-endpoint
/// bindings; the inventory groups the bindings by name so the tag list and
/// the per-endpoint membership lookup both have the tag → endpoints shape.
/// `Default` is the "no tags loaded" fallback the Overview filter pass uses
/// while the inventory is still loading or failed — an empty inventory
/// constrains nothing.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct TagInventoryView {
    tags: Vec<TagView>,
}

#[cfg(any(target_arch = "wasm32", test))]
impl TagInventoryView {
    #[must_use]
    pub const fn new(tags: Vec<TagView>) -> Self {
        Self { tags }
    }

    #[must_use]
    pub fn tags(&self) -> &[TagView] {
        &self.tags
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.tags.is_empty()
    }
}

#[cfg(any(target_arch = "wasm32", test))]
impl From<&TagListResponse> for TagInventoryView {
    fn from(response: &TagListResponse) -> Self {
        let mut tags: Vec<TagView> = Vec::new();
        for binding in response.tags() {
            // Bindings arrive in deterministic product order; grouping keeps
            // the first-seen order and appends endpoints in wire order.
            let endpoint_id = binding.endpoint_id().to_string();
            match tags.iter_mut().find(|tag| tag.name() == binding.name()) {
                Some(tag) => tag.endpoint_ids.push(endpoint_id),
                None => tags.push(TagView::new(binding.name().to_owned(), vec![endpoint_id])),
            }
        }
        Self::new(tags)
    }
}

#[cfg(any(target_arch = "wasm32", test))]
/// One §14.2 group card: the name, the member count, and the short ids of
/// the member endpoints.
#[derive(Clone, Debug, Eq, PartialEq)]
struct GroupCardProjection {
    group_id: String,
    name: String,
    member_count_text: String,
    member_short_ids: Vec<String>,
}

#[cfg(any(target_arch = "wasm32", test))]
impl From<&GroupResponse> for GroupCardProjection {
    fn from(group: &GroupResponse) -> Self {
        let members = group.member_endpoint_ids();
        Self {
            group_id: group.group_id().to_string(),
            name: group.name().to_owned(),
            member_count_text: match members.len() {
                1 => "1 member".to_owned(),
                _ => format!("{} members", members.len()),
            },
            member_short_ids: members
                .iter()
                .map(|endpoint_id| short_endpoint_id(&endpoint_id.to_string()))
                .collect(),
        }
    }
}

#[cfg(any(target_arch = "wasm32", test))]
/// The lazy-loading state of the §14.2 group list section.
#[derive(Clone, Debug, Eq, PartialEq)]
enum GroupsListState {
    Idle,
    Loading,
    Ready(Vec<GroupCardProjection>),
    Failed,
}

#[cfg(any(target_arch = "wasm32", test))]
impl GroupsListState {
    const fn is_ready(&self) -> bool {
        matches!(self, Self::Ready(_))
    }

    const fn is_loading(&self) -> bool {
        matches!(self, Self::Loading)
    }

    const fn is_failed(&self) -> bool {
        matches!(self, Self::Failed)
    }

    fn has_empty_list(&self) -> bool {
        matches!(self, Self::Ready(groups) if groups.is_empty())
    }

    fn count_text(&self) -> String {
        let count = match self {
            Self::Ready(groups) => groups.len(),
            Self::Idle | Self::Loading | Self::Failed => 0,
        };
        match count {
            1 => "1 group".to_owned(),
            _ => format!("{count} groups"),
        }
    }

    const fn failure_message(&self) -> &'static str {
        match self {
            Self::Failed => "The group list is temporarily unavailable.",
            Self::Idle | Self::Loading | Self::Ready(_) => "",
        }
    }

    fn group_cards(&self) -> Vec<GroupCardProjection> {
        match self {
            Self::Ready(groups) => groups.clone(),
            Self::Idle | Self::Loading | Self::Failed => Vec::new(),
        }
    }
}

#[cfg(any(target_arch = "wasm32", test))]
/// One member of a §14.2 group, joined with the managed-endpoint inventory
/// so the member row renders the display name and address.
#[derive(Clone, Debug, Eq, PartialEq)]
struct GroupMemberProjection {
    endpoint_id: String,
    short_id: String,
    display_name: String,
    address: String,
}

#[cfg(any(target_arch = "wasm32", test))]
/// One §14.2 group detail: the group plus every member joined against the
/// loaded endpoint inventory.
#[derive(Clone, Debug, Eq, PartialEq)]
struct GroupDetailProjection {
    group_id: String,
    name: String,
    members: Vec<GroupMemberProjection>,
}

#[cfg(any(target_arch = "wasm32", test))]
impl GroupDetailProjection {
    /// Projects the detail from the wire `GroupResponse` (the same DTO the
    /// list uses, since the group-detail route returns the full group) and
    /// joins the member ids against the loaded endpoint inventory.
    fn from_response(group: &GroupResponse, inventory: &[EndpointSummaryResponse]) -> Self {
        let members = group
            .member_endpoint_ids()
            .iter()
            .map(|endpoint_id| {
                let endpoint_id_text = endpoint_id.to_string();
                let summary = inventory
                    .iter()
                    .find(|summary| summary.identity().endpoint_id() == *endpoint_id);
                GroupMemberProjection {
                    endpoint_id: endpoint_id_text.clone(),
                    short_id: short_endpoint_id(&endpoint_id_text),
                    // A member that left the inventory (deleted endpoint)
                    // still renders its row defensively instead of dropping
                    // it from the group.
                    display_name: summary.map_or_else(
                        || "Unknown endpoint".to_owned(),
                        |summary| summary.identity().display_name().to_owned(),
                    ),
                    address: summary.map_or_else(String::new, |summary| {
                        summary.identity().address().to_owned()
                    }),
                }
            })
            .collect();
        Self {
            group_id: group.group_id().to_string(),
            name: group.name().to_owned(),
            members,
        }
    }

    #[must_use]
    const fn has_no_members(&self) -> bool {
        self.members.is_empty()
    }
}

#[cfg(any(target_arch = "wasm32", test))]
/// One endpoint the operator can add to the §14.2 group being managed.
#[derive(Clone, Debug, Eq, PartialEq)]
struct GroupMemberChoice {
    endpoint_id: String,
    display_name: String,
    address: String,
}

#[cfg(any(target_arch = "wasm32", test))]
/// The managed endpoints not yet in the group, in inventory order.
///
/// The detail fetch and the inventory come from the same product snapshot in
/// the common flow; a member id absent from the inventory is never offered
/// again, because it cannot be re-added.
fn group_member_choices(
    inventory: &[EndpointSummaryResponse],
    detail: &GroupDetailProjection,
) -> Vec<GroupMemberChoice> {
    inventory
        .iter()
        .filter(|summary| {
            !detail
                .members
                .iter()
                .any(|member| member.endpoint_id == summary.identity().endpoint_id().to_string())
        })
        .map(|summary| GroupMemberChoice {
            endpoint_id: summary.identity().endpoint_id().to_string(),
            display_name: summary.identity().display_name().to_owned(),
            address: summary.identity().address().to_owned(),
        })
        .collect()
}

#[cfg(any(target_arch = "wasm32", test))]
/// The lazy-loading state of the selected §14.2 group detail.
#[derive(Clone, Debug, Eq, PartialEq)]
enum GroupDetailState {
    Idle,
    Loading,
    Ready(GroupDetailProjection),
    Failed,
}

#[cfg(any(target_arch = "wasm32", test))]
impl GroupDetailState {
    const fn is_loading(&self) -> bool {
        matches!(self, Self::Loading)
    }

    const fn is_failed(&self) -> bool {
        matches!(self, Self::Failed)
    }

    const fn failure_message(&self) -> &'static str {
        match self {
            Self::Failed => "The group detail is temporarily unavailable.",
            Self::Idle | Self::Loading | Self::Ready(_) => "",
        }
    }

    fn ready_projection(&self) -> Option<&GroupDetailProjection> {
        match self {
            Self::Ready(detail) => Some(detail),
            Self::Idle | Self::Loading | Self::Failed => None,
        }
    }
}

#[cfg(any(target_arch = "wasm32", test))]
/// One §14.2 tag card row: the full endpoint id (the untag action target)
/// beside its short display form.
#[derive(Clone, Debug, Eq, PartialEq)]
struct TagEndpointRow {
    endpoint_id: String,
    short_id: String,
}

#[cfg(any(target_arch = "wasm32", test))]
/// One §14.2 tag card: the tag name and the endpoints that carry it, each
/// row keeping its full id so the untag action can target it.
#[derive(Clone, Debug, Eq, PartialEq)]
struct TagCardProjection {
    name: String,
    endpoint_count_text: String,
    endpoints: Vec<TagEndpointRow>,
}

#[cfg(any(target_arch = "wasm32", test))]
impl TagCardProjection {
    fn from_view(tag: &TagView) -> Self {
        let endpoints = tag.endpoint_ids();
        Self {
            name: tag.name().to_owned(),
            endpoint_count_text: match endpoints.len() {
                1 => "1 endpoint".to_owned(),
                _ => format!("{} endpoints", endpoints.len()),
            },
            endpoints: endpoints
                .iter()
                .map(|endpoint_id| TagEndpointRow {
                    endpoint_id: endpoint_id.clone(),
                    short_id: short_endpoint_id(endpoint_id),
                })
                .collect(),
        }
    }
}

#[cfg(any(target_arch = "wasm32", test))]
/// The lazy-loading state of the §14.2 tag inventory.
///
/// The Overview filter bar and the Groups view both consume this state; each
/// owns its own copy so a refresh in one view never disturbs the other.
#[derive(Clone, Debug, Eq, PartialEq)]
enum TagsListState {
    Idle,
    Loading,
    Ready(TagInventoryView),
    Failed,
}

#[cfg(any(target_arch = "wasm32", test))]
impl TagsListState {
    const fn is_ready(&self) -> bool {
        matches!(self, Self::Ready(_))
    }

    const fn is_loading(&self) -> bool {
        matches!(self, Self::Loading)
    }

    const fn is_failed(&self) -> bool {
        matches!(self, Self::Failed)
    }

    fn has_empty_tags(&self) -> bool {
        matches!(self, Self::Ready(tags) if tags.is_empty())
    }

    const fn failure_message(&self) -> &'static str {
        match self {
            Self::Failed => "The tag inventory is temporarily unavailable.",
            Self::Idle | Self::Loading | Self::Ready(_) => "",
        }
    }

    fn tag_names(&self) -> Vec<String> {
        match self {
            Self::Ready(tags) => {
                let mut names = tags
                    .tags()
                    .iter()
                    .map(|tag| tag.name().to_owned())
                    .collect::<Vec<_>>();
                names.sort();
                names
            }
            Self::Idle | Self::Loading | Self::Failed => Vec::new(),
        }
    }

    fn inventory(&self) -> Option<&TagInventoryView> {
        match self {
            Self::Ready(tags) => Some(tags),
            Self::Idle | Self::Loading | Self::Failed => None,
        }
    }

    fn tag_cards(&self) -> Vec<TagCardProjection> {
        match self {
            Self::Ready(tags) => tags
                .tags()
                .iter()
                .map(TagCardProjection::from_view)
                .collect(),
            Self::Idle | Self::Loading | Self::Failed => Vec::new(),
        }
    }
}

#[cfg(any(target_arch = "wasm32", test))]
/// The maximum §14.2 group-name length; the server remains authoritative.
const MAX_GROUP_NAME_CHARS: usize = 64;

#[cfg(any(target_arch = "wasm32", test))]
/// Why a §14.2 group name cannot be submitted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GroupNameDraftError {
    Required,
    ControlCharacter,
    TooLong,
}

#[cfg(any(target_arch = "wasm32", test))]
impl GroupNameDraftError {
    const fn message(self) -> &'static str {
        match self {
            Self::Required => "A group name is required.",
            Self::ControlCharacter => "The group name cannot contain control characters.",
            Self::TooLong => "The group name cannot exceed 64 characters.",
        }
    }
}

#[cfg(any(target_arch = "wasm32", test))]
/// Client-side mirror of the static-group name rules; the server remains
/// authoritative when the group is created.
fn group_name_draft_error(value: &str) -> Result<(), GroupNameDraftError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(GroupNameDraftError::Required);
    }
    if trimmed.chars().any(char::is_control) {
        return Err(GroupNameDraftError::ControlCharacter);
    }
    if trimmed.chars().count() > MAX_GROUP_NAME_CHARS {
        return Err(GroupNameDraftError::TooLong);
    }
    Ok(())
}

#[cfg(any(target_arch = "wasm32", test))]
/// The §14.2 create-group form draft.
#[derive(Clone, Debug, Eq, PartialEq)]
struct GroupDraft {
    name: String,
}

#[cfg(any(target_arch = "wasm32", test))]
impl GroupDraft {
    #[must_use]
    const fn new() -> Self {
        Self {
            name: String::new(),
        }
    }

    fn validate(&self) -> Result<(), GroupNameDraftError> {
        group_name_draft_error(&self.name)
    }
}

#[cfg(any(target_arch = "wasm32", test))]
/// The maximum §14.2 tag-name length.
const MAX_TAG_NAME_CHARS: usize = 64;

#[cfg(any(target_arch = "wasm32", test))]
/// Why a §14.2 tag cannot be applied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TagDraftError {
    EndpointRequired,
    NameRequired,
    ControlCharacter,
    TooLong,
}

#[cfg(any(target_arch = "wasm32", test))]
impl TagDraftError {
    const fn message(self) -> &'static str {
        match self {
            Self::EndpointRequired => "Select the endpoint to tag.",
            Self::NameRequired => "A tag name is required.",
            Self::ControlCharacter => "A tag name cannot contain control characters.",
            Self::TooLong => "A tag name cannot exceed 64 characters.",
        }
    }
}

#[cfg(any(target_arch = "wasm32", test))]
/// Client-side mirror of the §14.2 tag-name rules.
///
/// Spaces and slashes are deliberately allowed: the domain `TagName` accepts
/// them, and the tag route percent-encodes the name when it is removed (the
/// web route percent-decodes it back). The server remains authoritative.
fn tag_draft_error(endpoint_id: Option<&str>, name: &str) -> Result<(), TagDraftError> {
    if endpoint_id.is_none() {
        return Err(TagDraftError::EndpointRequired);
    }
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(TagDraftError::NameRequired);
    }
    if trimmed.chars().any(char::is_control) {
        return Err(TagDraftError::ControlCharacter);
    }
    if trimmed.chars().count() > MAX_TAG_NAME_CHARS {
        return Err(TagDraftError::TooLong);
    }
    Ok(())
}

#[cfg(any(target_arch = "wasm32", test))]
/// The uppercase hex digits of one percent-encoded byte.
const PERCENT_HEX_DIGITS: &[u8; 16] = b"0123456789ABCDEF";

#[cfg(any(target_arch = "wasm32", test))]
/// Percent-encodes one tag name for the removal route path.
///
/// The route (`/api/v1/endpoints/{endpoint_id}/tags/{tag_name}`) percent-
/// decodes the segment, so every byte outside the RFC 3986 unreserved set is
/// encoded — spaces, slashes, and non-ASCII names all round-trip exactly.
fn percent_encode_path_segment(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(byte as char);
        } else {
            encoded.push('%');
            encoded.push(PERCENT_HEX_DIGITS[(byte >> 4) as usize] as char);
            encoded.push(PERCENT_HEX_DIGITS[(byte & 0x0F) as usize] as char);
        }
    }
    encoded
}

#[cfg(any(target_arch = "wasm32", test))]
/// The §14.2 tag-management form draft: the endpoint to tag and the tag
/// name.
#[derive(Clone, Debug, Eq, PartialEq)]
struct TagDraft {
    endpoint_id: Option<String>,
    name: String,
}

#[cfg(any(target_arch = "wasm32", test))]
impl TagDraft {
    #[must_use]
    const fn new() -> Self {
        Self {
            endpoint_id: None,
            name: String::new(),
        }
    }

    fn validate(&self) -> Result<(), TagDraftError> {
        tag_draft_error(self.endpoint_id.as_deref(), &self.name)
    }
}

#[cfg(any(target_arch = "wasm32", test))]
/// The progression of one §14.2 group creation submission.
#[derive(Clone, Debug, Eq, PartialEq)]
enum GroupCreateState {
    Idle,
    InFlight,
    Created,
    Failed(String),
}

#[cfg(any(target_arch = "wasm32", test))]
/// The progression of one §14.2 group member add/remove submission.
#[derive(Clone, Debug, Eq, PartialEq)]
enum GroupMemberActionState {
    Idle,
    InFlight,
    Succeeded,
    Failed(String),
}

#[cfg(any(target_arch = "wasm32", test))]
/// The progression of one §14.2 tag apply/remove submission.
#[derive(Clone, Debug, Eq, PartialEq)]
enum TagApplyState {
    Idle,
    InFlight,
    Applied,
    Failed(String),
}

#[cfg(any(target_arch = "wasm32", test))]
/// Parses the submission acknowledgement for the selected target count
/// (§13.1, §13.7).
///
/// One target acknowledges an ordinary operation; several targets acknowledge
/// the batch parent whose children pair with the submitted endpoints. A body
/// that cannot be parsed as the selected contract is a malformed
/// acknowledgement and maps to the single static failure message, exactly
/// like every other refused submission. The batch per-endpoint report view
/// is a later slice; this cut only needs the submission to succeed.
fn acknowledge_submission(target_count: usize, body: &str) -> Result<(), &'static str> {
    if target_count > 1 {
        json::from_str::<BatchOperationResponse>(body)
            .map(|_| ())
            .map_err(|_| OperationSubmitState::FAILURE_MESSAGE)
    } else {
        json::from_str::<OperationResponse>(body)
            .map(|_| ())
            .map_err(|_| OperationSubmitState::FAILURE_MESSAGE)
    }
}

#[cfg(target_arch = "wasm32")]
mod browser {
    use std::collections::{BTreeSet, HashMap};

    use gloo_net::http::{Request, RequestBuilder, Response};
    use leptos::{
        mount::mount_to_body,
        prelude::*,
        wasm_bindgen::{JsCast, JsValue},
        web_sys::{Blob, Event, HtmlInputElement},
    };
    use rutilus_api::{
        AboutResponse, AppendArtifactChunkRequest, ArtifactListResponse, ArtifactProgressResponse,
        ArtifactResponse, AssignRoleRequest, AssignTagRequest, AuditQueryResponse,
        BatchDetailResponse, BatchListResponse, BatchRefreshResponse, BeginEndpointTrustRequest,
        BootstrapCompleteRequest, BootstrapCompleteResponse, CenterBindingRegisterRequest,
        CenterBindingRegisterResponse, CenterBindingRevokeRequest, CenterEndpointViewListResponse,
        CenterOperationListResponse, CenterOperationSubmitRequest, CenterOperationSubmitResponse,
        CenterSitesResponse, ConfirmEndpointTrustRequest, CreateArtifactRequest,
        CreateCredentialRequest, CreateGroupRequest, CreateOperationRequest, CreateUserRequest,
        CredentialInventoryResponse, CredentialSummaryResponse,
        EndpointCapabilityInventoryResponse, EndpointCsvImportRequest, EndpointCsvImportResponse,
        EndpointEnrollmentResponse, EndpointInventoryResponse, EndpointResourceInventoryResponse,
        EndpointTrustChallengeResponse, EndpointTrustExpectationRequest, EnrollEndpointRequest,
        EventListResponse, GroupListResponse, GroupResponse, LoginRequest, LoginResponse,
        LogoutRequest, MeResponse, OperationListResponse, PrincipalStateResponse,
        RefreshEndpointsRequest, ResourceDiagnosticsResponse, RevokeSessionRequest, RoleResponse,
        SessionAdminResponse, SetPrincipalStateRequest, TagListResponse,
        TelemetrySampleListResponse, TelemetrySeriesListResponse, TelemetrySeriesResponse,
        TrustedEndpointResponse, UserAdminResponse,
    };
    use wasm_bindgen::prelude::wasm_bindgen;

    impl CenterBindingsListState {
        const fn is_failed(&self) -> bool {
            matches!(self, Self::Failed)
        }

        const fn is_ready(&self) -> bool {
            matches!(self, Self::Ready(_))
        }
    }

    impl CenterOperationSubmitState {
        const fn is_in_flight(&self) -> bool {
            matches!(self, Self::InFlight)
        }
    }

    impl CenterOperationsListState {
        const fn is_failed(&self) -> bool {
            matches!(self, Self::Failed)
        }

        const fn is_ready(&self) -> bool {
            matches!(self, Self::Ready(_))
        }

        const fn is_loading(&self) -> bool {
            matches!(self, Self::Loading)
        }

        fn count_text(&self) -> String {
            let count = match self {
                Self::Ready(operations) => operations.len(),
                Self::Idle | Self::Loading | Self::Failed => 0,
            };
            match count {
                1 => "1 center operation".to_owned(),
                _ => format!("{count} center operations"),
            }
        }
    }

    impl CenterEndpointsDetailState {
        const fn is_failed(&self) -> bool {
            matches!(self, Self::Failed)
        }

        const fn is_ready(&self) -> bool {
            matches!(self, Self::Ready(_))
        }
    }

    impl CenterSitesListState {
        const fn is_failed(&self) -> bool {
            matches!(self, Self::Failed)
        }

        const fn is_ready(&self) -> bool {
            matches!(self, Self::Ready(_))
        }

        fn count_text(&self) -> String {
            let count = match self {
                Self::Ready(sites) => sites.len(),
                Self::Idle | Self::Loading | Self::Failed => 0,
            };
            match count {
                1 => "1 registered site".to_owned(),
                _ => format!("{count} registered sites"),
            }
        }
    }

    /// The outcome of one revocation submission.
    #[cfg(any(target_arch = "wasm32", test))]
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum CenterRevokeState {
        Idle,
        InFlight,
        Succeeded,
        Failed,
    }

    /// The outcome of one registration submission.
    #[cfg(any(target_arch = "wasm32", test))]
    #[derive(Clone, Debug, Eq, PartialEq)]
    enum CenterRegisterState {
        Idle,
        InFlight,
        Issued(CenterBindingCodeView),
        Failed,
    }

    /// The one-time binding code acknowledgement of a registration (design
    /// D2): the raw code is shown exactly once, here, and never again.
    #[cfg(any(target_arch = "wasm32", test))]
    #[derive(Clone, Debug, Eq, PartialEq)]
    struct CenterBindingCodeView {
        site_id: String,
        binding_id: String,
        code: String,
        expires_at: OffsetDateTime,
    }

    /// The loading state of the center's binding surface (the register form
    /// results and the revocable site list).
    #[cfg(any(target_arch = "wasm32", test))]
    #[derive(Clone, Debug, Eq, PartialEq)]
    enum CenterBindingsListState {
        Idle,
        Loading,
        Ready(Vec<CenterSiteCardProjection>),
        Failed,
    }

    /// The outcome of one center operation submission.
    #[cfg(any(target_arch = "wasm32", test))]
    #[derive(Clone, Debug, Eq, PartialEq)]
    enum CenterOperationSubmitState {
        Idle,
        InFlight,
        Succeeded,
        Failed(String),
    }

    #[cfg(any(target_arch = "wasm32", test))]
    impl CenterOperationDraftError {
        /// Static English message of one invalid field.
        #[must_use]
        pub const fn message(self) -> &'static str {
            match self {
                Self::SiteRequired => "A site must be selected.",
                Self::EndpointRequired => "An endpoint must be selected.",
                Self::TargetRequired => "A Redfish target is required.",
                Self::Command(error) => error.message(),
            }
        }
    }

    /// The loading state of the center's §15.6 operation tracking view.
    #[cfg(any(target_arch = "wasm32", test))]
    #[derive(Clone, Debug, Eq, PartialEq)]
    enum CenterOperationsListState {
        Idle,
        Loading,
        Ready(Vec<CenterOperationCardProjection>),
        Failed,
    }

    /// The loading state of one site's aggregated endpoint detail.
    #[cfg(any(target_arch = "wasm32", test))]
    #[derive(Clone, Debug, Eq, PartialEq)]
    enum CenterEndpointsDetailState {
        Idle,
        Loading,
        Ready(Vec<CenterEndpointCardProjection>),
        Failed,
    }

    /// The loading state of the center's §15.5 site list.
    #[cfg(any(target_arch = "wasm32", test))]
    #[derive(Clone, Debug, Eq, PartialEq)]
    enum CenterSitesListState {
        Idle,
        Loading,
        Ready(Vec<CenterSiteCardProjection>),
        Failed,
    }

    #[cfg(any(target_arch = "wasm32", test))]
    impl CenterBindingStateView {
        /// Static English label of one binding phase.
        #[must_use]
        pub const fn label(self) -> &'static str {
            match self {
                Self::Pending => "pending",
                Self::Bound => "bound",
                Self::Revoked => "revoked",
            }
        }
    }

    /// The console scope of the serving posture (audit follow-up F2/S8): the
    /// center console renders the center views, the edge consoles the
    /// local-management views.
    #[cfg(any(target_arch = "wasm32", test))]
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum ConsoleScopeView {
        /// The scope probe has not answered yet; the navigation stays hidden.
        Checking,
        /// An Edge posture (Standalone or Site).
        Edge,
        /// The Center aggregation posture.
        Center,
    }
    use wasm_bindgen_futures::{JsFuture, spawn_local};

    use super::{
        ArtifactCardProjection, ArtifactStatusView, ArtifactUploadFailure, ArtifactUploadState,
        ArtifactsListState, AuditEventCardProjection, AuditListState, BatchCardProjection,
        BatchChildRowProjection, BatchesListState, BootEnabledView, BootModeView, BootSourceView,
        CapabilityEntryProjection, CapabilityGroupProjection, CapabilityLoadFailure,
        CapabilityMatrixProjection, CapabilityMatrixState, CapabilityTargetProjection,
        CenterBindingStateView, CenterEndpointCardProjection, CenterOperationCardProjection,
        CenterOperationDraft, CenterOperationDraftError, CenterOperationSubmission,
        CenterSiteCardProjection, CommandFamilyView, ConsoleLoadFailure, ConsoleLoadState,
        ConsoleView, CoreResourceCardProjection, CreateCredentialState, CredentialCardProjection,
        CredentialDraft, CredentialDraftError, CredentialsListState, CsvImportReportProjection,
        DIAGNOSTICS_FOOTER_NOTE, DiagnosticsLoadFailure, DiagnosticsProjection, DiagnosticsState,
        DiagnosticsTargetProjection, EndpointAddressDraftError, EndpointCardProjection,
        EnrollmentDraft, EnrollmentDraftError, EraseTypeView, EventActionView, EventCardProjection,
        EventProtocolView, EventTypeView, EventsListState, GroupCardProjection, GroupCreateState,
        GroupDetailProjection, GroupDetailState, GroupDraft, GroupMemberActionState,
        GroupNameDraftError, GroupsListState, HealthLevel, ImportFailure, ImportState,
        OEM_UNSUPPORTED_NOTICE, OemActionView, OemFaceView, OffsetDateTime,
        OnboardingCredentialsState, OnboardingFailure, OnboardingStep, OperationCardProjection,
        OperationCommandDraft, OperationEndpointChoice, OperationFormDraft, OperationFormError,
        OperationSubmitState, OperationsListState, OverviewFilterSelections,
        RefreshBatchReportProjection, RefreshBatchState, RefreshFailure, ResetKeysTypeView,
        ResetTypeView, RoleView, SecureBootActionView, TagApplyState, TagCardProjection, TagDraft,
        TagDraftError, TagInventoryView, TagsListState, TelemetryCardProjection,
        TelemetryListState, TokenTypeView, TrustChallengeProjection, UpdateArtifactChoice,
        apply_overview_filters, artifact_chunk_range_at, artifact_upload_status_text,
        base64_encode, batch_children_projection, build_command, command_summary,
        diagnostics_optional_text, endpoint_address_draft_error, format_artifact_size,
        format_observed_at, group_member_choices, group_name_draft_error, health_badge_class,
        health_choices, health_level_label, oem_action_key, operation_endpoint_choices,
        percent_encode_path_segment, sha256_hex, tag_draft_error, toggle_set_membership,
        trust_mode_label, update_artifact_choices, vendor_choices,
    };

    /// The first screen decision of the console (§16.2).
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum AuthScreen {
        /// The `me` round-trip has not answered yet.
        Loading,
        /// An unconsumed bootstrap code exists: the first-run claim screen.
        Bootstrap,
        /// Sessions are enforced and none is presented: the sign-in screen.
        Login,
        /// The console is usable.
        Console,
    }

    /// The CSRF token of the presenting session, held only in memory
    /// (§16.2 "CSRF 防护"): the session cookie lives in the browser, and
    /// this module-level token accompanies every mutating request.
    static CSRF_TOKEN: std::sync::OnceLock<std::sync::Mutex<Option<String>>> =
        std::sync::OnceLock::new();

    /// The in-memory CSRF token of the presenting session.
    fn csrf_token() -> Option<String> {
        CSRF_TOKEN
            .get_or_init(|| std::sync::Mutex::new(None))
            .lock()
            .ok()
            .and_then(|guard| guard.clone())
    }

    fn set_csrf_token(token: String) {
        if let Ok(mut slot) = CSRF_TOKEN
            .get_or_init(|| std::sync::Mutex::new(None))
            .lock()
        {
            *slot = Some(token);
        }
    }

    /// Flips to the sign-in screen when a request is refused with 401.
    static SESSION_EXPIRED: std::sync::OnceLock<RwSignal<bool>> = std::sync::OnceLock::new();

    fn session_expired_signal() -> RwSignal<bool> {
        *SESSION_EXPIRED.get_or_init(|| RwSignal::new(false))
    }

    fn mark_session_expired() {
        session_expired_signal().set(true);
    }

    /// Whether a response is usable; a 401 marks the session as expired so
    /// the shell returns to the sign-in screen.
    fn response_ok(response: &Response) -> bool {
        if response.status() == 401 {
            mark_session_expired();
        }
        response.ok()
    }

    /// Adds the presenting CSRF token to one mutating request (§16.2).
    fn with_csrf(request: RequestBuilder) -> RequestBuilder {
        match csrf_token() {
            Some(token) => request.header("X-CSRF-Token", &token),
            None => request,
        }
    }

    /// The §16.2 session state of the client: the console's first screen
    /// decision.
    async fn fetch_me() -> Option<MeResponse> {
        let response = Request::get("/api/v1/auth/me")
            .header("Accept", "application/json")
            .send()
            .await
            .ok()?;
        if !response_ok(&response) {
            return None;
        }
        response.json::<MeResponse>().await.ok()
    }

    /// Presents credentials and returns the CSRF token of the fresh
    /// session. The browser stores the session cookie automatically.
    async fn post_login(
        username: &str,
        password: &str,
        totp_code: Option<&str>,
    ) -> Result<LoginResponse, String> {
        let request = LoginRequest::new(
            username.to_owned(),
            password.to_owned().into(),
            totp_code.map(str::to_owned),
        );
        let Ok(request) = Request::post("/api/v1/auth/login").json(&request) else {
            return Err("the sign-in request could not be prepared".to_owned());
        };
        let Ok(response) = request.send().await else {
            return Err("the sign-in request could not be sent".to_owned());
        };
        if !response_ok(&response) {
            return Err("sign-in failed".to_owned());
        }
        response
            .json::<LoginResponse>()
            .await
            .map_err(|_| "the sign-in response could not be parsed".to_owned())
    }

    /// Claims the product with the one-time code and the first password.
    async fn post_bootstrap(
        code: &str,
        password: &str,
        totp_secret: Option<&str>,
        totp_code: Option<&str>,
    ) -> Result<BootstrapCompleteResponse, String> {
        let request = BootstrapCompleteRequest::new(
            code.to_owned(),
            password.to_owned().into(),
            totp_secret.map(str::to_owned),
            totp_code.map(str::to_owned),
        );
        let Ok(request) = Request::post("/api/v1/auth/bootstrap").json(&request) else {
            return Err("the bootstrap request could not be prepared".to_owned());
        };
        let Ok(response) = request.send().await else {
            return Err("the bootstrap request could not be sent".to_owned());
        };
        if !response_ok(&response) {
            return Err("bootstrap failed — check the one-time code".to_owned());
        }
        response
            .json::<BootstrapCompleteResponse>()
            .await
            .map_err(|_| "the bootstrap response could not be parsed".to_owned())
    }

    /// Signs the presenting session out.
    async fn post_logout() -> bool {
        let Ok(request) = with_csrf(Request::post("/api/v1/auth/logout")).json(&LogoutRequest {})
        else {
            return false;
        };
        let Ok(response) = request.send().await else {
            return false;
        };
        response.ok()
    }

    /// The §16.2 session administration listing.
    async fn fetch_sessions() -> Option<SessionAdminResponse> {
        let response = Request::get("/api/v1/admin/sessions")
            .header("Accept", "application/json")
            .send()
            .await
            .ok()?;
        if !response_ok(&response) {
            return None;
        }
        response.json::<SessionAdminResponse>().await.ok()
    }

    /// Revokes one presented session (§16.2).
    async fn post_revoke_session(session_id: &str) -> bool {
        let Ok(session_id) = uuid::Uuid::parse_str(session_id) else {
            return false;
        };
        let request = RevokeSessionRequest::new(session_id);
        let Ok(request) = with_csrf(Request::post("/api/v1/admin/sessions")).json(&request) else {
            return false;
        };
        let Ok(response) = request.send().await else {
            return false;
        };
        response.ok()
    }

    /// The §16.1 user administration listing.
    async fn fetch_users() -> Option<UserAdminResponse> {
        let response = Request::get("/api/v1/admin/users")
            .header("Accept", "application/json")
            .send()
            .await
            .ok()?;
        if !response_ok(&response) {
            return None;
        }
        response.json::<UserAdminResponse>().await.ok()
    }

    /// Creates one product user with its §16.1 role.
    async fn post_create_user(name: &str, role: RoleResponse) -> bool {
        let request = CreateUserRequest::new(name.to_owned(), role);
        let Ok(request) = with_csrf(Request::post("/api/v1/admin/users")).json(&request) else {
            return false;
        };
        let Ok(response) = request.send().await else {
            return false;
        };
        response.ok()
    }

    /// Transitions one principal's enabled/disabled state (§16.1).
    async fn post_set_user_state(principal_id: &str, state: PrincipalStateResponse) -> bool {
        let request = SetPrincipalStateRequest::new(state);
        let path = format!("/api/v1/admin/users/{principal_id}/state");
        let Ok(request) = with_csrf(Request::post(&path)).json(&request) else {
            return false;
        };
        let Ok(response) = request.send().await else {
            return false;
        };
        response.ok()
    }

    /// Reassigns one principal's §16.1 role.
    async fn post_assign_role(principal_id: &str, role: RoleResponse) -> bool {
        let request = AssignRoleRequest::new(role);
        let path = format!("/api/v1/admin/users/{principal_id}/role");
        let Ok(request) = with_csrf(Request::post(&path)).json(&request) else {
            return false;
        };
        let Ok(response) = request.send().await else {
            return false;
        };
        response.ok()
    }

    /// The §16.2 sign-in screen: username, password, and the optional TOTP
    /// code of an active authenticator.
    #[component]
    fn LoginView(on_success: Callback<()>) -> impl IntoView {
        let (username, set_username) = signal(String::new());
        let (password, set_password) = signal(String::new());
        let (totp_code, set_totp_code) = signal(String::new());
        let (error, set_error) = signal(None::<String>);
        let (busy, set_busy) = signal(false);

        let submit = move |_| {
            if busy.get() {
                return;
            }
            set_busy.set(true);
            set_error.set(None);
            let username = username.get();
            let password = password.get();
            let totp_code = totp_code.get();
            spawn_local(async move {
                let totp = (!totp_code.is_empty()).then_some(totp_code.as_str());
                match post_login(&username, &password, totp).await {
                    Ok(response) => {
                        set_csrf_token(response.csrf_token().to_owned());
                        on_success.run(());
                    }
                    Err(message) => {
                        set_busy.set(false);
                        set_error.set(Some(message));
                    }
                }
            });
        };

        view! {
            <section class="auth-screen" aria-label="Sign in">
                <div class="auth-card">
                    <p class="eyebrow">"Local Redfish management"</p>
                    <h2>"Sign in"</h2>
                    <label>
                        "Username"
                        <input
                            type="text"
                            autocomplete="username"
                            prop:value=username
                            on:input=move |event| set_username.set(event_target_value(&event))
                        />
                    </label>
                    <label>
                        "Password"
                        <input
                            type="password"
                            autocomplete="current-password"
                            prop:value=password
                            on:input=move |event| set_password.set(event_target_value(&event))
                        />
                    </label>
                    <label>
                        "TOTP code (if enrolled)"
                        <input
                            type="text"
                            inputmode="numeric"
                            autocomplete="one-time-code"
                            placeholder="6 digits"
                            prop:value=totp_code
                            on:input=move |event| set_totp_code.set(event_target_value(&event))
                        />
                    </label>
                    <p class="auth-error" hidden=move || error.get().is_none()>
                        {move || error.get().unwrap_or_default()}
                    </p>
                    <button type="button" class="btn btn-primary" disabled=move || busy.get() on:click=submit>
                        "Sign in"
                    </button>
                </div>
            </section>
        }
    }

    /// The §16.2 first-run screen: the one-time bootstrap code and the
    /// first administrator password, with the optional TOTP enrollment.
    #[component]
    fn BootstrapView(on_success: Callback<()>) -> impl IntoView {
        let (code, set_code) = signal(String::new());
        let (password, set_password) = signal(String::new());
        let (confirmation, set_confirmation) = signal(String::new());
        let (want_totp, set_want_totp) = signal(false);
        let (totp_secret, set_totp_secret) = signal(String::new());
        let (totp_code, set_totp_code) = signal(String::new());
        let (error, set_error) = signal(None::<String>);
        let (busy, set_busy) = signal(false);

        let submit = move |_| {
            if busy.get() {
                return;
            }
            set_error.set(None);
            if password.get() != confirmation.get() {
                set_error.set(Some("the passwords do not match".to_owned()));
                return;
            }
            if password.get().chars().count() < 12 {
                set_error.set(Some(
                    "the password must contain at least 12 characters".to_owned(),
                ));
                return;
            }
            set_busy.set(true);
            let code = code.get();
            let password = password.get();
            let totp_pair = want_totp
                .get()
                .then(|| (totp_secret.get(), totp_code.get()));
            spawn_local(async move {
                let (secret, activation) = match &totp_pair {
                    Some((secret, activation)) => {
                        (Some(secret.as_str()), Some(activation.as_str()))
                    }
                    None => (None, None),
                };
                match post_bootstrap(&code, &password, secret, activation).await {
                    Ok(response) => {
                        set_csrf_token(response.csrf_token().to_owned());
                        on_success.run(());
                    }
                    Err(message) => {
                        set_busy.set(false);
                        set_error.set(Some(message));
                    }
                }
            });
        };

        view! {
            <section class="auth-screen" aria-label="First-run setup">
                <div class="auth-card">
                    <p class="eyebrow">"Local Redfish management"</p>
                    <h2>"First-run setup"</h2>
                    <p class="auth-note">
                        "Enter the one-time bootstrap code printed by the console to set the administrator password."
                    </p>
                    <label>
                        "Bootstrap code"
                        <input
                            type="text"
                            autocomplete="off"
                            spellcheck="false"
                            prop:value=code
                            on:input=move |event| set_code.set(event_target_value(&event))
                        />
                    </label>
                    <label>
                        "New password"
                        <input
                            type="password"
                            autocomplete="new-password"
                            prop:value=password
                            on:input=move |event| set_password.set(event_target_value(&event))
                        />
                    </label>
                    <label>
                        "Confirm password"
                        <input
                            type="password"
                            autocomplete="new-password"
                            prop:value=confirmation
                            on:input=move |event| set_confirmation.set(event_target_value(&event))
                        />
                    </label>
                    <label class="auth-check">
                        <input
                            type="checkbox"
                            prop:checked=want_totp
                            on:change=move |event| set_want_totp.set(event_target_checked(&event))
                        />
                        "Set up TOTP now (optional)"
                    </label>
                    <div hidden=move || !want_totp.get()>
                        <label>
                            "Secret from your authenticator app"
                            <input
                                type="text"
                                autocomplete="off"
                                spellcheck="false"
                                prop:value=totp_secret
                                on:input=move |event| set_totp_secret.set(event_target_value(&event))
                            />
                        </label>
                        <label>
                            "Activation code"
                            <input
                                type="text"
                                inputmode="numeric"
                                autocomplete="one-time-code"
                                placeholder="6 digits"
                                prop:value=totp_code
                                on:input=move |event| set_totp_code.set(event_target_value(&event))
                            />
                        </label>
                    </div>
                    <p class="auth-error" hidden=move || error.get().is_none()>
                        {move || error.get().unwrap_or_default()}
                    </p>
                    <button type="button" class="btn btn-primary" disabled=move || busy.get() on:click=submit>
                        "Set up"
                    </button>
                </div>
            </section>
        }
    }

    /// The §16.1 user administration view: the principal listing, state
    /// transitions, role assignments, and the create-user form.
    #[component]
    fn UsersView(view: ReadSignal<ConsoleView>) -> impl IntoView {
        let active = move || view.get() == ConsoleView::Users;
        let (list_state, set_list_state) = signal(UsersListState::Idle);
        let (list_triggered, set_list_triggered) = signal(false);
        let (draft_name, set_draft_name) = signal(String::new());
        let (draft_role, set_draft_role) = signal(RoleView::Viewer);
        let (draft_error, set_draft_error) = signal(None::<String>);
        let (create_state, set_create_state) = signal(CreateUserState::Idle);

        Effect::new(move |_| {
            if active() && !list_triggered.get() {
                set_list_triggered.set(true);
                set_list_state.set(UsersListState::Loading);
                spawn_local(async move {
                    set_list_state.set(match fetch_users().await {
                        Some(response) => UsersListState::Ready(response),
                        None => UsersListState::Failed,
                    });
                });
            }
        });

        let reload_list = move || {
            set_list_state.set(UsersListState::Loading);
            spawn_local(async move {
                set_list_state.set(match fetch_users().await {
                    Some(response) => UsersListState::Ready(response),
                    None => UsersListState::Failed,
                });
            });
        };
        let on_reload = move |_| reload_list();

        let on_create = move |_| {
            if draft_name.get().trim().is_empty() {
                set_draft_error.set(Some("the user name is required".to_owned()));
                return;
            }
            set_create_state.set(CreateUserState::InFlight);
            let name = draft_name.get();
            let role = draft_role.get();
            spawn_local(async move {
                let role = match role {
                    RoleView::Administrator => RoleResponse::Administrator,
                    RoleView::Operator => RoleResponse::Operator,
                    RoleView::Viewer => RoleResponse::Viewer,
                };
                if post_create_user(&name, role).await {
                    set_create_state.set(CreateUserState::Created);
                    set_draft_name.set(String::new());
                    reload_list();
                } else {
                    set_create_state.set(CreateUserState::Failed);
                }
            });
        };

        let on_set_state = move |principal_id: String, state: PrincipalStateResponse| {
            spawn_local(async move {
                if post_set_user_state(&principal_id, state).await {
                    reload_list();
                }
            });
        };

        let on_assign_role = move |principal_id: String, role: RoleResponse| {
            spawn_local(async move {
                if post_assign_role(&principal_id, role).await {
                    reload_list();
                }
            });
        };

        view! {
            <section class="auth-admin" hidden=move || !active()>
                <div class="section-heading">
                    <div>
                        <p class="section-label">"Administration"</p>
                        <h2>"Users"</h2>
                    </div>
                    <button type="button" class="btn" on:click=on_reload>
                        "Refresh"
                    </button>
                </div>
                <div class="auth-admin-form">
                    <input
                        type="text"
                        placeholder="User name"
                        autocomplete="off"
                        spellcheck="false"
                        prop:value=draft_name
                        on:input=move |event| set_draft_name.set(event_target_value(&event))
                    />
                    <select
                        aria-label="New user role"
                        on:change=move |event| {
                            let value = event_target_value(&event);
                            set_draft_role.set(match value.as_str() {
                                "Administrator" => RoleView::Administrator,
                                "Operator" => RoleView::Operator,
                                _ => RoleView::Viewer,
                            });
                        }
                    >
                        <option value="Administrator">"Administrator"</option>
                        <option value="Operator">"Operator"</option>
                        <option value="Viewer">"Viewer"</option>
                    </select>
                    <button type="button" class="btn btn-primary" on:click=on_create>
                        "Create user"
                    </button>
                </div>
                <p class="auth-error" hidden=move || draft_error.get().is_none()>
                    {move || draft_error.get().unwrap_or_default()}
                </p>
                <p class="auth-note" hidden=move || create_state.get() != CreateUserState::Failed>
                    "The user could not be created."
                </p>
                <div class="auth-table" hidden=move || !matches!(list_state.get(), UsersListState::Ready(_))>
                    {move || {
                        let UsersListState::Ready(response) = list_state.get() else {
                            return Vec::new();
                        };
                        response
                            .users()
                            .iter()
                            .map(|user| {
                                let principal_id = user.id().to_owned();
                                let principal_id_for_select = principal_id.clone();
                                let enabled = user.state() == PrincipalStateResponse::Enabled;
                                let role_label = user
                                    .role()
                                    .map(RoleView::from_wire)
                                    .map(RoleView::label)
                                    .unwrap_or("—")
                                    .to_owned();
                                let name = user.name().to_owned();
                                let state_label = if enabled {
                                    "enabled".to_owned()
                                } else {
                                    "disabled".to_owned()
                                };
                                let action_label = if enabled {
                                    "Disable".to_owned()
                                } else {
                                    "Enable".to_owned()
                                };
                                view! {
                                    <div class="auth-table-row">
                                        <span class="auth-table-name">{name}</span>
                                        <span class="auth-table-role">{role_label}</span>
                                        <span class="auth-table-state">{state_label}</span>
                                        <select
                                            aria-label="Role"
                                            on:change=move |event| {
                                                let value = event_target_value(&event);
                                                let role = match value.as_str() {
                                                    "Administrator" => RoleResponse::Administrator,
                                                    "Operator" => RoleResponse::Operator,
                                                    _ => RoleResponse::Viewer,
                                                };
                                                on_assign_role(principal_id_for_select.clone(), role);
                                            }
                                        >
                                            <option value="Administrator">"Administrator"</option>
                                            <option value="Operator">"Operator"</option>
                                            <option value="Viewer">"Viewer"</option>
                                        </select>
                                        <button
                                            type="button"
                                            class="btn"
                                            on:click=move |_| {
                                                let state = if enabled {
                                                    PrincipalStateResponse::Disabled
                                                } else {
                                                    PrincipalStateResponse::Enabled
                                                };
                                                on_set_state(principal_id.clone(), state);
                                            }
                                        >
                                            {action_label}
                                        </button>
                                    </div>
                                }
                            })
                            .collect()
                    }}
                </div>
                <p class="auth-note" hidden=move || !list_state.get().is_failed()>
                    "The user list is temporarily unavailable."
                </p>
            </section>
        }
    }

    /// The §16.2 session administration view: every session with its
    /// lifecycle and the per-session revocation action.
    #[component]
    fn SessionsView(view: ReadSignal<ConsoleView>) -> impl IntoView {
        let active = move || view.get() == ConsoleView::Sessions;
        let (list_state, set_list_state) = signal(SessionsListState::Idle);
        let (list_triggered, set_list_triggered) = signal(false);

        Effect::new(move |_| {
            if active() && !list_triggered.get() {
                set_list_triggered.set(true);
                set_list_state.set(SessionsListState::Loading);
                spawn_local(async move {
                    set_list_state.set(match fetch_sessions().await {
                        Some(response) => SessionsListState::Ready(response),
                        None => SessionsListState::Failed,
                    });
                });
            }
        });

        let reload_list = move || {
            set_list_state.set(SessionsListState::Loading);
            spawn_local(async move {
                set_list_state.set(match fetch_sessions().await {
                    Some(response) => SessionsListState::Ready(response),
                    None => SessionsListState::Failed,
                });
            });
        };
        let on_reload = move |_| reload_list();

        let on_revoke = move |session_id: String| {
            spawn_local(async move {
                if post_revoke_session(&session_id).await {
                    reload_list();
                }
            });
        };

        view! {
            <section class="auth-admin" hidden=move || !active()>
                <div class="section-heading">
                    <div>
                        <p class="section-label">"Administration"</p>
                        <h2>"Sessions"</h2>
                    </div>
                    <button type="button" class="btn" on:click=on_reload>
                        "Refresh"
                    </button>
                </div>
                <div class="auth-table" hidden=move || !matches!(list_state.get(), SessionsListState::Ready(_))>
                    {move || {
                        let SessionsListState::Ready(response) = list_state.get() else {
                            return Vec::new();
                        };
                        response
                            .sessions()
                            .iter()
                            .map(|session| {
                                let session_id = session.session_id().to_owned();
                                let name = session.principal_name().to_owned();
                                let created = format_observed_at(&session.created_at());
                                let last_used = format_observed_at(&session.last_used_at());
                                let expires = format_observed_at(&session.expires_at());
                                let revoked = session.revoked_at().is_some();
                                let current = session.is_current();
                                view! {
                                    <div class="auth-table-row">
                                        <span class="auth-table-name">{name.clone()}</span>
                                        <span class="auth-table-time">"created " {created}</span>
                                        <span class="auth-table-time">"used " {last_used}</span>
                                        <span class="auth-table-time">"expires " {expires}</span>
                                        <span class="auth-table-state">
                                            {if revoked { "revoked" } else if current { "current" } else { "active" }}
                                        </span>
                                        <button
                                            type="button"
                                            class="btn"
                                            disabled=revoked || current
                                            on:click=move |_| on_revoke(session_id.clone())
                                        >
                                            "Revoke"
                                        </button>
                                    </div>
                                }
                            })
                            .collect()
                    }}
                </div>
                <p class="auth-note" hidden=move || !list_state.get().is_failed()>
                    "The session list is temporarily unavailable."
                </p>
            </section>
        }
    }

    #[component]
    fn CenterSitesView(view: ReadSignal<ConsoleView>) -> impl IntoView {
        let active = move || view.get() == ConsoleView::CenterSites;
        let (list_state, set_list_state) = signal(CenterSitesListState::Idle);
        let (list_triggered, set_list_triggered) = signal(false);
        let (selected_site, set_selected_site) = signal(None::<String>);
        let (detail_state, set_detail_state) = signal(CenterEndpointsDetailState::Idle);

        Effect::new(move |_| {
            if active() && !list_triggered.get() {
                set_list_triggered.set(true);
                set_list_state.set(CenterSitesListState::Loading);
                spawn_local(async move {
                    set_list_state.set(fetch_center_sites().await);
                });
            }
        });

        let reload_sites = move || {
            set_list_state.set(CenterSitesListState::Loading);
            spawn_local(async move {
                set_list_state.set(fetch_center_sites().await);
            });
        };

        let on_refresh = move |_| {
            reload_sites();
            if let Some(site_id) = selected_site.get() {
                set_detail_state.set(CenterEndpointsDetailState::Loading);
                spawn_local(async move {
                    set_detail_state.set(fetch_center_endpoints(Some(&site_id)).await);
                });
            }
        };

        let on_select_site = Callback::new(move |site_id: String| {
            set_selected_site.set(Some(site_id.clone()));
            set_detail_state.set(CenterEndpointsDetailState::Loading);
            spawn_local(async move {
                set_detail_state.set(fetch_center_endpoints(Some(&site_id)).await);
            });
        });

        let on_clear_site = move |_| {
            set_selected_site.set(None);
            set_detail_state.set(CenterEndpointsDetailState::Idle);
        };

        view! {
            <section class="view-section" hidden=move || !active()>
                <div class="inventory-heading">
                    <div>
                        <p class="section-label">"Center connection"</p>
                        <h2>{move || list_state.get().count_text()}</h2>
                    </div>
                    <p>"The §15.5 registered-site view: bindings, presence, and aggregated endpoints."</p>
                </div>
                <div class="inventory-actions">
                    <button
                        type="button"
                        class="btn"
                        disabled=move || matches!(list_state.get(), CenterSitesListState::Loading)
                        on:click=on_refresh
                    >
                        "Refresh"
                    </button>
                </div>
                <p class="inline-status" hidden=move || !matches!(list_state.get(), CenterSitesListState::Loading)>
                    "Loading registered sites..."
                </p>
                <p class="form-error" hidden=move || !list_state.get().is_failed()>
                    "The registered-site list is temporarily unavailable."
                </p>
                <p
                    class="empty-inventory"
                    hidden=move || !list_state.get().is_ready() || list_state.get().count_text() != "0 registered sites"
                >
                    "No sites are registered yet. Register a site on the Center bindings page."
                </p>
                <div class="endpoint-grid">
                    {move || {
                        let CenterSitesListState::Ready(sites) = list_state.get() else {
                            return Vec::new();
                        };
                        sites
                            .into_iter()
                            .map(|site| {
                                let site_id = site.site_id.clone();
                                let site_id_for_click = site_id.clone();
                                let display_name = site.display_name.clone();
                                let binding_label = site.binding.map(|binding| binding.label().to_owned());
                                let online = site.online;
                                let endpoint_count = site.endpoint_count;
                                let last_refresh = site.last_refresh_at.as_ref().map(format_observed_at);
                                view! {
                                    <button
                                        type="button"
                                        class="center-site-card"
                                        on:click=move |_| on_select_site.run(site_id_for_click.clone())
                                    >
                                        <div class="endpoint-title">
                                            <div>
                                                <h3>{display_name}</h3>
                                                <p class="endpoint-address">{site_id}</p>
                                            </div>
                                            <span class="trust-badge">
                                                {move || binding_label.clone().unwrap_or_else(|| "no binding".to_owned())}
                                            </span>
                                            <span
                                                class="status-dot"
                                                class:status-dot-waiting=move || !online
                                                title=move || if online { "online" } else { "offline" }
                                            ></span>
                                        </div>
                                        <div class="snapshot-heading">
                                            <span>{move || match endpoint_count {
                                                1 => "1 aggregated endpoint".to_owned(),
                                                count => format!("{count} aggregated endpoints"),
                                            }}</span>
                                        </div>
                                        <p class="endpoint-address">
                                            {move || last_refresh.clone().map_or_else(|| "no refresh yet".to_owned(), |text| format!("last refresh {text}"))}
                                        </p>
                                    </button>
                                }
                            })
                            .collect_view()
                    }}
                </div>
                <div class="form-panel result-panel" hidden=move || selected_site.get().is_none()>
                    <div class="section-heading">
                        <div>
                            <p class="section-label">"Site detail"</p>
                            <h2>{move || selected_site.get().unwrap_or_default()}</h2>
                        </div>
                        <button type="button" class="btn" on:click=on_clear_site>
                            "Close detail"
                        </button>
                    </div>
                    <p class="inline-status" hidden=move || !matches!(detail_state.get(), CenterEndpointsDetailState::Loading)>
                        "Loading aggregated endpoints..."
                    </p>
                    <p class="form-error" hidden=move || !detail_state.get().is_failed()>
                        "The aggregated endpoint list is temporarily unavailable."
                    </p>
                    <p
                        class="empty-inventory"
                        hidden=move || {
                            !matches!(detail_state.get(), CenterEndpointsDetailState::Ready(ref rows) if rows.is_empty())
                        }
                    >
                        "This site has not projected any endpoints yet."
                    </p>
                    <table class="results-table" hidden=move || !detail_state.get().is_ready()>
                        <thead>
                            <tr>
                                <th>"Endpoint"</th>
                                <th>"Address"</th>
                                <th>"Health"</th>
                                <th>"Generation"</th>
                            </tr>
                        </thead>
                        <tbody>
                            {move || {
                                let CenterEndpointsDetailState::Ready(endpoints) = detail_state.get()
                                else {
                                    return Vec::new();
                                };
                                endpoints
                                    .into_iter()
                                    .map(|endpoint| {
                                        view! {
                                            <tr>
                                                <td class="result-address">{endpoint.display_name}</td>
                                                <td class="result-detail">{endpoint.address}</td>
                                                <td class="result-detail">{endpoint.health}</td>
                                                <td class="result-detail">
                                                    {move || endpoint.refresh_generation.to_string()}
                                                </td>
                                            </tr>
                                        }
                                    })
                                    .collect_view()
                            }}
                        </tbody>
                    </table>
                </div>
            </section>
        }
    }

    #[component]
    fn CenterOperationsView(view: ReadSignal<ConsoleView>) -> impl IntoView {
        let active = move || view.get() == ConsoleView::CenterOperations;
        let (list_state, set_list_state) = signal(CenterOperationsListState::Idle);
        let (list_triggered, set_list_triggered) = signal(false);
        let (sites_state, set_sites_state) = signal(CenterSitesListState::Idle);
        let (sites_triggered, set_sites_triggered) = signal(false);
        let (endpoints_state, set_endpoints_state) = signal(CenterEndpointsDetailState::Idle);
        let (endpoints_triggered, set_endpoints_triggered) = signal(false);
        let (draft, set_draft) = signal(CenterOperationDraft::new());
        let (draft_error, set_draft_error) = signal(None::<CenterOperationDraftError>);
        let (submit_state, set_submit_state) = signal(CenterOperationSubmitState::Idle);

        Effect::new(move |_| {
            if active() && !list_triggered.get() {
                set_list_triggered.set(true);
                set_list_state.set(CenterOperationsListState::Loading);
                spawn_local(async move {
                    set_list_state.set(fetch_center_operations().await);
                });
            }
        });
        Effect::new(move |_| {
            if active() && !sites_triggered.get() {
                set_sites_triggered.set(true);
                set_sites_state.set(CenterSitesListState::Loading);
                spawn_local(async move {
                    set_sites_state.set(fetch_center_sites().await);
                });
            }
        });
        Effect::new(move |_| {
            if active() && !endpoints_triggered.get() {
                set_endpoints_triggered.set(true);
                set_endpoints_state.set(CenterEndpointsDetailState::Loading);
                spawn_local(async move {
                    set_endpoints_state.set(fetch_center_endpoints(None).await);
                });
            }
        });

        let reload = move |_| {
            set_list_state.set(CenterOperationsListState::Loading);
            spawn_local(async move {
                set_list_state.set(fetch_center_operations().await);
            });
            set_sites_state.set(CenterSitesListState::Loading);
            spawn_local(async move {
                set_sites_state.set(fetch_center_sites().await);
            });
            set_endpoints_state.set(CenterEndpointsDetailState::Loading);
            spawn_local(async move {
                set_endpoints_state.set(fetch_center_endpoints(None).await);
            });
        };

        let on_select_site = Callback::new(move |site_id: String| {
            set_draft.update(|draft| draft.site_id = site_id);
            set_draft.update(|draft| draft.endpoint_id = String::new());
            set_draft_error.set(None);
            set_submit_state.set(CenterOperationSubmitState::Idle);
        });

        let on_select_endpoint = Callback::new(move |endpoint_id: String| {
            set_draft.update(|draft| draft.endpoint_id = endpoint_id);
            set_draft_error.set(None);
            set_submit_state.set(CenterOperationSubmitState::Idle);
        });

        let on_target_input = move |event| {
            set_draft.update(|draft| draft.target = event_target_value(&event));
            set_draft_error.set(None);
            set_submit_state.set(CenterOperationSubmitState::Idle);
        };

        let on_select_family = Callback::new(move |family: CommandFamilyView| {
            set_draft.update(|draft| {
                draft.family = Some(family);
                // Switching families clears every other family's parameters,
                // so a later submission can never carry stale selections.
                draft.reset_type = None;
                draft.boot_source = None;
                draft.boot_enabled = None;
                draft.boot_mode = None;
                draft.secure_boot_action = None;
                draft.reset_keys_type = None;
                draft.event_action = None;
                draft.destination = String::new();
                draft.protocol = None;
                draft.event_types = Vec::new();
                draft.subscription_id = String::new();
            });
            set_draft_error.set(None);
            set_submit_state.set(CenterOperationSubmitState::Idle);
        });

        let on_submit = move |_| {
            let submitted = draft.get();
            let submission = match submitted.try_build() {
                Ok(submission) => submission,
                Err(error) => {
                    set_draft_error.set(Some(error));
                    return;
                }
            };
            set_draft_error.set(None);
            set_submit_state.set(CenterOperationSubmitState::InFlight);
            spawn_local(async move {
                match submit_center_operation(&submission).await {
                    Ok(()) => {
                        set_submit_state.set(CenterOperationSubmitState::Succeeded);
                        set_draft.set(CenterOperationDraft::new());
                        set_draft_error.set(None);
                        set_list_state.set(CenterOperationsListState::Loading);
                        spawn_local(async move {
                            set_list_state.set(fetch_center_operations().await);
                        });
                    }
                    Err(message) => {
                        set_submit_state
                            .set(CenterOperationSubmitState::Failed(message.to_owned()));
                    }
                }
            });
        };

        let site_choices = move || {
            let CenterSitesListState::Ready(sites) = sites_state.get() else {
                return Vec::new();
            };
            sites
        };
        let endpoint_choices = move || {
            let CenterEndpointsDetailState::Ready(endpoints) = endpoints_state.get() else {
                return Vec::new();
            };
            endpoints
        };

        view! {
            <section class="view-section" hidden=move || !active()>
                <div class="inventory-heading">
                    <div>
                        <p class="section-label">"Center connection"</p>
                        <h2>{move || list_state.get().count_text()}</h2>
                    </div>
                    <p>"The §15.6 tracking view and the typed dispatch form."</p>
                </div>
                <div class="inventory-actions">
                    <button type="button" class="btn" on:click=reload>
                        "Refresh"
                    </button>
                </div>
                <p class="inline-status" hidden=move || !list_state.get().is_loading()>
                    "Loading center operations..."
                </p>
                <p class="form-error" hidden=move || !list_state.get().is_failed()>
                    "The center operation list is temporarily unavailable."
                </p>
                <p
                    class="empty-inventory"
                    hidden=move || {
                        !list_state.get().is_ready() || !matches!(list_state.get(), CenterOperationsListState::Ready(ref rows) if rows.is_empty())
                    }
                >
                    "No center operations have been dispatched yet."
                </p>
                <div class="form-panel" hidden=move || !list_state.get().is_ready()>
                    {move || {
                        let CenterOperationsListState::Ready(operations) = list_state.get()
                        else {
                            return Vec::new();
                        };
                        operations
                            .into_iter()
                            .map(|operation| {
                                let state_class = if operation.state == "succeeded" {
                                    "result-success"
                                } else if operation.state == "failed" || operation.state == "cancelled" {
                                    "result-failure"
                                } else {
                                    "result-detail"
                                };
                                view! {
                                    <div class="auth-table-row">
                                        <span class="auth-table-name">{operation.command}</span>
                                        <span class="auth-table-time">
                                            {move || operation.target.clone().unwrap_or_else(|| "no target on record".to_owned())}
                                        </span>
                                        <span class="auth-table-time">
                                            {move || operation.actor.clone().unwrap_or_else(|| "system".to_owned())}
                                        </span>
                                        <span class=state_class>{operation.state}</span>
                                        <span class="auth-table-time">
                                            {move || format_observed_at(&operation.created_at)}
                                        </span>
                                    </div>
                                }
                            })
                            .collect_view()
                    }}
                </div>
                <div class="form-panel">
                    <p class="section-label">"Dispatch a center operation"</p>
                    <p class="form-hint">
                        "The site re-checks every precondition and only accepts what it can execute (§15.6)."
                    </p>
                    <div class="form-row">
                        <label for="center-op-site">"Site"</label>
                        <select
                            id="center-op-site"
                            prop:value=move || draft.get().site_id
                            on:change=move |event| {
                                on_select_site.run(event_target_value(&event));
                            }
                        >
                            <option value="">"Choose a site..."</option>
                            {move || {
                                site_choices()
                                    .into_iter()
                                    .map(|site| {
                                        let site_id = site.site_id.clone();
                                        let site_id_for_option = site_id.clone();
                                        let display_name = site.display_name.clone();
                                        view! {
                                            <option value=site_id_for_option.clone()>
                                                {move || format!("{display_name} ({site_id})")}
                                            </option>
                                        }
                                    })
                                    .collect_view()
                            }}
                        </select>
                    </div>
                    <div class="form-row">
                        <label for="center-op-endpoint">"Endpoint"</label>
                        <select
                            id="center-op-endpoint"
                            prop:value=move || draft.get().endpoint_id
                            on:change=move |event| {
                                on_select_endpoint.run(event_target_value(&event));
                            }
                        >
                            <option value="">"Choose an endpoint..."</option>
                            {move || {
                                let site = draft.get().site_id;
                                endpoint_choices()
                                    .into_iter()
                                    .filter(|endpoint| endpoint.site_id.as_deref() == Some(site.as_str()))
                                    .map(|endpoint| {
                                        let endpoint_id = endpoint.endpoint_id.clone();
                                        view! {
                                            <option value=endpoint_id.clone()>
                                                {move || format!("{} ({})", endpoint.display_name, endpoint.address)}
                                            </option>
                                        }
                                    })
                                    .collect_view()
                            }}
                        </select>
                    </div>
                    <div class="form-row">
                        <label for="center-op-target">"Target"</label>
                        <input
                            id="center-op-target"
                            type="text"
                            placeholder="/redfish/v1/Systems/1"
                            autocomplete="off"
                            prop:value=move || draft.get().target
                            on:input=on_target_input
                        />
                    </div>
                    <div class="form-row">
                        <label for="center-op-family">"Command family"</label>
                        <select
                            id="center-op-family"
                            prop:value=move || draft.get().family.map(|family| family.as_str()).unwrap_or("")
                            on:change=move |event| {
                                let value = event_target_value(&event);
                                if let Some(family) = CommandFamilyView::ALL
                                    .into_iter()
                                    .find(|family| family.as_str() == value)
                                {
                                    on_select_family.run(family);
                                }
                            }
                        >
                            <option value="">"Choose a family..."</option>
                            {CommandFamilyView::ALL
                                .into_iter()
                                .map(|family| {
                                    view! {
                                        <option value=family.as_str()>{family.label()}</option>
                                    }
                                })
                                .collect_view()}
                        </select>
                    </div>
                    {move || {
                        let family = draft.get().family;
                        match family {
                            Some(
                                CommandFamilyView::SystemReset
                                | CommandFamilyView::ManagerReset
                                | CommandFamilyView::ChassisReset,
                            ) => {
                                view! {
                                    <div class="form-row">
                                        <label for="center-op-reset">"Reset type"</label>
                                        <select
                                            id="center-op-reset"
                                            on:change=move |event| {
                                                let value = event_target_value(&event);
                                                if let Some(reset) = ResetTypeView::ALL
                                                    .into_iter()
                                                    .find(|reset| reset.as_str() == value)
                                                {
                                                    set_draft.update(|draft| draft.reset_type = Some(reset));
                                                    set_draft_error.set(None);
                                                    set_submit_state.set(CenterOperationSubmitState::Idle);
                                                }
                                            }
                                        >
                                            <option value="">"Choose a reset type..."</option>
                                            {ResetTypeView::ALL
                                                .into_iter()
                                                .map(|reset| {
                                                    view! {
                                                        <option value=reset.as_str()>{reset.as_str()}</option>
                                                    }
                                                })
                                                .collect_view()}
                                        </select>
                                    </div>
                                }
                                    .into_any()
                            }
                            Some(CommandFamilyView::BootOverride) => {
                                view! {
                                    <div class="form-row">
                                        <label for="center-op-boot-source">"Boot source"</label>
                                        <select
                                            id="center-op-boot-source"
                                            on:change=move |event| {
                                                let value = event_target_value(&event);
                                                if let Some(source) = BootSourceView::ALL
                                                    .into_iter()
                                                    .find(|source| source.as_str() == value)
                                                {
                                                    set_draft.update(|draft| draft.boot_source = Some(source));
                                                    set_draft_error.set(None);
                                                    set_submit_state.set(CenterOperationSubmitState::Idle);
                                                }
                                            }
                                        >
                                            <option value="">"Choose a boot source..."</option>
                                            {BootSourceView::ALL
                                                .into_iter()
                                                .map(|source| {
                                                    view! {
                                                        <option value=source.as_str()>{source.as_str()}</option>
                                                    }
                                                })
                                                .collect_view()}
                                        </select>
                                    </div>
                                    <div class="form-row">
                                        <label for="center-op-boot-enabled">"Enabled"</label>
                                        <select
                                            id="center-op-boot-enabled"
                                            on:change=move |event| {
                                                let value = event_target_value(&event);
                                                if let Some(enabled) = BootEnabledView::ALL
                                                    .into_iter()
                                                    .find(|enabled| enabled.as_str() == value)
                                                {
                                                    set_draft.update(|draft| draft.boot_enabled = Some(enabled));
                                                    set_draft_error.set(None);
                                                    set_submit_state.set(CenterOperationSubmitState::Idle);
                                                }
                                            }
                                        >
                                            <option value="">"Choose..."</option>
                                            {BootEnabledView::ALL
                                                .into_iter()
                                                .map(|enabled| {
                                                    view! {
                                                        <option value=enabled.as_str()>{enabled.as_str()}</option>
                                                    }
                                                })
                                                .collect_view()}
                                        </select>
                                    </div>
                                    <div class="form-row">
                                        <label for="center-op-boot-mode">"Mode"</label>
                                        <select
                                            id="center-op-boot-mode"
                                            on:change=move |event| {
                                                let value = event_target_value(&event);
                                                if let Some(mode) = BootModeView::ALL
                                                    .into_iter()
                                                    .find(|mode| mode.as_str() == value)
                                                {
                                                    set_draft.update(|draft| draft.boot_mode = Some(mode));
                                                    set_draft_error.set(None);
                                                    set_submit_state.set(CenterOperationSubmitState::Idle);
                                                }
                                            }
                                        >
                                            <option value="">"Choose a mode..."</option>
                                            {BootModeView::ALL
                                                .into_iter()
                                                .map(|mode| {
                                                    view! {
                                                        <option value=mode.as_str()>{mode.as_str()}</option>
                                                    }
                                                })
                                                .collect_view()}
                                        </select>
                                    </div>
                                }
                                    .into_any()
                            }
                            Some(CommandFamilyView::SecureBoot) => {
                                view! {
                                    <div class="form-row">
                                        <label for="center-op-secure-boot">"Action"</label>
                                        <select
                                            id="center-op-secure-boot"
                                            on:change=move |event| {
                                                let value = event_target_value(&event);
                                                let selected = match value.as_str() {
                                                    "enable" => Some(SecureBootActionView::Enable),
                                                    "disable" => Some(SecureBootActionView::Disable),
                                                    "reset-keys" => Some(SecureBootActionView::ResetKeys(
                                                        ResetKeysTypeView::ResetAllKeysToDefault,
                                                    )),
                                                    _ => None,
                                                };
                                                set_draft.update(|draft| draft.secure_boot_action = selected);
                                                set_draft_error.set(None);
                                                set_submit_state.set(CenterOperationSubmitState::Idle);
                                            }
                                        >
                                            <option value="">"Choose an action..."</option>
                                            <option value="enable">
                                                {SecureBootActionView::Enable.label()}
                                            </option>
                                            <option value="disable">
                                                {SecureBootActionView::Disable.label()}
                                            </option>
                                            <option value="reset-keys">
                                                {SecureBootActionView::ResetKeys(ResetKeysTypeView::DeleteAllKeys).label()}
                                            </option>
                                        </select>
                                    </div>
                                    <div class="form-row" hidden=move || {
                                        !matches!(draft.get().secure_boot_action, Some(SecureBootActionView::ResetKeys(_)))
                                    }>
                                        <label for="center-op-reset-keys">"Key set"</label>
                                        <select
                                            id="center-op-reset-keys"
                                            on:change=move |event| {
                                                let value = event_target_value(&event);
                                                if let Some(kind) = ResetKeysTypeView::ALL
                                                    .into_iter()
                                                    .find(|kind| kind.as_str() == value)
                                                {
                                                    set_draft.update(|draft| draft.reset_keys_type = Some(kind));
                                                    set_draft_error.set(None);
                                                    set_submit_state.set(CenterOperationSubmitState::Idle);
                                                }
                                            }
                                        >
                                            <option value="">"Choose a key set..."</option>
                                            {ResetKeysTypeView::ALL
                                                .into_iter()
                                                .map(|kind| {
                                                    view! {
                                                        <option value=kind.as_str()>{kind.as_str()}</option>
                                                    }
                                                })
                                                .collect_view()}
                                        </select>
                                    </div>
                                }
                                    .into_any()
                            }
                            Some(CommandFamilyView::EventSubscription) => {
                                view! {
                                    <div class="form-row">
                                        <label for="center-op-event-action">"Action"</label>
                                        <select
                                            id="center-op-event-action"
                                            on:change=move |event| {
                                                let value = event_target_value(&event);
                                                let selected = match value.as_str() {
                                                    "create" => Some(EventActionView::CreateSubscription),
                                                    "delete" => Some(EventActionView::DeleteSubscription),
                                                    _ => None,
                                                };
                                                set_draft.update(|draft| draft.event_action = selected);
                                                set_draft_error.set(None);
                                                set_submit_state.set(CenterOperationSubmitState::Idle);
                                            }
                                        >
                                            <option value="">"Choose an action..."</option>
                                            <option value="create">
                                                {EventActionView::CreateSubscription.label()}
                                            </option>
                                            <option value="delete">
                                                {EventActionView::DeleteSubscription.label()}
                                            </option>
                                        </select>
                                    </div>
                                    <div class="form-row" hidden=move || {
                                        !matches!(draft.get().event_action, Some(EventActionView::CreateSubscription))
                                    }>
                                        <label for="center-op-destination">"Destination"</label>
                                        <input
                                            id="center-op-destination"
                                            type="text"
                                            placeholder="https://listener.example/sink"
                                            autocomplete="off"
                                            on:input=move |event| {
                                                set_draft.update(|draft| draft.destination = event_target_value(&event));
                                                set_draft_error.set(None);
                                                set_submit_state.set(CenterOperationSubmitState::Idle);
                                            }
                                        />
                                    </div>
                                    <div class="form-row" hidden=move || {
                                        !matches!(draft.get().event_action, Some(EventActionView::CreateSubscription))
                                    }>
                                        <label for="center-op-protocol">"Protocol"</label>
                                        <select
                                            id="center-op-protocol"
                                            on:change=move |event| {
                                                let value = event_target_value(&event);
                                                if let Some(protocol) = EventProtocolView::ALL
                                                    .into_iter()
                                                    .find(|protocol| protocol.as_str() == value)
                                                {
                                                    set_draft.update(|draft| draft.protocol = Some(protocol));
                                                    set_draft_error.set(None);
                                                    set_submit_state.set(CenterOperationSubmitState::Idle);
                                                }
                                            }
                                        >
                                            <option value="">"Choose a protocol..."</option>
                                            {EventProtocolView::ALL
                                                .into_iter()
                                                .map(|protocol| {
                                                    view! {
                                                        <option value=protocol.as_str()>{protocol.as_str()}</option>
                                                    }
                                                })
                                                .collect_view()}
                                        </select>
                                    </div>
                                    <div class="form-row" hidden=move || {
                                        !matches!(draft.get().event_action, Some(EventActionView::CreateSubscription))
                                    }>
                                        <label for="center-op-event-types">"Event types"</label>
                                        <div class="filter-chip-list">
                                            {EventTypeView::ALL
                                                .into_iter()
                                                .map(|event_type| {
                                                    let code = event_type.as_str();
                                                    let label = event_type.as_str();
                                                    view! {
                                                        <label class="filter-chip">
                                                            <input
                                                                type="checkbox"
                                                                on:change=move |event| {
                                                                    let checked = event_target_checked(&event);
                                                                    let code = code;
                                                                    set_draft.update(|draft| {
                                                                        if checked {
                                                                            if let Some(event_type) = EventTypeView::ALL
                                                                                .into_iter()
                                                                                .find(|candidate| candidate.as_str() == code)
                                                                            {
                                                                                if !draft.event_types.contains(&event_type) {
                                                                                    draft.event_types.push(event_type);
                                                                                }
                                                                            }
                                                                        } else {
                                                                            draft.event_types.retain(|candidate| candidate.as_str() != code);
                                                                        }
                                                                    });
                                                                    set_draft_error.set(None);
                                                                    set_submit_state.set(CenterOperationSubmitState::Idle);
                                                                }
                                                            />
                                                            <span>{label}</span>
                                                        </label>
                                                    }
                                                })
                                                .collect_view()}
                                        </div>
                                    </div>
                                    <div class="form-row" hidden=move || {
                                        !matches!(draft.get().event_action, Some(EventActionView::DeleteSubscription))
                                    }>
                                        <label for="center-op-subscription-id">"Subscription id"</label>
                                        <input
                                            id="center-op-subscription-id"
                                            type="text"
                                            autocomplete="off"
                                            on:input=move |event| {
                                                set_draft.update(|draft| draft.subscription_id = event_target_value(&event));
                                                set_draft_error.set(None);
                                                set_submit_state.set(CenterOperationSubmitState::Idle);
                                            }
                                        />
                                    </div>
                                }
                                    .into_any()
                            }
                            Some(CommandFamilyView::FirmwareUpdate) => {
                                view! {
                                    <p class="form-hint">
                                        "Firmware updates dispatch from the site console, which holds the artifact."
                                    </p>
                                }
                                    .into_any()
                            }
                            Some(CommandFamilyView::Oem) => {
                                view! {
                                    <p class="form-hint">
                                        "OEM profile files dispatch from the site console, which holds the file."
                                    </p>
                                }
                                    .into_any()
                            }
                            None => view! {}.into_any(),
                        }
                    }}
                    <p class="form-error" hidden=move || draft_error.get().is_none()>
                        {move || draft_error.get().map_or("", |error| error.message())}
                    </p>
                    <div class="inventory-actions">
                        <button
                            type="button"
                            class="btn btn-primary"
                            disabled=move || submit_state.get().is_in_flight()
                            on:click=on_submit
                        >
                            "Dispatch operation"
                        </button>
                        <p class="inline-status success" hidden=move || !matches!(submit_state.get(), CenterOperationSubmitState::Succeeded)>
                            "The operation was dispatched to the site."
                        </p>
                        <p class="form-error" hidden=move || !matches!(submit_state.get(), CenterOperationSubmitState::Failed(_))>
                            {move || match submit_state.get() {
                                CenterOperationSubmitState::Failed(message) => message,
                                _ => String::new(),
                            }}
                        </p>
                    </div>
                </div>
            </section>
        }
    }

    #[component]
    fn CenterBindingsView(view: ReadSignal<ConsoleView>) -> impl IntoView {
        let active = move || view.get() == ConsoleView::CenterBindings;
        let (list_state, set_list_state) = signal(CenterBindingsListState::Idle);
        let (list_triggered, set_list_triggered) = signal(false);
        let (display_name, set_display_name) = signal(String::new());
        let (center_url, set_center_url) = signal(String::new());
        let (name_error, set_name_error) = signal(None::<&'static str>);
        let (register_state, set_register_state) = signal(CenterRegisterState::Idle);
        let (revoke_state, set_revoke_state) = signal(CenterRevokeState::Idle);

        Effect::new(move |_| {
            if active() && !list_triggered.get() {
                set_list_triggered.set(true);
                set_list_state.set(CenterBindingsListState::Loading);
                spawn_local(async move {
                    set_list_state.set(match fetch_center_sites().await {
                        CenterSitesListState::Ready(sites) => CenterBindingsListState::Ready(sites),
                        _ => CenterBindingsListState::Failed,
                    });
                });
            }
        });

        let reload_list = move || {
            set_list_state.set(CenterBindingsListState::Loading);
            spawn_local(async move {
                set_list_state.set(match fetch_center_sites().await {
                    CenterSitesListState::Ready(sites) => CenterBindingsListState::Ready(sites),
                    _ => CenterBindingsListState::Failed,
                });
            });
        };

        let on_name_input = move |event| {
            set_display_name.set(event_target_value(&event));
            set_name_error.set(None);
            set_register_state.set(CenterRegisterState::Idle);
        };
        let on_url_input = move |event| {
            set_center_url.set(event_target_value(&event));
            set_name_error.set(None);
            set_register_state.set(CenterRegisterState::Idle);
        };

        let on_register = move |_| {
            let name = display_name.get();
            if name.trim().is_empty() {
                set_name_error.set(Some("A site display name is required."));
                return;
            }
            let url = center_url.get();
            if url.trim().is_empty() {
                set_name_error.set(Some("The center URL is required."));
                return;
            }
            set_name_error.set(None);
            set_register_state.set(CenterRegisterState::InFlight);
            spawn_local(async move {
                match register_center_site(name.trim(), url.trim()).await {
                    Ok(code) => {
                        // The one-time code is shown exactly once, here; a
                        // later refresh of the view never repeats it.
                        set_register_state.set(CenterRegisterState::Issued(code));
                        set_display_name.set(String::new());
                        set_center_url.set(String::new());
                        reload_list();
                    }
                    Err(message) => {
                        set_name_error.set(Some(message));
                        set_register_state.set(CenterRegisterState::Failed);
                    }
                }
            });
        };

        let on_revoke = Callback::new(move |site_id: String| {
            set_revoke_state.set(CenterRevokeState::InFlight);
            spawn_local(async move {
                let succeeded = revoke_center_binding(&site_id).await;
                set_revoke_state.set(if succeeded {
                    CenterRevokeState::Succeeded
                } else {
                    CenterRevokeState::Failed
                });
                reload_list();
            });
        });

        view! {
            <section class="view-section" hidden=move || !active()>
                <div class="inventory-heading">
                    <div>
                        <p class="section-label">"Center connection"</p>
                        <h2>"Bindings"</h2>
                    </div>
                    <p>"Register a site and hand its one-time code to the site operator (design D2)."</p>
                </div>
                <div class="form-panel">
                    <p class="section-label">"Register a site"</p>
                    <div class="form-row">
                        <label for="center-bind-name">"Display name"</label>
                        <input
                            id="center-bind-name"
                            type="text"
                            autocomplete="off"
                            placeholder="Rack 7 site"
                            prop:value=move || display_name.get()
                            on:input=on_name_input
                        />
                    </div>
                    <div class="form-row">
                        <label for="center-bind-url">"Center URL the site connects to"</label>
                        <input
                            id="center-bind-url"
                            type="text"
                            autocomplete="off"
                            placeholder="center.example:8443"
                            prop:value=move || center_url.get()
                            on:input=on_url_input
                        />
                    </div>
                    <p class="form-error" hidden=move || name_error.get().is_none()>
                        {move || name_error.get().unwrap_or("")}
                    </p>
                    <div class="inventory-actions">
                        <button
                            type="button"
                            class="btn btn-primary"
                            disabled=move || matches!(register_state.get(), CenterRegisterState::InFlight)
                            on:click=on_register
                        >
                            "Register site"
                        </button>
                    </div>
                </div>
                <div
                    class="form-panel result-panel"
                    hidden=move || !matches!(register_state.get(), CenterRegisterState::Issued(_))
                >
                    <p class="section-label">"One-time binding code"</p>
                    <p class="form-hint">
                        "This code is shown exactly once. Hand it to the site operator; it expires at the shown time."
                    </p>
                    {move || {
                        let CenterRegisterState::Issued(code) = register_state.get() else {
                            return Vec::new();
                        };
                        let binding_code = code.code.clone();
                        let code_meta = format!(
                            "Site {} · binding {} · expires {}",
                            code.site_id,
                            code.binding_id,
                            format_observed_at(&code.expires_at)
                        );
                        [view! {
                            <p class="binding-code">{binding_code}</p>
                            <p class="endpoint-address">{code_meta}</p>
                        }]
                        .into_iter()
                        .collect_view()
                    }}
                </div>
                <div class="form-panel">
                    <p class="section-label">"Active bindings"</p>
                    <p class="inline-status" hidden=move || !matches!(list_state.get(), CenterBindingsListState::Loading)>
                        "Loading bindings..."
                    </p>
                    <p class="form-error" hidden=move || !list_state.get().is_failed()>
                        "The binding list is temporarily unavailable."
                    </p>
                    <p
                        class="empty-inventory"
                        hidden=move || {
                            !list_state.get().is_ready() || !matches!(list_state.get(), CenterBindingsListState::Ready(ref rows) if rows.is_empty())
                        }
                    >
                        "No sites are registered yet."
                    </p>
                    <div hidden=move || !list_state.get().is_ready()>
                        {move || {
                            let CenterBindingsListState::Ready(sites) = list_state.get()
                            else {
                                return Vec::new();
                            };
                            sites
                                .into_iter()
                                .map(|site| {
                                    let site_id = site.site_id.clone();
                                    let binding_label = site.binding.map(|binding| binding.label().to_owned());
                                    let online = site.online;
                                    let revocable = matches!(site.binding, Some(CenterBindingStateView::Bound | CenterBindingStateView::Pending));
                                    view! {
                                        <div class="auth-table-row">
                                            <span class="auth-table-name">{site.display_name}</span>
                                            <span class="auth-table-time">
                                                {move || binding_label.clone().unwrap_or_else(|| "no binding".to_owned())}
                                            </span>
                                            <span class="auth-table-time">
                                                {move || if online { "online" } else { "offline" }}
                                            </span>
                                            <button
                                                type="button"
                                                class="btn"
                                                disabled=!revocable
                                                on:click=move |_| on_revoke.run(site_id.clone())
                                            >
                                                "Revoke"
                                            </button>
                                        </div>
                                    }
                                })
                                .collect_view()
                        }}
                    </div>
                    <p class="inline-status success" hidden=move || !matches!(revoke_state.get(), CenterRevokeState::Succeeded)>
                        "The binding was revoked; the site converges on its next connection."
                    </p>
                    <p class="form-error" hidden=move || !matches!(revoke_state.get(), CenterRevokeState::Failed)>
                        "The revocation was refused; the binding is unchanged."
                    </p>
                </div>
            </section>
        }
    }

    /// The loading state of the §16.1 user administration listing.
    #[derive(Clone, Debug, Eq, PartialEq)]
    enum UsersListState {
        Idle,
        Loading,
        Ready(UserAdminResponse),
        Failed,
    }

    impl UsersListState {
        const fn is_failed(&self) -> bool {
            matches!(self, Self::Failed)
        }
    }

    /// The outcome of one create-user submission.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum CreateUserState {
        Idle,
        InFlight,
        Created,
        Failed,
    }

    /// The loading state of the §16.2 session administration listing.
    #[derive(Clone, Debug, Eq, PartialEq)]
    enum SessionsListState {
        Idle,
        Loading,
        Ready(SessionAdminResponse),
        Failed,
    }

    impl SessionsListState {
        const fn is_failed(&self) -> bool {
            matches!(self, Self::Failed)
        }
    }

    #[wasm_bindgen(start)]
    pub fn start() {
        mount_to_body(|| view! { <ProductShell /> });
    }

    #[component]
    fn ProductShell() -> impl IntoView {
        // The serving posture decides the console surface (audit follow-up
        // F2/S8): the center console renders the center views, the edge
        // consoles the local-management views. The scope probe runs at
        // mount and again after every fresh sign-in.
        let (console_scope, set_console_scope) = signal(ConsoleScopeView::Checking);
        // The console data loads once at mount; the auth screen decides
        // when it is shown and reloads it after a fresh sign-in.
        let (state, set_state) = signal(ConsoleLoadState::Loading);
        spawn_local(async move {
            let scope = probe_console_scope().await;
            set_console_scope.set(scope);
            if scope == ConsoleScopeView::Edge {
                set_state.set(fetch_console().await);
            }
        });

        // The §16.2 first-screen decision: `me` answers whether the client
        // is signed in, whether the first-run bootstrap claim is pending,
        // and which role the signed-in principal holds. The console content
        // renders only in the Console screen.
        let (auth_screen, set_auth_screen) = signal(AuthScreen::Loading);
        let (auth_principal, set_auth_principal) =
            signal(None::<rutilus_api::PrincipalSummaryResponse>);
        let decide_auth_screen = move |_| {
            spawn_local(async move {
                match fetch_me().await {
                    Some(me) if me.authenticated() => {
                        set_auth_principal.set(me.principal().cloned());
                        set_auth_screen.set(AuthScreen::Console);
                        // A fresh session must load fresh console data: the
                        // earlier attempts were refused without one. The
                        // scope probe runs first, so the center console
                        // never fetches the edge inventory (audit follow-up
                        // F2 — those routes do not exist on the center).
                        set_state.set(ConsoleLoadState::Loading);
                        set_console_scope.set(ConsoleScopeView::Checking);
                        spawn_local(async move {
                            let scope = probe_console_scope().await;
                            set_console_scope.set(scope);
                            if scope == ConsoleScopeView::Edge {
                                set_state.set(ConsoleLoadState::Loading);
                                spawn_local(async move {
                                    set_state.set(fetch_console().await);
                                });
                            }
                        });
                    }
                    Some(me) if me.bootstrap_pending() => {
                        set_auth_principal.set(None);
                        set_auth_screen.set(AuthScreen::Bootstrap);
                    }
                    _ => {
                        set_auth_principal.set(None);
                        set_auth_screen.set(AuthScreen::Login);
                    }
                }
            });
        };
        decide_auth_screen(());
        let on_auth_success = Callback::new(decide_auth_screen);
        // A 401 anywhere in the console returns the client to the sign-in
        // screen (§16.2 session enforcement).
        Effect::new(move |_| {
            if session_expired_signal().get() {
                session_expired_signal().set(false);
                set_auth_screen.set(AuthScreen::Login);
            }
        });
        let on_logout = move |_| {
            spawn_local(async move {
                if post_logout().await {
                    set_csrf_token(String::new());
                }
                session_expired_signal().set(false);
                decide_auth_screen(());
            });
        };

        let (view, set_view) = signal(ConsoleView::Overview);

        // The capability drill-down keeps its target and matrix state at the
        // shell level so the endpoint-card entry can reset them; the view
        // itself only reads and refreshes them.
        let (capability_target, set_capability_target) = signal(None::<CapabilityTargetProjection>);
        let (capability_state, set_capability_state) = signal(CapabilityMatrixState::Idle);
        let (capability_triggered, set_capability_triggered) = signal(false);

        // The §12.4 diagnostics drill-down mirrors the capability pattern:
        // target and state live at the shell level so the resource-card
        // entry can reset them, and the view itself only reads and refreshes.
        let (diagnostics_target, set_diagnostics_target) =
            signal(None::<DiagnosticsTargetProjection>);
        let (diagnostics_state, set_diagnostics_state) = signal(DiagnosticsState::Idle);
        let (diagnostics_triggered, set_diagnostics_triggered) = signal(false);

        let on_view_capabilities = Callback::new(move |target: CapabilityTargetProjection| {
            set_capability_target.set(Some(target));
            set_capability_state.set(CapabilityMatrixState::Idle);
            set_capability_triggered.set(false);
            set_view.set(ConsoleView::Capabilities);
        });

        let on_open_diagnostics = Callback::new(move |target: DiagnosticsTargetProjection| {
            set_diagnostics_target.set(Some(target));
            set_diagnostics_state.set(DiagnosticsState::Idle);
            set_diagnostics_triggered.set(false);
            set_view.set(ConsoleView::Diagnostics);
        });

        let on_back_to_overview = Callback::new(move |()| {
            set_capability_target.set(None);
            set_capability_state.set(CapabilityMatrixState::Idle);
            set_capability_triggered.set(false);
            // Leaving either drill-down clears both targets so the hidden
            // navigation entries re-hide once the overview is active again.
            set_diagnostics_target.set(None);
            set_diagnostics_state.set(DiagnosticsState::Idle);
            set_diagnostics_triggered.set(false);
            set_view.set(ConsoleView::Overview);
        });

        // The §14.2 filter bar state lives at the shell level because the
        // Overview section renders here. Every dimension is an optional
        // AND-constraint (an empty selection does not constrain), and the
        // chips of the tag dimension come from the shared tag inventory.
        let (filter_search, set_filter_search) = signal(String::new());
        let (filter_tags, set_filter_tags) = signal(BTreeSet::<String>::new());
        let (filter_vendors, set_filter_vendors) = signal(BTreeSet::<String>::new());
        let (filter_health, set_filter_health) = signal(BTreeSet::<HealthLevel>::new());
        // The tag inventory feeds both the filter choices and the per-endpoint
        // membership checks; it is fetched once the inventory is ready and
        // again on every inventory refresh, because the Groups view can
        // change tags independently of endpoint data.
        let (tags_state, set_tags_state) = signal(TagsListState::Idle);
        let (tags_triggered, set_tags_triggered) = signal(false);

        // The §14.2 refresh-selection state lives at the shell level because
        // the Overview section renders here: the selection is the set of
        // endpoint ids whose cards are checked, and the batch report belongs
        // to the same inventory view that launched it.
        let (selected_endpoint_ids, set_selected_endpoint_ids) = signal(BTreeSet::<String>::new());
        let (refresh_state, set_refresh_state) = signal(RefreshBatchState::Idle);

        Effect::new(move |_| {
            if state.with(ConsoleLoadState::is_ready) && !tags_triggered.get() {
                set_tags_triggered.set(true);
                set_tags_state.set(TagsListState::Loading);
                spawn_local(async move {
                    set_tags_state.set(fetch_tags().await);
                });
            }
        });

        let on_refresh_inventory = move |_| {
            set_state.set(ConsoleLoadState::Loading);
            spawn_local(async move {
                set_state.set(fetch_console().await);
            });
            // Re-arming the trigger lets the ready-effect above fetch the tag
            // inventory once the refreshed console data lands.
            set_tags_triggered.set(false);
            set_tags_state.set(TagsListState::Loading);
        };

        let on_search_input = move |event| {
            set_filter_search.set(event_target_value(&event));
        };

        let on_toggle_tag = move |tag: String| {
            set_filter_tags.update(|set| toggle_set_membership(set, tag));
        };

        let on_toggle_vendor = move |vendor: String| {
            set_filter_vendors.update(|set| toggle_set_membership(set, vendor));
        };

        let on_toggle_health = move |level: HealthLevel| {
            set_filter_health.update(|set| toggle_set_membership(set, level));
        };

        let on_clear_filters = move |_| {
            set_filter_search.set(String::new());
            set_filter_tags.set(BTreeSet::new());
            set_filter_vendors.set(BTreeSet::new());
            set_filter_health.set(BTreeSet::new());
        };

        let on_toggle_selection = Callback::new(move |endpoint_id: String| {
            set_selected_endpoint_ids.update(|set| toggle_set_membership(set, endpoint_id));
        });

        let on_refresh_selected = move |_| {
            let selected: Vec<String> = selected_endpoint_ids.get().into_iter().collect();
            if selected.is_empty() {
                return;
            }
            let ConsoleLoadState::Ready(data) = state.get() else {
                return;
            };
            let inventory = data.inventory;
            set_refresh_state.set(RefreshBatchState::InFlight);
            spawn_local(async move {
                match post_endpoint_refresh(&selected, &inventory).await {
                    Ok(report) => {
                        set_refresh_state.set(RefreshBatchState::Ready(report));
                        set_selected_endpoint_ids.set(BTreeSet::new());
                        // The refreshed Generations changed what the cards
                        // render, so the console reloads exactly like a
                        // manual "Refresh inventory" click.
                        set_state.set(ConsoleLoadState::Loading);
                        spawn_local(async move {
                            set_state.set(fetch_console().await);
                        });
                        set_tags_triggered.set(false);
                        set_tags_state.set(TagsListState::Loading);
                    }
                    Err(failure) => {
                        set_refresh_state.set(RefreshBatchState::Failed(failure));
                    }
                }
            });
        };

        let filters_active = move || {
            !OverviewFilterSelections {
                search: filter_search.get(),
                tags: filter_tags.get(),
                vendors: filter_vendors.get(),
                health: filter_health.get(),
            }
            .is_empty()
        };

        // The §14.2 client-side filter pass: the inventory response already
        // carries every managed endpoint, so the four dimensions apply to the
        // loaded cards without another server round-trip.
        let filtered_endpoint_cards = move || {
            let cards = state.with(ConsoleLoadState::endpoint_cards);
            let tags = tags_state.get().inventory().cloned().unwrap_or_default();
            let selections = OverviewFilterSelections {
                search: filter_search.get(),
                tags: filter_tags.get(),
                vendors: filter_vendors.get(),
                health: filter_health.get(),
            };
            apply_overview_filters(&cards, &tags, &selections)
        };

        let filter_summary_text = move || {
            let shown = filtered_endpoint_cards().len();
            let total = state.with(ConsoleLoadState::endpoint_cards).len();
            match shown {
                1 => format!("1 of {total} endpoints shown"),
                _ => format!("{shown} of {total} endpoints shown"),
            }
        };

        let has_filtered_empty_result = move || {
            !state.with(ConsoleLoadState::has_empty_inventory)
                && filters_active()
                && filtered_endpoint_cards().is_empty()
        };

        let console_active = move || auth_screen.get() == AuthScreen::Console;
        let auth_screen_view = move || match auth_screen.get() {
            AuthScreen::Loading => view! {
                <section class="auth-screen" aria-label="Loading">
                    <div class="auth-card">
                        <p class="eyebrow">"Local Redfish management"</p>
                        <p class="auth-note">"Checking…"</p>
                    </div>
                </section>
            }
            .into_any(),
            AuthScreen::Bootstrap => {
                view! { <BootstrapView on_success=on_auth_success /> }.into_any()
            }
            AuthScreen::Login => view! { <LoginView on_success=on_auth_success /> }.into_any(),
            AuthScreen::Console => view! {}.into_any(),
        };

        view! {
            <main id="app" aria-live="polite">
                {auth_screen_view}
                <header class="product-header" hidden=move || !console_active()>
                    <div>
                        <p class="eyebrow">"Local Redfish management"</p>
                        <h1>"Rutilus"</h1>
                        <p id="status">{move || match console_scope.get() {
                            ConsoleScopeView::Center => "Center aggregation console",
                            _ => state.with(ConsoleLoadState::status_message),
                        }}</p>
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
                    <button
                        type="button"
                        class="btn"
                        hidden=move || !console_active()
                        on:click=on_logout
                    >
                        "Sign out"
                    </button>
                </header>

                <nav class="view-nav" aria-label="Console sections" hidden=move || !console_active()>
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
                            // The capability and diagnostics drill-downs need
                            // an endpoint (and, for diagnostics, a resource)
                            // chosen from a card first, so their navigation
                            // entries stay hidden until a target is selected.
                            // The user and session administration entries are
                            // §16.1 Administrator only. The center views
                            // render only on the Center console and the edge
                            // views only on the Edge consoles (audit
                            // follow-up F2/S8), and the navigation stays
                            // hidden while the scope probe runs.
                            let hidden = move || {
                                console_scope.get() == ConsoleScopeView::Checking
                                    || candidate.is_center_view()
                                        != (console_scope.get() == ConsoleScopeView::Center)
                                    || (candidate == ConsoleView::Capabilities
                                        && capability_target.get().is_none())
                                    || (candidate == ConsoleView::Diagnostics
                                        && diagnostics_target.get().is_none())
                                    || !candidate.allowed_for(
                                        auth_principal
                                            .get()
                                            .as_ref()
                                            .and_then(|principal| principal.role())
                                            .map(RoleView::from_wire),
                                    )
                            };
                            view! {
                                <button
                                    type="button"
                                    class=class
                                    hidden=hidden
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
                            class="btn btn-primary"
                            disabled=move || {
                                state.with(ConsoleLoadState::is_loading)
                                    || refresh_state.get().is_in_flight()
                                    || selected_endpoint_ids.get().is_empty()
                            }
                            on:click=on_refresh_selected
                        >
                            "Refresh selected"
                        </button>
                        <button
                            type="button"
                            class="btn"
                            disabled=move || state.with(ConsoleLoadState::is_loading)
                            on:click=on_refresh_inventory
                        >
                            "Refresh inventory"
                        </button>
                        <p
                            class="form-hint"
                            hidden=move || selected_endpoint_ids.get().is_empty()
                        >
                            {move || {
                                let count = selected_endpoint_ids.get().len();
                                match count {
                                    1 => "1 endpoint selected".to_owned(),
                                    _ => format!("{count} endpoints selected"),
                                }
                            }}
                        </p>
                    </div>
                    <div class="overview-filter-bar">
                        <div class="filter-field filter-field-search">
                            <label for="overview-search">"Search"</label>
                            <input
                                id="overview-search"
                                class="filter-search"
                                type="search"
                                autocomplete="off"
                                placeholder="Name or address"
                                prop:value=move || filter_search.get()
                                on:input=on_search_input
                            />
                        </div>
                        <div class="filter-field">
                            <span class="filter-field-label">"Tags"</span>
                            <div class="filter-chip-list">
                                {move || {
                                    tags_state
                                        .get()
                                        .tag_names()
                                        .into_iter()
                                        .map(|tag| {
                                            let tag_for_check = tag.clone();
                                            let tag_for_toggle = tag.clone();
                                            view! {
                                                <label class="filter-chip">
                                                    <input
                                                        type="checkbox"
                                                        prop:checked=move || {
                                                            filter_tags.get().contains(&tag_for_check)
                                                        }
                                                        on:change=move |_| {
                                                            on_toggle_tag(tag_for_toggle.clone());
                                                        }
                                                    />
                                                    <span>{tag}</span>
                                                </label>
                                            }
                                        })
                                        .collect_view()
                                }}
                            </div>
                            <p
                                class="form-hint"
                                hidden=move || !tags_state.get().is_failed()
                            >
                                "The tag list is temporarily unavailable."
                            </p>
                        </div>
                        <div class="filter-field">
                            <span class="filter-field-label">"Vendor"</span>
                            <div class="filter-chip-list">
                                {move || {
                                    let cards = state.with(ConsoleLoadState::endpoint_cards);
                                    vendor_choices(&cards)
                                        .into_iter()
                                        .map(|vendor| {
                                            let vendor_for_check = vendor.clone();
                                            let vendor_for_toggle = vendor.clone();
                                            view! {
                                                <label class="filter-chip">
                                                    <input
                                                        type="checkbox"
                                                        prop:checked=move || {
                                                            filter_vendors.get().contains(&vendor_for_check)
                                                        }
                                                        on:change=move |_| {
                                                            on_toggle_vendor(vendor_for_toggle.clone());
                                                        }
                                                    />
                                                    <span>{vendor}</span>
                                                </label>
                                            }
                                        })
                                        .collect_view()
                                }}
                            </div>
                        </div>
                        <div class="filter-field">
                            <span class="filter-field-label">"Health"</span>
                            <div class="filter-chip-list">
                                {move || {
                                    let cards = state.with(ConsoleLoadState::endpoint_cards);
                                    health_choices(&cards)
                                        .into_iter()
                                        .map(|level| {
                                            let level_for_check = level;
                                            let level_for_toggle = level;
                                            view! {
                                                <label class="filter-chip">
                                                    <input
                                                        type="checkbox"
                                                        prop:checked=move || {
                                                            filter_health.get().contains(&level_for_check)
                                                        }
                                                        on:change=move |_| {
                                                            on_toggle_health(level_for_toggle);
                                                        }
                                                    />
                                                    <span>{health_level_label(level)}</span>
                                                </label>
                                            }
                                        })
                                        .collect_view()
                                }}
                            </div>
                        </div>
                        <div class="filter-field filter-field-actions">
                            <button type="button" class="btn" on:click=on_clear_filters>
                                "Clear filters"
                            </button>
                        </div>
                    </div>
                    <p class="filter-summary" hidden=move || !filters_active()>
                        {move || filter_summary_text()}
                    </p>
                    <p
                        class="empty-inventory"
                        hidden=move || !state.with(ConsoleLoadState::has_empty_inventory)
                    >
                        "No endpoints are managed yet. Add a trusted BMC endpoint to begin."
                    </p>
                    <p class="empty-inventory" hidden=move || !has_filtered_empty_result()>
                        "No endpoints match the current filters."
                    </p>
                    <div class="endpoint-grid">
                        {move || {
                            filtered_endpoint_cards()
                                .into_iter()
                                .map(|card| {
                                    let selected = selected_endpoint_ids
                                        .get()
                                        .contains(&card.endpoint_id);
                                    view! {
                                        <EndpointCard
                                            card=card
                                            selected=selected
                                            on_toggle_selection=on_toggle_selection
                                            on_view_capabilities=on_view_capabilities
                                            on_open_diagnostics=on_open_diagnostics
                                        />
                                    }
                                })
                                .collect_view()
                        }}
                    </div>
                    <div
                        class="form-panel result-panel"
                        hidden=move || !refresh_state.get().is_ready()
                    >
                        <p class="section-label">"Refresh report"</p>
                        <p class="inline-status success">
                            {move || match refresh_state.get() {
                                RefreshBatchState::Ready(report) => report.summary_text(),
                                _ => String::new(),
                            }}
                        </p>
                        <table class="results-table">
                            <thead>
                                <tr>
                                    <th>"Endpoint"</th>
                                    <th>"Result"</th>
                                    <th>"Detail"</th>
                                </tr>
                            </thead>
                            <tbody>
                                {move || {
                                    let RefreshBatchState::Ready(report) = refresh_state.get()
                                    else {
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
                                                    <td class="result-address">
                                                        {row.display_name}
                                                    </td>
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
                        hidden=move || {
                            !matches!(refresh_state.get(), RefreshBatchState::Failed(_))
                        }
                    >
                        {move || match refresh_state.get() {
                            RefreshBatchState::Failed(failure) => failure.message(),
                            _ => String::new(),
                        }}
                    </p>
                </section>

                <CredentialsView view=view />
                <AddEndpointView view=view />
                <ImportView view=view />
                <AuditView view=view />
                <CapabilitiesView
                    view=view
                    target=capability_target
                    state=capability_state
                    set_state=set_capability_state
                    triggered=capability_triggered
                    set_triggered=set_capability_triggered
                    on_back=on_back_to_overview
                />
                <OperationsView view=view load_state=state />
                <EventsView view=view />
                <TelemetryView view=view />
                <ArtifactsView view=view />
                <GroupsView view=view load_state=state />
                <DiagnosticsView
                    view=view
                    target=diagnostics_target
                    state=diagnostics_state
                    set_state=set_diagnostics_state
                    triggered=diagnostics_triggered
                    set_triggered=set_diagnostics_triggered
                    on_back=on_back_to_overview
                />
                <UsersView view=view />
                <SessionsView view=view />
                <CenterSitesView view=view />
                <CenterOperationsView view=view />
                <CenterBindingsView view=view />
            </main>
        }
    }

    #[component]
    fn EndpointCard(
        card: EndpointCardProjection,
        selected: bool,
        on_toggle_selection: Callback<String>,
        on_view_capabilities: Callback<CapabilityTargetProjection>,
        on_open_diagnostics: Callback<DiagnosticsTargetProjection>,
    ) -> impl IntoView {
        let endpoint_id_for_selection = card.endpoint_id.clone();
        let systems = card.resource_counts.map_or(0, |counts| counts.systems);
        let chassis = card.resource_counts.map_or(0, |counts| counts.chassis);
        let managers = card.resource_counts.map_or(0, |counts| counts.managers);
        let awaiting_refresh = card.resource_counts.is_none();
        let status_dot_class = if awaiting_refresh {
            "status-dot status-dot-waiting"
        } else {
            "status-dot"
        };
        // The §12.3 health badge shows the vendor's raw text with the unified
        // level's styling; no raw text means no health observed yet, and the
        // badge stays hidden instead of rendering a placeholder.
        let health_badge_class = health_badge_class(card.health_level);
        let health_badge_hidden = card.health_label.is_none();
        let health_badge_text = card.health_label.clone();
        let resources = card.resources;
        // The §12.2 OEM section renders either the honest §11.5
        // UnsupportedByNvRedfishBaseline notice or the typed OEM resource
        // cards; the projection pins the switch condition, the component
        // only mirrors it into the two visibility flags.
        let oem_supported = card.oem_section.is_supported();
        let oem_cards = card.oem_section.cards();
        let capability_target = CapabilityTargetProjection {
            endpoint_id: card.endpoint_id.clone(),
            display_name: card.display_name.clone(),
            address: card.address.clone(),
        };

        view! {
            <article class="endpoint-card">
                <div class="endpoint-title">
                    <div>
                        <h3>{card.display_name}</h3>
                        <p class="endpoint-address">{card.address}</p>
                    </div>
                    <span
                        class=health_badge_class
                        hidden=health_badge_hidden
                        title="Unified endpoint health"
                    >
                        {health_badge_text.unwrap_or_default()}
                    </span>
                    <span class="trust-badge">{card.trust_label}</span>
                </div>
                <div class="snapshot-heading">
                    <span class=status_dot_class aria-hidden="true"></span>
                    <span>{card.snapshot_label}</span>
                </div>
                <div class="endpoint-card-actions">
                    <label class="endpoint-select">
                        <input
                            type="checkbox"
                            aria-label="Select this endpoint for refresh"
                            prop:checked=selected
                            on:change=move |_| {
                                on_toggle_selection.run(endpoint_id_for_selection.clone());
                            }
                        />
                        <span>"Refresh"</span>
                    </label>
                    <button
                        type="button"
                        class="btn"
                        on:click=move |_| on_view_capabilities.run(capability_target.clone())
                    >
                        "View capabilities"
                    </button>
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
                            .map(|resource| {
                                view! {
                                    <CoreResourceCard
                                        resource=resource
                                        on_open_diagnostics=on_open_diagnostics
                                    />
                                }
                            })
                            .collect_view()}
                    </div>
                </section>
                <section class="oem-section" hidden=awaiting_refresh>
                    <div class="core-resources-heading">
                        <h4>"OEM"</h4>
                    </div>
                    <p class="oem-unsupported" hidden=oem_supported>
                        {OEM_UNSUPPORTED_NOTICE}
                    </p>
                    <div class="core-resource-grid" hidden=!oem_supported>
                        {oem_cards
                            .into_iter()
                            .map(|resource| {
                                view! {
                                    <CoreResourceCard
                                        resource=resource
                                        on_open_diagnostics=on_open_diagnostics
                                    />
                                }
                            })
                            .collect_view()}
                    </div>
                </section>
            </article>
        }
    }

    #[component]
    fn CoreResourceCard(
        resource: CoreResourceCardProjection,
        on_open_diagnostics: Callback<DiagnosticsTargetProjection>,
    ) -> impl IntoView {
        let CoreResourceCardProjection {
            type_label,
            name,
            description,
            source,
            facts,
            endpoint_id,
            resource_id,
        } = resource;
        let has_description = description.is_some();
        let description = description.unwrap_or_default();
        let source_title = source.clone();
        // The §12.4 entry opens exactly this card's resource: the ids are the
        // two route parameters, captured from the projection at render time.
        let diagnostics_target = DiagnosticsTargetProjection {
            endpoint_id,
            resource_id,
            name: name.clone(),
            source: source.clone(),
        };

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
                <div class="core-resource-actions">
                    <button
                        type="button"
                        class="btn"
                        on:click=move |_| on_open_diagnostics.run(diagnostics_target.clone())
                    >
                        "Diagnostics"
                    </button>
                </div>
            </article>
        }
    }

    #[component]
    fn GroupsView(
        view: ReadSignal<ConsoleView>,
        load_state: ReadSignal<ConsoleLoadState>,
    ) -> impl IntoView {
        let active = move || view.get() == ConsoleView::Groups;
        let (list_state, set_list_state) = signal(GroupsListState::Idle);
        let (list_triggered, set_list_triggered) = signal(false);
        let (selected_group, set_selected_group) = signal(None::<String>);
        let (detail_state, set_detail_state) = signal(GroupDetailState::Idle);
        let (group_draft, set_group_draft) = signal(GroupDraft::new());
        let (group_draft_error, set_group_draft_error) = signal(None::<GroupNameDraftError>);
        let (create_state, set_create_state) = signal(GroupCreateState::Idle);
        let (selected_members, set_selected_members) = signal(BTreeSet::<String>::new());
        let (member_action, set_member_action) = signal(GroupMemberActionState::Idle);
        let (tags_state, set_tags_state) = signal(TagsListState::Idle);
        let (tags_triggered, set_tags_triggered) = signal(false);
        let (tag_draft, set_tag_draft) = signal(TagDraft::new());
        let (tag_error, set_tag_error) = signal(None::<TagDraftError>);
        let (tag_action, set_tag_action) = signal(TagApplyState::Idle);

        Effect::new(move |_| {
            if active() && !list_triggered.get() {
                set_list_triggered.set(true);
                set_list_state.set(GroupsListState::Loading);
                spawn_local(async move {
                    set_list_state.set(fetch_groups().await);
                });
            }
        });

        Effect::new(move |_| {
            if active() && !tags_triggered.get() {
                set_tags_triggered.set(true);
                set_tags_state.set(TagsListState::Loading);
                spawn_local(async move {
                    set_tags_state.set(fetch_tags().await);
                });
            }
        });

        // Selecting a group fetches its detail; clearing the selection leaves
        // the stale detail behind until the next selection, which is safe
        // because the detail panel is hidden while no group is selected.
        Effect::new(move |_| {
            if let Some(group_id) = selected_group.get() {
                set_detail_state.set(GroupDetailState::Loading);
                let load = load_state.get();
                spawn_local(async move {
                    set_detail_state.set(fetch_group_detail(&group_id, load).await);
                });
            }
        });

        let on_group_name_input = move |event| {
            let value = event_target_value(&event);
            set_group_draft.update(|draft| draft.name.clone_from(&value));
            set_group_draft_error.set(group_name_draft_error(&value).err());
            set_create_state.set(GroupCreateState::Idle);
        };

        let on_create_group = move |_| {
            let draft = group_draft.get();
            if let Err(error) = draft.validate() {
                set_group_draft_error.set(Some(error));
                return;
            }
            set_group_draft_error.set(None);
            set_create_state.set(GroupCreateState::InFlight);
            let name = draft.name.trim().to_owned();
            spawn_local(async move {
                if create_group(&name).await {
                    set_create_state.set(GroupCreateState::Created);
                    set_group_draft.set(GroupDraft::new());
                    set_group_draft_error.set(None);
                    set_list_state.set(GroupsListState::Loading);
                    set_list_state.set(fetch_groups().await);
                } else {
                    set_create_state.set(GroupCreateState::Failed(
                        "The group could not be created.".to_owned(),
                    ));
                }
            });
        };

        let on_open_group = Callback::new(move |group_id: String| {
            set_selected_members.set(BTreeSet::new());
            set_member_action.set(GroupMemberActionState::Idle);
            set_selected_group.set(Some(group_id));
        });

        let on_back_to_list = Callback::new(move |()| {
            set_selected_group.set(None);
            set_detail_state.set(GroupDetailState::Idle);
            set_selected_members.set(BTreeSet::new());
            set_member_action.set(GroupMemberActionState::Idle);
        });

        let on_delete_group = Callback::new(move |group_id: String| {
            spawn_local(async move {
                if delete_group(&group_id).await {
                    // Deleting the group that is currently open returns the
                    // operator to the list instead of leaving a stale detail.
                    if selected_group.get().as_deref() == Some(group_id.as_str()) {
                        set_selected_group.set(None);
                        set_detail_state.set(GroupDetailState::Idle);
                    }
                    set_list_state.set(GroupsListState::Loading);
                    set_list_state.set(fetch_groups().await);
                }
            });
        });

        let on_refresh = move |_| {
            set_list_state.set(GroupsListState::Loading);
            spawn_local(async move {
                set_list_state.set(fetch_groups().await);
            });
            set_tags_state.set(TagsListState::Loading);
            spawn_local(async move {
                set_tags_state.set(fetch_tags().await);
            });
        };

        let on_toggle_member = Callback::new(move |endpoint_id: String| {
            set_selected_members.update(|set| toggle_set_membership(set, endpoint_id));
            set_member_action.set(GroupMemberActionState::Idle);
        });

        let on_add_members = Callback::new(move |()| {
            let Some(group_id) = selected_group.get() else {
                return;
            };
            let members = selected_members.get();
            if members.is_empty() {
                return;
            }
            set_member_action.set(GroupMemberActionState::InFlight);
            spawn_local(async move {
                // The adds are sequential, mirroring the per-endpoint member
                // route; a partial failure still refetches the detail so the
                // member list reflects exactly which adds succeeded.
                let mut all_added = true;
                for endpoint_id in members {
                    all_added = all_added && put_group_member(&group_id, &endpoint_id).await;
                }
                set_member_action.set(if all_added {
                    GroupMemberActionState::Succeeded
                } else {
                    GroupMemberActionState::Failed(
                        "One or more endpoints could not be added to the group.".to_owned(),
                    )
                });
                set_selected_members.set(BTreeSet::new());
                let load = load_state.get();
                set_detail_state.set(GroupDetailState::Loading);
                set_detail_state.set(fetch_group_detail(&group_id, load).await);
                set_list_state.set(GroupsListState::Loading);
                set_list_state.set(fetch_groups().await);
            });
        });

        let on_remove_member = Callback::new(move |endpoint_id: String| {
            let Some(group_id) = selected_group.get() else {
                return;
            };
            set_member_action.set(GroupMemberActionState::InFlight);
            let load = load_state.get();
            spawn_local(async move {
                set_member_action.set(if delete_group_member(&group_id, &endpoint_id).await {
                    GroupMemberActionState::Succeeded
                } else {
                    GroupMemberActionState::Failed(
                        "The member could not be removed from the group.".to_owned(),
                    )
                });
                set_detail_state.set(GroupDetailState::Loading);
                set_detail_state.set(fetch_group_detail(&group_id, load).await);
                set_list_state.set(GroupsListState::Loading);
                set_list_state.set(fetch_groups().await);
            });
        });

        let on_tag_endpoint_change = move |event| {
            let value = event_target_value(&event);
            let endpoint_id = if value.is_empty() { None } else { Some(value) };
            set_tag_draft.update(|draft| draft.endpoint_id = endpoint_id);
            let draft = tag_draft.get();
            set_tag_error.set(tag_draft_error(draft.endpoint_id.as_deref(), &draft.name).err());
            set_tag_action.set(TagApplyState::Idle);
        };

        let on_tag_name_input = move |event| {
            let value = event_target_value(&event);
            set_tag_draft.update(|draft| draft.name.clone_from(&value));
            let draft = tag_draft.get();
            set_tag_error.set(tag_draft_error(draft.endpoint_id.as_deref(), &value).err());
            set_tag_action.set(TagApplyState::Idle);
        };

        let on_apply_tag = Callback::new(move |()| {
            let draft = tag_draft.get();
            if let Err(error) = draft.validate() {
                set_tag_error.set(Some(error));
                return;
            }
            set_tag_error.set(None);
            set_tag_action.set(TagApplyState::InFlight);
            let Some(endpoint_id) = draft.endpoint_id.clone() else {
                return;
            };
            let name = draft.name.trim().to_owned();
            let load = load_state.get();
            spawn_local(async move {
                if put_endpoint_tag(&endpoint_id, &name, &load).await {
                    set_tag_action.set(TagApplyState::Applied);
                    set_tag_draft.set(TagDraft::new());
                    set_tag_error.set(None);
                    set_tags_state.set(TagsListState::Loading);
                    set_tags_state.set(fetch_tags().await);
                } else {
                    set_tag_action.set(TagApplyState::Failed(
                        "The tag could not be applied.".to_owned(),
                    ));
                }
            });
        });

        let on_remove_tag = Callback::new(move |(endpoint_id, name): (String, String)| {
            set_tag_action.set(TagApplyState::InFlight);
            spawn_local(async move {
                set_tag_action.set(if delete_endpoint_tag(&endpoint_id, &name).await {
                    TagApplyState::Applied
                } else {
                    TagApplyState::Failed("The tag could not be removed.".to_owned())
                });
                set_tags_state.set(TagsListState::Loading);
                set_tags_state.set(fetch_tags().await);
            });
        });

        view! {
            <section class="view-section" hidden=move || !active()>
                <div class="inventory-heading">
                    <div>
                        <p class="section-label">"Groups"</p>
                        <h2>{move || list_state.get().count_text()}</h2>
                    </div>
                    <p>"Static groups for organizing managed endpoints"</p>
                </div>
                <div class="inventory-actions">
                    <button
                        type="button"
                        class="btn"
                        disabled=move || list_state.get().is_loading()
                        on:click=on_refresh
                    >
                        "Refresh"
                    </button>
                </div>
                <p class="inline-status" hidden=move || !list_state.get().is_loading()>
                    "Loading groups..."
                </p>
                <p class="form-error" hidden=move || !list_state.get().is_failed()>
                    {move || list_state.get().failure_message()}
                </p>
                <div class="group-list" hidden=move || selected_group.get().is_some()>
                    <p
                        class="empty-inventory"
                        hidden=move || {
                            !list_state.get().is_ready() || !list_state.get().has_empty_list()
                        }
                    >
                        "No groups have been created yet. Create a group to organize endpoints."
                    </p>
                    <div class="resource-list">
                        {move || {
                            list_state
                                .get()
                                .group_cards()
                                .into_iter()
                                .map(|card| {
                                    view! {
                                        <GroupCard
                                            card=card
                                            on_open=on_open_group
                                            on_delete=on_delete_group
                                        />
                                    }
                                })
                                .collect_view()
                        }}
                    </div>
                </div>
                <div class="group-detail" hidden=move || selected_group.get().is_none()>
                    <GroupDetailPanel
                        detail_state=detail_state
                        load_state=load_state
                        selected_members=selected_members
                        member_action=member_action
                        on_back=on_back_to_list
                        on_toggle_member=on_toggle_member
                        on_add_members=on_add_members
                        on_remove_member=on_remove_member
                    />
                </div>
                <div class="form-panel">
                    <div class="form-panel-heading">
                        <div>
                            <p class="section-label">"Create group"</p>
                            <p class="form-hint">
                                "A static group collects managed endpoints for the Overview
                                filter and bulk actions."
                            </p>
                        </div>
                    </div>
                    <div class="form-grid">
                        <div class="form-field">
                            <label for="group-name-input">"Group name"</label>
                            <input
                                id="group-name-input"
                                class="form-input"
                                type="text"
                                autocomplete="off"
                                prop:value=move || group_draft.get().name
                                on:input=on_group_name_input
                            />
                            <p
                                class="form-error"
                                hidden=move || group_draft_error.get().is_none()
                            >
                                {move || {
                                    group_draft_error.get().map_or("", GroupNameDraftError::message)
                                }}
                            </p>
                        </div>
                        <div class="form-actions">
                            <button
                                type="button"
                                class="btn btn-primary"
                                disabled=move || {
                                    matches!(create_state.get(), GroupCreateState::InFlight)
                                }
                                on:click=on_create_group
                            >
                                "Create group"
                            </button>
                        </div>
                    </div>
                    <p
                        class="inline-status success"
                        hidden=move || !matches!(create_state.get(), GroupCreateState::Created)
                    >
                        "Group created."
                    </p>
                    <p
                        class="form-error"
                        hidden=move || !matches!(create_state.get(), GroupCreateState::Failed(_))
                    >
                        {move || match create_state.get() {
                            GroupCreateState::Failed(message) => message,
                            GroupCreateState::Idle
                            | GroupCreateState::InFlight
                            | GroupCreateState::Created => String::new(),
                        }}
                    </p>
                </div>
                <div class="form-panel">
                    <div class="form-panel-heading">
                        <div>
                            <p class="section-label">"Tags"</p>
                            <p class="form-hint">
                                "Tags label endpoints for the Overview tag filter."
                            </p>
                        </div>
                    </div>
                    <div class="form-grid">
                        <div class="form-field">
                            <label for="tag-endpoint-select">"Endpoint"</label>
                            <select
                                id="tag-endpoint-select"
                                class="form-input"
                                prop:value=move || {
                                    tag_draft.get().endpoint_id.clone().unwrap_or_default()
                                }
                                on:change=on_tag_endpoint_change
                            >
                                <option value="">"Select an endpoint..."</option>
                                {move || {
                                    let load = load_state.get();
                                    let inventory = match &load {
                                        ConsoleLoadState::Ready(data) => {
                                            data.inventory.endpoints()
                                        }
                                        ConsoleLoadState::Loading
                                        | ConsoleLoadState::Failed(_) => return Vec::new(),
                                    };
                                    inventory
                                        .iter()
                                        .map(|summary| {
                                            let endpoint_id = summary
                                                .identity()
                                                .endpoint_id()
                                                .to_string();
                                            let display_name = summary
                                                .identity()
                                                .display_name()
                                                .to_owned();
                                            view! {
                                                <option value=endpoint_id>{display_name}</option>
                                            }
                                        })
                                        .collect::<Vec<_>>()
                                }}
                            </select>
                        </div>
                        <div class="form-field">
                            <label for="tag-name-input">"Tag name"</label>
                            <input
                                id="tag-name-input"
                                class="form-input"
                                type="text"
                                autocomplete="off"
                                prop:value=move || tag_draft.get().name
                                on:input=on_tag_name_input
                            />
                            <p class="form-error" hidden=move || tag_error.get().is_none()>
                                {move || tag_error.get().map_or("", TagDraftError::message)}
                            </p>
                        </div>
                        <div class="form-actions">
                            <button
                                type="button"
                                class="btn btn-primary"
                                disabled=move || matches!(tag_action.get(), TagApplyState::InFlight)
                                on:click=move |_| on_apply_tag.run(())
                            >
                                "Apply tag"
                            </button>
                        </div>
                    </div>
                    <p
                        class="inline-status success"
                        hidden=move || !matches!(tag_action.get(), TagApplyState::Applied)
                    >
                        "Tag updated."
                    </p>
                    <p
                        class="form-error"
                        hidden=move || !matches!(tag_action.get(), TagApplyState::Failed(_))
                    >
                        {move || match tag_action.get() {
                            TagApplyState::Failed(message) => message,
                            TagApplyState::Idle
                            | TagApplyState::InFlight
                            | TagApplyState::Applied => String::new(),
                        }}
                    </p>
                    <p class="inline-status" hidden=move || !tags_state.get().is_loading()>
                        "Loading tags..."
                    </p>
                    <p class="form-error" hidden=move || !tags_state.get().is_failed()>
                        {move || tags_state.get().failure_message()}
                    </p>
                    <p
                        class="empty-inventory"
                        hidden=move || {
                            !tags_state.get().is_ready() || !tags_state.get().has_empty_tags()
                        }
                    >
                        "No tags have been applied yet."
                    </p>
                    <div class="resource-list">
                        {move || {
                            tags_state
                                .get()
                                .tag_cards()
                                .into_iter()
                                .map(|card| view! { <TagCard card=card on_remove=on_remove_tag /> })
                                .collect_view()
                        }}
                    </div>
                </div>
            </section>
        }
    }

    #[component]
    fn GroupCard(
        card: GroupCardProjection,
        on_open: Callback<String>,
        on_delete: Callback<String>,
    ) -> impl IntoView {
        let members_hidden = card.member_short_ids.is_empty();
        let manage_group_id = card.group_id.clone();
        let delete_group_id = card.group_id.clone();
        view! {
            <article class="credential-card">
                <div class="credential-title">
                    <div>
                        <h3>{card.name}</h3>
                        <p class="credential-username">{card.member_count_text}</p>
                    </div>
                </div>
                <p class="section-label" hidden=members_hidden>"Members"</p>
                <ul class="short-id-list" hidden=members_hidden>
                    {card
                        .member_short_ids
                        .into_iter()
                        .map(|short_id| {
                            view! { <li><code>{short_id}</code></li> }
                        })
                        .collect_view()}
                </ul>
                <div class="endpoint-card-actions">
                    <button
                        type="button"
                        class="btn"
                        on:click=move |_| on_open.run(manage_group_id.clone())
                    >
                        "Manage members"
                    </button>
                    <button
                        type="button"
                        class="btn"
                        on:click=move |_| on_delete.run(delete_group_id.clone())
                    >
                        "Delete"
                    </button>
                </div>
            </article>
        }
    }

    #[component]
    fn GroupDetailPanel(
        detail_state: ReadSignal<GroupDetailState>,
        load_state: ReadSignal<ConsoleLoadState>,
        selected_members: ReadSignal<BTreeSet<String>>,
        member_action: ReadSignal<GroupMemberActionState>,
        on_back: Callback<()>,
        on_toggle_member: Callback<String>,
        on_add_members: Callback<()>,
        on_remove_member: Callback<String>,
    ) -> impl IntoView {
        // The add-choices are the managed endpoints not yet in the group,
        // joined against the inventory the shell already loaded. The load
        // state is bound to a named local so its borrow outlives the match.
        let member_choices = move || {
            let state = detail_state.get();
            let Some(detail) = state.ready_projection() else {
                return Vec::new();
            };
            let load = load_state.get();
            let inventory = match &load {
                ConsoleLoadState::Ready(data) => data.inventory.endpoints(),
                ConsoleLoadState::Loading | ConsoleLoadState::Failed(_) => return Vec::new(),
            };
            group_member_choices(inventory, detail)
        };

        view! {
            <div class="form-panel">
                <div class="group-detail-heading">
                    <div>
                        <p class="section-label">"Group detail"</p>
                        <h3>
                            {move || {
                                let state = detail_state.get();
                                state
                                    .ready_projection()
                                    .map_or_else(|| "Group".to_owned(), |detail| detail.name.clone())
                            }}
                        </h3>
                    </div>
                    <button type="button" class="btn" on:click=move |_| on_back.run(())>
                        "Back to groups"
                    </button>
                </div>
                <p class="inline-status" hidden=move || !detail_state.get().is_loading()>
                    "Loading group detail..."
                </p>
                <p class="form-error" hidden=move || !detail_state.get().is_failed()>
                    {move || detail_state.get().failure_message()}
                </p>
                <p
                    class="empty-inventory"
                    hidden=move || {
                        let state = detail_state.get();
                        let Some(detail) = state.ready_projection() else {
                            return true;
                        };
                        !detail.has_no_members()
                    }
                >
                    "No members yet. Add endpoints below."
                </p>
                <div class="member-list">
                    {move || {
                        let state = detail_state.get();
                        let members = state
                            .ready_projection()
                            .map_or_else(Vec::new, |detail| detail.members.clone());
                        members
                            .into_iter()
                            .map(|member| {
                                let endpoint_id = member.endpoint_id.clone();
                                view! {
                                    <div class="member-row">
                                        <div>
                                            <h4>{member.display_name}</h4>
                                            <p class="endpoint-address">{member.address}</p>
                                            <code class="member-short-id">{member.short_id}</code>
                                        </div>
                                        <button
                                            type="button"
                                            class="btn"
                                            on:click=move |_| {
                                                on_remove_member.run(endpoint_id.clone());
                                            }
                                        >
                                            "Remove"
                                        </button>
                                    </div>
                                }
                            })
                            .collect_view()
                    }}
                </div>
                <p class="section-label">"Add members"</p>
                <div class="member-choice-grid">
                    {move || {
                        let choices = member_choices();
                        if choices.is_empty() {
                            return view! {
                                <p class="form-hint">
                                    "Every managed endpoint is already in this group."
                                </p>
                            }
                            .into_any();
                        }
                        choices
                            .into_iter()
                            .map(|choice| {
                                let endpoint_id_for_check = choice.endpoint_id.clone();
                                let endpoint_id_for_toggle = choice.endpoint_id.clone();
                                view! {
                                    <label class="member-chip">
                                        <input
                                            type="checkbox"
                                            prop:checked=move || {
                                                selected_members
                                                    .get()
                                                    .contains(&endpoint_id_for_check)
                                            }
                                            on:change=move |_| {
                                                on_toggle_member.run(endpoint_id_for_toggle.clone());
                                            }
                                        />
                                        <span>{choice.display_name}</span>
                                        <code>{choice.address}</code>
                                    </label>
                                }
                            })
                            .collect_view()
                            .into_any()
                    }}
                </div>
                <div class="form-actions">
                    <button
                        type="button"
                        class="btn"
                        disabled=move || {
                            selected_members.get().is_empty()
                                || matches!(
                                    member_action.get(),
                                    GroupMemberActionState::InFlight
                                )
                        }
                        on:click=move |_| on_add_members.run(())
                    >
                        "Add selected"
                    </button>
                </div>
                <p
                    class="inline-status success"
                    hidden=move || {
                        !matches!(member_action.get(), GroupMemberActionState::Succeeded)
                    }
                >
                    "Members updated."
                </p>
                <p
                    class="form-error"
                    hidden=move || !matches!(member_action.get(), GroupMemberActionState::Failed(_))
                >
                    {move || match member_action.get() {
                        GroupMemberActionState::Failed(message) => message,
                        GroupMemberActionState::Idle
                        | GroupMemberActionState::InFlight
                        | GroupMemberActionState::Succeeded => String::new(),
                    }}
                </p>
            </div>
        }
    }

    #[component]
    fn TagCard(card: TagCardProjection, on_remove: Callback<(String, String)>) -> impl IntoView {
        let rows_hidden = card.endpoints.is_empty();
        let tag_name = card.name.clone();
        view! {
            <article class="credential-card">
                <div class="credential-title">
                    <div>
                        <h3>{card.name}</h3>
                        <p class="credential-username">{card.endpoint_count_text}</p>
                    </div>
                </div>
                <ul class="tag-endpoint-list" hidden=rows_hidden>
                    {card
                        .endpoints
                        .into_iter()
                        .map(|row| {
                            let target = (row.endpoint_id.clone(), tag_name.clone());
                            view! {
                                <li>
                                    <code class="member-short-id">{row.short_id}</code>
                                    <span>{row.endpoint_id}</span>
                                    <button
                                        type="button"
                                        class="btn"
                                        on:click=move |_| on_remove.run(target.clone())
                                    >
                                        "Untag"
                                    </button>
                                </li>
                            }
                        })
                        .collect_view()}
                </ul>
                <p class="form-hint" hidden=!rows_hidden>
                    "No endpoints carry this tag yet."
                </p>
            </article>
        }
    }

    /// Fetches the §14.2 group inventory from `GET /api/v1/groups`.
    ///
    /// Any transport failure, non-2xx status, or contract violation reports
    /// the unavailable state so the view renders its failure copy.
    async fn fetch_groups() -> GroupsListState {
        let Some(response) = Request::get("/api/v1/groups")
            .header("Accept", "application/json")
            .send()
            .await
            .ok()
        else {
            return GroupsListState::Failed;
        };
        if !response_ok(&response) {
            return GroupsListState::Failed;
        }
        let Some(inventory) = response.json::<GroupListResponse>().await.ok() else {
            return GroupsListState::Failed;
        };
        GroupsListState::Ready(
            inventory
                .groups()
                .iter()
                .map(GroupCardProjection::from)
                .collect(),
        )
    }

    /// Creates one §14.2 group through `POST /api/v1/groups`; `false` means
    /// the submission failed (transport, rejection, or the duplicate-name
    /// 409 verdict).
    async fn create_group(name: &str) -> bool {
        let request = CreateGroupRequest::new(name.to_owned());
        let Some(prepared) = with_csrf(Request::post("/api/v1/groups"))
            .json(&request)
            .ok()
        else {
            return false;
        };
        let Some(response) = prepared.send().await.ok() else {
            return false;
        };
        response.ok()
    }

    /// Fetches one §14.2 group from `GET /api/v1/groups/{group_id}` and
    /// joins its members against the loaded endpoint inventory; a failed or
    /// inventory-less load reports the unavailable state.
    async fn fetch_group_detail(group_id: &str, load_state: ConsoleLoadState) -> GroupDetailState {
        let ConsoleLoadState::Ready(data) = load_state else {
            return GroupDetailState::Failed;
        };
        let path = format!("/api/v1/groups/{group_id}");
        let Some(response) = Request::get(&path)
            .header("Accept", "application/json")
            .send()
            .await
            .ok()
        else {
            return GroupDetailState::Failed;
        };
        if !response_ok(&response) {
            return GroupDetailState::Failed;
        }
        let Some(group) = response.json::<GroupResponse>().await.ok() else {
            return GroupDetailState::Failed;
        };
        GroupDetailState::Ready(GroupDetailProjection::from_response(
            &group,
            data.inventory.endpoints(),
        ))
    }

    /// Deletes one §14.2 group through `DELETE /api/v1/groups/{group_id}`.
    async fn delete_group(group_id: &str) -> bool {
        let path = format!("/api/v1/groups/{group_id}");
        let Some(response) = with_csrf(Request::delete(&path)).send().await.ok() else {
            return false;
        };
        response.ok()
    }

    /// Adds one member to one group through the idempotent
    /// `PUT /api/v1/groups/{group_id}/members/{endpoint_id}`.
    async fn put_group_member(group_id: &str, endpoint_id: &str) -> bool {
        let path = format!("/api/v1/groups/{group_id}/members/{endpoint_id}");
        let Some(response) = with_csrf(Request::put(&path)).send().await.ok() else {
            return false;
        };
        response.ok()
    }

    /// Removes one member from one group through the idempotent
    /// `DELETE /api/v1/groups/{group_id}/members/{endpoint_id}`.
    async fn delete_group_member(group_id: &str, endpoint_id: &str) -> bool {
        let path = format!("/api/v1/groups/{group_id}/members/{endpoint_id}");
        let Some(response) = with_csrf(Request::delete(&path)).send().await.ok() else {
            return false;
        };
        response.ok()
    }

    /// Fetches the §14.2 tag inventory from `GET /api/v1/tags` and groups
    /// the flat binding list by tag name.
    async fn fetch_tags() -> TagsListState {
        let Some(response) = Request::get("/api/v1/tags")
            .header("Accept", "application/json")
            .send()
            .await
            .ok()
        else {
            return TagsListState::Failed;
        };
        if !response_ok(&response) {
            return TagsListState::Failed;
        }
        let Some(list) = response.json::<TagListResponse>().await.ok() else {
            return TagsListState::Failed;
        };
        TagsListState::Ready(TagInventoryView::from(&list))
    }

    /// Binds one tag name to one endpoint through the idempotent
    /// `PUT /api/v1/tags` body route.
    ///
    /// The endpoint id is resolved against the loaded inventory instead of
    /// re-parsed, so the wire request always carries the exact managed
    /// endpoint identity the product persisted.
    async fn put_endpoint_tag(
        endpoint_id: &str,
        tag_name: &str,
        load_state: &ConsoleLoadState,
    ) -> bool {
        let ConsoleLoadState::Ready(data) = load_state else {
            return false;
        };
        let Some(summary) = data
            .inventory
            .endpoints()
            .iter()
            .find(|summary| summary.identity().endpoint_id().to_string() == endpoint_id)
        else {
            return false;
        };
        let request = AssignTagRequest::new(summary.identity().endpoint_id(), tag_name.to_owned());
        let Some(prepared) = with_csrf(Request::put("/api/v1/tags")).json(&request).ok() else {
            return false;
        };
        let Some(response) = prepared.send().await.ok() else {
            return false;
        };
        response.ok()
    }

    /// Removes one tag binding through the idempotent
    /// `DELETE /api/v1/endpoints/{endpoint_id}/tags/{tag_name}`.
    ///
    /// The tag name is percent-encoded because it is a path segment: names
    /// with spaces, slashes, or non-ASCII characters (all valid for the
    /// domain `TagName`) must round-trip exactly through the route.
    async fn delete_endpoint_tag(endpoint_id: &str, tag_name: &str) -> bool {
        let encoded_name = percent_encode_path_segment(tag_name);
        let path = format!("/api/v1/endpoints/{endpoint_id}/tags/{encoded_name}");
        let Some(response) = with_csrf(Request::delete(&path)).send().await.ok() else {
            return false;
        };
        response.ok()
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
        if !response_ok(&response) {
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
        if !response_ok(&response) {
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
            if !response_ok(&response) {
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

    #[component]
    fn EventsView(view: ReadSignal<ConsoleView>) -> impl IntoView {
        let active = move || view.get() == ConsoleView::Events;
        let (state, set_state) = signal(EventsListState::Idle);
        let (triggered, set_triggered) = signal(false);

        Effect::new(move |_| {
            if active() && !triggered.get() {
                set_triggered.set(true);
                set_state.set(EventsListState::Loading);
                spawn_local(async move {
                    let state = match fetch_events().await {
                        Some(query) => EventsListState::Ready(query),
                        None => EventsListState::Failed,
                    };
                    set_state.set(state);
                });
            }
        });

        let on_refresh = move |_| {
            set_state.set(EventsListState::Loading);
            spawn_local(async move {
                let state = match fetch_events().await {
                    Some(query) => EventsListState::Ready(query),
                    None => EventsListState::Failed,
                };
                set_state.set(state);
            });
        };

        view! {
            <section class="view-section" hidden=move || !active()>
                <div class="inventory-heading">
                    <div>
                        <p class="section-label">"Event history"</p>
                        <h2>{move || state.get().count_text()}</h2>
                    </div>
                    <p>"BMC event records, newest first"</p>
                </div>
                <p
                    class="event-bound"
                    hidden=move || {
                        !state.get().is_ready() || state.get().has_empty_events()
                    }
                >
                    {move || state.get().bound_text()}
                </p>
                <p
                    class="empty-inventory"
                    hidden=move || {
                        !state.get().is_ready() || !state.get().has_empty_events()
                    }
                >
                    "No events have been recorded yet."
                </p>
                <div class="resource-list">
                    {move || {
                        state
                            .get()
                            .event_cards()
                            .into_iter()
                            .map(|card| view! { <EventCard card=card /> })
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
                    {move || state.get().failure_message()}
                </p>
            </section>
        }
    }

    #[component]
    fn EventCard(card: EventCardProjection) -> impl IntoView {
        let EventCardProjection {
            event_id,
            endpoint_short_id,
            message_id,
            severity_label,
            severity_class,
            message,
            event_timestamp_text,
            observed_at_text,
        } = card;
        // The card header and the facts list both need these values; each
        // interpolation moves its own copy into the static view surface.
        let event_id_title = event_id.clone();
        let event_time_text = event_timestamp_text.clone();
        let source_endpoint_text = endpoint_short_id.clone();
        // Redfish events may carry no message text; the message paragraph is
        // then omitted instead of rendering an empty block.
        let message_empty = message.is_empty();

        view! {
            <article class="credential-card">
                <div class="credential-title">
                    <div>
                        <h3 class="event-message-id" title=event_id_title>{message_id}</h3>
                        <p class="credential-username">
                            {event_timestamp_text}
                            <span class="event-source">" · endpoint "{endpoint_short_id}</span>
                        </p>
                    </div>
                    <span class=severity_class>{severity_label}</span>
                </div>
                <p class="audit-message" hidden=message_empty>{message}</p>
                <dl class="resource-facts">
                    <div>
                        <dt>"Event time"</dt>
                        <dd>{event_time_text}</dd>
                    </div>
                    <div>
                        <dt>"Observed at"</dt>
                        <dd>{observed_at_text}</dd>
                    </div>
                    <div>
                        <dt>"Source endpoint"</dt>
                        <dd>{source_endpoint_text}</dd>
                    </div>
                    <div>
                        <dt>"Event id"</dt>
                        <dd>{event_id}</dd>
                    </div>
                </dl>
            </article>
        }
    }

    #[component]
    fn TelemetryView(view: ReadSignal<ConsoleView>) -> impl IntoView {
        let active = move || view.get() == ConsoleView::Telemetry;
        let (state, set_state) = signal(TelemetryListState::Idle);
        let (triggered, set_triggered) = signal(false);

        Effect::new(move |_| {
            if active() && !triggered.get() {
                set_triggered.set(true);
                set_state.set(TelemetryListState::Loading);
                spawn_local(async move {
                    let state = match fetch_telemetry().await {
                        Some(cards) => TelemetryListState::Ready(cards),
                        None => TelemetryListState::Failed,
                    };
                    set_state.set(state);
                });
            }
        });

        let on_refresh = move |_| {
            set_state.set(TelemetryListState::Loading);
            spawn_local(async move {
                let state = match fetch_telemetry().await {
                    Some(cards) => TelemetryListState::Ready(cards),
                    None => TelemetryListState::Failed,
                };
                set_state.set(state);
            });
        };

        view! {
            <section class="view-section" hidden=move || !active()>
                <div class="inventory-heading">
                    <div>
                        <p class="section-label">"Telemetry"</p>
                        <h2>{move || state.get().count_text()}</h2>
                    </div>
                    <p>"Current values and bounded history, newest first"</p>
                </div>
                <p
                    class="empty-inventory"
                    hidden=move || {
                        !state.get().is_ready() || !state.get().has_empty_series()
                    }
                >
                    "No telemetry series have been sampled yet. Refresh the endpoint inventory to capture readings."
                </p>
                <div class="resource-list">
                    {move || {
                        state
                            .get()
                            .cards()
                            .into_iter()
                            .map(|card| view! { <TelemetrySeriesCard card=card /> })
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
                    {move || state.get().failure_message()}
                </p>
            </section>
        }
    }

    #[component]
    fn TelemetrySeriesCard(card: TelemetryCardProjection) -> impl IntoView {
        let TelemetryCardProjection {
            series_id_title,
            endpoint_short_id,
            series_key,
            latest_value_text,
            latest_observed_at_text,
            sample_count_text,
            history,
        } = card;
        // Absent current value renders no facts instead of a placeholder
        // (the facts-list precedent); the rows are pre-formatted.
        let value_empty = latest_value_text.is_none() || latest_observed_at_text.is_none();
        let value_text = latest_value_text.unwrap_or_default();
        let observed_at_text = latest_observed_at_text.unwrap_or_default();
        let history_empty = history.is_empty();

        view! {
            <article class="credential-card">
                <div class="credential-title">
                    <div>
                        <h3 class="event-message-id" title=series_id_title>{series_key}</h3>
                        <p class="credential-username">"endpoint "{endpoint_short_id}</p>
                    </div>
                </div>
                <dl class="resource-facts">
                    <div hidden=value_empty>
                        <dt>"Current value"</dt>
                        <dd>{value_text}</dd>
                    </div>
                    <div hidden=value_empty>
                        <dt>"Latest observed at"</dt>
                        <dd>{observed_at_text}</dd>
                    </div>
                    <div>
                        <dt>"Samples retained"</dt>
                        <dd>{sample_count_text}</dd>
                    </div>
                </dl>
                <p class="section-label" hidden=history_empty>"Latest readings"</p>
                <ol class="telemetry-history" hidden=history_empty>
                    {history
                        .into_iter()
                        .map(|reading| {
                            view! {
                                <li>
                                    <span class="telemetry-history-value">{reading.value_text}</span>
                                    <span class="telemetry-history-time">{reading.observed_at_text}</span>
                                </li>
                            }
                        })
                        .collect_view()}
                </ol>
            </article>
        }
    }

    #[component]
    fn CapabilitiesView(
        view: ReadSignal<ConsoleView>,
        target: ReadSignal<Option<CapabilityTargetProjection>>,
        state: ReadSignal<CapabilityMatrixState>,
        set_state: WriteSignal<CapabilityMatrixState>,
        triggered: ReadSignal<bool>,
        set_triggered: WriteSignal<bool>,
        on_back: Callback<()>,
    ) -> impl IntoView {
        let active = move || view.get() == ConsoleView::Capabilities;

        // Fetches exactly once per target: the endpoint-card entry resets the
        // triggered flag, and the nav re-entry keeps the cached matrix.
        Effect::new(move |_| {
            if !active() {
                return;
            }
            let Some(target) = target.get() else {
                return;
            };
            if triggered.get() {
                return;
            }
            set_triggered.set(true);
            set_state.set(CapabilityMatrixState::Loading);
            let endpoint_id = target.endpoint_id;
            spawn_local(async move {
                set_state.set(fetch_capabilities(&endpoint_id).await);
            });
        });

        let on_refresh = move |_| {
            set_state.set(CapabilityMatrixState::Loading);
            let Some(target) = target.get() else {
                return;
            };
            let endpoint_id = target.endpoint_id;
            spawn_local(async move {
                set_state.set(fetch_capabilities(&endpoint_id).await);
            });
        };

        view! {
            <section class="view-section" hidden=move || !active()>
                <div class="inventory-heading">
                    <div>
                        <p class="section-label">"Capabilities"</p>
                        <h2>
                            {move || {
                                target
                                    .get()
                                    .map_or_else(String::new, |target| target.display_name)
                            }}
                        </h2>
                    </div>
                    <p class="endpoint-address">
                        {move || {
                            target
                                .get()
                                .map_or_else(String::new, |target| target.address)
                        }}
                    </p>
                </div>
                <div class="inventory-actions">
                    <button
                        type="button"
                        class="btn"
                        on:click=move |_| on_back.run(())
                    >
                        "Back to overview"
                    </button>
                    <button
                        type="button"
                        class="btn"
                        disabled=move || state.get().is_loading()
                        on:click=on_refresh
                    >
                        "Refresh"
                    </button>
                </div>
                <p class="inline-status" hidden=move || !state.get().is_loading()>
                    "Loading capability list..."
                </p>
                <p class="form-error" hidden=move || !state.get().is_failed()>
                    {move || state.get().failure_message()}
                </p>
                <p
                    class="empty-inventory"
                    hidden=move || {
                        !state.get().is_ready() || !state.get().has_empty_matrix()
                    }
                >
                    "No capability data is available for this endpoint yet."
                </p>
                <p class="capability-summary" hidden=move || !state.get().is_ready()>
                    {move || state.get().summary_text()}
                </p>
                <div class="capability-groups">
                    {move || {
                        state
                            .get()
                            .groups()
                            .into_iter()
                            .map(|group| view! { <CapabilityGroup group=group /> })
                            .collect_view()
                    }}
                </div>
            </section>
        }
    }

    #[component]
    fn CapabilityGroup(group: CapabilityGroupProjection) -> impl IntoView {
        let page_title = group.page_title;
        let entry_count = group.entries.len();
        view! {
            <section class="capability-group">
                <div class="capability-group-heading">
                    <h4>{page_title}</h4>
                    <span>{entry_count}</span>
                </div>
                <div class="capability-item-grid">
                    {group
                        .entries
                        .into_iter()
                        .map(|entry| view! { <CapabilityItem entry=entry /> })
                        .collect_view()}
                </div>
            </section>
        }
    }

    #[component]
    fn CapabilityItem(entry: CapabilityEntryProjection) -> impl IntoView {
        let has_observed_at = entry.observed_at_text.is_some();
        view! {
            <article class="capability-item">
                <div class="capability-item-title">
                    <code class="capability-code">{entry.product_code}</code>
                    <span class=entry.state_class>{entry.state_label}</span>
                </div>
                <p class="capability-feature">
                    <span>"Upstream feature"</span>
                    <code>{entry.upstream_feature}</code>
                </p>
                <p class="capability-observed" hidden=!has_observed_at>
                    <span>"Observed at"</span>
                    {entry.observed_at_text}
                </p>
            </article>
        }
    }

    #[component]
    fn DiagnosticsView(
        view: ReadSignal<ConsoleView>,
        target: ReadSignal<Option<DiagnosticsTargetProjection>>,
        state: ReadSignal<DiagnosticsState>,
        set_state: WriteSignal<DiagnosticsState>,
        triggered: ReadSignal<bool>,
        set_triggered: WriteSignal<bool>,
        on_back: Callback<()>,
    ) -> impl IntoView {
        let active = move || view.get() == ConsoleView::Diagnostics;

        // Fetches exactly once per target: the card entry resets the
        // triggered flag, and the nav re-entry keeps the cached snapshot.
        Effect::new(move |_| {
            if !active() {
                return;
            }
            let Some(target) = target.get() else {
                return;
            };
            if triggered.get() {
                return;
            }
            set_triggered.set(true);
            set_state.set(DiagnosticsState::Loading);
            let endpoint_id = target.endpoint_id;
            let resource_id = target.resource_id;
            spawn_local(async move {
                set_state.set(fetch_diagnostics(&endpoint_id, &resource_id).await);
            });
        });

        let on_refresh = move |_| {
            set_state.set(DiagnosticsState::Loading);
            let Some(target) = target.get() else {
                return;
            };
            let endpoint_id = target.endpoint_id;
            let resource_id = target.resource_id;
            spawn_local(async move {
                set_state.set(fetch_diagnostics(&endpoint_id, &resource_id).await);
            });
        };

        view! {
            <section class="view-section" hidden=move || !active()>
                <div class="inventory-heading">
                    <div>
                        <p class="section-label">"Diagnostics"</p>
                        <h2>
                            {move || {
                                target
                                    .get()
                                    .map_or_else(String::new, |target| target.name)
                            }}
                        </h2>
                    </div>
                    <p class="endpoint-address">
                        {move || {
                            target
                                .get()
                                .map_or_else(String::new, |target| target.source)
                        }}
                    </p>
                </div>
                <div class="inventory-actions">
                    <button
                        type="button"
                        class="btn"
                        on:click=move |_| on_back.run(())
                    >
                        "Back to overview"
                    </button>
                    <button
                        type="button"
                        class="btn"
                        disabled=move || state.get().is_loading()
                        on:click=on_refresh
                    >
                        "Refresh"
                    </button>
                </div>
                <p class="inline-status" hidden=move || !state.get().is_loading()>
                    "Loading diagnostics..."
                </p>
                <p class="form-error" hidden=move || !state.get().is_failed()>
                    {move || state.get().failure_message()}
                </p>
                <div class="diagnostics-panel" hidden=move || !state.get().is_ready()>
                    {move || {
                        state
                            .get()
                            .projection()
                            .into_iter()
                            .map(|projection| {
                                view! { <DiagnosticsReady projection=projection /> }
                            })
                            .collect_view()
                    }}
                </div>
            </section>
        }
    }

    #[component]
    fn DiagnosticsReady(projection: DiagnosticsProjection) -> impl IntoView {
        let DiagnosticsProjection {
            endpoint_id,
            odata_uri,
            odata_type,
            etag,
            feature,
            generation,
            typed_payload_json,
        } = projection;
        // An absent optional field is information: the BMC did not publish
        // it. The muted placeholder keeps the row visible instead of hiding
        // what is missing; the pinned rendering helper keeps the decision
        // testable outside the wasm component.
        let odata_type_text = diagnostics_optional_text(odata_type.as_deref());
        let etag_text = diagnostics_optional_text(etag.as_deref());

        view! {
            <dl class="diagnostics-facts">
                <div>
                    <dt>"Endpoint"</dt>
                    <dd><code>{endpoint_id}</code></dd>
                </div>
                <div>
                    <dt>"OData URI"</dt>
                    <dd><code>{odata_uri}</code></dd>
                </div>
                <div>
                    <dt>"OData Type"</dt>
                    <dd><code>{odata_type_text}</code></dd>
                </div>
                <div>
                    <dt>"ETag"</dt>
                    <dd><code>{etag_text}</code></dd>
                </div>
                <div>
                    <dt>"nv-redfish feature"</dt>
                    <dd><code>{feature}</code></dd>
                </div>
                <div>
                    <dt>"Generation"</dt>
                    <dd>{generation}</dd>
                </div>
            </dl>
            // The decoded payload is read-only (§12.4 forbids submitting
            // arbitrary JSON): a native collapsible keeps the raw JSON one
            // click away without any edit surface, and the pre scrolls
            // within its bound instead of stretching the page.
            <details class="diagnostics-json" open>
                <summary>"Decoded typed payload"</summary>
                <pre class="diagnostics-json-body"><code>{typed_payload_json}</code></pre>
            </details>
            <p class="diagnostics-note">{DIAGNOSTICS_FOOTER_NOTE}</p>
        }
    }

    /// Loads the §12.4 diagnostics snapshot of one resource.
    ///
    /// A 404 means the endpoint or its resource no longer exists. Any other
    /// non-200 status — including 503 and the 400 that cannot originate from
    /// this UI, whose ids always come from the local inventory — maps to the
    /// generic unavailable message; a 200 body that violates the strict
    /// shared contract maps to the malformed message.
    async fn fetch_diagnostics(endpoint_id: &str, resource_id: &str) -> DiagnosticsState {
        let path = format!("/api/v1/endpoints/{endpoint_id}/resources/{resource_id}/diagnostics");
        let Ok(response) = Request::get(&path)
            .header("Accept", "application/json")
            .send()
            .await
        else {
            return DiagnosticsState::Failed(DiagnosticsLoadFailure::Unavailable);
        };
        if response.status() == 404 {
            return DiagnosticsState::Failed(DiagnosticsLoadFailure::ResourceNotFound);
        }
        if !response_ok(&response) {
            return DiagnosticsState::Failed(DiagnosticsLoadFailure::Unavailable);
        }
        match response.json::<ResourceDiagnosticsResponse>().await {
            Ok(diagnostics) => DiagnosticsState::Ready(DiagnosticsProjection::from(&diagnostics)),
            Err(_) => DiagnosticsState::Failed(DiagnosticsLoadFailure::Malformed),
        }
    }

    /// Loads the complete capability matrix of one endpoint.
    ///
    /// A 404 means the endpoint no longer exists. Any other non-200 status —
    /// including 503 and the 400 that cannot originate from this UI, whose
    /// endpoint ids always come from the local inventory — maps to the
    /// generic unavailable message; a 200 body that violates the strict
    /// shared contract maps to the malformed message.
    async fn fetch_capabilities(endpoint_id: &str) -> CapabilityMatrixState {
        let path = format!("/api/v1/endpoints/{endpoint_id}/capabilities");
        let Ok(response) = Request::get(&path)
            .header("Accept", "application/json")
            .send()
            .await
        else {
            return CapabilityMatrixState::Failed(CapabilityLoadFailure::Unavailable);
        };
        if response.status() == 404 {
            return CapabilityMatrixState::Failed(CapabilityLoadFailure::EndpointNotFound);
        }
        if !response_ok(&response) {
            return CapabilityMatrixState::Failed(CapabilityLoadFailure::Unavailable);
        }
        match response.json::<EndpointCapabilityInventoryResponse>().await {
            Ok(inventory) => {
                CapabilityMatrixState::Ready(CapabilityMatrixProjection::from(&inventory))
            }
            Err(_) => CapabilityMatrixState::Failed(CapabilityLoadFailure::Malformed),
        }
    }

    async fn fetch_audit() -> Option<AuditQueryResponse> {
        let response = Request::get("/api/v1/audit")
            .header("Accept", "application/json")
            .send()
            .await
            .ok()?;
        if !response_ok(&response) {
            return None;
        }
        response.json::<AuditQueryResponse>().await.ok()
    }

    /// How many recent events the console requests from the bounded §14.4
    /// history query. The server may return fewer while the history is
    /// shorter than the bound, and the view's bound hint reports the count
    /// actually returned.
    const EVENT_QUERY_LIMIT: u32 = 50;

    /// How many readings the console requests per series from the bounded
    /// §14.4 history query. The presentation boundary of 不把产品变成通用时序
    /// 数据库: a bounded newest-first list per card, not a chart or an
    /// unbounded scroll.
    const TELEMETRY_SAMPLE_LIMIT: u32 = 20;

    async fn fetch_events() -> Option<EventListResponse> {
        let url = format!("/api/v1/events?limit={EVENT_QUERY_LIMIT}");
        let response = Request::get(&url)
            .header("Accept", "application/json")
            .send()
            .await
            .ok()?;
        if !response_ok(&response) {
            return None;
        }
        response.json::<EventListResponse>().await.ok()
    }

    /// Fetches the §14.4 telemetry surface: the series inventory, then the
    /// bounded newest-first history of every series. A series without
    /// samples keeps its card with the current-value facts absent.
    async fn fetch_telemetry() -> Option<Vec<TelemetryCardProjection>> {
        let response = Request::get("/api/v1/telemetry")
            .header("Accept", "application/json")
            .send()
            .await
            .ok()?;
        if !response_ok(&response) {
            return None;
        }
        let series = response.json::<TelemetrySeriesListResponse>().await.ok()?;
        let mut cards = Vec::with_capacity(series.series().len());
        for item in series.series() {
            let samples = fetch_telemetry_samples(item).await;
            cards.push(TelemetryCardProjection::from_series(item).with_history(samples.as_ref()));
        }
        Some(cards)
    }

    async fn fetch_telemetry_samples(
        series: &TelemetrySeriesResponse,
    ) -> Option<TelemetrySampleListResponse> {
        // The series id renders through its `Display`; the id type itself
        // stays serialization-free in this crate.
        let url = format!(
            "/api/v1/telemetry/{}/samples?limit={TELEMETRY_SAMPLE_LIMIT}",
            series.series_id()
        );
        let response = Request::get(&url)
            .header("Accept", "application/json")
            .send()
            .await
            .ok()?;
        if !response_ok(&response) {
            return None;
        }
        response.json::<TelemetrySampleListResponse>().await.ok()
    }

    async fn fetch_credentials() -> Option<CredentialInventoryResponse> {
        let response = Request::get("/api/v1/credentials")
            .header("Accept", "application/json")
            .send()
            .await
            .ok()?;
        if !response_ok(&response) {
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
        let response = with_csrf(Request::post("/api/v1/credentials"))
            .json(&request)
            .ok()?
            .send()
            .await
            .ok()?;
        if !response_ok(&response) {
            return None;
        }
        response.json::<CredentialSummaryResponse>().await.ok()
    }

    async fn begin_endpoint_trust(address: &str) -> Option<EndpointTrustChallengeResponse> {
        let request = BeginEndpointTrustRequest::new(address.to_owned());
        let response = with_csrf(Request::post("/api/v1/endpoints/trust"))
            .json(&request)
            .ok()?
            .send()
            .await
            .ok()?;
        if !response_ok(&response) {
            return None;
        }
        response.json::<EndpointTrustChallengeResponse>().await.ok()
    }

    async fn confirm_endpoint_trust(
        address: &str,
        trust: &EndpointTrustExpectationRequest,
    ) -> Option<()> {
        let request = ConfirmEndpointTrustRequest::new(address.to_owned(), trust.clone());
        let response = with_csrf(Request::post("/api/v1/endpoints/trust/expect"))
            .json(&request)
            .ok()?
            .send()
            .await
            .ok()?;
        if !response_ok(&response) {
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
        let response = with_csrf(Request::post("/api/v1/endpoints"))
            .json(&request)
            .ok()?
            .send()
            .await
            .ok()?;
        if !response_ok(&response) {
            return None;
        }
        response.json::<EndpointEnrollmentResponse>().await.ok()
    }

    async fn post_endpoint_csv_import(
        csv: &str,
    ) -> Result<CsvImportReportProjection, ImportFailure> {
        let request = EndpointCsvImportRequest::new(csv.to_owned());
        let response = with_csrf(Request::post("/api/v1/endpoints/import"))
            .json(&request)
            .map_err(|_| ImportFailure::Unavailable)?
            .send()
            .await
            .map_err(|_| ImportFailure::Unavailable)?;
        if !response_ok(&response) {
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

    /// Refreshes the selected managed endpoints in one bounded batch and
    /// projects the server's per-endpoint report.
    ///
    /// The endpoint ids come from the loaded inventory, so the id-to-UUID
    /// parse follows the operation form's inference pattern; a parse failure
    /// means the console and the server disagree about the inventory and is
    /// reported like a malformed server response. A non-200 verdict maps to
    /// the rejection message carrying the HTTP status, and the report
    /// projection resolves display names against the inventory the selection
    /// was made from.
    async fn post_endpoint_refresh(
        endpoint_ids: &[String],
        inventory: &EndpointInventoryResponse,
    ) -> Result<RefreshBatchReportProjection, RefreshFailure> {
        let parsed: Result<Vec<_>, _> = endpoint_ids.iter().map(|id| id.parse()).collect();
        let Ok(parsed) = parsed else {
            return Err(RefreshFailure::MalformedReport);
        };
        let request = RefreshEndpointsRequest::new(parsed);
        let response = with_csrf(Request::post("/api/v1/endpoints/refresh"))
            .json(&request)
            .map_err(|_| RefreshFailure::Unavailable)?
            .send()
            .await
            .map_err(|_| RefreshFailure::Unavailable)?;
        if !response_ok(&response) {
            return Err(RefreshFailure::Rejected {
                status: response.status(),
            });
        }
        let report = response
            .json::<BatchRefreshResponse>()
            .await
            .map_err(|_| RefreshFailure::MalformedReport)?;
        Ok(RefreshBatchReportProjection::from_response(
            &report, inventory,
        ))
    }

    /// Loads the persisted §13 operation list.
    ///
    /// Any transport failure or non-200 status maps to the single static
    /// unavailable message, exactly like the audit and credential lists;
    /// a 200 body that violates the strict shared contract maps to the same
    /// failure because a list that cannot be projected is as useless as a
    /// list that never arrived.
    async fn fetch_operations() -> OperationsListState {
        let response = Request::get("/api/v1/operations")
            .header("Accept", "application/json")
            .send()
            .await;
        let Ok(response) = response else {
            return OperationsListState::Failed;
        };
        if !response_ok(&response) {
            return OperationsListState::Failed;
        }
        match response.json::<OperationListResponse>().await {
            Ok(list) => OperationsListState::Ready(
                list.operations()
                    .iter()
                    .map(OperationCardProjection::from)
                    .collect(),
            ),
            Err(_) => OperationsListState::Failed,
        }
    }

    /// Probes the serving posture (audit follow-up F2/S8): the
    /// `/api/v1/center/sites` surface exists only on the Center console, so
    /// a 200 answers Center and a 404 answers Edge. Anything else (a
    /// failing center, a network error) falls back to Edge — the edge
    /// console is the common deployment and the center's views would fail
    /// the same way.
    async fn probe_console_scope() -> ConsoleScopeView {
        match Request::get("/api/v1/center/sites")
            .header("Accept", "application/json")
            .send()
            .await
        {
            Ok(response) if response.status() == 404 => ConsoleScopeView::Edge,
            Ok(response) if response_ok(&response) => ConsoleScopeView::Center,
            _ => ConsoleScopeView::Edge,
        }
    }

    /// Loads the center's §15.5 registered-site view.
    ///
    /// Any transport failure or non-200 status maps to the single static
    /// unavailable message, exactly like the audit and credential lists.
    async fn fetch_center_sites() -> CenterSitesListState {
        let Ok(response) = Request::get("/api/v1/center/sites")
            .header("Accept", "application/json")
            .send()
            .await
        else {
            return CenterSitesListState::Failed;
        };
        if !response_ok(&response) {
            return CenterSitesListState::Failed;
        }
        match response.json::<CenterSitesResponse>().await {
            Ok(list) => CenterSitesListState::Ready(
                list.sites()
                    .iter()
                    .map(CenterSiteCardProjection::from)
                    .collect(),
            ),
            Err(_) => CenterSitesListState::Failed,
        }
    }

    /// Loads the center's §15.5 aggregated endpoint view, optionally
    /// narrowed to one site.
    async fn fetch_center_endpoints(site_id: Option<&str>) -> CenterEndpointsDetailState {
        let path = match site_id {
            Some(site_id) => format!("/api/v1/center/endpoints?site_id={site_id}"),
            None => "/api/v1/center/endpoints".to_owned(),
        };
        let Ok(response) = Request::get(&path)
            .header("Accept", "application/json")
            .send()
            .await
        else {
            return CenterEndpointsDetailState::Failed;
        };
        if !response_ok(&response) {
            return CenterEndpointsDetailState::Failed;
        }
        match response.json::<CenterEndpointViewListResponse>().await {
            Ok(list) => CenterEndpointsDetailState::Ready(
                list.endpoints()
                    .iter()
                    .map(CenterEndpointCardProjection::from)
                    .collect(),
            ),
            Err(_) => CenterEndpointsDetailState::Failed,
        }
    }

    /// Loads the center's §15.6 operation tracking view.
    async fn fetch_center_operations() -> CenterOperationsListState {
        let Ok(response) = Request::get("/api/v1/center/operations")
            .header("Accept", "application/json")
            .send()
            .await
        else {
            return CenterOperationsListState::Failed;
        };
        if !response_ok(&response) {
            return CenterOperationsListState::Failed;
        }
        match response.json::<CenterOperationListResponse>().await {
            Ok(list) => CenterOperationsListState::Ready(
                list.operations()
                    .iter()
                    .map(CenterOperationCardProjection::from)
                    .collect(),
            ),
            Err(_) => CenterOperationsListState::Failed,
        }
    }

    /// Submits one §15.6 center operation: the typed command, the target,
    /// and the site — nothing else (§15.6).
    async fn submit_center_operation(
        submission: &CenterOperationSubmission,
    ) -> Result<(), &'static str> {
        let Ok(site_id) = submission.site_id.parse() else {
            return Err("The submission could not be prepared.");
        };
        let Ok(endpoint_id) = submission.endpoint_id.parse() else {
            return Err("The submission could not be prepared.");
        };
        let request = CenterOperationSubmitRequest::new(
            site_id,
            endpoint_id,
            submission.target.clone(),
            submission.command.clone(),
        );
        let Ok(request) = with_csrf(Request::post("/api/v1/center/operations")).json(&request)
        else {
            return Err("The submission could not be prepared.");
        };
        let Ok(response) = request.send().await else {
            return Err("The center did not answer.");
        };
        if !response_ok(&response) {
            return Err("The center refused the submission.");
        }
        response
            .json::<CenterOperationSubmitResponse>()
            .await
            .map(|_| ())
            .map_err(|_| "The acknowledgement could not be parsed.")
    }

    /// Registers one site and returns its one-time binding code (design
    /// D2); the raw code travels exactly once, here.
    async fn register_center_site(
        display_name: &str,
        center_url: &str,
    ) -> Result<CenterBindingCodeView, &'static str> {
        let request =
            CenterBindingRegisterRequest::new(display_name.to_owned(), center_url.to_owned());
        let Ok(request) = with_csrf(Request::post("/api/v1/center/bindings")).json(&request) else {
            return Err("The registration could not be prepared.");
        };
        let Ok(response) = request.send().await else {
            return Err("The center did not answer.");
        };
        if !response_ok(&response) {
            return Err("The center refused the registration.");
        }
        response
            .json::<CenterBindingRegisterResponse>()
            .await
            .map(|registered| CenterBindingCodeView {
                site_id: registered.site_id().to_string(),
                binding_id: registered.binding_id().to_string(),
                code: registered.code().to_owned(),
                expires_at: registered.expires_at(),
            })
            .map_err(|_| "The binding code could not be parsed.")
    }

    /// Revokes the active binding of one site (design D2).
    async fn revoke_center_binding(site_id: &str) -> bool {
        let Ok(site_id) = site_id.parse() else {
            return false;
        };
        let request = CenterBindingRevokeRequest::new(site_id);
        let Ok(request) = with_csrf(Request::post("/api/v1/center/bindings/revoke")).json(&request)
        else {
            return false;
        };
        let Ok(response) = request.send().await else {
            return false;
        };
        response_ok(&response)
    }

    /// Loads the persisted §13.7 batch list.
    ///
    /// The cards render the server-derived verdict and outcome buckets
    /// verbatim — the client never derives a batch outcome from the children;
    /// the per-endpoint child rows are fetched separately on first expand.
    /// Any transport failure or non-200 status maps to the single static
    /// unavailable message, exactly like the operation list.
    async fn fetch_batches() -> BatchesListState {
        let response = Request::get("/api/v1/batches")
            .header("Accept", "application/json")
            .send()
            .await;
        let Ok(response) = response else {
            return BatchesListState::Failed;
        };
        if !response_ok(&response) {
            return BatchesListState::Failed;
        }
        match response.json::<BatchListResponse>().await {
            Ok(list) => BatchesListState::Ready(
                list.batches()
                    .iter()
                    .map(BatchCardProjection::from)
                    .collect(),
            ),
            Err(_) => BatchesListState::Failed,
        }
    }

    /// Loads one batch's full report for the expanded per-endpoint rows
    /// (§13.7); `None` when the batch cannot be read.
    async fn fetch_batch_detail(batch_id: &str) -> Option<BatchDetailResponse> {
        let path = format!("/api/v1/batches/{batch_id}");
        let response = Request::get(&path)
            .header("Accept", "application/json")
            .send()
            .await
            .ok()?;
        if !response_ok(&response) {
            return None;
        }
        response.json::<BatchDetailResponse>().await.ok()
    }

    /// Submits one operation draft (§13.1, §13.7).
    ///
    /// The draft must already be validated (the form only calls this after
    /// `try_build` succeeds); a refused submission maps to the single static
    /// failure message because the route's rejection reasons are not part of
    /// the current console contract.
    ///
    /// The acknowledgement is parsed by the selected-target count: one target
    /// acknowledges an ordinary `OperationResponse`; several targets
    /// acknowledge the batch parent (`BatchOperationResponse`), whose
    /// children carry the same typed command and are executed and reported as
    /// ordinary operations. The per-endpoint batch report view is a later
    /// slice; this cut only needs the submission to succeed.
    async fn submit_operation(
        draft: &OperationFormDraft,
        command: &OperationCommandDraft,
    ) -> Result<(), &'static str> {
        let target_count = draft.selected_endpoint_ids.len();
        let targets: Result<Vec<_>, _> = draft
            .selected_endpoint_ids
            .iter()
            .map(|id| id.parse())
            .collect();
        let Ok(targets) = targets else {
            return Err(OperationSubmitState::FAILURE_MESSAGE);
        };
        let Ok(command) = build_command(command) else {
            return Err(OperationSubmitState::FAILURE_MESSAGE);
        };
        let request = CreateOperationRequest::new(None, targets, command);
        let response = with_csrf(Request::post("/api/v1/operations"))
            .json(&request)
            .map_err(|_| OperationSubmitState::FAILURE_MESSAGE)?
            .send()
            .await
            .map_err(|_| OperationSubmitState::FAILURE_MESSAGE)?;
        if !response_ok(&response) {
            return Err(OperationSubmitState::FAILURE_MESSAGE);
        }
        let body = response
            .text()
            .await
            .map_err(|_| OperationSubmitState::FAILURE_MESSAGE)?;
        super::acknowledge_submission(target_count, &body)
    }

    /// Loads the §9.3 artifact inventory.
    ///
    /// Any transport failure or non-200 status maps to the single static
    /// unavailable message, exactly like the audit and credential lists; a
    /// 200 body that violates the strict shared contract maps to the same
    /// failure because a list that cannot be projected is as useless as one
    /// that never arrived.
    async fn fetch_artifacts() -> ArtifactsListState {
        let Ok(response) = Request::get("/api/v1/artifacts")
            .header("Accept", "application/json")
            .send()
            .await
        else {
            return ArtifactsListState::Failed;
        };
        if !response_ok(&response) {
            return ArtifactsListState::Failed;
        }
        match response.json::<ArtifactListResponse>().await {
            Ok(list) => ArtifactsListState::Ready(
                list.artifacts()
                    .iter()
                    .map(ArtifactCardProjection::from)
                    .collect(),
            ),
            Err(_) => ArtifactsListState::Failed,
        }
    }

    /// Reads one artifact's current projection, used to recover the
    /// acknowledged byte count after a chunk response that did not advance.
    async fn fetch_artifact(artifact_id: &str) -> Option<ArtifactResponse> {
        let path = format!("/api/v1/artifacts/{artifact_id}");
        let response = Request::get(&path)
            .header("Accept", "application/json")
            .send()
            .await
            .ok()?;
        if !response_ok(&response) {
            return None;
        }
        response.json::<ArtifactResponse>().await.ok()
    }

    /// Declares an artifact (§14.3) with the client-computed SHA-256 digest,
    /// because the create contract requires the digest up front; the server
    /// independently recomputes and verifies it at finalize.
    async fn create_artifact(name: &str, bytes: &[u8]) -> Result<String, ArtifactUploadFailure> {
        let size_bytes = u64::try_from(bytes.len()).ok().unwrap_or(0);
        let request = CreateArtifactRequest::new(name.to_owned(), size_bytes, sha256_hex(bytes));
        let response = with_csrf(Request::post("/api/v1/artifacts"))
            .json(&request)
            .map_err(|_| ArtifactUploadFailure::Unavailable)?
            .send()
            .await
            .map_err(|_| ArtifactUploadFailure::Unavailable)?;
        if !response_ok(&response) {
            return Err(ArtifactUploadFailure::CreateRejected {
                status: response.status(),
            });
        }
        response
            .json::<ArtifactResponse>()
            .await
            .map(|artifact| artifact.artifact_id().to_string())
            .map_err(|_| ArtifactUploadFailure::MalformedResponse)
    }

    /// Appends one base64-encoded chunk at the exact next offset the server
    /// acknowledged; the response's `uploaded_bytes` is the source of truth
    /// for the following chunk.
    async fn append_artifact_chunk(
        artifact_id: &str,
        offset: u64,
        data: String,
    ) -> Result<ArtifactProgressResponse, ArtifactUploadFailure> {
        let path = format!("/api/v1/artifacts/{artifact_id}/chunks");
        let request = AppendArtifactChunkRequest::new(offset, data);
        let response = with_csrf(Request::post(&path))
            .json(&request)
            .map_err(|_| ArtifactUploadFailure::Unavailable)?
            .send()
            .await
            .map_err(|_| ArtifactUploadFailure::Unavailable)?;
        if !response_ok(&response) {
            return Err(ArtifactUploadFailure::ChunkRejected {
                status: response.status(),
            });
        }
        response
            .json::<ArtifactProgressResponse>()
            .await
            .map_err(|_| ArtifactUploadFailure::MalformedResponse)
    }

    /// Commits an artifact: the server reads the stored bytes back and
    /// verifies them against the declared SHA-256 (§14.3).
    async fn finalize_artifact(artifact_id: &str) -> Result<(), ArtifactUploadFailure> {
        let path = format!("/api/v1/artifacts/{artifact_id}/finalize");
        let response = with_csrf(Request::post(&path))
            .send()
            .await
            .map_err(|_| ArtifactUploadFailure::Unavailable)?;
        if !response_ok(&response) {
            return Err(ArtifactUploadFailure::FinalizeRejected {
                status: response.status(),
            });
        }
        response
            .json::<ArtifactResponse>()
            .await
            .map_err(|_| ArtifactUploadFailure::MalformedResponse)?;
        Ok(())
    }

    /// Drives one create → chunked upload → finalize sequence (§14.3) and
    /// reports every step through `report` so the form can render the
    /// progress bar.
    ///
    /// The loop is driven by the server's acknowledged `uploaded_bytes`,
    /// never by local arithmetic: each successful chunk response advances the
    /// offset, and a chunk response that did not advance (an idempotent
    /// retransmit of a chunk the server already committed) re-reads the
    /// artifact once before failing.
    async fn run_artifact_upload(
        name: &str,
        bytes: &[u8],
        resume: Option<ArtifactCardProjection>,
        report: impl Fn(ArtifactUploadState) + Send + 'static,
    ) -> Result<(), ArtifactUploadFailure> {
        let size_bytes = u64::try_from(bytes.len()).ok().unwrap_or(0);
        let (artifact_id, mut offset) = match resume {
            // Every byte is already stored; only the finalize step remains.
            Some(card) if card.is_completely_uploaded() => {
                report(ArtifactUploadState::Finalizing {
                    artifact_id: card.artifact_id.clone(),
                });
                return finalize_artifact(&card.artifact_id).await;
            }
            Some(card) => (card.artifact_id.clone(), card.uploaded_bytes),
            None => {
                report(ArtifactUploadState::Creating);
                (create_artifact(name, bytes).await?, 0)
            }
        };
        while let Some(range) = artifact_chunk_range_at(offset, size_bytes) {
            let start = usize::try_from(range.offset).ok().unwrap_or(0);
            let end = start + range.length;
            let data = base64_encode(&bytes[start..end]);
            report(ArtifactUploadState::Uploading {
                artifact_id: artifact_id.clone(),
                uploaded_bytes: offset,
                total_bytes: size_bytes,
            });
            match append_artifact_chunk(&artifact_id, range.offset, data).await {
                Ok(progress) if progress.uploaded_bytes() >= size_bytes => break,
                Ok(progress) if progress.uploaded_bytes() > offset => {
                    offset = progress.uploaded_bytes();
                }
                Ok(_) => {
                    // The server already held the chunk (idempotent
                    // retransmit) but reported no advance; re-read its truth
                    // once. A second no-advance is a contract violation.
                    let Some(artifact) = fetch_artifact(&artifact_id).await else {
                        return Err(ArtifactUploadFailure::Unavailable);
                    };
                    if artifact.uploaded_bytes() > offset {
                        offset = artifact.uploaded_bytes();
                    } else {
                        return Err(ArtifactUploadFailure::MalformedResponse);
                    }
                }
                Err(failure) => return Err(failure),
            }
        }
        report(ArtifactUploadState::Finalizing {
            artifact_id: artifact_id.clone(),
        });
        finalize_artifact(&artifact_id).await
    }

    #[component]
    fn OperationsView(
        view: ReadSignal<ConsoleView>,
        load_state: ReadSignal<ConsoleLoadState>,
    ) -> impl IntoView {
        let active = move || view.get() == ConsoleView::Operations;
        let (list_state, set_list_state) = signal(OperationsListState::Loading);
        let (list_triggered, set_list_triggered) = signal(false);
        let (draft, set_draft) = signal(OperationFormDraft::new());
        let (draft_error, set_draft_error) = signal(None::<OperationFormError>);
        let (submit_state, set_submit_state) = signal(OperationSubmitState::Idle);
        // The update form needs the §14.3 artifact inventory to offer ready
        // choices. It is fetched lazily when the update family is selected
        // (not on every visit of the view), because only that family renders
        // the artifact select and the list is otherwise the Artifacts view's
        // own state.
        let (artifact_list_state, set_artifact_list_state) = signal(ArtifactsListState::Loading);
        let (artifact_list_triggered, set_artifact_list_triggered) = signal(false);
        // The §13.7 batch area shares the view's load lifecycle: the cards
        // render the server-derived verdict and outcome buckets, and the
        // expanded per-endpoint rows are fetched lazily on first expand.
        let (batches_state, set_batches_state) = signal(BatchesListState::Loading);
        let (batches_triggered, set_batches_triggered) = signal(false);
        let (expanded_batches, set_expanded_batches) = signal(BTreeSet::<String>::new());
        let (expanded_children, set_expanded_children) =
            signal(HashMap::<String, Vec<BatchChildRowProjection>>::new());

        Effect::new(move |_| {
            if active() && !list_triggered.get() {
                set_list_triggered.set(true);
                set_list_state.set(OperationsListState::Loading);
                spawn_local(async move {
                    set_list_state.set(fetch_operations().await);
                });
            }
        });

        Effect::new(move |_| {
            if active() && !batches_triggered.get() {
                set_batches_triggered.set(true);
                set_batches_state.set(BatchesListState::Loading);
                spawn_local(async move {
                    set_batches_state.set(fetch_batches().await);
                });
            }
        });

        Effect::new(move |_| {
            if active()
                && draft.get().family == Some(CommandFamilyView::FirmwareUpdate)
                && !artifact_list_triggered.get()
            {
                set_artifact_list_triggered.set(true);
                set_artifact_list_state.set(ArtifactsListState::Loading);
                spawn_local(async move {
                    set_artifact_list_state.set(fetch_artifacts().await);
                });
            }
        });

        let on_refresh = move |_| {
            set_list_state.set(OperationsListState::Loading);
            set_batches_state.set(BatchesListState::Loading);
            spawn_local(async move {
                set_list_state.set(fetch_operations().await);
            });
            spawn_local(async move {
                set_batches_state.set(fetch_batches().await);
            });
        };

        let on_toggle_endpoint = Callback::new(move |endpoint_id: String| {
            set_draft.update(|draft| draft.toggle_endpoint(endpoint_id));
            set_draft_error.set(None);
            set_submit_state.set(OperationSubmitState::Idle);
        });

        let on_select_family = Callback::new(move |family: CommandFamilyView| {
            set_draft.update(|draft| {
                draft.family = Some(family);
                // Switching families clears every other family's parameters,
                // so a later submission can never carry stale selections.
                draft.reset_type = None;
                draft.boot_source = None;
                draft.boot_enabled = None;
                draft.boot_mode = None;
                draft.secure_boot_action = None;
                draft.reset_keys_type = None;
                draft.event_action = None;
                draft.protocol = None;
                draft.artifact_id = None;
                draft.push_uri = String::new();
            });
            // Re-entering the update family refreshes the artifact choices,
            // so a firmware file finalized after the last fetch is offered
            // immediately.
            if family == CommandFamilyView::FirmwareUpdate {
                set_artifact_list_triggered.set(false);
                set_artifact_list_state.set(ArtifactsListState::Loading);
            }
            set_draft_error.set(None);
            set_submit_state.set(OperationSubmitState::Idle);
        });

        let on_submit = Callback::new(move |()| {
            let submitted = draft.get();
            let command = match submitted.try_build() {
                Ok(command) => command,
                Err(error) => {
                    set_draft_error.set(Some(error));
                    return;
                }
            };
            set_draft_error.set(None);
            set_submit_state.set(OperationSubmitState::InFlight);
            spawn_local(async move {
                match submit_operation(&submitted, &command).await {
                    Ok(()) => {
                        set_submit_state.set(OperationSubmitState::Succeeded);
                        set_draft.set(OperationFormDraft::new());
                        set_draft_error.set(None);
                        set_list_state.set(OperationsListState::Loading);
                        set_list_state.set(fetch_operations().await);
                        // A batch submission creates a new batch parent, so
                        // the batch area refreshes with the operation list.
                        set_batches_state.set(BatchesListState::Loading);
                        set_batches_state.set(fetch_batches().await);
                    }
                    Err(message) => set_submit_state.set(OperationSubmitState::Failed(message)),
                }
            });
        });

        let endpoint_choices = move || match &load_state.get() {
            ConsoleLoadState::Ready(data) => operation_endpoint_choices(&data.inventory),
            ConsoleLoadState::Loading | ConsoleLoadState::Failed(_) => Vec::new(),
        };

        let artifact_choices = move || match &artifact_list_state.get() {
            ArtifactsListState::Ready(cards) => update_artifact_choices(cards),
            ArtifactsListState::Loading | ArtifactsListState::Failed => Vec::new(),
        };

        view! {
            <section class="view-section" hidden=move || !active()>
                <div class="inventory-heading">
                    <div>
                        <p class="section-label">"Operation tasks"</p>
                        <h2>{move || list_state.get().count_text()}</h2>
                    </div>
                    <p>"Every write is a persisted, typed operation before it executes."</p>
                </div>
                <div class="inventory-actions">
                    <button
                        type="button"
                        class="btn"
                        disabled=move || list_state.get().is_loading()
                        on:click=on_refresh
                    >
                        "Refresh"
                    </button>
                </div>
                <p class="inline-status" hidden=move || !list_state.get().is_loading()>
                    "Loading operations..."
                </p>
                <p class="form-error" hidden=move || !list_state.get().is_failed()>
                    "The operation list is temporarily unavailable."
                </p>
                <p
                    class="empty-inventory"
                    hidden=move || {
                        !list_state.get().is_ready() || !list_state.get().has_empty_list()
                    }
                >
                    "No operations have been submitted yet."
                </p>
                <div class="resource-list">
                    {move || {
                        list_state
                            .get()
                            .cards()
                            .into_iter()
                            .map(|card| view! { <OperationCard card=card /> })
                            .collect_view()
                    }}
                </div>
                <div class="inventory-heading">
                    <div>
                        <p class="section-label">"Batch operations"</p>
                        <h2>{move || batches_state.get().count_text()}</h2>
                    </div>
                    <p>"A multi-endpoint write is one batch with a per-endpoint outcome report."</p>
                </div>
                <p class="inline-status" hidden=move || !batches_state.get().is_loading()>
                    "Loading batches..."
                </p>
                <p class="form-error" hidden=move || !batches_state.get().is_failed()>
                    "The batch list is temporarily unavailable."
                </p>
                <p
                    class="empty-inventory"
                    hidden=move || {
                        !batches_state.get().is_ready() || !batches_state.get().has_empty_list()
                    }
                >
                    "No batch operations have been submitted yet."
                </p>
                <div class="resource-list">
                    {move || {
                        batches_state
                            .get()
                            .cards()
                            .into_iter()
                            .map(|card| {
                                view! {
                                    <BatchCard
                                        card=card
                                        expanded=expanded_batches
                                        set_expanded=set_expanded_batches
                                        expanded_children=expanded_children
                                        set_expanded_children=set_expanded_children
                                        load_state=load_state
                                    />
                                }
                            })
                            .collect_view()
                    }}
                </div>
                <OperationSubmitForm
                    endpoint_choices=endpoint_choices
                    artifact_choices=artifact_choices
                    artifact_list_state=artifact_list_state
                    draft=draft
                    set_draft=set_draft
                    error=draft_error
                    set_error=set_draft_error
                    submit_state=submit_state
                    set_submit_state=set_submit_state
                    on_toggle_endpoint=on_toggle_endpoint
                    on_select_family=on_select_family
                    on_submit=on_submit
                />
            </section>
        }
    }

    #[component]
    fn OperationSubmitForm(
        endpoint_choices: impl Fn() -> Vec<OperationEndpointChoice> + Send + 'static,
        artifact_choices: impl Fn() -> Vec<UpdateArtifactChoice> + Send + 'static,
        artifact_list_state: ReadSignal<ArtifactsListState>,
        draft: ReadSignal<OperationFormDraft>,
        set_draft: WriteSignal<OperationFormDraft>,
        error: ReadSignal<Option<OperationFormError>>,
        set_error: WriteSignal<Option<OperationFormError>>,
        submit_state: ReadSignal<OperationSubmitState>,
        set_submit_state: WriteSignal<OperationSubmitState>,
        on_toggle_endpoint: Callback<String>,
        on_select_family: Callback<CommandFamilyView>,
        on_submit: Callback<()>,
    ) -> impl IntoView {
        let on_reset_type_change = move |event| {
            let value = event_target_value(&event);
            let selected = ResetTypeView::ALL
                .into_iter()
                .find(|candidate| candidate.as_str() == value);
            set_draft.update(|draft| draft.reset_type = selected);
            set_error.set(None);
            set_submit_state.set(OperationSubmitState::Idle);
        };
        let on_boot_source_change = move |event| {
            let value = event_target_value(&event);
            let selected = BootSourceView::ALL
                .into_iter()
                .find(|candidate| candidate.as_str() == value);
            set_draft.update(|draft| draft.boot_source = selected);
            set_error.set(None);
            set_submit_state.set(OperationSubmitState::Idle);
        };
        let on_boot_enabled_change = move |event| {
            let value = event_target_value(&event);
            let selected = BootEnabledView::ALL
                .into_iter()
                .find(|candidate| candidate.as_str() == value);
            set_draft.update(|draft| draft.boot_enabled = selected);
            set_error.set(None);
            set_submit_state.set(OperationSubmitState::Idle);
        };
        let on_boot_mode_change = move |event| {
            let value = event_target_value(&event);
            let selected = BootModeView::ALL
                .into_iter()
                .find(|candidate| candidate.as_str() == value);
            set_draft.update(|draft| draft.boot_mode = selected);
            set_error.set(None);
            set_submit_state.set(OperationSubmitState::Idle);
        };
        let on_secure_boot_change = move |event| {
            let value = event_target_value(&event);
            let selected = match value.as_str() {
                "enable" => Some(SecureBootActionView::Enable),
                "disable" => Some(SecureBootActionView::Disable),
                "reset-keys" => Some(SecureBootActionView::ResetKeys(
                    ResetKeysTypeView::ResetAllKeysToDefault,
                )),
                _ => None,
            };
            set_draft.update(|draft| draft.secure_boot_action = selected);
            set_error.set(None);
            set_submit_state.set(OperationSubmitState::Idle);
        };
        let on_reset_keys_change = move |event| {
            let value = event_target_value(&event);
            let selected = ResetKeysTypeView::ALL
                .into_iter()
                .find(|candidate| candidate.as_str() == value);
            set_draft.update(|draft| draft.reset_keys_type = selected);
            set_error.set(None);
            set_submit_state.set(OperationSubmitState::Idle);
        };
        let on_event_action_change = move |event| {
            let value = event_target_value(&event);
            let selected = match value.as_str() {
                "create" => Some(EventActionView::CreateSubscription),
                "delete" => Some(EventActionView::DeleteSubscription),
                _ => None,
            };
            set_draft.update(|draft| draft.event_action = selected);
            set_error.set(None);
            set_submit_state.set(OperationSubmitState::Idle);
        };
        let on_protocol_change = move |event| {
            let value = event_target_value(&event);
            let selected = EventProtocolView::ALL
                .into_iter()
                .find(|candidate| candidate.as_str() == value);
            set_draft.update(|draft| draft.protocol = selected);
            set_error.set(None);
            set_submit_state.set(OperationSubmitState::Idle);
        };
        let on_destination_input = move |event| {
            set_draft.update(|draft| draft.destination = event_target_value(&event));
            set_error.set(None);
            set_submit_state.set(OperationSubmitState::Idle);
        };
        let on_subscription_id_input = move |event| {
            set_draft.update(|draft| draft.subscription_id = event_target_value(&event));
            set_error.set(None);
            set_submit_state.set(OperationSubmitState::Idle);
        };
        let on_toggle_event_type = Callback::new(move |kind: EventTypeView| {
            set_draft.update(|draft| {
                if let Some(index) = draft.event_types.iter().position(|t| *t == kind) {
                    draft.event_types.remove(index);
                } else {
                    draft.event_types.push(kind);
                }
            });
            set_error.set(None);
            set_submit_state.set(OperationSubmitState::Idle);
        });
        let on_update_artifact_change = move |event| {
            let value = event_target_value(&event);
            let selected = if value.is_empty() { None } else { Some(value) };
            set_draft.update(|draft| draft.artifact_id = selected);
            set_error.set(None);
            set_submit_state.set(OperationSubmitState::Idle);
        };
        let on_update_push_uri_input = move |event| {
            set_draft.update(|draft| draft.push_uri = event_target_value(&event));
            set_error.set(None);
            set_submit_state.set(OperationSubmitState::Idle);
        };
        let on_oem_face_change = move |event| {
            let value = event_target_value(&event);
            let selected = match value.as_str() {
                "system-config-profile" => Some(OemFaceView::SystemConfigProfile),
                "debug-token" => Some(OemFaceView::DebugToken),
                "power-smoothing" => Some(OemFaceView::PowerSmoothing),
                _ => None,
            };
            set_draft.update(|draft| {
                draft.oem_face = selected;
                // An action of the other face would be a stale choice after
                // the face changes, so it is dropped with the face.
                if let Some(face) = selected {
                    if draft.oem_action.is_some_and(|action| action.face() != face) {
                        draft.oem_action = None;
                    }
                }
            });
            set_error.set(None);
            set_submit_state.set(OperationSubmitState::Idle);
        };
        let on_oem_action_change = move |event| {
            let value = event_target_value(&event);
            let selected = match value.as_str() {
                "profile-update" => Some(OemActionView::ProfileUpdate),
                "profile-factory-reset" => Some(OemActionView::ProfileFactoryReset),
                "profile-activate" => Some(OemActionView::ProfileActivate),
                "token-generate" => Some(OemActionView::TokenGenerate),
                "token-install" => Some(OemActionView::TokenInstall),
                "token-disable" => Some(OemActionView::TokenDisable),
                "token-erase" => Some(OemActionView::TokenErase),
                "power-activate-preset" => Some(OemActionView::PowerActivatePreset),
                "power-apply-overrides" => Some(OemActionView::PowerApplyOverrides),
                _ => None,
            };
            set_draft.update(|draft| {
                draft.oem_action = selected;
                // The face follows the action, so the action list can never
                // show an action outside the chosen face.
                if let Some(action) = selected {
                    draft.oem_face = Some(action.face());
                }
            });
            set_error.set(None);
            set_submit_state.set(OperationSubmitState::Idle);
        };
        let on_token_type_change = move |event| {
            let value = event_target_value(&event);
            let selected = TokenTypeView::ALL
                .into_iter()
                .find(|candidate| candidate.as_str() == value);
            set_draft.update(|draft| draft.token_type = selected);
            set_error.set(None);
            set_submit_state.set(OperationSubmitState::Idle);
        };
        let on_erase_type_change = move |event| {
            let value = event_target_value(&event);
            let selected = EraseTypeView::ALL
                .into_iter()
                .find(|candidate| candidate.as_str() == value);
            set_draft.update(|draft| draft.erase_type = selected);
            set_error.set(None);
            set_submit_state.set(OperationSubmitState::Idle);
        };
        let on_profile_file_input = move |event| {
            set_draft.update(|draft| draft.profile_file = event_target_value(&event));
            set_error.set(None);
            set_submit_state.set(OperationSubmitState::Idle);
        };
        let on_token_data_input = move |event| {
            set_draft.update(|draft| draft.token_data = event_target_value(&event));
            set_error.set(None);
            set_submit_state.set(OperationSubmitState::Idle);
        };
        let on_profile_id_input = move |event| {
            set_draft.update(|draft| draft.profile_id = event_target_value(&event));
            set_error.set(None);
            set_submit_state.set(OperationSubmitState::Idle);
        };

        // The reset families share one parameter block; any of the three
        // selections shows it.
        let reset_family_selected = move || {
            matches!(
                draft.get().family,
                Some(
                    CommandFamilyView::SystemReset
                        | CommandFamilyView::ManagerReset
                        | CommandFamilyView::ChassisReset
                )
            )
        };
        let family_selected = move |family: CommandFamilyView| draft.get().family == Some(family);
        let is_reset_keys = move || {
            matches!(
                draft.get().secure_boot_action,
                Some(SecureBootActionView::ResetKeys(_))
            )
        };
        let is_create_subscription =
            move || draft.get().event_action == Some(EventActionView::CreateSubscription);
        let is_delete_subscription =
            move || draft.get().event_action == Some(EventActionView::DeleteSubscription);
        let oem_action_selected =
            move |action: OemActionView| draft.get().oem_action == Some(action);
        // The live preview shows exactly what the card of a submitted
        // operation will render, because both use the same projection.
        let preview_text = move || match draft.get().try_build() {
            Ok(command) => {
                let summary = command_summary(&command);
                format!("{} · {}", summary.family, summary.payload)
            }
            Err(_) => String::new(),
        };
        let field_error = move |candidate: OperationFormError| match error.get() {
            Some(error) if error == candidate => error.message(),
            _ => "",
        };

        view! {
            <div class="form-panel">
                <p class="section-label">"Submit operation"</p>
                <p class="form-hint">
                    "Choose the target endpoints and the typed command. The submission is persisted before it is executed."
                </p>

                <p class="section-label">"Targets"</p>
                <div class="command-choice-grid">
                    {endpoint_choices()
                        .into_iter()
                        .map(|choice| {
                            // The id is cloned before the template closures,
                            // because the selected check and the click handler
                            // both move-capture it while the template moves
                            // the display fields.
                            let endpoint_id = choice.endpoint_id.clone();
                            let selected_endpoint_id = endpoint_id.clone();
                            let display_name = choice.display_name;
                            let address = choice.address;
                            let is_selected = move || {
                                draft.get().is_endpoint_selected(&selected_endpoint_id)
                            };
                            let class = move || {
                                if is_selected() {
                                    "command-choice is-selected"
                                } else {
                                    "command-choice"
                                }
                            };
                            view! {
                                <button
                                    type="button"
                                    class=class
                                    on:click=move |_| {
                                        on_toggle_endpoint.run(endpoint_id.clone());
                                    }
                                >
                                    <span class="command-choice-name">{display_name}</span>
                                    <span class="command-choice-detail">{address}</span>
                                </button>
                            }
                        })
                        .collect_view()}
                </div>
                <p
                    class="form-error"
                    hidden=move || field_error(OperationFormError::EndpointsRequired).is_empty()
                >
                    {OperationFormError::EndpointsRequired.message()}
                </p>

                <p class="section-label">"Command"</p>
                <div class="command-choice-grid">
                    {CommandFamilyView::ALL
                        .into_iter()
                        .map(|family| {
                            let is_selected = move || family_selected(family);
                            let class = move || {
                                if is_selected() {
                                    "command-choice is-selected"
                                } else {
                                    "command-choice"
                                }
                            };
                            view! {
                                <button
                                    type="button"
                                    class=class
                                    on:click=move |_| on_select_family.run(family)
                                >
                                    <span class="command-choice-name">{family.label()}</span>
                                    <span class="command-choice-detail">{family.as_str()}</span>
                                </button>
                            }
                        })
                        .collect_view()}
                </div>
                <p
                    class="form-error"
                    hidden=move || field_error(OperationFormError::FamilyRequired).is_empty()
                >
                    {OperationFormError::FamilyRequired.message()}
                </p>

                <div class="form-field" hidden=move || !reset_family_selected()>
                    <label for="operation-reset-type">"Reset type"</label>
                    <select
                        id="operation-reset-type"
                        class="form-select"
                        prop:value=move || {
                            draft
                                .get()
                                .reset_type
                                .map_or_else(String::new, |t| t.as_str().to_owned())
                        }
                        on:change=on_reset_type_change
                    >
                        <option value="">"Choose a reset type"</option>
                        {ResetTypeView::ALL
                            .into_iter()
                            .map(|t| view! { <option value=t.as_str()>{t.as_str()}</option> })
                            .collect_view()}
                    </select>
                    <p
                        class="form-error"
                        hidden=move || field_error(OperationFormError::ResetTypeRequired).is_empty()
                    >
                        {OperationFormError::ResetTypeRequired.message()}
                    </p>
                </div>

                <div class="form-field" hidden=move || !family_selected(CommandFamilyView::BootOverride)>
                    <label for="operation-boot-source">"Boot source"</label>
                    <select
                        id="operation-boot-source"
                        class="form-select"
                        prop:value=move || {
                            draft
                                .get()
                                .boot_source
                                .map_or_else(String::new, |s| s.as_str().to_owned())
                        }
                        on:change=on_boot_source_change
                    >
                        <option value="">"Choose a boot source"</option>
                        {BootSourceView::ALL
                            .into_iter()
                            .map(|s| view! { <option value=s.as_str()>{s.as_str()}</option> })
                            .collect_view()}
                    </select>
                    <div class="form-field-inline">
                        <div class="form-field">
                            <label for="operation-boot-enabled">"Applies"</label>
                            <select
                                id="operation-boot-enabled"
                                class="form-select"
                                prop:value=move || {
                                    draft
                                        .get()
                                        .boot_enabled
                                        .map_or_else(String::new, |e| e.as_str().to_owned())
                                }
                                on:change=on_boot_enabled_change
                            >
                                <option value="">"Choose"</option>
                                {BootEnabledView::ALL
                                    .into_iter()
                                    .map(|e| view! { <option value=e.as_str()>{e.as_str()}</option> })
                                    .collect_view()}
                            </select>
                        </div>
                        <div class="form-field">
                            <label for="operation-boot-mode">"Mode"</label>
                            <select
                                id="operation-boot-mode"
                                class="form-select"
                                prop:value=move || {
                                    draft
                                        .get()
                                        .boot_mode
                                        .map_or_else(String::new, |m| m.as_str().to_owned())
                                }
                                on:change=on_boot_mode_change
                            >
                                <option value="">"Choose"</option>
                                {BootModeView::ALL
                                    .into_iter()
                                    .map(|m| view! { <option value=m.as_str()>{m.as_str()}</option> })
                                    .collect_view()}
                            </select>
                        </div>
                    </div>
                    <p
                        class="form-error"
                        hidden=move || {
                            field_error(OperationFormError::BootSourceRequired).is_empty()
                                && field_error(OperationFormError::BootEnabledRequired).is_empty()
                                && field_error(OperationFormError::BootModeRequired).is_empty()
                        }
                    >
                        {move || {
                            [
                                OperationFormError::BootSourceRequired,
                                OperationFormError::BootEnabledRequired,
                                OperationFormError::BootModeRequired,
                            ]
                            .into_iter()
                            .find_map(|candidate| {
                                let message = field_error(candidate);
                                if message.is_empty() { None } else { Some(message) }
                            })
                        }}
                    </p>
                </div>

                <div class="form-field" hidden=move || !family_selected(CommandFamilyView::SecureBoot)>
                    <label for="operation-secure-boot-action">"Action"</label>
                    <select
                        id="operation-secure-boot-action"
                        class="form-select"
                        prop:value=move || match draft.get().secure_boot_action {
                            Some(SecureBootActionView::Enable) => "enable".to_owned(),
                            Some(SecureBootActionView::Disable) => "disable".to_owned(),
                            Some(SecureBootActionView::ResetKeys(_)) => "reset-keys".to_owned(),
                            None => String::new(),
                        }
                        on:change=on_secure_boot_change
                    >
                        <option value="">"Choose an action"</option>
                        <option value="enable">{SecureBootActionView::Enable.label()}</option>
                        <option value="disable">{SecureBootActionView::Disable.label()}</option>
                        <option value="reset-keys">
                            {SecureBootActionView::ResetKeys(ResetKeysTypeView::DeleteAllKeys)
                                .label()}
                        </option>
                    </select>
                    <div class="form-field" hidden=move || !is_reset_keys()>
                        <label for="operation-reset-keys-type">"Key set"</label>
                        <select
                            id="operation-reset-keys-type"
                            class="form-select"
                            prop:value=move || {
                                draft
                                    .get()
                                    .reset_keys_type
                                    .map_or_else(String::new, |k| k.as_str().to_owned())
                            }
                            on:change=on_reset_keys_change
                        >
                            <option value="">"Choose a key set"</option>
                            {ResetKeysTypeView::ALL
                                .into_iter()
                                .map(|k| view! { <option value=k.as_str()>{k.as_str()}</option> })
                                .collect_view()}
                        </select>
                    </div>
                    <p
                        class="form-error"
                        hidden=move || {
                            field_error(OperationFormError::SecureBootActionRequired).is_empty()
                                && field_error(OperationFormError::ResetKeysTypeRequired).is_empty()
                        }
                    >
                        {move || {
                            [
                                OperationFormError::SecureBootActionRequired,
                                OperationFormError::ResetKeysTypeRequired,
                            ]
                            .into_iter()
                            .find_map(|candidate| {
                                let message = field_error(candidate);
                                if message.is_empty() { None } else { Some(message) }
                            })
                        }}
                    </p>
                </div>

                <div
                    class="form-field"
                    hidden=move || !family_selected(CommandFamilyView::EventSubscription)
                >
                    <label for="operation-event-action">"Action"</label>
                    <select
                        id="operation-event-action"
                        class="form-select"
                        prop:value=move || match draft.get().event_action {
                            Some(EventActionView::CreateSubscription) => "create".to_owned(),
                            Some(EventActionView::DeleteSubscription) => "delete".to_owned(),
                            None => String::new(),
                        }
                        on:change=on_event_action_change
                    >
                        <option value="">"Choose an action"</option>
                        {EventActionView::ALL
                            .into_iter()
                            .map(|action| {
                                let value = match action {
                                    EventActionView::CreateSubscription => "create",
                                    EventActionView::DeleteSubscription => "delete",
                                };
                                view! {
                                    <option value=value>{action.label()}</option>
                                }
                            })
                            .collect_view()}
                    </select>
                    <p
                        class="form-error"
                        hidden=move || field_error(OperationFormError::EventActionRequired).is_empty()
                    >
                        {OperationFormError::EventActionRequired.message()}
                    </p>

                    <div class="form-panel create-panel" hidden=move || !is_create_subscription()>
                        <div class="form-field">
                            <label for="operation-destination">"Destination URL"</label>
                            <input
                                id="operation-destination"
                                class="form-input"
                                type="text"
                                autocomplete="off"
                                placeholder="https://subscriber.example.test/events"
                                prop:value=move || draft.get().destination
                                on:input=on_destination_input
                            />
                            <p
                                class="form-error"
                                hidden=move || {
                                    field_error(OperationFormError::DestinationRequired).is_empty()
                                        && field_error(OperationFormError::DestinationInvalid).is_empty()
                                }
                            >
                                {move || {
                                    match error.get() {
                                        Some(
                                            error @ (OperationFormError::DestinationRequired
                                            | OperationFormError::DestinationInvalid),
                                        ) => error.message(),
                                        _ => "",
                                    }
                                }}
                            </p>
                        </div>
                        <div class="form-field">
                            <label for="operation-protocol">"Protocol"</label>
                            <select
                                id="operation-protocol"
                                class="form-select"
                                prop:value=move || {
                                    draft
                                        .get()
                                        .protocol
                                        .map_or_else(String::new, |p| p.as_str().to_owned())
                                }
                                on:change=on_protocol_change
                            >
                                <option value="">"Choose a protocol"</option>
                                {EventProtocolView::ALL
                                    .into_iter()
                                    .map(|p| view! { <option value=p.as_str()>{p.as_str()}</option> })
                                    .collect_view()}
                            </select>
                            <p
                                class="form-error"
                                hidden=move || field_error(OperationFormError::ProtocolRequired).is_empty()
                            >
                                {OperationFormError::ProtocolRequired.message()}
                            </p>
                        </div>
                        <p class="section-label">"Event types"</p>
                        <div class="command-choice-grid">
                            {EventTypeView::ALL
                                .into_iter()
                                .map(|kind| {
                                    let is_selected = move || {
                                        draft.get().event_types.contains(&kind)
                                    };
                                    let class = move || {
                                        if is_selected() {
                                            "command-choice is-selected"
                                        } else {
                                            "command-choice"
                                        }
                                    };
                                    view! {
                                        <button
                                            type="button"
                                            class=class
                                            on:click=move |_| on_toggle_event_type.run(kind)
                                        >
                                            <span class="command-choice-name">{kind.as_str()}</span>
                                        </button>
                                    }
                                })
                                .collect_view()}
                        </div>
                        <p
                            class="form-error"
                            hidden=move || field_error(OperationFormError::EventTypesRequired).is_empty()
                        >
                            {OperationFormError::EventTypesRequired.message()}
                        </p>
                    </div>

                    <div class="form-panel create-panel" hidden=move || !is_delete_subscription()>
                        <div class="form-field">
                            <label for="operation-subscription-id">"Subscription ID"</label>
                            <input
                                id="operation-subscription-id"
                                class="form-input"
                                type="text"
                                autocomplete="off"
                                placeholder="Sub-1"
                                prop:value=move || draft.get().subscription_id
                                on:input=on_subscription_id_input
                            />
                            <p
                                class="form-error"
                                hidden=move || {
                                    field_error(OperationFormError::SubscriptionIdRequired).is_empty()
                                }
                            >
                                {OperationFormError::SubscriptionIdRequired.message()}
                            </p>
                        </div>
                    </div>
                </div>

                <div
                    class="form-field"
                    hidden=move || !family_selected(CommandFamilyView::FirmwareUpdate)
                >
                    <label for="operation-update-artifact">"Firmware artifact"</label>
                    <select
                        id="operation-update-artifact"
                        class="form-select"
                        prop:value=move || draft.get().artifact_id.clone().unwrap_or_default()
                        on:change=on_update_artifact_change
                    >
                        <option value="">"Choose an artifact"</option>
                        {artifact_choices()
                            .into_iter()
                            .map(|choice| {
                                // The id is cloned before the template moves
                                // the display fields, mirroring the endpoint
                                // choice buttons.
                                let artifact_id = choice.artifact_id.clone();
                                view! {
                                    <option value=artifact_id>
                                        {format!("{} · {}", choice.name, choice.size_text)}
                                    </option>
                                }
                            })
                            .collect_view()}
                    </select>
                    <p class="form-hint">
                        "Only artifacts with a verified complete upload (Ready) can be dispatched."
                    </p>
                    <p
                        class="form-error"
                        hidden=move || field_error(OperationFormError::ArtifactRequired).is_empty()
                    >
                        {OperationFormError::ArtifactRequired.message()}
                    </p>
                    <p
                        class="inline-status"
                        hidden=move || !artifact_list_state.get().is_loading()
                    >
                        "Loading firmware artifacts..."
                    </p>
                    <p
                        class="form-error"
                        hidden=move || !artifact_list_state.get().is_failed()
                    >
                        "The firmware artifact list is temporarily unavailable."
                    </p>
                    <p
                        class="form-hint"
                        hidden=move || {
                            !artifact_list_state.get().is_ready() || !artifact_choices().is_empty()
                        }
                    >
                        "No ready firmware artifacts. Upload and finalize one in the Artifacts view."
                    </p>
                    <div class="form-field">
                        <label for="operation-update-push-uri">"Push URI (optional)"</label>
                        <input
                            id="operation-update-push-uri"
                            class="form-input"
                            type="text"
                            autocomplete="off"
                            placeholder="https://mirror.example.test/firmware.bin"
                            prop:value=move || draft.get().push_uri
                            on:input=on_update_push_uri_input
                        />
                        <p class="form-hint">
                            "Leave empty to dispatch the locally stored artifact as multipart upload."
                        </p>
                        <p
                            class="form-error"
                            hidden=move || field_error(OperationFormError::PushUriInvalid).is_empty()
                        >
                            {OperationFormError::PushUriInvalid.message()}
                        </p>
                    </div>
                </div>

                <div class="form-field" hidden=move || !family_selected(CommandFamilyView::Oem)>
                    <div class="form-field">
                        <label for="operation-oem-face">"OEM face"</label>
                        <select
                            id="operation-oem-face"
                            class="form-select"
                            prop:value=move || match draft.get().oem_face {
                                Some(OemFaceView::SystemConfigProfile) => {
                                    "system-config-profile".to_owned()
                                }
                                Some(OemFaceView::DebugToken) => "debug-token".to_owned(),
                                Some(OemFaceView::PowerSmoothing) => "power-smoothing".to_owned(),
                                None => String::new(),
                            }
                            on:change=on_oem_face_change
                        >
                            <option value="">"Choose an OEM face"</option>
                            {OemFaceView::ALL
                                .into_iter()
                                .map(|face| {
                                    let value = match face {
                                        OemFaceView::SystemConfigProfile => {
                                            "system-config-profile"
                                        }
                                        OemFaceView::DebugToken => "debug-token",
                                        OemFaceView::PowerSmoothing => "power-smoothing",
                                    };
                                    view! { <option value=value>{face.label()}</option> }
                                })
                                .collect_view()}
                        </select>
                    </div>
                    <div class="form-field">
                        <label for="operation-oem-action">"Action"</label>
                        <select
                            id="operation-oem-action"
                            class="form-select"
                            prop:value=move || {
                                draft
                                    .get()
                                    .oem_action
                                    .map_or_else(String::new, |action| {
                                        oem_action_key(action).to_owned()
                                    })
                            }
                            on:change=on_oem_action_change
                        >
                            <option value="">"Choose an action"</option>
                            {OemActionView::ALL
                                .into_iter()
                                .filter(move |action| {
                                    draft
                                        .get()
                                        .oem_face
                                        .is_none_or(|face| action.face() == face)
                                })
                                .map(|action| {
                                    view! {
                                        <option value=oem_action_key(action)>{action.label()}</option>
                                    }
                                })
                                .collect_view()}
                        </select>
                        <p
                            class="form-error"
                            hidden=move || field_error(OperationFormError::OemActionRequired).is_empty()
                        >
                            {OperationFormError::OemActionRequired.message()}
                        </p>
                    </div>

                    <div class="form-panel create-panel" hidden=move || !oem_action_selected(OemActionView::ProfileUpdate)>
                        <div class="form-field">
                            <label for="operation-profile-file">"Profile file (JSON)"</label>
                            <textarea
                                id="operation-profile-file"
                                class="form-input"
                                rows="4"
                                placeholder=r#"{"UUID":"11111111-2222-3333-4444-555555555555"}"#
                                prop:value=move || draft.get().profile_file
                                on:input=on_profile_file_input
                            />
                            <p
                                class="form-error"
                                hidden=move || field_error(OperationFormError::ProfileFileRequired).is_empty()
                            >
                                {OperationFormError::ProfileFileRequired.message()}
                            </p>
                        </div>
                    </div>

                    <div class="form-panel create-panel" hidden=move || !oem_action_selected(OemActionView::TokenGenerate)>
                        <div class="form-field">
                            <label for="operation-token-type">"Token type"</label>
                            <select
                                id="operation-token-type"
                                class="form-select"
                                prop:value=move || {
                                    draft
                                        .get()
                                        .token_type
                                        .map_or_else(String::new, |t| t.as_str().to_owned())
                                }
                                on:change=on_token_type_change
                            >
                                <option value="">"Choose a token type"</option>
                                {TokenTypeView::ALL
                                    .into_iter()
                                    .map(|t| view! { <option value=t.as_str()>{t.as_str()}</option> })
                                    .collect_view()}
                            </select>
                            <p
                                class="form-error"
                                hidden=move || field_error(OperationFormError::TokenTypeRequired).is_empty()
                            >
                                {OperationFormError::TokenTypeRequired.message()}
                            </p>
                        </div>
                    </div>

                    <div class="form-panel create-panel" hidden=move || !oem_action_selected(OemActionView::TokenInstall)>
                        <div class="form-field">
                            <label for="operation-token-data">"Token data (Base64)"</label>
                            <input
                                id="operation-token-data"
                                class="form-input"
                                type="text"
                                autocomplete="off"
                                placeholder="dG9rZW4tZGF0YQ=="
                                prop:value=move || draft.get().token_data
                                on:input=on_token_data_input
                            />
                            <p
                                class="form-error"
                                hidden=move || field_error(OperationFormError::TokenDataRequired).is_empty()
                            >
                                {OperationFormError::TokenDataRequired.message()}
                            </p>
                        </div>
                    </div>

                    <div class="form-panel create-panel" hidden=move || !oem_action_selected(OemActionView::TokenErase)>
                        <div class="form-field">
                            <label for="operation-erase-type">"Erase scope"</label>
                            <select
                                id="operation-erase-type"
                                class="form-select"
                                prop:value=move || {
                                    draft
                                        .get()
                                        .erase_type
                                        .map_or_else(String::new, |e| e.as_str().to_owned())
                                }
                                on:change=on_erase_type_change
                            >
                                <option value="">"Choose an erase scope"</option>
                                {EraseTypeView::ALL
                                    .into_iter()
                                    .map(|e| view! { <option value=e.as_str()>{e.as_str()}</option> })
                                    .collect_view()}
                            </select>
                            <p
                                class="form-error"
                                hidden=move || field_error(OperationFormError::EraseTypeRequired).is_empty()
                            >
                                {OperationFormError::EraseTypeRequired.message()}
                            </p>
                        </div>
                        <div class="form-field">
                            <label for="operation-erase-token-type">"Token type"</label>
                            <select
                                id="operation-erase-token-type"
                                class="form-select"
                                prop:value=move || {
                                    draft
                                        .get()
                                        .token_type
                                        .map_or_else(String::new, |t| t.as_str().to_owned())
                                }
                                on:change=on_token_type_change
                            >
                                <option value="">"Choose a token type"</option>
                                {TokenTypeView::ALL
                                    .into_iter()
                                    .map(|t| view! { <option value=t.as_str()>{t.as_str()}</option> })
                                    .collect_view()}
                            </select>
                            <p
                                class="form-error"
                                hidden=move || field_error(OperationFormError::TokenTypeRequired).is_empty()
                            >
                                {OperationFormError::TokenTypeRequired.message()}
                            </p>
                        </div>
                    </div>

                    <div class="form-panel create-panel" hidden=move || !oem_action_selected(OemActionView::PowerActivatePreset)>
                        <div class="form-field">
                            <label for="operation-profile-id">"Preset profile id"</label>
                            <input
                                id="operation-profile-id"
                                class="form-input"
                                type="text"
                                autocomplete="off"
                                placeholder="3"
                                prop:value=move || draft.get().profile_id
                                on:input=on_profile_id_input
                            />
                            <p
                                class="form-error"
                                hidden=move || field_error(OperationFormError::ProfileIdInvalid).is_empty()
                            >
                                {OperationFormError::ProfileIdInvalid.message()}
                            </p>
                        </div>
                    </div>
                </div>

                <p class="form-hint" hidden=move || preview_text().is_empty()>
                    {move || preview_text()}
                </p>
                <div class="form-actions">
                    <button
                        type="button"
                        class="btn btn-primary"
                        disabled=move || submit_state.get().is_in_flight()
                        on:click=move |_| on_submit.run(())
                    >
                        "Submit operation"
                    </button>
                </div>
                <p
                    class="inline-status"
                    hidden=move || !submit_state.get().is_in_flight()
                >
                    "Submitting the operation..."
                </p>
                <p
                    class="inline-status success"
                    hidden=move || !submit_state.get().is_succeeded()
                >
                    "Operation submitted."
                </p>
                <p
                    class="inline-status error"
                    hidden=move || submit_state.get().failure_message().is_empty()
                >
                    {move || submit_state.get().failure_message()}
                </p>
            </div>
        }
    }

    #[component]
    fn OperationCard(card: OperationCardProjection) -> impl IntoView {
        let state_label = card.state_label();
        let state_class = card.state_class();
        let source_label = card.source_label();
        let OperationCardProjection {
            operation_id,
            short_id,
            target_count,
            command,
            created_at_text,
            updated_at_text,
            ..
        } = card;
        let command_family = command.family;
        let command_payload = command.payload;
        let operation_id_title = operation_id.clone();
        let targets_text = match target_count {
            1 => "1 target".to_owned(),
            _ => format!("{target_count} targets"),
        };

        view! {
            <article class="credential-card">
                <div class="operation-card-heading">
                    <div>
                        <h3>{command_family}</h3>
                        <p class="operation-card-id" title=operation_id_title>{short_id}</p>
                    </div>
                    <span class=state_class>{state_label}</span>
                </div>
                <p class="operation-command-summary">
                    <span>{source_label}</span>
                    {command_payload}
                </p>
                <dl class="resource-facts">
                    <div>
                        <dt>"Targets"</dt>
                        <dd>{targets_text}</dd>
                    </div>
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

    /// One §13.7 batch card: the server-derived verdict badge, the five
    /// outcome count chips, and the expandable per-endpoint rows.
    ///
    /// The verdict and the chips come from the list summary and are rendered
    /// verbatim; the per-endpoint rows are fetched once on first expand and
    /// pair each child with its endpoint's display name from the loaded
    /// inventory.
    #[component]
    fn BatchCard(
        card: BatchCardProjection,
        expanded: ReadSignal<BTreeSet<String>>,
        set_expanded: WriteSignal<BTreeSet<String>>,
        expanded_children: ReadSignal<HashMap<String, Vec<BatchChildRowProjection>>>,
        set_expanded_children: WriteSignal<HashMap<String, Vec<BatchChildRowProjection>>>,
        load_state: ReadSignal<ConsoleLoadState>,
    ) -> impl IntoView {
        let state_label = card.state_label();
        let state_class = card.state_class();
        let batch_id = card.batch_id.clone();
        let short_id = card.short_id.clone();
        let command_family = card.command.family;
        let command_payload = card.command.payload.clone();
        let created_at_text = card.created_at_text.clone();
        let chips = card.outcomes.chips().to_vec();
        let is_expanded = {
            let batch_id = batch_id.clone();
            move || expanded.with(|set| set.contains(&batch_id))
        };

        let on_toggle = {
            let batch_id = batch_id.clone();
            move |_| {
                // The containment check is inlined here (instead of calling
                // `is_expanded`) so the toggle closure never captures the
                // display closure; the view! macro needs `is_expanded` for
                // the badge state too.
                if expanded.with(|set| set.contains(&batch_id)) {
                    set_expanded.update(|set| {
                        set.remove(&batch_id);
                    });
                    return;
                }
                set_expanded.update(|set| {
                    set.insert(batch_id.clone());
                });
                // The full report is fetched once per session on first expand;
                // a failed fetch leaves the rows empty so a collapse/expand
                // retries.
                if !expanded_children.with(|rows| rows.contains_key(&batch_id)) {
                    let inventory = load_state.get();
                    let batch_id = batch_id.clone();
                    spawn_local(async move {
                        if let Some(detail) = fetch_batch_detail(&batch_id).await {
                            let children = match &inventory {
                                ConsoleLoadState::Ready(data) => {
                                    batch_children_projection(&detail, &data.inventory)
                                }
                                ConsoleLoadState::Loading | ConsoleLoadState::Failed(_) => {
                                    Vec::new()
                                }
                            };
                            set_expanded_children.update(|rows| {
                                rows.insert(batch_id, children);
                            });
                        }
                    });
                }
            }
        };

        let rows = {
            let batch_id = batch_id.clone();
            move || {
                expanded_children
                    .get()
                    .get(&batch_id)
                    .cloned()
                    .unwrap_or_default()
            }
        };

        // The display closure is cloned per use: the view! macro's inline
        // closures each move-capture their own copy, and the toggle closure
        // above deliberately does not capture it.
        let expand_aria = {
            let is_expanded = is_expanded.clone();
            move || is_expanded()
        };
        let expand_label = {
            let is_expanded = is_expanded.clone();
            move || {
                if is_expanded() {
                    "Hide endpoints"
                } else {
                    "Show endpoints"
                }
            }
        };
        let children_hidden = {
            let is_expanded = is_expanded.clone();
            move || !is_expanded()
        };

        view! {
            <article class="credential-card">
                <div class="operation-card-heading">
                    <div>
                        <h3>{command_family}</h3>
                        <p class="operation-card-id">{short_id}</p>
                    </div>
                    <span class=state_class>{state_label}</span>
                </div>
                <p class="operation-command-summary">{command_payload}</p>
                <div class="batch-outcome-chips">
                    {chips
                        .iter()
                        .map(|chip| {
                            view! {
                                <span class=chip.class>
                                    {format!("{} · {}", chip.label, chip.count)}
                                </span>
                            }
                        })
                        .collect_view()}
                </div>
                <dl class="resource-facts">
                    <div>
                        <dt>"Created"</dt>
                        <dd>{created_at_text}</dd>
                    </div>
                </dl>
                <button
                    type="button"
                    class="btn"
                    on:click=on_toggle
                    aria-expanded=expand_aria
                >
                    {expand_label}
                </button>
                <div class="batch-children" hidden=children_hidden>
                    {move || {
                        rows()
                            .into_iter()
                            .map(|row| {
                                let child_state_label = row.state.label();
                                let child_state_class = row.state.class();
                                view! {
                                    <div class="batch-child-row">
                                        <span class="batch-child-endpoint">{row.display_name}</span>
                                        <span class=child_state_class>{child_state_label}</span>
                                    </div>
                                }
                            })
                            .collect_view()
                    }}
                </div>
            </article>
        }
    }

    #[component]
    fn ArtifactsView(view: ReadSignal<ConsoleView>) -> impl IntoView {
        let active = move || view.get() == ConsoleView::Artifacts;
        let (list_state, set_list_state) = signal(ArtifactsListState::Loading);
        let (list_triggered, set_list_triggered) = signal(false);
        let (file_info, set_file_info) = signal(None::<(String, u64)>);
        // The file bytes stay outside the reactive view surface: the form
        // renders name and size, while the submit path reads the bytes once
        // and drops the signal copy so only the upload future holds the
        // file during the chunk loop.
        //
        // Holding the whole file in browser memory is deliberate for this
        // iteration: the §0.4.0 chunk contract needs the base64 encoding of
        // arbitrary byte ranges, and re-reading a `File` slice per chunk is a
        // later iteration together with the `File.slice()`-driven streaming
        // upload path, which must land with its own progress semantics and
        // chunk-alignment tests. The memory ceiling is the selected file
        // size, and the one-shot copy at submit time is bounded and dropped
        // as soon as the upload future owns the bytes.
        let (file_bytes, set_file_bytes) = signal(None::<Vec<u8>>);
        let (resume_target, set_resume_target) = signal(None::<ArtifactCardProjection>);
        let (upload_state, set_upload_state) = signal(ArtifactUploadState::Idle);

        Effect::new(move |_| {
            if active() && !list_triggered.get() {
                set_list_triggered.set(true);
                set_list_state.set(ArtifactsListState::Loading);
                spawn_local(async move {
                    set_list_state.set(fetch_artifacts().await);
                });
            }
        });

        let on_refresh = move |_| {
            set_list_state.set(ArtifactsListState::Loading);
            spawn_local(async move {
                set_list_state.set(fetch_artifacts().await);
            });
        };

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
            set_upload_state.set(ArtifactUploadState::Idle);
            let file_name = selected_file_name(&file);
            spawn_local(async move {
                match read_blob_bytes(&file).await {
                    Some(bytes) if bytes.is_empty() => {
                        set_upload_state.set(ArtifactUploadState::Failed(
                            ArtifactUploadFailure::FileEmpty,
                        ));
                    }
                    Some(bytes) => {
                        let size_bytes = u64::try_from(bytes.len()).ok().unwrap_or(0);
                        // A selected file that matches an interrupted
                        // artifact by name and size arms the §0.4.0 resume
                        // path instead of a fresh create.
                        let candidate = list_state.get().resume_candidate(&file_name, size_bytes);
                        set_file_info.set(Some((file_name, size_bytes)));
                        set_file_bytes.set(Some(bytes));
                        set_resume_target.set(candidate);
                    }
                    None => {
                        set_upload_state.set(ArtifactUploadState::Failed(
                            ArtifactUploadFailure::FileUnreadable,
                        ));
                    }
                }
            });
        };

        let on_submit = move |_| {
            let Some((name, _)) = file_info.get() else {
                return;
            };
            let Some(bytes) = file_bytes.get() else {
                return;
            };
            let resume = resume_target.get();
            // The upload future now owns the only copy of the file bytes.
            set_file_bytes.set(None);
            set_upload_state.set(ArtifactUploadState::Creating);
            let report = {
                let set_upload_state = set_upload_state;
                move |state| set_upload_state.set(state)
            };
            spawn_local(async move {
                match run_artifact_upload(&name, &bytes, resume, report).await {
                    Ok(()) => {
                        set_upload_state.set(ArtifactUploadState::Succeeded);
                        set_file_info.set(None);
                        set_resume_target.set(None);
                        set_list_state.set(fetch_artifacts().await);
                    }
                    Err(failure) => {
                        set_upload_state.set(ArtifactUploadState::Failed(failure));
                        // Refresh the list so the interrupted artifact's card
                        // shows the server's acknowledged progress (the
                        // resume anchor) or its terminal failed state.
                        set_list_state.set(fetch_artifacts().await);
                    }
                }
            });
        };

        view! {
            <section class="view-section" hidden=move || !active()>
                <div class="inventory-heading">
                    <div>
                        <p class="section-label">"Firmware artifacts"</p>
                        <h2>{move || list_state.get().count_text()}</h2>
                    </div>
                    <p>"Uploaded firmware artifacts for the §14.3 update flow."</p>
                </div>
                <div class="inventory-actions">
                    <button
                        type="button"
                        class="btn"
                        disabled=move || list_state.get().is_loading()
                        on:click=on_refresh
                    >
                        "Refresh"
                    </button>
                </div>
                <p class="inline-status" hidden=move || !list_state.get().is_loading()>
                    "Loading artifacts..."
                </p>
                <p class="form-error" hidden=move || !list_state.get().is_failed()>
                    "The artifact store is temporarily unavailable."
                </p>
                <p
                    class="empty-inventory"
                    hidden=move || {
                        !list_state.get().is_ready() || !list_state.get().has_empty_list()
                    }
                >
                    "No firmware artifacts have been uploaded yet."
                </p>
                <div class="resource-list">
                    {move || {
                        list_state
                            .get()
                            .cards()
                            .into_iter()
                            .map(|card| view! { <ArtifactCard card=card /> })
                            .collect_view()
                    }}
                </div>
                <div class="form-panel">
                    <div class="form-field">
                        <label for="artifact-file">"Firmware file"</label>
                        <input
                            id="artifact-file"
                            class="form-input"
                            type="file"
                            on:change=on_file_change
                        />
                    </div>
                    <p class="form-hint" hidden=move || file_info.get().is_none()>
                        {move || {
                            file_info.get().map_or_else(String::new, |(name, size)| {
                                format!("Selected: {name} · {}", format_artifact_size(size))
                            })
                        }}
                    </p>
                    <p class="form-hint" hidden=move || resume_target.get().is_none()>
                        {move || {
                            resume_target.get().map_or_else(String::new, |card| {
                                format!(
                                    "Resumes the interrupted upload of this file from {}%.",
                                    card.progress_percent
                                )
                            })
                        }}
                    </p>
                    <p class="form-error" hidden=move || !upload_state.get().is_failed()>
                        {move || upload_state.get().failure_message()}
                    </p>
                    <p class="inline-status" hidden=move || !upload_state.get().is_in_flight()>
                        {move || artifact_upload_status_text(&upload_state.get())}
                    </p>
                    <p
                        class="inline-status success"
                        hidden=move || !upload_state.get().is_succeeded()
                    >
                        "Artifact uploaded and verified."
                    </p>
                    <div class="form-actions">
                        <button
                            type="button"
                            class="btn btn-primary"
                            disabled=move || {
                                file_info.get().is_none() || upload_state.get().is_in_flight()
                            }
                            on:click=on_submit
                        >
                            {move || {
                                if resume_target.get().is_some() {
                                    "Resume upload"
                                } else {
                                    "Upload artifact"
                                }
                            }}
                        </button>
                    </div>
                </div>
            </section>
        }
    }

    #[component]
    fn ArtifactCard(card: ArtifactCardProjection) -> impl IntoView {
        let is_uploading = card.is_uploading();
        let is_failed = card.status == ArtifactStatusView::Failed;
        let status_label = card.status_label().to_owned();
        let status_class = card.status_class().to_owned();
        let ArtifactCardProjection {
            artifact_id,
            short_id,
            name,
            size_text,
            sha256_short,
            uploaded_bytes,
            progress_percent,
            created_at_text,
            ..
        } = card;
        let progress_width = format!("{progress_percent}%");
        let uploaded_text = format_artifact_size(uploaded_bytes);
        let sha256_title = sha256_short.clone();
        let sha256_text = format!("{sha256_short}…");

        view! {
            <article class="artifact-card">
                <div class="artifact-title">
                    <div>
                        <h3>{name}</h3>
                        <p class="artifact-id" title=artifact_id>{short_id}</p>
                    </div>
                    <span class=status_class>{status_label}</span>
                </div>
                <dl class="resource-facts">
                    <div>
                        <dt>"Size"</dt>
                        <dd>{size_text.clone()}</dd>
                    </div>
                    <div>
                        <dt>"SHA-256"</dt>
                        <dd title=sha256_title>{sha256_text}</dd>
                    </div>
                    <div>
                        <dt>"Created"</dt>
                        <dd>{created_at_text}</dd>
                    </div>
                </dl>
                <div class="artifact-progress" hidden=!is_uploading>
                    <div class="progress-track" aria-hidden="true">
                        <div class="progress-fill" style=("width", progress_width)></div>
                    </div>
                    <p class="form-hint">
                        {format!("{uploaded_text} of {size_text} uploaded · {progress_percent}%")}
                    </p>
                    <p class="form-hint">
                        "Select the same file in the upload form to resume from this point."
                    </p>
                </div>
                <p class="form-error" hidden=!is_failed>
                    "The uploaded bytes did not pass SHA-256 verification."
                </p>
            </article>
        }
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

        // The artifact upload reads firmware bytes, so the binary Blob
        // surface is bound here: `arrayBuffer` (the CSV path's `text` cannot
        // represent arbitrary bytes) and `Uint8Array`, whose type is not in
        // the enabled `web-sys` feature set. `Vec<u8>` is wasm-bindgen's
        // `Uint8Array` wire type, so the `slice` binding copies the whole
        // typed array into Rust in one boundary crossing instead of one JS
        // call per byte.
        #[wasm_bindgen(typescript_type = "Blob")]
        type BlobBinaryHandle;

        #[wasm_bindgen(method, structural, js_class = "Blob", js_name = "arrayBuffer")]
        fn array_buffer(this: &BlobBinaryHandle) -> JsValue;

        #[wasm_bindgen(js_name = "Uint8Array")]
        type Uint8ArrayHandle;

        #[wasm_bindgen(constructor)]
        fn new_uint8_array(buffer: &JsValue) -> Uint8ArrayHandle;

        #[wasm_bindgen(method, structural, js_name = "slice")]
        fn copy_to_vec(this: &Uint8ArrayHandle) -> Vec<u8>;
    }

    /// Starts the `arrayBuffer()` promise of one `Blob`.
    fn blob_array_buffer(file: &Blob) -> JsValue {
        file.unchecked_ref::<BlobBinaryHandle>().array_buffer()
    }

    /// Reads the full binary content of a `Blob` as `Vec<u8>`.
    ///
    /// The CSV import path reads `Blob::text()` because CSV is text;
    /// firmware files are binary, so this path awaits `arrayBuffer()` and
    /// copies the resulting `Uint8Array` into Rust. An empty result is
    /// returned as an empty vector; the caller maps it to the "empty file"
    /// validation.
    async fn read_blob_bytes(file: &Blob) -> Option<Vec<u8>> {
        // `leptos::web_sys` re-exports `js_sys` unconditionally, so the
        // promise wrapper is reachable without a direct `js-sys` dependency;
        // the value is a real JS Promise, so the unchecked cast is sound.
        let promise = blob_array_buffer(file).unchecked_into::<leptos::web_sys::js_sys::Promise>();
        let buffer = JsFuture::from(promise).await.ok()?;
        let bytes = Uint8ArrayHandle::new_uint8_array(&buffer);
        Some(bytes.copy_to_vec())
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

    use rutilus_api::{
        CenterEndpointViewListResponse, CenterOperationListResponse, CenterOperationSubmitRequest,
        CenterSitesResponse, TelemetrySeriesListResponse,
    };
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
                            manager_resource(),
                            processor_resource(),
                            memory_resource(),
                            storage_resource(),
                            network_adapter_resource(),
                            ethernet_interface_resource(),
                            account_resource(),
                            bios_resource(),
                            boot_option_resource(),
                            secure_boot_resource(),
                            power_resource(),
                            thermal_resource(),
                            sensor_resource(),
                            control_resource(),
                            log_service_resource(),
                            manager_network_protocol_resource(),
                            host_interface_resource(),
                            pcie_device_resource(),
                            assembly_resource(),
                            software_inventory_resource(),
                            event_service_resource(),
                            event_subscription_resource(),
                            telemetry_service_resource(),
                            metric_definition_resource(),
                            metric_report_resource(),
                            task_service_resource(),
                            task_resource()
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

    fn processor_resource() -> serde_json::Value {
        json!({
            "source": {
                "resource_id": "01989abc-def0-7abc-8def-0123456789d4",
                "odata_id": "/redfish/v1/Systems/1/Processors/CPU1",
                "odata_type": "#Processor.v1_15_0.Processor",
                "etag": "W/\"cpu-7\""
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
                    "model": "Model P",
                    "total_cores": 64,
                    "status": {
                        "state": "Enabled",
                        "health": "OK",
                        "health_rollup": "OK"
                    }
                }
            }
        })
    }

    fn memory_resource() -> serde_json::Value {
        json!({
            "source": {
                "resource_id": "01989abc-def0-7abc-8def-0123456789d5",
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
                    "model": "Model MEM",
                    "status": {
                        "state": "Enabled",
                        "health": "OK",
                        "health_rollup": null
                    }
                }
            }
        })
    }

    fn storage_resource() -> serde_json::Value {
        json!({
            "source": {
                "resource_id": "01989abc-def0-7abc-8def-0123456789d6",
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
    }

    fn network_adapter_resource() -> serde_json::Value {
        json!({
            "source": {
                "resource_id": "01989abc-def0-7abc-8def-0123456789d7",
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
    }

    fn account_resource() -> serde_json::Value {
        json!({
            "source": {
                "resource_id": "01989abc-def0-7abc-8def-0123456789d9",
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
    }

    fn bios_resource() -> serde_json::Value {
        json!({
            "source": {
                "resource_id": "01989abc-def0-7abc-8def-0123456789da",
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
    }

    fn boot_option_resource() -> serde_json::Value {
        json!({
            "source": {
                "resource_id": "01989abc-def0-7abc-8def-0123456789db",
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
    }

    fn secure_boot_resource() -> serde_json::Value {
        json!({
            "source": {
                "resource_id": "01989abc-def0-7abc-8def-0123456789dc",
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
    }

    fn ethernet_interface_resource() -> serde_json::Value {
        json!({
            "source": {
                "resource_id": "01989abc-def0-7abc-8def-0123456789d8",
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
    }

    /// The §2.1 capability ledger in design-document order: product code,
    /// upstream feature, and wire `ui_location` value of the shared contract.
    const LEDGER_FIXTURE: [(&str, &str, &str); 30] = [
        ("accounts", "accounts", "accounts"),
        ("assembly", "assembly", "assembly"),
        ("bios", "bios", "bios"),
        ("boot-options", "boot-options", "boot"),
        ("chassis", "chassis", "chassis"),
        ("systems", "computer-systems", "systems"),
        ("controls", "controls", "power"),
        ("environment-metrics", "environment-metrics", "sensors"),
        ("ethernet-interfaces", "ethernet-interfaces", "network"),
        ("event-service", "event-service", "events"),
        ("host-interfaces", "host-interfaces", "network"),
        ("log-services", "log-services", "logs"),
        (
            "manager-network-protocol",
            "manager-network-protocol",
            "managers",
        ),
        ("managers", "managers", "managers"),
        ("memory", "memory", "memory"),
        ("network-adapters", "network-adapters", "network"),
        (
            "network-device-functions",
            "network-device-functions",
            "network",
        ),
        ("pcie-devices", "pcie-devices", "pcie"),
        ("power", "power", "power"),
        ("power-equipment", "power-equipment", "power"),
        ("power-supplies", "power-supplies", "power"),
        ("processors", "processors", "processors"),
        ("secure-boot", "secure-boot", "secure_boot"),
        ("sensors", "sensors", "sensors"),
        ("session-service", "session-service", "infrastructure"),
        ("storages", "storages", "storage"),
        ("task-service", "task-service", "tasks"),
        ("telemetry-service", "telemetry-service", "telemetry"),
        ("thermal", "thermal", "thermal"),
        ("update-service", "update-service", "update"),
    ];

    /// Wire classification for one capability code, mirroring the shared
    /// contract: session and task services are infrastructure.
    fn fixture_classification(capability: &str) -> &'static str {
        match capability {
            "session-service" | "task-service" => "infrastructure",
            _ => "user_facing",
        }
    }

    fn ledger_entries(states: &[Option<&str>]) -> Vec<serde_json::Value> {
        LEDGER_FIXTURE
            .iter()
            .enumerate()
            .map(|(index, &(capability, feature, location))| {
                let state = states.get(index).copied().flatten();
                json!({
                    "capability": capability,
                    "upstream_feature": feature,
                    "classification": fixture_classification(capability),
                    "ui_location": location,
                    "state": state,
                    "observed_at": state.map(|_| "2026-08-05T09:12:13Z")
                })
            })
            .collect()
    }

    /// The 14 OEM capability entries the nv-redfish baseline compiles
    /// (infra-redfish `COMPILED_OEM_FEATURES`), as (product code, upstream
    /// feature) pairs in feature order. The ledger lands them under the
    /// §12.2 OEM page (`ui_location = "oem"`), so the capability page must
    /// render exactly this set under the OEM group.
    const OEM_LEDGER_FIXTURE: [(&str, &str); 14] = [
        ("oem-ami", "oem-ami"),
        ("oem-dell", "oem-dell"),
        ("oem-dell-attributes", "oem-dell-attributes"),
        ("oem-delta", "oem-delta"),
        ("oem-hpe", "oem-hpe"),
        ("oem-lenovo", "oem-lenovo"),
        ("oem-liteon", "oem-liteon"),
        ("oem-nvidia", "oem-nvidia"),
        ("oem-nvidia-cper", "oem-nvidia-cper"),
        ("oem-nvidia-fabrics", "oem-nvidia-fabrics"),
        ("oem-nvidia-power-management", "oem-nvidia-power-management"),
        ("oem-nvidia-profiles", "oem-nvidia-profiles"),
        ("oem-nvidia-security", "oem-nvidia-security"),
        ("oem-supermicro", "oem-supermicro"),
    ];

    fn oem_ledger_entries(states: &[Option<&str>]) -> Vec<serde_json::Value> {
        OEM_LEDGER_FIXTURE
            .iter()
            .enumerate()
            .map(|(index, &(capability, feature))| {
                let state = states.get(index).copied().flatten();
                json!({
                    "capability": capability,
                    "upstream_feature": feature,
                    "classification": "user_facing",
                    "ui_location": "oem",
                    "state": state,
                    "observed_at": state.map(|_| "2026-08-05T09:12:13Z")
                })
            })
            .collect()
    }

    fn oem_dell_resource() -> serde_json::Value {
        json!({
            "source": {
                "resource_id": "01989abc-def0-7abc-8def-0123456789d8",
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
    }

    fn oem_smc_sys_lockdown_resource() -> serde_json::Value {
        json!({
            "source": {
                "resource_id": "01989abc-def0-7abc-8def-0123456789da",
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
    }

    fn oem_smc_kcs_interface_resource() -> serde_json::Value {
        json!({
            "source": {
                "resource_id": "01989abc-def0-7abc-8def-0123456789db",
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
                    "privilege": "Operator"
                }
            }
        })
    }

    fn oem_lenovo_security_service_resource() -> serde_json::Value {
        json!({
            "source": {
                "resource_id": "01989abc-def0-7abc-8def-0123456789ed",
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
    }

    fn oem_nvidia_system_config_profile_resource() -> serde_json::Value {
        json!({
            "source": {
                "resource_id": "01989abc-def0-7abc-8def-0123456789e4",
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
    }

    fn oem_nvidia_system_config_profile_status_resource() -> serde_json::Value {
        json!({
            "source": {
                "resource_id": "01989abc-def0-7abc-8def-0123456789e5",
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
    }

    fn oem_nvidia_system_profile_resource() -> serde_json::Value {
        json!({
            "source": {
                "resource_id": "01989abc-def0-7abc-8def-0123456789e6",
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
    }

    fn oem_nvidia_system_profile_file_resource() -> serde_json::Value {
        json!({
            "source": {
                "resource_id": "01989abc-def0-7abc-8def-0123456789e7",
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
    }

    fn oem_nvidia_power_compliance_resource() -> serde_json::Value {
        json!({
            "source": {
                "resource_id": "01989abc-def0-7abc-8def-0123456789f0",
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
    }

    fn oem_nvidia_power_domain_resource() -> serde_json::Value {
        json!({
            "source": {
                "resource_id": "01989abc-def0-7abc-8def-0123456789f1",
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
    }

    fn oem_nvidia_power_policy_resource() -> serde_json::Value {
        json!({
            "source": {
                "resource_id": "01989abc-def0-7abc-8def-0123456789f2",
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
    }

    fn oem_nvidia_managed_entity_group_resource() -> serde_json::Value {
        json!({
            "source": {
                "resource_id": "01989abc-def0-7abc-8def-0123456789f3",
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
    }

    fn oem_nvidia_power_state_group_resource() -> serde_json::Value {
        json!({
            "source": {
                "resource_id": "01989abc-def0-7abc-8def-0123456789f4",
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
    }

    fn oem_nvidia_psc_state_resource() -> serde_json::Value {
        json!({
            "source": {
                "resource_id": "01989abc-def0-7abc-8def-0123456789f5",
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
    }

    fn oem_nvidia_psu_state_resource() -> serde_json::Value {
        json!({
            "source": {
                "resource_id": "01989abc-def0-7abc-8def-0123456789f6",
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
    }

    fn oem_nvidia_psu_redundancy_resource() -> serde_json::Value {
        json!({
            "source": {
                "resource_id": "01989abc-def0-7abc-8def-0123456789f7",
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
    }

    fn oem_nvidia_managed_entity_resource() -> serde_json::Value {
        json!({
            "source": {
                "resource_id": "01989abc-def0-7abc-8def-0123456789f8",
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
    }

    fn capability_inventory_with_oem(
        standard_states: &[Option<&str>],
        oem_states: &[Option<&str>],
    ) -> Result<EndpointCapabilityInventoryResponse, serde_json::Error> {
        let mut entries = ledger_entries(standard_states);
        entries.extend(oem_ledger_entries(oem_states));
        serde_json::from_value(json!({
            "endpoint_id": "01989abc-def0-7abc-8def-0123456789e1",
            "entries": entries,
        }))
    }

    fn power_resource() -> serde_json::Value {
        json!({
            "source": {
                "resource_id": "01989abc-def0-7abc-8def-0123456789dd",
                "odata_id": "/redfish/v1/Chassis/1/Power",
                "odata_type": "#Power.v1_17_0.Power",
                "etag": "W/\"power-1\""
            },
            "common": {
                "id": "Power",
                "name": "Power",
                "description": "Chassis power control"
            },
            "resource": {
                "resource_type": "power",
                "details": {}
            }
        })
    }

    fn thermal_resource() -> serde_json::Value {
        json!({
            "source": {
                "resource_id": "01989abc-def0-7abc-8def-0123456789de",
                "odata_id": "/redfish/v1/Chassis/1/Thermal",
                "odata_type": "#Thermal.v1_7_2.Thermal",
                "etag": "W/\"thermal-1\""
            },
            "common": {
                "id": "Thermal",
                "name": "Thermal",
                "description": "Chassis temperature and fan monitoring"
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
    }

    fn sensor_resource() -> serde_json::Value {
        json!({
            "source": {
                "resource_id": "01989abc-def0-7abc-8def-0123456789df",
                "odata_id": "/redfish/v1/Chassis/1/Sensors/InletTemp",
                "odata_type": "#Sensor.v1_9_0.Sensor",
                "etag": "W/\"sensor-inlet-1\""
            },
            "common": {
                "id": "InletTemp",
                "name": "Chassis Inlet Temperature",
                "description": null
            },
            "resource": {
                "resource_type": "sensor",
                "details": {
                    "reading_type": "Temperature",
                    "reading": 27.5,
                    "reading_units": "Cel",
                    "status": {
                        "state": "Enabled",
                        "health": "OK",
                        "health_rollup": "OK"
                    }
                }
            }
        })
    }

    fn control_resource() -> serde_json::Value {
        json!({
            "source": {
                "resource_id": "01989abc-def0-7abc-8def-0123456789e0",
                "odata_id": "/redfish/v1/Chassis/1/Controls/FanDuty",
                "odata_type": "#Control.v1_3_0.Control",
                "etag": "W/\"control-fan-1\""
            },
            "common": {
                "id": "FanDuty",
                "name": "Chassis Fan Duty",
                "description": null
            },
            "resource": {
                "resource_type": "control",
                "details": {
                    "control_type": "DutyCycle",
                    "set_point": 30.0,
                    "status": {
                        "state": "Enabled",
                        "health": "OK",
                        "health_rollup": "OK"
                    }
                }
            }
        })
    }

    fn log_service_resource() -> serde_json::Value {
        json!({
            "source": {
                "resource_id": "01989abc-def0-7abc-8def-0123456789e2",
                "odata_id": "/redfish/v1/Managers/1/LogServices/1",
                "odata_type": "#LogService.v1_9_0.LogService",
                "etag": "W/\"log-service-1\""
            },
            "common": {
                "id": "1",
                "name": "BMC Event Log",
                "description": "Manager event log"
            },
            "resource": {
                "resource_type": "log_service",
                "details": {
                    "service_enabled": true,
                    "max_log_entries": 1000,
                    "status": {
                        "state": "Enabled",
                        "health": "OK",
                        "health_rollup": "OK"
                    }
                }
            }
        })
    }

    fn manager_network_protocol_resource() -> serde_json::Value {
        json!({
            "source": {
                "resource_id": "01989abc-def0-7abc-8def-0123456789e3",
                "odata_id": "/redfish/v1/Managers/1/NetworkProtocol",
                "odata_type": "#ManagerNetworkProtocol.v1_12_0.ManagerNetworkProtocol",
                "etag": "W/\"network-protocol-1\""
            },
            "common": {
                "id": "NetworkProtocol",
                "name": "Manager Network Protocol",
                "description": null
            },
            "resource": {
                "resource_type": "manager_network_protocol",
                "details": {
                    "host_name": "bmc-1",
                    "fqdn": "bmc-1.example.com",
                    "status": {
                        "state": "Enabled",
                        "health": "OK",
                        "health_rollup": "OK"
                    }
                }
            }
        })
    }

    fn host_interface_resource() -> serde_json::Value {
        json!({
            "source": {
                "resource_id": "01989abc-def0-7abc-8def-0123456789e4",
                "odata_id": "/redfish/v1/Managers/1/HostInterfaces/1",
                "odata_type": "#HostInterface.v1_3_3.HostInterface",
                "etag": "W/\"host-interface-1\""
            },
            "common": {
                "id": "1",
                "name": "Host Interface One",
                "description": "Manager host interface"
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
    }

    fn pcie_device_resource() -> serde_json::Value {
        json!({
            "source": {
                "resource_id": "01989abc-def0-7abc-8def-0123456789e3",
                "odata_id": "/redfish/v1/Systems/1/PCIeDevices/GPU1",
                "odata_type": "#PCIeDevice.v1_12_0.PCIeDevice",
                "etag": "W/\"pcie-device-1\""
            },
            "common": {
                "id": "GPU1",
                "name": "PCIe Device One",
                "description": "GPU accelerator"
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
    }

    fn assembly_resource() -> serde_json::Value {
        json!({
            "source": {
                "resource_id": "01989abc-def0-7abc-8def-0123456789e4",
                "odata_id": "/redfish/v1/Chassis/1/Assembly#/Assemblies/0",
                "odata_type": "#Assembly.v1_5_0.AssemblyData",
                "etag": "W/\"assembly-data-0\""
            },
            "common": {
                "id": "0",
                "name": "Fan Assembly",
                "description": "Cooling fan"
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
    }

    fn software_inventory_resource() -> serde_json::Value {
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
                "description": "Host firmware"
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
    }

    fn event_service_resource() -> serde_json::Value {
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
    }

    fn event_subscription_resource() -> serde_json::Value {
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
    }

    fn telemetry_service_resource() -> serde_json::Value {
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
    }

    fn metric_definition_resource() -> serde_json::Value {
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
    }

    fn metric_report_resource() -> serde_json::Value {
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
                            "value": "32.0"
                        }
                    ]
                }
            }
        })
    }

    fn task_service_resource() -> serde_json::Value {
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
    }

    fn task_resource() -> serde_json::Value {
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
    }

    fn capability_inventory(
        states: &[Option<&str>],
    ) -> Result<EndpointCapabilityInventoryResponse, serde_json::Error> {
        serde_json::from_value(json!({
            "endpoint_id": "01989abc-def0-7abc-8def-0123456789e1",
            "entries": ledger_entries(states),
        }))
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
        // The complete fixture tree carries every typed family: the 0.1
        // triad, the 0.2 configuration, storage/network, telemetry, and
        // manager surfaces, plus the pcie-devices, assembly,
        // software-inventory, event, telemetry-service, and task read
        // families.
        assert_eq!(current.resources.len(), 30);
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
        let processor = current
            .resources
            .iter()
            .find(|resource| resource.type_label == "Processor")
            .ok_or("processor resource must exist")?;
        assert_eq!(processor.name, "Processor One");
        assert_eq!(processor.source, "/redfish/v1/Systems/1/Processors/CPU1");
        assert!(processor.facts.contains(&ResourceFactProjection {
            label: "Processor type",
            value: "CPU".to_owned(),
        }));
        assert!(processor.facts.contains(&ResourceFactProjection {
            label: "Socket",
            value: "LGA4189".to_owned(),
        }));
        assert!(processor.facts.contains(&ResourceFactProjection {
            label: "Total cores",
            value: "64".to_owned(),
        }));
        assert!(
            !processor
                .facts
                .iter()
                .any(|fact| fact.label == "Part number")
        );
        let memory = current
            .resources
            .iter()
            .find(|resource| resource.type_label == "Memory")
            .ok_or("memory resource must exist")?;
        assert_eq!(memory.name, "Memory Module One");
        assert_eq!(memory.source, "/redfish/v1/Systems/1/Memory/DIMM1");
        assert!(memory.facts.contains(&ResourceFactProjection {
            label: "Memory device type",
            value: "DDR4".to_owned(),
        }));
        assert!(memory.facts.contains(&ResourceFactProjection {
            label: "Capacity (MiB)",
            value: "32768".to_owned(),
        }));
        assert!(memory.facts.contains(&ResourceFactProjection {
            label: "Manufacturer",
            value: "Vendor B".to_owned(),
        }));
        assert!(memory.facts.contains(&ResourceFactProjection {
            label: "Health",
            value: "OK".to_owned(),
        }));
        Ok(())
    }

    #[test]
    fn processor_and_memory_cards_keep_the_counts_summary_unchanged() -> Result<(), Box<dyn Error>>
    {
        let current =
            ConsoleLoadState::accepted(about(PRODUCT_ID), inventory()?, resource_inventories()?)
                .endpoint_cards()
                .into_iter()
                .find(|card| card.resource_counts.is_some())
                .ok_or("current endpoint card must exist")?;

        assert_eq!(
            current.resource_counts,
            Some(ResourceCountsProjection {
                systems: 1,
                chassis: 1,
                managers: 1,
            })
        );
        assert_eq!(
            current
                .resources
                .iter()
                .filter(|resource| resource.type_label == "Processor")
                .count(),
            1
        );
        assert_eq!(
            current
                .resources
                .iter()
                .filter(|resource| resource.type_label == "Memory")
                .count(),
            1
        );
        Ok(())
    }

    #[test]
    fn storage_network_and_ethernet_cards_render_family_facts() -> Result<(), Box<dyn Error>> {
        let current =
            ConsoleLoadState::accepted(about(PRODUCT_ID), inventory()?, resource_inventories()?)
                .endpoint_cards()
                .into_iter()
                .find(|card| card.resource_counts.is_some())
                .ok_or("current endpoint card must exist")?;

        let storage = current
            .resources
            .iter()
            .find(|resource| resource.type_label == "Storage")
            .ok_or("storage resource must exist")?;
        assert_eq!(storage.name, "Storage Subsystem One");
        assert_eq!(storage.source, "/redfish/v1/Systems/1/Storage/SATA-1");
        assert!(storage.facts.contains(&ResourceFactProjection {
            label: "Controller count",
            value: "2".to_owned(),
        }));
        assert!(storage.facts.contains(&ResourceFactProjection {
            label: "Drive count",
            value: "6".to_owned(),
        }));
        assert!(storage.facts.contains(&ResourceFactProjection {
            label: "Health",
            value: "OK".to_owned(),
        }));
        let network_adapter = current
            .resources
            .iter()
            .find(|resource| resource.type_label == "Network adapter")
            .ok_or("network adapter resource must exist")?;
        assert_eq!(network_adapter.name, "Network Adapter One");
        assert_eq!(
            network_adapter.source,
            "/redfish/v1/Chassis/1/NetworkAdapters/1"
        );
        assert!(network_adapter.facts.contains(&ResourceFactProjection {
            label: "Manufacturer",
            value: "Vendor A".to_owned(),
        }));
        assert!(network_adapter.facts.contains(&ResourceFactProjection {
            label: "Model",
            value: "NA-25G-2P".to_owned(),
        }));
        assert!(
            !network_adapter
                .facts
                .iter()
                .any(|fact| fact.label == "Part number")
        );
        assert!(
            !network_adapter
                .facts
                .iter()
                .any(|fact| fact.label == "State")
        );
        let ethernet = current
            .resources
            .iter()
            .find(|resource| resource.type_label == "Ethernet interface")
            .ok_or("ethernet interface resource must exist")?;
        assert_eq!(ethernet.name, "Ethernet Interface One");
        assert_eq!(
            ethernet.source,
            "/redfish/v1/Managers/1/EthernetInterfaces/1"
        );
        assert!(ethernet.facts.contains(&ResourceFactProjection {
            label: "MAC address",
            value: "52:54:00:12:34:56".to_owned(),
        }));
        assert!(ethernet.facts.contains(&ResourceFactProjection {
            label: "Speed (Mbps)",
            value: "10000".to_owned(),
        }));
        assert!(ethernet.facts.contains(&ResourceFactProjection {
            label: "Interface enabled",
            value: "Yes".to_owned(),
        }));
        assert_eq!(
            current.resource_counts,
            Some(ResourceCountsProjection {
                systems: 1,
                chassis: 1,
                managers: 1,
            })
        );
        Ok(())
    }

    #[test]
    fn accounts_bios_boot_options_and_secure_boot_cards_render_family_facts()
    -> Result<(), Box<dyn Error>> {
        let current =
            ConsoleLoadState::accepted(about(PRODUCT_ID), inventory()?, resource_inventories()?)
                .endpoint_cards()
                .into_iter()
                .find(|card| card.resource_counts.is_some())
                .ok_or("current endpoint card must exist")?;

        let account = current
            .resources
            .iter()
            .find(|resource| resource.type_label == "Account")
            .ok_or("account resource must exist")?;
        assert_eq!(account.name, "Administrator Account");
        assert_eq!(account.source, "/redfish/v1/AccountService/Accounts/admin");
        assert!(account.facts.contains(&ResourceFactProjection {
            label: "Enabled",
            value: "Yes".to_owned(),
        }));
        assert!(account.facts.contains(&ResourceFactProjection {
            label: "Role",
            value: "Administrator".to_owned(),
        }));
        assert!(account.facts.contains(&ResourceFactProjection {
            label: "Locked",
            value: "No".to_owned(),
        }));
        assert!(!account.facts.iter().any(|fact| fact.label == "State"));
        let bios = current
            .resources
            .iter()
            .find(|resource| resource.type_label == "BIOS")
            .ok_or("bios resource must exist")?;
        assert_eq!(bios.name, "BIOS Configuration");
        assert_eq!(bios.source, "/redfish/v1/Systems/1/Bios");
        assert!(bios.facts.contains(&ResourceFactProjection {
            label: "Attribute registry",
            value: "BiosAttributeRegistry.v1_0_0".to_owned(),
        }));
        let boot_option = current
            .resources
            .iter()
            .find(|resource| resource.type_label == "Boot option")
            .ok_or("boot option resource must exist")?;
        assert_eq!(boot_option.name, "Network Boot Option");
        assert_eq!(
            boot_option.source,
            "/redfish/v1/Systems/1/BootOptions/PXE-1"
        );
        assert!(boot_option.facts.contains(&ResourceFactProjection {
            label: "Display name",
            value: "PXE Network Boot".to_owned(),
        }));
        assert!(boot_option.facts.contains(&ResourceFactProjection {
            label: "Enabled",
            value: "Yes".to_owned(),
        }));
        assert!(boot_option.facts.contains(&ResourceFactProjection {
            label: "UEFI device path",
            value: "PciRoot(0x0)/Pci(0x1C,0x0)/Pci(0x0,0x0)".to_owned(),
        }));
        let secure_boot = current
            .resources
            .iter()
            .find(|resource| resource.type_label == "Secure Boot")
            .ok_or("secure boot resource must exist")?;
        assert_eq!(secure_boot.name, "Secure Boot");
        assert_eq!(secure_boot.source, "/redfish/v1/Systems/1/SecureBoot");
        assert!(secure_boot.facts.contains(&ResourceFactProjection {
            label: "Secure boot enabled",
            value: "Yes".to_owned(),
        }));
        assert!(secure_boot.facts.contains(&ResourceFactProjection {
            label: "Secure boot mode",
            value: "DeployedMode".to_owned(),
        }));
        assert_eq!(
            current.resource_counts,
            Some(ResourceCountsProjection {
                systems: 1,
                chassis: 1,
                managers: 1,
            })
        );
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
    fn refresh_report_projection_preserves_every_row_outcome() -> Result<(), Box<dyn Error>> {
        let inventory = inventory()?;
        let report = serde_json::from_value::<BatchRefreshResponse>(json!({
            "total": 3,
            "succeeded_count": 1,
            "failed_count": 2,
            "results": [
                {
                    "endpoint_id": "01989abc-def0-7abc-8def-0123456789ab",
                    "status": "refreshed",
                    "generation": 8,
                    "snapshot_count": 31,
                    "message": null
                },
                {
                    "endpoint_id": "01989abc-def0-7abc-8def-0123456789ac",
                    "status": "failed",
                    "generation": null,
                    "snapshot_count": null,
                    "message": "resource read failed: connection refused"
                },
                {
                    "endpoint_id": "01989abc-def0-7abc-8def-0123456789ad",
                    "status": "not_found",
                    "generation": null,
                    "snapshot_count": null,
                    "message": null
                }
            ]
        }))?;
        let projection = RefreshBatchReportProjection::from_response(&report, &inventory);

        assert_eq!(projection.total, 3);
        assert_eq!(projection.succeeded_count, 1);
        assert_eq!(projection.failed_count, 2);
        assert_eq!(
            projection.summary_text(),
            "1 of 3 endpoints refreshed; 2 failed"
        );
        let refreshed = projection.rows.first().ok_or("refreshed row must exist")?;
        assert!(refreshed.is_success);
        assert_eq!(refreshed.status_label, "Refreshed");
        assert_eq!(
            refreshed.endpoint_id,
            "01989abc-def0-7abc-8def-0123456789ab"
        );
        assert_eq!(refreshed.display_name, "Rack A BMC");
        assert_eq!(
            refreshed.detail,
            Some("Generation 8 — 31 snapshots".to_owned())
        );
        let failed = projection.rows.get(1).ok_or("failed row must exist")?;
        assert!(!failed.is_success);
        assert_eq!(failed.status_label, "Failed");
        assert_eq!(failed.display_name, "Rack B BMC");
        assert_eq!(
            failed.detail,
            Some("resource read failed: connection refused".to_owned())
        );
        let missing = projection.rows.get(2).ok_or("not-found row must exist")?;
        assert!(!missing.is_success);
        assert_eq!(missing.status_label, "Not found");
        assert_eq!(missing.display_name, "01989abc");
        assert_eq!(missing.detail, None);
        Ok(())
    }

    #[test]
    fn refresh_failure_messages_cover_every_rejection() {
        assert_eq!(
            RefreshFailure::Unavailable.message(),
            "The refresh service is temporarily unavailable."
        );
        assert_eq!(
            RefreshFailure::MalformedReport.message(),
            "The server response could not be read."
        );
        assert_eq!(
            RefreshFailure::Rejected { status: 422 }.message(),
            "The server rejected the refresh request (HTTP 422)."
        );
        assert_ne!(RefreshBatchState::Idle, RefreshBatchState::InFlight);
        assert!(RefreshBatchState::InFlight.is_in_flight());
        assert!(!RefreshBatchState::Idle.is_in_flight());
        let empty_report = RefreshBatchReportProjection {
            total: 0,
            succeeded_count: 0,
            failed_count: 0,
            rows: Vec::new(),
        };
        assert!(matches!(
            RefreshBatchState::Ready(empty_report),
            RefreshBatchState::Ready(_)
        ));
        assert!(
            RefreshBatchState::Ready(RefreshBatchReportProjection {
                total: 0,
                succeeded_count: 0,
                failed_count: 0,
                rows: Vec::new(),
            })
            .is_ready()
        );
        assert!(matches!(
            RefreshBatchState::Failed(RefreshFailure::Unavailable),
            RefreshBatchState::Failed(_)
        ));
        assert!(!RefreshBatchState::Failed(RefreshFailure::Unavailable).is_ready());
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
    fn event_query_projection_renders_raw_message_ids_and_severity_badges()
    -> Result<(), Box<dyn Error>> {
        let query = serde_json::from_value::<EventListResponse>(json!({
            "events": [
                {
                    "id": "01989abc-def0-7abc-8def-0123456789f1",
                    "endpoint_id": "01989abc-def0-7abc-8def-0123456789a1",
                    "message_id": "Base.1.18.ResourceUpdated",
                    "severity": "ok",
                    "message": "The resource was updated by a configuration change.",
                    "event_timestamp": "2026-08-06T11:12:13Z",
                    "observed_at": "2026-08-06T11:12:14Z"
                },
                {
                    "id": "01989abc-def0-7abc-8def-0123456789f2",
                    "endpoint_id": "01989abc-def0-7abc-8def-0123456789a2",
                    "message_id": "OEM.ACME.1.0.CoolingThresholdApproaching",
                    "severity": "warning",
                    "message": "Inlet temperature is approaching the warning threshold.",
                    "event_timestamp": "2026-08-06T11:11:00Z",
                    "observed_at": "2026-08-06T11:11:01Z"
                },
                {
                    "id": "01989abc-def0-7abc-8def-0123456789f3",
                    "endpoint_id": "01989abc-def0-7abc-8def-0123456789a3",
                    "message_id": "ResourceEvent.1.0.ResourceErrorsDetected",
                    "severity": "critical",
                    "message": "Errors were detected on the resource.",
                    "event_timestamp": "2026-08-06T11:10:00Z",
                    "observed_at": "2026-08-06T11:10:02Z"
                }
            ]
        }))?;
        let state = EventsListState::Ready(query);
        assert!(state.is_ready());
        assert!(!state.is_failed());
        assert_eq!(state.count_text(), "3 events");
        assert_eq!(state.bound_text(), "Showing the latest 3 events");

        let cards = state.event_cards();
        let updated = cards.first().ok_or("ok event card must exist")?;
        assert_eq!(updated.event_id, "01989abc-def0-7abc-8def-0123456789f1");
        assert_eq!(updated.endpoint_short_id, "01989abc");
        assert_eq!(updated.message_id, "Base.1.18.ResourceUpdated");
        assert_eq!(updated.severity_label, "OK");
        assert_eq!(updated.severity_class, "event-severity event-ok");
        assert_eq!(
            updated.message,
            "The resource was updated by a configuration change."
        );
        assert_eq!(updated.event_timestamp_text, "2026-08-06T11:12:13Z");
        assert_eq!(updated.observed_at_text, "2026-08-06T11:12:14Z");

        let warning = cards.get(1).ok_or("warning event card must exist")?;
        assert_eq!(
            warning.message_id,
            "OEM.ACME.1.0.CoolingThresholdApproaching"
        );
        assert_eq!(warning.severity_label, "Warning");
        assert_eq!(warning.severity_class, "event-severity event-warn");

        let critical = cards.get(2).ok_or("critical event card must exist")?;
        assert_eq!(
            critical.message_id,
            "ResourceEvent.1.0.ResourceErrorsDetected"
        );
        assert_eq!(critical.severity_label, "Critical");
        assert_eq!(critical.severity_class, "event-severity event-critical");
        Ok(())
    }

    #[test]
    fn telemetry_projection_renders_current_value_and_bounded_history() -> Result<(), Box<dyn Error>>
    {
        let series = serde_json::from_value::<TelemetrySeriesListResponse>(json!({
            "series": [
                {
                    "series_id": "01989abc-def0-7abc-8def-0123456789c1",
                    "endpoint_id": "01989abc-def0-7abc-8def-0123456789a1",
                    "series_key": "PowerMetrics",
                    "sample_count": 1440,
                    "latest_value": 94.0,
                    "latest_observed_at": "2026-08-06T11:12:14Z"
                },
                {
                    "series_id": "01989abc-def0-7abc-8def-0123456789c2",
                    "endpoint_id": "01989abc-def0-7abc-8def-0123456789a1",
                    "series_key": "ThermalMetrics",
                    "sample_count": 0,
                    "latest_value": null,
                    "latest_observed_at": null
                }
            ]
        }))?;
        let samples = serde_json::from_value::<TelemetrySampleListResponse>(json!({
            "samples": [
                {
                    "series_id": "01989abc-def0-7abc-8def-0123456789c1",
                    "observed_at": "2026-08-06T11:12:14Z",
                    "bmc_timestamp": "2026-08-06T11:12:13Z",
                    "value": 94.0
                },
                {
                    "series_id": "01989abc-def0-7abc-8def-0123456789c1",
                    "observed_at": "2026-08-06T11:11:14Z",
                    "bmc_timestamp": "2026-08-06T11:11:13Z",
                    "value": 100.0
                }
            ]
        }))?;

        let first = TelemetryCardProjection::from_series(
            series.series().first().ok_or("series card must exist")?,
        )
        .with_history(Some(&samples));
        assert_eq!(first.series_key, "PowerMetrics");
        assert_eq!(first.endpoint_short_id, "01989abc");
        assert_eq!(
            first.series_id_title,
            "01989abc-def0-7abc-8def-0123456789c1"
        );
        assert_eq!(first.latest_value_text.as_deref(), Some("94"));
        assert_eq!(
            first.latest_observed_at_text.as_deref(),
            Some("2026-08-06T11:12:14Z")
        );
        assert_eq!(first.sample_count_text, "1440");
        // The bounded history renders newest first, exactly as the server
        // listed it — the presentation boundary of 不把产品变成通用时序数据库.
        assert_eq!(
            first.history,
            [
                TelemetryReadingProjection {
                    observed_at_text: "2026-08-06T11:12:14Z".to_owned(),
                    value_text: "94".to_owned(),
                },
                TelemetryReadingProjection {
                    observed_at_text: "2026-08-06T11:11:14Z".to_owned(),
                    value_text: "100".to_owned(),
                },
            ]
        );

        // A series whose upsert preceded its first append has no current
        // value: the card renders no value facts instead of a placeholder.
        let empty = TelemetryCardProjection::from_series(
            series
                .series()
                .get(1)
                .ok_or("empty series card must exist")?,
        )
        .with_history(None);
        assert_eq!(empty.series_key, "ThermalMetrics");
        assert_eq!(empty.latest_value_text, None);
        assert_eq!(empty.latest_observed_at_text, None);
        assert_eq!(empty.sample_count_text, "0");
        assert!(empty.history.is_empty());
        Ok(())
    }

    #[test]
    fn telemetry_list_state_counts_and_reports_failures() -> Result<(), Box<dyn Error>> {
        let series = serde_json::from_value::<TelemetrySeriesListResponse>(json!({
            "series": [
                {
                    "series_id": "01989abc-def0-7abc-8def-0123456789c1",
                    "endpoint_id": "01989abc-def0-7abc-8def-0123456789a1",
                    "series_key": "PowerMetrics",
                    "sample_count": 1,
                    "latest_value": 94.0,
                    "latest_observed_at": "2026-08-06T11:12:14Z"
                }
            ]
        }))?;
        let card = TelemetryCardProjection::from_series(
            series.series().first().ok_or("series card must exist")?,
        );
        let state = TelemetryListState::Ready(vec![card]);
        assert!(state.is_ready());
        assert!(!state.is_failed());
        assert!(!state.has_empty_series());
        assert_eq!(state.count_text(), "1 series");
        assert_eq!(state.cards().len(), 1);

        assert!(!TelemetryListState::Idle.is_loading());
        assert!(TelemetryListState::Loading.is_loading());
        assert_eq!(
            TelemetryListState::Failed.failure_message(),
            "The telemetry history is temporarily unavailable."
        );
        assert!(TelemetryListState::Ready(Vec::new()).has_empty_series());
        Ok(())
    }

    #[test]
    fn event_cards_reestablish_newest_first_order() -> Result<(), Box<dyn Error>> {
        // The fixture deliberately arrives out of order, and its BMC event
        // timestamps run against the receive times: the bounded history
        // contract is newest-first by the product receive time, and the view
        // re-orders defensively on exactly that key, so a misordered payload
        // or a drifted BMC clock can never present an older event above a
        // newer one.
        let query = serde_json::from_value::<EventListResponse>(json!({
            "events": [
                {
                    "id": "01989abc-def0-7abc-8def-0123456789f2",
                    "endpoint_id": "01989abc-def0-7abc-8def-0123456789a2",
                    "message_id": "Base.1.18.ResourceUpdated",
                    "severity": "ok",
                    "message": "Received first",
                    "event_timestamp": "2026-08-06T12:00:00Z",
                    "observed_at": "2026-08-06T09:00:01Z"
                },
                {
                    "id": "01989abc-def0-7abc-8def-0123456789f3",
                    "endpoint_id": "01989abc-def0-7abc-8def-0123456789a3",
                    "message_id": "Base.1.18.ResourceErrorsDetected",
                    "severity": "critical",
                    "message": "Received last",
                    "event_timestamp": "2026-08-06T09:00:00Z",
                    "observed_at": "2026-08-06T12:00:02Z"
                },
                {
                    "id": "01989abc-def0-7abc-8def-0123456789f1",
                    "endpoint_id": "01989abc-def0-7abc-8def-0123456789a1",
                    "message_id": "Base.1.18.ResourceStatusChanged",
                    "severity": "warning",
                    "message": "Received second",
                    "event_timestamp": "2026-08-06T10:30:00Z",
                    "observed_at": "2026-08-06T10:30:01Z"
                }
            ]
        }))?;
        let cards = EventsListState::Ready(query).event_cards();
        assert_eq!(cards.len(), 3);
        let messages = cards
            .iter()
            .map(|card| card.message.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            messages,
            ["Received last", "Received second", "Received first"]
        );
        let observed = cards
            .iter()
            .map(|card| card.observed_at_text.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            observed,
            [
                "2026-08-06T12:00:02Z",
                "2026-08-06T10:30:01Z",
                "2026-08-06T09:00:01Z"
            ]
        );
        Ok(())
    }

    #[test]
    fn unknown_severity_code_renders_raw_code_with_neutral_badge() -> Result<(), Box<dyn Error>> {
        // The api refuses unclassifiable severities at ingestion, but the
        // projection stays total: an unexpected code is shown verbatim with
        // the neutral badge instead of being relabeled as one of the three
        // known severities.
        let query = serde_json::from_value::<EventListResponse>(json!({
            "events": [
                {
                    "id": "01989abc-def0-7abc-8def-0123456789f9",
                    "endpoint_id": "01989abc-def0-7abc-8def-0123456789a9",
                    "message_id": "Base.1.18.ResourceUpdated",
                    "severity": "informational",
                    "message": null,
                    "event_timestamp": "2026-08-06T11:12:13Z",
                    "observed_at": "2026-08-06T11:12:14Z"
                }
            ]
        }))?;
        let card = EventsListState::Ready(query)
            .event_cards()
            .into_iter()
            .next()
            .ok_or("event card must exist")?;
        assert_eq!(card.severity_label, "informational");
        assert_eq!(card.severity_class, "event-severity event-neutral");
        assert_eq!(card.message, "");
        Ok(())
    }

    #[test]
    fn events_list_state_failure_uses_static_copy() {
        assert!(EventsListState::Failed.is_failed());
        assert!(!EventsListState::Failed.is_ready());
        assert_eq!(
            EventsListState::Failed.failure_message(),
            "The event history is temporarily unavailable."
        );
        assert_eq!(EventsListState::Idle.failure_message(), "");
        assert_eq!(EventsListState::Failed.event_cards().len(), 0);
        assert_eq!(EventsListState::Failed.count_text(), "0 events");
        assert!(EventsListState::Loading.is_loading());
    }

    #[test]
    fn events_list_state_renders_empty_history() {
        let empty = EventsListState::Ready(EventListResponse::new(Vec::new()));
        assert!(empty.has_empty_events());
        assert!(!empty.is_failed());
        assert_eq!(empty.count_text(), "0 events");
        assert_eq!(empty.event_cards().len(), 0);
        assert_eq!(EventsListState::Idle.event_cards().len(), 0);
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
    fn power_thermal_sensors_and_controls_cards_render_family_facts() -> Result<(), Box<dyn Error>>
    {
        let current =
            ConsoleLoadState::accepted(about(PRODUCT_ID), inventory()?, resource_inventories()?)
                .endpoint_cards()
                .into_iter()
                .find(|card| card.resource_counts.is_some())
                .ok_or("current endpoint card must exist")?;

        let power = current
            .resources
            .iter()
            .find(|resource| resource.type_label == "Power")
            .ok_or("power resource must exist")?;
        assert_eq!(power.name, "Power");
        assert_eq!(power.source, "/redfish/v1/Chassis/1/Power");
        assert!(
            power.facts.iter().all(|fact| fact.label == "Redfish ID"),
            "the Power projection carries no family facts"
        );
        let thermal = current
            .resources
            .iter()
            .find(|resource| resource.type_label == "Thermal")
            .ok_or("thermal resource must exist")?;
        assert_eq!(thermal.name, "Thermal");
        assert_eq!(thermal.source, "/redfish/v1/Chassis/1/Thermal");
        assert!(thermal.facts.contains(&ResourceFactProjection {
            label: "Health",
            value: "OK".to_owned(),
        }));
        let sensor = current
            .resources
            .iter()
            .find(|resource| resource.type_label == "Sensor")
            .ok_or("sensor resource must exist")?;
        assert_eq!(sensor.name, "Chassis Inlet Temperature");
        assert_eq!(sensor.source, "/redfish/v1/Chassis/1/Sensors/InletTemp");
        assert!(sensor.facts.contains(&ResourceFactProjection {
            label: "Reading type",
            value: "Temperature".to_owned(),
        }));
        assert!(sensor.facts.contains(&ResourceFactProjection {
            label: "Reading",
            value: "27.5".to_owned(),
        }));
        assert!(sensor.facts.contains(&ResourceFactProjection {
            label: "Reading units",
            value: "Cel".to_owned(),
        }));
        assert!(sensor.facts.contains(&ResourceFactProjection {
            label: "Health",
            value: "OK".to_owned(),
        }));
        let control = current
            .resources
            .iter()
            .find(|resource| resource.type_label == "Control")
            .ok_or("control resource must exist")?;
        assert_eq!(control.name, "Chassis Fan Duty");
        assert_eq!(control.source, "/redfish/v1/Chassis/1/Controls/FanDuty");
        assert!(control.facts.contains(&ResourceFactProjection {
            label: "Control type",
            value: "DutyCycle".to_owned(),
        }));
        assert!(control.facts.contains(&ResourceFactProjection {
            label: "Set point",
            value: "30".to_owned(),
        }));
        assert!(
            !control
                .facts
                .iter()
                .any(|fact| fact.label == "Set point units")
        );
        assert!(control.facts.contains(&ResourceFactProjection {
            label: "State",
            value: "Enabled".to_owned(),
        }));
        assert_eq!(
            current.resource_counts,
            Some(ResourceCountsProjection {
                systems: 1,
                chassis: 1,
                managers: 1,
            })
        );
        Ok(())
    }

    #[test]
    fn log_services_manager_network_protocol_and_host_interfaces_cards_render_family_facts()
    -> Result<(), Box<dyn Error>> {
        let current =
            ConsoleLoadState::accepted(about(PRODUCT_ID), inventory()?, resource_inventories()?)
                .endpoint_cards()
                .into_iter()
                .find(|card| card.resource_counts.is_some())
                .ok_or("current endpoint card must exist")?;

        let log_service = current
            .resources
            .iter()
            .find(|resource| resource.type_label == "Log Service")
            .ok_or("log service resource must exist")?;
        assert_eq!(log_service.name, "BMC Event Log");
        assert_eq!(log_service.source, "/redfish/v1/Managers/1/LogServices/1");
        assert!(log_service.facts.contains(&ResourceFactProjection {
            label: "Service enabled",
            value: "Yes".to_owned(),
        }));
        assert!(log_service.facts.contains(&ResourceFactProjection {
            label: "Max records",
            value: "1000".to_owned(),
        }));
        assert!(log_service.facts.contains(&ResourceFactProjection {
            label: "Health",
            value: "OK".to_owned(),
        }));
        let network_protocol = current
            .resources
            .iter()
            .find(|resource| resource.type_label == "Manager Network Protocol")
            .ok_or("manager network protocol resource must exist")?;
        assert_eq!(network_protocol.name, "Manager Network Protocol");
        assert_eq!(
            network_protocol.source,
            "/redfish/v1/Managers/1/NetworkProtocol"
        );
        assert!(network_protocol.facts.contains(&ResourceFactProjection {
            label: "Host name",
            value: "bmc-1".to_owned(),
        }));
        assert!(network_protocol.facts.contains(&ResourceFactProjection {
            label: "FQDN",
            value: "bmc-1.example.com".to_owned(),
        }));
        assert!(network_protocol.facts.contains(&ResourceFactProjection {
            label: "State",
            value: "Enabled".to_owned(),
        }));
        let host_interface = current
            .resources
            .iter()
            .find(|resource| resource.type_label == "Host Interface")
            .ok_or("host interface resource must exist")?;
        assert_eq!(host_interface.name, "Host Interface One");
        assert_eq!(
            host_interface.source,
            "/redfish/v1/Managers/1/HostInterfaces/1"
        );
        assert!(host_interface.facts.contains(&ResourceFactProjection {
            label: "Interface enabled",
            value: "Yes".to_owned(),
        }));
        assert!(
            !host_interface
                .facts
                .iter()
                .any(|fact| fact.label == "Host interface type")
        );
        assert!(host_interface.facts.contains(&ResourceFactProjection {
            label: "State",
            value: "Enabled".to_owned(),
        }));
        assert_eq!(
            current.resource_counts,
            Some(ResourceCountsProjection {
                systems: 1,
                chassis: 1,
                managers: 1,
            })
        );
        Ok(())
    }

    #[test]
    fn pcie_devices_assembly_and_software_inventory_cards_render_family_facts()
    -> Result<(), Box<dyn Error>> {
        let current =
            ConsoleLoadState::accepted(about(PRODUCT_ID), inventory()?, resource_inventories()?)
                .endpoint_cards()
                .into_iter()
                .find(|card| card.resource_counts.is_some())
                .ok_or("current endpoint card must exist")?;

        let pcie_device = current
            .resources
            .iter()
            .find(|resource| resource.type_label == "PCIe device")
            .ok_or("pcie device resource must exist")?;
        assert_eq!(pcie_device.name, "PCIe Device One");
        assert_eq!(pcie_device.source, "/redfish/v1/Systems/1/PCIeDevices/GPU1");
        assert!(pcie_device.facts.contains(&ResourceFactProjection {
            label: "Device type",
            value: "SingleFunction".to_owned(),
        }));
        assert!(pcie_device.facts.contains(&ResourceFactProjection {
            label: "Manufacturer",
            value: "Vendor C".to_owned(),
        }));
        assert!(pcie_device.facts.contains(&ResourceFactProjection {
            label: "Model",
            value: "PCIE-GEN4-X16".to_owned(),
        }));
        let assembly = current
            .resources
            .iter()
            .find(|resource| resource.type_label == "Assembly")
            .ok_or("assembly resource must exist")?;
        assert_eq!(assembly.name, "Fan Assembly");
        assert_eq!(
            assembly.source,
            "/redfish/v1/Chassis/1/Assembly#/Assemblies/0"
        );
        assert!(assembly.facts.contains(&ResourceFactProjection {
            label: "Producer",
            value: "Vendor D".to_owned(),
        }));
        assert!(assembly.facts.contains(&ResourceFactProjection {
            label: "Health",
            value: "OK".to_owned(),
        }));
        let software_inventory = current
            .resources
            .iter()
            .find(|resource| resource.type_label == "Software inventory")
            .ok_or("software inventory resource must exist")?;
        assert_eq!(software_inventory.name, "System BIOS");
        assert_eq!(
            software_inventory.source,
            "/redfish/v1/UpdateService/SoftwareInventory/BIOS"
        );
        assert!(software_inventory.facts.contains(&ResourceFactProjection {
            label: "Software ID",
            value: "BIOS-2026-1".to_owned(),
        }));
        assert!(software_inventory.facts.contains(&ResourceFactProjection {
            label: "Version",
            value: "2.7.0".to_owned(),
        }));
        assert!(software_inventory.facts.contains(&ResourceFactProjection {
            label: "Release date",
            value: "2026-05-01T00:00:00Z".to_owned(),
        }));
        assert_eq!(
            current.resource_counts,
            Some(ResourceCountsProjection {
                systems: 1,
                chassis: 1,
                managers: 1,
            })
        );
        Ok(())
    }

    #[test]
    fn event_and_task_service_cards_render_family_facts() -> Result<(), Box<dyn Error>> {
        let current =
            ConsoleLoadState::accepted(about(PRODUCT_ID), inventory()?, resource_inventories()?)
                .endpoint_cards()
                .into_iter()
                .find(|card| card.resource_counts.is_some())
                .ok_or("current endpoint card must exist")?;

        let event_service = current
            .resources
            .iter()
            .find(|resource| resource.type_label == "Event Service")
            .ok_or("event service resource must exist")?;
        assert_eq!(event_service.name, "Event Service");
        assert_eq!(event_service.source, "/redfish/v1/EventService");
        assert!(event_service.facts.contains(&ResourceFactProjection {
            label: "Service enabled",
            value: "Yes".to_owned(),
        }));
        assert!(event_service.facts.contains(&ResourceFactProjection {
            label: "Health",
            value: "OK".to_owned(),
        }));
        let subscription = current
            .resources
            .iter()
            .find(|resource| resource.type_label == "Event subscription")
            .ok_or("event subscription resource must exist")?;
        assert_eq!(subscription.name, "Subscription One");
        assert_eq!(
            subscription.source,
            "/redfish/v1/EventService/Subscriptions/1"
        );
        assert!(subscription.facts.contains(&ResourceFactProjection {
            label: "Destination",
            value: "https://subscriber.example.test/events".to_owned(),
        }));
        assert!(subscription.facts.contains(&ResourceFactProjection {
            label: "Protocol",
            value: "Redfish".to_owned(),
        }));
        assert!(subscription.facts.contains(&ResourceFactProjection {
            label: "Event types",
            value: "Alert, StatusChange".to_owned(),
        }));
        let task_service = current
            .resources
            .iter()
            .find(|resource| resource.type_label == "Task Service")
            .ok_or("task service resource must exist")?;
        assert_eq!(task_service.name, "Task Service");
        assert_eq!(task_service.source, "/redfish/v1/TaskService");
        assert!(task_service.facts.contains(&ResourceFactProjection {
            label: "Service enabled",
            value: "Yes".to_owned(),
        }));
        assert!(task_service.facts.contains(&ResourceFactProjection {
            label: "Completed task policy",
            value: "Oldest".to_owned(),
        }));
        let task = current
            .resources
            .iter()
            .find(|resource| resource.type_label == "Task")
            .ok_or("task resource must exist")?;
        assert_eq!(task.name, "Firmware Update Task");
        assert_eq!(task.source, "/redfish/v1/TaskService/Tasks/1");
        assert!(task.facts.contains(&ResourceFactProjection {
            label: "Task state",
            value: "Running".to_owned(),
        }));
        assert!(task.facts.contains(&ResourceFactProjection {
            label: "Task status",
            value: "OK".to_owned(),
        }));
        assert!(task.facts.contains(&ResourceFactProjection {
            label: "Percent complete",
            value: "42".to_owned(),
        }));
        assert!(task.facts.contains(&ResourceFactProjection {
            label: "Start time",
            value: "2026-08-05T10:20:00Z".to_owned(),
        }));
        assert_eq!(
            current.resource_counts,
            Some(ResourceCountsProjection {
                systems: 1,
                chassis: 1,
                managers: 1,
            })
        );
        Ok(())
    }

    #[test]
    fn telemetry_service_cards_render_family_facts() -> Result<(), Box<dyn Error>> {
        let current =
            ConsoleLoadState::accepted(about(PRODUCT_ID), inventory()?, resource_inventories()?)
                .endpoint_cards()
                .into_iter()
                .find(|card| card.resource_counts.is_some())
                .ok_or("current endpoint card must exist")?;

        let telemetry_service = current
            .resources
            .iter()
            .find(|resource| resource.type_label == "Telemetry Service")
            .ok_or("telemetry service resource must exist")?;
        assert_eq!(telemetry_service.name, "Telemetry Service");
        assert_eq!(telemetry_service.source, "/redfish/v1/TelemetryService");
        assert!(telemetry_service.facts.contains(&ResourceFactProjection {
            label: "State",
            value: "Enabled".to_owned(),
        }));
        let definition = current
            .resources
            .iter()
            .find(|resource| resource.type_label == "Metric definition")
            .ok_or("metric definition resource must exist")?;
        assert_eq!(definition.name, "Inlet Temperature Definition");
        assert_eq!(
            definition.source,
            "/redfish/v1/TelemetryService/MetricDefinitions/1"
        );
        assert!(definition.facts.contains(&ResourceFactProjection {
            label: "Units",
            value: "Cel".to_owned(),
        }));
        assert!(definition.facts.contains(&ResourceFactProjection {
            label: "Metric type",
            value: "Numeric".to_owned(),
        }));
        let report = current
            .resources
            .iter()
            .find(|resource| resource.type_label == "Metric report")
            .ok_or("metric report resource must exist")?;
        assert_eq!(report.name, "Inlet Temperature Report");
        assert_eq!(
            report.source,
            "/redfish/v1/TelemetryService/MetricReports/1"
        );
        assert!(report.facts.contains(&ResourceFactProjection {
            label: "Metric values",
            value: "2".to_owned(),
        }));
        // The card stays concise: only the latest reading of the value array
        // renders as a fact; the timestamped history belongs to the Telemetry
        // view.
        assert!(report.facts.contains(&ResourceFactProjection {
            label: "Latest value",
            value: "32.0".to_owned(),
        }));
        assert_eq!(
            current.resource_counts,
            Some(ResourceCountsProjection {
                systems: 1,
                chassis: 1,
                managers: 1,
            })
        );
        Ok(())
    }

    #[test]
    fn role_view_mirrors_the_wire_contract_and_gates_admin_views() {
        assert_eq!(
            RoleView::from_wire(RoleResponse::Administrator),
            RoleView::Administrator
        );
        assert_eq!(
            RoleView::from_wire(RoleResponse::Operator),
            RoleView::Operator
        );
        assert_eq!(RoleView::from_wire(RoleResponse::Viewer), RoleView::Viewer);
        assert_eq!(RoleView::Administrator.label(), "Administrator");
        assert_eq!(RoleView::Operator.label(), "Operator");
        assert_eq!(RoleView::Viewer.label(), "Viewer");
        assert!(ConsoleView::Users.allowed_for(Some(RoleView::Administrator)));
        assert!(!ConsoleView::Users.allowed_for(Some(RoleView::Operator)));
        assert!(!ConsoleView::Users.allowed_for(Some(RoleView::Viewer)));
        assert!(!ConsoleView::Users.allowed_for(None));
        assert!(!ConsoleView::Sessions.allowed_for(Some(RoleView::Operator)));
        assert!(ConsoleView::Overview.allowed_for(None));
        assert!(ConsoleView::Operations.allowed_for(Some(RoleView::Viewer)));
    }

    #[test]
    fn console_views_and_loading_state_expose_static_labels() {
        assert_eq!(
            ConsoleView::ALL,
            [
                ConsoleView::Overview,
                ConsoleView::Groups,
                ConsoleView::Credentials,
                ConsoleView::AddEndpoint,
                ConsoleView::Import,
                ConsoleView::Audit,
                ConsoleView::Capabilities,
                ConsoleView::Operations,
                ConsoleView::Events,
                ConsoleView::Artifacts,
                ConsoleView::Telemetry,
                ConsoleView::Diagnostics,
                ConsoleView::Users,
                ConsoleView::Sessions,
                ConsoleView::CenterSites,
                ConsoleView::CenterOperations,
                ConsoleView::CenterBindings,
            ]
        );
        assert_eq!(ConsoleView::Overview.label(), "Overview");
        assert_eq!(ConsoleView::Groups.label(), "Groups");
        assert_eq!(ConsoleView::Credentials.label(), "Credentials");
        assert_eq!(ConsoleView::AddEndpoint.label(), "Add endpoint");
        assert_eq!(ConsoleView::Import.label(), "Import");
        assert_eq!(ConsoleView::Audit.label(), "Audit");
        assert_eq!(ConsoleView::Capabilities.label(), "Capabilities");
        assert_eq!(ConsoleView::Operations.label(), "Operations");
        assert_eq!(ConsoleView::Events.label(), "Events");
        assert_eq!(ConsoleView::Artifacts.label(), "Artifacts");
        assert_eq!(ConsoleView::Telemetry.label(), "Telemetry");
        assert_eq!(ConsoleView::Diagnostics.label(), "Diagnostics");

        assert!(ConsoleLoadState::Loading.is_loading());
        assert!(
            !ConsoleLoadState::accepted(
                about(PRODUCT_ID),
                EndpointInventoryResponse::new(Vec::new()),
                Vec::new()
            )
            .is_loading()
        );

        assert_eq!(ConsoleView::CenterSites.label(), "Center sites");
        assert_eq!(ConsoleView::CenterOperations.label(), "Center operations");
        assert_eq!(ConsoleView::CenterBindings.label(), "Center bindings");
    }

    #[test]
    fn the_center_views_are_scoped_to_the_center_console_posture() {
        // Audit follow-up F2/S8: the center views render only on the Center
        // console and every edge view only on the Edge consoles, and the
        // binding management is Administrator only (the §16.1 matrix).
        for view in ConsoleView::ALL {
            let center = view.is_center_view();
            assert_eq!(
                center,
                matches!(
                    view,
                    ConsoleView::CenterSites
                        | ConsoleView::CenterOperations
                        | ConsoleView::CenterBindings
                ),
                "the center-view classification must cover every view"
            );
        }
        assert!(ConsoleView::CenterSites.is_center_view());
        assert!(ConsoleView::CenterOperations.is_center_view());
        assert!(ConsoleView::CenterBindings.is_center_view());
        assert!(!ConsoleView::Overview.is_center_view());
        assert!(!ConsoleView::Users.is_center_view());

        assert!(ConsoleView::CenterBindings.allowed_for(Some(RoleView::Administrator)));
        assert!(!ConsoleView::CenterBindings.allowed_for(Some(RoleView::Operator)));
        assert!(ConsoleView::CenterSites.allowed_for(Some(RoleView::Viewer)));
        assert!(ConsoleView::CenterOperations.allowed_for(Some(RoleView::Operator)));
    }

    #[test]
    fn center_site_cards_project_the_registered_site_wire_shape() -> Result<(), Box<dyn Error>> {
        let list: CenterSitesResponse = serde_json::from_value(json!({
            "sites": [
                {
                    "site_id": "6f6f9e40-2c5a-4b4e-9f6f-7f7f7f7f7f7f",
                    "display_name": "Rack 7 site",
                    "binding": "bound",
                    "online": true,
                    "endpoint_count": 3,
                    "last_refresh_at": "2026-08-05T10:11:12Z"
                },
                {
                    "site_id": "6f6f9e40-2c5a-4b4e-9f6f-8a8a8a8a8a8a",
                    "display_name": "Rack 8 site",
                    "binding": "pending",
                    "online": false,
                    "endpoint_count": 0,
                    "last_refresh_at": null
                }
            ]
        }))?;
        let cards: Vec<CenterSiteCardProjection> = list
            .sites()
            .iter()
            .map(CenterSiteCardProjection::from)
            .collect();
        assert_eq!(cards.len(), 2);
        assert_eq!(cards[0].site_id, "6f6f9e40-2c5a-4b4e-9f6f-7f7f7f7f7f7f");
        assert_eq!(cards[0].display_name, "Rack 7 site");
        assert_eq!(cards[0].binding, Some(CenterBindingStateView::Bound));
        assert!(cards[0].online);
        assert_eq!(cards[0].endpoint_count, 3);
        assert_eq!(
            cards[0].last_refresh_at,
            Some(OffsetDateTime::parse("2026-08-05T10:11:12Z", &Rfc3339)?)
        );
        assert_eq!(cards[1].binding, Some(CenterBindingStateView::Pending));
        assert!(!cards[1].online);
        assert_eq!(cards[1].last_refresh_at, None);
        Ok(())
    }

    #[test]
    fn center_endpoint_cards_project_the_aggregated_endpoint_wire_shape()
    -> Result<(), Box<dyn Error>> {
        let list: CenterEndpointViewListResponse = serde_json::from_value(json!({
            "endpoints": [
                {
                    "site_id": "6f6f9e40-2c5a-4b4e-9f6f-7f7f7f7f7f7f",
                    "endpoint_id": "6f6f9e40-2c5a-4b4e-9f6f-9b9b9b9b9b9b",
                    "display_name": "Rack A BMC",
                    "address": "https://192.0.2.10/",
                    "health": "ok",
                    "refresh_generation": 7
                }
            ]
        }))?;
        let cards: Vec<CenterEndpointCardProjection> = list
            .endpoints()
            .iter()
            .map(CenterEndpointCardProjection::from)
            .collect();
        assert_eq!(cards.len(), 1);
        assert_eq!(
            cards[0].site_id.as_deref(),
            Some("6f6f9e40-2c5a-4b4e-9f6f-7f7f7f7f7f7f")
        );
        assert_eq!(cards[0].endpoint_id, "6f6f9e40-2c5a-4b4e-9f6f-9b9b9b9b9b9b");
        assert_eq!(cards[0].display_name, "Rack A BMC");
        assert_eq!(cards[0].address, "https://192.0.2.10/");
        assert_eq!(cards[0].health, "ok");
        assert_eq!(cards[0].refresh_generation, 7);
        Ok(())
    }

    #[test]
    fn center_operation_cards_project_the_tracking_wire_shape() -> Result<(), Box<dyn Error>> {
        let list: CenterOperationListResponse = serde_json::from_value(json!({
            "operations": [
                {
                    "operation_id": "6f6f9e40-2c5a-4b4e-9f6f-9c9c9c9c9c9c",
                    "site_id": "6f6f9e40-2c5a-4b4e-9f6f-7f7f7f7f7f7f",
                    "endpoint_id": "6f6f9e40-2c5a-4b4e-9f6f-9b9b9b9b9b9b",
                    "command": { "System": { "Reset": "PowerCycle" } },
                    "target": "/redfish/v1/Systems/1",
                    "state": "queued",
                    "actor": "admin",
                    "ttl_expires_at": "2026-08-05T10:26:12Z",
                    "created_at": "2026-08-05T10:11:12Z"
                }
            ]
        }))?;
        let cards: Vec<CenterOperationCardProjection> = list
            .operations()
            .iter()
            .map(CenterOperationCardProjection::from)
            .collect();
        assert_eq!(cards.len(), 1);
        assert_eq!(
            cards[0].operation_id,
            "6f6f9e40-2c5a-4b4e-9f6f-9c9c9c9c9c9c"
        );
        assert_eq!(
            cards[0].site_id.as_deref(),
            Some("6f6f9e40-2c5a-4b4e-9f6f-7f7f7f7f7f7f")
        );
        assert_eq!(cards[0].endpoint_id, "6f6f9e40-2c5a-4b4e-9f6f-9b9b9b9b9b9b");
        assert!(cards[0].command.contains("System reset"));
        assert_eq!(cards[0].target.as_deref(), Some("/redfish/v1/Systems/1"));
        assert_eq!(cards[0].state, "Queued");
        assert_eq!(cards[0].actor.as_deref(), Some("admin"));
        assert_eq!(
            cards[0].created_at,
            OffsetDateTime::parse("2026-08-05T10:11:12Z", &Rfc3339)?
        );
        Ok(())
    }

    #[test]
    fn the_center_operation_draft_builds_the_wire_submission() -> Result<(), Box<dyn Error>> {
        // The §15.6 submit contract: the form's validated payload carries
        // exactly the site, the endpoint, the target, and the typed command.
        let mut draft = CenterOperationDraft::new();
        assert_eq!(
            draft.try_build(),
            Err(CenterOperationDraftError::SiteRequired)
        );
        draft.site_id = "6f6f9e40-2c5a-4b4e-9f6f-7f7f7f7f7f7f".to_owned();
        assert_eq!(
            draft.try_build(),
            Err(CenterOperationDraftError::EndpointRequired)
        );
        draft.endpoint_id = "6f6f9e40-2c5a-4b4e-9f6f-9b9b9b9b9b9b".to_owned();
        assert_eq!(
            draft.try_build(),
            Err(CenterOperationDraftError::TargetRequired)
        );
        draft.target = "/redfish/v1/Systems/1".to_owned();
        assert_eq!(
            draft.try_build(),
            Err(CenterOperationDraftError::Command(
                OperationFormError::FamilyRequired
            ))
        );
        draft.family = Some(CommandFamilyView::SystemReset);
        assert_eq!(
            draft.try_build(),
            Err(CenterOperationDraftError::Command(
                OperationFormError::ResetTypeRequired
            ))
        );
        draft.reset_type = Some(ResetTypeView::PowerCycle);
        let submission = draft
            .try_build()
            .map_err(|_| "the complete draft must build")?;
        assert_eq!(submission.site_id, "6f6f9e40-2c5a-4b4e-9f6f-7f7f7f7f7f7f");
        assert_eq!(
            submission.endpoint_id,
            "6f6f9e40-2c5a-4b4e-9f6f-9b9b9b9b9b9b"
        );
        assert_eq!(submission.target, "/redfish/v1/Systems/1");

        // The wire contract round-trips through CenterOperationSubmitRequest.
        let request = CenterOperationSubmitRequest::new(
            submission.site_id.parse()?,
            submission.endpoint_id.parse()?,
            submission.target,
            submission.command,
        );
        let wire = serde_json::to_value(&request)?;
        assert_eq!(wire["site_id"], "6f6f9e40-2c5a-4b4e-9f6f-7f7f7f7f7f7f");
        assert_eq!(wire["endpoint_id"], "6f6f9e40-2c5a-4b4e-9f6f-9b9b9b9b9b9b");
        assert_eq!(wire["target"], "/redfish/v1/Systems/1");
        assert_eq!(
            wire["command"],
            json!({ "System": { "Reset": "PowerCycle" } })
        );
        Ok(())
    }

    #[test]
    fn artifact_chunk_ranges_split_every_size_class_on_the_base64_capped_boundary() {
        let empty = artifact_chunk_ranges(0);
        assert!(empty.is_empty());

        // A single byte is one 1-byte chunk.
        let tiny = artifact_chunk_ranges(1);
        assert_eq!(
            tiny,
            [ArtifactChunkRange {
                offset: 0,
                length: 1,
            }]
        );

        // Exactly one full chunk: 3 MiB of payload, whose base64 text is
        // exactly the server's 4 MiB character cap.
        let exact = artifact_chunk_ranges(ARTIFACT_CHUNK_BYTES);
        assert_eq!(
            exact,
            [ArtifactChunkRange {
                offset: 0,
                length: 3 * 1024 * 1024,
            }]
        );
        assert_eq!(
            base64_encode(&vec![0_u8; 3 * 1024 * 1024]).len(),
            4 * 1024 * 1024,
            "a full chunk must fit the server's base64 text cap exactly"
        );

        // Two full chunks plus a remainder: the last chunk is never padded.
        let total = 2 * ARTIFACT_CHUNK_BYTES + 17;
        let ranges = artifact_chunk_ranges(total);
        assert_eq!(ranges.len(), 3);
        assert_eq!(ranges[0].offset, 0);
        assert_eq!(ranges[0].length as u64, ARTIFACT_CHUNK_BYTES);
        assert_eq!(ranges[1].offset, ARTIFACT_CHUNK_BYTES);
        assert_eq!(ranges[1].length as u64, ARTIFACT_CHUNK_BYTES);
        assert_eq!(ranges[2].offset, 2 * ARTIFACT_CHUNK_BYTES);
        assert_eq!(ranges[2].length, 17);

        // The ranges tile the file exactly.
        let total: u64 = ranges.iter().map(|range| range.length as u64).sum();
        assert_eq!(total, 2 * ARTIFACT_CHUNK_BYTES + 17);
    }

    #[test]
    fn artifact_resume_offset_is_the_acknowledged_byte_count_not_a_boundary() {
        // Aligned acknowledgement resumes at the next chunk start.
        let resumed = artifact_chunk_range_at(3 * 1024 * 1024, 10 * 1024 * 1024);
        assert_eq!(
            resumed,
            Some(ArtifactChunkRange {
                offset: 3 * 1024 * 1024,
                length: 3 * 1024 * 1024,
            })
        );

        // A server that acknowledged a partial chunk resumes at that exact
        // byte, never rounded down, because the chunk contract requires the
        // offset to equal the bytes already received.
        let partial = artifact_chunk_range_at(5 * 1024 * 1024, 10 * 1024 * 1024);
        assert_eq!(
            partial,
            Some(ArtifactChunkRange {
                offset: 5 * 1024 * 1024,
                length: 3 * 1024 * 1024,
            })
        );

        // A fully received file has no chunk left; callers jump to finalize.
        assert_eq!(
            artifact_chunk_range_at(10 * 1024 * 1024, 10 * 1024 * 1024),
            None
        );
        assert_eq!(
            artifact_chunk_range_at(11 * 1024 * 1024, 10 * 1024 * 1024),
            None
        );
    }

    #[test]
    fn upload_progress_percent_scales_and_clamps() {
        assert_eq!(upload_progress_percent(0, 0), 100);
        assert_eq!(upload_progress_percent(0, 8), 0);
        assert_eq!(upload_progress_percent(2, 8), 25);
        assert_eq!(upload_progress_percent(6, 8), 75);
        assert_eq!(upload_progress_percent(8, 8), 100);
        // A server that reports slightly more than the declared size cannot
        // render an overfull bar.
        assert_eq!(upload_progress_percent(9, 8), 100);
        assert_eq!(upload_progress_percent(u64::MAX, 1), 100);
    }

    #[test]
    fn format_artifact_size_uses_binary_units() {
        assert_eq!(format_artifact_size(0), "0 B");
        assert_eq!(format_artifact_size(512), "512 B");
        assert_eq!(format_artifact_size(1536), "1.5 KiB");
        assert_eq!(format_artifact_size(4 * 1024 * 1024), "4.0 MiB");
        assert_eq!(format_artifact_size(10 * 1024 * 1024), "10.0 MiB");
        assert_eq!(format_artifact_size(12 * 1024 * 1024 * 1024), "12.0 GiB");
    }

    #[test]
    fn base64_encoding_follows_rfc_4648_vectors() {
        for (bytes, expected) in [
            (&[][..], ""),
            (b"f", "Zg=="),
            (b"fo", "Zm8="),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg=="),
            (b"fooba", "Zm9vYmE="),
            (b"foobar", "Zm9vYmFy"),
            (&[0x00, 0x01, 0x02][..], "AAEC"),
            (&[0xFF, 0xFF, 0xFF][..], "////"),
            (&[0xFE, 0xED][..], "/u0="),
            (&[0x00_u8; 3][..], "AAAA"),
        ] {
            assert_eq!(base64_encode(bytes), expected);
        }
    }

    #[test]
    fn sha256_hex_matches_rfc_6234_vectors() {
        for (bytes, expected) in [
            (
                &[][..],
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            (
                b"abc",
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
            (
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
            ),
            (
                b"The quick brown fox jumps over the lazy dog",
                "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
            ),
            // The million-"a" vector exercises the two-block padding path:
            // 1 000 000 bytes fill 15 625 blocks and leave a 64-byte tail.
            // A heap `Vec` keeps the million bytes off the test stack.
            (
                vec![b'a'; 1_000_000].as_slice(),
                "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
            ),
        ] {
            assert_eq!(sha256_hex(bytes), expected);
        }
        // A digest of 3 MiB spans the padding boundary exactly once at the
        // tail: 49 152 full blocks, then a 64-byte tail block whose padding
        // spills into a second block.
        let three_mib = vec![b'x'; 3 * 1024 * 1024];
        assert_eq!(sha256_hex(&three_mib).len(), 64);
        assert_eq!(sha256_hex(&three_mib), sha256_hex(&three_mib));
    }

    #[test]
    fn artifact_fixture_projects_cards_across_three_states() -> Result<(), Box<dyn Error>> {
        let list: rutilus_api::ArtifactListResponse = serde_json::from_value(json!({
            "artifacts": [
                {
                    "artifact_id": "01989abc-def0-7abc-8def-0123456789e1",
                    "name": "firmware-a.bin",
                    "size_bytes": 8 * 1024 * 1024,
                    "sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
                    "state": "uploading",
                    "uploaded_bytes": 4 * 1024 * 1024,
                    "created_at": "2026-08-06T10:11:12Z",
                    "updated_at": "2026-08-06T10:12:13Z"
                },
                {
                    "artifact_id": "01989abc-def0-7abc-8def-0123456789e2",
                    "name": "firmware-b.bin",
                    "size_bytes": 6,
                    "sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
                    "state": "ready",
                    "uploaded_bytes": 6,
                    "created_at": "2026-08-06T10:11:12Z",
                    "updated_at": "2026-08-06T10:12:13Z"
                },
                {
                    "artifact_id": "01989abc-def0-7abc-8def-0123456789e3",
                    "name": "firmware-c.bin",
                    "size_bytes": 6,
                    "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
                    "state": "failed",
                    "uploaded_bytes": 6,
                    "created_at": "2026-08-06T10:11:12Z",
                    "updated_at": "2026-08-06T10:12:13Z"
                }
            ]
        }))?;
        let cards = list
            .artifacts()
            .iter()
            .map(ArtifactCardProjection::from)
            .collect::<Vec<_>>();

        assert_eq!(cards.len(), 3);

        let uploading = &cards[0];
        assert_eq!(uploading.status, ArtifactStatusView::Uploading);
        assert_eq!(uploading.status_label(), "Uploading");
        assert_eq!(uploading.status_class(), "artifact-state artifact-active");
        assert_eq!(uploading.progress_percent, 50);
        assert_eq!(uploading.size_text, "8.0 MiB");
        assert_eq!(uploading.uploaded_bytes, 4 * 1024 * 1024);
        assert_eq!(uploading.sha256_short, "9f86d081");
        assert_eq!(uploading.created_at_text, "2026-08-06T10:11:12Z");
        assert!(uploading.is_uploading());
        assert!(!uploading.is_completely_uploaded());

        let ready = &cards[1];
        assert_eq!(ready.status, ArtifactStatusView::Ready);
        assert_eq!(ready.status_label(), "Ready");
        assert_eq!(ready.status_class(), "artifact-state artifact-ok");
        assert_eq!(ready.progress_percent, 100);
        assert!(ready.is_completely_uploaded());

        let failed = &cards[2];
        assert_eq!(failed.status, ArtifactStatusView::Failed);
        assert_eq!(failed.status_label(), "Failed");
        assert_eq!(failed.status_class(), "artifact-state artifact-error");
        assert_eq!(failed.sha256_short, "00000000");
        Ok(())
    }

    #[test]
    fn artifact_resume_candidate_matches_only_uploading_cards_by_name_and_size()
    -> Result<(), Box<dyn Error>> {
        let cards = vec![
            artifact_fixture_card("firmware.bin", ArtifactStatusView::Uploading, 4, 8),
            artifact_fixture_card("firmware.bin", ArtifactStatusView::Ready, 8, 8),
            artifact_fixture_card("other.bin", ArtifactStatusView::Uploading, 0, 8),
        ];
        let list = ArtifactsListState::Ready(cards);

        // The interrupted artifact matches by name and declared size.
        let candidate = list
            .resume_candidate("firmware.bin", 8 * 1024 * 1024)
            .ok_or("uploading card must be the resume candidate")?;
        assert_eq!(candidate.artifact_id, "resume-target");

        // A ready artifact with the same name is not a resume target: its
        // upload is complete, and re-selecting it would create a duplicate.
        assert!(
            list.resume_candidate("other.bin", 8 * 1024 * 1024)
                .is_some()
        );
        assert!(
            list.resume_candidate("firmware.bin", 7 * 1024 * 1024)
                .is_none(),
            "a size mismatch must never resume a different file"
        );
        assert!(
            list.resume_candidate("missing.bin", 8 * 1024 * 1024)
                .is_none()
        );
        Ok(())
    }

    #[test]
    fn artifact_upload_status_text_and_failure_messages_are_static_or_status_aware() {
        // The list and upload states are exercised here so the host build
        // keeps every variant reachable, mirroring the operations list test.
        assert!(ArtifactsListState::Loading.is_loading());
        assert!(!ArtifactsListState::Loading.is_ready());
        assert!(ArtifactsListState::Failed.is_failed());
        assert!(!ArtifactsListState::Failed.is_loading());
        assert_eq!(ArtifactsListState::Failed.count_text(), "0 artifacts");
        assert!(!ArtifactsListState::Loading.has_empty_list());
        assert!(!ArtifactUploadState::Idle.is_in_flight());
        assert!(ArtifactUploadState::Creating.is_in_flight());
        assert!(
            ArtifactUploadState::Failed(ArtifactUploadFailure::FileEmpty).is_failed(),
            "a failed upload must be visible as failed"
        );
        assert!(ArtifactUploadState::Succeeded.is_succeeded());
        assert_eq!(
            ArtifactUploadState::Failed(ArtifactUploadFailure::FileEmpty).failure_message(),
            "The selected file is empty."
        );

        assert_eq!(artifact_upload_status_text(&ArtifactUploadState::Idle), "");
        assert_eq!(
            artifact_upload_status_text(&ArtifactUploadState::Creating),
            "Creating artifact..."
        );
        assert_eq!(
            artifact_upload_status_text(&ArtifactUploadState::Uploading {
                artifact_id: "id".to_owned(),
                uploaded_bytes: 4 * 1024 * 1024,
                total_bytes: 10 * 1024 * 1024,
            }),
            "Uploading chunk 2 of 4 · 40%"
        );
        assert_eq!(
            artifact_upload_status_text(&ArtifactUploadState::Finalizing {
                artifact_id: "id".to_owned(),
            }),
            "Verifying the uploaded digest..."
        );
        assert_eq!(
            artifact_upload_status_text(&ArtifactUploadState::Succeeded),
            ""
        );
        assert_eq!(
            ArtifactUploadFailure::FileUnreadable.message(),
            "The selected file could not be read."
        );
        assert_eq!(
            ArtifactUploadFailure::FileEmpty.message(),
            "The selected file is empty."
        );
        assert_eq!(
            ArtifactUploadFailure::CreateRejected { status: 422 }.message(),
            "The server rejected the artifact creation (HTTP 422)."
        );
        assert_eq!(
            ArtifactUploadFailure::ChunkRejected { status: 409 }.message(),
            "The server rejected an upload chunk (HTTP 409)."
        );
        assert_eq!(
            ArtifactUploadFailure::FinalizeRejected { status: 422 }.message(),
            "The server rejected the upload finalize (HTTP 422)."
        );
        assert_eq!(
            ArtifactUploadFailure::Unavailable.message(),
            "The artifact store is temporarily unavailable."
        );
        assert_eq!(
            ArtifactUploadFailure::MalformedResponse.message(),
            "The server response could not be read."
        );
    }

    /// One artifact card fixture, sized in MiB so tests read in storage
    /// units instead of raw bytes.
    fn artifact_fixture_card(
        name: &str,
        status: ArtifactStatusView,
        uploaded_mib: u64,
        size_mib: u64,
    ) -> ArtifactCardProjection {
        ArtifactCardProjection {
            artifact_id: "resume-target".to_owned(),
            short_id: "resume".to_owned(),
            name: name.to_owned(),
            size_text: format_artifact_size(size_mib * 1024 * 1024),
            sha256_short: "9f86d081".to_owned(),
            status,
            uploaded_bytes: uploaded_mib * 1024 * 1024,
            size_bytes: size_mib * 1024 * 1024,
            progress_percent: upload_progress_percent(
                uploaded_mib * 1024 * 1024,
                size_mib * 1024 * 1024,
            ),
            created_at_text: "2026-08-06T10:11:12Z".to_owned(),
        }
    }

    #[test]
    fn capability_matrix_projection_preserves_ledger_order_and_grouping()
    -> Result<(), Box<dyn Error>> {
        let states: [Option<&str>; 30] = [Some("supported"); 30];
        let projection = CapabilityMatrixProjection::from(&capability_inventory(&states)?);

        assert_eq!(projection.groups.len(), 22);
        let accounts = projection
            .groups
            .first()
            .ok_or("accounts group must exist")?;
        assert_eq!(accounts.page_title, "Accounts");
        let entry = accounts
            .entries
            .first()
            .ok_or("accounts entry must exist")?;
        assert_eq!(entry.product_code, "accounts");
        assert_eq!(entry.upstream_feature, "accounts");
        assert_eq!(entry.state_label, "Supported");
        assert_eq!(entry.state_class, "capability-state capability-ok");
        assert_eq!(
            entry.observed_at_text.as_deref(),
            Some("2026-08-05T09:12:13Z")
        );

        let network = projection
            .groups
            .iter()
            .find(|group| group.page_title == "Network")
            .ok_or("network group must exist")?;
        let network_codes = network
            .entries
            .iter()
            .map(|entry| entry.product_code.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            network_codes,
            [
                "ethernet-interfaces",
                "host-interfaces",
                "network-adapters",
                "network-device-functions",
            ]
        );
        let power = projection
            .groups
            .iter()
            .find(|group| group.page_title == "Power")
            .ok_or("power group must exist")?;
        let power_codes = power
            .entries
            .iter()
            .map(|entry| entry.product_code.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            power_codes,
            ["controls", "power", "power-equipment", "power-supplies"]
        );
        Ok(())
    }

    #[test]
    fn capability_group_order_follows_ui_location_appearance_not_string_sort()
    -> Result<(), Box<dyn Error>> {
        let states: [Option<&str>; 30] = [Some("supported"); 30];
        let projection = CapabilityMatrixProjection::from(&capability_inventory(&states)?);
        let titles = projection
            .groups
            .iter()
            .map(|group| group.page_title)
            .collect::<Vec<_>>();
        assert_eq!(
            titles,
            [
                "Accounts",
                "Assembly",
                "BIOS",
                "Boot",
                "Chassis",
                "Systems",
                "Power",
                "Sensors",
                "Network",
                "Events",
                "Logs",
                "Managers",
                "Memory",
                "PCIe",
                "Processors",
                "Secure Boot",
                "Infrastructure",
                "Storage",
                "Tasks",
                "Telemetry",
                "Thermal",
                "Update",
            ]
        );
        // The grouping follows ledger appearance order, not page-name order:
        // a lexicographic sort would place "Events" and "Infrastructure"
        // near the start and "Systems" far past "Power".
        let mut sorted = titles.clone();
        sorted.sort_unstable();
        assert_ne!(titles, sorted);
        Ok(())
    }

    #[test]
    fn capability_none_state_renders_not_observed_without_fabricated_reason()
    -> Result<(), Box<dyn Error>> {
        let mut states: [Option<&str>; 30] = [None; 30];
        states[0] = Some("supported");
        states[1] = Some("read_only");
        states[2] = Some("unauthorized");
        states[3] = Some("temporarily_unavailable");
        states[4] = Some("schema_incompatible");
        states[5] = Some("not_advertised");
        states[6] = Some("not_compiled");
        let projection = CapabilityMatrixProjection::from(&capability_inventory(&states)?);
        let entries = projection
            .groups
            .iter()
            .flat_map(|group| group.entries.iter())
            .collect::<Vec<_>>();

        assert_eq!(entries.len(), 30);
        let accounts = entries.first().ok_or("accounts entry must exist")?;
        assert_eq!(accounts.state_label, "Supported");
        assert_eq!(
            accounts.observed_at_text.as_deref(),
            Some("2026-08-05T09:12:13Z")
        );
        let assembly = entries.get(1).ok_or("assembly entry must exist")?;
        assert_eq!(assembly.state_label, "Read only");
        let bios = entries.get(2).ok_or("bios entry must exist")?;
        assert_eq!(bios.state_label, "Unauthorized");
        let boot = entries.get(3).ok_or("boot-options entry must exist")?;
        assert_eq!(boot.state_label, "Temporarily unavailable");
        let chassis = entries.get(4).ok_or("chassis entry must exist")?;
        assert_eq!(chassis.state_label, "Schema incompatible");
        let systems = entries.get(5).ok_or("systems entry must exist")?;
        assert_eq!(systems.state_label, "Not advertised");
        assert_eq!(systems.state_class, "capability-state capability-off");
        let controls = entries.get(6).ok_or("controls entry must exist")?;
        assert_eq!(controls.state_label, "Not compiled");
        assert_eq!(controls.state_class, "capability-state capability-off");
        let environment_metrics = entries
            .get(7)
            .ok_or("environment-metrics entry must exist")?;
        assert_eq!(environment_metrics.state_label, "Not yet observed");
        assert_eq!(environment_metrics.observed_at_text, None);
        assert_eq!(
            environment_metrics.state_class,
            "capability-state capability-none"
        );
        let session_service = entries.get(24).ok_or("session-service entry must exist")?;
        assert_eq!(session_service.state_label, "Not yet observed");
        assert_eq!(session_service.observed_at_text, None);
        Ok(())
    }

    #[test]
    fn capability_load_failures_render_distinct_static_messages() -> Result<(), Box<dyn Error>> {
        assert_eq!(
            CapabilityLoadFailure::EndpointNotFound.message(),
            "This endpoint no longer exists."
        );
        assert_eq!(
            CapabilityLoadFailure::Unavailable.message(),
            "The capability list is temporarily unavailable."
        );
        assert_eq!(
            CapabilityLoadFailure::Malformed.message(),
            "The server response could not be parsed."
        );
        assert_eq!(
            CapabilityMatrixState::Failed(CapabilityLoadFailure::Unavailable).failure_message(),
            "The capability list is temporarily unavailable."
        );
        assert_eq!(CapabilityMatrixState::Idle.failure_message(), "");
        assert!(CapabilityMatrixState::Loading.is_loading());
        assert!(CapabilityMatrixState::Failed(CapabilityLoadFailure::Malformed).is_failed());

        let empty = CapabilityMatrixState::Ready(CapabilityMatrixProjection { groups: Vec::new() });
        assert!(empty.is_ready());
        assert!(empty.has_empty_matrix());
        assert_eq!(empty.summary_text(), "0 capabilities across 0 pages");
        assert_eq!(empty.groups().len(), 0);
        assert_eq!(empty.failure_message(), "");

        let states: [Option<&str>; 30] = [Some("supported"); 30];
        let ready = CapabilityMatrixState::Ready(CapabilityMatrixProjection::from(
            &capability_inventory(&states)?,
        ));
        assert!(!ready.has_empty_matrix());
        assert_eq!(ready.groups().len(), 22);
        assert_eq!(ready.summary_text(), "30 capabilities across 22 pages");
        assert_eq!(ready.failure_message(), "");
        Ok(())
    }

    #[test]
    fn capability_matrix_groups_oem_entries_under_the_oem_page() -> Result<(), Box<dyn Error>> {
        let standard_states: [Option<&str>; 30] = [None; 30];
        let oem_states: [Option<&str>; 14] = [None; 14];
        let matrix = CapabilityMatrixProjection::from(&capability_inventory_with_oem(
            &standard_states,
            &oem_states,
        )?);

        // The 30 standard entries still group into the same 22 pages; the 14
        // OEM entries add exactly one page — the §12.2 OEM page — because
        // they arrive with `ui_location = "oem"`.
        assert_eq!(matrix.groups.len(), 23);
        let oem_group = matrix
            .groups
            .iter()
            .find(|group| group.page_title == "OEM")
            .ok_or("an OEM capability page must exist")?;
        assert_eq!(oem_group.entries.len(), 14);
        assert_eq!(
            oem_group
                .entries
                .iter()
                .map(|entry| entry.product_code.as_str())
                .collect::<Vec<_>>(),
            [
                "oem-ami",
                "oem-dell",
                "oem-dell-attributes",
                "oem-delta",
                "oem-hpe",
                "oem-lenovo",
                "oem-liteon",
                "oem-nvidia",
                "oem-nvidia-cper",
                "oem-nvidia-fabrics",
                "oem-nvidia-power-management",
                "oem-nvidia-profiles",
                "oem-nvidia-security",
                "oem-supermicro",
            ]
        );
        // Every entry keeps its upstream feature and its honest unobserved
        // state (missing data is never disguised as a probe result).
        for (index, entry) in oem_group.entries.iter().enumerate() {
            assert_eq!(entry.upstream_feature, OEM_LEDGER_FIXTURE[index].1);
            assert_eq!(entry.state_label, NOT_OBSERVED_STATE_LABEL);
            assert_eq!(entry.state_class, "capability-state capability-none");
            assert_eq!(entry.observed_at_text, None);
        }
        assert_eq!(
            CapabilityMatrixState::Ready(matrix).summary_text(),
            "44 capabilities across 23 pages"
        );
        Ok(())
    }

    #[test]
    fn oem_capability_entries_render_honest_state_semantics() -> Result<(), Box<dyn Error>> {
        // OEM probing may reach only the compiled layer for a vendor; the
        // state semantics stay identical to standard entries, so a compiled
        // but unprobed OEM feature renders "Not compiled" instead of being
        // disguised as supported.
        let standard_states: [Option<&str>; 30] = [None; 30];
        let oem_states: [Option<&str>; 14] = [
            Some("supported"),
            Some("read_only"),
            Some("unauthorized"),
            Some("temporarily_unavailable"),
            Some("schema_incompatible"),
            Some("not_advertised"),
            Some("not_compiled"),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        ];
        let matrix = CapabilityMatrixProjection::from(&capability_inventory_with_oem(
            &standard_states,
            &oem_states,
        )?);
        let oem_group = matrix
            .groups
            .iter()
            .find(|group| group.page_title == "OEM")
            .ok_or("an OEM capability page must exist")?;
        let labels = oem_group
            .entries
            .iter()
            .map(|entry| (entry.state_label, entry.state_class))
            .collect::<Vec<_>>();
        assert_eq!(labels[0], ("Supported", "capability-state capability-ok"));
        assert_eq!(labels[1], ("Read only", "capability-state capability-ok"));
        assert_eq!(
            labels[2],
            ("Unauthorized", "capability-state capability-warn")
        );
        assert_eq!(
            labels[3],
            (
                "Temporarily unavailable",
                "capability-state capability-warn"
            )
        );
        assert_eq!(
            labels[4],
            ("Schema incompatible", "capability-state capability-warn")
        );
        assert_eq!(
            labels[5],
            ("Not advertised", "capability-state capability-off")
        );
        assert_eq!(
            labels[6],
            ("Not compiled", "capability-state capability-off")
        );
        assert_eq!(
            labels[7],
            ("Not yet observed", "capability-state capability-none")
        );
        Ok(())
    }

    #[test]
    fn oem_section_derives_the_placeholder_form_without_oem_resources() -> Result<(), Box<dyn Error>>
    {
        let state =
            ConsoleLoadState::accepted(about(PRODUCT_ID), inventory()?, resource_inventories()?);
        let cards = state.endpoint_cards();
        let waiting = cards.first().ok_or("waiting endpoint must exist")?;
        let current = cards.get(1).ok_or("current endpoint must exist")?;

        // The awaiting endpoint has no snapshot yet, and the current
        // endpoint's complete snapshot carries the standard families but no
        // OEM resource: a non-Dell endpoint derives the §11.5 placeholder
        // form, exactly like §11.5's second branch requires.
        assert_eq!(
            waiting.oem_section,
            OemSectionProjection::UnsupportedByNvRedfishBaseline
        );
        assert_eq!(
            current.oem_section,
            OemSectionProjection::UnsupportedByNvRedfishBaseline
        );
        assert!(!current.oem_section.is_supported());
        assert!(current.oem_section.cards().is_empty());

        // The switch condition is pinned: an empty card list derives the
        // placeholder form, a non-empty list the card form.
        assert_eq!(
            OemSectionProjection::from_cards(Vec::new()),
            OemSectionProjection::UnsupportedByNvRedfishBaseline
        );
        Ok(())
    }

    #[test]
    fn oem_section_derives_the_card_form_from_landed_dell_resources() -> Result<(), Box<dyn Error>>
    {
        // The api contract has landed the Dell OEM family
        // (`oem-dell-attributes`), so a Dell snapshot (a manager publishing
        // a DellAttributes document) derives the data-card form through the
        // wire projection, not by direct construction.
        let inventory: EndpointResourceInventoryResponse = serde_json::from_value(json!({
            "endpoint": {
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
                    "observed_at": "2026-08-05T09:12:13Z",
                    "resources": [oem_dell_resource()]
                }
            }
        }))?;
        let card = EndpointCardProjection::from(&inventory);
        let OemSectionProjection::Available { cards } = card.oem_section else {
            return Err("a Dell snapshot must derive the OEM card form".into());
        };
        assert_eq!(cards.len(), 1);
        let dell = cards.first().ok_or("the Dell card must exist")?;
        assert_eq!(dell.type_label, "Dell OEM");
        assert_eq!(dell.name, "Dell Attributes");
        assert_eq!(
            dell.source,
            "/redfish/v1/Managers/1/Oem/Dell/DellAttributes/1"
        );
        // The iDRAC identity attributes render with the vendor's original
        // values verbatim (§12.3).
        assert!(dell.facts.contains(&ResourceFactProjection {
            label: "Model",
            value: "PowerEdge R750".to_owned(),
        }));
        assert!(dell.facts.contains(&ResourceFactProjection {
            label: "Service tag",
            value: "ABC1234".to_owned(),
        }));
        assert!(dell.facts.contains(&ResourceFactProjection {
            label: "Generation",
            value: "16G".to_owned(),
        }));
        assert!(dell.facts.contains(&ResourceFactProjection {
            label: "BMC MAC address",
            value: "14:18:77:aa:bb:cc".to_owned(),
        }));
        assert!(dell.facts.contains(&ResourceFactProjection {
            label: "Server name",
            value: "rack-1-server-2".to_owned(),
        }));
        Ok(())
    }

    #[test]
    fn oem_section_derives_the_card_form_from_landed_supermicro_resources()
    -> Result<(), Box<dyn Error>> {
        // The api contract has landed the Supermicro OEM families
        // (`oem-supermicro`), so a Supermicro snapshot (a manager publishing
        // `SysLockdown` and `KCSInterface` documents) derives the data-card
        // form through the wire projection, not by direct construction.
        let inventory: EndpointResourceInventoryResponse = serde_json::from_value(json!({
            "endpoint": {
                "endpoint_id": "01989abc-def0-7abc-8def-0123456789ad",
                "display_name": "Rack C BMC",
                "address": "https://192.0.2.12/",
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
                        oem_smc_sys_lockdown_resource(),
                        oem_smc_kcs_interface_resource()
                    ]
                }
            }
        }))?;
        let card = EndpointCardProjection::from(&inventory);
        let OemSectionProjection::Available { cards } = card.oem_section else {
            return Err("a Supermicro snapshot must derive the OEM card form".into());
        };
        assert_eq!(cards.len(), 2);
        let sys_lockdown = cards
            .iter()
            .find(|card| card.source == "/redfish/v1/Managers/1/SysLockdown")
            .ok_or("the SysLockdown card must exist")?;
        assert_eq!(sys_lockdown.type_label, "Supermicro SysLockdown");
        // The compiled schema models no `Name`, so the card identity is the
        // resource's own `@odata.id` final segment, never an invented label.
        assert_eq!(sys_lockdown.name, "SysLockdown");
        // The vendor's boolean is rendered in its canonical wire spelling
        // verbatim (§12.3).
        assert!(sys_lockdown.facts.contains(&ResourceFactProjection {
            label: "SysLockdown enabled",
            value: "true".to_owned(),
        }));
        let kcs_interface = cards
            .iter()
            .find(|card| card.source == "/redfish/v1/Managers/1/KCSInterface")
            .ok_or("the KCSInterface card must exist")?;
        assert_eq!(kcs_interface.type_label, "Supermicro KCS Interface");
        assert_eq!(kcs_interface.name, "KCSInterface");
        // The vendor's enum spelling is kept verbatim per §12.3.
        assert!(kcs_interface.facts.contains(&ResourceFactProjection {
            label: "Privilege",
            value: "Operator".to_owned(),
        }));
        Ok(())
    }

    #[test]
    fn oem_section_derives_the_card_form_from_landed_lenovo_resources() -> Result<(), Box<dyn Error>>
    {
        // The api contract has landed the Lenovo OEM family (`oem-lenovo`),
        // so a Lenovo snapshot (a manager publishing a `SecurityService`
        // document) derives the data-card form through the wire projection,
        // not by direct construction.
        let inventory: EndpointResourceInventoryResponse = serde_json::from_value(json!({
            "endpoint": {
                "endpoint_id": "01989abc-def0-7abc-8def-0123456789af",
                "display_name": "Rack E BMC",
                "address": "https://192.0.2.14/",
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
                        oem_lenovo_security_service_resource()
                    ]
                }
            }
        }))?;
        let card = EndpointCardProjection::from(&inventory);
        let OemSectionProjection::Available { cards } = card.oem_section else {
            return Err("a Lenovo snapshot must derive the OEM card form".into());
        };
        assert_eq!(cards.len(), 1);
        let security_service = cards
            .iter()
            .find(|card| card.source == "/redfish/v1/Managers/1/Oem/Lenovo/SecurityService")
            .ok_or("the SecurityService card must exist")?;
        assert_eq!(security_service.type_label, "Lenovo Security Service");
        assert_eq!(security_service.name, "Lenovo Security Service");
        // The vendor's `FWRollback` enum spelling is kept verbatim per §12.3,
        // never translated into a product label.
        assert!(security_service.facts.contains(&ResourceFactProjection {
            label: "Firmware rollback",
            value: "Enabled".to_owned(),
        }));
        Ok(())
    }

    // The four NVIDIA chain documents are asserted in one test so the card
    // order and the full fact surface stay one contract; the four card
    // projections exceed the pedantic line budget, so the lint is scoped
    // here exactly like the other OEM card-form tests.
    #[allow(clippy::too_many_lines)]
    #[test]
    fn oem_section_derives_the_card_form_from_landed_nvidia_resources() -> Result<(), Box<dyn Error>>
    {
        // The api contract has landed the NVIDIA system-config-profile family
        // (`oem-nvidia-profiles`), so an NVIDIA snapshot (a system publishing
        // the `Oem.Nvidia` profile chain) derives the data-card form through
        // the wire projection, not by direct construction.
        let inventory: EndpointResourceInventoryResponse = serde_json::from_value(json!({
            "endpoint": {
                "endpoint_id": "01989abc-def0-7abc-8def-0123456789ae",
                "display_name": "Rack D BMC",
                "address": "https://192.0.2.13/",
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
                        oem_nvidia_system_config_profile_resource(),
                        oem_nvidia_system_config_profile_status_resource(),
                        oem_nvidia_system_profile_resource(),
                        oem_nvidia_system_profile_file_resource()
                    ]
                }
            }
        }))?;
        let card = EndpointCardProjection::from(&inventory);
        let OemSectionProjection::Available { cards } = card.oem_section else {
            return Err("an NVIDIA snapshot must derive the OEM card form".into());
        };
        assert_eq!(cards.len(), 4);
        let chain_root = cards
            .iter()
            .find(|card| card.source == "/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile")
            .ok_or("the SystemConfigProfile card must exist")?;
        assert_eq!(chain_root.type_label, "NVIDIA System Config Profile");
        assert_eq!(chain_root.name, "NVIDIA System Config Profile");
        // The Truststore link-presence metadata renders in its canonical
        // wire spelling verbatim (§12.3); the certificate payloads behind
        // the links never reach the card.
        assert!(chain_root.facts.contains(&ResourceFactProjection {
            label: "NVIDIA certificates",
            value: "true".to_owned(),
        }));
        assert!(chain_root.facts.contains(&ResourceFactProjection {
            label: "OEM certificates",
            value: "false".to_owned(),
        }));
        let status = cards
            .iter()
            .find(|card| {
                card.source == "/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile/Status"
            })
            .ok_or("the status card must exist")?;
        assert_eq!(status.type_label, "NVIDIA Profile Status");
        assert!(status.facts.contains(&ResourceFactProjection {
            label: "Pending activation",
            value: "profile-1".to_owned(),
        }));
        assert!(status.facts.contains(&ResourceFactProjection {
            label: "Active profile index",
            value: "1".to_owned(),
        }));
        assert!(status.facts.contains(&ResourceFactProjection {
            label: "BMC profile version",
            value: "2".to_owned(),
        }));
        assert!(status.facts.contains(&ResourceFactProjection {
            label: "Factory reset status",
            value: "Idle".to_owned(),
        }));
        assert!(status.facts.contains(&ResourceFactProjection {
            label: "Default profile index",
            value: "1".to_owned(),
        }));
        let profile = cards
            .iter()
            .find(|card| {
                card.source == "/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile/Profiles/1"
            })
            .ok_or("the profile card must exist")?;
        assert_eq!(profile.type_label, "NVIDIA System Profile");
        // The compiled metadata fields render verbatim per §12.3.
        assert!(profile.facts.contains(&ResourceFactProjection {
            label: "Default",
            value: "true".to_owned(),
        }));
        assert!(profile.facts.contains(&ResourceFactProjection {
            label: "Owner",
            value: "Nvidia".to_owned(),
        }));
        assert!(profile.facts.contains(&ResourceFactProjection {
            label: "UUID",
            value: "11111111-2222-3333-4444-555555555555".to_owned(),
        }));
        assert!(profile.facts.contains(&ResourceFactProjection {
            label: "Version",
            value: "1".to_owned(),
        }));
        assert!(profile.facts.contains(&ResourceFactProjection {
            label: "Profile name",
            value: "default-profile".to_owned(),
        }));
        let profile_file = cards
            .iter()
            .find(|card| {
                card.source
                    == "/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile/Profiles/1/ProfileFile"
            })
            .ok_or("the profile file card must exist")?;
        assert_eq!(profile_file.type_label, "NVIDIA Profile File");
        // The metadata fields and the base64 content render verbatim (§12.3).
        assert!(profile_file.facts.contains(&ResourceFactProjection {
            label: "Activate",
            value: "true".to_owned(),
        }));
        assert!(profile_file.facts.contains(&ResourceFactProjection {
            label: "Delete",
            value: "false".to_owned(),
        }));
        assert!(profile_file.facts.contains(&ResourceFactProjection {
            label: "Origin profile UUID",
            value: "11111111-2222-3333-4444-555555555555".to_owned(),
        }));
        assert!(profile_file.facts.contains(&ResourceFactProjection {
            label: "More profiles",
            value: "false".to_owned(),
        }));
        assert!(profile_file.facts.contains(&ResourceFactProjection {
            label: "Project name",
            value: "BlueField".to_owned(),
        }));
        assert!(profile_file.facts.contains(&ResourceFactProjection {
            label: "Profile",
            value: "eyJwcm9maWxlIjogInRlc3QifQ==".to_owned(),
        }));
        Ok(())
    }

    // The nine power-family cards are asserted in one test so the card order
    // and the full fact surface stay one contract; the nine card projections
    // exceed the pedantic line budget, so the lint is scoped here exactly
    // like the other OEM card-form tests.
    #[allow(clippy::too_many_lines)]
    #[test]
    fn oem_section_derives_the_card_form_from_landed_nvidia_power_resources()
    -> Result<(), Box<dyn Error>> {
        // The api contract has landed the NVIDIA power-compliance and
        // managed-entity families (`oem-nvidia-power-management`), so a
        // manager publishing the `Oem.Nvidia` power chain derives the
        // data-card form through the wire projection, not by direct
        // construction.
        let inventory: EndpointResourceInventoryResponse = serde_json::from_value(json!({
            "endpoint": {
                "endpoint_id": "01989abc-def0-7abc-8def-0123456789af",
                "display_name": "BlueField BMC",
                "address": "https://192.0.2.14/",
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
                        oem_nvidia_power_compliance_resource(),
                        oem_nvidia_power_domain_resource(),
                        oem_nvidia_power_policy_resource(),
                        oem_nvidia_managed_entity_group_resource(),
                        oem_nvidia_power_state_group_resource(),
                        oem_nvidia_psc_state_resource(),
                        oem_nvidia_psu_state_resource(),
                        oem_nvidia_psu_redundancy_resource(),
                        oem_nvidia_managed_entity_resource()
                    ]
                }
            }
        }))?;
        let card = EndpointCardProjection::from(&inventory);
        let OemSectionProjection::Available { cards } = card.oem_section else {
            return Err("an NVIDIA power snapshot must derive the OEM card form".into());
        };
        assert_eq!(cards.len(), 9);
        // The chain root card carries the compiled `ManagerType` spelling
        // verbatim per §12.3.
        let compliance = cards
            .iter()
            .find(|card| card.source == "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance")
            .ok_or("the PowerCompliance card must exist")?;
        assert_eq!(compliance.type_label, "NVIDIA Power Compliance");
        assert!(compliance.facts.contains(&ResourceFactProjection {
            label: "Manager type",
            value: "PowerManager".to_owned(),
        }));
        let domain = cards
            .iter()
            .find(|card| {
                card.source == "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PowerDomains/1"
            })
            .ok_or("the power domain card must exist")?;
        assert_eq!(domain.type_label, "NVIDIA Power Domain");
        // The compiled scalar fields render verbatim per §12.3.
        assert!(domain.facts.contains(&ResourceFactProjection {
            label: "Value",
            value: "800".to_owned(),
        }));
        assert!(domain.facts.contains(&ResourceFactProjection {
            label: "Type",
            value: "Above".to_owned(),
        }));
        assert!(domain.facts.contains(&ResourceFactProjection {
            label: "Unit",
            value: "Watts".to_owned(),
        }));
        assert!(domain.facts.contains(&ResourceFactProjection {
            label: "Sensor reading type",
            value: "Power".to_owned(),
        }));
        assert!(domain.facts.contains(&ResourceFactProjection {
            label: "Sensor implementation",
            value: "PhysicalSensor".to_owned(),
        }));
        let policy = cards
            .iter()
            .find(|card| {
                card.source == "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/ACLossPolicy"
            })
            .ok_or("the power policy card must exist")?;
        assert_eq!(policy.type_label, "NVIDIA Power Policy");
        assert!(policy.facts.contains(&ResourceFactProjection {
            label: "Auto deassert power brake",
            value: "true".to_owned(),
        }));
        assert!(policy.facts.contains(&ResourceFactProjection {
            label: "Min",
            value: "200".to_owned(),
        }));
        assert!(policy.facts.contains(&ResourceFactProjection {
            label: "Max",
            value: "600".to_owned(),
        }));
        assert!(policy.facts.contains(&ResourceFactProjection {
            label: "Type",
            value: "Inclusive".to_owned(),
        }));
        assert!(policy.facts.contains(&ResourceFactProjection {
            label: "Policy actions",
            value: "AssertPowerBrake".to_owned(),
        }));
        let group = cards
            .iter()
            .find(|card| {
                card.source
                    == "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/ManagedEntityGroups/1"
            })
            .ok_or("the managed entity group card must exist")?;
        assert_eq!(group.type_label, "NVIDIA Managed Entity Group");
        assert!(group.facts.contains(&ResourceFactProjection {
            label: "Current managed entity",
            value: "BF1".to_owned(),
        }));
        let state_group = cards
            .iter()
            .find(|card| {
                card.source == "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PowerStateGroup"
            })
            .ok_or("the power state group card must exist")?;
        assert_eq!(state_group.type_label, "NVIDIA Power State Group");
        assert!(state_group.facts.contains(&ResourceFactProjection {
            label: "PSC ID",
            value: "PSC1".to_owned(),
        }));
        assert!(state_group.facts.contains(&ResourceFactProjection {
            label: "Generated watts",
            value: "2400".to_owned(),
        }));
        assert!(state_group.facts.contains(&ResourceFactProjection {
            label: "Number of PSCs",
            value: "1".to_owned(),
        }));
        assert!(state_group.facts.contains(&ResourceFactProjection {
            label: "Number of local PSUs",
            value: "2".to_owned(),
        }));
        let psc = cards
            .iter()
            .find(|card| {
                card.source
                    == "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PowerStateGroup/PowerShelfControllers/1"
            })
            .ok_or("the PSC state card must exist")?;
        assert_eq!(psc.type_label, "NVIDIA PSC State");
        assert!(psc.facts.contains(&ResourceFactProjection {
            label: "Operational PSUs",
            value: "4".to_owned(),
        }));
        assert!(psc.facts.contains(&ResourceFactProjection {
            label: "Power brake assert",
            value: "false".to_owned(),
        }));
        assert!(psc.facts.contains(&ResourceFactProjection {
            label: "Milliseconds since last heartbeat",
            value: "12".to_owned(),
        }));
        assert!(psc.facts.contains(&ResourceFactProjection {
            label: "Status",
            value: "Operational".to_owned(),
        }));
        let psu = cards
            .iter()
            .find(|card| {
                card.source
                    == "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PowerStateGroup/PowerSupplies/1"
            })
            .ok_or("the PSU state card must exist")?;
        assert_eq!(psu.type_label, "NVIDIA PSU State");
        assert!(psu.facts.contains(&ResourceFactProjection {
            label: "PSU ID",
            value: "PSU1".to_owned(),
        }));
        assert!(psu.facts.contains(&ResourceFactProjection {
            label: "Presence",
            value: "true".to_owned(),
        }));
        assert!(psu.facts.contains(&ResourceFactProjection {
            label: "Input 1 active",
            value: "true".to_owned(),
        }));
        assert!(psu.facts.contains(&ResourceFactProjection {
            label: "Input 2 active",
            value: "false".to_owned(),
        }));
        let redundancy = cards
            .iter()
            .find(|card| {
                card.source == "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PSURedundancy"
            })
            .ok_or("the PSU redundancy card must exist")?;
        assert_eq!(redundancy.type_label, "NVIDIA PSU Redundancy");
        assert!(redundancy.facts.contains(&ResourceFactProjection {
            label: "Max PSUs supported",
            value: "4".to_owned(),
        }));
        assert!(redundancy.facts.contains(&ResourceFactProjection {
            label: "Min PSUs needed",
            value: "2".to_owned(),
        }));
        assert!(redundancy.facts.contains(&ResourceFactProjection {
            label: "Redundancy setting",
            value: "NPlusOne".to_owned(),
        }));
        let entity = cards
            .iter()
            .find(|card| {
                card.source
                    == "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/ManagedEntityGroups/1/ManagedEntities/1"
            })
            .ok_or("the managed entity card must exist")?;
        assert_eq!(entity.type_label, "NVIDIA Managed Entity");
        assert!(entity.facts.contains(&ResourceFactProjection {
            label: "Transport protocol",
            value: "HTTPS".to_owned(),
        }));
        assert!(entity.facts.contains(&ResourceFactProjection {
            label: "IPv4 address",
            value: "192.0.2.10".to_owned(),
        }));
        assert!(entity.facts.contains(&ResourceFactProjection {
            label: "IPv6 address",
            value: "2001:db8::10".to_owned(),
        }));
        assert!(entity.facts.contains(&ResourceFactProjection {
            label: "Port",
            value: "443".to_owned(),
        }));
        Ok(())
    }

    #[test]
    fn oem_section_card_form_keeps_the_resource_card_surface() -> Result<(), Box<dyn Error>> {
        // Direct construction pins the switch condition and the card surface
        // the §12.2 OEM page renders through the standard card path (the
        // wire-driven Dell form is covered separately).
        let resource: CoreResourceResponse = serde_json::from_value(system_resource())?;
        let card = CoreResourceCardProjection::from_resource(
            "01989abc-def0-7abc-8def-0123456789ac",
            &resource,
        );
        assert_eq!(card.type_label, "System");
        assert!(card.facts.contains(&ResourceFactProjection {
            label: "Redfish ID",
            value: "1".to_owned(),
        }));

        let section = OemSectionProjection::from_cards(vec![card.clone()]);
        assert!(section.is_supported());
        assert_eq!(
            section,
            OemSectionProjection::Available { cards: vec![card] }
        );
        Ok(())
    }

    #[test]
    fn oem_unsupported_notice_pins_the_11_5_wording() {
        // The placeholder is the §11.5 `UnsupportedByNvRedfishBaseline`
        // rendering: the exact copy is pinned so the honest boundary cannot
        // drift into claiming OEM support.
        assert_eq!(
            OEM_UNSUPPORTED_NOTICE,
            "OEM data is not available in the nv-redfish baseline for this vendor"
        );
    }

    #[test]
    fn capability_target_projection_carries_the_drill_down_identity() {
        let target = CapabilityTargetProjection {
            endpoint_id: "01989abc-def0-7abc-8def-0123456789ac".to_owned(),
            display_name: "Rack B BMC".to_owned(),
            address: "https://192.0.2.11/".to_owned(),
        };

        assert_eq!(target.endpoint_id, "01989abc-def0-7abc-8def-0123456789ac");
        assert_eq!(target.display_name, "Rack B BMC");
        assert_eq!(target.address, "https://192.0.2.11/");
    }

    #[test]
    fn diagnostics_fixture_projects_every_field_and_pins_pretty_json() -> Result<(), Box<dyn Error>>
    {
        let diagnostics: ResourceDiagnosticsResponse = serde_json::from_value(json!({
            "endpoint_id": "01989abc-def0-7abc-8def-0123456789ac",
            "odata_uri": "/redfish/v1/Systems/1",
            "odata_type": "#ComputerSystem.v1_20_0.ComputerSystem",
            "etag": "W/\"system-7\"",
            "feature": "std-redfish",
            "generation": 7,
            "typed_payload": {
                "@odata.id": "/redfish/v1/Systems/1",
                "@odata.type": "#ComputerSystem.v1_20_0.ComputerSystem",
                "Id": "1",
                "Name": "Web Front End",
                "SystemType": "Physical",
                "Status": { "State": "Enabled", "Health": "OK" },
                "Boot": {
                    "BootSourceOverrideEnabled": "Once",
                    "BootSourceOverrideTarget": "Pxe"
                }
            }
        }))?;

        let projection = DiagnosticsProjection::from(&diagnostics);
        assert_eq!(
            projection.endpoint_id,
            "01989abc-def0-7abc-8def-0123456789ac"
        );
        assert_eq!(projection.odata_uri, "/redfish/v1/Systems/1");
        assert_eq!(
            projection.odata_type.as_deref(),
            Some("#ComputerSystem.v1_20_0.ComputerSystem")
        );
        assert_eq!(projection.etag.as_deref(), Some("W/\"system-7\""));
        assert_eq!(projection.feature, "std-redfish");
        assert_eq!(projection.generation, "7");
        // The rendering decision is pinned: canonical 2-space pretty JSON.
        // `serde_json::Value` objects sort keys, so the output is
        // deterministic for a given payload (no original text survives the
        // typed decode anyway).
        assert_eq!(
            projection.typed_payload_json,
            concat!(
                "{\n",
                "  \"@odata.id\": \"/redfish/v1/Systems/1\",\n",
                "  \"@odata.type\": \"#ComputerSystem.v1_20_0.ComputerSystem\",\n",
                "  \"Boot\": {\n",
                "    \"BootSourceOverrideEnabled\": \"Once\",\n",
                "    \"BootSourceOverrideTarget\": \"Pxe\"\n",
                "  },\n",
                "  \"Id\": \"1\",\n",
                "  \"Name\": \"Web Front End\",\n",
                "  \"Status\": {\n",
                "    \"Health\": \"OK\",\n",
                "    \"State\": \"Enabled\"\n",
                "  },\n",
                "  \"SystemType\": \"Physical\"\n",
                "}"
            )
        );
        Ok(())
    }

    #[test]
    fn diagnostics_projection_preserves_absent_optional_fields() -> Result<(), Box<dyn Error>> {
        let diagnostics: ResourceDiagnosticsResponse = serde_json::from_value(json!({
            "endpoint_id": "01989abc-def0-7abc-8def-0123456789ab",
            "odata_uri": "/redfish/v1/Chassis/1/Thermal",
            "odata_type": null,
            "etag": null,
            "feature": "oem-dell",
            "generation": 3,
            "typed_payload": { "Temperature": [] }
        }))?;

        let projection = DiagnosticsProjection::from(&diagnostics);
        assert_eq!(projection.odata_type, None);
        assert_eq!(projection.etag, None);
        assert_eq!(projection.feature, "oem-dell");
        assert_eq!(projection.generation, "3");
        assert_eq!(projection.typed_payload_json, "{\n  \"Temperature\": []\n}");
        Ok(())
    }

    #[test]
    fn diagnostics_absent_optional_fields_render_the_not_published_placeholder() {
        // Pins the rendering decision like the capability
        // `NOT_OBSERVED_STATE_LABEL` precedent: absence keeps the row
        // visible with a stable placeholder instead of hiding what the BMC
        // did not publish.
        assert_eq!(DIAGNOSTICS_ABSENT_FIELD_LABEL, "Not published");
        assert_eq!(diagnostics_optional_text(None), "Not published".to_owned());
        assert_eq!(
            diagnostics_optional_text(Some("#ComputerSystem.v1_20_0.ComputerSystem")),
            "#ComputerSystem.v1_20_0.ComputerSystem".to_owned()
        );
    }

    #[test]
    fn diagnostics_states_cover_loading_ready_and_typed_failures() {
        assert_eq!(
            DiagnosticsLoadFailure::ResourceNotFound.message(),
            "This resource no longer exists in the product."
        );
        assert_eq!(
            DiagnosticsLoadFailure::Unavailable.message(),
            "The diagnostics snapshot is temporarily unavailable."
        );
        assert_eq!(
            DiagnosticsLoadFailure::Malformed.message(),
            "The server response could not be parsed."
        );
        assert_eq!(DiagnosticsState::Idle.failure_message(), "");
        assert!(DiagnosticsState::Loading.is_loading());
        assert!(DiagnosticsState::Failed(DiagnosticsLoadFailure::ResourceNotFound).is_failed());
        assert_eq!(
            DiagnosticsState::Failed(DiagnosticsLoadFailure::ResourceNotFound).failure_message(),
            "This resource no longer exists in the product."
        );
        assert_eq!(
            DiagnosticsState::Failed(DiagnosticsLoadFailure::Malformed).failure_message(),
            "The server response could not be parsed."
        );

        let projection = DiagnosticsProjection {
            endpoint_id: "01989abc-def0-7abc-8def-0123456789ac".to_owned(),
            odata_uri: "/redfish/v1/Systems/1".to_owned(),
            odata_type: Some("#ComputerSystem.v1_20_0.ComputerSystem".to_owned()),
            etag: Some("W/\"system-7\"".to_owned()),
            feature: "std-redfish".to_owned(),
            generation: "7".to_owned(),
            typed_payload_json: "{}".to_owned(),
        };
        let ready = DiagnosticsState::Ready(projection.clone());
        assert!(ready.is_ready());
        assert_eq!(ready.projection(), Some(projection));
        assert_eq!(ready.failure_message(), "");
        assert_eq!(DiagnosticsState::Idle.projection(), None);
        assert_eq!(DiagnosticsState::Loading.projection(), None);
        assert_eq!(
            DiagnosticsState::Failed(DiagnosticsLoadFailure::Unavailable).projection(),
            None
        );
    }

    #[test]
    fn core_resource_card_entry_opens_its_own_diagnostics_target() -> Result<(), Box<dyn Error>> {
        let inventories = resource_inventories()?;
        let cards = inventories
            .iter()
            .map(EndpointCardProjection::from)
            .collect::<Vec<_>>();
        let rack_b = cards
            .iter()
            .find(|card| card.endpoint_id == "01989abc-def0-7abc-8def-0123456789ac")
            .ok_or("rack B card must exist")?;
        let system = rack_b
            .resources
            .iter()
            .find(|card| card.type_label == "System")
            .ok_or("system card must exist")?;

        // The entry must open exactly this card's resource: the target
        // carries the endpoint id, the resource id, and the display identity
        // the panel header renders.
        let target = DiagnosticsTargetProjection::from(system);
        assert_eq!(target.endpoint_id, rack_b.endpoint_id);
        assert_eq!(target.resource_id, "01989abc-def0-7abc-8def-0123456789d1");
        assert_eq!(target.name, "Compute One");
        assert_eq!(target.source, "/redfish/v1/Systems/1");
        Ok(())
    }

    #[test]
    fn diagnostics_footer_note_discloses_decoded_snapshot_and_unpersisted_decode_errors() {
        // The footnote is the honest boundary of §12.4 (mirroring the api
        // contract): the panel shows the decoded snapshot of the latest
        // complete refresh, and decode-error paths are not persisted, so the
        // panel must never imply it covers failed decodes.
        assert!(DIAGNOSTICS_FOOTER_NOTE.contains("decoded snapshot"));
        assert!(DIAGNOSTICS_FOOTER_NOTE.contains("latest complete refresh"));
        assert!(DIAGNOSTICS_FOOTER_NOTE.contains("not persisted"));
    }

    #[test]
    fn operation_state_views_cover_all_nine_phases_with_labels_and_classes() {
        let all_states = [
            OperationStateView::Queued,
            OperationStateView::Validating,
            OperationStateView::Running,
            OperationStateView::WaitingRemote,
            OperationStateView::Verifying,
            OperationStateView::Succeeded,
            OperationStateView::Failed,
            OperationStateView::Unknown,
            OperationStateView::Cancelled,
        ];
        assert_eq!(all_states.len(), 9);
        for (state, label) in [
            (OperationStateView::Queued, "Queued"),
            (OperationStateView::Validating, "Validating"),
            (OperationStateView::Running, "Running"),
            (OperationStateView::WaitingRemote, "Waiting for BMC"),
            (OperationStateView::Verifying, "Verifying"),
            (OperationStateView::Succeeded, "Succeeded"),
            (OperationStateView::Failed, "Failed"),
            (OperationStateView::Unknown, "Unknown"),
            (OperationStateView::Cancelled, "Cancelled"),
        ] {
            assert!(all_states.contains(&state));
            assert_eq!(state.label(), label);
        }
        // The four semantic tiers: ok, error, off, active.
        assert_eq!(
            OperationStateView::Succeeded.class(),
            "operation-state operation-ok"
        );
        assert_eq!(
            OperationStateView::Failed.class(),
            "operation-state operation-error"
        );
        assert_eq!(
            OperationStateView::Unknown.class(),
            "operation-state operation-off"
        );
        assert_eq!(
            OperationStateView::Cancelled.class(),
            "operation-state operation-off"
        );
        for state in [
            OperationStateView::Queued,
            OperationStateView::Validating,
            OperationStateView::Running,
            OperationStateView::WaitingRemote,
            OperationStateView::Verifying,
        ] {
            assert_eq!(state.class(), "operation-state operation-active");
        }
    }

    #[test]
    fn operation_sources_and_command_families_render_static_labels() {
        assert_eq!(OperationSourceView::Standalone.label(), "Standalone");
        assert_eq!(OperationSourceView::Site.label(), "Site");
        assert_eq!(OperationSourceView::Center.label(), "Center");

        assert_eq!(
            CommandFamilyView::ALL,
            [
                CommandFamilyView::SystemReset,
                CommandFamilyView::ManagerReset,
                CommandFamilyView::ChassisReset,
                CommandFamilyView::BootOverride,
                CommandFamilyView::SecureBoot,
                CommandFamilyView::EventSubscription,
                CommandFamilyView::FirmwareUpdate,
                CommandFamilyView::Oem,
            ]
        );
        for (family, code, label) in [
            (CommandFamilyView::SystemReset, "system", "System reset"),
            (CommandFamilyView::ManagerReset, "manager", "Manager reset"),
            (CommandFamilyView::ChassisReset, "chassis", "Chassis reset"),
            (
                CommandFamilyView::BootOverride,
                "boot",
                "Boot source override",
            ),
            (CommandFamilyView::SecureBoot, "secure-boot", "Secure Boot"),
            (
                CommandFamilyView::EventSubscription,
                "event",
                "Event subscription",
            ),
            (
                CommandFamilyView::FirmwareUpdate,
                "update",
                "Firmware update",
            ),
            (CommandFamilyView::Oem, "oem", "OEM (NVIDIA)"),
        ] {
            assert_eq!(family.as_str(), code);
            assert_eq!(family.label(), label);
        }
        // The family codes are the §7.5 wire contract; the families that
        // still have no form surface must not be claimed by one.
        assert_eq!(CommandFamilyView::ALL.len(), 8);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn oem_view_vocabularies_follow_the_domain_and_group_their_actions() {
        let faces = [
            OemFaceView::SystemConfigProfile,
            OemFaceView::DebugToken,
            OemFaceView::PowerSmoothing,
        ];
        assert_eq!(OemFaceView::ALL.len(), faces.len());
        for (face, label) in
            faces
                .into_iter()
                .zip(["System config profile", "Debug token", "Power smoothing"])
        {
            assert_eq!(face.label(), label);
        }
        assert_eq!(OemActionView::ALL.len(), 9);
        for action in OemActionView::ALL {
            assert!(!action.label().is_empty());
        }
        for (action, face) in [
            (
                OemActionView::ProfileUpdate,
                OemFaceView::SystemConfigProfile,
            ),
            (
                OemActionView::ProfileFactoryReset,
                OemFaceView::SystemConfigProfile,
            ),
            (
                OemActionView::ProfileActivate,
                OemFaceView::SystemConfigProfile,
            ),
            (OemActionView::TokenGenerate, OemFaceView::DebugToken),
            (OemActionView::TokenInstall, OemFaceView::DebugToken),
            (OemActionView::TokenDisable, OemFaceView::DebugToken),
            (OemActionView::TokenErase, OemFaceView::DebugToken),
            (
                OemActionView::PowerActivatePreset,
                OemFaceView::PowerSmoothing,
            ),
            (
                OemActionView::PowerApplyOverrides,
                OemFaceView::PowerSmoothing,
            ),
        ] {
            assert_eq!(action.face(), face);
        }
        for (action, key) in [
            (OemActionView::ProfileUpdate, "profile-update"),
            (OemActionView::ProfileFactoryReset, "profile-factory-reset"),
            (OemActionView::ProfileActivate, "profile-activate"),
            (OemActionView::TokenGenerate, "token-generate"),
            (OemActionView::TokenInstall, "token-install"),
            (OemActionView::TokenDisable, "token-disable"),
            (OemActionView::TokenErase, "token-erase"),
            (OemActionView::PowerActivatePreset, "power-activate-preset"),
            (OemActionView::PowerApplyOverrides, "power-apply-overrides"),
        ] {
            assert_eq!(oem_action_key(action), key);
        }
        let token_members = [
            (TokenTypeView::Frc, "FRC"),
            (TokenTypeView::Crcs, "CRCS"),
            (TokenTypeView::Crdt, "CRDT"),
            (TokenTypeView::DebugFirmwareRunning, "DebugFirmwareRunning"),
            (TokenTypeView::DebugFirmwareUnlock, "DebugFirmwareUnlock"),
            (TokenTypeView::OtpDumpEnable, "OTPDumpEnable"),
            (TokenTypeView::JtagUnlock, "JtagUnlock"),
            (TokenTypeView::HardwareUnlock, "HardwareUnlock"),
            (TokenTypeView::RuntimeDebugUnlock, "RuntimeDebugUnlock"),
            (TokenTypeView::FeatureUnlock, "FeatureUnlock"),
            (TokenTypeView::Mtdt, "MTDT"),
            (
                TokenTypeView::CcplexArmJtagDebugCont,
                "CcplexArmJtagDebugCont",
            ),
            (TokenTypeView::NvJtagControl, "NVJtagControl"),
            (TokenTypeView::DiagnosticBoot, "DiagnosticBoot"),
            (TokenTypeView::BpmpFirmwareDebugFs, "BpmpFirmwareDebugFS"),
            (TokenTypeView::FirmwareDebugKnobs, "FirmwareDebugKnobs"),
            (TokenTypeView::FirewallLifting, "FirewallLifting"),
            (TokenTypeView::Verbosity, "Verbosity"),
            (TokenTypeView::SmaDebugCapability, "SMADebugCapability"),
            (TokenTypeView::CpldDebugCapability, "CpldDebugCapability"),
        ];
        assert_eq!(TokenTypeView::ALL.len(), token_members.len());
        for (member, wire) in token_members {
            assert_eq!(member.as_str(), wire);
            assert_eq!(domain_token_type(member).as_str(), wire);
        }
        let erase_members = [
            (EraseTypeView::EraseAll, "EraseAll"),
            (
                EraseTypeView::EraseAllAndRatchetCounterIncreased,
                "EraseAllAndRatchetCounterIncreased",
            ),
            (EraseTypeView::TokenType, "TokenType"),
        ];
        assert_eq!(EraseTypeView::ALL.len(), erase_members.len());
        for (member, wire) in erase_members {
            assert_eq!(member.as_str(), wire);
            assert_eq!(domain_erase_type(member).as_str(), wire);
        }
    }

    #[test]
    fn reset_type_view_members_follow_the_csdl() {
        let members = [
            (ResetTypeView::On, "On"),
            (ResetTypeView::ForceOff, "ForceOff"),
            (ResetTypeView::GracefulShutdown, "GracefulShutdown"),
            (ResetTypeView::GracefulRestart, "GracefulRestart"),
            (ResetTypeView::ForceRestart, "ForceRestart"),
            (ResetTypeView::Nmi, "Nmi"),
            (ResetTypeView::ForceOn, "ForceOn"),
            (ResetTypeView::PushPowerButton, "PushPowerButton"),
            (ResetTypeView::PowerCycle, "PowerCycle"),
            (ResetTypeView::Suspend, "Suspend"),
            (ResetTypeView::Pause, "Pause"),
            (ResetTypeView::Resume, "Resume"),
            (ResetTypeView::FullPowerCycle, "FullPowerCycle"),
        ];
        assert_eq!(ResetTypeView::ALL.len(), members.len());
        for (member, wire) in members {
            assert_eq!(member.as_str(), wire);
        }
    }

    #[test]
    fn boot_secure_boot_and_event_view_members_follow_the_csdl() {
        let boot_sources = [
            (BootSourceView::None, "None"),
            (BootSourceView::Pxe, "Pxe"),
            (BootSourceView::Floppy, "Floppy"),
            (BootSourceView::Cd, "Cd"),
            (BootSourceView::Usb, "Usb"),
            (BootSourceView::Hdd, "Hdd"),
            (BootSourceView::BiosSetup, "BiosSetup"),
            (BootSourceView::Utilities, "Utilities"),
            (BootSourceView::Diags, "Diags"),
            (BootSourceView::UefiShell, "UefiShell"),
            (BootSourceView::UefiTarget, "UefiTarget"),
            (BootSourceView::SdCard, "SDCard"),
            (BootSourceView::UefiHttp, "UefiHttp"),
            (BootSourceView::RemoteDrive, "RemoteDrive"),
            (BootSourceView::UefiBootNext, "UefiBootNext"),
            (BootSourceView::Recovery, "Recovery"),
        ];
        assert_eq!(BootSourceView::ALL.len(), boot_sources.len());
        for (member, wire) in boot_sources {
            assert_eq!(member.as_str(), wire);
        }
        let enabled_members = [
            (BootEnabledView::Disabled, "Disabled"),
            (BootEnabledView::Once, "Once"),
            (BootEnabledView::Continuous, "Continuous"),
        ];
        assert_eq!(BootEnabledView::ALL.len(), enabled_members.len());
        for (member, wire) in enabled_members {
            assert_eq!(member.as_str(), wire);
        }
        let mode_members = [
            (BootModeView::Legacy, "Legacy"),
            (BootModeView::Uefi, "UEFI"),
        ];
        assert_eq!(BootModeView::ALL.len(), mode_members.len());
        for (member, wire) in mode_members {
            assert_eq!(member.as_str(), wire);
        }
        let keys_members = [
            (
                ResetKeysTypeView::ResetAllKeysToDefault,
                "ResetAllKeysToDefault",
            ),
            (ResetKeysTypeView::DeleteAllKeys, "DeleteAllKeys"),
            (ResetKeysTypeView::DeletePk, "DeletePK"),
        ];
        assert_eq!(ResetKeysTypeView::ALL.len(), keys_members.len());
        for (member, wire) in keys_members {
            assert_eq!(member.as_str(), wire);
        }
        let protocol_members = [
            (EventProtocolView::Redfish, "Redfish"),
            (EventProtocolView::Kafka, "Kafka"),
            (EventProtocolView::Snmpv1, "SNMPv1"),
            (EventProtocolView::Snmpv2c, "SNMPv2c"),
            (EventProtocolView::Snmpv3, "SNMPv3"),
            (EventProtocolView::Smtp, "SMTP"),
            (EventProtocolView::SyslogTls, "SyslogTLS"),
            (EventProtocolView::SyslogTcp, "SyslogTCP"),
            (EventProtocolView::SyslogUdp, "SyslogUDP"),
            (EventProtocolView::SyslogRelp, "SyslogRELP"),
            (EventProtocolView::Oem, "OEM"),
        ];
        assert_eq!(EventProtocolView::ALL.len(), protocol_members.len());
        for (member, wire) in protocol_members {
            assert_eq!(member.as_str(), wire);
        }
        let event_type_members = [
            (EventTypeView::StatusChange, "StatusChange"),
            (EventTypeView::ResourceUpdated, "ResourceUpdated"),
            (EventTypeView::ResourceAdded, "ResourceAdded"),
            (EventTypeView::ResourceRemoved, "ResourceRemoved"),
            (EventTypeView::Alert, "Alert"),
            (EventTypeView::MetricReport, "MetricReport"),
            (EventTypeView::Other, "Other"),
        ];
        assert_eq!(EventTypeView::ALL.len(), event_type_members.len());
        for (member, wire) in event_type_members {
            assert_eq!(member.as_str(), wire);
        }
        assert_eq!(EventActionView::ALL.len(), 2);
        assert_eq!(SecureBootActionView::Enable.label(), "Enable");
        assert_eq!(SecureBootActionView::Disable.label(), "Disable");
        assert_eq!(
            SecureBootActionView::ResetKeys(ResetKeysTypeView::DeleteAllKeys).label(),
            "Reset keys"
        );
        assert_eq!(
            EventActionView::CreateSubscription.label(),
            "Create subscription"
        );
        assert_eq!(
            EventActionView::DeleteSubscription.label(),
            "Delete subscription"
        );
    }

    #[test]
    fn command_summaries_render_every_family_and_payload() {
        for (command, family, payload) in [
            (
                OperationCommandDraft::Reset {
                    family: ResetResourceView::System,
                    reset_type: ResetTypeView::PowerCycle,
                },
                "System reset",
                "PowerCycle",
            ),
            (
                OperationCommandDraft::Reset {
                    family: ResetResourceView::Manager,
                    reset_type: ResetTypeView::GracefulRestart,
                },
                "Manager reset",
                "GracefulRestart",
            ),
            (
                OperationCommandDraft::Reset {
                    family: ResetResourceView::Chassis,
                    reset_type: ResetTypeView::ForceOff,
                },
                "Chassis reset",
                "ForceOff",
            ),
            (
                OperationCommandDraft::BootOverride {
                    source: BootSourceView::Pxe,
                    enabled: BootEnabledView::Once,
                    mode: BootModeView::Uefi,
                },
                "Boot source override",
                "Pxe · Once · UEFI",
            ),
            (
                OperationCommandDraft::SecureBoot(SecureBootActionView::Enable),
                "Secure Boot",
                "Enable",
            ),
            (
                OperationCommandDraft::SecureBoot(SecureBootActionView::Disable),
                "Secure Boot",
                "Disable",
            ),
            (
                OperationCommandDraft::SecureBoot(SecureBootActionView::ResetKeys(
                    ResetKeysTypeView::ResetAllKeysToDefault,
                )),
                "Secure Boot",
                "Reset keys · ResetAllKeysToDefault",
            ),
        ] {
            let summary = command_summary(&command);
            assert_eq!(summary.family, family);
            assert_eq!(summary.payload, payload);
        }

        let create = OperationCommandDraft::Event(EventActionDraft::CreateSubscription {
            destination: "https://subscriber.example.test/events".to_owned(),
            protocol: EventProtocolView::Redfish,
            event_types: vec![EventTypeView::Alert, EventTypeView::StatusChange],
        });
        let summary = command_summary(&create);
        assert_eq!(summary.family, "Event subscription");
        assert_eq!(
            summary.payload,
            "Create · https://subscriber.example.test/events · Redfish · Alert, StatusChange"
        );

        let delete = OperationCommandDraft::Event(EventActionDraft::DeleteSubscription {
            subscription_id: "Sub-1".to_owned(),
        });
        let summary = command_summary(&delete);
        assert_eq!(summary.family, "Event subscription");
        assert_eq!(summary.payload, "Delete · Sub-1");
    }

    #[test]
    fn operation_form_validation_rejects_incomplete_drafts() {
        let fresh = OperationFormDraft::new();
        assert_eq!(
            fresh.try_build(),
            Err(OperationFormError::EndpointsRequired)
        );

        let mut no_family = fresh.clone();
        no_family
            .selected_endpoint_ids
            .push("01989abc-def0-7abc-8def-0123456789ab".to_owned());
        assert_eq!(
            no_family.try_build(),
            Err(OperationFormError::FamilyRequired)
        );

        let mut no_reset_type = no_family.clone();
        no_reset_type.family = Some(CommandFamilyView::SystemReset);
        assert_eq!(
            no_reset_type.try_build(),
            Err(OperationFormError::ResetTypeRequired)
        );

        let mut no_boot_params = no_family.clone();
        no_boot_params.family = Some(CommandFamilyView::BootOverride);
        assert_eq!(
            no_boot_params.try_build(),
            Err(OperationFormError::BootSourceRequired)
        );
        let mut boot = no_boot_params.clone();
        boot.boot_source = Some(BootSourceView::Pxe);
        assert_eq!(
            boot.try_build(),
            Err(OperationFormError::BootEnabledRequired)
        );
        boot.boot_enabled = Some(BootEnabledView::Once);
        assert_eq!(boot.try_build(), Err(OperationFormError::BootModeRequired));

        let mut no_secure_boot_action = no_family.clone();
        no_secure_boot_action.family = Some(CommandFamilyView::SecureBoot);
        assert_eq!(
            no_secure_boot_action.try_build(),
            Err(OperationFormError::SecureBootActionRequired)
        );
        let mut reset_keys = no_secure_boot_action.clone();
        reset_keys.secure_boot_action = Some(SecureBootActionView::ResetKeys(
            ResetKeysTypeView::DeleteAllKeys,
        ));
        assert_eq!(
            reset_keys.try_build(),
            Err(OperationFormError::ResetKeysTypeRequired)
        );

        let mut no_event_action = no_family.clone();
        no_event_action.family = Some(CommandFamilyView::EventSubscription);
        assert_eq!(
            no_event_action.try_build(),
            Err(OperationFormError::EventActionRequired)
        );
        let mut create = no_event_action.clone();
        create.event_action = Some(EventActionView::CreateSubscription);
        assert_eq!(
            create.try_build(),
            Err(OperationFormError::DestinationRequired)
        );
        create.destination = "not a url".to_owned();
        assert_eq!(
            create.try_build(),
            Err(OperationFormError::DestinationInvalid)
        );
        create.destination = "https://subscriber.example.test/events".to_owned();
        assert_eq!(
            create.try_build(),
            Err(OperationFormError::ProtocolRequired)
        );
        create.protocol = Some(EventProtocolView::Redfish);
        assert_eq!(
            create.try_build(),
            Err(OperationFormError::EventTypesRequired)
        );
        let mut delete = no_event_action.clone();
        delete.event_action = Some(EventActionView::DeleteSubscription);
        assert_eq!(
            delete.try_build(),
            Err(OperationFormError::SubscriptionIdRequired)
        );
    }

    #[test]
    fn operation_form_drafts_build_typed_commands_and_toggle_endpoints() {
        let mut draft = OperationFormDraft::new();
        let endpoint_a = "01989abc-def0-7abc-8def-0123456789ab".to_owned();
        let endpoint_b = "01989abc-def0-7abc-8def-0123456789ac".to_owned();
        draft.toggle_endpoint(endpoint_a.clone());
        draft.toggle_endpoint(endpoint_b.clone());
        assert!(draft.is_endpoint_selected(&endpoint_a));
        assert!(draft.is_endpoint_selected(&endpoint_b));
        draft.toggle_endpoint(endpoint_a.clone());
        assert!(!draft.is_endpoint_selected(&endpoint_a));
        assert!(draft.is_endpoint_selected(&endpoint_b));

        draft.family = Some(CommandFamilyView::SystemReset);
        draft.reset_type = Some(ResetTypeView::On);
        assert_eq!(
            draft.try_build(),
            Ok(OperationCommandDraft::Reset {
                family: ResetResourceView::System,
                reset_type: ResetTypeView::On,
            })
        );

        let mut event = OperationFormDraft::new();
        event.toggle_endpoint(endpoint_a);
        event.family = Some(CommandFamilyView::EventSubscription);
        event.event_action = Some(EventActionView::CreateSubscription);
        event.destination = "https://subscriber.example.test/events".to_owned();
        event.protocol = Some(EventProtocolView::Redfish);
        event.event_types = vec![EventTypeView::Alert];
        assert_eq!(
            event.try_build(),
            Ok(OperationCommandDraft::Event(
                EventActionDraft::CreateSubscription {
                    destination: "https://subscriber.example.test/events".to_owned(),
                    protocol: EventProtocolView::Redfish,
                    event_types: vec![EventTypeView::Alert],
                }
            ))
        );

        let mut delete = OperationFormDraft::new();
        delete.toggle_endpoint(endpoint_b);
        delete.family = Some(CommandFamilyView::EventSubscription);
        delete.event_action = Some(EventActionView::DeleteSubscription);
        delete.subscription_id = "  Sub-1  ".to_owned();
        assert_eq!(
            delete.try_build(),
            Ok(OperationCommandDraft::Event(
                EventActionDraft::DeleteSubscription {
                    subscription_id: "Sub-1".to_owned(),
                }
            ))
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn oem_form_drafts_build_typed_commands_and_reject_incomplete_forms() {
        let endpoint = "01989abc-def0-7abc-8def-0123456789ad".to_owned();
        let mut draft = OperationFormDraft::new();
        draft.toggle_endpoint(endpoint.clone());
        draft.family = Some(CommandFamilyView::Oem);
        assert_eq!(
            draft.try_build(),
            Err(OperationFormError::OemActionRequired)
        );

        draft.oem_action = Some(OemActionView::ProfileUpdate);
        assert_eq!(
            draft.try_build(),
            Err(OperationFormError::ProfileFileRequired)
        );
        draft.profile_file = "  {\"UUID\":\"1\"}  ".to_owned();
        assert_eq!(
            draft.try_build(),
            Ok(OperationCommandDraft::Oem(OemCommandDraft::ProfileUpdate {
                profile_file: "{\"UUID\":\"1\"}".to_owned(),
            }))
        );

        let mut generate = OperationFormDraft::new();
        generate.toggle_endpoint(endpoint.clone());
        generate.family = Some(CommandFamilyView::Oem);
        generate.oem_action = Some(OemActionView::TokenGenerate);
        assert_eq!(
            generate.try_build(),
            Err(OperationFormError::TokenTypeRequired)
        );
        generate.token_type = Some(TokenTypeView::Frc);
        assert_eq!(
            generate.try_build(),
            Ok(OperationCommandDraft::Oem(OemCommandDraft::TokenGenerate {
                token_type: TokenTypeView::Frc,
            }))
        );

        let mut install = OperationFormDraft::new();
        install.toggle_endpoint(endpoint.clone());
        install.family = Some(CommandFamilyView::Oem);
        install.oem_action = Some(OemActionView::TokenInstall);
        assert_eq!(
            install.try_build(),
            Err(OperationFormError::TokenDataRequired)
        );
        install.token_data = "dG9rZW4tZGF0YQ==".to_owned();
        assert_eq!(
            install.try_build(),
            Ok(OperationCommandDraft::Oem(OemCommandDraft::TokenInstall {
                token_data: "dG9rZW4tZGF0YQ==".to_owned(),
            }))
        );

        let mut erase = OperationFormDraft::new();
        erase.toggle_endpoint(endpoint.clone());
        erase.family = Some(CommandFamilyView::Oem);
        erase.oem_action = Some(OemActionView::TokenErase);
        assert_eq!(
            erase.try_build(),
            Err(OperationFormError::EraseTypeRequired)
        );
        erase.erase_type = Some(EraseTypeView::EraseAll);
        assert_eq!(
            erase.try_build(),
            Err(OperationFormError::TokenTypeRequired)
        );
        erase.token_type = Some(TokenTypeView::Crdt);
        assert_eq!(
            erase.try_build(),
            Ok(OperationCommandDraft::Oem(OemCommandDraft::TokenErase {
                erase_type: EraseTypeView::EraseAll,
                token_type: TokenTypeView::Crdt,
            }))
        );

        let mut activate = OperationFormDraft::new();
        activate.toggle_endpoint(endpoint.clone());
        activate.family = Some(CommandFamilyView::Oem);
        activate.oem_action = Some(OemActionView::PowerActivatePreset);
        activate.profile_id = "not-a-number".to_owned();
        assert_eq!(
            activate.try_build(),
            Err(OperationFormError::ProfileIdInvalid)
        );
        activate.profile_id = " 3 ".to_owned();
        assert_eq!(
            activate.try_build(),
            Ok(OperationCommandDraft::Oem(
                OemCommandDraft::PowerActivatePreset { profile_id: 3 }
            ))
        );

        // The unit actions need no payload beyond the action choice.
        for action in [
            OemActionView::ProfileFactoryReset,
            OemActionView::ProfileActivate,
            OemActionView::TokenDisable,
            OemActionView::PowerApplyOverrides,
        ] {
            let mut unit = OperationFormDraft::new();
            unit.toggle_endpoint(endpoint.clone());
            unit.family = Some(CommandFamilyView::Oem);
            unit.oem_action = Some(action);
            assert!(
                unit.try_build().is_ok(),
                "action {action:?} must build without a payload"
            );
        }
    }

    #[test]
    fn built_oem_commands_serialize_to_the_domain_wire_contract() -> Result<(), Box<dyn Error>> {
        for (draft, golden) in [
            (
                OperationCommandDraft::Oem(OemCommandDraft::ProfileUpdate {
                    profile_file: "{\"UUID\":\"1\"}".to_owned(),
                }),
                r#"{"Oem":{"SystemConfigProfile":{"Update":{"profile_file":"{\"UUID\":\"1\"}"}}}}"#,
            ),
            (
                OperationCommandDraft::Oem(OemCommandDraft::ProfileFactoryReset),
                r#"{"Oem":{"SystemConfigProfile":"FactoryReset"}}"#,
            ),
            (
                OperationCommandDraft::Oem(OemCommandDraft::TokenGenerate {
                    token_type: TokenTypeView::Frc,
                }),
                r#"{"Oem":{"DebugToken":{"GenerateToken":"FRC"}}}"#,
            ),
            (
                OperationCommandDraft::Oem(OemCommandDraft::TokenErase {
                    erase_type: EraseTypeView::EraseAll,
                    token_type: TokenTypeView::Crdt,
                }),
                r#"{"Oem":{"DebugToken":{"EraseToken":{"erase_type":"EraseAll","token_type":"CRDT"}}}}"#,
            ),
            (
                OperationCommandDraft::Oem(OemCommandDraft::PowerActivatePreset { profile_id: 3 }),
                r#"{"Oem":{"PowerSmoothing":{"ActivatePresetProfile":{"profile_id":3}}}}"#,
            ),
        ] {
            let command = build_command(&draft).map_err(|error| error.message().to_owned())?;
            assert_eq!(serde_json::to_string(&command)?, golden);
        }
        Ok(())
    }

    #[test]
    fn oem_command_draft_summaries_project_face_and_payload() {
        for (draft, payload) in [
            (
                OperationCommandDraft::Oem(OemCommandDraft::ProfileUpdate {
                    profile_file: "{}".to_owned(),
                }),
                "Profile · Update",
            ),
            (
                OperationCommandDraft::Oem(OemCommandDraft::ProfileFactoryReset),
                "Profile · Factory reset",
            ),
            (
                OperationCommandDraft::Oem(OemCommandDraft::TokenGenerate {
                    token_type: TokenTypeView::Frc,
                }),
                "Token · Generate · FRC",
            ),
            (
                OperationCommandDraft::Oem(OemCommandDraft::TokenErase {
                    erase_type: EraseTypeView::EraseAll,
                    token_type: TokenTypeView::Crdt,
                }),
                "Token · Erase · EraseAll · CRDT",
            ),
            (
                OperationCommandDraft::Oem(OemCommandDraft::PowerActivatePreset { profile_id: 3 }),
                "Power smoothing · Activate preset · 3",
            ),
            (
                OperationCommandDraft::Oem(OemCommandDraft::PowerApplyOverrides),
                "Power smoothing · Apply overrides",
            ),
        ] {
            let summary = command_summary(&draft);
            assert_eq!(summary.family, "OEM (NVIDIA)");
            assert_eq!(summary.payload, payload);
        }
    }

    /// One artifact card fixture for the update choice filtering tests; the
    /// status is the only field that varies between fixtures.
    fn artifact_card_fixture(
        artifact_id: &str,
        name: &str,
        status: ArtifactStatusView,
    ) -> ArtifactCardProjection {
        ArtifactCardProjection {
            artifact_id: artifact_id.to_owned(),
            short_id: short_sha256(artifact_id),
            name: name.to_owned(),
            size_text: "8.0 MiB".to_owned(),
            sha256_short: "a1b2c3d4".to_owned(),
            status,
            uploaded_bytes: 0,
            size_bytes: 8_388_608,
            progress_percent: 0,
            created_at_text: "2026-08-06T09:10:11Z".to_owned(),
        }
    }

    #[test]
    fn update_artifact_choices_offer_only_ready_artifacts() {
        let cards = [
            artifact_card_fixture(
                "01989abc-def0-7abc-8def-0123456789aa",
                "bmc-fw-1.2.3.bin",
                ArtifactStatusView::Uploading,
            ),
            artifact_card_fixture(
                "01989abc-def0-7abc-8def-0123456789ab",
                "bmc-fw-1.2.3.bin",
                ArtifactStatusView::Ready,
            ),
            artifact_card_fixture(
                "01989abc-def0-7abc-8def-0123456789ac",
                "bmc-fw-1.2.3-corrupt.bin",
                ArtifactStatusView::Failed,
            ),
        ];
        let choices = update_artifact_choices(&cards);
        assert_eq!(choices.len(), 1);
        assert_eq!(
            choices[0].artifact_id,
            "01989abc-def0-7abc-8def-0123456789ab"
        );
        assert_eq!(choices[0].name, "bmc-fw-1.2.3.bin");
        assert_eq!(choices[0].size_text, "8.0 MiB");
        assert!(update_artifact_choices(&[]).is_empty());
    }

    #[test]
    fn update_form_validation_rejects_missing_artifact_and_invalid_push_uri() {
        let mut draft = OperationFormDraft::new();
        draft.toggle_endpoint("01989abc-def0-7abc-8def-0123456789ad".to_owned());
        draft.family = Some(CommandFamilyView::FirmwareUpdate);
        assert_eq!(draft.try_build(), Err(OperationFormError::ArtifactRequired));

        draft.artifact_id = Some("01989abc-def0-7abc-8def-0123456789ab".to_owned());
        draft.push_uri = "ftp://mirror.example.test/fw.bin".to_owned();
        assert_eq!(draft.try_build(), Err(OperationFormError::PushUriInvalid));
        draft.push_uri = "https://mirror.example.test/fw.bin extra".to_owned();
        assert_eq!(draft.try_build(), Err(OperationFormError::PushUriInvalid));
        draft.push_uri = "mirror.example.test/fw.bin".to_owned();
        assert_eq!(draft.try_build(), Err(OperationFormError::PushUriInvalid));
        draft.push_uri = "https:///fw.bin".to_owned();
        assert_eq!(draft.try_build(), Err(OperationFormError::PushUriInvalid));

        draft.push_uri = "https://mirror.example.test/fw.bin".to_owned();
        assert_eq!(
            draft.try_build(),
            Ok(OperationCommandDraft::Update(UpdateDraft {
                artifact_id: "01989abc-def0-7abc-8def-0123456789ab".to_owned(),
                push_uri: Some("https://mirror.example.test/fw.bin".to_owned()),
            }))
        );
        // Whitespace-only means the default multipart dispatch path.
        draft.push_uri = "   ".to_owned();
        assert_eq!(
            draft.try_build(),
            Ok(OperationCommandDraft::Update(UpdateDraft {
                artifact_id: "01989abc-def0-7abc-8def-0123456789ab".to_owned(),
                push_uri: None,
            }))
        );
    }

    #[test]
    fn update_command_draft_summaries_project_multipart_and_push_modes() {
        let multipart = OperationCommandDraft::Update(UpdateDraft {
            artifact_id: "01989abc-def0-7abc-8def-0123456789ab".to_owned(),
            push_uri: None,
        });
        let summary = command_summary(&multipart);
        assert_eq!(summary.family, "Firmware update");
        assert_eq!(summary.payload, "Start · 01989abc · multipart");

        let push = OperationCommandDraft::Update(UpdateDraft {
            artifact_id: "01989abc-def0-7abc-8def-0123456789ab".to_owned(),
            push_uri: Some("https://mirror.example.test/fw.bin".to_owned()),
        });
        let summary = command_summary(&push);
        assert_eq!(summary.family, "Firmware update");
        assert_eq!(
            summary.payload,
            "Start · 01989abc · push https://mirror.example.test/fw.bin"
        );
    }

    #[test]
    fn built_update_commands_serialize_to_the_canonical_wire_contract() -> Result<(), Box<dyn Error>>
    {
        // The multipart default leaves `push_uri` absent from the wire form,
        // exactly like the domain golden contract.
        let multipart = OperationCommandDraft::Update(UpdateDraft {
            artifact_id: "01989abc-def0-7abc-8def-0123456789ab".to_owned(),
            push_uri: None,
        });
        let command = build_command(&multipart).map_err(|error| error.message().to_owned())?;
        assert_eq!(
            serde_json::to_value(&command)?,
            json!({
                "Update": {
                    "StartUpdate": {
                        "artifact_id": "01989abc-def0-7abc-8def-0123456789ab"
                    }
                }
            })
        );

        let push = OperationCommandDraft::Update(UpdateDraft {
            artifact_id: "01989abc-def0-7abc-8def-0123456789ab".to_owned(),
            push_uri: Some("https://mirror.example.test/fw.bin".to_owned()),
        });
        let command = build_command(&push).map_err(|error| error.message().to_owned())?;
        assert_eq!(
            serde_json::to_value(&command)?,
            json!({
                "Update": {
                    "StartUpdate": {
                        "artifact_id": "01989abc-def0-7abc-8def-0123456789ab",
                        "push_uri": "https://mirror.example.test/fw.bin"
                    }
                }
            })
        );
        Ok(())
    }

    #[test]
    fn wire_command_summaries_render_the_update_family() -> Result<(), Box<dyn Error>> {
        for (wire, payload) in [
            (
                json!({
                    "Update": {
                        "StartUpdate": {
                            "artifact_id": "01989abc-def0-7abc-8def-0123456789ab"
                        }
                    }
                }),
                "Start · 01989abc · multipart",
            ),
            (
                json!({
                    "Update": {
                        "StartUpdate": {
                            "artifact_id": "01989abc-def0-7abc-8def-0123456789ab",
                            "push_uri": "https://mirror.example.test/fw.bin"
                        }
                    }
                }),
                "Start · 01989abc · push https://mirror.example.test/fw.bin",
            ),
        ] {
            let command = serde_json::from_value::<RedfishCommand>(wire)?;
            let summary = wire_command_summary(&command);
            assert_eq!(summary.family, "Firmware update");
            assert_eq!(summary.payload, payload);
        }
        Ok(())
    }

    #[test]
    fn operation_list_and_submit_states_render_static_messages_and_counts()
    -> Result<(), Box<dyn Error>> {
        assert!(OperationsListState::Loading.is_loading());
        assert!(OperationsListState::Failed.is_failed());
        assert_eq!(OperationsListState::Loading.count_text(), "0 operations");
        assert_eq!(OperationsListState::Failed.count_text(), "0 operations");
        let empty = OperationsListState::Ready(Vec::new());
        assert!(empty.is_ready());
        assert!(empty.has_empty_list());
        assert_eq!(empty.count_text(), "0 operations");
        assert_eq!(empty.cards().len(), 0);
        let one = OperationsListState::Ready(vec![OperationCardProjection {
            operation_id: "01989abc-def0-7abc-8def-0123456789ab".to_owned(),
            short_id: short_operation_id("01989abc-def0-7abc-8def-0123456789ab"),
            source: OperationSourceView::Standalone,
            target_count: 1,
            state: OperationStateView::Succeeded,
            command: CommandSummaryProjection {
                family: "System reset",
                payload: "PowerCycle".to_owned(),
            },
            created_at_text: "2026-08-06T09:10:11Z".to_owned(),
            updated_at_text: "2026-08-06T09:12:13Z".to_owned(),
        }]);
        assert_eq!(one.count_text(), "1 operation");
        assert!(!one.has_empty_list());
        let cards = one.cards();
        let card = cards.first().ok_or("the ready list must carry its card")?;
        assert_eq!(card.short_id, "01989abc");
        assert_eq!(card.state_label(), "Succeeded");
        assert_eq!(card.state_class(), "operation-state operation-ok");
        assert_eq!(card.source_label(), "Standalone");
        assert_eq!(
            short_operation_id("01989abc-def0-7abc-8def-0123456789ab"),
            "01989abc"
        );
        assert_eq!(short_operation_id("short"), "short");

        assert_eq!(OperationSubmitState::Idle.failure_message(), "");
        assert_eq!(OperationSubmitState::InFlight.failure_message(), "");
        assert_eq!(OperationSubmitState::Succeeded.failure_message(), "");
        assert!(OperationSubmitState::InFlight.is_in_flight());
        assert!(OperationSubmitState::Succeeded.is_succeeded());
        assert_eq!(
            OperationSubmitState::Failed(OperationSubmitState::FAILURE_MESSAGE).failure_message(),
            OperationSubmitState::FAILURE_MESSAGE
        );
        assert_eq!(
            OperationSubmitState::FAILURE_MESSAGE,
            "The operation could not be submitted. Check the fields and try again."
        );
        Ok(())
    }

    #[test]
    fn operation_endpoint_choices_project_the_inventory() -> Result<(), Box<dyn Error>> {
        let choices = operation_endpoint_choices(&inventory()?);
        assert_eq!(choices.len(), 2);
        assert_eq!(
            choices[0].endpoint_id,
            "01989abc-def0-7abc-8def-0123456789ab"
        );
        assert_eq!(choices[0].display_name, "Rack A BMC");
        assert_eq!(choices[0].address, "https://192.0.2.10/");
        assert_eq!(
            choices[1].endpoint_id,
            "01989abc-def0-7abc-8def-0123456789ac"
        );
        assert_eq!(choices[1].display_name, "Rack B BMC");
        assert_eq!(choices[1].address, "https://192.0.2.11/");
        Ok(())
    }

    /// One wire operation fixture with the given state code, pinned against
    /// the console contract exercised by the Web path tests.
    fn operation_response_fixture(state: &str) -> Result<OperationResponse, serde_json::Error> {
        serde_json::from_value(json!({
            "operation_id": "01989abc-def0-7abc-8def-0123456789ab",
            "source": "standalone",
            "targets": [
                {
                    "target_id": "01989abc-def0-7abc-8def-0123456789ac",
                    "endpoint_id": "01989abc-def0-7abc-8def-0123456789ad"
                },
                {
                    "target_id": "01989abc-def0-7abc-8def-0123456789ae",
                    "endpoint_id": "01989abc-def0-7abc-8def-0123456789af"
                }
            ],
            "command": { "System": { "Reset": "PowerCycle" } },
            "state": state,
            "created_at": "2026-08-06T09:10:11Z",
            "updated_at": "2026-08-06T09:12:13Z"
        }))
    }

    #[test]
    fn submission_acknowledgement_branches_on_the_selected_target_count()
    -> Result<(), Box<dyn Error>> {
        // One selected target acknowledges an ordinary operation response.
        let operation_body = serde_json::to_string(&operation_response_fixture("queued")?)?;
        assert_eq!(acknowledge_submission(1, &operation_body), Ok(()));

        // Several selected targets acknowledge the batch parent (§13.7): the
        // response carries the batch id and one child operation id per
        // target, and the submission succeeds even though the per-endpoint
        // batch report view is a later slice.
        let batch_body = serde_json::to_string(&rutilus_api::BatchOperationResponse::new(
            "01989abc-def0-7abc-8def-0123456789b1".parse()?,
            rutilus_api::OperationSourceResponse::Site,
            RedfishCommand::System(SystemCommand::Reset(ResetType::PowerCycle)),
            vec![
                "01989abc-def0-7abc-8def-0123456789ab".parse()?,
                "01989abc-def0-7abc-8def-0123456789ac".parse()?,
            ],
            vec![
                "01989abc-def0-7abc-8def-0123456789b2".parse()?,
                "01989abc-def0-7abc-8def-0123456789b3".parse()?,
            ],
            time::OffsetDateTime::UNIX_EPOCH,
        ))?;
        assert_eq!(acknowledge_submission(2, &batch_body), Ok(()));

        // The two contracts do not interchange: the operation acknowledgement
        // is malformed for a batch selection and the batch acknowledgement
        // for a single selection, and both map to the static failure message
        // like any other rejected or unparseable submission.
        assert_eq!(
            acknowledge_submission(2, &operation_body),
            Err(OperationSubmitState::FAILURE_MESSAGE)
        );
        assert_eq!(
            acknowledge_submission(1, &batch_body),
            Err(OperationSubmitState::FAILURE_MESSAGE)
        );
        assert_eq!(
            acknowledge_submission(3, "not json"),
            Err(OperationSubmitState::FAILURE_MESSAGE)
        );
        Ok(())
    }

    /// One wire batch summary fixture with the given derived state code and
    /// outcome buckets, pinned against the console contract.
    fn batch_summary_fixture(
        state: &str,
        outcomes: &serde_json::Value,
    ) -> Result<BatchSummaryResponse, serde_json::Error> {
        serde_json::from_value(json!({
            "batch_id": "01989abc-def0-7abc-8def-0123456789b1",
            "source": "site",
            "command": { "System": { "Reset": "PowerCycle" } },
            "state": state,
            "outcomes": outcomes,
            "created_at": "2026-08-06T09:10:11Z"
        }))
    }

    /// The canonical outcome buckets of the batch fixtures: two successes,
    /// one ordinary failure, one unsupported verdict, and one cancelled —
    /// `total` six with one child still in flight.
    fn batch_outcomes_fixture() -> serde_json::Value {
        json!({
            "succeeded": 2,
            "failed": 1,
            "unknown": 0,
            "unsupported": 1,
            "cancelled": 1,
            "total": 6
        })
    }

    #[test]
    fn batch_state_view_labels_and_classes_pin_the_six_derived_verdicts() {
        for (state, label, class) in [
            (
                BatchOperationStateResponse::Queued,
                "Queued",
                "operation-state operation-active",
            ),
            (
                BatchOperationStateResponse::Running,
                "Running",
                "operation-state operation-active",
            ),
            (
                BatchOperationStateResponse::Succeeded,
                "Succeeded",
                "operation-state operation-ok",
            ),
            (
                BatchOperationStateResponse::Failed,
                "Failed",
                "operation-state operation-error",
            ),
            (
                BatchOperationStateResponse::Unknown,
                "Unknown",
                "operation-state operation-off",
            ),
            (
                BatchOperationStateResponse::Cancelled,
                "Cancelled",
                "operation-state operation-off",
            ),
        ] {
            let view = BatchStateView::from(state);
            assert_eq!(view.label(), label);
            assert_eq!(view.class(), class);
        }
    }

    #[test]
    fn batch_card_projection_renders_the_server_derived_state_and_count_chips()
    -> Result<(), Box<dyn Error>> {
        let response = batch_summary_fixture("failed", &batch_outcomes_fixture())?;
        let card = BatchCardProjection::from(&response);

        assert_eq!(card.batch_id, "01989abc-def0-7abc-8def-0123456789b1");
        assert_eq!(card.short_id, "01989abc");
        // The derived verdict is the server's, rendered verbatim.
        assert_eq!(card.state_label(), "Failed");
        assert_eq!(card.state_class(), "operation-state operation-error");
        assert_eq!(card.command.family, "System reset");
        assert_eq!(card.command.payload, "PowerCycle");
        assert_eq!(card.created_at_text, "2026-08-06T09:10:11Z");
        // The five chips render the server counts verbatim in fixed order —
        // the client never derives a batch outcome from the children.
        let chips = card.outcomes.chips();
        assert_eq!(
            chips
                .iter()
                .map(|chip| (chip.label, chip.count))
                .collect::<Vec<_>>(),
            [
                ("Succeeded", 2),
                ("Failed", 1),
                ("Unknown", 0),
                ("Unsupported", 1),
                ("Cancelled", 1),
            ]
        );
        // The unsupported verdict is a distinct chip: it never masquerades as
        // an ordinary failure count.
        assert_eq!(chips[3].label, "Unsupported");
        assert_eq!(chips[3].count, 1);
        assert_eq!(chips[1].count, 1);
        // The card starts with no children; the per-endpoint rows arrive with
        // the detail fetch on first expand.
        assert!(card.children.is_empty());
        Ok(())
    }

    #[test]
    fn batch_card_projection_parses_fixtures_for_all_six_derived_states()
    -> Result<(), Box<dyn Error>> {
        for (state_code, label, class) in [
            ("queued", "Queued", "operation-state operation-active"),
            ("running", "Running", "operation-state operation-active"),
            ("succeeded", "Succeeded", "operation-state operation-ok"),
            ("failed", "Failed", "operation-state operation-error"),
            ("unknown", "Unknown", "operation-state operation-off"),
            ("cancelled", "Cancelled", "operation-state operation-off"),
        ] {
            let response = batch_summary_fixture(state_code, &batch_outcomes_fixture())?;
            let card = BatchCardProjection::from(&response);
            assert_eq!(card.state_label(), label, "state code {state_code}");
            assert_eq!(card.state_class(), class, "state code {state_code}");
            assert_eq!(card.outcomes.chips()[3].count, 1, "state code {state_code}");
        }
        Ok(())
    }

    #[test]
    fn batch_children_projection_pairs_every_endpoint_with_its_display_name()
    -> Result<(), Box<dyn Error>> {
        let inventory = inventory()?;
        let detail = serde_json::from_value::<BatchDetailResponse>(json!({
            "batch_id": "01989abc-def0-7abc-8def-0123456789b1",
            "source": "site",
            "command": { "System": { "Reset": "PowerCycle" } },
            "state": "running",
            "outcomes": batch_outcomes_fixture(),
            "created_at": "2026-08-06T09:10:11Z",
            "children": [
                {
                    "operation_id": "01989abc-def0-7abc-8def-0123456789b2",
                    "source": "site",
                    "targets": [
                        {
                            "target_id": "01989abc-def0-7abc-8def-0123456789b3",
                            "endpoint_id": "01989abc-def0-7abc-8def-0123456789ab"
                        }
                    ],
                    "command": { "System": { "Reset": "PowerCycle" } },
                    "state": "succeeded",
                    "created_at": "2026-08-06T09:10:11Z",
                    "updated_at": "2026-08-06T09:12:13Z"
                },
                {
                    "operation_id": "01989abc-def0-7abc-8def-0123456789b4",
                    "source": "site",
                    "targets": [
                        {
                            "target_id": "01989abc-def0-7abc-8def-0123456789b5",
                            "endpoint_id": "01989abc-def0-7abc-8def-0123456789ac"
                        }
                    ],
                    "command": { "System": { "Reset": "PowerCycle" } },
                    "state": "failed",
                    "created_at": "2026-08-06T09:10:11Z",
                    "updated_at": "2026-08-06T09:12:13Z"
                },
                {
                    "operation_id": "01989abc-def0-7abc-8def-0123456789b6",
                    "source": "site",
                    "targets": [
                        {
                            "target_id": "01989abc-def0-7abc-8def-0123456789b7",
                            "endpoint_id": "01989abc-def0-7abc-8def-0123456789dd"
                        }
                    ],
                    "command": { "System": { "Reset": "PowerCycle" } },
                    "state": "queued",
                    "created_at": "2026-08-06T09:10:11Z",
                    "updated_at": "2026-08-06T09:10:11Z"
                }
            ]
        }))?;

        let rows = batch_children_projection(&detail, &inventory);

        assert_eq!(rows.len(), 3);
        // The display names come from the loaded inventory, exactly like the
        // operation form's target choices.
        assert_eq!(rows[0].endpoint_id, "01989abc-def0-7abc-8def-0123456789ab");
        assert_eq!(rows[0].display_name, "Rack A BMC");
        assert_eq!(rows[0].state, OperationStateView::Succeeded);
        assert_eq!(rows[1].endpoint_id, "01989abc-def0-7abc-8def-0123456789ac");
        assert_eq!(rows[1].display_name, "Rack B BMC");
        assert_eq!(rows[1].state, OperationStateView::Failed);
        // An endpoint missing from the inventory falls back to its short id
        // instead of inventing a name.
        assert_eq!(rows[2].endpoint_id, "01989abc-def0-7abc-8def-0123456789dd");
        assert_eq!(rows[2].display_name, "01989abc");
        assert_eq!(rows[2].state, OperationStateView::Queued);
        Ok(())
    }

    #[test]
    fn batches_list_state_renders_static_messages_and_counts() -> Result<(), Box<dyn Error>> {
        assert!(BatchesListState::Loading.is_loading());
        assert!(BatchesListState::Failed.is_failed());
        assert_eq!(BatchesListState::Loading.count_text(), "0 batches");
        assert_eq!(BatchesListState::Failed.count_text(), "0 batches");
        let empty = BatchesListState::Ready(Vec::new());
        assert!(empty.is_ready());
        assert!(empty.has_empty_list());
        assert_eq!(empty.count_text(), "0 batches");
        assert_eq!(empty.cards().len(), 0);
        let response = batch_summary_fixture("failed", &batch_outcomes_fixture())?;
        let one = BatchesListState::Ready(vec![BatchCardProjection::from(&response)]);
        assert_eq!(one.count_text(), "1 batch");
        assert!(!one.has_empty_list());
        assert_eq!(one.cards().len(), 1);
        Ok(())
    }

    #[test]
    fn operation_card_projection_parses_fixtures_for_all_nine_states() -> Result<(), Box<dyn Error>>
    {
        for (state_code, label, class) in [
            ("queued", "Queued", "operation-state operation-active"),
            (
                "validating",
                "Validating",
                "operation-state operation-active",
            ),
            ("running", "Running", "operation-state operation-active"),
            (
                "waiting_remote",
                "Waiting for BMC",
                "operation-state operation-active",
            ),
            ("verifying", "Verifying", "operation-state operation-active"),
            ("succeeded", "Succeeded", "operation-state operation-ok"),
            ("failed", "Failed", "operation-state operation-error"),
            ("unknown", "Unknown", "operation-state operation-off"),
            ("cancelled", "Cancelled", "operation-state operation-off"),
        ] {
            let response = operation_response_fixture(state_code)?;
            let card = OperationCardProjection::from(&response);
            assert_eq!(card.operation_id, "01989abc-def0-7abc-8def-0123456789ab");
            assert_eq!(card.short_id, "01989abc");
            assert_eq!(card.source_label(), "Standalone");
            assert_eq!(card.target_count, 2);
            assert_eq!(card.command.family, "System reset");
            assert_eq!(card.command.payload, "PowerCycle");
            assert_eq!(card.created_at_text, "2026-08-06T09:10:11Z");
            assert_eq!(card.updated_at_text, "2026-08-06T09:12:13Z");
            assert_eq!(card.state_label(), label);
            assert_eq!(card.state_class(), class);
        }
        Ok(())
    }

    #[test]
    fn operation_card_projection_parses_center_and_site_sources() -> Result<(), Box<dyn Error>> {
        let mut site = serde_json::from_value::<OperationResponse>(json!({
            "operation_id": "01989abc-def0-7abc-8def-0123456789c0",
            "source": "site",
            "targets": [
                {
                    "target_id": "01989abc-def0-7abc-8def-0123456789ac",
                    "endpoint_id": "01989abc-def0-7abc-8def-0123456789ad"
                }
            ],
            "command": { "Manager": { "Reset": "GracefulRestart" } },
            "state": "succeeded",
            "created_at": "2026-08-06T09:10:11Z",
            "updated_at": "2026-08-06T09:12:13Z"
        }))?;
        let card = OperationCardProjection::from(&site);
        assert_eq!(card.source_label(), "Site");
        assert_eq!(card.command.family, "Manager reset");
        assert_eq!(card.command.payload, "GracefulRestart");
        assert_eq!(card.target_count, 1);
        assert_eq!(card.state_label(), "Succeeded");

        site = serde_json::from_value(json!({
            "operation_id": "01989abc-def0-7abc-8def-0123456789c0",
            "source": "center",
            "targets": [],
            "command": { "Chassis": { "Reset": "ForceOff" } },
            "state": "cancelled",
            "created_at": "2026-08-06T09:10:11Z",
            "updated_at": "2026-08-06T09:12:13Z"
        }))?;
        let card = OperationCardProjection::from(&site);
        assert_eq!(card.source_label(), "Center");
        assert_eq!(card.command.family, "Chassis reset");
        assert_eq!(card.command.payload, "ForceOff");
        assert_eq!(card.target_count, 0);
        assert_eq!(card.state_label(), "Cancelled");
        Ok(())
    }

    // The wire literal table exceeds the pedantic line budget, so the lint
    // is scoped here exactly like the other fixture-table tests.
    #[allow(clippy::too_many_lines)]
    #[test]
    fn wire_command_summaries_render_every_family() -> Result<(), Box<dyn Error>> {
        for (wire, family, payload) in [
            (json!({ "System": { "Reset": "On" } }), "System reset", "On"),
            (
                json!({ "Manager": { "Reset": "GracefulRestart" } }),
                "Manager reset",
                "GracefulRestart",
            ),
            (
                json!({ "Chassis": { "Reset": "ForceOff" } }),
                "Chassis reset",
                "ForceOff",
            ),
            (
                json!({
                    "Boot": {
                        "SetBootSourceOverride": {
                            "source": "Pxe",
                            "enabled": "Once",
                            "mode": "UEFI"
                        }
                    }
                }),
                "Boot source override",
                "Pxe · Once · UEFI",
            ),
            (json!({ "SecureBoot": "Enable" }), "Secure Boot", "Enable"),
            (json!({ "SecureBoot": "Disable" }), "Secure Boot", "Disable"),
            (
                json!({ "SecureBoot": { "ResetKeys": "ResetAllKeysToDefault" } }),
                "Secure Boot",
                "Reset keys · ResetAllKeysToDefault",
            ),
            (
                json!({
                    "Event": {
                        "CreateSubscription": {
                            "destination": "https://subscriber.example.test/events",
                            "protocol": "Redfish",
                            "event_types": ["Alert", "StatusChange"]
                        }
                    }
                }),
                "Event subscription",
                "Create · https://subscriber.example.test/events · Redfish · Alert, StatusChange",
            ),
            (
                json!({ "Event": { "DeleteSubscription": { "subscription_id": "Sub-1" } } }),
                "Event subscription",
                "Delete · Sub-1",
            ),
            (
                json!({
                    "Oem": {
                        "SystemConfigProfile": {
                            "Update": { "profile_file": "{}" }
                        }
                    }
                }),
                "OEM (NVIDIA)",
                "Profile · Update",
            ),
            (
                json!({ "Oem": { "SystemConfigProfile": "FactoryReset" } }),
                "OEM (NVIDIA)",
                "Profile · Factory reset",
            ),
            (
                json!({ "Oem": { "SystemConfigProfile": "ActivateProfile" } }),
                "OEM (NVIDIA)",
                "Profile · Activate",
            ),
            (
                json!({ "Oem": { "DebugToken": { "GenerateToken": "FRC" } } }),
                "OEM (NVIDIA)",
                "Token · Generate · FRC",
            ),
            (
                json!({ "Oem": { "DebugToken": { "InstallToken": { "token_data": "AA==" } } } }),
                "OEM (NVIDIA)",
                "Token · Install",
            ),
            (
                json!({ "Oem": { "DebugToken": "DisableToken" } }),
                "OEM (NVIDIA)",
                "Token · Disable",
            ),
            (
                json!({
                    "Oem": {
                        "DebugToken": {
                            "EraseToken": {
                                "erase_type": "EraseAll",
                                "token_type": "CRDT"
                            }
                        }
                    }
                }),
                "OEM (NVIDIA)",
                "Token · Erase · EraseAll · CRDT",
            ),
            (
                json!({
                    "Oem": {
                        "PowerSmoothing": {
                            "ActivatePresetProfile": { "profile_id": 3 }
                        }
                    }
                }),
                "OEM (NVIDIA)",
                "Power smoothing · Activate preset · 3",
            ),
            (
                json!({ "Oem": { "PowerSmoothing": "ApplyAdminOverrides" } }),
                "OEM (NVIDIA)",
                "Power smoothing · Apply overrides",
            ),
        ] {
            let command = serde_json::from_value::<RedfishCommand>(wire)?;
            let summary = wire_command_summary(&command);
            assert_eq!(summary.family, family);
            assert_eq!(summary.payload, payload);
        }
        Ok(())
    }

    #[test]
    fn built_commands_serialize_to_the_canonical_wire_contract() -> Result<(), Box<dyn Error>> {
        for (draft, golden) in [
            (
                OperationCommandDraft::Reset {
                    family: ResetResourceView::System,
                    reset_type: ResetTypeView::PowerCycle,
                },
                json!({ "System": { "Reset": "PowerCycle" } }),
            ),
            (
                OperationCommandDraft::BootOverride {
                    source: BootSourceView::Pxe,
                    enabled: BootEnabledView::Once,
                    mode: BootModeView::Uefi,
                },
                json!({
                    "Boot": {
                        "SetBootSourceOverride": {
                            "source": "Pxe",
                            "enabled": "Once",
                            "mode": "UEFI"
                        }
                    }
                }),
            ),
            (
                OperationCommandDraft::SecureBoot(SecureBootActionView::ResetKeys(
                    ResetKeysTypeView::DeletePk,
                )),
                json!({ "SecureBoot": { "ResetKeys": "DeletePK" } }),
            ),
            (
                OperationCommandDraft::Event(EventActionDraft::CreateSubscription {
                    destination: "https://subscriber.example.test/events".to_owned(),
                    protocol: EventProtocolView::Redfish,
                    event_types: vec![EventTypeView::Alert],
                }),
                json!({
                    "Event": {
                        "CreateSubscription": {
                            "destination": "https://subscriber.example.test/events",
                            "protocol": "Redfish",
                            "event_types": ["Alert"]
                        }
                    }
                }),
            ),
            (
                OperationCommandDraft::Event(EventActionDraft::DeleteSubscription {
                    subscription_id: "Sub-1".to_owned(),
                }),
                json!({ "Event": { "DeleteSubscription": { "subscription_id": "Sub-1" } } }),
            ),
        ] {
            let command = build_command(&draft).map_err(|error| error.message().to_owned())?;
            assert_eq!(serde_json::to_value(&command)?, golden);
        }
        Ok(())
    }

    fn overview_card(
        endpoint_id: &str,
        display_name: &str,
        address: &str,
        vendor: Option<&str>,
        health_level: HealthLevel,
    ) -> EndpointCardProjection {
        EndpointCardProjection {
            endpoint_id: endpoint_id.to_owned(),
            display_name: display_name.to_owned(),
            address: address.to_owned(),
            trust_label: "System CA",
            snapshot_label: "Generation 1 · observed 2026-08-05T09:12:13Z".to_owned(),
            resource_counts: Some(ResourceCountsProjection {
                systems: 1,
                chassis: 1,
                managers: 1,
            }),
            resources: Vec::new(),
            vendor: vendor.map(str::to_owned),
            health_level,
            health_label: None,
            oem_section: OemSectionProjection::UnsupportedByNvRedfishBaseline,
        }
    }

    fn group_response(
        group_id: &str,
        name: &str,
        members: &[&str],
    ) -> Result<GroupResponse, serde_json::Error> {
        serde_json::from_value(json!({
            "group_id": group_id,
            "name": name,
            "member_endpoint_ids": members,
            "created_at": "2026-08-05T09:10:11Z",
            "updated_at": "2026-08-05T09:12:13Z"
        }))
    }

    fn tag_list_response(
        bindings: &[(&str, &str, &str)],
    ) -> Result<TagListResponse, serde_json::Error> {
        let tags = bindings
            .iter()
            .map(|(tag_id, endpoint_id, name)| {
                json!({ "tag_id": tag_id, "endpoint_id": endpoint_id, "name": name })
            })
            .collect::<Vec<_>>();
        serde_json::from_value(json!({ "tags": tags }))
    }

    fn selections(
        search: &str,
        tags: &[&str],
        vendors: &[&str],
        health: &[HealthLevel],
    ) -> OverviewFilterSelections {
        OverviewFilterSelections {
            search: search.to_owned(),
            tags: tags.iter().map(|tag| (*tag).to_owned()).collect(),
            vendors: vendors.iter().map(|vendor| (*vendor).to_owned()).collect(),
            health: health.iter().copied().collect(),
        }
    }

    fn resource_with_health(
        resource_type: &str,
        health: Option<&str>,
    ) -> Result<CoreResourceResponse, serde_json::Error> {
        let status = health
            .map(|health| json!({ "state": "Enabled", "health": health, "health_rollup": null }));
        let details = if resource_type == "chassis" {
            json!({ "chassis_type": "RackMount", "status": status })
        } else {
            json!({ "status": status })
        };
        serde_json::from_value(json!({
            "source": {
                "resource_id": "01989abc-def0-7abc-8def-0123456789f0",
                "odata_id": "/redfish/v1/Systems/1",
                "odata_type": null,
                "etag": null
            },
            "common": { "id": "1", "name": "One", "description": null },
            "resource": {
                "resource_type": resource_type,
                "details": details
            }
        }))
    }

    #[test]
    fn overview_search_filters_by_name_and_address_substrings() {
        let cards = vec![
            overview_card(
                "01989abc-def0-7abc-8def-0123456789ab",
                "Rack A BMC",
                "https://192.0.2.10/",
                Some("Vendor A"),
                HealthLevel::Ok,
            ),
            overview_card(
                "01989abc-def0-7abc-8def-0123456789ac",
                "Rack B BMC",
                "https://192.0.2.11/",
                Some("Vendor B"),
                HealthLevel::Warning,
            ),
        ];
        let tags = TagInventoryView::new(Vec::new());

        // The search matches display-name and address substrings,
        // case-insensitively.
        let by_name = apply_overview_filters(&cards, &tags, &selections("rack b", &[], &[], &[]));
        assert_eq!(by_name.len(), 1);
        assert_eq!(by_name[0].display_name, "Rack B BMC");

        let by_address =
            apply_overview_filters(&cards, &tags, &selections("192.0.2.10", &[], &[], &[]));
        assert_eq!(by_address.len(), 1);
        assert_eq!(by_address[0].display_name, "Rack A BMC");

        // Whitespace around the needle is ignored; an unmatched needle
        // filters everything out.
        assert_eq!(
            apply_overview_filters(&cards, &tags, &selections("  RACK A  ", &[], &[], &[])).len(),
            1
        );
        assert!(
            apply_overview_filters(&cards, &tags, &selections("nowhere", &[], &[], &[])).is_empty()
        );
        assert_eq!(
            apply_overview_filters(&cards, &tags, &selections("", &[], &[], &[])).len(),
            2
        );
    }

    #[test]
    fn overview_filters_combine_with_and_semantics() {
        let first = "01989abc-def0-7abc-8def-0123456789ab";
        let second = "01989abc-def0-7abc-8def-0123456789ac";
        let third = "01989abc-def0-7abc-8def-0123456789ad";
        let cards = vec![
            overview_card(
                first,
                "Rack A BMC",
                "https://192.0.2.10/",
                Some("Vendor A"),
                HealthLevel::Ok,
            ),
            overview_card(
                second,
                "Rack B BMC",
                "https://192.0.2.11/",
                Some("Vendor A"),
                HealthLevel::Warning,
            ),
            overview_card(
                third,
                "Rack C BMC",
                "https://192.0.2.12/",
                Some("Vendor B"),
                HealthLevel::Critical,
            ),
        ];
        let tags = TagInventoryView::new(vec![
            TagView::new(
                "tier-1".to_owned(),
                vec![first.to_owned(), second.to_owned()],
            ),
            TagView::new("edge".to_owned(), vec![third.to_owned()]),
        ]);

        // Within a dimension the selected values are `ORed`.
        let by_tag = apply_overview_filters(&cards, &tags, &selections("", &["tier-1"], &[], &[]));
        assert_eq!(by_tag.len(), 2);
        let by_vendor =
            apply_overview_filters(&cards, &tags, &selections("", &[], &["Vendor A"], &[]));
        assert_eq!(by_vendor.len(), 2);
        let by_health = apply_overview_filters(
            &cards,
            &tags,
            &selections("", &[], &[], &[HealthLevel::Critical]),
        );
        assert_eq!(by_health.len(), 1);

        // Across dimensions the constraints are `ANDed`: Rack B is Vendor A
        // but not OK, and no card is both tier-1 and Vendor B.
        let combined = apply_overview_filters(
            &cards,
            &tags,
            &selections("", &["tier-1"], &["Vendor A"], &[HealthLevel::Ok]),
        );
        assert_eq!(combined.len(), 1);
        assert_eq!(combined[0].display_name, "Rack A BMC");
        assert!(
            apply_overview_filters(
                &cards,
                &tags,
                &selections("", &["tier-1"], &["Vendor B"], &[]),
            )
            .is_empty()
        );
    }

    #[test]
    fn overview_empty_result_when_filters_exclude_every_card() {
        let cards = vec![overview_card(
            "01989abc-def0-7abc-8def-0123456789ab",
            "Rack A BMC",
            "https://192.0.2.10/",
            Some("Vendor A"),
            HealthLevel::Ok,
        )];
        let tags = TagInventoryView::new(Vec::new());
        let selections = selections("", &[], &["Vendor B"], &[]);
        assert!(!selections.is_empty());
        assert!(
            apply_overview_filters(&cards, &tags, &selections).is_empty(),
            "a vendor that no card carries filters the whole list out"
        );
        assert!(
            OverviewFilterSelections::default().is_empty(),
            "an untouched filter bar constrains nothing"
        );
    }

    #[test]
    fn overview_vendor_and_health_choices_derive_from_cards() {
        let cards = vec![
            overview_card(
                "01989abc-def0-7abc-8def-0123456789ab",
                "Rack A BMC",
                "https://192.0.2.10/",
                Some("Vendor A"),
                HealthLevel::Ok,
            ),
            overview_card(
                "01989abc-def0-7abc-8def-0123456789ac",
                "Rack B BMC",
                "https://192.0.2.11/",
                Some("Vendor B"),
                HealthLevel::Warning,
            ),
            overview_card(
                "01989abc-def0-7abc-8def-0123456789ad",
                "Rack C BMC",
                "https://192.0.2.12/",
                Some("Vendor A"),
                HealthLevel::Unknown,
            ),
            overview_card(
                "01989abc-def0-7abc-8def-0123456789ae",
                "Rack D BMC",
                "https://192.0.2.13/",
                None,
                HealthLevel::Unknown,
            ),
        ];
        assert_eq!(
            vendor_choices(&cards),
            vec!["Vendor A".to_owned(), "Vendor B".to_owned()]
        );
        assert_eq!(
            health_choices(&cards),
            vec![HealthLevel::Warning, HealthLevel::Ok, HealthLevel::Unknown]
        );
    }

    #[test]
    fn aggregate_health_takes_the_worst_status_across_resource_families()
    -> Result<(), Box<dyn Error>> {
        let ok_system = resource_with_health("system", Some("OK"))?;
        let warning_chassis = resource_with_health("chassis", Some("Warning"))?;
        let critical_manager = resource_with_health("manager", Some("Critical"))?;
        assert_eq!(
            aggregate_health(&[ok_system.clone(), warning_chassis.clone(), critical_manager]),
            HealthLevel::Critical
        );
        assert_eq!(
            aggregate_health(&[ok_system, warning_chassis]),
            HealthLevel::Warning
        );

        // A family without a health status contributes nothing, and a
        // vendor's unknown spelling neither invents a level nor distorts the
        // aggregation.
        assert_eq!(
            aggregate_health(&[resource_with_health("system", Some("Degraded"))?]),
            HealthLevel::Unknown
        );
        assert_eq!(
            aggregate_health(&[resource_with_health("system", None)?]),
            HealthLevel::Unknown
        );
        assert_eq!(aggregate_health(&[]), HealthLevel::Unknown);
        Ok(())
    }

    #[test]
    fn endpoint_card_projection_extracts_vendor_and_unified_health() -> Result<(), Box<dyn Error>> {
        let state =
            ConsoleLoadState::accepted(about(PRODUCT_ID), inventory()?, resource_inventories()?);
        let cards = state.endpoint_cards();
        let waiting = cards.first().ok_or("waiting endpoint must exist")?;
        let current = cards.get(1).ok_or("current endpoint must exist")?;

        // The awaiting endpoint has no Service Root observation yet.
        assert_eq!(waiting.vendor, None);
        assert_eq!(waiting.health_level, HealthLevel::Unknown);
        assert_eq!(waiting.health_label, None);

        // The current endpoint publishes a Service Root vendor and a System
        // status; the raw health text is retained beside the unified level.
        assert_eq!(current.vendor.as_deref(), Some("Vendor A"));
        assert_eq!(current.health_level, HealthLevel::Ok);
        assert_eq!(current.health_label.as_deref(), Some("OK"));
        Ok(())
    }

    #[test]
    fn groups_list_projects_name_count_and_member_short_ids() -> Result<(), Box<dyn Error>> {
        let group = group_response(
            "01989abc-def0-7abc-8def-0123456789ab",
            "Production",
            &[
                "01989abc-def0-7abc-8def-0123456789ac",
                "01989abc-def0-7abc-8def-0123456789ad",
            ],
        )?;
        let card = GroupCardProjection::from(&group);
        assert_eq!(card.group_id, "01989abc-def0-7abc-8def-0123456789ab");
        assert_eq!(card.name, "Production");
        assert_eq!(card.member_count_text, "2 members");
        assert_eq!(
            card.member_short_ids,
            vec!["01989abc".to_owned(), "01989abc".to_owned()]
        );

        let single = GroupCardProjection::from(&group_response(
            "01989abc-def0-7abc-8def-0123456789ae",
            "Solo",
            &["01989abc-def0-7abc-8def-0123456789af"],
        )?);
        assert_eq!(single.member_count_text, "1 member");

        let state = GroupsListState::Ready(vec![card, single]);
        assert_eq!(state.count_text(), "2 groups");
        assert!(!state.has_empty_list());
        assert_eq!(state.group_cards().len(), 2);
        assert!(GroupsListState::Ready(Vec::new()).has_empty_list());
        Ok(())
    }

    #[test]
    fn group_name_draft_rejects_blank_control_and_overlong_names() {
        assert_eq!(
            group_name_draft_error("   "),
            Err(GroupNameDraftError::Required)
        );
        assert_eq!(
            group_name_draft_error("bad\u{0}name"),
            Err(GroupNameDraftError::ControlCharacter)
        );
        let overlong = "a".repeat(MAX_GROUP_NAME_CHARS + 1);
        assert_eq!(
            group_name_draft_error(&overlong),
            Err(GroupNameDraftError::TooLong)
        );
        assert_eq!(
            group_name_draft_error(&"a".repeat(MAX_GROUP_NAME_CHARS)),
            Ok(())
        );
        assert_eq!(group_name_draft_error("Production"), Ok(()));
    }

    #[test]
    fn group_detail_joins_members_and_offers_only_unassigned_endpoints()
    -> Result<(), Box<dyn Error>> {
        let inventory = inventory()?;
        let endpoints = inventory.endpoints();
        let first_id = "01989abc-def0-7abc-8def-0123456789ab";
        let detail = group_response(
            "01989abc-def0-7abc-8def-0123456789e0",
            "Rack A",
            &[first_id, "01989abc-def0-7abc-8def-0123456789ff"],
        )?;
        let projection = GroupDetailProjection::from_response(&detail, endpoints);

        // The inventory join renders the managed member with its display
        // name and address; a member that left the inventory renders
        // defensively instead of dropping the row.
        assert_eq!(projection.members.len(), 2);
        assert_eq!(projection.members[0].display_name, "Rack A BMC");
        assert_eq!(projection.members[0].address, "https://192.0.2.10/");
        assert_eq!(projection.members[1].display_name, "Unknown endpoint");
        assert!(!projection.has_no_members());

        // Only the managed endpoint not yet in the group is offered as an
        // add choice; toggling it into the selection set and back simulates
        // the checkbox interaction state.
        let choices = group_member_choices(endpoints, &projection);
        assert_eq!(choices.len(), 1);
        assert_eq!(choices[0].display_name, "Rack B BMC");
        let mut selection = BTreeSet::new();
        toggle_set_membership(&mut selection, choices[0].endpoint_id.clone());
        assert!(selection.contains(&choices[0].endpoint_id));
        toggle_set_membership(&mut selection, choices[0].endpoint_id.clone());
        assert!(selection.is_empty());
        Ok(())
    }

    #[test]
    fn tag_inventory_projects_cards_and_supports_endpoint_membership_lookup()
    -> Result<(), Box<dyn Error>> {
        let first = "01989abc-def0-7abc-8def-0123456789ab";
        let second = "01989abc-def0-7abc-8def-0123456789ac";
        let response = tag_list_response(&[
            ("01989abc-def0-7abc-8def-0123456789b1", first, "tier-1"),
            ("01989abc-def0-7abc-8def-0123456789b2", second, "tier-1"),
            ("01989abc-def0-7abc-8def-0123456789b3", second, "edge"),
        ])?;
        let tags = TagInventoryView::from(&response);

        // The flat binding list is grouped by tag name, preserving the wire
        // order within each tag.
        assert_eq!(tags.tags().len(), 2);
        assert_eq!(tags.tags()[0].name(), "tier-1");
        assert_eq!(
            tags.tags()[0].endpoint_ids(),
            &[first.to_owned(), second.to_owned()]
        );
        assert_eq!(tags.tags()[1].name(), "edge");

        // The membership lookup inverts the tag → endpoints mapping for the
        // Overview tag filter.
        assert_eq!(
            endpoint_tags(first, &tags),
            BTreeSet::from(["tier-1".to_owned()])
        );
        assert_eq!(
            endpoint_tags(second, &tags),
            BTreeSet::from(["tier-1".to_owned(), "edge".to_owned()])
        );
        assert!(endpoint_tags("01989abc-def0-7abc-8def-0123456789ad", &tags).is_empty());

        let state = TagsListState::Ready(tags);
        let cards = state.tag_cards();
        assert_eq!(cards.len(), 2);
        assert_eq!(cards[0].name, "tier-1");
        assert_eq!(cards[0].endpoint_count_text, "2 endpoints");
        assert_eq!(cards[0].endpoints[0].short_id, "01989abc");
        assert_eq!(cards[0].endpoints[0].endpoint_id, first);
        assert_eq!(cards[1].endpoint_count_text, "1 endpoint");

        // The tag names feed the filter chips in a stable sorted order.
        assert_eq!(
            state.tag_names(),
            vec!["edge".to_owned(), "tier-1".to_owned()]
        );
        assert!(!state.has_empty_tags());
        Ok(())
    }

    #[test]
    fn percent_encoding_keeps_unreserved_characters_and_encodes_the_rest() {
        assert_eq!(percent_encode_path_segment("tier-1"), "tier-1");
        assert_eq!(percent_encode_path_segment("Rack A"), "Rack%20A");
        assert_eq!(percent_encode_path_segment("a/b"), "a%2Fb");
        assert_eq!(percent_encode_path_segment("réservé"), "r%C3%A9serv%C3%A9");
    }

    #[test]
    fn tag_draft_requires_an_endpoint_and_a_valid_tag_name() {
        let endpoint = Some("01989abc-def0-7abc-8def-0123456789ab");
        assert_eq!(
            tag_draft_error(None, "tier-1"),
            Err(TagDraftError::EndpointRequired)
        );
        assert_eq!(
            tag_draft_error(endpoint, "  "),
            Err(TagDraftError::NameRequired)
        );
        assert_eq!(
            tag_draft_error(endpoint, "bad\u{0}tag"),
            Err(TagDraftError::ControlCharacter)
        );
        let overlong = "a".repeat(MAX_TAG_NAME_CHARS + 1);
        assert_eq!(
            tag_draft_error(endpoint, &overlong),
            Err(TagDraftError::TooLong)
        );
        // Spaces and slashes are valid tag characters: the domain `TagName`
        // accepts them and the removal route percent-encodes them.
        assert_eq!(tag_draft_error(endpoint, "tier-1"), Ok(()));
        assert_eq!(tag_draft_error(endpoint, "Rack A"), Ok(()));
        assert_eq!(tag_draft_error(endpoint, "a/b"), Ok(()));
    }

    #[test]
    fn grouping_states_render_typed_progress_copy() -> Result<(), Box<dyn Error>> {
        // The wire group DTO carries the full member set the projections
        // consume.
        let group = group_response(
            "01989abc-def0-7abc-8def-0123456789ab",
            "Prod",
            &["01989abc-def0-7abc-8def-0123456789ac"],
        )?;
        assert_eq!(group.name(), "Prod");
        assert_eq!(group.member_endpoint_ids().len(), 1);

        // Every group-list phase renders a distinct static status.
        assert!(!GroupsListState::Idle.is_ready());
        assert!(GroupsListState::Loading.is_loading());
        assert!(!GroupsListState::Loading.is_ready());
        assert!(GroupsListState::Failed.is_failed());
        assert_eq!(
            GroupsListState::Failed.failure_message(),
            "The group list is temporarily unavailable."
        );
        assert_eq!(GroupsListState::Ready(Vec::new()).count_text(), "0 groups");

        // The group-detail phases mirror the list phases.
        assert!(!GroupDetailState::Idle.is_loading());
        assert!(GroupDetailState::Loading.is_loading());
        assert!(GroupDetailState::Failed.is_failed());
        assert_eq!(
            GroupDetailState::Failed.failure_message(),
            "The group detail is temporarily unavailable."
        );
        assert!(
            GroupDetailState::Ready(GroupDetailProjection::from_response(
                &group,
                inventory()?.endpoints(),
            ))
            .ready_projection()
            .is_some()
        );

        // The tag phases, including the shared inventory accessor.
        assert!(TagsListState::Loading.is_loading());
        assert!(TagsListState::Failed.is_failed());
        assert_eq!(
            TagsListState::Failed.failure_message(),
            "The tag inventory is temporarily unavailable."
        );
        assert!(TagsListState::Idle.inventory().is_none());
        let tags_ready = TagsListState::Ready(TagInventoryView::new(Vec::new()));
        assert!(tags_ready.is_ready());
        assert!(tags_ready.inventory().is_some());
        assert!(tags_ready.has_empty_tags());
        assert!(tags_ready.tag_names().is_empty());

        // The submission-progress states carry the typed progression the
        // forms render.
        let create_progress = [
            GroupCreateState::Idle,
            GroupCreateState::InFlight,
            GroupCreateState::Created,
            GroupCreateState::Failed("boom".to_owned()),
        ];
        assert_eq!(create_progress.len(), 4);
        let member_progress = [
            GroupMemberActionState::Idle,
            GroupMemberActionState::InFlight,
            GroupMemberActionState::Succeeded,
            GroupMemberActionState::Failed("boom".to_owned()),
        ];
        assert_eq!(member_progress.len(), 4);
        let tag_progress = [
            TagApplyState::Idle,
            TagApplyState::InFlight,
            TagApplyState::Applied,
            TagApplyState::Failed("boom".to_owned()),
        ];
        assert_eq!(tag_progress.len(), 4);

        // The create and tag drafts validate through the shared rules.
        let mut group_draft = GroupDraft::new();
        assert_eq!(group_draft.validate(), Err(GroupNameDraftError::Required));
        group_draft.name = "Prod".to_owned();
        assert_eq!(group_draft.validate(), Ok(()));
        let mut tag_draft = TagDraft::new();
        assert_eq!(tag_draft.validate(), Err(TagDraftError::EndpointRequired));
        tag_draft.endpoint_id = Some("01989abc-def0-7abc-8def-0123456789ab".to_owned());
        tag_draft.name = "tier-1".to_owned();
        assert_eq!(tag_draft.validate(), Ok(()));

        // The health badge vocabulary stays closed and labelled.
        assert_eq!(health_level_label(HealthLevel::Unknown), "Unknown");
        assert_eq!(health_level_label(HealthLevel::Ok), "OK");
        assert_eq!(health_level_label(HealthLevel::Warning), "Warning");
        assert_eq!(health_level_label(HealthLevel::Critical), "Critical");
        assert_eq!(
            health_badge_class(HealthLevel::Critical),
            "health-badge health-critical"
        );
        assert_eq!(
            GroupNameDraftError::Required.message(),
            "A group name is required."
        );
        assert_eq!(
            TagDraftError::EndpointRequired.message(),
            "Select the endpoint to tag."
        );
        Ok(())
    }
}
