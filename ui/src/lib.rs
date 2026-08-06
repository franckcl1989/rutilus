#![forbid(unsafe_code)]
#![cfg_attr(
    all(not(target_arch = "wasm32"), target_env = "msvc"),
    allow(linker_messages)
)]

#[cfg(any(target_arch = "wasm32", test))]
use std::{collections::BTreeSet, fmt};

#[cfg(any(target_arch = "wasm32", test))]
use rutilus_api::{
    AboutResponse, AuditEventResponse, AuditQueryResponse, CapabilityEntryResponse,
    CapabilityStateResponse, CoreResourceDetailsResponse, CoreResourceResponse,
    CredentialInventoryResponse, CredentialSummaryResponse, EndpointCapabilityInventoryResponse,
    EndpointCsvImportResponse, EndpointCsvImportRowResponse, EndpointCsvImportRowStatusResponse,
    EndpointEnrollmentResponse, EndpointInventoryResponse, EndpointResourceInventoryResponse,
    EndpointResourceSnapshotResponse, EndpointTrustChallengeResponse,
    EndpointTrustChallengeStateResponse, EndpointTrustExpectationRequest, ResourceStatusResponse,
    TlsTrustModeResponse, UiLocationResponse,
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
            endpoint_id: identity.endpoint_id().to_string(),
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
            // The 0.2 resource families mirror the server-side counts
            // contract: they render as cards in the resource list, while the
            // three-line counts summary keeps its 0.1 wire shape. The
            // Power/Thermal/Sensors/Controls telemetry families, the
            // LogServices/ManagerNetworkProtocol/HostInterfaces manager
            // surface, the PcieDevice/Assembly/SoftwareInventory read
            // families, and the EventService/EventSubscription/
            // TelemetryService/MetricDefinition/MetricReport/TaskService/Task
            // service families follow the same rule.
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
}

#[cfg(any(target_arch = "wasm32", test))]
impl From<&CoreResourceResponse> for CoreResourceCardProjection {
    fn from(resource: &CoreResourceResponse) -> Self {
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
        }
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
/// derived metric-values count stays numeric as published so the card renders
/// the sample size without re-parsing text.
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
    } = resource
    else {
        return ("Metric report", Vec::new());
    };
    let mut facts = Vec::new();
    push_u64_fact(&mut facts, "Metric values", *metric_values_count);
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
/// One of the top-level console sections reachable from the navigation bar.
///
/// `Capabilities` is a per-endpoint drill-down: the navigation entry only
/// appears while a capability target is selected, and entering it from an
/// endpoint card always carries that endpoint's identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConsoleView {
    Overview,
    Credentials,
    AddEndpoint,
    Import,
    Audit,
    Capabilities,
}

#[cfg(any(target_arch = "wasm32", test))]
impl ConsoleView {
    const ALL: [ConsoleView; 6] = [
        Self::Overview,
        Self::Credentials,
        Self::AddEndpoint,
        Self::Import,
        Self::Audit,
        Self::Capabilities,
    ];

    const fn label(self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Credentials => "Credentials",
            Self::AddEndpoint => "Add endpoint",
            Self::Import => "Import",
            Self::Audit => "Audit",
            Self::Capabilities => "Capabilities",
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
        EndpointCapabilityInventoryResponse, EndpointCsvImportRequest, EndpointCsvImportResponse,
        EndpointEnrollmentResponse, EndpointInventoryResponse, EndpointResourceInventoryResponse,
        EndpointTrustChallengeResponse, EndpointTrustExpectationRequest, EnrollEndpointRequest,
        TrustedEndpointResponse,
    };
    use wasm_bindgen::prelude::wasm_bindgen;
    use wasm_bindgen_futures::{JsFuture, spawn_local};

    use super::{
        AuditEventCardProjection, AuditListState, CapabilityEntryProjection,
        CapabilityGroupProjection, CapabilityLoadFailure, CapabilityMatrixProjection,
        CapabilityMatrixState, CapabilityTargetProjection, ConsoleLoadFailure, ConsoleLoadState,
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

        // The capability drill-down keeps its target and matrix state at the
        // shell level so the endpoint-card entry can reset them; the view
        // itself only reads and refreshes them.
        let (capability_target, set_capability_target) = signal(None::<CapabilityTargetProjection>);
        let (capability_state, set_capability_state) = signal(CapabilityMatrixState::Idle);
        let (capability_triggered, set_capability_triggered) = signal(false);

        let on_view_capabilities = Callback::new(move |target: CapabilityTargetProjection| {
            set_capability_target.set(Some(target));
            set_capability_state.set(CapabilityMatrixState::Idle);
            set_capability_triggered.set(false);
            set_view.set(ConsoleView::Capabilities);
        });

        let on_back_to_overview = Callback::new(move |()| {
            set_capability_target.set(None);
            set_capability_state.set(CapabilityMatrixState::Idle);
            set_capability_triggered.set(false);
            set_view.set(ConsoleView::Overview);
        });

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
                            // The capability drill-down needs an endpoint
                            // chosen from a card first, so its navigation
                            // entry stays hidden until a target is selected.
                            let hidden = move || {
                                candidate == ConsoleView::Capabilities
                                    && capability_target.get().is_none()
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
                                .map(|card| {
                                    view! {
                                        <EndpointCard
                                            card=card
                                            on_view_capabilities=on_view_capabilities
                                        />
                                    }
                                })
                                .collect_view()
                        }}
                    </div>
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
            </main>
        }
    }

    #[component]
    fn EndpointCard(
        card: EndpointCardProjection,
        on_view_capabilities: Callback<CapabilityTargetProjection>,
    ) -> impl IntoView {
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
                    <span class="trust-badge">{card.trust_label}</span>
                </div>
                <div class="snapshot-heading">
                    <span class=status_dot_class aria-hidden="true"></span>
                    <span>{card.snapshot_label}</span>
                </div>
                <div class="endpoint-card-actions">
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
        if !response.ok() {
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
                    "metric_values_count": 12
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
            value: "12".to_owned(),
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
    fn console_views_and_loading_state_expose_static_labels() {
        assert_eq!(
            ConsoleView::ALL,
            [
                ConsoleView::Overview,
                ConsoleView::Credentials,
                ConsoleView::AddEndpoint,
                ConsoleView::Import,
                ConsoleView::Audit,
                ConsoleView::Capabilities,
            ]
        );
        assert_eq!(ConsoleView::Overview.label(), "Overview");
        assert_eq!(ConsoleView::Credentials.label(), "Credentials");
        assert_eq!(ConsoleView::AddEndpoint.label(), "Add endpoint");
        assert_eq!(ConsoleView::Import.label(), "Import");
        assert_eq!(ConsoleView::Audit.label(), "Audit");
        assert_eq!(ConsoleView::Capabilities.label(), "Capabilities");

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
}
