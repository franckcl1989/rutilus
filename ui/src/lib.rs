#![forbid(unsafe_code)]
#![cfg_attr(
    all(not(target_arch = "wasm32"), target_env = "msvc"),
    allow(linker_messages)
)]

#[cfg(any(target_arch = "wasm32", test))]
use std::collections::BTreeSet;

#[cfg(any(target_arch = "wasm32", test))]
use rutilus_api::{
    AboutResponse, CoreResourceDetailsResponse, CoreResourceResponse, EndpointInventoryResponse,
    EndpointResourceInventoryResponse, EndpointResourceSnapshotResponse, ResourceStatusResponse,
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

#[cfg(target_arch = "wasm32")]
mod browser {
    use gloo_net::http::Request;
    use leptos::{mount::mount_to_body, prelude::*};
    use rutilus_api::{
        AboutResponse, EndpointInventoryResponse, EndpointResourceInventoryResponse,
    };
    use wasm_bindgen::prelude::wasm_bindgen;
    use wasm_bindgen_futures::spawn_local;

    use super::{
        ConsoleLoadFailure, ConsoleLoadState, CoreResourceCardProjection, EndpointCardProjection,
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

                <section class="inventory" hidden=move || !state.with(ConsoleLoadState::is_ready)>
                    <div class="inventory-heading">
                        <div>
                            <p class="section-label">"Inventory"</p>
                            <h2>{move || state.with(ConsoleLoadState::endpoint_count_text)}</h2>
                        </div>
                        <p>"Latest complete Redfish resource generations"</p>
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
}
