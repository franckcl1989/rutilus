#![forbid(unsafe_code)]

use std::{num::NonZeroU64, path::Path, sync::Arc};

use axum::{
    Json, Router,
    body::Body,
    extract::{Path as AxumPath, State},
    http::{
        HeaderValue, StatusCode, Uri,
        header::{CACHE_CONTROL, CONTENT_TYPE, HeaderName},
    },
    response::{IntoResponse, Response},
    routing::get,
};
use rust_embed::RustEmbed;
use rutilus_api::{
    AboutResponse, CoreResourceCommonResponse, CoreResourceCountsResponse,
    CoreResourceDetailsResponse, CoreResourceResponse, CoreResourceSourceResponse,
    EndpointIdentityResponse, EndpointInventoryResponse, EndpointResourceInventoryResponse,
    EndpointResourceSnapshotResponse, EndpointSnapshotSummaryResponse, EndpointSummaryResponse,
    HealthResponse, ResourceStatusResponse, TlsTrustModeResponse,
};
use rutilus_application::{
    CoreResourceDetails, CoreResourceSummary, EndpointInventoryItem, EndpointInventoryQuery,
    EndpointInventoryQueryError, EndpointInventoryRepository, EndpointResourceInventory,
    EndpointResourceInventoryQuery, EndpointResourceInventoryQueryError, ResourceStatusSummary,
};
use rutilus_domain::{Endpoint, EndpointId, ResourceFeature, TlsTrust};
use tower_http::set_header::SetResponseHeaderLayer;

const CONTENT_SECURITY_POLICY: HeaderName = HeaderName::from_static("content-security-policy");
const CROSS_ORIGIN_OPENER_POLICY: HeaderName =
    HeaderName::from_static("cross-origin-opener-policy");
const PERMISSIONS_POLICY: HeaderName = HeaderName::from_static("permissions-policy");
const REFERRER_POLICY: HeaderName = HeaderName::from_static("referrer-policy");
const X_CONTENT_TYPE_OPTIONS: HeaderName = HeaderName::from_static("x-content-type-options");
const CSP: &str = "default-src 'self'; base-uri 'none'; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; img-src 'self' data:; object-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; form-action 'self'";

#[derive(RustEmbed)]
#[folder = "assets/"]
struct EmbeddedAssets;

/// Immutable build metadata displayed by the local management console.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WebProductInfo {
    product_version: &'static str,
    nv_redfish_baseline: &'static str,
}

impl WebProductInfo {
    #[must_use]
    pub const fn new(product_version: &'static str, nv_redfish_baseline: &'static str) -> Self {
        Self {
            product_version,
            nv_redfish_baseline,
        }
    }

    #[must_use]
    pub const fn product_version(self) -> &'static str {
        self.product_version
    }

    #[must_use]
    pub const fn nv_redfish_baseline(self) -> &'static str {
        self.nv_redfish_baseline
    }
}

struct WebState<Repository> {
    product: WebProductInfo,
    inventory: Arc<Repository>,
}

impl<Repository> Clone for WebState<Repository> {
    fn clone(&self) -> Self {
        Self {
            product: self.product,
            inventory: Arc::clone(&self.inventory),
        }
    }
}

/// Builds the local Web application without binding a socket.
///
/// Socket policy remains an app/platform responsibility, so the same Router
/// can serve Standalone loopback and a future HTTPS Site listener.
pub fn router<Repository>(product: WebProductInfo, inventory: Arc<Repository>) -> Router
where
    Repository: EndpointInventoryRepository + 'static,
{
    Router::new()
        .route("/api/v1/health", get(health))
        .route("/api/v1/about", get(about::<Repository>))
        .route("/api/v1/endpoints", get(endpoint_inventory::<Repository>))
        .route(
            "/api/v1/endpoints/{endpoint_id}/resources",
            get(endpoint_resources::<Repository>),
        )
        .fallback(static_asset)
        .with_state(WebState { product, inventory })
        .layer(SetResponseHeaderLayer::overriding(
            CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(CSP),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            CROSS_ORIGIN_OPENER_POLICY,
            HeaderValue::from_static("same-origin"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            PERMISSIONS_POLICY,
            HeaderValue::from_static("camera=(), geolocation=(), microphone=()"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            REFERRER_POLICY,
            HeaderValue::from_static("no-referrer"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse::healthy())
}

async fn about<Repository>(State(state): State<WebState<Repository>>) -> Json<AboutResponse> {
    Json(AboutResponse::new(
        "rutilus".to_owned(),
        state.product.product_version().to_owned(),
        state.product.nv_redfish_baseline().to_owned(),
    ))
}

async fn endpoint_inventory<Repository>(State(state): State<WebState<Repository>>) -> Response
where
    Repository: EndpointInventoryRepository,
{
    let Ok(items) = EndpointInventoryQuery::new(state.inventory.as_ref())
        .execute()
        .await
    else {
        return uncached_status(StatusCode::SERVICE_UNAVAILABLE);
    };
    let Ok(endpoints) = items
        .iter()
        .map(project_endpoint_summary)
        .collect::<Result<Vec<_>, _>>()
    else {
        return uncached_status(StatusCode::INTERNAL_SERVER_ERROR);
    };
    let mut response = Json(EndpointInventoryResponse::new(endpoints)).into_response();
    response.headers_mut().insert(
        CACHE_CONTROL,
        HeaderValue::from_static("no-store, must-revalidate"),
    );
    response
}

async fn endpoint_resources<Repository>(
    State(state): State<WebState<Repository>>,
    AxumPath(endpoint_id): AxumPath<String>,
) -> Response
where
    Repository: EndpointInventoryRepository,
{
    let Ok(endpoint_id) = endpoint_id.parse::<EndpointId>() else {
        return uncached_status(StatusCode::BAD_REQUEST);
    };
    let inventory = match EndpointResourceInventoryQuery::new(state.inventory.as_ref(), endpoint_id)
        .execute()
        .await
    {
        Ok(Some(inventory)) => inventory,
        Ok(None) => return uncached_status(StatusCode::NOT_FOUND),
        Err(EndpointResourceInventoryQueryError::Inventory(
            EndpointInventoryQueryError::Repository(_),
        )) => return uncached_status(StatusCode::SERVICE_UNAVAILABLE),
        Err(
            EndpointResourceInventoryQueryError::Inventory(
                EndpointInventoryQueryError::DuplicateEndpoint { .. },
            )
            | EndpointResourceInventoryQueryError::Projection { .. },
        ) => return uncached_status(StatusCode::INTERNAL_SERVER_ERROR),
    };
    let Ok(response) = project_endpoint_resources(&inventory) else {
        return uncached_status(StatusCode::INTERNAL_SERVER_ERROR);
    };
    let mut response = Json(response).into_response();
    response.headers_mut().insert(
        CACHE_CONTROL,
        HeaderValue::from_static("no-store, must-revalidate"),
    );
    response
}

fn project_endpoint_summary(
    item: &EndpointInventoryItem,
) -> Result<EndpointSummaryResponse, EndpointInventoryProjectionError> {
    let endpoint = item.endpoint();
    let identity = project_endpoint_identity(endpoint);
    let snapshot = match item.generation() {
        None => EndpointSnapshotSummaryResponse::AwaitingFirstRefresh,
        Some(generation) => EndpointSnapshotSummaryResponse::current(
            NonZeroU64::new(generation.get())
                .ok_or(EndpointInventoryProjectionError::ZeroGeneration)?,
            item.last_successful_refresh_at()
                .ok_or(EndpointInventoryProjectionError::MissingRefreshTime)?,
            CoreResourceCountsResponse::new(
                count_resources(item, ResourceFeature::Systems)?,
                count_resources(item, ResourceFeature::Chassis)?,
                count_resources(item, ResourceFeature::Managers)?,
            ),
        ),
    };
    Ok(EndpointSummaryResponse::new(identity, snapshot))
}

fn project_endpoint_resources(
    inventory: &EndpointResourceInventory,
) -> Result<EndpointResourceInventoryResponse, EndpointInventoryProjectionError> {
    let resources = inventory
        .resources()
        .iter()
        .map(project_core_resource)
        .collect::<Vec<_>>();
    let snapshot = match (inventory.generation(), inventory.observed_at()) {
        (None, None) if resources.is_empty() => {
            EndpointResourceSnapshotResponse::AwaitingFirstRefresh
        }
        (Some(generation), Some(observed_at)) if !resources.is_empty() => {
            EndpointResourceSnapshotResponse::current(
                NonZeroU64::new(generation.get())
                    .ok_or(EndpointInventoryProjectionError::ZeroGeneration)?,
                observed_at,
                resources,
            )
        }
        _ => {
            return Err(EndpointInventoryProjectionError::IncoherentResourceSnapshot);
        }
    };
    Ok(EndpointResourceInventoryResponse::new(
        project_endpoint_identity(inventory.endpoint()),
        snapshot,
    ))
}

fn project_endpoint_identity(endpoint: &Endpoint) -> EndpointIdentityResponse {
    let trust = match endpoint.trust() {
        TlsTrust::SystemCa { .. } => TlsTrustModeResponse::SystemCa,
        TlsTrust::PinnedCertificate { .. } => TlsTrustModeResponse::PinnedCertificate,
    };
    EndpointIdentityResponse::new(
        endpoint.id().into_uuid(),
        endpoint.display_name().to_string(),
        endpoint.address().to_string(),
        trust,
        endpoint.created_at(),
        endpoint.updated_at(),
    )
}

fn project_core_resource(resource: &CoreResourceSummary) -> CoreResourceResponse {
    CoreResourceResponse::new(
        CoreResourceSourceResponse::new(
            resource.resource_id().into_uuid(),
            resource.odata_id().to_string(),
            resource.odata_type().map(ToString::to_string),
            resource.etag().map(ToString::to_string),
        ),
        CoreResourceCommonResponse::new(
            resource.common().id().to_owned(),
            resource.common().name().to_owned(),
            resource.common().description().map(str::to_owned),
        ),
        project_core_resource_details(resource.details()),
    )
}

fn project_core_resource_details(details: &CoreResourceDetails) -> CoreResourceDetailsResponse {
    match details {
        CoreResourceDetails::ServiceRoot {
            vendor,
            product,
            redfish_version,
        } => CoreResourceDetailsResponse::ServiceRoot {
            vendor: vendor.clone(),
            product: product.clone(),
            redfish_version: redfish_version.clone(),
        },
        CoreResourceDetails::System {
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
        } => CoreResourceDetailsResponse::System {
            system_type: system_type.clone(),
            manufacturer: manufacturer.clone(),
            model: model.clone(),
            part_number: part_number.clone(),
            serial_number: serial_number.clone(),
            sku: sku.clone(),
            host_name: host_name.clone(),
            bios_version: bios_version.clone(),
            power_state: power_state.clone(),
            status: status.as_ref().map(project_resource_status),
        },
        CoreResourceDetails::Chassis {
            chassis_type,
            manufacturer,
            model,
            part_number,
            serial_number,
            sku,
            asset_tag,
            power_state,
            status,
        } => CoreResourceDetailsResponse::Chassis {
            chassis_type: chassis_type.clone(),
            manufacturer: manufacturer.clone(),
            model: model.clone(),
            part_number: part_number.clone(),
            serial_number: serial_number.clone(),
            sku: sku.clone(),
            asset_tag: asset_tag.clone(),
            power_state: power_state.clone(),
            status: status.as_ref().map(project_resource_status),
        },
        CoreResourceDetails::Manager {
            manager_type,
            manufacturer,
            model,
            part_number,
            serial_number,
            firmware_version,
            version,
            power_state,
            status,
        } => CoreResourceDetailsResponse::Manager {
            manager_type: manager_type.clone(),
            manufacturer: manufacturer.clone(),
            model: model.clone(),
            part_number: part_number.clone(),
            serial_number: serial_number.clone(),
            firmware_version: firmware_version.clone(),
            version: version.clone(),
            power_state: power_state.clone(),
            status: status.as_ref().map(project_resource_status),
        },
    }
}

fn project_resource_status(status: &ResourceStatusSummary) -> ResourceStatusResponse {
    ResourceStatusResponse::new(
        status.state().map(str::to_owned),
        status.health().map(str::to_owned),
        status.health_rollup().map(str::to_owned),
    )
}

fn count_resources(
    item: &EndpointInventoryItem,
    feature: ResourceFeature,
) -> Result<u64, EndpointInventoryProjectionError> {
    u64::try_from(item.resource_count(feature))
        .map_err(|_| EndpointInventoryProjectionError::ResourceCountOverflow)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EndpointInventoryProjectionError {
    ZeroGeneration,
    MissingRefreshTime,
    ResourceCountOverflow,
    IncoherentResourceSnapshot,
}

fn uncached_status(status: StatusCode) -> Response {
    let mut response = status.into_response();
    response.headers_mut().insert(
        CACHE_CONTROL,
        HeaderValue::from_static("no-store, must-revalidate"),
    );
    response
}

async fn static_asset(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    if path == "api" || path.starts_with("api/") {
        return StatusCode::NOT_FOUND.into_response();
    }
    let requested = if path.is_empty() { "index.html" } else { path };
    if let Some(asset) = EmbeddedAssets::get(requested) {
        return embedded_response(requested, asset.data.into_owned());
    }
    if !requested.contains('.')
        && let Some(index) = EmbeddedAssets::get("index.html")
    {
        return embedded_response("index.html", index.data.into_owned());
    }
    StatusCode::NOT_FOUND.into_response()
}

fn embedded_response(path: &str, content: Vec<u8>) -> Response {
    let mut response = Response::new(Body::from(content));
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static(content_type(path)));
    response.headers_mut().insert(
        CACHE_CONTROL,
        HeaderValue::from_static("no-cache, no-store, must-revalidate"),
    );
    response
}

fn content_type(path: &str) -> &'static str {
    match Path::new(path).extension().and_then(|value| value.to_str()) {
        Some(extension) if extension.eq_ignore_ascii_case("html") => "text/html; charset=utf-8",
        Some(extension) if extension.eq_ignore_ascii_case("css") => "text/css; charset=utf-8",
        Some(extension) if extension.eq_ignore_ascii_case("js") => "text/javascript; charset=utf-8",
        Some(extension) if extension.eq_ignore_ascii_case("wasm") => "application/wasm",
        Some(extension) if extension.eq_ignore_ascii_case("svg") => "image/svg+xml",
        Some(extension) if extension.eq_ignore_ascii_case("png") => "image/png",
        Some(_) | None => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use std::{error::Error, fmt};

    use axum::{body::Body, http::Request};
    use http_body_util::BodyExt as _;
    use rutilus_application::BoundaryFuture;
    use rutilus_domain::{
        CredentialId, Endpoint, EndpointAddress, EndpointDisplayName, EndpointId,
        RefreshGeneration, ResourceEtag, ResourceId, ResourceODataId, ResourceODataType,
        ResourceSnapshot, ResourceSnapshotPayload, TlsCertificate,
    };
    use serde_json::{Value, json};
    use time::{Duration, OffsetDateTime};
    use tower::ServiceExt as _;

    use super::*;

    fn test_router() -> Router {
        test_router_with(MockInventory::ok(Vec::new()))
    }

    fn test_router_with(inventory: MockInventory) -> Router {
        router(
            WebProductInfo::new("0.1.0-test", "0.13.0-test"),
            Arc::new(inventory),
        )
    }

    #[tokio::test]
    async fn exposes_health_and_build_metadata_as_same_origin_json() -> Result<(), Box<dyn Error>> {
        let health = test_router()
            .oneshot(Request::get("/api/v1/health").body(Body::empty())?)
            .await?;
        assert_eq!(health.status(), StatusCode::OK);
        assert_eq!(json_body(health).await?, json!({ "status": "ok" }));

        let about = test_router()
            .oneshot(Request::get("/api/v1/about").body(Body::empty())?)
            .await?;
        assert_eq!(about.status(), StatusCode::OK);
        assert_eq!(
            about.headers().get(CONTENT_SECURITY_POLICY),
            Some(&HeaderValue::from_static(CSP))
        );
        assert_eq!(
            about.headers().get(CROSS_ORIGIN_OPENER_POLICY),
            Some(&HeaderValue::from_static("same-origin"))
        );
        assert_eq!(
            about.headers().get(PERMISSIONS_POLICY),
            Some(&HeaderValue::from_static(
                "camera=(), geolocation=(), microphone=()"
            ))
        );
        assert_eq!(
            about.headers().get(REFERRER_POLICY),
            Some(&HeaderValue::from_static("no-referrer"))
        );
        assert_eq!(
            about.headers().get(X_CONTENT_TYPE_OPTIONS),
            Some(&HeaderValue::from_static("nosniff"))
        );
        assert_eq!(
            json_body(about).await?,
            json!({
                "product": "rutilus",
                "product_version": "0.1.0-test",
                "nv_redfish_baseline": "0.13.0-test"
            })
        );
        Ok(())
    }

    #[tokio::test]
    async fn serves_only_embedded_assets_with_spa_fallback() -> Result<(), Box<dyn Error>> {
        let index = test_router()
            .oneshot(Request::get("/").body(Body::empty())?)
            .await?;
        assert_eq!(index.status(), StatusCode::OK);
        assert_eq!(
            index.headers().get(CONTENT_TYPE),
            Some(&HeaderValue::from_static("text/html; charset=utf-8"))
        );
        assert_eq!(
            index.headers().get(CACHE_CONTROL),
            Some(&HeaderValue::from_static(
                "no-cache, no-store, must-revalidate"
            ))
        );
        assert!(text_body(index).await?.contains("id=\"app\""));

        let javascript = test_router()
            .oneshot(Request::get("/rutilus_ui.js").body(Body::empty())?)
            .await?;
        assert_eq!(javascript.status(), StatusCode::OK);
        assert_eq!(
            javascript.headers().get(CONTENT_TYPE),
            Some(&HeaderValue::from_static("text/javascript; charset=utf-8"))
        );

        let wasm = test_router()
            .oneshot(Request::get("/rutilus_ui_bg.wasm").body(Body::empty())?)
            .await?;
        assert_eq!(wasm.status(), StatusCode::OK);
        assert_eq!(
            wasm.headers().get(CONTENT_TYPE),
            Some(&HeaderValue::from_static("application/wasm"))
        );
        assert!(bytes_body(wasm).await?.starts_with(b"\0asm"));

        let spa = test_router()
            .oneshot(Request::get("/endpoints").body(Body::empty())?)
            .await?;
        assert_eq!(spa.status(), StatusCode::OK);

        let css = test_router()
            .oneshot(Request::get("/app.css").body(Body::empty())?)
            .await?;
        assert_eq!(css.status(), StatusCode::OK);
        assert_eq!(
            css.headers().get(CONTENT_TYPE),
            Some(&HeaderValue::from_static("text/css; charset=utf-8"))
        );

        let missing_asset = test_router()
            .oneshot(Request::get("/missing.js").body(Body::empty())?)
            .await?;
        assert_eq!(missing_asset.status(), StatusCode::NOT_FOUND);
        let missing_api = test_router()
            .oneshot(Request::get("/api/v1/missing").body(Body::empty())?)
            .await?;
        assert_eq!(missing_api.status(), StatusCode::NOT_FOUND);
        let api_root = test_router()
            .oneshot(Request::get("/api").body(Body::empty())?)
            .await?;
        assert_eq!(api_root.status(), StatusCode::NOT_FOUND);
        Ok(())
    }

    #[tokio::test]
    async fn exposes_secret_free_complete_endpoint_inventory() -> Result<(), Box<dyn Error>> {
        let waiting = inventory_item("Rack A BMC", "https://192.0.2.10", 10, false)?;
        let current = inventory_item("Rack B BMC", "https://192.0.2.11", 11, true)?;
        let waiting_id = waiting.endpoint().id().to_string();
        let current_id = current.endpoint().id().to_string();
        let response = test_router_with(MockInventory::ok(vec![current, waiting]))
            .oneshot(Request::get("/api/v1/endpoints").body(Body::empty())?)
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store, must-revalidate"))
        );
        assert_eq!(
            json_body(response).await?,
            json!({
                "endpoints": [
                    {
                        "identity": {
                            "endpoint_id": waiting_id,
                            "display_name": "Rack A BMC",
                            "address": "https://192.0.2.10/",
                            "tls_trust_mode": "pinned_certificate",
                            "created_at": "1970-01-01T00:00:00Z",
                            "updated_at": "1970-01-01T00:00:00Z"
                        },
                        "snapshot": { "state": "awaiting_first_refresh" }
                    },
                    {
                        "identity": {
                            "endpoint_id": current_id,
                            "display_name": "Rack B BMC",
                            "address": "https://192.0.2.11/",
                            "tls_trust_mode": "pinned_certificate",
                            "created_at": "1970-01-01T00:00:00Z",
                            "updated_at": "1970-01-01T00:00:00Z"
                        },
                        "snapshot": {
                            "state": "current",
                            "details": {
                                "generation": 1,
                                "last_successful_refresh_at": "1970-01-01T00:00:01Z",
                                "resource_counts": {
                                    "systems": 1,
                                    "chassis": 0,
                                    "managers": 0
                                }
                            }
                        }
                    }
                ]
            })
        );

        let failed = test_router_with(MockInventory::failed())
            .oneshot(Request::get("/api/v1/endpoints").body(Body::empty())?)
            .await?;
        assert_eq!(failed.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            failed.headers().get(CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store, must-revalidate"))
        );
        let wrong_method = test_router()
            .oneshot(Request::post("/api/v1/endpoints").body(Body::empty())?)
            .await?;
        assert_eq!(wrong_method.status(), StatusCode::METHOD_NOT_ALLOWED);
        Ok(())
    }

    #[tokio::test]
    async fn exposes_typed_core_resources_with_source_values() -> Result<(), Box<dyn Error>> {
        let item = core_resource_inventory_item()?;
        let endpoint_id = item.endpoint().id();
        let response = test_router_with(MockInventory::ok(vec![item]))
            .oneshot(
                Request::get(format!("/api/v1/endpoints/{endpoint_id}/resources"))
                    .body(Body::empty())?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store, must-revalidate"))
        );
        let body = json_body(response).await?;
        assert_eq!(body["endpoint"]["display_name"], "Resource detail BMC");
        assert_eq!(body["endpoint"]["tls_trust_mode"], "pinned_certificate");
        assert_eq!(body["snapshot"]["state"], "current");
        assert_eq!(body["snapshot"]["details"]["generation"], 3);
        assert_eq!(
            body["snapshot"]["details"]["observed_at"],
            "1970-01-01T00:00:01Z"
        );
        let resources = body["snapshot"]["details"]["resources"]
            .as_array()
            .ok_or("resources must be an array")?;
        assert_eq!(resources.len(), 2);
        assert_eq!(resources[0]["resource"]["resource_type"], "service_root");
        assert_eq!(resources[0]["common"]["name"], "Root Service");
        assert_eq!(
            resources[0]["resource"]["details"]["redfish_version"],
            "1.20.0"
        );
        assert_eq!(resources[1]["resource"]["resource_type"], "system");
        assert_eq!(resources[1]["source"]["odata_id"], "/redfish/v1/Systems/1");
        assert_eq!(
            resources[1]["source"]["odata_type"],
            "#ComputerSystem.v1_20_0.ComputerSystem"
        );
        assert_eq!(resources[1]["source"]["etag"], "W/\"system-1\"");
        assert_eq!(
            resources[1]["resource"]["details"]["manufacturer"],
            "Vendor A"
        );
        assert_eq!(
            resources[1]["resource"]["details"]["status"]["health"],
            "OK"
        );
        let encoded = serde_json::to_string(&body)?;
        assert!(!encoded.contains("credential"));
        assert!(!encoded.contains("\"certificate\":"));
        Ok(())
    }

    #[tokio::test]
    async fn distinguishes_core_resource_route_states() -> Result<(), Box<dyn Error>> {
        let waiting = inventory_item("Waiting BMC", "https://192.0.2.20", 20, false)?;
        let endpoint_id = waiting.endpoint().id();
        let waiting_router = test_router_with(MockInventory::ok(vec![waiting]));

        let bad_id = waiting_router
            .clone()
            .oneshot(Request::get("/api/v1/endpoints/not-a-uuid/resources").body(Body::empty())?)
            .await?;
        assert_eq!(bad_id.status(), StatusCode::BAD_REQUEST);
        let missing = waiting_router
            .clone()
            .oneshot(
                Request::get(format!(
                    "/api/v1/endpoints/{}/resources",
                    EndpointId::generate()
                ))
                .body(Body::empty())?,
            )
            .await?;
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
        let waiting = waiting_router
            .clone()
            .oneshot(
                Request::get(format!("/api/v1/endpoints/{endpoint_id}/resources"))
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(waiting.status(), StatusCode::OK);
        assert_eq!(
            json_body(waiting).await?["snapshot"],
            json!({ "state": "awaiting_first_refresh" })
        );
        let wrong_method = waiting_router
            .oneshot(
                Request::post(format!("/api/v1/endpoints/{endpoint_id}/resources"))
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(wrong_method.status(), StatusCode::METHOD_NOT_ALLOWED);

        let unavailable = test_router_with(MockInventory::failed())
            .oneshot(
                Request::get(format!("/api/v1/endpoints/{endpoint_id}/resources"))
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(unavailable.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            unavailable.headers().get(CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store, must-revalidate"))
        );

        let corrupt = inventory_item("Corrupt BMC", "https://192.0.2.21", 21, true)?;
        let corrupt_id = corrupt.endpoint().id();
        let corrupt = test_router_with(MockInventory::ok(vec![corrupt]))
            .oneshot(
                Request::get(format!("/api/v1/endpoints/{corrupt_id}/resources"))
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(corrupt.status(), StatusCode::INTERNAL_SERVER_ERROR);
        Ok(())
    }

    async fn json_body(response: Response) -> Result<Value, Box<dyn Error>> {
        let bytes = response.into_body().collect().await?.to_bytes();
        Ok(serde_json::from_slice(&bytes)?)
    }

    async fn text_body(response: Response) -> Result<String, Box<dyn Error>> {
        let bytes = bytes_body(response).await?;
        Ok(String::from_utf8(bytes.to_vec())?)
    }

    async fn bytes_body(response: Response) -> Result<axum::body::Bytes, Box<dyn Error>> {
        Ok(response.into_body().collect().await?.to_bytes())
    }

    #[test]
    fn exposes_stable_content_types_and_product_metadata() {
        let product = WebProductInfo::new("1.2.3", "4.5.6");
        assert_eq!(product.product_version(), "1.2.3");
        assert_eq!(product.nv_redfish_baseline(), "4.5.6");
        assert_eq!(content_type("app.wasm"), "application/wasm");
        assert_eq!(content_type("icon.svg"), "image/svg+xml");
        assert_eq!(content_type("icon.png"), "image/png");
        assert_eq!(content_type("unknown.bin"), "application/octet-stream");
    }

    fn inventory_item(
        display_name: &str,
        address: &str,
        certificate_byte: u8,
        refreshed: bool,
    ) -> Result<EndpointInventoryItem, Box<dyn Error>> {
        let created_at = OffsetDateTime::UNIX_EPOCH;
        let endpoint = Endpoint::try_new(
            EndpointId::generate(),
            EndpointDisplayName::parse(display_name)?,
            EndpointAddress::parse(address)?,
            TlsTrust::PinnedCertificate {
                certificate: TlsCertificate::from_der(vec![certificate_byte])?,
                trusted_at: created_at,
            },
            CredentialId::generate(),
            created_at,
            created_at,
        )?;
        let resources = if refreshed {
            let observed_at = created_at + Duration::SECOND;
            let generation = RefreshGeneration::new(1)?;
            vec![
                resource_snapshot(
                    endpoint.id(),
                    ResourceFeature::ServiceRoot,
                    "/redfish/v1",
                    observed_at,
                    generation,
                )?,
                resource_snapshot(
                    endpoint.id(),
                    ResourceFeature::Systems,
                    "/redfish/v1/Systems/1",
                    observed_at,
                    generation,
                )?,
            ]
        } else {
            Vec::new()
        };
        Ok(EndpointInventoryItem::try_new(endpoint, resources)?)
    }

    fn core_resource_inventory_item() -> Result<EndpointInventoryItem, Box<dyn Error>> {
        let created_at = OffsetDateTime::UNIX_EPOCH;
        let observed_at = created_at + Duration::SECOND;
        let endpoint = Endpoint::try_new(
            EndpointId::generate(),
            EndpointDisplayName::parse("Resource detail BMC")?,
            EndpointAddress::parse("https://192.0.2.30")?,
            TlsTrust::PinnedCertificate {
                certificate: TlsCertificate::from_der(vec![30])?,
                trusted_at: created_at,
            },
            CredentialId::generate(),
            created_at,
            created_at,
        )?;
        let generation = RefreshGeneration::new(3)?;
        let root = resource_snapshot_with_payload(
            endpoint.id(),
            ResourceFeature::ServiceRoot,
            "/redfish/v1",
            r#"{"Id":"RootService","Name":"Root Service","Vendor":"Vendor A","Product":"BMC","RedfishVersion":"1.20.0"}"#,
            observed_at,
            generation,
        )?;
        let system = resource_snapshot_with_payload(
            endpoint.id(),
            ResourceFeature::Systems,
            "/redfish/v1/Systems/1",
            r#"{"Id":"1","Name":"System One","Description":"Compute","SystemType":"Physical","Manufacturer":"Vendor A","Model":"Model S","PartNumber":"P1","SerialNumber":"S1","SKU":"SKU1","HostName":"compute-1","BiosVersion":"2.3.4","PowerState":"On","Status":{"State":"Enabled","Health":"OK","HealthRollup":"Warning"}}"#,
            observed_at,
            generation,
        )?
        .with_odata_type(ResourceODataType::parse(
            "#ComputerSystem.v1_20_0.ComputerSystem",
        )?)
        .with_etag(ResourceEtag::parse("W/\"system-1\"")?);
        Ok(EndpointInventoryItem::try_new(
            endpoint,
            vec![system, root],
        )?)
    }

    fn resource_snapshot(
        endpoint_id: EndpointId,
        feature: ResourceFeature,
        odata_id: &str,
        observed_at: OffsetDateTime,
        generation: RefreshGeneration,
    ) -> Result<ResourceSnapshot, Box<dyn Error>> {
        resource_snapshot_with_payload(
            endpoint_id,
            feature,
            odata_id,
            r#"{"Name":"Web test"}"#,
            observed_at,
            generation,
        )
    }

    fn resource_snapshot_with_payload(
        endpoint_id: EndpointId,
        feature: ResourceFeature,
        odata_id: &str,
        payload: &str,
        observed_at: OffsetDateTime,
        generation: RefreshGeneration,
    ) -> Result<ResourceSnapshot, Box<dyn Error>> {
        Ok(ResourceSnapshot::new(
            ResourceId::generate(),
            endpoint_id,
            feature,
            ResourceODataId::parse(odata_id)?,
            ResourceSnapshotPayload::parse(payload)?,
            observed_at,
            generation,
        ))
    }

    #[derive(Clone, Copy, Debug)]
    struct MockInventoryError;

    impl fmt::Display for MockInventoryError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("mock inventory unavailable")
        }
    }

    impl Error for MockInventoryError {}

    struct MockInventory {
        result: Result<Vec<EndpointInventoryItem>, MockInventoryError>,
    }

    impl MockInventory {
        fn ok(items: Vec<EndpointInventoryItem>) -> Self {
            Self { result: Ok(items) }
        }

        fn failed() -> Self {
            Self {
                result: Err(MockInventoryError),
            }
        }
    }

    impl EndpointInventoryRepository for MockInventory {
        type Error = MockInventoryError;

        fn list_endpoint_inventory(
            &self,
        ) -> BoundaryFuture<'_, Result<Vec<EndpointInventoryItem>, Self::Error>> {
            Box::pin(async { self.result.clone() })
        }
    }
}
