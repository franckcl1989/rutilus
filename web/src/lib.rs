#![forbid(unsafe_code)]

use std::path::Path;

use axum::{
    Json, Router,
    body::Body,
    extract::State,
    http::{
        HeaderValue, StatusCode, Uri,
        header::{CACHE_CONTROL, CONTENT_TYPE, HeaderName},
    },
    response::{IntoResponse, Response},
    routing::get,
};
use rust_embed::RustEmbed;
use serde::Serialize;
use tower_http::set_header::SetResponseHeaderLayer;

const CONTENT_SECURITY_POLICY: HeaderName = HeaderName::from_static("content-security-policy");
const CROSS_ORIGIN_OPENER_POLICY: HeaderName =
    HeaderName::from_static("cross-origin-opener-policy");
const PERMISSIONS_POLICY: HeaderName = HeaderName::from_static("permissions-policy");
const REFERRER_POLICY: HeaderName = HeaderName::from_static("referrer-policy");
const X_CONTENT_TYPE_OPTIONS: HeaderName = HeaderName::from_static("x-content-type-options");
const CSP: &str = "default-src 'self'; base-uri 'none'; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; img-src 'self' data:; object-src 'none'; script-src 'self'; style-src 'self'; form-action 'self'";

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

/// Builds the local Web application without binding a socket.
///
/// Socket policy remains an app/platform responsibility, so the same Router
/// can serve Standalone loopback and a future HTTPS Site listener.
pub fn router(product: WebProductInfo) -> Router {
    Router::new()
        .route("/api/v1/health", get(health))
        .route("/api/v1/about", get(about))
        .fallback(static_asset)
        .with_state(product)
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

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

#[derive(Serialize)]
struct AboutResponse {
    product: &'static str,
    product_version: &'static str,
    nv_redfish_baseline: &'static str,
}

async fn about(State(product): State<WebProductInfo>) -> Json<AboutResponse> {
    Json(AboutResponse {
        product: "rutilus",
        product_version: product.product_version(),
        nv_redfish_baseline: product.nv_redfish_baseline(),
    })
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
    use std::error::Error;

    use axum::{body::Body, http::Request};
    use http_body_util::BodyExt as _;
    use serde_json::{Value, json};
    use tower::ServiceExt as _;

    use super::*;

    fn test_router() -> Router {
        router(WebProductInfo::new("0.1.0-test", "0.13.0-test"))
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

    async fn json_body(response: Response) -> Result<Value, Box<dyn Error>> {
        let bytes = response.into_body().collect().await?.to_bytes();
        Ok(serde_json::from_slice(&bytes)?)
    }

    async fn text_body(response: Response) -> Result<String, Box<dyn Error>> {
        let bytes = response.into_body().collect().await?.to_bytes();
        Ok(String::from_utf8(bytes.to_vec())?)
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
}
