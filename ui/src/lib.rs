#![forbid(unsafe_code)]
#![cfg_attr(
    all(not(target_arch = "wasm32"), target_env = "msvc"),
    allow(linker_messages)
)]

#[cfg(any(target_arch = "wasm32", test))]
use rutilus_api::AboutResponse;

#[cfg(any(target_arch = "wasm32", test))]
const PRODUCT_ID: &str = "rutilus";

#[cfg(any(target_arch = "wasm32", test))]
#[derive(Clone, Debug, Eq, PartialEq)]
enum AboutLoadState {
    Loading,
    Ready(AboutResponse),
    Failed,
}

#[cfg(any(target_arch = "wasm32", test))]
impl AboutLoadState {
    fn accepted(response: AboutResponse) -> Self {
        if response.product() == PRODUCT_ID {
            Self::Ready(response)
        } else {
            Self::Failed
        }
    }

    const fn status_message(&self) -> &'static str {
        match self {
            Self::Loading => "Starting the local management console…",
            Self::Ready(_) => "The embedded console is ready.",
            Self::Failed => "The local console could not load product metadata.",
        }
    }

    const fn is_ready(&self) -> bool {
        matches!(self, Self::Ready(_))
    }

    fn product_version_text(&self) -> String {
        match self {
            Self::Ready(response) => response.product_version().to_owned(),
            Self::Loading | Self::Failed => String::new(),
        }
    }

    fn nv_redfish_baseline_text(&self) -> String {
        match self {
            Self::Ready(response) => response.nv_redfish_baseline().to_owned(),
            Self::Loading | Self::Failed => String::new(),
        }
    }
}

#[cfg(target_arch = "wasm32")]
mod browser {
    use gloo_net::http::Request;
    use leptos::{mount::mount_to_body, prelude::*};
    use rutilus_api::AboutResponse;
    use wasm_bindgen::prelude::wasm_bindgen;
    use wasm_bindgen_futures::spawn_local;

    use super::AboutLoadState;

    #[wasm_bindgen(start)]
    pub fn start() {
        mount_to_body(|| view! { <ProductShell /> });
    }

    #[component]
    fn ProductShell() -> impl IntoView {
        let (state, set_state) = signal(AboutLoadState::Loading);
        spawn_local(async move {
            set_state.set(fetch_about().await);
        });

        view! {
            <main id="app" aria-live="polite">
                <section class="shell">
                    <p class="eyebrow">"Local Redfish management"</p>
                    <h1>"Rutilus"</h1>
                    <p id="status">{move || state.with(AboutLoadState::status_message)}</p>
                    <dl id="build" hidden=move || !state.with(AboutLoadState::is_ready)>
                        <div>
                            <dt>"Product"</dt>
                            <dd id="product-version">
                                {move || state.with(AboutLoadState::product_version_text)}
                            </dd>
                        </div>
                        <div>
                            <dt>"nv-redfish"</dt>
                            <dd id="redfish-version">
                                {move || state.with(AboutLoadState::nv_redfish_baseline_text)}
                            </dd>
                        </div>
                    </dl>
                </section>
            </main>
        }
    }

    async fn fetch_about() -> AboutLoadState {
        let Ok(response) = Request::get("/api/v1/about")
            .header("Accept", "application/json")
            .send()
            .await
        else {
            return AboutLoadState::Failed;
        };
        if !response.ok() {
            return AboutLoadState::Failed;
        }
        match response.json::<AboutResponse>().await {
            Ok(about) => AboutLoadState::accepted(about),
            Err(_) => AboutLoadState::Failed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn about(product: &str) -> AboutResponse {
        AboutResponse::new(
            product.to_owned(),
            "0.1.0-test".to_owned(),
            "0.13.0-test".to_owned(),
        )
    }

    #[test]
    fn projects_loading_ready_and_failure_without_dynamic_error_text() {
        let loading = AboutLoadState::Loading;
        let ready = AboutLoadState::accepted(about(PRODUCT_ID));
        let failed = AboutLoadState::Failed;

        assert_eq!(
            loading.status_message(),
            "Starting the local management console…"
        );
        assert!(!loading.is_ready());
        assert!(ready.is_ready());
        assert_eq!(ready.status_message(), "The embedded console is ready.");
        assert_eq!(ready.product_version_text(), "0.1.0-test");
        assert_eq!(ready.nv_redfish_baseline_text(), "0.13.0-test");
        assert!(!failed.is_ready());
        assert_eq!(
            failed.status_message(),
            "The local console could not load product metadata."
        );
        assert!(failed.product_version_text().is_empty());
        assert!(failed.nv_redfish_baseline_text().is_empty());
    }

    #[test]
    fn rejects_metadata_from_a_different_product_identity() {
        assert_eq!(
            AboutLoadState::accepted(about("different-product")),
            AboutLoadState::Failed
        );
    }
}
