#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

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

#[cfg(test)]
mod tests {
    use std::error::Error;

    use serde_json::json;

    use super::*;

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
}
