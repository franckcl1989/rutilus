#![forbid(unsafe_code)]

use std::marker::PhantomData;

mod application_adapter;
mod redfish_gateway;
mod tls_probe;

pub use redfish_gateway::{
    CoreEndpointDiscovery, RedfishGateway, RedfishServiceRootError, ServiceRootSummary,
    TlsIdentityStateError,
};
pub use tls_probe::{
    SystemCaStatus, TlsCertificateObservation, TlsProbe, TlsProbeError, TlsProbeInitError,
};

/// The exact upstream version currently evaluated during product development.
///
/// This remains movable until the 0.8.0 capability freeze.
pub const NV_REDFISH_DEVELOPMENT_BASELINE: &str = "0.13.0";

const COMPILED_OEM_FEATURES: &[&str] = &[
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
];

/// Auditable metadata for the upstream capability surface compiled into Rutilus.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NvRedfishBaseline {
    version: &'static str,
    standard_redfish: bool,
    oem_features: &'static [&'static str],
}

impl NvRedfishBaseline {
    /// Returns the exact upstream crate version selected for development.
    #[must_use]
    pub const fn version(self) -> &'static str {
        self.version
    }

    /// Reports whether the upstream `std-redfish` capability group is compiled.
    #[must_use]
    pub const fn includes_standard_redfish(self) -> bool {
        self.standard_redfish
    }

    /// Returns every explicitly compiled upstream OEM capability feature.
    #[must_use]
    pub const fn oem_features(self) -> &'static [&'static str] {
        self.oem_features
    }
}

/// The development capability surface linked into the single Rutilus binary.
pub const COMPILED_NV_REDFISH_BASELINE: NvRedfishBaseline = NvRedfishBaseline {
    version: NV_REDFISH_DEVELOPMENT_BASELINE,
    standard_redfish: true,
    oem_features: COMPILED_OEM_FEATURES,
};

/// Compile-time proof that all BMC schema types enter through this crate.
///
/// Networking and credentials will be attached to the concrete gateway rather
/// than exposed through this boundary marker.
#[derive(Clone, Copy, Debug, Default)]
pub struct CompiledCapabilityBoundary {
    upstream_service_root: PhantomData<fn() -> nv_redfish::schema::service_root::ServiceRoot>,
}

impl CompiledCapabilityBoundary {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            upstream_service_root: PhantomData,
        }
    }

    /// Returns the capability ledger for the linked upstream schema surface.
    #[must_use]
    pub const fn baseline(self) -> NvRedfishBaseline {
        COMPILED_NV_REDFISH_BASELINE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn links_the_complete_development_capability_surface() {
        let baseline = CompiledCapabilityBoundary::new().baseline();

        assert_eq!(baseline.version(), NV_REDFISH_DEVELOPMENT_BASELINE);
        assert!(baseline.includes_standard_redfish());
        assert_eq!(baseline.oem_features(), COMPILED_OEM_FEATURES);
        assert_eq!(baseline.oem_features().len(), 14);
    }
}
