use rutilus_application::{
    BoundaryFuture, EndpointDiscovery, RedfishDiscovery, SystemCaEvaluation,
    TlsIdentityObservation, TlsIdentityProbe,
};
use rutilus_domain::{CredentialUsername, EndpointAddress, TlsTrust};
use secrecy::SecretString;

use crate::{RedfishGateway, RedfishServiceRootError, SystemCaStatus, TlsProbeError};

impl TlsIdentityProbe for RedfishGateway {
    type Error = TlsProbeError;

    fn observe<'a>(
        &'a self,
        address: &'a EndpointAddress,
    ) -> BoundaryFuture<'a, Result<TlsIdentityObservation, Self::Error>> {
        Box::pin(async move {
            let observation = RedfishGateway::observe_tls(self, address).await?;
            let (certificate, system_ca_status) = observation.into_parts();
            let system_ca = match system_ca_status {
                SystemCaStatus::Verified => SystemCaEvaluation::Verified,
                SystemCaStatus::Rejected => SystemCaEvaluation::Rejected,
            };
            Ok(TlsIdentityObservation::new(certificate, system_ca))
        })
    }
}

impl RedfishDiscovery for RedfishGateway {
    type Error = RedfishServiceRootError;

    fn probe_core_capabilities<'a>(
        &'a self,
        address: &'a EndpointAddress,
        trust: &'a TlsTrust,
        username: &'a CredentialUsername,
        password: &'a SecretString,
    ) -> BoundaryFuture<'a, Result<EndpointDiscovery, Self::Error>> {
        Box::pin(async move {
            let discovery =
                RedfishGateway::probe_core_capabilities(self, address, trust, username, password)
                    .await?;
            Ok(EndpointDiscovery::new(discovery.capabilities().to_vec()))
        })
    }
}

#[cfg(test)]
mod tests {
    use rutilus_application::{RedfishDiscovery, TlsIdentityProbe};

    use crate::RedfishGateway;

    #[test]
    fn gateway_implements_the_application_discovery_boundary() {
        fn assert_discovery<Gateway: RedfishDiscovery>() {}

        assert_discovery::<RedfishGateway>();
    }

    #[test]
    fn gateway_implements_the_application_tls_identity_boundary() {
        fn assert_tls_identity_probe<Gateway: TlsIdentityProbe>() {}

        assert_tls_identity_probe::<RedfishGateway>();
    }
}
