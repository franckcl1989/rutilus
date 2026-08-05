use rutilus_application::{BoundaryFuture, EndpointDiscovery, RedfishDiscovery};
use rutilus_domain::{CredentialUsername, EndpointAddress, TlsTrust};
use secrecy::SecretString;

use crate::{RedfishGateway, RedfishServiceRootError};

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
    use rutilus_application::RedfishDiscovery;

    use crate::RedfishGateway;

    #[test]
    fn gateway_implements_the_application_discovery_boundary() {
        fn assert_discovery<Gateway: RedfishDiscovery>() {}

        assert_discovery::<RedfishGateway>();
    }
}
