use rutilus_application::{BoundaryFuture, DiscoveredEndpointRepository};
use rutilus_domain::{Endpoint, EndpointCapabilityObservation};

use crate::{EndpointRepositoryError, SqliteStore};

impl DiscoveredEndpointRepository for SqliteStore {
    type Error = EndpointRepositoryError;

    fn create_discovered_endpoint<'a>(
        &'a self,
        endpoint: Endpoint,
        observations: &'a [EndpointCapabilityObservation],
    ) -> BoundaryFuture<'a, Result<Endpoint, Self::Error>> {
        Box::pin(async move {
            SqliteStore::create_discovered_endpoint(self, endpoint, observations).await
        })
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use rutilus_application::DiscoveredEndpointRepository;
    use rutilus_domain::{
        CredentialId, Endpoint, EndpointAddress, EndpointDisplayName, EndpointId, TlsCertificate,
        TlsTrust,
    };
    use time::OffsetDateTime;

    use crate::{EndpointRepositoryError, SqliteStore};

    #[tokio::test]
    async fn sqlite_store_implements_and_forwards_the_application_repository_boundary()
    -> Result<(), Box<dyn Error>> {
        fn assert_repository<Repository: DiscoveredEndpointRepository>() {}
        assert_repository::<SqliteStore>();

        let directory = tempfile::tempdir()?;
        let store = SqliteStore::open(directory.path().join("rutilus.db")).await?;
        let now = OffsetDateTime::now_utc();
        let endpoint = Endpoint::try_new(
            EndpointId::generate(),
            EndpointDisplayName::parse("Adapter test BMC")?,
            EndpointAddress::parse("https://192.0.2.80")?,
            TlsTrust::PinnedCertificate {
                certificate: TlsCertificate::from_der(b"adapter certificate".to_vec())?,
                trusted_at: now,
            },
            CredentialId::generate(),
            now,
            now,
        )?;

        assert!(matches!(
            DiscoveredEndpointRepository::create_discovered_endpoint(&store, endpoint, &[]).await,
            Err(EndpointRepositoryError::EmptyCapabilitySnapshot)
        ));
        store.close().await?;
        drop(directory);
        Ok(())
    }
}
