use rutilus_application::{
    AuditEventWriter, BoundaryFuture, DiscoveredEndpointRepository, EndpointRefreshRepository,
    ResourceObservation,
};
use rutilus_domain::{
    AuditEvent, Endpoint, EndpointCapabilityObservation, EndpointId, ResourceSnapshot,
};
use thiserror::Error;
use time::OffsetDateTime;

use crate::{
    AuditRepositoryError, EndpointRepositoryError, NewResourceSnapshot,
    ResourceSnapshotRepositoryError, SqliteStore,
};

impl AuditEventWriter for SqliteStore {
    type Error = AuditRepositoryError;

    fn append_audit_event<'a>(
        &'a self,
        event: &'a AuditEvent,
    ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
        Box::pin(async move { SqliteStore::append_audit_event(self, event).await })
    }
}

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

impl EndpointRefreshRepository for SqliteStore {
    type Error = EndpointRefreshPersistenceError;

    fn find_endpoint(
        &self,
        endpoint_id: EndpointId,
    ) -> BoundaryFuture<'_, Result<Option<Endpoint>, Self::Error>> {
        Box::pin(async move {
            SqliteStore::find_endpoint(self, endpoint_id)
                .await
                .map_err(EndpointRefreshPersistenceError::Endpoint)
        })
    }

    fn commit_resource_generation<'a>(
        &'a self,
        endpoint_id: EndpointId,
        observations: &'a [ResourceObservation],
        observed_at: OffsetDateTime,
    ) -> BoundaryFuture<'a, Result<Vec<ResourceSnapshot>, Self::Error>> {
        Box::pin(async move {
            let snapshots = observations
                .iter()
                .map(project_observation)
                .collect::<Vec<_>>();
            SqliteStore::commit_resource_generation(self, endpoint_id, &snapshots, observed_at)
                .await
                .map_err(EndpointRefreshPersistenceError::Snapshot)
        })
    }
}

fn project_observation(observation: &ResourceObservation) -> NewResourceSnapshot {
    let mut snapshot = NewResourceSnapshot::new(
        observation.feature(),
        observation.odata_id().clone(),
        observation.payload().clone(),
    );
    if let Some(odata_type) = observation.odata_type() {
        snapshot = snapshot.with_odata_type(odata_type.clone());
    }
    if let Some(etag) = observation.etag() {
        snapshot = snapshot.with_etag(etag.clone());
    }
    snapshot
}

/// A persistence failure at one of the endpoint refresh repository operations.
#[derive(Debug, Error)]
pub enum EndpointRefreshPersistenceError {
    #[error("failed to load the endpoint aggregate: {0}")]
    Endpoint(#[source] EndpointRepositoryError),
    #[error("failed to commit the resource Generation: {0}")]
    Snapshot(#[source] ResourceSnapshotRepositoryError),
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use rutilus_application::{
        AuditEventWriter, DiscoveredEndpointRepository, EndpointRefreshRepository,
        ResourceObservation,
    };
    use rutilus_domain::{
        AuditAction, AuditActor, AuditEvent, AuditOperationContext, AuditOperationId,
        AuditParameterSummary, AuditRedfishOperation, AuditTarget, CredentialId, DeploymentPosture,
        Endpoint, EndpointAddress, EndpointDisplayName, EndpointId, ProductPermission,
        ResourceFeature, ResourceODataId, ResourceSnapshotPayload, TlsCertificate, TlsTrust,
    };
    use time::OffsetDateTime;

    use crate::{
        EndpointRefreshPersistenceError, EndpointRepositoryError, ResourceSnapshotRepositoryError,
        SqliteStore,
    };

    #[tokio::test]
    async fn sqlite_store_forwards_the_append_only_audit_boundary() -> Result<(), Box<dyn Error>> {
        fn assert_writer<Writer: AuditEventWriter>() {}
        assert_writer::<SqliteStore>();

        let directory = tempfile::tempdir()?;
        let store = SqliteStore::open(directory.path().join("rutilus.db")).await?;
        let operation_id = AuditOperationId::generate();
        let context = AuditOperationContext::try_new(
            operation_id,
            AuditActor::LocalOperator,
            DeploymentPosture::Standalone,
            AuditTarget::Product,
            AuditParameterSummary::csv_endpoint_import(1)?,
            ProductPermission::ManageEndpoints,
            AuditAction::ImportEndpoints,
            AuditRedfishOperation::None,
        )?;
        let event = AuditEvent::started(context, OffsetDateTime::now_utc());

        AuditEventWriter::append_audit_event(&store, &event).await?;

        assert_eq!(store.find_audit_operation(operation_id).await?, [event]);
        store.close().await?;
        drop(directory);
        Ok(())
    }

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

    #[tokio::test]
    async fn sqlite_store_forwards_the_endpoint_refresh_repository_boundary()
    -> Result<(), Box<dyn Error>> {
        fn assert_repository<Repository: EndpointRefreshRepository>() {}
        assert_repository::<SqliteStore>();

        let directory = tempfile::tempdir()?;
        let store = SqliteStore::open(directory.path().join("rutilus.db")).await?;
        let endpoint_id = EndpointId::generate();
        assert!(
            EndpointRefreshRepository::find_endpoint(&store, endpoint_id)
                .await?
                .is_none()
        );
        let observations = [ResourceObservation::new(
            ResourceFeature::ServiceRoot,
            ResourceODataId::parse("/redfish/v1/")?,
            ResourceSnapshotPayload::parse(r#"{"Name":"Root"}"#)?,
        )];
        assert!(matches!(
            EndpointRefreshRepository::commit_resource_generation(
                &store,
                endpoint_id,
                &observations,
                OffsetDateTime::now_utc(),
            )
            .await,
            Err(EndpointRefreshPersistenceError::Snapshot(
                ResourceSnapshotRepositoryError::EndpointNotFound { .. }
            ))
        ));

        store.close().await?;
        drop(directory);
        Ok(())
    }
}
