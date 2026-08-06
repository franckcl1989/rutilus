use rutilus_application::{
    AuditEventWriter, BoundaryFuture, CapabilityQueryRepository, CapabilitySnapshotRepository,
    CredentialInventoryRepository, DiscoveredEndpointRepository, EndpointInventoryItem,
    EndpointInventoryItemError, EndpointInventoryRepository, EndpointRefreshRepository,
    ResourceObservation, StoredCapability,
};
use rutilus_domain::{
    AuditEvent, Credential, Endpoint, EndpointCapabilityObservation, EndpointId, Operation,
    OperationId, OperationState, ResourceSnapshot,
};
use rutilus_operation_engine::{BoundaryFuture as OperationBoundaryFuture, OperationStore};
use thiserror::Error;
use time::OffsetDateTime;

use crate::{
    AuditRepositoryError, CredentialRepositoryError, EndpointCapabilityRepositoryError,
    EndpointRepositoryError, NewResourceSnapshot, OperationRepositoryError,
    ResourceSnapshotRepositoryError, SqliteStore,
};

/// Defensive upper bound for one credential inventory projection.
const CREDENTIAL_INVENTORY_LIMIT: u64 = 1000;

impl AuditEventWriter for SqliteStore {
    type Error = AuditRepositoryError;

    fn append_audit_event<'a>(
        &'a self,
        event: &'a AuditEvent,
    ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
        Box::pin(async move { SqliteStore::append_audit_event(self, event).await })
    }
}

impl CapabilityQueryRepository for SqliteStore {
    type Error = EndpointCapabilityRepositoryError;

    fn find_endpoint_capabilities(
        &self,
        endpoint_id: EndpointId,
    ) -> BoundaryFuture<'_, Result<Option<Vec<StoredCapability>>, Self::Error>> {
        Box::pin(async move {
            let stored = SqliteStore::find_endpoint_capabilities(self, endpoint_id).await?;
            Ok(stored.map(|capabilities| {
                capabilities
                    .iter()
                    .map(|capability| {
                        StoredCapability::new(capability.observation(), capability.observed_at())
                    })
                    .collect()
            }))
        })
    }
}

impl CapabilitySnapshotRepository for SqliteStore {
    type Error = EndpointCapabilityRepositoryError;

    /// Forwards the whole-snapshot write unchanged: the atomic store
    /// transaction already rejects empty and duplicated pages, which is the
    /// same contract the refresh use case promises, so no boundary-side
    /// validation or error shaping is needed here.
    fn replace_endpoint_capabilities<'a>(
        &'a self,
        endpoint_id: EndpointId,
        observations: &'a [EndpointCapabilityObservation],
        observed_at: OffsetDateTime,
    ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
        Box::pin(async move {
            SqliteStore::replace_endpoint_capabilities(self, endpoint_id, observations, observed_at)
                .await
        })
    }
}

impl CredentialInventoryRepository for SqliteStore {
    type Error = CredentialRepositoryError;

    fn list_credentials(&self) -> BoundaryFuture<'_, Result<Vec<Credential>, Self::Error>> {
        Box::pin(
            async move { SqliteStore::list_credentials(self, CREDENTIAL_INVENTORY_LIMIT).await },
        )
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

impl OperationStore for SqliteStore {
    type Error = OperationRepositoryError;

    fn create_operation<'a>(
        &'a self,
        operation: &'a Operation,
    ) -> OperationBoundaryFuture<'a, Result<(), Self::Error>> {
        Box::pin(async move { SqliteStore::create_operation(self, operation).await })
    }

    fn find_operation(
        &self,
        operation_id: OperationId,
    ) -> OperationBoundaryFuture<'_, Result<Option<Operation>, Self::Error>> {
        Box::pin(async move { SqliteStore::find_operation(self, operation_id).await })
    }

    fn apply_transition(
        &self,
        operation_id: OperationId,
        new_state: OperationState,
        occurred_at: OffsetDateTime,
    ) -> OperationBoundaryFuture<'_, Result<(), Self::Error>> {
        Box::pin(async move {
            SqliteStore::apply_transition(self, operation_id, new_state, occurred_at).await
        })
    }

    fn list_operations(
        &self,
        state: Option<OperationState>,
    ) -> OperationBoundaryFuture<'_, Result<Vec<Operation>, Self::Error>> {
        Box::pin(async move { SqliteStore::list_operations(self, state).await })
    }
}

impl EndpointInventoryRepository for SqliteStore {
    type Error = EndpointInventoryPersistenceError;

    fn list_endpoint_inventory(
        &self,
    ) -> BoundaryFuture<'_, Result<Vec<EndpointInventoryItem>, Self::Error>> {
        Box::pin(async move {
            let endpoints = SqliteStore::list_endpoints(self)
                .await
                .map_err(EndpointInventoryPersistenceError::Endpoint)?;
            let mut inventory = Vec::with_capacity(endpoints.len());
            for endpoint in endpoints {
                let endpoint_id = endpoint.id();
                let resources = SqliteStore::find_current_resource_generation(self, endpoint_id)
                    .await
                    .map_err(EndpointInventoryPersistenceError::Snapshot)?
                    .ok_or(EndpointInventoryPersistenceError::EndpointDisappeared {
                        endpoint_id,
                    })?;
                inventory.push(
                    EndpointInventoryItem::try_new(endpoint, resources)
                        .map_err(EndpointInventoryPersistenceError::Inventory)?,
                );
            }
            Ok(inventory)
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

/// A persistence failure while projecting the complete endpoint inventory.
#[derive(Debug, Error)]
pub enum EndpointInventoryPersistenceError {
    #[error("failed to list endpoint aggregates: {0}")]
    Endpoint(#[source] EndpointRepositoryError),
    #[error("failed to load an endpoint's current resource Generation: {0}")]
    Snapshot(#[source] ResourceSnapshotRepositoryError),
    #[error("endpoint {endpoint_id} disappeared while loading its inventory")]
    EndpointDisappeared { endpoint_id: EndpointId },
    #[error("persisted endpoint inventory violates application invariants: {0}")]
    Inventory(#[source] EndpointInventoryItemError),
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use rutilus_application::{
        AuditEventWriter, CapabilityQueryRepository, CapabilitySnapshotRepository,
        CredentialInventoryQuery, CredentialInventoryRepository, DiscoveredEndpointRepository,
        EndpointCapabilityQuery, EndpointInventoryQuery, EndpointInventoryRepository,
        EndpointRefreshRepository, ResourceObservation,
    };
    use rutilus_domain::{
        AuditAction, AuditActor, AuditEvent, AuditOperationContext, AuditOperationId,
        AuditParameterSummary, AuditRedfishOperation, AuditTarget, CAPABILITY_LEDGER_ORDER,
        CapabilityState, CredentialId, CredentialName, CredentialUsername, CredentialVersionId,
        DeploymentPosture, Endpoint, EndpointAddress, EndpointCapabilityObservation,
        EndpointDisplayName, EndpointId, Operation, OperationEvent, OperationId, OperationSource,
        OperationState, OperationTarget, ProductPermission, ResourceFeature, ResourceODataId,
        ResourceSnapshotPayload, TargetId, TlsCertificate, TlsTrust,
    };
    use rutilus_operation_engine::{OperationEngine, OperationStore};
    use rutilus_security::{MasterKey, encrypt_credential};
    use secrecy::SecretString;
    use time::{Duration, OffsetDateTime};

    use crate::{
        EndpointCapabilityRepositoryError, EndpointRefreshPersistenceError,
        EndpointRepositoryError, NewCredential, ResourceSnapshotRepositoryError, SqliteStore,
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

    #[tokio::test]
    async fn sqlite_store_projects_complete_endpoint_inventory() -> Result<(), Box<dyn Error>> {
        fn assert_repository<Repository: EndpointInventoryRepository>() {}
        assert_repository::<SqliteStore>();

        let directory = tempfile::tempdir()?;
        let store = SqliteStore::open(directory.path().join("rutilus.db")).await?;
        assert!(
            EndpointInventoryQuery::new(&store)
                .execute()
                .await?
                .is_empty()
        );
        let (endpoint, observed_at) = inventory_endpoint(&store).await?;
        store.create_endpoint(endpoint.clone()).await?;

        let before_refresh = EndpointInventoryQuery::new(&store).execute().await?;
        assert_eq!(before_refresh.len(), 1);
        assert_eq!(before_refresh[0].endpoint(), &endpoint);
        assert_eq!(before_refresh[0].generation(), None);

        let observations = [
            ResourceObservation::new(
                ResourceFeature::Systems,
                ResourceODataId::parse("/redfish/v1/Systems/1")?,
                ResourceSnapshotPayload::parse(r#"{"Name":"System"}"#)?,
            ),
            ResourceObservation::new(
                ResourceFeature::ServiceRoot,
                ResourceODataId::parse("/redfish/v1")?,
                ResourceSnapshotPayload::parse(r#"{"Name":"Root"}"#)?,
            ),
        ];
        EndpointRefreshRepository::commit_resource_generation(
            &store,
            endpoint.id(),
            &observations,
            observed_at,
        )
        .await?;

        let after_refresh = EndpointInventoryQuery::new(&store).execute().await?;
        assert_eq!(after_refresh.len(), 1);
        assert_eq!(
            after_refresh[0]
                .generation()
                .map(rutilus_domain::RefreshGeneration::get),
            Some(1)
        );
        assert_eq!(
            after_refresh[0].last_successful_refresh_at(),
            Some(observed_at)
        );
        assert_eq!(after_refresh[0].resource_count(ResourceFeature::Systems), 1);
        assert_eq!(
            after_refresh[0].resources()[0].odata_id().as_str(),
            "/redfish/v1"
        );

        store.close().await?;
        drop(directory);
        Ok(())
    }

    async fn inventory_endpoint(
        store: &SqliteStore,
    ) -> Result<(Endpoint, OffsetDateTime), Box<dyn Error>> {
        let credential_id = CredentialId::generate();
        let version_id = CredentialVersionId::generate();
        let key = MasterKey::from_boxed_bytes(Box::new([0x61; 32]));
        let secret = SecretString::from(String::from("inventory test secret"));
        let protected = encrypt_credential(&key, credential_id, version_id, &secret)?;
        store
            .create_credential(NewCredential::new(
                CredentialName::parse("Inventory credential")?,
                CredentialUsername::parse("administrator")?,
                protected,
            ))
            .await?;
        let created_at = OffsetDateTime::now_utc();
        let observed_at = created_at + time::Duration::SECOND;
        let endpoint = Endpoint::try_new(
            EndpointId::generate(),
            EndpointDisplayName::parse("Inventory BMC")?,
            EndpointAddress::parse("https://192.0.2.81")?,
            TlsTrust::PinnedCertificate {
                certificate: TlsCertificate::from_der(b"inventory certificate".to_vec())?,
                trusted_at: created_at,
            },
            credential_id,
            created_at,
            created_at,
        )?;
        Ok((endpoint, observed_at))
    }

    #[tokio::test]
    async fn sqlite_store_merges_the_complete_capability_ledger_at_the_boundary()
    -> Result<(), Box<dyn Error>> {
        fn assert_repository<Repository: CapabilityQueryRepository>() {}
        assert_repository::<SqliteStore>();

        let directory = tempfile::tempdir()?;
        let store = SqliteStore::open(directory.path().join("rutilus.db")).await?;
        let (endpoint, created_at) = capability_endpoint(&store).await?;
        store.create_endpoint(endpoint.clone()).await?;
        let endpoint_id = endpoint.id();

        // An existing endpoint with no completed probe still yields the
        // complete unobserved ledger, never a missing result.
        let unobserved = EndpointCapabilityQuery::new(&store, endpoint_id)
            .execute()
            .await?
            .ok_or("endpoint capabilities are missing")?;
        assert_eq!(unobserved.len(), CAPABILITY_LEDGER_ORDER.len());
        assert!(
            unobserved
                .iter()
                .zip(CAPABILITY_LEDGER_ORDER)
                .all(|(entry, capability)| {
                    entry.capability() == capability
                        && entry.state().is_none()
                        && entry.observed_at().is_none()
                }),
            "an unobserved endpoint must still expose the complete §2.1 ledger"
        );

        let observed_at = created_at + Duration::SECOND;
        store
            .replace_endpoint_capabilities(endpoint_id, &all_capability_observations(), observed_at)
            .await?;
        let observed = EndpointCapabilityQuery::new(&store, endpoint_id)
            .execute()
            .await?
            .ok_or("endpoint capabilities are missing")?;
        assert_eq!(observed.len(), CAPABILITY_LEDGER_ORDER.len());
        assert!(
            observed
                .iter()
                .zip(CAPABILITY_LEDGER_ORDER)
                .all(|(entry, capability)| {
                    entry.capability() == capability
                        && entry.observed_at() == Some(observed_at)
                        && entry.state().is_some()
                }),
            "every compiled capability must read back in §2.1 ledger order with its observed state"
        );
        assert_eq!(
            observed
                .iter()
                .find(|entry| entry.capability()
                    == rutilus_domain::EndpointCapability::SessionService)
                .ok_or("session-service entry is missing")?
                .classification(),
            rutilus_domain::CapabilityClassification::Infrastructure
        );

        // An unknown endpoint stays distinguishable from an unobserved one.
        assert!(
            EndpointCapabilityQuery::new(&store, EndpointId::generate())
                .execute()
                .await?
                .is_none()
        );

        store.close().await?;
        drop(directory);
        Ok(())
    }

    async fn capability_endpoint(
        store: &SqliteStore,
    ) -> Result<(Endpoint, OffsetDateTime), Box<dyn Error>> {
        let credential_id = CredentialId::generate();
        let version_id = CredentialVersionId::generate();
        let key = MasterKey::from_boxed_bytes(Box::new([0x63; 32]));
        let secret = SecretString::from(String::from("capability test secret"));
        let protected = encrypt_credential(&key, credential_id, version_id, &secret)?;
        store
            .create_credential(NewCredential::new(
                CredentialName::parse("Capability credential")?,
                CredentialUsername::parse("administrator")?,
                protected,
            ))
            .await?;
        let created_at = OffsetDateTime::now_utc();
        let endpoint = Endpoint::try_new(
            EndpointId::generate(),
            EndpointDisplayName::parse("Capability BMC")?,
            EndpointAddress::parse("https://192.0.2.82")?,
            TlsTrust::PinnedCertificate {
                certificate: TlsCertificate::from_der(b"capability certificate".to_vec())?,
                trusted_at: created_at,
            },
            credential_id,
            created_at,
            created_at,
        )?;
        Ok((endpoint, created_at))
    }

    /// Every `EndpointCapability` variant with a deterministic state, so the
    /// boundary round-trip proves the complete compiled surface survives
    /// persistence and the §2.1 ledger order is restored by the query.
    fn all_capability_observations() -> Vec<EndpointCapabilityObservation> {
        const STATES: [CapabilityState; 7] = [
            CapabilityState::Supported,
            CapabilityState::ReadOnly,
            CapabilityState::Unauthorized,
            CapabilityState::TemporarilyUnavailable,
            CapabilityState::SchemaIncompatible,
            CapabilityState::NotAdvertised,
            CapabilityState::NotCompiled,
        ];
        CAPABILITY_LEDGER_ORDER
            .into_iter()
            .enumerate()
            .map(|(index, capability)| {
                EndpointCapabilityObservation::new(capability, STATES[index % STATES.len()])
            })
            .collect()
    }

    #[tokio::test]
    async fn sqlite_store_forwards_the_capability_snapshot_boundary() -> Result<(), Box<dyn Error>>
    {
        fn assert_repository<Repository: CapabilitySnapshotRepository>() {}
        assert_repository::<SqliteStore>();

        let directory = tempfile::tempdir()?;
        let store = SqliteStore::open(directory.path().join("rutilus.db")).await?;
        let (endpoint, created_at) = capability_endpoint(&store).await?;
        store.create_endpoint(endpoint.clone()).await?;
        let endpoint_id = endpoint.id();

        // The atomic store contract stays intact at the application boundary:
        // empty and internally duplicated pages are rejected before any
        // existing observation can change.
        assert!(matches!(
            CapabilitySnapshotRepository::replace_endpoint_capabilities(
                &store,
                endpoint_id,
                &[],
                created_at,
            )
            .await,
            Err(EndpointCapabilityRepositoryError::EmptySnapshot { .. })
        ));
        let observations = all_capability_observations();
        let duplicated = [observations[0], observations[0]];
        assert!(matches!(
            CapabilitySnapshotRepository::replace_endpoint_capabilities(
                &store,
                endpoint_id,
                &duplicated,
                created_at,
            )
            .await,
            Err(EndpointCapabilityRepositoryError::DuplicateCapability { .. })
        ));

        // One valid call replaces the whole snapshot and reads back through
        // the query boundary with the same observed time.
        let observed_at = created_at + Duration::SECOND;
        CapabilitySnapshotRepository::replace_endpoint_capabilities(
            &store,
            endpoint_id,
            &observations,
            observed_at,
        )
        .await?;
        let stored = CapabilityQueryRepository::find_endpoint_capabilities(&store, endpoint_id)
            .await?
            .ok_or("endpoint capabilities are missing")?;
        assert_eq!(stored.len(), CAPABILITY_LEDGER_ORDER.len());
        assert!(
            stored
                .iter()
                .all(|capability| capability.observed_at() == observed_at),
            "every persisted observation must carry the refresh clock time"
        );

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn sqlite_store_forwards_the_credential_inventory_boundary() -> Result<(), Box<dyn Error>>
    {
        fn assert_repository<Repository: CredentialInventoryRepository>() {}
        assert_repository::<SqliteStore>();

        let directory = tempfile::tempdir()?;
        let store = SqliteStore::open(directory.path().join("rutilus.db")).await?;
        assert!(
            CredentialInventoryQuery::new(&store)
                .execute()
                .await?
                .is_empty()
        );

        let key = MasterKey::from_boxed_bytes(Box::new([0x66; 32]));
        let secret: SecretString = String::from("inventory secret").into();
        store
            .create_credential(NewCredential::new(
                CredentialName::parse("Zulu inventory")?,
                CredentialUsername::parse("operator")?,
                encrypt_credential(
                    &key,
                    CredentialId::generate(),
                    CredentialVersionId::generate(),
                    &secret,
                )?,
            ))
            .await?;
        store
            .create_credential(NewCredential::new(
                CredentialName::parse("Alpha inventory")?,
                CredentialUsername::parse("administrator")?,
                encrypt_credential(
                    &key,
                    CredentialId::generate(),
                    CredentialVersionId::generate(),
                    &secret,
                )?,
            ))
            .await?;

        let credentials = CredentialInventoryQuery::new(&store).execute().await?;
        assert_eq!(credentials.len(), 2);
        assert_eq!(credentials[0].name().as_str(), "Alpha inventory");
        assert_eq!(credentials[1].name().as_str(), "Zulu inventory");
        assert_eq!(
            credentials[1].username().as_str(),
            "operator",
            "deterministic inventory order must pair name and username"
        );

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn sqlite_store_forwards_the_operation_store_boundary() -> Result<(), Box<dyn Error>> {
        fn assert_repository<Repository: OperationStore>() {}
        assert_repository::<SqliteStore>();

        let directory = tempfile::tempdir()?;
        let store = SqliteStore::open(directory.path().join("rutilus.db")).await?;
        let created_at = OffsetDateTime::now_utc();
        let operation = Operation::new(
            OperationId::generate(),
            OperationSource::Site,
            vec![OperationTarget::new(
                TargetId::generate(),
                EndpointId::generate(),
            )],
            created_at,
        );

        OperationStore::create_operation(&store, &operation).await?;
        assert_eq!(
            OperationStore::find_operation(&store, operation.id()).await?,
            Some(operation.clone())
        );
        let occurred_at = created_at + Duration::SECOND;
        OperationStore::apply_transition(
            &store,
            operation.id(),
            OperationState::Validating,
            occurred_at,
        )
        .await?;
        let stored = OperationStore::find_operation(&store, operation.id())
            .await?
            .ok_or("stored operation is missing")?;
        assert_eq!(stored.state(), OperationState::Validating);
        assert_eq!(stored.updated_at(), occurred_at);
        assert_eq!(
            OperationStore::list_operations(&store, None).await?.len(),
            1
        );
        assert_eq!(
            OperationStore::list_operations(&store, Some(OperationState::Validating))
                .await?
                .len(),
            1
        );

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn operation_engine_drives_the_sqlite_store_end_to_end() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let store = SqliteStore::open(directory.path().join("rutilus.db")).await?;
        let engine = OperationEngine::new(&store);
        let created_at = OffsetDateTime::now_utc();
        let target = OperationTarget::new(TargetId::generate(), EndpointId::generate());

        // The engine persists through the adapter into real SQLite and re-reads
        // the stored aggregate after every step (§13.3), so the returned value
        // is exactly what the database holds.
        let created = engine
            .create(OperationSource::Site, vec![target], created_at)
            .await?;
        assert_eq!(created.state(), OperationState::Queued);
        let operation_id = created.id();
        assert_eq!(
            OperationStore::find_operation(&store, operation_id).await?,
            Some(created.clone())
        );

        let validating_at = created_at + Duration::SECOND;
        let validating = engine
            .apply(
                operation_id,
                OperationEvent::ValidationStarted,
                validating_at,
            )
            .await?;
        assert_eq!(validating.state(), OperationState::Validating);
        let running_at = validating_at + Duration::SECOND;
        let running = engine
            .apply(operation_id, OperationEvent::ValidationPassed, running_at)
            .await?;
        assert_eq!(running.state(), OperationState::Running);
        let waiting_at = running_at + Duration::SECOND;
        let waiting = engine
            .apply(operation_id, OperationEvent::RemoteTaskStarted, waiting_at)
            .await?;
        assert_eq!(waiting.state(), OperationState::WaitingRemote);

        // The §13.6 recovery scan finds the interrupted in-flight operation.
        let recovered = engine.recover_pending().await?;
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].id(), operation_id);

        let verifying_at = waiting_at + Duration::SECOND;
        let verifying = engine
            .apply(
                operation_id,
                OperationEvent::RemoteTaskCompleted,
                verifying_at,
            )
            .await?;
        assert_eq!(verifying.state(), OperationState::Verifying);
        let succeeded_at = verifying_at + Duration::SECOND;
        let succeeded = engine
            .apply(
                operation_id,
                OperationEvent::VerificationPassed,
                succeeded_at,
            )
            .await?;
        assert_eq!(succeeded.state(), OperationState::Succeeded);
        assert!(succeeded.is_terminal());

        // A finished operation is never reported as recoverable again, and
        // the batch summary boundary (§13.7) still sees it by exact state.
        assert!(
            engine.recover_pending().await?.is_empty(),
            "a finished operation must never be recovered"
        );
        assert_eq!(
            OperationStore::list_operations(&store, Some(OperationState::Succeeded))
                .await?
                .len(),
            1
        );

        store.close().await?;
        drop(directory);
        Ok(())
    }
}
