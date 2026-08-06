use std::{collections::BTreeSet, error::Error};

use rutilus_domain::{
    Endpoint, EndpointId, RefreshGeneration, ResourceFeature, ResourceId, ResourceSnapshot,
};
use thiserror::Error;
use time::OffsetDateTime;

use crate::BoundaryFuture;

/// One managed endpoint and its latest complete resource Generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndpointInventoryItem {
    endpoint: Endpoint,
    resources: Vec<ResourceSnapshot>,
}

impl EndpointInventoryItem {
    /// Constructs an inventory item while enforcing complete-Generation
    /// invariants at the application boundary.
    ///
    /// An empty resource set represents an endpoint whose first successful
    /// refresh has not completed yet. A non-empty set must belong entirely to
    /// the endpoint, contain exactly one Service Root, and share one refresh
    /// Generation and observation time.
    ///
    /// # Errors
    ///
    /// Returns [`EndpointInventoryItemError`] when a repository supplies a
    /// mixed, duplicated, incomplete, or foreign resource Generation.
    pub fn try_new(
        endpoint: Endpoint,
        mut resources: Vec<ResourceSnapshot>,
    ) -> Result<Self, EndpointInventoryItemError> {
        if resources.is_empty() {
            return Ok(Self {
                endpoint,
                resources,
            });
        }

        let endpoint_id = endpoint.id();
        let expected_generation = resources[0].generation();
        let expected_observed_at = resources[0].observed_at();
        let mut resource_ids = BTreeSet::new();
        let mut odata_ids = BTreeSet::new();
        let mut service_roots = 0_usize;

        for resource in &resources {
            if resource.endpoint_id() != endpoint_id {
                return Err(EndpointInventoryItemError::ForeignResource {
                    endpoint_id,
                    resource_id: resource.resource_id(),
                });
            }
            if resource.generation() != expected_generation {
                return Err(EndpointInventoryItemError::MixedGeneration { endpoint_id });
            }
            if resource.observed_at() != expected_observed_at {
                return Err(EndpointInventoryItemError::MixedObservationTime { endpoint_id });
            }
            if !resource_ids.insert(resource.resource_id()) {
                return Err(EndpointInventoryItemError::DuplicateResourceId {
                    endpoint_id,
                    resource_id: resource.resource_id(),
                });
            }
            if !odata_ids.insert(resource.odata_id().as_str()) {
                return Err(EndpointInventoryItemError::DuplicateODataId { endpoint_id });
            }
            if resource.feature() == ResourceFeature::ServiceRoot {
                service_roots += 1;
            }
        }

        match service_roots {
            1 => {}
            0 => return Err(EndpointInventoryItemError::ServiceRootMissing { endpoint_id }),
            _ => return Err(EndpointInventoryItemError::MultipleServiceRoots { endpoint_id }),
        }
        resources.sort_by(|left, right| left.odata_id().cmp(right.odata_id()));
        Ok(Self {
            endpoint,
            resources,
        })
    }

    #[must_use]
    pub const fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    #[must_use]
    pub fn resources(&self) -> &[ResourceSnapshot] {
        &self.resources
    }

    #[must_use]
    pub fn generation(&self) -> Option<RefreshGeneration> {
        self.resources.first().map(ResourceSnapshot::generation)
    }

    #[must_use]
    pub fn last_successful_refresh_at(&self) -> Option<OffsetDateTime> {
        self.resources.first().map(ResourceSnapshot::observed_at)
    }

    #[must_use]
    pub fn resource_count(&self, feature: ResourceFeature) -> usize {
        self.resources
            .iter()
            .filter(|resource| resource.feature() == feature)
            .count()
    }

    #[must_use]
    pub fn into_parts(self) -> (Endpoint, Vec<ResourceSnapshot>) {
        (self.endpoint, self.resources)
    }
}

/// A repository returned an invalid endpoint inventory projection.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum EndpointInventoryItemError {
    #[error("resource {resource_id} does not belong to endpoint {endpoint_id}")]
    ForeignResource {
        endpoint_id: EndpointId,
        resource_id: ResourceId,
    },
    #[error("endpoint {endpoint_id} inventory contains mixed refresh Generations")]
    MixedGeneration { endpoint_id: EndpointId },
    #[error("endpoint {endpoint_id} inventory contains mixed observation times")]
    MixedObservationTime { endpoint_id: EndpointId },
    #[error("endpoint {endpoint_id} inventory repeats resource {resource_id}")]
    DuplicateResourceId {
        endpoint_id: EndpointId,
        resource_id: ResourceId,
    },
    #[error("endpoint {endpoint_id} inventory repeats an @odata.id")]
    DuplicateODataId { endpoint_id: EndpointId },
    #[error("endpoint {endpoint_id} inventory has no Service Root")]
    ServiceRootMissing { endpoint_id: EndpointId },
    #[error("endpoint {endpoint_id} inventory has multiple Service Roots")]
    MultipleServiceRoots { endpoint_id: EndpointId },
}

/// Reads every endpoint with its latest complete resource Generation.
pub trait EndpointInventoryRepository: Send + Sync {
    type Error: Error + Send + Sync + 'static;

    fn list_endpoint_inventory(
        &self,
    ) -> BoundaryFuture<'_, Result<Vec<EndpointInventoryItem>, Self::Error>>;
}

impl<Repository> EndpointInventoryRepository for &Repository
where
    Repository: EndpointInventoryRepository + ?Sized,
{
    type Error = Repository::Error;

    fn list_endpoint_inventory(
        &self,
    ) -> BoundaryFuture<'_, Result<Vec<EndpointInventoryItem>, Self::Error>> {
        Repository::list_endpoint_inventory(*self)
    }
}

/// Lists endpoint inventory in deterministic product order.
pub struct EndpointInventoryQuery<Repository> {
    repository: Repository,
}

impl<Repository> EndpointInventoryQuery<Repository>
where
    Repository: EndpointInventoryRepository,
{
    #[must_use]
    pub const fn new(repository: Repository) -> Self {
        Self { repository }
    }

    /// Loads every inventory item, rejects duplicate endpoint identities, and
    /// orders the result by display name and stable identity.
    ///
    /// # Errors
    ///
    /// Returns [`EndpointInventoryQueryError`] when persistence fails or emits
    /// the same endpoint more than once.
    pub async fn execute(
        &self,
    ) -> Result<Vec<EndpointInventoryItem>, EndpointInventoryQueryError<Repository::Error>> {
        let mut items = self
            .repository
            .list_endpoint_inventory()
            .await
            .map_err(EndpointInventoryQueryError::Repository)?;
        let mut endpoint_ids = BTreeSet::new();
        for item in &items {
            let endpoint_id = item.endpoint().id();
            if !endpoint_ids.insert(endpoint_id) {
                return Err(EndpointInventoryQueryError::DuplicateEndpoint { endpoint_id });
            }
        }
        items.sort_by(|left, right| {
            left.endpoint()
                .display_name()
                .cmp(right.endpoint().display_name())
                .then_with(|| left.endpoint().id().cmp(&right.endpoint().id()))
        });
        Ok(items)
    }
}

/// A controlled failure while listing the managed endpoint inventory.
#[derive(Debug, Error)]
pub enum EndpointInventoryQueryError<RepositoryError>
where
    RepositoryError: Error + 'static,
{
    #[error("failed to load endpoint inventory: {0}")]
    Repository(#[source] RepositoryError),
    #[error("endpoint inventory repeats endpoint {endpoint_id}")]
    DuplicateEndpoint { endpoint_id: EndpointId },
}

#[cfg(test)]
mod tests {
    use std::fmt;

    use rutilus_domain::{
        CredentialId, EndpointAddress, EndpointDisplayName, RefreshGeneration, ResourceODataId,
        ResourceSnapshotPayload, TlsCertificate, TlsTrust,
    };

    use super::*;

    #[test]
    fn accepts_empty_or_one_complete_generation_and_projects_summary() -> Result<(), Box<dyn Error>>
    {
        let endpoint = endpoint("Rack B", 1)?;
        let empty = EndpointInventoryItem::try_new(endpoint.clone(), Vec::new())?;
        assert_eq!(empty.generation(), None);
        assert_eq!(empty.last_successful_refresh_at(), None);
        assert_eq!(empty.resource_count(ResourceFeature::Systems), 0);

        let generation = RefreshGeneration::new(7)?;
        let observed_at = endpoint.updated_at();
        let systems = snapshot(
            endpoint.id(),
            ResourceId::generate(),
            ResourceFeature::Systems,
            "/redfish/v1/Systems/1",
            observed_at,
            generation,
        )?;
        let root = snapshot(
            endpoint.id(),
            ResourceId::generate(),
            ResourceFeature::ServiceRoot,
            "/redfish/v1",
            observed_at,
            generation,
        )?;
        let item = EndpointInventoryItem::try_new(endpoint.clone(), vec![systems, root])?;

        assert_eq!(item.endpoint(), &endpoint);
        assert_eq!(item.generation(), Some(generation));
        assert_eq!(item.last_successful_refresh_at(), Some(observed_at));
        assert_eq!(item.resource_count(ResourceFeature::ServiceRoot), 1);
        assert_eq!(item.resource_count(ResourceFeature::Systems), 1);
        assert_eq!(item.resources()[0].odata_id().as_str(), "/redfish/v1");
        Ok(())
    }

    #[test]
    fn rejects_foreign_and_mixed_generations() -> Result<(), Box<dyn Error>> {
        let other = endpoint("Rack B", 3)?;
        let endpoint = endpoint("Rack A", 2)?;
        let observed_at = endpoint.updated_at();
        let generation = RefreshGeneration::new(1)?;
        let root_id = ResourceId::generate();
        let root = snapshot(
            endpoint.id(),
            root_id,
            ResourceFeature::ServiceRoot,
            "/redfish/v1",
            observed_at,
            generation,
        )?;

        assert!(matches!(
            EndpointInventoryItem::try_new(
                endpoint.clone(),
                vec![snapshot(
                    other.id(),
                    ResourceId::generate(),
                    ResourceFeature::ServiceRoot,
                    "/redfish/v1",
                    observed_at,
                    generation,
                )?]
            ),
            Err(EndpointInventoryItemError::ForeignResource { .. })
        ));
        assert_eq!(
            EndpointInventoryItem::try_new(
                endpoint.clone(),
                vec![
                    root.clone(),
                    snapshot(
                        endpoint.id(),
                        ResourceId::generate(),
                        ResourceFeature::Systems,
                        "/redfish/v1/Systems/1",
                        observed_at,
                        RefreshGeneration::new(2)?,
                    )?,
                ],
            ),
            Err(EndpointInventoryItemError::MixedGeneration {
                endpoint_id: endpoint.id()
            })
        );
        assert!(matches!(
            EndpointInventoryItem::try_new(
                endpoint.clone(),
                vec![
                    root.clone(),
                    snapshot(
                        endpoint.id(),
                        ResourceId::generate(),
                        ResourceFeature::Systems,
                        "/redfish/v1/Systems/1",
                        observed_at + time::Duration::SECOND,
                        generation,
                    )?,
                ],
            ),
            Err(EndpointInventoryItemError::MixedObservationTime { .. })
        ));
        Ok(())
    }

    #[test]
    fn rejects_duplicated_and_incomplete_generations() -> Result<(), Box<dyn Error>> {
        let endpoint = endpoint("Rack A", 2)?;
        let observed_at = endpoint.updated_at();
        let generation = RefreshGeneration::new(1)?;
        let root = snapshot(
            endpoint.id(),
            ResourceId::generate(),
            ResourceFeature::ServiceRoot,
            "/redfish/v1",
            observed_at,
            generation,
        )?;

        assert!(matches!(
            EndpointInventoryItem::try_new(endpoint.clone(), vec![root.clone(), root.clone()]),
            Err(EndpointInventoryItemError::DuplicateResourceId { .. })
        ));
        assert!(matches!(
            EndpointInventoryItem::try_new(
                endpoint.clone(),
                vec![
                    root.clone(),
                    snapshot(
                        endpoint.id(),
                        ResourceId::generate(),
                        ResourceFeature::Systems,
                        "/redfish/v1",
                        observed_at,
                        generation,
                    )?,
                ],
            ),
            Err(EndpointInventoryItemError::DuplicateODataId { .. })
        ));
        assert!(matches!(
            EndpointInventoryItem::try_new(
                endpoint.clone(),
                vec![snapshot(
                    endpoint.id(),
                    ResourceId::generate(),
                    ResourceFeature::Systems,
                    "/redfish/v1/Systems/1",
                    observed_at,
                    generation,
                )?]
            ),
            Err(EndpointInventoryItemError::ServiceRootMissing { .. })
        ));
        assert!(matches!(
            EndpointInventoryItem::try_new(
                endpoint.clone(),
                vec![
                    root,
                    snapshot(
                        endpoint.id(),
                        ResourceId::generate(),
                        ResourceFeature::ServiceRoot,
                        "/redfish/v1/duplicate",
                        observed_at,
                        generation,
                    )?,
                ],
            ),
            Err(EndpointInventoryItemError::MultipleServiceRoots { .. })
        ));
        Ok(())
    }

    #[tokio::test]
    async fn query_sorts_and_rejects_duplicate_endpoint_identity() -> Result<(), Box<dyn Error>> {
        let first = EndpointInventoryItem::try_new(endpoint("Rack B", 4)?, Vec::new())?;
        let second = EndpointInventoryItem::try_new(endpoint("Rack A", 5)?, Vec::new())?;
        let query = EndpointInventoryQuery::new(MockRepository::ok(vec![first, second]));

        let items = query.execute().await?;
        assert_eq!(items[0].endpoint().display_name().as_str(), "Rack A");
        assert_eq!(items[1].endpoint().display_name().as_str(), "Rack B");

        let repeated = items[0].clone();
        let duplicate_id = repeated.endpoint().id();
        let duplicate =
            EndpointInventoryQuery::new(MockRepository::ok(vec![repeated.clone(), repeated]));
        assert!(matches!(
            duplicate.execute().await,
            Err(EndpointInventoryQueryError::DuplicateEndpoint { endpoint_id })
                if endpoint_id == duplicate_id
        ));

        let failed = EndpointInventoryQuery::new(MockRepository::failed());
        assert!(matches!(
            failed.execute().await,
            Err(EndpointInventoryQueryError::Repository(MockError))
        ));
        Ok(())
    }

    fn endpoint(name: &str, address_suffix: u8) -> Result<Endpoint, Box<dyn Error>> {
        let now = OffsetDateTime::from_unix_timestamp(1_800_000_000)?;
        Ok(Endpoint::try_new(
            EndpointId::generate(),
            EndpointDisplayName::parse(name)?,
            EndpointAddress::parse(&format!("https://192.0.2.{address_suffix}"))?,
            TlsTrust::PinnedCertificate {
                certificate: TlsCertificate::from_der(vec![address_suffix])?,
                trusted_at: now,
            },
            CredentialId::generate(),
            now,
            now,
        )?)
    }

    fn snapshot(
        endpoint_id: EndpointId,
        resource_id: ResourceId,
        feature: ResourceFeature,
        odata_id: &str,
        observed_at: OffsetDateTime,
        generation: RefreshGeneration,
    ) -> Result<ResourceSnapshot, Box<dyn Error>> {
        Ok(ResourceSnapshot::new(
            resource_id,
            endpoint_id,
            feature,
            ResourceODataId::parse(odata_id)?,
            ResourceSnapshotPayload::parse(r#"{"Name":"Inventory test"}"#)?,
            observed_at,
            generation,
        ))
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct MockError;

    impl fmt::Display for MockError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("mock inventory failure")
        }
    }

    impl Error for MockError {}

    struct MockRepository {
        result: Result<Vec<EndpointInventoryItem>, MockError>,
    }

    impl MockRepository {
        fn ok(items: Vec<EndpointInventoryItem>) -> Self {
            Self { result: Ok(items) }
        }

        fn failed() -> Self {
            Self {
                result: Err(MockError),
            }
        }
    }

    impl EndpointInventoryRepository for MockRepository {
        type Error = MockError;

        fn list_endpoint_inventory(
            &self,
        ) -> BoundaryFuture<'_, Result<Vec<EndpointInventoryItem>, Self::Error>> {
            Box::pin(async { self.result.clone() })
        }
    }
}
