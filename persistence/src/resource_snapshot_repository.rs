use std::{collections::BTreeMap, str::FromStr};

use rutilus_domain::{
    EndpointId, RefreshGeneration, RefreshGenerationError, ResourceEtag, ResourceEtagError,
    ResourceFeature, ResourceFeatureParseError, ResourceId, ResourceODataId, ResourceODataIdError,
    ResourceODataType, ResourceODataTypeError, ResourceSnapshot, ResourceSnapshotPayload,
    ResourceSnapshotPayloadError,
};
use rutilus_entity::{endpoint, resource, resource_snapshot};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DbErr, EntityTrait, JoinType, QueryFilter,
    QueryOrder, QuerySelect, RelationTrait, Set, TransactionTrait,
};
use thiserror::Error;
use time::OffsetDateTime;

use crate::SqliteStore;

/// One validated typed resource observation awaiting a refresh Generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewResourceSnapshot {
    feature: ResourceFeature,
    odata_id: ResourceODataId,
    odata_type: Option<ResourceODataType>,
    etag: Option<ResourceEtag>,
    payload: ResourceSnapshotPayload,
}

impl NewResourceSnapshot {
    #[must_use]
    pub fn new(
        feature: ResourceFeature,
        odata_id: ResourceODataId,
        payload: ResourceSnapshotPayload,
    ) -> Self {
        Self {
            feature,
            odata_id,
            odata_type: None,
            etag: None,
            payload,
        }
    }

    #[must_use]
    pub fn with_odata_type(mut self, odata_type: ResourceODataType) -> Self {
        self.odata_type = Some(odata_type);
        self
    }

    #[must_use]
    pub fn with_etag(mut self, etag: ResourceEtag) -> Self {
        self.etag = Some(etag);
        self
    }
}

impl SqliteStore {
    /// Atomically appends one complete endpoint refresh Generation.
    ///
    /// The Generation is assigned under the store's write gate. Existing
    /// resource identities are reused by exact `@odata.id`; newly observed
    /// identities are created in the same transaction. Readers see either the
    /// preceding complete Generation or this complete Generation.
    ///
    /// # Errors
    ///
    /// Returns [`ResourceSnapshotRepositoryError`] when the endpoint is absent,
    /// observations are empty or duplicated, no unique Service Root exists,
    /// an observation predates the endpoint, a stable resource changes
    /// feature, Generation space is exhausted, or `SQLite` rejects the commit.
    pub async fn commit_resource_generation(
        &self,
        endpoint_id: EndpointId,
        observations: &[NewResourceSnapshot],
        observed_at: OffsetDateTime,
    ) -> Result<Vec<ResourceSnapshot>, ResourceSnapshotRepositoryError> {
        validate_observations(endpoint_id, observations)?;
        let _write_permit = self
            .write_gate
            .acquire()
            .await
            .map_err(ResourceSnapshotRepositoryError::Coordinate)?;
        let transaction = self
            .database
            .begin()
            .await
            .map_err(ResourceSnapshotRepositoryError::Database)?;
        let endpoint_model = endpoint::Entity::find_by_id(endpoint_id.into_uuid())
            .one(&transaction)
            .await
            .map_err(ResourceSnapshotRepositoryError::Database)?
            .ok_or(ResourceSnapshotRepositoryError::EndpointNotFound { endpoint_id })?;
        if observed_at < endpoint_model.created_at {
            return Err(
                ResourceSnapshotRepositoryError::ObservationPredatesEndpoint { endpoint_id },
            );
        }
        let generation = next_generation(&transaction, endpoint_id).await?;
        let existing = resource::Entity::find()
            .filter(resource::Column::EndpointId.eq(endpoint_id.into_uuid()))
            .all(&transaction)
            .await
            .map_err(ResourceSnapshotRepositoryError::Database)?
            .into_iter()
            .map(|model| (model.odata_id.clone(), model))
            .collect::<BTreeMap<_, _>>();
        validate_stable_features(endpoint_id, observations, &existing)?;

        let mut snapshots = Vec::with_capacity(observations.len());
        for observation in observations {
            let resource_id = match existing.get(observation.odata_id.as_str()) {
                Some(model) => ResourceId::from_uuid(model.id),
                None => {
                    insert_resource(&transaction, endpoint_id, observation, observed_at).await?
                }
            };
            insert_snapshot(
                &transaction,
                resource_id,
                generation,
                observation,
                observed_at,
            )
            .await?;
            snapshots.push(to_domain_snapshot(
                resource_id,
                endpoint_id,
                generation,
                observation,
                observed_at,
            ));
        }
        transaction
            .commit()
            .await
            .map_err(ResourceSnapshotRepositoryError::Database)?;
        snapshots.sort_by(|left, right| left.odata_id().cmp(right.odata_id()));
        Ok(snapshots)
    }

    /// Loads the latest complete resource Generation in stable `@odata.id`
    /// order.
    ///
    /// An existing endpoint without a completed refresh returns an empty
    /// vector; an absent endpoint returns `None`.
    ///
    /// # Errors
    ///
    /// Returns [`ResourceSnapshotRepositoryError`] when a query fails or
    /// persisted identity, metadata, payload, time, or Generation data violates
    /// the domain contract.
    pub async fn find_current_resource_generation(
        &self,
        endpoint_id: EndpointId,
    ) -> Result<Option<Vec<ResourceSnapshot>>, ResourceSnapshotRepositoryError> {
        let transaction = self
            .database
            .begin()
            .await
            .map_err(ResourceSnapshotRepositoryError::Database)?;
        let Some(endpoint_model) = endpoint::Entity::find_by_id(endpoint_id.into_uuid())
            .one(&transaction)
            .await
            .map_err(ResourceSnapshotRepositoryError::Database)?
        else {
            transaction
                .commit()
                .await
                .map_err(ResourceSnapshotRepositoryError::Database)?;
            return Ok(None);
        };
        let Some(latest) = latest_snapshot(&transaction, endpoint_id).await? else {
            transaction
                .commit()
                .await
                .map_err(ResourceSnapshotRepositoryError::Database)?;
            return Ok(Some(Vec::new()));
        };
        let generation = map_generation(endpoint_id, latest.generation)?;
        let rows = resource_snapshot::Entity::find()
            .find_also_related(resource::Entity)
            .filter(resource::Column::EndpointId.eq(endpoint_id.into_uuid()))
            .filter(resource_snapshot::Column::Generation.eq(latest.generation))
            .order_by_asc(resource::Column::OdataId)
            .all(&transaction)
            .await
            .map_err(ResourceSnapshotRepositoryError::Database)?;
        let snapshots = rows
            .into_iter()
            .map(|(snapshot, resource)| {
                let resource = resource.ok_or_else(|| {
                    corrupt(
                        endpoint_id,
                        StoredResourceSnapshotError::ResourceMissing {
                            resource_id: ResourceId::from_uuid(snapshot.resource_id),
                        },
                    )
                })?;
                map_stored_snapshot(
                    endpoint_id,
                    endpoint_model.created_at,
                    generation,
                    &resource,
                    &snapshot,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        validate_loaded_generation(endpoint_id, &snapshots)?;
        transaction
            .commit()
            .await
            .map_err(ResourceSnapshotRepositoryError::Database)?;
        Ok(Some(snapshots))
    }
}

fn validate_observations(
    endpoint_id: EndpointId,
    observations: &[NewResourceSnapshot],
) -> Result<(), ResourceSnapshotRepositoryError> {
    if observations.is_empty() {
        return Err(ResourceSnapshotRepositoryError::EmptyGeneration { endpoint_id });
    }
    let mut identities = BTreeMap::new();
    let mut service_roots = 0_usize;
    for observation in observations {
        if identities
            .insert(observation.odata_id.as_str(), observation.feature)
            .is_some()
        {
            return Err(ResourceSnapshotRepositoryError::DuplicateODataId {
                endpoint_id,
                odata_id: observation.odata_id.clone(),
            });
        }
        if observation.feature == ResourceFeature::ServiceRoot {
            service_roots += 1;
        }
    }
    match service_roots {
        0 => Err(ResourceSnapshotRepositoryError::ServiceRootMissing { endpoint_id }),
        1 => Ok(()),
        _ => Err(ResourceSnapshotRepositoryError::MultipleServiceRoots { endpoint_id }),
    }
}

fn validate_stable_features(
    endpoint_id: EndpointId,
    observations: &[NewResourceSnapshot],
    existing: &BTreeMap<String, resource::Model>,
) -> Result<(), ResourceSnapshotRepositoryError> {
    for observation in observations {
        let Some(model) = existing.get(observation.odata_id.as_str()) else {
            continue;
        };
        let stored = ResourceFeature::from_str(&model.feature)
            .map_err(StoredResourceSnapshotError::UnknownFeature)
            .map_err(|source| corrupt(endpoint_id, source))?;
        if stored != observation.feature {
            return Err(ResourceSnapshotRepositoryError::FeatureChanged {
                endpoint_id,
                odata_id: observation.odata_id.clone(),
                stored,
                observed: observation.feature,
            });
        }
    }
    Ok(())
}

async fn latest_snapshot<C>(
    database: &C,
    endpoint_id: EndpointId,
) -> Result<Option<resource_snapshot::Model>, ResourceSnapshotRepositoryError>
where
    C: ConnectionTrait,
{
    resource_snapshot::Entity::find()
        .join(
            JoinType::InnerJoin,
            resource_snapshot::Relation::Resource.def(),
        )
        .filter(resource::Column::EndpointId.eq(endpoint_id.into_uuid()))
        .order_by_desc(resource_snapshot::Column::Generation)
        .one(database)
        .await
        .map_err(ResourceSnapshotRepositoryError::Database)
}

async fn next_generation<C>(
    database: &C,
    endpoint_id: EndpointId,
) -> Result<RefreshGeneration, ResourceSnapshotRepositoryError>
where
    C: ConnectionTrait,
{
    let Some(latest) = latest_snapshot(database, endpoint_id).await? else {
        return RefreshGeneration::new(1).map_err(|source| corrupt(endpoint_id, source.into()));
    };
    let current = map_generation(endpoint_id, latest.generation)?;
    let next = current
        .get()
        .checked_add(1)
        .ok_or(ResourceSnapshotRepositoryError::GenerationExhausted { endpoint_id })?;
    RefreshGeneration::new(next)
        .map_err(|_| ResourceSnapshotRepositoryError::GenerationExhausted { endpoint_id })
}

async fn insert_resource<C>(
    database: &C,
    endpoint_id: EndpointId,
    observation: &NewResourceSnapshot,
    created_at: OffsetDateTime,
) -> Result<ResourceId, ResourceSnapshotRepositoryError>
where
    C: ConnectionTrait,
{
    let resource_id = ResourceId::generate();
    resource::ActiveModel {
        id: Set(resource_id.into_uuid()),
        endpoint_id: Set(endpoint_id.into_uuid()),
        odata_id: Set(observation.odata_id.to_string()),
        feature: Set(observation.feature.to_string()),
        created_at: Set(created_at),
    }
    .insert(database)
    .await
    .map_err(ResourceSnapshotRepositoryError::Database)?;
    Ok(resource_id)
}

async fn insert_snapshot<C>(
    database: &C,
    resource_id: ResourceId,
    generation: RefreshGeneration,
    observation: &NewResourceSnapshot,
    observed_at: OffsetDateTime,
) -> Result<(), ResourceSnapshotRepositoryError>
where
    C: ConnectionTrait,
{
    resource_snapshot::ActiveModel {
        resource_id: Set(resource_id.into_uuid()),
        generation: Set(generation.get().cast_signed()),
        odata_type: Set(observation.odata_type.as_ref().map(ToString::to_string)),
        etag: Set(observation.etag.as_ref().map(ToString::to_string)),
        typed_payload_json: Set(observation.payload.as_str().to_owned()),
        observed_at: Set(observed_at),
    }
    .insert(database)
    .await
    .map_err(ResourceSnapshotRepositoryError::Database)?;
    Ok(())
}

fn to_domain_snapshot(
    resource_id: ResourceId,
    endpoint_id: EndpointId,
    generation: RefreshGeneration,
    observation: &NewResourceSnapshot,
    observed_at: OffsetDateTime,
) -> ResourceSnapshot {
    let mut snapshot = ResourceSnapshot::new(
        resource_id,
        endpoint_id,
        observation.feature,
        observation.odata_id.clone(),
        observation.payload.clone(),
        observed_at,
        generation,
    );
    if let Some(odata_type) = &observation.odata_type {
        snapshot = snapshot.with_odata_type(odata_type.clone());
    }
    if let Some(etag) = &observation.etag {
        snapshot = snapshot.with_etag(etag.clone());
    }
    snapshot
}

fn map_stored_snapshot(
    endpoint_id: EndpointId,
    endpoint_created_at: OffsetDateTime,
    generation: RefreshGeneration,
    resource: &resource::Model,
    snapshot: &resource_snapshot::Model,
) -> Result<ResourceSnapshot, ResourceSnapshotRepositoryError> {
    if resource.created_at < endpoint_created_at {
        return Err(corrupt(
            endpoint_id,
            StoredResourceSnapshotError::ResourcePredatesEndpoint,
        ));
    }
    if snapshot.observed_at < resource.created_at {
        return Err(corrupt(
            endpoint_id,
            StoredResourceSnapshotError::SnapshotPredatesResource {
                resource_id: ResourceId::from_uuid(resource.id),
            },
        ));
    }
    let feature = ResourceFeature::from_str(&resource.feature)
        .map_err(StoredResourceSnapshotError::UnknownFeature)
        .map_err(|source| corrupt(endpoint_id, source))?;
    let odata_id = ResourceODataId::parse(&resource.odata_id)
        .map_err(StoredResourceSnapshotError::InvalidODataId)
        .map_err(|source| corrupt(endpoint_id, source))?;
    let payload = ResourceSnapshotPayload::parse(&snapshot.typed_payload_json)
        .map_err(StoredResourceSnapshotError::InvalidPayload)
        .map_err(|source| corrupt(endpoint_id, source))?;
    let mut domain = ResourceSnapshot::new(
        ResourceId::from_uuid(resource.id),
        endpoint_id,
        feature,
        odata_id,
        payload,
        snapshot.observed_at,
        generation,
    );
    if let Some(value) = &snapshot.odata_type {
        domain = domain.with_odata_type(
            ResourceODataType::parse(value)
                .map_err(StoredResourceSnapshotError::InvalidODataType)
                .map_err(|source| corrupt(endpoint_id, source))?,
        );
    }
    if let Some(value) = &snapshot.etag {
        domain = domain.with_etag(
            ResourceEtag::parse(value)
                .map_err(StoredResourceSnapshotError::InvalidEtag)
                .map_err(|source| corrupt(endpoint_id, source))?,
        );
    }
    Ok(domain)
}

fn map_generation(
    endpoint_id: EndpointId,
    value: i64,
) -> Result<RefreshGeneration, ResourceSnapshotRepositoryError> {
    let value = u64::try_from(value).map_err(|_| {
        corrupt(
            endpoint_id,
            StoredResourceSnapshotError::InvalidGenerationValue,
        )
    })?;
    RefreshGeneration::new(value)
        .map_err(StoredResourceSnapshotError::InvalidGeneration)
        .map_err(|source| corrupt(endpoint_id, source))
}

fn validate_loaded_generation(
    endpoint_id: EndpointId,
    snapshots: &[ResourceSnapshot],
) -> Result<(), ResourceSnapshotRepositoryError> {
    let Some(first) = snapshots.first() else {
        return Err(corrupt(
            endpoint_id,
            StoredResourceSnapshotError::EmptyGeneration,
        ));
    };
    let observed_at = first.observed_at();
    let service_roots = snapshots
        .iter()
        .filter(|snapshot| snapshot.feature() == ResourceFeature::ServiceRoot)
        .count();
    if snapshots
        .iter()
        .any(|snapshot| snapshot.observed_at() != observed_at)
    {
        return Err(corrupt(
            endpoint_id,
            StoredResourceSnapshotError::MixedObservationTimes,
        ));
    }
    if service_roots != 1 {
        return Err(corrupt(
            endpoint_id,
            StoredResourceSnapshotError::InvalidServiceRootCount {
                actual: service_roots,
            },
        ));
    }
    Ok(())
}

fn corrupt(
    endpoint_id: EndpointId,
    source: StoredResourceSnapshotError,
) -> ResourceSnapshotRepositoryError {
    ResourceSnapshotRepositoryError::Corrupt {
        endpoint_id,
        source,
    }
}

/// A controlled failure while committing or reading resource Generations.
#[derive(Debug, Error)]
pub enum ResourceSnapshotRepositoryError {
    #[error("resource snapshot write coordination is unavailable")]
    Coordinate(#[source] tokio::sync::AcquireError),
    #[error("endpoint {endpoint_id} resource Generation cannot be empty")]
    EmptyGeneration { endpoint_id: EndpointId },
    #[error("endpoint {endpoint_id} resource Generation repeats {odata_id}")]
    DuplicateODataId {
        endpoint_id: EndpointId,
        odata_id: ResourceODataId,
    },
    #[error("endpoint {endpoint_id} resource Generation has no Service Root")]
    ServiceRootMissing { endpoint_id: EndpointId },
    #[error("endpoint {endpoint_id} resource Generation has multiple Service Roots")]
    MultipleServiceRoots { endpoint_id: EndpointId },
    #[error("endpoint {endpoint_id} was not found")]
    EndpointNotFound { endpoint_id: EndpointId },
    #[error("endpoint {endpoint_id} resource observation predates the endpoint")]
    ObservationPredatesEndpoint { endpoint_id: EndpointId },
    #[error(
        "endpoint {endpoint_id} resource {odata_id} changed feature from {stored} to {observed}"
    )]
    FeatureChanged {
        endpoint_id: EndpointId,
        odata_id: ResourceODataId,
        stored: ResourceFeature,
        observed: ResourceFeature,
    },
    #[error("endpoint {endpoint_id} exhausted resource Generation space")]
    GenerationExhausted { endpoint_id: EndpointId },
    #[error("stored endpoint {endpoint_id} resource Generation is invalid: {source}")]
    Corrupt {
        endpoint_id: EndpointId,
        #[source]
        source: StoredResourceSnapshotError,
    },
    #[error("resource snapshot database operation failed: {0}")]
    Database(#[source] DbErr),
}

/// Why a persisted resource Generation cannot be mapped into product types.
#[derive(Debug, Error)]
pub enum StoredResourceSnapshotError {
    #[error("resource feature is unknown to this product build: {0}")]
    UnknownFeature(#[source] ResourceFeatureParseError),
    #[error("resource @odata.id is invalid: {0}")]
    InvalidODataId(#[source] ResourceODataIdError),
    #[error("resource @odata.type is invalid: {0}")]
    InvalidODataType(#[source] ResourceODataTypeError),
    #[error("resource ETag is invalid: {0}")]
    InvalidEtag(#[source] ResourceEtagError),
    #[error("typed resource payload is invalid: {0}")]
    InvalidPayload(#[source] ResourceSnapshotPayloadError),
    #[error("resource Generation is negative or outside the unsigned range")]
    InvalidGenerationValue,
    #[error("resource Generation is invalid: {0}")]
    InvalidGeneration(#[source] RefreshGenerationError),
    #[error("resource identity predates its endpoint")]
    ResourcePredatesEndpoint,
    #[error("snapshot for resource {resource_id} predates the resource identity")]
    SnapshotPredatesResource { resource_id: ResourceId },
    #[error("snapshot references missing resource {resource_id}")]
    ResourceMissing { resource_id: ResourceId },
    #[error("the selected current Generation contains no snapshots")]
    EmptyGeneration,
    #[error("the selected current Generation has mixed observation times")]
    MixedObservationTimes,
    #[error("the selected current Generation has {actual} Service Roots; expected one")]
    InvalidServiceRootCount { actual: usize },
}

impl From<RefreshGenerationError> for StoredResourceSnapshotError {
    fn from(value: RefreshGenerationError) -> Self {
        Self::InvalidGeneration(value)
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use rutilus_entity::{endpoint, resource, resource_snapshot};
    use sea_orm::{
        ActiveModelTrait, ColumnTrait, EntityTrait, IntoActiveModel, PaginatorTrait, QueryFilter,
        Set,
    };
    use time::{Duration, OffsetDateTime};

    use super::*;

    #[tokio::test]
    async fn commits_generations_and_loads_only_the_latest_complete_view()
    -> Result<(), Box<dyn Error>> {
        let (directory, store, endpoint_id, created_at) = store_with_endpoint().await?;
        assert_eq!(
            store.find_current_resource_generation(endpoint_id).await?,
            Some(Vec::new())
        );
        let first = vec![
            observation(ResourceFeature::Systems, "/redfish/v1/Systems/1", "System")?,
            observation(ResourceFeature::ServiceRoot, "/redfish/v1/", "Root")?
                .with_odata_type(ResourceODataType::parse(
                    "#ServiceRoot.v1_19_0.ServiceRoot",
                )?)
                .with_etag(ResourceEtag::parse("W/\"one\"")?),
        ];
        let first = store
            .commit_resource_generation(endpoint_id, &first, created_at + Duration::SECOND)
            .await?;
        assert!(
            first
                .iter()
                .all(|snapshot| snapshot.generation().get() == 1)
        );
        let system_id = first
            .iter()
            .find(|snapshot| snapshot.feature() == ResourceFeature::Systems)
            .map(ResourceSnapshot::resource_id)
            .ok_or("first system snapshot is missing")?;

        let second = vec![
            observation(
                ResourceFeature::Managers,
                "/redfish/v1/Managers/1",
                "Manager",
            )?,
            observation(ResourceFeature::ServiceRoot, "/redfish/v1/", "Root updated")?,
            observation(
                ResourceFeature::Systems,
                "/redfish/v1/Systems/1",
                "System updated",
            )?,
        ];
        let second = store
            .commit_resource_generation(endpoint_id, &second, created_at + Duration::seconds(2))
            .await?;
        assert!(
            second
                .iter()
                .all(|snapshot| snapshot.generation().get() == 2)
        );
        assert_eq!(
            second
                .iter()
                .find(|snapshot| snapshot.feature() == ResourceFeature::Systems)
                .map(ResourceSnapshot::resource_id),
            Some(system_id)
        );
        assert_eq!(
            store.find_current_resource_generation(endpoint_id).await?,
            Some(second)
        );
        assert!(
            store
                .find_current_resource_generation(EndpointId::generate())
                .await?
                .is_none()
        );

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn rejects_incomplete_or_ambiguous_generations_before_writing()
    -> Result<(), Box<dyn Error>> {
        let (directory, store, endpoint_id, created_at) = store_with_endpoint().await?;
        let root = observation(ResourceFeature::ServiceRoot, "/redfish/v1/", "Root")?;
        let system = observation(ResourceFeature::Systems, "/redfish/v1/Systems/1", "System")?;

        assert!(matches!(
            store
                .commit_resource_generation(endpoint_id, &[], created_at)
                .await,
            Err(ResourceSnapshotRepositoryError::EmptyGeneration { .. })
        ));
        assert!(matches!(
            store
                .commit_resource_generation(endpoint_id, &[system], created_at)
                .await,
            Err(ResourceSnapshotRepositoryError::ServiceRootMissing { .. })
        ));
        assert!(matches!(
            store
                .commit_resource_generation(
                    endpoint_id,
                    &[
                        root.clone(),
                        observation(
                            ResourceFeature::ServiceRoot,
                            "/redfish/v1/alternate",
                            "Other root",
                        )?,
                    ],
                    created_at,
                )
                .await,
            Err(ResourceSnapshotRepositoryError::MultipleServiceRoots { .. })
        ));
        assert!(matches!(
            store
                .commit_resource_generation(endpoint_id, &[root.clone(), root.clone()], created_at)
                .await,
            Err(ResourceSnapshotRepositoryError::DuplicateODataId { .. })
        ));
        assert!(matches!(
            store
                .commit_resource_generation(
                    endpoint_id,
                    std::slice::from_ref(&root),
                    created_at - Duration::SECOND,
                )
                .await,
            Err(ResourceSnapshotRepositoryError::ObservationPredatesEndpoint { .. })
        ));
        assert!(matches!(
            store
                .commit_resource_generation(EndpointId::generate(), &[root], created_at)
                .await,
            Err(ResourceSnapshotRepositoryError::EndpointNotFound { .. })
        ));
        assert_eq!(resource::Entity::find().count(&store.database).await?, 0);
        assert_eq!(
            resource_snapshot::Entity::find()
                .count(&store.database)
                .await?,
            0
        );

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn commits_and_reads_back_processor_and_memory_features() -> Result<(), Box<dyn Error>> {
        let (directory, store, endpoint_id, created_at) = store_with_endpoint().await?;
        let generation = [
            observation(ResourceFeature::ServiceRoot, "/redfish/v1/", "Root")?,
            observation(
                ResourceFeature::Processors,
                "/redfish/v1/Systems/1/Processors/CPU1",
                "Processor One",
            )?
            .with_odata_type(ResourceODataType::parse("#Processor.v1_15_0.Processor")?),
            observation(
                ResourceFeature::Memory,
                "/redfish/v1/Systems/1/Memory/DIMM1",
                "Memory Module One",
            )?,
        ];
        let committed = store
            .commit_resource_generation(endpoint_id, &generation, created_at)
            .await?;
        assert!(
            committed
                .iter()
                .all(|snapshot| snapshot.generation().get() == 1)
        );
        let processor = committed
            .iter()
            .find(|snapshot| snapshot.feature() == ResourceFeature::Processors)
            .ok_or("processor snapshot is missing")?;
        assert_eq!(
            processor.odata_id().as_str(),
            "/redfish/v1/Systems/1/Processors/CPU1"
        );
        assert_eq!(
            processor.odata_type().map(ResourceODataType::as_str),
            Some("#Processor.v1_15_0.Processor")
        );
        assert!(processor.payload().as_str().contains("Processor One"));

        let loaded = store
            .find_current_resource_generation(endpoint_id)
            .await?
            .ok_or("committed generation must load")?;
        assert_eq!(loaded, committed);
        assert_eq!(
            loaded
                .iter()
                .filter(|snapshot| snapshot.feature() == ResourceFeature::Processors)
                .count(),
            1
        );
        assert_eq!(
            loaded
                .iter()
                .filter(|snapshot| snapshot.feature() == ResourceFeature::Memory)
                .count(),
            1
        );
        assert!(loaded.iter().all(|snapshot| matches!(
            snapshot.feature(),
            ResourceFeature::ServiceRoot | ResourceFeature::Processors | ResourceFeature::Memory
        )));

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn feature_change_rejection_rolls_back_the_complete_generation()
    -> Result<(), Box<dyn Error>> {
        let (directory, store, endpoint_id, created_at) = store_with_endpoint().await?;
        let first = [
            observation(ResourceFeature::ServiceRoot, "/redfish/v1/", "Root")?,
            observation(ResourceFeature::Systems, "/redfish/v1/Systems/1", "System")?,
        ];
        store
            .commit_resource_generation(endpoint_id, &first, created_at)
            .await?;
        let invalid = [
            observation(ResourceFeature::Chassis, "/redfish/v1/Chassis/1", "Chassis")?,
            observation(ResourceFeature::ServiceRoot, "/redfish/v1/", "Root")?,
            observation(
                ResourceFeature::Managers,
                "/redfish/v1/Systems/1",
                "Changed",
            )?,
        ];

        assert!(matches!(
            store
                .commit_resource_generation(endpoint_id, &invalid, created_at + Duration::SECOND)
                .await,
            Err(ResourceSnapshotRepositoryError::FeatureChanged {
                stored: ResourceFeature::Systems,
                observed: ResourceFeature::Managers,
                ..
            })
        ));
        assert_eq!(resource::Entity::find().count(&store.database).await?, 2);
        assert_eq!(
            resource_snapshot::Entity::find()
                .count(&store.database)
                .await?,
            2
        );
        let current = store
            .find_current_resource_generation(endpoint_id)
            .await?
            .ok_or("endpoint disappeared")?;
        assert!(
            current
                .iter()
                .all(|snapshot| snapshot.generation().get() == 1)
        );

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn rejects_corrupt_persisted_resource_generations() -> Result<(), Box<dyn Error>> {
        let (directory, store, endpoint_id, created_at) = store_with_endpoint().await?;
        let generation = [
            observation(ResourceFeature::ServiceRoot, "/redfish/v1/", "Root")?,
            observation(ResourceFeature::Systems, "/redfish/v1/Systems/1", "System")?,
        ];
        store
            .commit_resource_generation(endpoint_id, &generation, created_at)
            .await?;
        let system = resource::Entity::find()
            .filter(resource::Column::EndpointId.eq(endpoint_id.into_uuid()))
            .filter(resource::Column::Feature.eq("systems"))
            .one(&store.database)
            .await?
            .ok_or("system resource is missing")?;

        let mut invalid_identity = system.clone().into_active_model();
        invalid_identity.odata_id = Set(String::from(" /redfish/v1/Systems/1"));
        invalid_identity.update(&store.database).await?;
        assert!(matches!(
            store.find_current_resource_generation(endpoint_id).await,
            Err(ResourceSnapshotRepositoryError::Corrupt {
                source: StoredResourceSnapshotError::InvalidODataId(_),
                ..
            })
        ));
        let mut restored_identity = system.clone().into_active_model();
        restored_identity.odata_id = Set(system.odata_id.clone());
        restored_identity.update(&store.database).await?;

        let stored_snapshot = resource_snapshot::Entity::find_by_id((system.id, 1))
            .one(&store.database)
            .await?
            .ok_or("system snapshot is missing")?;
        let mut invalid_payload = stored_snapshot.clone().into_active_model();
        invalid_payload.typed_payload_json = Set(String::from("[]"));
        invalid_payload.update(&store.database).await?;
        assert!(matches!(
            store.find_current_resource_generation(endpoint_id).await,
            Err(ResourceSnapshotRepositoryError::Corrupt {
                source: StoredResourceSnapshotError::InvalidPayload(_),
                ..
            })
        ));
        let mut restored_snapshot = stored_snapshot.clone().into_active_model();
        restored_snapshot.typed_payload_json = Set(stored_snapshot.typed_payload_json.clone());
        restored_snapshot.update(&store.database).await?;

        let mut mixed_time = stored_snapshot.into_active_model();
        mixed_time.observed_at = Set(created_at + Duration::SECOND);
        mixed_time.update(&store.database).await?;
        assert!(matches!(
            store.find_current_resource_generation(endpoint_id).await,
            Err(ResourceSnapshotRepositoryError::Corrupt {
                source: StoredResourceSnapshotError::MixedObservationTimes,
                ..
            })
        ));

        store.close().await?;
        drop(directory);
        Ok(())
    }

    fn observation(
        feature: ResourceFeature,
        odata_id: &str,
        name: &str,
    ) -> Result<NewResourceSnapshot, Box<dyn Error>> {
        Ok(NewResourceSnapshot::new(
            feature,
            ResourceODataId::parse(odata_id)?,
            ResourceSnapshotPayload::parse(&format!(r#"{{"Name":"{name}"}}"#))?,
        ))
    }

    async fn store_with_endpoint()
    -> Result<(tempfile::TempDir, SqliteStore, EndpointId, OffsetDateTime), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let store = SqliteStore::open(directory.path().join("rutilus.db")).await?;
        let endpoint_id = EndpointId::generate();
        let created_at = OffsetDateTime::now_utc();
        endpoint::ActiveModel {
            id: Set(endpoint_id.into_uuid()),
            display_name: Set(String::from("Resource snapshot endpoint")),
            created_at: Set(created_at),
            updated_at: Set(created_at),
        }
        .insert(&store.database)
        .await?;
        Ok((directory, store, endpoint_id, created_at))
    }
}
