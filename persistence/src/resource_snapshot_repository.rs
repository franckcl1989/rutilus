use std::{collections::BTreeMap, str::FromStr};

use rutilus_application::{
    ResourceDecodeFailure, ResourceDecodeFailureError, ResourceExtendedInfo,
};
use rutilus_domain::{
    EndpointId, RefreshGeneration, RefreshGenerationError, ResourceEtag, ResourceEtagError,
    ResourceFeature, ResourceFeatureParseError, ResourceId, ResourceODataId, ResourceODataIdError,
    ResourceODataType, ResourceODataTypeError, ResourceSnapshot, ResourceSnapshotPayload,
    ResourceSnapshotPayloadError,
};
use rutilus_entity::{endpoint, resource, resource_decode_failure, resource_snapshot};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DbErr, EntityTrait, JoinType, QueryFilter,
    QueryOrder, QuerySelect, RelationTrait, Set, TransactionTrait,
};
use serde::{Deserialize, Serialize};
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
    /// Atomically appends one complete endpoint refresh Generation, including
    /// the Generation's member decode-failure records (§12.4).
    ///
    /// The Generation is assigned under the store's write gate. Existing
    /// resource identities are reused by exact `@odata.id`; newly observed
    /// identities are created in the same transaction. The decode-failure
    /// records are written in the same transaction, so they are retained or
    /// dropped with the Generation they describe (§9.5): a failed commit
    /// keeps the last complete snapshot — and the last Generation's records —
    /// as one intact whole. Readers see either the preceding complete
    /// Generation or this complete Generation.
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
        decode_failures: &[ResourceDecodeFailure],
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
        for failure in decode_failures {
            insert_decode_failure(&transaction, endpoint_id, generation, failure).await?;
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

    /// Loads one endpoint Generation's member decode-failure records
    /// (§12.4) in stable `@odata.id` order.
    ///
    /// The records are managed exactly like the snapshots: they belong to one
    /// explicit Generation, so the caller passes the Generation whose
    /// snapshots it already loaded. A Generation that recorded no member
    /// decode failures returns an empty vector — a stale record from an older
    /// Generation can never leak into a newer one, because the records are
    /// replaced by Generation, not accumulated.
    ///
    /// # Errors
    ///
    /// Returns [`ResourceSnapshotRepositoryError`] when the query fails or
    /// persisted record data violates the diagnostics contract.
    pub async fn find_current_decode_failures(
        &self,
        endpoint_id: EndpointId,
        generation: RefreshGeneration,
    ) -> Result<Vec<ResourceDecodeFailure>, ResourceSnapshotRepositoryError> {
        let transaction = self
            .database
            .begin()
            .await
            .map_err(ResourceSnapshotRepositoryError::Database)?;
        let rows = resource_decode_failure::Entity::find()
            .filter(resource_decode_failure::Column::EndpointId.eq(endpoint_id.into_uuid()))
            .filter(resource_decode_failure::Column::Generation.eq(generation.get().cast_signed()))
            .order_by_asc(resource_decode_failure::Column::OdataUri)
            .all(&transaction)
            .await
            .map_err(ResourceSnapshotRepositoryError::Database)?;
        let failures = rows
            .iter()
            .map(|row| map_stored_decode_failure(endpoint_id, row))
            .collect::<Result<Vec<_>, _>>()?;
        transaction
            .commit()
            .await
            .map_err(ResourceSnapshotRepositoryError::Database)?;
        Ok(failures)
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

/// Inserts one member decode-failure record of a refresh Generation.
///
/// The record arrives as the validated application record type (its
/// construction is the record layer's `try_new` contract), and the row is
/// keyed by `endpoint_id + generation + odata_uri`, so re-committing a
/// Generation can never duplicate a record.
async fn insert_decode_failure<C>(
    database: &C,
    endpoint_id: EndpointId,
    generation: RefreshGeneration,
    failure: &ResourceDecodeFailure,
) -> Result<(), ResourceSnapshotRepositoryError>
where
    C: ConnectionTrait,
{
    resource_decode_failure::ActiveModel {
        endpoint_id: Set(endpoint_id.into_uuid()),
        generation: Set(generation.get().cast_signed()),
        odata_uri: Set(failure.odata_uri().as_str().to_owned()),
        odata_type: Set(failure.odata_type().map(ToString::to_string)),
        feature: Set(failure.feature().to_string()),
        oem_namespace: Set(failure.oem_namespace().map(str::to_owned)),
        error_summary: Set(failure.error_summary().to_owned()),
        extended_info_json: Set(serialize_extended_info(failure)?),
    }
    .insert(database)
    .await
    .map_err(ResourceSnapshotRepositoryError::Database)?;
    Ok(())
}

/// The stored JSON shape of one `ExtendedInfo` entry, exactly the
/// Redfish-defined fields the diagnostics view displays.
#[derive(Deserialize, Serialize)]
struct StoredExtendedInfo {
    message_id: String,
    message: Option<String>,
    severity: Option<String>,
    resolution: Option<String>,
    related_properties: Vec<String>,
}

/// Serializes one record's `ExtendedInfo` entries into their stored JSON
/// shape.
fn serialize_extended_info(
    failure: &ResourceDecodeFailure,
) -> Result<String, ResourceSnapshotRepositoryError> {
    let entries = failure
        .extended_info()
        .iter()
        .map(|entry| StoredExtendedInfo {
            message_id: entry.message_id().to_owned(),
            message: entry.message().map(str::to_owned),
            severity: entry.severity().map(str::to_owned),
            resolution: entry.resolution().map(str::to_owned),
            related_properties: entry.related_properties().to_vec(),
        })
        .collect::<Vec<_>>();
    serde_json::to_string(&entries).map_err(|source| {
        ResourceSnapshotRepositoryError::Database(DbErr::Json(source.to_string()))
    })
}

/// Maps one stored decode-failure row back into the validated application
/// record type.
///
/// The record-layer construction is re-run on read, so a store that does not
/// round-trip the diagnostics contract surfaces as an internal fault instead
/// of being silently trusted.
fn map_stored_decode_failure(
    endpoint_id: EndpointId,
    row: &resource_decode_failure::Model,
) -> Result<ResourceDecodeFailure, ResourceSnapshotRepositoryError> {
    let feature = ResourceFeature::from_str(&row.feature)
        .map_err(StoredResourceDecodeFailureError::UnknownFeature)
        .map_err(|source| corrupt_decode_failures(endpoint_id, source))?;
    let odata_uri = ResourceODataId::parse(&row.odata_uri)
        .map_err(StoredResourceDecodeFailureError::InvalidODataUri)
        .map_err(|source| corrupt_decode_failures(endpoint_id, source))?;
    let odata_type = row
        .odata_type
        .as_deref()
        .map(ResourceODataType::parse)
        .transpose()
        .map_err(StoredResourceDecodeFailureError::InvalidODataType)
        .map_err(|source| corrupt_decode_failures(endpoint_id, source))?;
    let extended_info = serde_json::from_str::<Vec<StoredExtendedInfo>>(&row.extended_info_json)
        .map_err(StoredResourceDecodeFailureError::InvalidExtendedInfo)
        .map_err(|source| corrupt_decode_failures(endpoint_id, source))?
        .into_iter()
        .map(|entry| {
            ResourceExtendedInfo::new(
                entry.message_id,
                entry.message,
                entry.severity,
                entry.resolution,
                entry.related_properties,
            )
        })
        .collect();
    ResourceDecodeFailure::try_new(
        odata_uri,
        odata_type,
        feature,
        row.oem_namespace.clone(),
        row.error_summary.clone(),
        extended_info,
    )
    .map_err(StoredResourceDecodeFailureError::InvalidDecodeFailure)
    .map_err(|source| corrupt_decode_failures(endpoint_id, source))
}

fn corrupt_decode_failures(
    endpoint_id: EndpointId,
    source: StoredResourceDecodeFailureError,
) -> ResourceSnapshotRepositoryError {
    ResourceSnapshotRepositoryError::CorruptDecodeFailures {
        endpoint_id,
        source,
    }
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
    #[error("stored endpoint {endpoint_id} member decode-failure records are invalid: {source}")]
    CorruptDecodeFailures {
        endpoint_id: EndpointId,
        #[source]
        source: StoredResourceDecodeFailureError,
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

/// Why one persisted member decode-failure record cannot be mapped into the
/// diagnostics record type.
#[derive(Debug, Error)]
pub enum StoredResourceDecodeFailureError {
    #[error("decode-failure feature is unknown to this product build: {0}")]
    UnknownFeature(#[source] ResourceFeatureParseError),
    #[error("decode-failure @odata.id is invalid: {0}")]
    InvalidODataUri(#[source] ResourceODataIdError),
    #[error("decode-failure @odata.type is invalid: {0}")]
    InvalidODataType(#[source] ResourceODataTypeError),
    #[error("decode-failure ExtendedInfo is not valid JSON: {0}")]
    InvalidExtendedInfo(#[source] serde_json::Error),
    #[error("decode-failure record violates the diagnostics contract: {0}")]
    InvalidDecodeFailure(#[source] ResourceDecodeFailureError),
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use rutilus_entity::{endpoint, resource, resource_decode_failure, resource_snapshot};
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
            .commit_resource_generation(endpoint_id, &first, &[], created_at + Duration::SECOND)
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
            .commit_resource_generation(
                endpoint_id,
                &second,
                &[],
                created_at + Duration::seconds(2),
            )
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
                .commit_resource_generation(endpoint_id, &[], &[], created_at)
                .await,
            Err(ResourceSnapshotRepositoryError::EmptyGeneration { .. })
        ));
        assert!(matches!(
            store
                .commit_resource_generation(endpoint_id, &[system], &[], created_at)
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
                    &[],
                    created_at,
                )
                .await,
            Err(ResourceSnapshotRepositoryError::MultipleServiceRoots { .. })
        ));
        assert!(matches!(
            store
                .commit_resource_generation(
                    endpoint_id,
                    &[root.clone(), root.clone()],
                    &[],
                    created_at
                )
                .await,
            Err(ResourceSnapshotRepositoryError::DuplicateODataId { .. })
        ));
        assert!(matches!(
            store
                .commit_resource_generation(
                    endpoint_id,
                    std::slice::from_ref(&root),
                    &[],
                    created_at - Duration::SECOND,
                )
                .await,
            Err(ResourceSnapshotRepositoryError::ObservationPredatesEndpoint { .. })
        ));
        assert!(matches!(
            store
                .commit_resource_generation(EndpointId::generate(), &[root], &[], created_at)
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
            .commit_resource_generation(endpoint_id, &generation, &[], created_at)
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
    async fn commits_and_reads_back_storage_network_and_ethernet_features()
    -> Result<(), Box<dyn Error>> {
        let (directory, store, endpoint_id, created_at) = store_with_endpoint().await?;
        let generation = [
            observation(ResourceFeature::ServiceRoot, "/redfish/v1/", "Root")?,
            observation(
                ResourceFeature::Storages,
                "/redfish/v1/Systems/1/Storage/SATA-1",
                "Storage Subsystem One",
            )?
            .with_odata_type(ResourceODataType::parse("#Storage.v1_21_0.Storage")?),
            observation(
                ResourceFeature::NetworkAdapters,
                "/redfish/v1/Chassis/1/NetworkAdapters/1",
                "Network Adapter One",
            )?,
            observation(
                ResourceFeature::EthernetInterfaces,
                "/redfish/v1/Managers/1/EthernetInterfaces/1",
                "Ethernet Interface One",
            )?
            .with_etag(ResourceEtag::parse("W/\"eth-1\"")?),
        ];
        let committed = store
            .commit_resource_generation(endpoint_id, &generation, &[], created_at)
            .await?;
        assert!(
            committed
                .iter()
                .all(|snapshot| snapshot.generation().get() == 1)
        );
        let storage = committed
            .iter()
            .find(|snapshot| snapshot.feature() == ResourceFeature::Storages)
            .ok_or("storage snapshot is missing")?;
        assert_eq!(
            storage.odata_id().as_str(),
            "/redfish/v1/Systems/1/Storage/SATA-1"
        );
        assert_eq!(
            storage.odata_type().map(ResourceODataType::as_str),
            Some("#Storage.v1_21_0.Storage")
        );
        assert!(storage.payload().as_str().contains("Storage Subsystem One"));

        let loaded = store
            .find_current_resource_generation(endpoint_id)
            .await?
            .ok_or("committed generation must load")?;
        assert_eq!(loaded, committed);
        assert_eq!(
            loaded
                .iter()
                .filter(|snapshot| snapshot.feature() == ResourceFeature::Storages)
                .count(),
            1
        );
        assert_eq!(
            loaded
                .iter()
                .filter(|snapshot| snapshot.feature() == ResourceFeature::NetworkAdapters)
                .count(),
            1
        );
        assert_eq!(
            loaded
                .iter()
                .filter(|snapshot| snapshot.feature() == ResourceFeature::EthernetInterfaces)
                .count(),
            1
        );
        assert!(loaded.iter().all(|snapshot| matches!(
            snapshot.feature(),
            ResourceFeature::ServiceRoot
                | ResourceFeature::Storages
                | ResourceFeature::NetworkAdapters
                | ResourceFeature::EthernetInterfaces
        )));

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn commits_and_reads_back_accounts_bios_boot_options_and_secure_boot_features()
    -> Result<(), Box<dyn Error>> {
        let (directory, store, endpoint_id, created_at) = store_with_endpoint().await?;
        let generation = [
            observation(ResourceFeature::ServiceRoot, "/redfish/v1/", "Root")?,
            observation(
                ResourceFeature::Accounts,
                "/redfish/v1/AccountService/Accounts/admin",
                "Administrator Account",
            )?
            .with_odata_type(ResourceODataType::parse(
                "#ManagerAccount.v1_14_1.ManagerAccount",
            )?)
            .with_etag(ResourceEtag::parse("W/\"account-1\"")?),
            observation(
                ResourceFeature::Bios,
                "/redfish/v1/Systems/1/Bios",
                "BIOS Configuration",
            )?,
            observation(
                ResourceFeature::BootOptions,
                "/redfish/v1/Systems/1/BootOptions/PXE-1",
                "Network Boot Option",
            )?,
            observation(
                ResourceFeature::SecureBoot,
                "/redfish/v1/Systems/1/SecureBoot",
                "Secure Boot",
            )?
            .with_odata_type(ResourceODataType::parse("#SecureBoot.v1_1_2.SecureBoot")?),
        ];
        let committed = store
            .commit_resource_generation(endpoint_id, &generation, &[], created_at)
            .await?;
        assert!(
            committed
                .iter()
                .all(|snapshot| snapshot.generation().get() == 1)
        );
        let account = committed
            .iter()
            .find(|snapshot| snapshot.feature() == ResourceFeature::Accounts)
            .ok_or("account snapshot is missing")?;
        assert_eq!(
            account.odata_id().as_str(),
            "/redfish/v1/AccountService/Accounts/admin"
        );
        assert_eq!(
            account.odata_type().map(ResourceODataType::as_str),
            Some("#ManagerAccount.v1_14_1.ManagerAccount")
        );
        assert!(account.payload().as_str().contains("Administrator Account"));

        let loaded = store
            .find_current_resource_generation(endpoint_id)
            .await?
            .ok_or("committed generation must load")?;
        assert_eq!(loaded, committed);
        for (feature, expected) in [
            (ResourceFeature::Accounts, 1),
            (ResourceFeature::Bios, 1),
            (ResourceFeature::BootOptions, 1),
            (ResourceFeature::SecureBoot, 1),
        ] {
            assert_eq!(
                loaded
                    .iter()
                    .filter(|snapshot| snapshot.feature() == feature)
                    .count(),
                expected,
                "feature {feature} must round-trip exactly once"
            );
        }
        assert!(loaded.iter().all(|snapshot| matches!(
            snapshot.feature(),
            ResourceFeature::ServiceRoot
                | ResourceFeature::Accounts
                | ResourceFeature::Bios
                | ResourceFeature::BootOptions
                | ResourceFeature::SecureBoot
        )));

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn commits_and_reads_back_power_thermal_sensors_and_controls_features()
    -> Result<(), Box<dyn Error>> {
        let (directory, store, endpoint_id, created_at) = store_with_endpoint().await?;
        let generation = [
            observation(ResourceFeature::ServiceRoot, "/redfish/v1/", "Root")?,
            observation(
                ResourceFeature::Power,
                "/redfish/v1/Chassis/1/Power",
                "Power",
            )?
            .with_odata_type(ResourceODataType::parse("#Power.v1_17_0.Power")?),
            observation(
                ResourceFeature::Thermal,
                "/redfish/v1/Chassis/1/Thermal",
                "Thermal",
            )?,
            observation(
                ResourceFeature::Sensors,
                "/redfish/v1/Chassis/1/Sensors/InletTemp",
                "Chassis Inlet Temperature",
            )?,
            observation(
                ResourceFeature::Controls,
                "/redfish/v1/Chassis/1/Controls/FanDuty",
                "Chassis Fan Duty",
            )?
            .with_etag(ResourceEtag::parse("W/\"control-fan-1\"")?),
        ];
        let committed = store
            .commit_resource_generation(endpoint_id, &generation, &[], created_at)
            .await?;
        assert!(
            committed
                .iter()
                .all(|snapshot| snapshot.generation().get() == 1)
        );
        let power = committed
            .iter()
            .find(|snapshot| snapshot.feature() == ResourceFeature::Power)
            .ok_or("power snapshot is missing")?;
        assert_eq!(power.odata_id().as_str(), "/redfish/v1/Chassis/1/Power");
        assert_eq!(
            power.odata_type().map(ResourceODataType::as_str),
            Some("#Power.v1_17_0.Power")
        );
        assert!(power.payload().as_str().contains("Power"));

        let loaded = store
            .find_current_resource_generation(endpoint_id)
            .await?
            .ok_or("committed generation must load")?;
        assert_eq!(loaded, committed);
        for (feature, expected) in [
            (ResourceFeature::Power, 1),
            (ResourceFeature::Thermal, 1),
            (ResourceFeature::Sensors, 1),
            (ResourceFeature::Controls, 1),
        ] {
            assert_eq!(
                loaded
                    .iter()
                    .filter(|snapshot| snapshot.feature() == feature)
                    .count(),
                expected,
                "feature {feature} must round-trip exactly once"
            );
        }
        assert!(loaded.iter().all(|snapshot| matches!(
            snapshot.feature(),
            ResourceFeature::ServiceRoot
                | ResourceFeature::Power
                | ResourceFeature::Thermal
                | ResourceFeature::Sensors
                | ResourceFeature::Controls
        )));

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn commits_and_reads_back_log_services_manager_network_protocol_and_host_interfaces_features()
    -> Result<(), Box<dyn Error>> {
        let (directory, store, endpoint_id, created_at) = store_with_endpoint().await?;
        let generation = [
            observation(ResourceFeature::ServiceRoot, "/redfish/v1/", "Root")?,
            observation(
                ResourceFeature::LogServices,
                "/redfish/v1/Managers/1/LogServices/1",
                "BMC Event Log",
            )?
            .with_odata_type(ResourceODataType::parse("#LogService.v1_9_0.LogService")?),
            observation(
                ResourceFeature::ManagerNetworkProtocol,
                "/redfish/v1/Managers/1/NetworkProtocol",
                "Manager Network Protocol",
            )?,
            observation(
                ResourceFeature::HostInterfaces,
                "/redfish/v1/Managers/1/HostInterfaces/1",
                "Host Interface One",
            )?
            .with_etag(ResourceEtag::parse("W/\"host-interface-1\"")?),
        ];
        let committed = store
            .commit_resource_generation(endpoint_id, &generation, &[], created_at)
            .await?;
        assert!(
            committed
                .iter()
                .all(|snapshot| snapshot.generation().get() == 1)
        );
        let log_service = committed
            .iter()
            .find(|snapshot| snapshot.feature() == ResourceFeature::LogServices)
            .ok_or("log service snapshot is missing")?;
        assert_eq!(
            log_service.odata_id().as_str(),
            "/redfish/v1/Managers/1/LogServices/1"
        );
        assert_eq!(
            log_service.odata_type().map(ResourceODataType::as_str),
            Some("#LogService.v1_9_0.LogService")
        );
        assert!(log_service.payload().as_str().contains("BMC Event Log"));

        let loaded = store
            .find_current_resource_generation(endpoint_id)
            .await?
            .ok_or("committed generation must load")?;
        assert_eq!(loaded, committed);
        for (feature, expected) in [
            (ResourceFeature::LogServices, 1),
            (ResourceFeature::ManagerNetworkProtocol, 1),
            (ResourceFeature::HostInterfaces, 1),
        ] {
            assert_eq!(
                loaded
                    .iter()
                    .filter(|snapshot| snapshot.feature() == feature)
                    .count(),
                expected,
                "feature {feature} must round-trip exactly once"
            );
        }
        assert!(loaded.iter().all(|snapshot| matches!(
            snapshot.feature(),
            ResourceFeature::ServiceRoot
                | ResourceFeature::LogServices
                | ResourceFeature::ManagerNetworkProtocol
                | ResourceFeature::HostInterfaces
        )));

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn commits_and_reads_back_pcie_devices_assembly_and_software_inventory_features()
    -> Result<(), Box<dyn Error>> {
        let (directory, store, endpoint_id, created_at) = store_with_endpoint().await?;
        let generation = [
            observation(ResourceFeature::ServiceRoot, "/redfish/v1/", "Root")?,
            observation(
                ResourceFeature::PcieDevices,
                "/redfish/v1/Systems/1/PCIeDevices/GPU1",
                "PCIe Device One",
            )?
            .with_odata_type(ResourceODataType::parse("#PCIeDevice.v1_12_0.PCIeDevice")?),
            observation(
                ResourceFeature::Assembly,
                "/redfish/v1/Chassis/1/Assembly#/Assemblies/0",
                "Fan Assembly",
            )?
            .with_etag(ResourceEtag::parse("W/\"assembly-data-0\"")?),
            observation(
                ResourceFeature::SoftwareInventory,
                "/redfish/v1/UpdateService/SoftwareInventory/BIOS",
                "System BIOS",
            )?,
        ];
        let committed = store
            .commit_resource_generation(endpoint_id, &generation, &[], created_at)
            .await?;
        assert!(
            committed
                .iter()
                .all(|snapshot| snapshot.generation().get() == 1)
        );
        let pcie_device = committed
            .iter()
            .find(|snapshot| snapshot.feature() == ResourceFeature::PcieDevices)
            .ok_or("pcie device snapshot is missing")?;
        assert_eq!(
            pcie_device.odata_id().as_str(),
            "/redfish/v1/Systems/1/PCIeDevices/GPU1"
        );
        assert_eq!(
            pcie_device.odata_type().map(ResourceODataType::as_str),
            Some("#PCIeDevice.v1_12_0.PCIeDevice")
        );

        let loaded = store
            .find_current_resource_generation(endpoint_id)
            .await?
            .ok_or("committed generation must load")?;
        assert_eq!(loaded, committed);
        for (feature, expected) in [
            (ResourceFeature::PcieDevices, 1),
            (ResourceFeature::Assembly, 1),
            (ResourceFeature::SoftwareInventory, 1),
        ] {
            assert_eq!(
                loaded
                    .iter()
                    .filter(|snapshot| snapshot.feature() == feature)
                    .count(),
                expected,
                "feature {feature} must round-trip exactly once"
            );
        }
        assert!(loaded.iter().all(|snapshot| matches!(
            snapshot.feature(),
            ResourceFeature::ServiceRoot
                | ResourceFeature::PcieDevices
                | ResourceFeature::Assembly
                | ResourceFeature::SoftwareInventory
        )));

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    // The seven service families must round-trip inside one committed
    // Generation so the count and full-equality assertions prove the complete
    // family set; splitting them would duplicate the store setup and fragment
    // the round-trip proof. The domain crate allows the same on its long
    // round-trip tests.
    #[allow(clippy::too_many_lines)]
    async fn commits_and_reads_back_event_telemetry_and_task_features() -> Result<(), Box<dyn Error>>
    {
        let (directory, store, endpoint_id, created_at) = store_with_endpoint().await?;
        let generation = [
            observation(ResourceFeature::ServiceRoot, "/redfish/v1/", "Root")?,
            observation(
                ResourceFeature::EventService,
                "/redfish/v1/EventService",
                "Event Service",
            )?
            .with_odata_type(ResourceODataType::parse(
                "#EventService.v1_12_0.EventService",
            )?),
            observation(
                ResourceFeature::EventSubscription,
                "/redfish/v1/EventService/Subscriptions/1",
                "Subscription One",
            )?
            .with_etag(ResourceEtag::parse("W/\"subscription-1\"")?),
            observation(
                ResourceFeature::TelemetryService,
                "/redfish/v1/TelemetryService",
                "Telemetry Service",
            )?,
            observation(
                ResourceFeature::MetricDefinition,
                "/redfish/v1/TelemetryService/MetricDefinitions/1",
                "Inlet Temperature Definition",
            )?,
            observation(
                ResourceFeature::MetricReport,
                "/redfish/v1/TelemetryService/MetricReports/1",
                "Inlet Temperature Report",
            )?
            .with_etag(ResourceEtag::parse("W/\"report-1\"")?),
            observation(
                ResourceFeature::TaskService,
                "/redfish/v1/TaskService",
                "Task Service",
            )?,
            observation(
                ResourceFeature::Task,
                "/redfish/v1/TaskService/Tasks/1",
                "Firmware Update Task",
            )?
            .with_odata_type(ResourceODataType::parse("#Task.v1_7_4.Task")?),
        ];
        let committed = store
            .commit_resource_generation(endpoint_id, &generation, &[], created_at)
            .await?;
        assert!(
            committed
                .iter()
                .all(|snapshot| snapshot.generation().get() == 1)
        );
        let event_service = committed
            .iter()
            .find(|snapshot| snapshot.feature() == ResourceFeature::EventService)
            .ok_or("event service snapshot is missing")?;
        assert_eq!(
            event_service.odata_id().as_str(),
            "/redfish/v1/EventService"
        );
        assert_eq!(
            event_service.odata_type().map(ResourceODataType::as_str),
            Some("#EventService.v1_12_0.EventService")
        );
        assert!(event_service.payload().as_str().contains("Event Service"));

        let loaded = store
            .find_current_resource_generation(endpoint_id)
            .await?
            .ok_or("committed generation must load")?;
        assert_eq!(loaded, committed);
        for (feature, expected) in [
            (ResourceFeature::EventService, 1),
            (ResourceFeature::EventSubscription, 1),
            (ResourceFeature::TelemetryService, 1),
            (ResourceFeature::MetricDefinition, 1),
            (ResourceFeature::MetricReport, 1),
            (ResourceFeature::TaskService, 1),
            (ResourceFeature::Task, 1),
        ] {
            assert_eq!(
                loaded
                    .iter()
                    .filter(|snapshot| snapshot.feature() == feature)
                    .count(),
                expected,
                "feature {feature} must round-trip exactly once"
            );
        }
        assert!(loaded.iter().all(|snapshot| matches!(
            snapshot.feature(),
            ResourceFeature::ServiceRoot
                | ResourceFeature::EventService
                | ResourceFeature::EventSubscription
                | ResourceFeature::TelemetryService
                | ResourceFeature::MetricDefinition
                | ResourceFeature::MetricReport
                | ResourceFeature::TaskService
                | ResourceFeature::Task
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
            .commit_resource_generation(endpoint_id, &first, &[], created_at)
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
                .commit_resource_generation(
                    endpoint_id,
                    &invalid,
                    &[],
                    created_at + Duration::SECOND
                )
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
            .commit_resource_generation(endpoint_id, &generation, &[], created_at)
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

    #[tokio::test]
    async fn commits_decode_failures_with_the_generation_and_reads_them_back()
    -> Result<(), Box<dyn Error>> {
        let (directory, store, endpoint_id, created_at) = store_with_endpoint().await?;
        let generation = vec![
            observation(ResourceFeature::Systems, "/redfish/v1/Systems/1", "System")?,
            observation(ResourceFeature::ServiceRoot, "/redfish/v1", "Root")?,
        ];
        let decode_failures = vec![decode_failure(
            "/redfish/v1/Systems/2",
            Some("#ComputerSystem.v1_20_0.ComputerSystem"),
            ResourceFeature::Systems,
            Some("Vendor"),
            "schema decode failed: missing required field",
            Some("Base.1.13.ResourceNotFound"),
        )?];
        store
            .commit_resource_generation(
                endpoint_id,
                &generation,
                &decode_failures,
                created_at + Duration::SECOND,
            )
            .await?;

        let generation = RefreshGeneration::new(1)?;
        let loaded = store
            .find_current_decode_failures(endpoint_id, generation)
            .await?;
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].odata_uri().as_str(), "/redfish/v1/Systems/2");
        assert_eq!(
            loaded[0].odata_type().map(ResourceODataType::as_str),
            Some("#ComputerSystem.v1_20_0.ComputerSystem")
        );
        assert_eq!(loaded[0].feature(), ResourceFeature::Systems);
        assert_eq!(loaded[0].oem_namespace(), Some("Vendor"));
        assert_eq!(
            loaded[0].error_summary(),
            "schema decode failed: missing required field"
        );
        let entries = loaded[0].extended_info();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].message_id(), "Base.1.13.ResourceNotFound");
        assert_eq!(
            entries[0].message(),
            Some("The requested resource could not be found.")
        );
        assert_eq!(entries[0].severity(), Some("Critical"));
        assert_eq!(
            entries[0].resolution(),
            Some("Remove and re-add the resource.")
        );
        assert_eq!(entries[0].related_properties(), &["MemberId".to_owned()]);

        // A Generation that recorded no failures reads back empty.
        assert!(
            store
                .find_current_decode_failures(endpoint_id, RefreshGeneration::new(2)?)
                .await?
                .is_empty()
        );
        // An endpoint without a completed refresh reads back empty.
        assert!(
            store
                .find_current_decode_failures(EndpointId::generate(), generation)
                .await?
                .is_empty()
        );

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn decode_failures_are_retained_per_generation_and_replaced_by_the_latest()
    -> Result<(), Box<dyn Error>> {
        let (directory, store, endpoint_id, created_at) = store_with_endpoint().await?;
        let first = vec![
            observation(ResourceFeature::Systems, "/redfish/v1/Systems/1", "System")?,
            observation(ResourceFeature::ServiceRoot, "/redfish/v1", "Root")?,
        ];
        store
            .commit_resource_generation(
                endpoint_id,
                &first,
                &[decode_failure(
                    "/redfish/v1/Systems/2",
                    None,
                    ResourceFeature::Systems,
                    None,
                    "first generation failure",
                    None,
                )?],
                created_at + Duration::SECOND,
            )
            .await?;
        store
            .commit_resource_generation(
                endpoint_id,
                &first,
                &[decode_failure(
                    "/redfish/v1/Managers/9",
                    None,
                    ResourceFeature::Managers,
                    None,
                    "second generation failure",
                    None,
                )?],
                created_at + Duration::seconds(2),
            )
            .await?;

        // The records are managed like the snapshots: each Generation keeps
        // its own rows, and a caller reads exactly the Generation it loaded.
        let second = store
            .find_current_decode_failures(endpoint_id, RefreshGeneration::new(2)?)
            .await?;
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].odata_uri().as_str(), "/redfish/v1/Managers/9");
        assert_eq!(second[0].error_summary(), "second generation failure");
        let first = store
            .find_current_decode_failures(endpoint_id, RefreshGeneration::new(1)?)
            .await?;
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].odata_uri().as_str(), "/redfish/v1/Systems/2");
        assert_eq!(first[0].error_summary(), "first generation failure");

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn failed_generation_commit_drops_its_decode_failures_with_it()
    -> Result<(), Box<dyn Error>> {
        let (directory, store, endpoint_id, created_at) = store_with_endpoint().await?;
        let first = vec![
            observation(ResourceFeature::Systems, "/redfish/v1/Systems/1", "System")?,
            observation(ResourceFeature::ServiceRoot, "/redfish/v1", "Root")?,
        ];
        store
            .commit_resource_generation(
                endpoint_id,
                &first,
                &[decode_failure(
                    "/redfish/v1/Systems/2",
                    None,
                    ResourceFeature::Systems,
                    None,
                    "committed generation failure",
                    None,
                )?],
                created_at + Duration::SECOND,
            )
            .await?;

        // A feature-changed second Generation rolls back as one atomic
        // transaction: neither its snapshots nor its decode-failure records
        // can leak into the store (§9.5).
        let invalid = vec![
            observation(
                ResourceFeature::Managers,
                "/redfish/v1/Systems/1",
                "Changed",
            )?,
            observation(ResourceFeature::ServiceRoot, "/redfish/v1", "Root")?,
        ];
        assert!(matches!(
            store
                .commit_resource_generation(
                    endpoint_id,
                    &invalid,
                    &[decode_failure(
                        "/redfish/v1/Managers/9",
                        None,
                        ResourceFeature::Managers,
                        None,
                        "rolled back generation failure",
                        None,
                    )?],
                    created_at + Duration::seconds(2),
                )
                .await,
            Err(ResourceSnapshotRepositoryError::FeatureChanged { .. })
        ));

        let second = store
            .find_current_decode_failures(endpoint_id, RefreshGeneration::new(2)?)
            .await?;
        assert!(
            second.is_empty(),
            "a rolled-back Generation must never leave its records behind"
        );
        let first = store
            .find_current_decode_failures(endpoint_id, RefreshGeneration::new(1)?)
            .await?;
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].error_summary(), "committed generation failure");

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn corrupt_stored_decode_failure_is_an_internal_fault() -> Result<(), Box<dyn Error>> {
        let (directory, store, endpoint_id, created_at) = store_with_endpoint().await?;
        let generation = vec![
            observation(ResourceFeature::Systems, "/redfish/v1/Systems/1", "System")?,
            observation(ResourceFeature::ServiceRoot, "/redfish/v1", "Root")?,
        ];
        store
            .commit_resource_generation(
                endpoint_id,
                &generation,
                &[decode_failure(
                    "/redfish/v1/Systems/2",
                    None,
                    ResourceFeature::Systems,
                    None,
                    "corruptible failure",
                    None,
                )?],
                created_at + Duration::SECOND,
            )
            .await?;

        // A stored record that no longer round-trips the diagnostics
        // contract surfaces as an internal fault instead of a fabricated
        // record: first an `ExtendedInfo` column that is not valid JSON,
        // then an empty error summary the record construction refuses.
        let stored = resource_decode_failure::Entity::find()
            .one(&store.database)
            .await?
            .ok_or("stored decode failure is missing")?;
        let mut invalid_json = stored.clone().into_active_model();
        invalid_json.extended_info_json = Set(String::from("not json"));
        invalid_json.update(&store.database).await?;
        assert!(matches!(
            store
                .find_current_decode_failures(endpoint_id, RefreshGeneration::new(1)?)
                .await,
            Err(ResourceSnapshotRepositoryError::CorruptDecodeFailures {
                source: StoredResourceDecodeFailureError::InvalidExtendedInfo(_),
                ..
            })
        ));
        let mut restored_json = stored.clone().into_active_model();
        restored_json.extended_info_json = Set(stored.extended_info_json.clone());
        restored_json.update(&store.database).await?;

        let mut invalid_summary = stored.into_active_model();
        invalid_summary.error_summary = Set(String::new());
        invalid_summary.update(&store.database).await?;
        assert!(matches!(
            store
                .find_current_decode_failures(endpoint_id, RefreshGeneration::new(1)?)
                .await,
            Err(ResourceSnapshotRepositoryError::CorruptDecodeFailures {
                source: StoredResourceDecodeFailureError::InvalidDecodeFailure(
                    ResourceDecodeFailureError::EmptyErrorSummary
                ),
                ..
            })
        ));

        store.close().await?;
        drop(directory);
        Ok(())
    }

    fn decode_failure(
        odata_uri: &str,
        odata_type: Option<&str>,
        feature: ResourceFeature,
        oem_namespace: Option<&str>,
        error_summary: &str,
        message_id: Option<&str>,
    ) -> Result<ResourceDecodeFailure, Box<dyn Error>> {
        let extended_info = match message_id {
            Some(message_id) => vec![ResourceExtendedInfo::new(
                message_id.to_owned(),
                Some("The requested resource could not be found.".to_owned()),
                Some("Critical".to_owned()),
                Some("Remove and re-add the resource.".to_owned()),
                vec!["MemberId".to_owned()],
            )],
            None => Vec::new(),
        };
        Ok(ResourceDecodeFailure::try_new(
            ResourceODataId::parse(odata_uri)?,
            odata_type.map(ResourceODataType::parse).transpose()?,
            feature,
            oem_namespace.map(str::to_owned),
            error_summary.to_owned(),
            extended_info,
        )?)
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
            site_id: Set(None),
            refresh_generation: Set(0),
            health: Set(String::from("unknown")),
        }
        .insert(&store.database)
        .await?;
        Ok((directory, store, endpoint_id, created_at))
    }
}
