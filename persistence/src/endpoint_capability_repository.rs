use std::{collections::BTreeSet, str::FromStr};

use rutilus_domain::{
    CapabilityState, CapabilityStateParseError, EndpointCapability, EndpointCapabilityObservation,
    EndpointCapabilityParseError, EndpointId,
};
use rutilus_entity::{endpoint, endpoint_capability};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DbErr, EntityTrait, QueryFilter, QueryOrder,
    Set, TransactionTrait,
};
use thiserror::Error;
use time::OffsetDateTime;

use crate::SqliteStore;

impl SqliteStore {
    /// Atomically replaces one endpoint's complete capability snapshot.
    ///
    /// Every row receives the same observation time. An empty or internally
    /// duplicated snapshot is rejected before existing observations are
    /// changed.
    ///
    /// # Errors
    ///
    /// Returns [`EndpointCapabilityRepositoryError`] when the endpoint is
    /// absent, the snapshot is empty or duplicated, the observation predates
    /// the endpoint, write coordination fails, or `SQLite` rejects the update.
    pub async fn replace_endpoint_capabilities(
        &self,
        endpoint_id: EndpointId,
        observations: &[EndpointCapabilityObservation],
        observed_at: OffsetDateTime,
    ) -> Result<(), EndpointCapabilityRepositoryError> {
        validate_snapshot(observations)
            .map_err(|source| map_snapshot_error(endpoint_id, source))?;

        let _write_permit = self
            .write_gate
            .acquire()
            .await
            .map_err(EndpointCapabilityRepositoryError::Coordinate)?;
        let transaction = self
            .database
            .begin()
            .await
            .map_err(EndpointCapabilityRepositoryError::Database)?;
        let endpoint_model = endpoint::Entity::find_by_id(endpoint_id.into_uuid())
            .one(&transaction)
            .await
            .map_err(EndpointCapabilityRepositoryError::Database)?
            .ok_or(EndpointCapabilityRepositoryError::EndpointNotFound { endpoint_id })?;
        if observed_at < endpoint_model.created_at {
            return Err(
                EndpointCapabilityRepositoryError::ObservationPredatesEndpoint { endpoint_id },
            );
        }

        endpoint_capability::Entity::delete_many()
            .filter(endpoint_capability::Column::EndpointId.eq(endpoint_id.into_uuid()))
            .exec(&transaction)
            .await
            .map_err(EndpointCapabilityRepositoryError::Database)?;
        insert_capabilities(&transaction, endpoint_id, observations, observed_at)
            .await
            .map_err(EndpointCapabilityRepositoryError::Database)?;
        transaction
            .commit()
            .await
            .map_err(EndpointCapabilityRepositoryError::Database)
    }

    /// Loads one endpoint's capability observations in stable capability-code
    /// order.
    ///
    /// An existing endpoint with no completed probe returns an empty vector;
    /// an absent endpoint returns `None`.
    ///
    /// # Errors
    ///
    /// Returns [`EndpointCapabilityRepositoryError`] when a query fails or a
    /// persisted capability, state, or timestamp violates domain invariants.
    pub async fn find_endpoint_capabilities(
        &self,
        endpoint_id: EndpointId,
    ) -> Result<Option<Vec<StoredEndpointCapability>>, EndpointCapabilityRepositoryError> {
        let transaction = self
            .database
            .begin()
            .await
            .map_err(EndpointCapabilityRepositoryError::Database)?;
        let Some(endpoint_model) = endpoint::Entity::find_by_id(endpoint_id.into_uuid())
            .one(&transaction)
            .await
            .map_err(EndpointCapabilityRepositoryError::Database)?
        else {
            transaction
                .commit()
                .await
                .map_err(EndpointCapabilityRepositoryError::Database)?;
            return Ok(None);
        };
        let models = endpoint_capability::Entity::find()
            .filter(endpoint_capability::Column::EndpointId.eq(endpoint_id.into_uuid()))
            .order_by_asc(endpoint_capability::Column::Capability)
            .all(&transaction)
            .await
            .map_err(EndpointCapabilityRepositoryError::Database)?;
        let capabilities = models
            .into_iter()
            .map(|model| map_stored_capability(endpoint_id, endpoint_model.created_at, &model))
            .collect::<Result<Vec<_>, _>>()?;
        transaction
            .commit()
            .await
            .map_err(EndpointCapabilityRepositoryError::Database)?;
        Ok(Some(capabilities))
    }
}

pub(crate) fn validate_snapshot(
    observations: &[EndpointCapabilityObservation],
) -> Result<(), InvalidCapabilitySnapshot> {
    if observations.is_empty() {
        return Err(InvalidCapabilitySnapshot::Empty);
    }
    let mut capabilities = BTreeSet::new();
    for observation in observations {
        let capability = observation.capability();
        if !capabilities.insert(capability) {
            return Err(InvalidCapabilitySnapshot::Duplicate { capability });
        }
    }
    Ok(())
}

pub(crate) async fn insert_capabilities<C>(
    database: &C,
    endpoint_id: EndpointId,
    observations: &[EndpointCapabilityObservation],
    observed_at: OffsetDateTime,
) -> Result<(), DbErr>
where
    C: ConnectionTrait,
{
    for observation in observations {
        endpoint_capability::ActiveModel {
            endpoint_id: Set(endpoint_id.into_uuid()),
            capability: Set(observation.capability().as_str().to_owned()),
            state: Set(observation.state().as_str().to_owned()),
            observed_at: Set(observed_at),
        }
        .insert(database)
        .await?;
    }
    Ok(())
}

fn map_snapshot_error(
    endpoint_id: EndpointId,
    source: InvalidCapabilitySnapshot,
) -> EndpointCapabilityRepositoryError {
    match source {
        InvalidCapabilitySnapshot::Empty => {
            EndpointCapabilityRepositoryError::EmptySnapshot { endpoint_id }
        }
        InvalidCapabilitySnapshot::Duplicate { capability } => {
            EndpointCapabilityRepositoryError::DuplicateCapability {
                endpoint_id,
                capability,
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InvalidCapabilitySnapshot {
    Empty,
    Duplicate { capability: EndpointCapability },
}

fn map_stored_capability(
    endpoint_id: EndpointId,
    endpoint_created_at: OffsetDateTime,
    model: &endpoint_capability::Model,
) -> Result<StoredEndpointCapability, EndpointCapabilityRepositoryError> {
    let capability = EndpointCapability::from_str(&model.capability)
        .map_err(StoredEndpointCapabilityError::UnknownCapability)
        .map_err(|source| corrupt(endpoint_id, source))?;
    let state = CapabilityState::from_str(&model.state)
        .map_err(StoredEndpointCapabilityError::UnknownState)
        .map_err(|source| corrupt(endpoint_id, source))?;
    if model.observed_at < endpoint_created_at {
        return Err(corrupt(
            endpoint_id,
            StoredEndpointCapabilityError::ObservationPredatesEndpoint { capability },
        ));
    }
    Ok(StoredEndpointCapability {
        observation: EndpointCapabilityObservation::new(capability, state),
        observed_at: model.observed_at,
    })
}

fn corrupt(
    endpoint_id: EndpointId,
    source: StoredEndpointCapabilityError,
) -> EndpointCapabilityRepositoryError {
    EndpointCapabilityRepositoryError::Corrupt {
        endpoint_id,
        source,
    }
}

/// One valid persisted capability state and the time it was observed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StoredEndpointCapability {
    observation: EndpointCapabilityObservation,
    observed_at: OffsetDateTime,
}

impl StoredEndpointCapability {
    #[must_use]
    pub const fn observation(self) -> EndpointCapabilityObservation {
        self.observation
    }

    #[must_use]
    pub const fn observed_at(self) -> OffsetDateTime {
        self.observed_at
    }
}

/// A controlled failure while replacing or reading endpoint capabilities.
#[derive(Debug, Error)]
pub enum EndpointCapabilityRepositoryError {
    #[error("endpoint capability write coordination is unavailable")]
    Coordinate(#[source] tokio::sync::AcquireError),
    #[error("endpoint {endpoint_id} capability snapshot cannot be empty")]
    EmptySnapshot { endpoint_id: EndpointId },
    #[error("endpoint {endpoint_id} capability snapshot repeats {capability}")]
    DuplicateCapability {
        endpoint_id: EndpointId,
        capability: EndpointCapability,
    },
    #[error("endpoint {endpoint_id} was not found")]
    EndpointNotFound { endpoint_id: EndpointId },
    #[error("endpoint {endpoint_id} capability observation predates the endpoint")]
    ObservationPredatesEndpoint { endpoint_id: EndpointId },
    #[error("stored endpoint {endpoint_id} capability is invalid: {source}")]
    Corrupt {
        endpoint_id: EndpointId,
        #[source]
        source: StoredEndpointCapabilityError,
    },
    #[error("endpoint capability database operation failed: {0}")]
    Database(#[source] sea_orm::DbErr),
}

/// Why a persisted endpoint capability cannot be mapped into product types.
#[derive(Debug, Error)]
pub enum StoredEndpointCapabilityError {
    #[error("capability code is unknown to this product build: {0}")]
    UnknownCapability(#[source] EndpointCapabilityParseError),
    #[error("capability state is unknown to this product build: {0}")]
    UnknownState(#[source] CapabilityStateParseError),
    #[error("{capability} observation predates the endpoint")]
    ObservationPredatesEndpoint { capability: EndpointCapability },
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use rutilus_entity::{endpoint, endpoint_capability};
    use sea_orm::{ActiveModelTrait, EntityTrait, Set};
    use time::{Duration, OffsetDateTime};

    use super::*;

    #[tokio::test]
    async fn replaces_and_loads_a_stable_capability_snapshot() -> Result<(), Box<dyn Error>> {
        let (directory, store, endpoint_id, created_at) = store_with_endpoint().await?;
        assert_eq!(
            store.find_endpoint_capabilities(endpoint_id).await?,
            Some(Vec::new())
        );
        let first_observed_at = created_at + Duration::SECOND;
        store
            .replace_endpoint_capabilities(
                endpoint_id,
                &[
                    observation(EndpointCapability::Systems, CapabilityState::Supported),
                    observation(EndpointCapability::Chassis, CapabilityState::Unauthorized),
                ],
                first_observed_at,
            )
            .await?;

        let second_observed_at = first_observed_at + Duration::SECOND;
        store
            .replace_endpoint_capabilities(
                endpoint_id,
                &[
                    observation(EndpointCapability::Systems, CapabilityState::ReadOnly),
                    observation(EndpointCapability::Managers, CapabilityState::NotAdvertised),
                ],
                second_observed_at,
            )
            .await?;

        assert_eq!(
            store.find_endpoint_capabilities(endpoint_id).await?,
            Some(vec![
                stored(
                    EndpointCapability::Managers,
                    CapabilityState::NotAdvertised,
                    second_observed_at,
                ),
                stored(
                    EndpointCapability::Systems,
                    CapabilityState::ReadOnly,
                    second_observed_at,
                ),
            ])
        );
        assert!(
            store
                .find_endpoint_capabilities(EndpointId::generate())
                .await?
                .is_none()
        );

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn rejects_invalid_snapshots_without_replacing_existing_data()
    -> Result<(), Box<dyn Error>> {
        let (directory, store, endpoint_id, created_at) = store_with_endpoint().await?;
        let original = [observation(
            EndpointCapability::Systems,
            CapabilityState::Supported,
        )];
        store
            .replace_endpoint_capabilities(endpoint_id, &original, created_at)
            .await?;

        assert!(matches!(
            store
                .replace_endpoint_capabilities(endpoint_id, &[], created_at)
                .await,
            Err(EndpointCapabilityRepositoryError::EmptySnapshot { .. })
        ));
        assert!(matches!(
            store
                .replace_endpoint_capabilities(endpoint_id, &[original[0], original[0]], created_at)
                .await,
            Err(EndpointCapabilityRepositoryError::DuplicateCapability { .. })
        ));
        assert!(matches!(
            store
                .replace_endpoint_capabilities(
                    endpoint_id,
                    &[observation(
                        EndpointCapability::Managers,
                        CapabilityState::Supported,
                    )],
                    created_at - Duration::SECOND,
                )
                .await,
            Err(EndpointCapabilityRepositoryError::ObservationPredatesEndpoint { .. })
        ));
        assert!(matches!(
            store
                .replace_endpoint_capabilities(EndpointId::generate(), &original, created_at,)
                .await,
            Err(EndpointCapabilityRepositoryError::EndpointNotFound { .. })
        ));
        assert_eq!(
            store.find_endpoint_capabilities(endpoint_id).await?,
            Some(vec![stored(
                EndpointCapability::Systems,
                CapabilityState::Supported,
                created_at,
            )])
        );

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn rejects_corrupt_persisted_capabilities() -> Result<(), Box<dyn Error>> {
        let (directory, store, endpoint_id, created_at) = store_with_endpoint().await?;
        endpoint_capability::ActiveModel {
            endpoint_id: Set(endpoint_id.into_uuid()),
            capability: Set(String::from("unknown-capability")),
            state: Set(String::from("supported")),
            observed_at: Set(created_at),
        }
        .insert(&store.database)
        .await?;

        assert!(matches!(
            store.find_endpoint_capabilities(endpoint_id).await,
            Err(EndpointCapabilityRepositoryError::Corrupt {
                source: StoredEndpointCapabilityError::UnknownCapability(_),
                ..
            })
        ));
        endpoint_capability::Entity::delete_many()
            .exec(&store.database)
            .await?;
        endpoint_capability::ActiveModel {
            endpoint_id: Set(endpoint_id.into_uuid()),
            capability: Set(String::from("systems")),
            state: Set(String::from("supported")),
            observed_at: Set(created_at - Duration::SECOND),
        }
        .insert(&store.database)
        .await?;
        assert!(matches!(
            store.find_endpoint_capabilities(endpoint_id).await,
            Err(EndpointCapabilityRepositoryError::Corrupt {
                source: StoredEndpointCapabilityError::ObservationPredatesEndpoint {
                    capability: EndpointCapability::Systems,
                },
                ..
            })
        ));

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn round_trips_the_complete_capability_snapshot() -> Result<(), Box<dyn Error>> {
        let (directory, store, endpoint_id, created_at) = store_with_endpoint().await?;
        let observed_at = created_at + Duration::SECOND;
        let full = all_capabilities();
        store
            .replace_endpoint_capabilities(endpoint_id, &full, observed_at)
            .await?;

        let stored = store
            .find_endpoint_capabilities(endpoint_id)
            .await?
            .ok_or("stored endpoint capabilities are missing")?;
        assert_eq!(stored.len(), full.len());
        assert!(
            stored
                .iter()
                .all(|capability| capability.observed_at() == observed_at)
        );
        let mut expected = full;
        expected.sort_by_key(|observation| observation.capability().as_str());
        assert_eq!(
            stored
                .iter()
                .map(|capability| capability.observation())
                .collect::<Vec<_>>(),
            expected,
            "every compiled capability must survive the round-trip in stable capability-code order"
        );

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn partial_replacement_drops_every_absent_capability() -> Result<(), Box<dyn Error>> {
        let (directory, store, endpoint_id, created_at) = store_with_endpoint().await?;
        let first_observed_at = created_at + Duration::SECOND;
        let full = all_capabilities();
        store
            .replace_endpoint_capabilities(endpoint_id, &full, first_observed_at)
            .await?;

        // A later, smaller probe must replace the complete snapshot rather than
        // merge with it, so a capability that stopped advertising disappears.
        let second_observed_at = first_observed_at + Duration::SECOND;
        let subset = subset_capabilities();
        store
            .replace_endpoint_capabilities(endpoint_id, &subset, second_observed_at)
            .await?;
        let stored_subset = store
            .find_endpoint_capabilities(endpoint_id)
            .await?
            .ok_or("stored endpoint capabilities are missing")?;
        assert_eq!(stored_subset.len(), subset.len());
        assert!(stored_subset.iter().all(|capability| {
            capability.observed_at() == second_observed_at
                && subset.contains(&capability.observation())
        }));

        // The full surface must be restorable without residue from either
        // earlier snapshot, proving every replace is a fresh generation.
        let third_observed_at = second_observed_at + Duration::SECOND;
        store
            .replace_endpoint_capabilities(endpoint_id, &full, third_observed_at)
            .await?;
        let stored_full = store
            .find_endpoint_capabilities(endpoint_id)
            .await?
            .ok_or("stored endpoint capabilities are missing")?;
        assert_eq!(stored_full.len(), full.len());
        assert!(stored_full.iter().all(|capability| {
            capability.observed_at() == third_observed_at
                && full.contains(&capability.observation())
        }));

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn unknown_capability_code_rejects_the_entire_read_back() -> Result<(), Box<dyn Error>> {
        let (directory, store, endpoint_id, created_at) = store_with_endpoint().await?;
        let observed_at = created_at + Duration::SECOND;
        store
            .replace_endpoint_capabilities(endpoint_id, &all_capabilities(), observed_at)
            .await?;
        endpoint_capability::ActiveModel {
            endpoint_id: Set(endpoint_id.into_uuid()),
            capability: Set(String::from("oem-future-capability")),
            state: Set(String::from("supported")),
            observed_at: Set(observed_at),
        }
        .insert(&store.database)
        .await?;

        // One unknown persisted code fails the complete read: callers must
        // never see a silently truncated capability snapshot.
        assert!(matches!(
            store.find_endpoint_capabilities(endpoint_id).await,
            Err(EndpointCapabilityRepositoryError::Corrupt {
                source: StoredEndpointCapabilityError::UnknownCapability(_),
                ..
            })
        ));

        store.close().await?;
        drop(directory);
        Ok(())
    }

    /// Every `EndpointCapability` variant of the standard-feature inventory
    /// (the 30 §2.1 entries plus the 0.13.0 compile-surface additions `ports`,
    /// `bmc-http`, and `update-service-deprecated`; only `ports` is new in
    /// 0.13.0), each with a deterministic state, so
    /// the round-trip proves both the capability code and the final state
    /// survive persistence.
    ///
    /// The enumeration mirrors the domain's `CAPABILITIES` test constant; when
    /// the compiled ledger grows, both lists must grow together so the
    /// round-trip always covers the complete compiled surface instead of a
    /// hand-picked subset.
    fn all_capabilities() -> Vec<EndpointCapabilityObservation> {
        const CAPABILITIES: [EndpointCapability; 33] = [
            EndpointCapability::Accounts,
            EndpointCapability::Assembly,
            EndpointCapability::Bios,
            EndpointCapability::BootOptions,
            EndpointCapability::Chassis,
            EndpointCapability::Systems,
            EndpointCapability::Controls,
            EndpointCapability::EnvironmentMetrics,
            EndpointCapability::EthernetInterfaces,
            EndpointCapability::EventService,
            EndpointCapability::HostInterfaces,
            EndpointCapability::LogServices,
            EndpointCapability::ManagerNetworkProtocol,
            EndpointCapability::Managers,
            EndpointCapability::Memory,
            EndpointCapability::NetworkAdapters,
            EndpointCapability::NetworkDeviceFunctions,
            EndpointCapability::PcieDevices,
            EndpointCapability::Power,
            EndpointCapability::PowerEquipment,
            EndpointCapability::PowerSupplies,
            EndpointCapability::Processors,
            EndpointCapability::SecureBoot,
            EndpointCapability::Sensors,
            EndpointCapability::SessionService,
            EndpointCapability::Storages,
            EndpointCapability::TaskService,
            EndpointCapability::TelemetryService,
            EndpointCapability::Thermal,
            EndpointCapability::UpdateService,
            EndpointCapability::Ports,
            EndpointCapability::BmcHttp,
            EndpointCapability::UpdateServiceDeprecated,
        ];
        const STATES: [CapabilityState; 7] = [
            CapabilityState::Supported,
            CapabilityState::ReadOnly,
            CapabilityState::Unauthorized,
            CapabilityState::TemporarilyUnavailable,
            CapabilityState::SchemaIncompatible,
            CapabilityState::NotAdvertised,
            CapabilityState::NotCompiled,
        ];
        CAPABILITIES
            .into_iter()
            .enumerate()
            .map(|(index, capability)| {
                EndpointCapabilityObservation::new(capability, STATES[index % STATES.len()])
            })
            .collect()
    }

    /// A smaller snapshot whose capabilities all belong to the full set, so
    /// the partial-replacement assertions prove that a reduced probe removes
    /// every absent capability instead of merging with the previous snapshot.
    fn subset_capabilities() -> Vec<EndpointCapabilityObservation> {
        all_capabilities().into_iter().take(5).collect()
    }

    fn observation(
        capability: EndpointCapability,
        state: CapabilityState,
    ) -> EndpointCapabilityObservation {
        EndpointCapabilityObservation::new(capability, state)
    }

    fn stored(
        capability: EndpointCapability,
        state: CapabilityState,
        observed_at: OffsetDateTime,
    ) -> StoredEndpointCapability {
        StoredEndpointCapability {
            observation: observation(capability, state),
            observed_at,
        }
    }

    async fn store_with_endpoint()
    -> Result<(tempfile::TempDir, SqliteStore, EndpointId, OffsetDateTime), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let store = SqliteStore::open(directory.path().join("rutilus.db")).await?;
        let endpoint_id = EndpointId::generate();
        let created_at = OffsetDateTime::now_utc();
        endpoint::ActiveModel {
            id: Set(endpoint_id.into_uuid()),
            display_name: Set(String::from("Capability test endpoint")),
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
