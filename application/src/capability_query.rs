use std::{collections::BTreeMap, error::Error};

use rutilus_domain::{
    CAPABILITY_LEDGER_ORDER, CapabilityClassification, CapabilityState, EndpointCapability,
    EndpointCapabilityObservation, EndpointId, UiLocation,
};
use thiserror::Error;
use time::OffsetDateTime;

use crate::BoundaryFuture;

/// One persisted observation of an endpoint's capability state.
///
/// The domain observation and its observation time stay paired here so a
/// ledger merge can attach each state to the exact probe that produced it
/// without mixing timestamps across observation Generations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StoredCapability {
    observation: EndpointCapabilityObservation,
    observed_at: OffsetDateTime,
}

impl StoredCapability {
    #[must_use]
    pub const fn new(
        observation: EndpointCapabilityObservation,
        observed_at: OffsetDateTime,
    ) -> Self {
        Self {
            observation,
            observed_at,
        }
    }

    #[must_use]
    pub const fn observation(self) -> EndpointCapabilityObservation {
        self.observation
    }

    #[must_use]
    pub const fn observed_at(self) -> OffsetDateTime {
        self.observed_at
    }
}

/// Loads the capability observations persisted for one endpoint.
///
/// `Ok(None)` means the endpoint is unknown; `Ok(Some(vec![]))` means the
/// endpoint exists but no capability probe has completed yet.
pub trait CapabilityQueryRepository: Send + Sync {
    type Error: Error + Send + Sync + 'static;

    fn find_endpoint_capabilities(
        &self,
        endpoint_id: EndpointId,
    ) -> BoundaryFuture<'_, Result<Option<Vec<StoredCapability>>, Self::Error>>;
}

impl<Repository> CapabilityQueryRepository for &Repository
where
    Repository: CapabilityQueryRepository + ?Sized,
{
    type Error = Repository::Error;

    fn find_endpoint_capabilities(
        &self,
        endpoint_id: EndpointId,
    ) -> BoundaryFuture<'_, Result<Option<Vec<StoredCapability>>, Self::Error>> {
        Repository::find_endpoint_capabilities(*self, endpoint_id)
    }
}

/// One §2.1 capability-ledger entry for an endpoint.
///
/// The metadata is derived from the capability itself, so an entry can never
/// disagree with the domain mapping. A `None` state means the endpoint has no
/// observation for this capability yet — it is not the `NotAdvertised` final
/// state, which requires an explicit probe result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapabilityLedgerEntry {
    capability: EndpointCapability,
    state: Option<CapabilityState>,
    observed_at: Option<OffsetDateTime>,
}

impl CapabilityLedgerEntry {
    fn new(
        capability: EndpointCapability,
        state: Option<CapabilityState>,
        observed_at: Option<OffsetDateTime>,
    ) -> Self {
        Self {
            capability,
            state,
            observed_at,
        }
    }

    #[must_use]
    pub const fn capability(self) -> EndpointCapability {
        self.capability
    }

    #[must_use]
    pub const fn upstream_feature(self) -> &'static str {
        self.capability.upstream_feature()
    }

    #[must_use]
    pub const fn classification(self) -> CapabilityClassification {
        self.capability.classification()
    }

    #[must_use]
    pub const fn ui_location(self) -> UiLocation {
        self.capability.ui_location()
    }

    #[must_use]
    pub const fn state(self) -> Option<CapabilityState> {
        self.state
    }

    #[must_use]
    pub const fn observed_at(self) -> Option<OffsetDateTime> {
        self.observed_at
    }
}

/// Merges one endpoint's persisted capability observations over the complete
/// §2.1 ledger.
pub struct EndpointCapabilityQuery<Repository> {
    repository: Repository,
    endpoint_id: EndpointId,
}

impl<Repository> EndpointCapabilityQuery<Repository>
where
    Repository: CapabilityQueryRepository,
{
    #[must_use]
    pub const fn new(repository: Repository, endpoint_id: EndpointId) -> Self {
        Self {
            repository,
            endpoint_id,
        }
    }

    /// Returns `None` for an unknown endpoint and otherwise merges the stored
    /// observations over [`CAPABILITY_LEDGER_ORDER`], so the result always
    /// contains exactly 47 entries in §2.1 ledger order: the 33 standard
    /// features (the 30 §2.1 entries in design-document order plus the 0.13.0
    /// compile-surface additions `ports`, `bmc-http`, and
    /// `update-service-deprecated`, of which only `ports` is new in 0.13.0)
    /// followed by the 14 OEM features in compiled feature order.
    ///
    /// # Errors
    ///
    /// Returns [`EndpointCapabilityQueryError`] when persistence fails or a
    /// stored observation repeats the same capability.
    pub async fn execute(
        &self,
    ) -> Result<Option<Vec<CapabilityLedgerEntry>>, EndpointCapabilityQueryError<Repository::Error>>
    {
        let Some(stored) = self
            .repository
            .find_endpoint_capabilities(self.endpoint_id)
            .await
            .map_err(EndpointCapabilityQueryError::Repository)?
        else {
            return Ok(None);
        };
        let mut by_capability = BTreeMap::new();
        for capability in stored {
            let observed = capability.observation().capability();
            if by_capability.insert(observed, capability).is_some() {
                return Err(EndpointCapabilityQueryError::DuplicateObservation {
                    endpoint_id: self.endpoint_id,
                    capability: observed,
                });
            }
        }
        Ok(Some(
            CAPABILITY_LEDGER_ORDER
                .into_iter()
                .map(|capability| {
                    let (state, observed_at) = match by_capability.get(&capability) {
                        Some(stored) => (
                            Some(stored.observation().state()),
                            Some(stored.observed_at()),
                        ),
                        None => (None, None),
                    };
                    CapabilityLedgerEntry::new(capability, state, observed_at)
                })
                .collect(),
        ))
    }
}

/// A controlled failure while merging one endpoint's capability ledger.
#[derive(Debug, Error)]
pub enum EndpointCapabilityQueryError<RepositoryError>
where
    RepositoryError: Error + 'static,
{
    #[error("failed to load endpoint capabilities: {0}")]
    Repository(#[source] RepositoryError),
    #[error("endpoint {endpoint_id} repeats the {capability} capability observation")]
    DuplicateObservation {
        endpoint_id: EndpointId,
        capability: EndpointCapability,
    },
}

#[cfg(test)]
mod tests {
    use std::{error::Error, fmt};

    use rutilus_domain::{
        CAPABILITY_LEDGER_ORDER, CapabilityClassification, CapabilityState, EndpointCapability,
        EndpointId, UiLocation,
    };
    use time::OffsetDateTime;

    use super::*;

    const OBSERVED_AT: OffsetDateTime = OffsetDateTime::UNIX_EPOCH;
    const STATES: [CapabilityState; 7] = [
        CapabilityState::Supported,
        CapabilityState::ReadOnly,
        CapabilityState::Unauthorized,
        CapabilityState::TemporarilyUnavailable,
        CapabilityState::SchemaIncompatible,
        CapabilityState::NotAdvertised,
        CapabilityState::NotCompiled,
    ];

    #[tokio::test]
    async fn merges_every_observation_over_the_complete_ledger_in_design_order()
    -> Result<(), Box<dyn Error>> {
        let query = EndpointCapabilityQuery::new(
            MockRepository::Observed(all_observations()),
            EndpointId::generate(),
        );

        let entries = query
            .execute()
            .await?
            .ok_or("endpoint capabilities are missing")?;

        assert_eq!(entries.len(), CAPABILITY_LEDGER_ORDER.len());
        assert!(
            entries
                .iter()
                .zip(CAPABILITY_LEDGER_ORDER)
                .all(|(entry, capability)| entry.capability() == capability),
            "entries must follow the §2.1 ledger order"
        );
        assert!(entries.iter().all(|entry| {
            entry.state().is_some()
                && entry.observed_at() == Some(OBSERVED_AT)
                && entry.upstream_feature() == entry.capability().upstream_feature()
                && entry.classification() == entry.capability().classification()
                && entry.ui_location() == entry.capability().ui_location()
        }));
        Ok(())
    }

    #[tokio::test]
    async fn no_observations_still_produces_forty_seven_unobserved_entries()
    -> Result<(), Box<dyn Error>> {
        let query = EndpointCapabilityQuery::new(
            MockRepository::Observed(Vec::new()),
            EndpointId::generate(),
        );

        let entries = query
            .execute()
            .await?
            .ok_or("endpoint capabilities are missing")?;

        assert_eq!(entries.len(), 47);
        assert!(entries.iter().all(|entry| {
            entry.state().is_none()
                && entry.observed_at().is_none()
                && entry.upstream_feature() == entry.capability().upstream_feature()
                && entry.classification() == entry.capability().classification()
                && entry.ui_location() == entry.capability().ui_location()
        }));
        Ok(())
    }

    #[tokio::test]
    async fn partial_observations_leave_every_other_entry_unobserved() -> Result<(), Box<dyn Error>>
    {
        let observed = [
            EndpointCapability::Managers,
            EndpointCapability::SessionService,
            EndpointCapability::UpdateService,
        ];
        let query = EndpointCapabilityQuery::new(
            MockRepository::Observed(
                observed
                    .iter()
                    .map(|capability| stored(*capability, CapabilityState::Supported))
                    .collect(),
            ),
            EndpointId::generate(),
        );

        let entries = query
            .execute()
            .await?
            .ok_or("endpoint capabilities are missing")?;

        assert_eq!(entries.len(), 47);
        for (entry, capability) in entries.iter().zip(CAPABILITY_LEDGER_ORDER) {
            if observed.contains(&capability) {
                assert_eq!(entry.state(), Some(CapabilityState::Supported));
                assert_eq!(entry.observed_at(), Some(OBSERVED_AT));
            } else {
                assert_eq!(entry.state(), None);
                assert_eq!(entry.observed_at(), None);
            }
        }
        assert_eq!(
            entries
                .iter()
                .find(|entry| entry.capability() == EndpointCapability::SessionService)
                .ok_or("session-service entry is missing")?
                .classification(),
            CapabilityClassification::Infrastructure
        );
        assert_eq!(
            entries
                .iter()
                .find(|entry| entry.capability() == EndpointCapability::SessionService)
                .ok_or("session-service entry is missing")?
                .ui_location(),
            UiLocation::Infrastructure
        );
        Ok(())
    }

    #[tokio::test]
    async fn unknown_endpoint_is_distinguishable_from_no_observations() -> Result<(), Box<dyn Error>>
    {
        let query = EndpointCapabilityQuery::new(MockRepository::Unknown, EndpointId::generate());

        assert!(query.execute().await?.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn rejects_duplicate_observations_and_repository_failures() -> Result<(), Box<dyn Error>>
    {
        let repeated = stored(EndpointCapability::Systems, CapabilityState::Supported);
        let query = EndpointCapabilityQuery::new(
            MockRepository::Observed(vec![repeated, repeated]),
            EndpointId::generate(),
        );
        assert!(matches!(
            query.execute().await,
            Err(EndpointCapabilityQueryError::DuplicateObservation {
                capability: EndpointCapability::Systems,
                ..
            })
        ));

        let failed = EndpointCapabilityQuery::new(MockRepository::Reject, EndpointId::generate());
        assert!(matches!(
            failed.execute().await,
            Err(EndpointCapabilityQueryError::Repository(MockError))
        ));
        Ok(())
    }

    fn all_observations() -> Vec<StoredCapability> {
        CAPABILITY_LEDGER_ORDER
            .into_iter()
            .enumerate()
            .map(|(index, capability)| stored(capability, STATES[index % STATES.len()]))
            .collect()
    }

    fn stored(capability: EndpointCapability, state: CapabilityState) -> StoredCapability {
        StoredCapability::new(
            EndpointCapabilityObservation::new(capability, state),
            OBSERVED_AT,
        )
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct MockError;

    impl fmt::Display for MockError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("mock capability query failure")
        }
    }

    impl Error for MockError {}

    enum MockRepository {
        Observed(Vec<StoredCapability>),
        Unknown,
        Reject,
    }

    impl CapabilityQueryRepository for MockRepository {
        type Error = MockError;

        fn find_endpoint_capabilities(
            &self,
            _endpoint_id: EndpointId,
        ) -> BoundaryFuture<'_, Result<Option<Vec<StoredCapability>>, Self::Error>> {
            Box::pin(async move {
                match self {
                    Self::Observed(stored) => Ok(Some(stored.clone())),
                    Self::Unknown => Ok(None),
                    Self::Reject => Err(MockError),
                }
            })
        }
    }
}
