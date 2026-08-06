use std::error::Error;

use rutilus_domain::{EndpointId, Group, GroupId, GroupName};
use thiserror::Error;
use time::OffsetDateTime;

use crate::{BoundaryFuture, EndpointRefreshRepository};

/// Persists §9.3 `groups` rows and their `group_members` membership.
///
/// The Web and persistence crates both meet at this boundary: the embedding
/// runtime delegates the six methods to the `groups`/`group_members` tables,
/// while the use cases compose them into the §12.1 grouping workflow. Member
/// mutation is deliberately repository-side idempotent: adding an existing
/// member or removing an absent one succeeds, so the Web layer can expose
/// PUT/DELETE semantics without a read-modify-write round trip.
pub trait GroupRepository: Send + Sync {
    type Error: Error + Send + Sync + 'static;

    /// Persists a new group and returns the stored row.
    fn create<'a>(&'a self, group: &'a Group) -> BoundaryFuture<'a, Result<Group, Self::Error>>;

    /// Loads one group, or `None` when no group carries the identity.
    fn find(&self, group_id: GroupId) -> BoundaryFuture<'_, Result<Option<Group>, Self::Error>>;

    /// Loads every group with its current member set.
    fn list(&self) -> BoundaryFuture<'_, Result<Vec<Group>, Self::Error>>;

    /// Adds one endpoint membership, succeeding when it already exists.
    fn add_member(
        &self,
        group_id: GroupId,
        endpoint_id: EndpointId,
    ) -> BoundaryFuture<'_, Result<(), Self::Error>>;

    /// Removes one endpoint membership, succeeding when it is already absent.
    fn remove_member(
        &self,
        group_id: GroupId,
        endpoint_id: EndpointId,
    ) -> BoundaryFuture<'_, Result<(), Self::Error>>;

    /// Deletes a group and all of its memberships.
    fn delete(&self, group_id: GroupId) -> BoundaryFuture<'_, Result<(), Self::Error>>;
}

impl<Repository> GroupRepository for &Repository
where
    Repository: GroupRepository + ?Sized,
{
    type Error = Repository::Error;

    fn create<'a>(&'a self, group: &'a Group) -> BoundaryFuture<'a, Result<Group, Self::Error>> {
        Repository::create(*self, group)
    }

    fn find(&self, group_id: GroupId) -> BoundaryFuture<'_, Result<Option<Group>, Self::Error>> {
        Repository::find(*self, group_id)
    }

    fn list(&self) -> BoundaryFuture<'_, Result<Vec<Group>, Self::Error>> {
        Repository::list(*self)
    }

    fn add_member(
        &self,
        group_id: GroupId,
        endpoint_id: EndpointId,
    ) -> BoundaryFuture<'_, Result<(), Self::Error>> {
        Repository::add_member(*self, group_id, endpoint_id)
    }

    fn remove_member(
        &self,
        group_id: GroupId,
        endpoint_id: EndpointId,
    ) -> BoundaryFuture<'_, Result<(), Self::Error>> {
        Repository::remove_member(*self, group_id, endpoint_id)
    }

    fn delete(&self, group_id: GroupId) -> BoundaryFuture<'_, Result<(), Self::Error>> {
        Repository::delete(*self, group_id)
    }
}

/// Coordinates the §12.1 static grouping workflow: create, list, member
/// mutations, and deletion of §9.3 `groups`.
///
/// `Endpoints` is the existing `EndpointRefreshRepository` boundary; its
/// `find_endpoint` read is the endpoint-existence check that keeps group
/// memberships referentially honest. The use case never touches persistence
/// directly.
pub struct GroupManagement<Groups, Endpoints> {
    groups: Groups,
    endpoints: Endpoints,
}

impl<Groups, Endpoints> GroupManagement<Groups, Endpoints>
where
    Groups: GroupRepository,
    Endpoints: EndpointRefreshRepository,
{
    #[must_use]
    pub const fn new(groups: Groups, endpoints: Endpoints) -> Self {
        Self { groups, endpoints }
    }

    /// Creates a group with an empty member set at the given clock time.
    ///
    /// The duplicate-name check scans the persisted groups first so a
    /// conflicting name surfaces as [`GroupManagementError::NameConflict`]
    /// (HTTP 409) instead of an opaque repository uniqueness failure. `SQLite`
    /// is the single writer (§9.2 write semaphore), so the check is
    /// deterministic within one product process; a concurrent duplicate
    /// would still be refused by the persisted unique constraint.
    ///
    /// # Errors
    ///
    /// Returns [`GroupManagementError::NameConflict`] when the name is taken,
    /// or a repository error when persistence fails.
    pub async fn create(
        &self,
        name: GroupName,
        now: OffsetDateTime,
    ) -> Result<Group, GroupManagementError<Groups::Error, Endpoints::Error>> {
        let existing = self
            .groups
            .list()
            .await
            .map_err(GroupManagementError::GroupRepository)?;
        if existing.iter().any(|group| group.name() == &name) {
            return Err(GroupManagementError::NameConflict { name });
        }
        let group = Group::new(GroupId::generate(), name, now);
        self.groups
            .create(&group)
            .await
            .map_err(GroupManagementError::GroupRepository)
    }

    /// Lists every group in deterministic product order (name, then stable
    /// identity) and rejects an incoherent repository that repeats one.
    ///
    /// # Errors
    ///
    /// Returns [`GroupManagementError::DuplicateGroup`] when the repository
    /// emits the same group twice, or a repository error.
    pub async fn list(
        &self,
    ) -> Result<Vec<Group>, GroupManagementError<Groups::Error, Endpoints::Error>> {
        let mut groups = self
            .groups
            .list()
            .await
            .map_err(GroupManagementError::GroupRepository)?;
        groups.sort_by(|left, right| {
            left.name()
                .as_str()
                .cmp(right.name().as_str())
                .then_with(|| left.id().cmp(&right.id()))
        });
        let mut seen = std::collections::BTreeSet::new();
        for group in &groups {
            if !seen.insert(group.id()) {
                return Err(GroupManagementError::DuplicateGroup {
                    group_id: group.id(),
                });
            }
        }
        Ok(groups)
    }

    /// Loads one group with its current member set.
    ///
    /// # Errors
    ///
    /// Returns [`GroupManagementError::GroupNotFound`] when the identity does
    /// not exist, or a repository error.
    pub async fn find(
        &self,
        group_id: GroupId,
    ) -> Result<Group, GroupManagementError<Groups::Error, Endpoints::Error>> {
        self.groups
            .find(group_id)
            .await
            .map_err(GroupManagementError::GroupRepository)?
            .ok_or(GroupManagementError::GroupNotFound { group_id })
    }

    /// Adds one endpoint membership. Unknown endpoints are rejected so a
    /// membership can never reference a device the product does not manage;
    /// adding an existing member succeeds (idempotent).
    ///
    /// # Errors
    ///
    /// Returns [`GroupManagementError::GroupNotFound`] or
    /// [`GroupManagementError::UnknownEndpoint`] for unknown identities, or a
    /// repository error.
    pub async fn add_member(
        &self,
        group_id: GroupId,
        endpoint_id: EndpointId,
    ) -> Result<(), GroupManagementError<Groups::Error, Endpoints::Error>> {
        self.require_group(group_id).await?;
        self.require_endpoint(endpoint_id).await?;
        self.groups
            .add_member(group_id, endpoint_id)
            .await
            .map_err(GroupManagementError::GroupRepository)
    }

    /// Removes one endpoint membership; removing an absent member succeeds
    /// (idempotent). The endpoint itself is not validated: a deleted endpoint
    /// leaves no membership, so the removal is trivially satisfied and the
    /// product never depends on the endpoint's continued existence to clean
    /// up a membership.
    ///
    /// # Errors
    ///
    /// Returns [`GroupManagementError::GroupNotFound`] for an unknown group,
    /// or a repository error.
    pub async fn remove_member(
        &self,
        group_id: GroupId,
        endpoint_id: EndpointId,
    ) -> Result<(), GroupManagementError<Groups::Error, Endpoints::Error>> {
        self.require_group(group_id).await?;
        self.groups
            .remove_member(group_id, endpoint_id)
            .await
            .map_err(GroupManagementError::GroupRepository)
    }

    /// Deletes a group and all of its memberships.
    ///
    /// # Errors
    ///
    /// Returns [`GroupManagementError::GroupNotFound`] for an unknown group,
    /// or a repository error.
    pub async fn delete(
        &self,
        group_id: GroupId,
    ) -> Result<(), GroupManagementError<Groups::Error, Endpoints::Error>> {
        self.require_group(group_id).await?;
        self.groups
            .delete(group_id)
            .await
            .map_err(GroupManagementError::GroupRepository)
    }

    async fn require_group(
        &self,
        group_id: GroupId,
    ) -> Result<(), GroupManagementError<Groups::Error, Endpoints::Error>> {
        if self
            .groups
            .find(group_id)
            .await
            .map_err(GroupManagementError::GroupRepository)?
            .is_none()
        {
            return Err(GroupManagementError::GroupNotFound { group_id });
        }
        Ok(())
    }

    async fn require_endpoint(
        &self,
        endpoint_id: EndpointId,
    ) -> Result<(), GroupManagementError<Groups::Error, Endpoints::Error>> {
        let exists = self
            .endpoints
            .find_endpoint(endpoint_id)
            .await
            .map_err(GroupManagementError::EndpointRepository)?
            .is_some();
        if exists {
            return Ok(());
        }
        Err(GroupManagementError::UnknownEndpoint { endpoint_id })
    }
}

/// A controlled failure of one §12.1 group workflow step.
#[derive(Debug, Error)]
pub enum GroupManagementError<GroupError, EndpointError>
where
    GroupError: Error + 'static,
    EndpointError: Error + 'static,
{
    #[error("failed to persist the group: {0}")]
    GroupRepository(#[source] GroupError),
    #[error("failed to verify endpoint existence: {0}")]
    EndpointRepository(#[source] EndpointError),
    #[error("a group named `{name}` already exists")]
    NameConflict { name: GroupName },
    #[error("group {group_id} does not exist")]
    GroupNotFound { group_id: GroupId },
    #[error("endpoint {endpoint_id} does not exist")]
    UnknownEndpoint { endpoint_id: EndpointId },
    #[error("group inventory repeats group {group_id}")]
    DuplicateGroup { group_id: GroupId },
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        fmt,
        sync::{Arc, Mutex},
    };

    use rutilus_domain::{
        CredentialId, Endpoint, EndpointAddress, EndpointDisplayName, EndpointId, TlsCertificate,
        TlsTrust,
    };

    use super::*;

    #[tokio::test]
    async fn create_persists_an_empty_group_and_rejects_a_duplicate_name()
    -> Result<(), Box<dyn Error>> {
        let now = OffsetDateTime::from_unix_timestamp(1_800_000_000)?;
        let management = GroupManagement::new(MockGroups::ok(Vec::new()), mock_endpoints()?);

        let name = GroupName::parse("Rack A")?;
        let created = management.create(name.clone(), now).await?;
        assert_eq!(created.name(), &name);
        assert!(created.member_endpoint_ids().is_empty());
        assert_eq!(created.created_at(), now);
        assert_eq!(created.updated_at(), now);

        let conflict = management.create(name, now).await;
        assert!(matches!(
            conflict,
            Err(GroupManagementError::NameConflict { .. })
        ));
        Ok(())
    }

    #[tokio::test]
    async fn list_is_deterministic_and_rejects_duplicate_identity() -> Result<(), Box<dyn Error>> {
        let now = OffsetDateTime::from_unix_timestamp(1_800_000_000)?;
        let first = Group::new(GroupId::generate(), GroupName::parse("Rack B")?, now);
        let second = Group::new(GroupId::generate(), GroupName::parse("Rack A")?, now);
        let management = GroupManagement::new(
            MockGroups::ok(vec![first.clone(), second.clone()]),
            mock_endpoints()?,
        );

        let groups = management.list().await?;
        assert_eq!(groups[0].name().as_str(), "Rack A");
        assert_eq!(groups[1].name().as_str(), "Rack B");

        let repeated = GroupManagement::new(MockGroups::duplicating(first), mock_endpoints()?);
        assert!(matches!(
            repeated.list().await,
            Err(GroupManagementError::DuplicateGroup { .. })
        ));
        Ok(())
    }

    #[tokio::test]
    async fn find_rejects_an_unknown_group() -> Result<(), Box<dyn Error>> {
        let unknown = GroupId::generate();
        let management = GroupManagement::new(MockGroups::ok(Vec::new()), mock_endpoints()?);
        assert!(matches!(
            management.find(unknown).await,
            Err(GroupManagementError::GroupNotFound { group_id })
                if group_id == unknown
        ));
        Ok(())
    }

    #[tokio::test]
    async fn add_member_rejects_unknown_group_and_endpoint_then_succeeds_idempotently()
    -> Result<(), Box<dyn Error>> {
        let now = OffsetDateTime::from_unix_timestamp(1_800_000_000)?;
        let member = endpoint("Rack A", 1)?;
        let groups = MockGroups::ok(Vec::new());
        let management =
            GroupManagement::new(groups.clone(), MockEndpoints::with(vec![member.clone()]));

        let unknown_group = GroupId::generate();
        assert!(matches!(
            management.add_member(unknown_group, member.id()).await,
            Err(GroupManagementError::GroupNotFound { .. })
        ));

        let group = management.create(GroupName::parse("Rack A")?, now).await?;
        let unknown_endpoint = endpoint_id("Rack B", 2)?;
        assert!(matches!(
            management.add_member(group.id(), unknown_endpoint).await,
            Err(GroupManagementError::UnknownEndpoint { endpoint_id })
                if endpoint_id == unknown_endpoint
        ));

        management.add_member(group.id(), member.id()).await?;
        let loaded = management.find(group.id()).await?;
        assert_eq!(loaded.member_endpoint_ids(), &[member.id()]);
        // Adding the same member again is idempotent and stays a single row.
        management.add_member(group.id(), member.id()).await?;
        let loaded = management.find(group.id()).await?;
        assert_eq!(loaded.member_endpoint_ids(), &[member.id()]);
        Ok(())
    }

    #[tokio::test]
    async fn remove_member_is_idempotent_and_delete_removes_everything()
    -> Result<(), Box<dyn Error>> {
        let now = OffsetDateTime::from_unix_timestamp(1_800_000_000)?;
        let member = endpoint("Rack A", 1)?;
        let management = GroupManagement::new(
            MockGroups::ok(Vec::new()),
            MockEndpoints::with(vec![member.clone()]),
        );
        let group = management.create(GroupName::parse("Rack A")?, now).await?;

        management.add_member(group.id(), member.id()).await?;
        management.remove_member(group.id(), member.id()).await?;
        // Removing an absent member is idempotent.
        management.remove_member(group.id(), member.id()).await?;
        let loaded = management.find(group.id()).await?;
        assert!(loaded.member_endpoint_ids().is_empty());

        management.delete(group.id()).await?;
        assert!(matches!(
            management.find(group.id()).await,
            Err(GroupManagementError::GroupNotFound { .. })
        ));
        Ok(())
    }

    #[tokio::test]
    async fn repository_failures_propagate_as_typed_errors() -> Result<(), Box<dyn Error>> {
        let failed = GroupManagement::new(MockGroups::failed(), mock_endpoints()?);
        assert!(matches!(
            failed.list().await,
            Err(GroupManagementError::GroupRepository(MockError))
        ));

        let group = Group::new(
            GroupId::generate(),
            GroupName::parse("Rack A")?,
            OffsetDateTime::now_utc(),
        );
        let failed = GroupManagement::new(MockGroups::with(group.clone()), MockEndpoints::failed());
        assert!(matches!(
            failed
                .add_member(group.id(), endpoint_id("Rack A", 1)?)
                .await,
            Err(GroupManagementError::EndpointRepository(MockError))
        ));
        Ok(())
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct MockError;

    impl fmt::Display for MockError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("mock group persistence failed")
        }
    }

    impl Error for MockError {}

    #[derive(Clone)]
    struct MockGroups {
        state: Arc<Mutex<MockGroupState>>,
    }

    #[derive(Default)]
    struct MockGroupState {
        groups: BTreeMap<GroupId, Group>,
        fail: bool,
        duplicate: bool,
    }

    impl MockGroups {
        fn ok(groups: Vec<Group>) -> Self {
            Self::with_groups(groups, false)
        }

        fn with(group: Group) -> Self {
            Self::ok(vec![group])
        }

        fn failed() -> Self {
            Self::with_groups(Vec::new(), true)
        }

        fn with_groups(groups: Vec<Group>, fail: bool) -> Self {
            Self::with_groups_and_duplicate(groups, fail, false)
        }

        fn duplicating(group: Group) -> Self {
            Self::with_groups_and_duplicate(vec![group], false, true)
        }

        fn with_groups_and_duplicate(groups: Vec<Group>, fail: bool, duplicate: bool) -> Self {
            let state = MockGroupState {
                groups: groups
                    .into_iter()
                    .map(|group| (group.id(), group))
                    .collect(),
                fail,
                duplicate,
            };
            Self {
                state: Arc::new(Mutex::new(state)),
            }
        }

        fn lock(&self) -> Result<std::sync::MutexGuard<'_, MockGroupState>, MockError> {
            self.state.lock().map_err(|_| MockError)
        }
    }

    impl GroupRepository for MockGroups {
        type Error = MockError;

        fn create<'a>(
            &'a self,
            group: &'a Group,
        ) -> BoundaryFuture<'a, Result<Group, Self::Error>> {
            Box::pin(async move {
                let mut state = self.lock()?;
                if state.fail {
                    return Err(MockError);
                }
                state.groups.insert(group.id(), group.clone());
                Ok(group.clone())
            })
        }

        fn find(
            &self,
            group_id: GroupId,
        ) -> BoundaryFuture<'_, Result<Option<Group>, Self::Error>> {
            Box::pin(async move {
                let state = self.lock()?;
                if state.fail {
                    return Err(MockError);
                }
                Ok(state.groups.get(&group_id).cloned())
            })
        }

        fn list(&self) -> BoundaryFuture<'_, Result<Vec<Group>, Self::Error>> {
            Box::pin(async move {
                let state = self.lock()?;
                if state.fail {
                    return Err(MockError);
                }
                let mut groups: Vec<_> = state.groups.values().cloned().collect();
                if state.duplicate {
                    groups.extend(groups.clone());
                }
                Ok(groups)
            })
        }

        fn add_member(
            &self,
            group_id: GroupId,
            endpoint_id: EndpointId,
        ) -> BoundaryFuture<'_, Result<(), Self::Error>> {
            Box::pin(async move {
                let mut state = self.lock()?;
                if state.fail {
                    return Err(MockError);
                }
                let mut group = state.groups.get(&group_id).ok_or(MockError)?.clone();
                let _changed = group.add_member(endpoint_id);
                state.groups.insert(group_id, group);
                Ok(())
            })
        }

        fn remove_member(
            &self,
            group_id: GroupId,
            endpoint_id: EndpointId,
        ) -> BoundaryFuture<'_, Result<(), Self::Error>> {
            Box::pin(async move {
                let mut state = self.lock()?;
                if state.fail {
                    return Err(MockError);
                }
                let mut group = state.groups.get(&group_id).ok_or(MockError)?.clone();
                let _changed = group.remove_member(endpoint_id);
                state.groups.insert(group_id, group);
                Ok(())
            })
        }

        fn delete(&self, group_id: GroupId) -> BoundaryFuture<'_, Result<(), Self::Error>> {
            Box::pin(async move {
                let mut state = self.lock()?;
                if state.fail {
                    return Err(MockError);
                }
                state.groups.remove(&group_id).ok_or(MockError)?;
                Ok(())
            })
        }
    }

    #[derive(Clone)]
    struct MockEndpoints {
        fail: bool,
        endpoints: Vec<Endpoint>,
    }

    impl MockEndpoints {
        fn with(endpoints: Vec<Endpoint>) -> Self {
            Self {
                fail: false,
                endpoints,
            }
        }

        fn failed() -> Self {
            Self {
                fail: true,
                endpoints: Vec::new(),
            }
        }
    }

    impl EndpointRefreshRepository for MockEndpoints {
        type Error = MockError;

        fn find_endpoint(
            &self,
            endpoint_id: EndpointId,
        ) -> BoundaryFuture<'_, Result<Option<Endpoint>, Self::Error>> {
            let endpoints = self.endpoints.clone();
            Box::pin(async move {
                if self.fail {
                    return Err(MockError);
                }
                Ok(endpoints
                    .into_iter()
                    .find(|endpoint| endpoint.id() == endpoint_id))
            })
        }

        fn commit_resource_generation<'a>(
            &'a self,
            _endpoint_id: EndpointId,
            _observations: &'a [crate::ResourceObservation],
            _observed_at: OffsetDateTime,
        ) -> BoundaryFuture<'a, Result<Vec<rutilus_domain::ResourceSnapshot>, Self::Error>>
        {
            Box::pin(async { Ok(Vec::new()) })
        }
    }

    fn mock_endpoints() -> Result<MockEndpoints, Box<dyn Error>> {
        Ok(MockEndpoints::with(vec![endpoint("Rack A", 1)?]))
    }

    fn endpoint_id(name: &str, address_suffix: u8) -> Result<EndpointId, Box<dyn Error>> {
        Ok(endpoint(name, address_suffix)?.id())
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
}
