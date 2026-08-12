use std::error::Error;

use rutilus_domain::{EndpointId, Tag, TagId, TagName};
use thiserror::Error;

use crate::{
    BoundaryFuture, EndpointInventoryQuery, EndpointInventoryQueryError,
    EndpointInventoryRepository, EndpointRefreshRepository,
};

/// Persists §9.3 `tags` rows: one tag name bound to one managed endpoint.
///
/// The Web and persistence crates both meet at this boundary; the embedding
/// runtime delegates the four methods to the `tags` table, while the use
/// cases compose them into the §14.2 tag filter workflow. Assignment and
/// removal are deliberately repository-side idempotent: re-assigning an
/// existing binding or removing an absent one succeeds, so the Web layer can
/// expose PUT/DELETE semantics without a read-modify-write round trip.
pub trait TagRepository: Send + Sync {
    type Error: Error + Send + Sync + 'static;

    /// Persists a tag binding, returning the stored row; re-assigning the
    /// same name to the same endpoint returns the existing binding.
    fn assign<'a>(&'a self, tag: &'a Tag) -> BoundaryFuture<'a, Result<Tag, Self::Error>>;

    /// Removes one tag binding, succeeding when it is already absent.
    fn remove<'a>(
        &'a self,
        endpoint_id: EndpointId,
        tag_name: &'a TagName,
    ) -> BoundaryFuture<'a, Result<(), Self::Error>>;

    /// Loads every tag bound to one endpoint.
    fn list_for_endpoint(
        &self,
        endpoint_id: EndpointId,
    ) -> BoundaryFuture<'_, Result<Vec<Tag>, Self::Error>>;

    /// Loads every endpoint binding that carries one tag name.
    fn list_by_tag<'a>(
        &'a self,
        tag_name: &'a TagName,
    ) -> BoundaryFuture<'a, Result<Vec<Tag>, Self::Error>>;
}

impl<Repository> TagRepository for &Repository
where
    Repository: TagRepository + ?Sized,
{
    type Error = Repository::Error;

    fn assign<'a>(&'a self, tag: &'a Tag) -> BoundaryFuture<'a, Result<Tag, Self::Error>> {
        Repository::assign(*self, tag)
    }

    fn remove<'a>(
        &'a self,
        endpoint_id: EndpointId,
        tag_name: &'a TagName,
    ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
        Repository::remove(*self, endpoint_id, tag_name)
    }

    fn list_for_endpoint(
        &self,
        endpoint_id: EndpointId,
    ) -> BoundaryFuture<'_, Result<Vec<Tag>, Self::Error>> {
        Repository::list_for_endpoint(*self, endpoint_id)
    }

    fn list_by_tag<'a>(
        &'a self,
        tag_name: &'a TagName,
    ) -> BoundaryFuture<'a, Result<Vec<Tag>, Self::Error>> {
        Repository::list_by_tag(*self, tag_name)
    }
}

/// Coordinates the §14.2 tag workflow: assign, remove, per-endpoint listing,
/// and the complete cross-endpoint union that feeds the homepage tag filter.
///
/// `Endpoints` reuses the existing `EndpointRefreshRepository` boundary for
/// the endpoint-existence check on the write and observation paths (assign
/// must never bind a tag to an unmanaged endpoint, and an unknown endpoint
/// has no observable tag state for listing) and the `EndpointInventoryRepository`
/// boundary to enumerate the managed endpoints for the union listing — the
/// same boundaries the Web product-services bundle already injects. Removal
/// deliberately skips the existence check (see [`Self::remove`]) so a deleted
/// endpoint's residual bindings stay cleanable. The use case never touches
/// persistence directly.
pub struct TagManagement<Tags, Endpoints> {
    tags: Tags,
    endpoints: Endpoints,
}

impl<Tags, Endpoints> TagManagement<Tags, Endpoints>
where
    Tags: TagRepository,
    Endpoints: EndpointRefreshRepository + EndpointInventoryRepository,
{
    #[must_use]
    pub const fn new(tags: Tags, endpoints: Endpoints) -> Self {
        Self { tags, endpoints }
    }

    /// Binds one tag name to one managed endpoint. Re-assigning an existing
    /// binding succeeds and returns the stored row (idempotent), so the
    /// console can submit an assignment without first checking the current
    /// tag set.
    ///
    /// # Errors
    ///
    /// Returns [`TagManagementError::UnknownEndpoint`] when the endpoint does
    /// not exist, or a repository error when persistence fails.
    pub async fn assign(
        &self,
        endpoint_id: EndpointId,
        name: TagName,
    ) -> Result<
        Tag,
        TagManagementError<
            <Tags as TagRepository>::Error,
            <Endpoints as EndpointRefreshRepository>::Error,
            <Endpoints as EndpointInventoryRepository>::Error,
        >,
    > {
        self.require_endpoint(endpoint_id).await?;
        let tag = Tag::new(TagId::generate(), endpoint_id, name);
        self.tags
            .assign(&tag)
            .await
            .map_err(TagManagementError::TagRepository)
    }

    /// Removes one tag binding; removing an absent binding succeeds
    /// (idempotent), so the console can submit a removal without first
    /// checking the current tag set.
    ///
    /// The endpoint itself is not validated, mirroring the group member
    /// removal decision: removal is a convergent cleanup that must not depend
    /// on the endpoint's continued existence. A deleted endpoint leaves
    /// orphan bindings behind (they never appear in the `list_all` union,
    /// which enumerates the managed endpoints), and refusing to remove them
    /// would make the residue — and the shared tag-name row — unreachable
    /// forever. The store's removal converges on "not bound" from every
    /// input state, so a cleanup after endpoint deletion is trivially
    /// satisfied.
    ///
    /// # Errors
    ///
    /// Returns a repository error when persistence fails.
    pub async fn remove(
        &self,
        endpoint_id: EndpointId,
        name: &TagName,
    ) -> Result<
        (),
        TagManagementError<
            <Tags as TagRepository>::Error,
            <Endpoints as EndpointRefreshRepository>::Error,
            <Endpoints as EndpointInventoryRepository>::Error,
        >,
    > {
        self.tags
            .remove(endpoint_id, name)
            .await
            .map_err(TagManagementError::TagRepository)
    }

    /// Loads one endpoint's tags in deterministic product order (name, then
    /// stable identity).
    ///
    /// # Errors
    ///
    /// Returns [`TagManagementError::UnknownEndpoint`] when the endpoint does
    /// not exist, or a repository error.
    pub async fn list_for_endpoint(
        &self,
        endpoint_id: EndpointId,
    ) -> Result<
        Vec<Tag>,
        TagManagementError<
            <Tags as TagRepository>::Error,
            <Endpoints as EndpointRefreshRepository>::Error,
            <Endpoints as EndpointInventoryRepository>::Error,
        >,
    > {
        self.require_endpoint(endpoint_id).await?;
        let mut tags = self
            .tags
            .list_for_endpoint(endpoint_id)
            .await
            .map_err(TagManagementError::TagRepository)?;
        sort_tags(&mut tags);
        Ok(tags)
    }

    /// Loads every tag across every managed endpoint — the complete §14.2
    /// tag-filter union, deduplicated by binding (endpoint plus tag name) and
    /// ordered by name, endpoint, and identity.
    ///
    /// The endpoint enumeration reuses `EndpointInventoryQuery`, whose
    /// duplicate-endpoint rejection keeps the union well-defined; the tag
    /// repository is then read per endpoint, so a repository that repeats a
    /// binding is refused instead of silently collapsed.
    ///
    /// # Errors
    ///
    /// Returns a repository error, or a duplicate-identity error when the
    /// inventory or a per-endpoint tag list repeats an identity.
    pub async fn list_all(
        &self,
    ) -> Result<
        Vec<Tag>,
        TagManagementError<
            <Tags as TagRepository>::Error,
            <Endpoints as EndpointRefreshRepository>::Error,
            <Endpoints as EndpointInventoryRepository>::Error,
        >,
    > {
        let inventory = match EndpointInventoryQuery::new(&self.endpoints).execute().await {
            Ok(inventory) => inventory,
            Err(EndpointInventoryQueryError::Repository(error)) => {
                return Err(TagManagementError::InventoryRepository(error));
            }
            Err(EndpointInventoryQueryError::DuplicateEndpoint { endpoint_id }) => {
                return Err(TagManagementError::DuplicateEndpoint { endpoint_id });
            }
        };
        let mut tags = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        for item in &inventory {
            for tag in self
                .tags
                .list_for_endpoint(item.endpoint().id())
                .await
                .map_err(TagManagementError::TagRepository)?
            {
                // The tag identity names the tag-name row, which two endpoints
                // carrying the same name share (tag.rs module doc), so the
                // binding — not the name row — is the deduplication unit.
                if !seen.insert((tag.endpoint_id(), tag.id())) {
                    return Err(TagManagementError::DuplicateTag { tag_id: tag.id() });
                }
                tags.push(tag);
            }
        }
        sort_tags(&mut tags);
        Ok(tags)
    }

    async fn require_endpoint(
        &self,
        endpoint_id: EndpointId,
    ) -> Result<
        (),
        TagManagementError<
            <Tags as TagRepository>::Error,
            <Endpoints as EndpointRefreshRepository>::Error,
            <Endpoints as EndpointInventoryRepository>::Error,
        >,
    > {
        let exists = self
            .endpoints
            .find_endpoint(endpoint_id)
            .await
            .map_err(TagManagementError::EndpointRepository)?
            .is_some();
        if exists {
            return Ok(());
        }
        Err(TagManagementError::UnknownEndpoint { endpoint_id })
    }
}

fn sort_tags(tags: &mut [Tag]) {
    tags.sort_by(|left, right| {
        left.name()
            .as_str()
            .cmp(right.name().as_str())
            .then_with(|| left.endpoint_id().cmp(&right.endpoint_id()))
            .then_with(|| left.id().cmp(&right.id()))
    });
}

/// A controlled failure of one §14.2 tag workflow step.
#[derive(Debug, Error)]
pub enum TagManagementError<TagError, EndpointError, InventoryError>
where
    TagError: Error + 'static,
    EndpointError: Error + 'static,
    InventoryError: Error + 'static,
{
    #[error("failed to persist the tag: {0}")]
    TagRepository(#[source] TagError),
    #[error("failed to verify endpoint existence: {0}")]
    EndpointRepository(#[source] EndpointError),
    #[error("failed to enumerate the managed endpoints: {0}")]
    InventoryRepository(#[source] InventoryError),
    #[error("endpoint {endpoint_id} does not exist")]
    UnknownEndpoint { endpoint_id: EndpointId },
    #[error("tag inventory repeats binding for tag {tag_id}")]
    DuplicateTag { tag_id: TagId },
    #[error("endpoint inventory repeats endpoint {endpoint_id}")]
    DuplicateEndpoint { endpoint_id: EndpointId },
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
    use time::OffsetDateTime;

    use super::*;
    use crate::EndpointInventoryItem;

    #[tokio::test]
    async fn assign_binds_one_tag_and_rejects_unknown_endpoints() -> Result<(), Box<dyn Error>> {
        let member = endpoint("Rack A", 1)?;
        let management =
            TagManagement::new(MockTags::ok(), MockEndpoints::with(vec![member.clone()]));

        let unknown = endpoint_id("Rack B", 2)?;
        assert!(matches!(
            management.assign(unknown, TagName::parse("production")?).await,
            Err(TagManagementError::UnknownEndpoint { endpoint_id })
                if endpoint_id == unknown
        ));

        let name = TagName::parse("production")?;
        let assigned = management.assign(member.id(), name.clone()).await?;
        assert_eq!(assigned.endpoint_id(), member.id());
        assert_eq!(assigned.name(), &name);

        // Re-assigning the same name to the same endpoint is idempotent.
        let again = management.assign(member.id(), name).await?;
        assert_eq!(again.id(), assigned.id());
        assert_eq!(management.list_for_endpoint(member.id()).await?.len(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn removal_is_idempotent_and_listing_is_endpoint_aware() -> Result<(), Box<dyn Error>> {
        let member = endpoint("Rack A", 1)?;
        let management =
            TagManagement::new(MockTags::ok(), MockEndpoints::with(vec![member.clone()]));

        let unknown = endpoint_id("Rack B", 2)?;
        // Removal never depends on the endpoint's continued existence: an
        // endpoint outside the managed set is a deleted endpoint whose
        // residual bindings must stay cleanable.
        management
            .remove(unknown, &TagName::parse("production")?)
            .await?;
        assert!(matches!(
            management.list_for_endpoint(unknown).await,
            Err(TagManagementError::UnknownEndpoint { endpoint_id })
                if endpoint_id == unknown
        ));

        management
            .assign(member.id(), TagName::parse("zeta")?)
            .await?;
        management
            .assign(member.id(), TagName::parse("alpha")?)
            .await?;
        let tags = management.list_for_endpoint(member.id()).await?;
        assert_eq!(tags[0].name().as_str(), "alpha");
        assert_eq!(tags[1].name().as_str(), "zeta");

        management
            .remove(member.id(), &TagName::parse("alpha")?)
            .await?;
        // Removing an absent binding is idempotent.
        management
            .remove(member.id(), &TagName::parse("alpha")?)
            .await?;
        let tags = management.list_for_endpoint(member.id()).await?;
        assert_eq!(tags.len(), 1);
        assert_eq!(tags[0].name().as_str(), "zeta");
        Ok(())
    }

    #[tokio::test]
    async fn deleted_endpoint_bindings_remain_removable() -> Result<(), Box<dyn Error>> {
        let member = endpoint("Rack A", 1)?;
        let tags = MockTags::ok();
        let management =
            TagManagement::new(tags.clone(), MockEndpoints::with(vec![member.clone()]));
        management
            .assign(member.id(), TagName::parse("production")?)
            .await?;

        // The endpoint is deleted: it leaves the managed set, its bindings
        // disappear from the §14.2 union, and the cleanup path must still
        // converge over the same tag store.
        let deleted = TagManagement::new(tags.clone(), MockEndpoints::with(Vec::new()));
        assert!(deleted.list_all().await?.is_empty());
        deleted
            .remove(member.id(), &TagName::parse("production")?)
            .await?;
        // Removing again, after the binding is gone, stays idempotent.
        deleted
            .remove(member.id(), &TagName::parse("production")?)
            .await?;
        assert!(
            management.list_for_endpoint(member.id()).await?.is_empty(),
            "the residual binding must be gone from the shared store"
        );
        Ok(())
    }

    #[tokio::test]
    async fn list_all_unions_every_endpoint_in_deterministic_order() -> Result<(), Box<dyn Error>> {
        let first = endpoint("Rack A", 1)?;
        let second = endpoint("Rack B", 2)?;
        let management = TagManagement::new(
            MockTags::ok(),
            MockEndpoints::with(vec![first.clone(), second.clone()]),
        );

        management
            .assign(first.id(), TagName::parse("production")?)
            .await?;
        management
            .assign(second.id(), TagName::parse("production")?)
            .await?;
        management
            .assign(second.id(), TagName::parse("lab")?)
            .await?;

        let all = management.list_all().await?;
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].name().as_str(), "lab");
        assert_eq!(all[0].endpoint_id(), second.id());
        assert_eq!(all[1].name().as_str(), "production");
        assert_eq!(all[1].endpoint_id(), first.id());
        assert_eq!(all[2].name().as_str(), "production");
        assert_eq!(all[2].endpoint_id(), second.id());
        Ok(())
    }

    #[tokio::test]
    async fn incoherent_inventories_are_refused() -> Result<(), Box<dyn Error>> {
        let known = endpoint("Rack A", 1)?;
        let duplicate = known.clone();
        let management = TagManagement::new(
            MockTags::ok(),
            MockEndpoints::with(vec![known.clone(), duplicate]),
        );
        assert!(matches!(
            management.list_all().await,
            Err(TagManagementError::DuplicateEndpoint { .. })
        ));

        let tag = Tag::new(TagId::generate(), known.id(), TagName::parse("duplicate")?);
        let management =
            TagManagement::new(MockTags::duplicating(tag), MockEndpoints::with(vec![known]));
        assert!(matches!(
            management.list_all().await,
            Err(TagManagementError::DuplicateTag { .. })
        ));
        Ok(())
    }

    #[tokio::test]
    async fn repository_failures_propagate_as_typed_errors() -> Result<(), Box<dyn Error>> {
        let member = endpoint("Rack A", 1)?;
        let failed = TagManagement::new(
            MockTags::failed(),
            MockEndpoints::with(vec![member.clone()]),
        );
        assert!(matches!(
            failed.list_for_endpoint(member.id()).await,
            Err(TagManagementError::TagRepository(MockError))
        ));

        let failed = TagManagement::new(MockTags::ok(), MockEndpoints::failed());
        assert!(matches!(
            failed
                .assign(member.id(), TagName::parse("production")?)
                .await,
            Err(TagManagementError::EndpointRepository(MockError))
        ));
        Ok(())
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct MockError;

    impl fmt::Display for MockError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("mock tag persistence failed")
        }
    }

    impl Error for MockError {}

    #[derive(Clone)]
    struct MockTags {
        state: Arc<Mutex<MockTagState>>,
    }

    #[derive(Default)]
    struct MockTagState {
        tags: BTreeMap<(EndpointId, String), Tag>,
        fail: bool,
        duplicate: bool,
    }

    impl MockTags {
        fn ok() -> Self {
            Self::with(Vec::new())
        }

        fn with(tags: Vec<Tag>) -> Self {
            let state = MockTagState {
                tags: tags
                    .into_iter()
                    .map(|tag| ((tag.endpoint_id(), tag.name().as_str().to_owned()), tag))
                    .collect(),
                fail: false,
                duplicate: false,
            };
            Self {
                state: Arc::new(Mutex::new(state)),
            }
        }

        fn duplicating(tag: Tag) -> Self {
            let state = MockTagState {
                tags: [((tag.endpoint_id(), tag.name().as_str().to_owned()), tag)]
                    .into_iter()
                    .collect(),
                fail: false,
                duplicate: true,
            };
            Self {
                state: Arc::new(Mutex::new(state)),
            }
        }

        fn failed() -> Self {
            let state = MockTagState {
                tags: BTreeMap::new(),
                fail: true,
                duplicate: false,
            };
            Self {
                state: Arc::new(Mutex::new(state)),
            }
        }

        fn lock(&self) -> Result<std::sync::MutexGuard<'_, MockTagState>, MockError> {
            self.state.lock().map_err(|_| MockError)
        }
    }

    impl TagRepository for MockTags {
        type Error = MockError;

        fn assign<'a>(&'a self, tag: &'a Tag) -> BoundaryFuture<'a, Result<Tag, Self::Error>> {
            let key = (tag.endpoint_id(), tag.name().as_str().to_owned());
            Box::pin(async move {
                let mut state = self.lock()?;
                if state.fail {
                    return Err(MockError);
                }
                Ok(state.tags.entry(key).or_insert_with(|| tag.clone()).clone())
            })
        }

        fn remove<'a>(
            &'a self,
            endpoint_id: EndpointId,
            tag_name: &'a TagName,
        ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
            let key = (endpoint_id, tag_name.as_str().to_owned());
            Box::pin(async move {
                let mut state = self.lock()?;
                if state.fail {
                    return Err(MockError);
                }
                state.tags.remove(&key);
                Ok(())
            })
        }

        fn list_for_endpoint(
            &self,
            endpoint_id: EndpointId,
        ) -> BoundaryFuture<'_, Result<Vec<Tag>, Self::Error>> {
            Box::pin(async move {
                let state = self.lock()?;
                if state.fail {
                    return Err(MockError);
                }
                let mut tags: Vec<_> = state
                    .tags
                    .iter()
                    .filter(|((bound_endpoint, _), _)| *bound_endpoint == endpoint_id)
                    .map(|(_, tag)| tag.clone())
                    .collect();
                if state.duplicate {
                    tags.extend(tags.clone());
                }
                Ok(tags)
            })
        }

        fn list_by_tag<'a>(
            &'a self,
            tag_name: &'a TagName,
        ) -> BoundaryFuture<'a, Result<Vec<Tag>, Self::Error>> {
            let key = tag_name.as_str().to_owned();
            Box::pin(async move {
                let state = self.lock()?;
                if state.fail {
                    return Err(MockError);
                }
                Ok(state
                    .tags
                    .iter()
                    .filter(|((_, name), _)| name.as_str() == key)
                    .map(|(_, tag)| tag.clone())
                    .collect())
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
            _decode_failures: &'a [crate::ResourceDecodeFailure],
            _observed_at: OffsetDateTime,
        ) -> BoundaryFuture<'a, Result<Vec<rutilus_domain::ResourceSnapshot>, Self::Error>>
        {
            Box::pin(async { Ok(Vec::new()) })
        }
    }

    impl EndpointInventoryRepository for MockEndpoints {
        type Error = MockError;

        fn list_endpoint_inventory(
            &self,
        ) -> BoundaryFuture<'_, Result<Vec<EndpointInventoryItem>, Self::Error>> {
            let endpoints = self.endpoints.clone();
            Box::pin(async move {
                if self.fail {
                    return Err(MockError);
                }
                endpoints
                    .into_iter()
                    .map(|endpoint| EndpointInventoryItem::try_new(endpoint, Vec::new()))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|_| MockError)
            })
        }
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
