use std::error::Error;

use rutilus_domain::{
    EndpointId, RefreshGeneration, ResourceEtag, ResourceFeature, ResourceId, ResourceODataId,
    ResourceODataType, ResourceSnapshot,
};
use thiserror::Error;

use crate::{EndpointInventoryQuery, EndpointInventoryQueryError, EndpointInventoryRepository};

/// One immutable §12.4 Advanced Diagnostics view of a stored resource snapshot.
///
/// The view is read-only by construction: every field comes from the latest
/// complete refresh Generation and there is no request surface, because §12.4
/// forbids changing Method, submitting arbitrary JSON, and bypassing the
/// normal permission and task model. `typed_payload` carries the persisted
/// `TypedPayloadJson` text verbatim — the honest representation of the decoded
/// read-only response (§9.4), including any OEM Namespace sections the
/// nv-redfish projection retained and any Task URI the payload itself carries.
///
/// The payload is carried as raw text, not as the domain-validated
/// [`ResourceSnapshotPayload`](rutilus_domain::ResourceSnapshotPayload): the
/// JSON-object guarantee lives at
/// `ResourceSnapshot` construction, while this view re-exposes the stored
/// text so delivery layers can re-parse it — a store that does not round-trip
/// is surfaced as an internal fault instead of being silently trusted.
///
/// Decode-error paths and `ExtendedInfo` are deliberately absent: a member
/// whose typed decoding failed was skipped at refresh time without leaving a
/// record (member-granular skips, §0.2.0), so no diagnostics can be fabricated
/// for resources that never entered the snapshot store.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceDiagnostics {
    endpoint_id: EndpointId,
    resource_id: ResourceId,
    odata_id: ResourceODataId,
    odata_type: Option<ResourceODataType>,
    etag: Option<ResourceEtag>,
    feature: ResourceFeature,
    typed_payload: String,
    generation: RefreshGeneration,
}

impl ResourceDiagnostics {
    /// Assembles a diagnostics view from already-validated parts.
    ///
    /// `typed_payload` must be the persisted `TypedPayloadJson` text; the
    /// delivery layer re-parses it and maps a non-round-tripping store to an
    /// internal fault rather than fabricating a diagnostics view.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        endpoint_id: EndpointId,
        resource_id: ResourceId,
        odata_id: ResourceODataId,
        odata_type: Option<ResourceODataType>,
        etag: Option<ResourceEtag>,
        feature: ResourceFeature,
        typed_payload: String,
        generation: RefreshGeneration,
    ) -> Self {
        Self {
            endpoint_id,
            resource_id,
            odata_id,
            odata_type,
            etag,
            feature,
            typed_payload,
            generation,
        }
    }

    #[must_use]
    pub const fn endpoint_id(&self) -> EndpointId {
        self.endpoint_id
    }

    #[must_use]
    pub const fn resource_id(&self) -> ResourceId {
        self.resource_id
    }

    #[must_use]
    pub const fn odata_id(&self) -> &ResourceODataId {
        &self.odata_id
    }

    #[must_use]
    pub const fn odata_type(&self) -> Option<&ResourceODataType> {
        self.odata_type.as_ref()
    }

    #[must_use]
    pub const fn etag(&self) -> Option<&ResourceEtag> {
        self.etag.as_ref()
    }

    #[must_use]
    pub const fn feature(&self) -> ResourceFeature {
        self.feature
    }

    #[must_use]
    pub fn typed_payload(&self) -> &str {
        &self.typed_payload
    }

    #[must_use]
    pub const fn generation(&self) -> RefreshGeneration {
        self.generation
    }

    fn from_snapshot(snapshot: &ResourceSnapshot) -> Self {
        Self::new(
            snapshot.endpoint_id(),
            snapshot.resource_id(),
            snapshot.odata_id().clone(),
            snapshot.odata_type().cloned(),
            snapshot.etag().cloned(),
            snapshot.feature(),
            snapshot.payload().as_str().to_owned(),
            snapshot.generation(),
        )
    }
}

/// Loads one resource's §12.4 diagnostics from the endpoint's current
/// Generation.
///
/// The query reuses the exact repository boundary and inventory-loading query
/// of [`EndpointResourceInventoryQuery`] instead of that query's projection,
/// because the projection drops the typed payload: the diagnostics view must
/// expose the persisted `TypedPayloadJson` verbatim, so the snapshot itself
/// (not the projected summary) is the data source.
pub struct ResourceDiagnosticsQuery<Repository> {
    repository: Repository,
    endpoint_id: EndpointId,
    resource_id: ResourceId,
}

impl<Repository> ResourceDiagnosticsQuery<Repository>
where
    Repository: EndpointInventoryRepository,
{
    #[must_use]
    pub const fn new(
        repository: Repository,
        endpoint_id: EndpointId,
        resource_id: ResourceId,
    ) -> Self {
        Self {
            repository,
            endpoint_id,
            resource_id,
        }
    }

    /// Returns `None` when the endpoint is unknown or when no snapshot of the
    /// endpoint's current Generation carries the requested `resource_id`; the
    /// caller maps both to the same not-found response and distinguishes them
    /// from a storage failure.
    ///
    /// # Errors
    ///
    /// Returns [`ResourceDiagnosticsQueryError`] when inventory loading fails
    /// or the repository emits one endpoint more than once.
    pub async fn execute(
        &self,
    ) -> Result<Option<ResourceDiagnostics>, ResourceDiagnosticsQueryError<Repository::Error>> {
        let items = EndpointInventoryQuery::new(&self.repository)
            .execute()
            .await
            .map_err(ResourceDiagnosticsQueryError::Inventory)?;
        let Some(item) = items
            .into_iter()
            .find(|item| item.endpoint().id() == self.endpoint_id)
        else {
            return Ok(None);
        };
        let Some(snapshot) = item
            .resources()
            .iter()
            .find(|snapshot| snapshot.resource_id() == self.resource_id)
        else {
            return Ok(None);
        };
        Ok(Some(ResourceDiagnostics::from_snapshot(snapshot)))
    }
}

/// A controlled failure while loading one resource's diagnostics view.
#[derive(Debug, Error)]
pub enum ResourceDiagnosticsQueryError<RepositoryError>
where
    RepositoryError: Error + 'static,
{
    #[error("failed to load endpoint inventory: {0}")]
    Inventory(#[source] EndpointInventoryQueryError<RepositoryError>),
}

#[cfg(test)]
mod tests {
    use std::fmt;

    use rutilus_domain::{
        CredentialId, Endpoint, EndpointAddress, EndpointDisplayName, ResourceODataType,
        ResourceSnapshotPayload, TlsCertificate, TlsTrust,
    };
    use time::OffsetDateTime;

    use super::*;
    use crate::{BoundaryFuture, EndpointInventoryItem};

    #[tokio::test]
    async fn projects_current_snapshot_into_diagnostics() -> Result<(), Box<dyn Error>> {
        let endpoint = endpoint()?;
        let endpoint_id = endpoint.id();
        let resource_id = ResourceId::generate();
        let generation = RefreshGeneration::new(7)?;
        let observed_at = endpoint.updated_at();
        let system_snapshot = ResourceSnapshot::new(
            resource_id,
            endpoint_id,
            ResourceFeature::Systems,
            ResourceODataId::parse("/redfish/v1/Systems/1")?,
            ResourceSnapshotPayload::parse(
                r#"{"Id":"1","Name":"System One","Oem":{"Vendor":{"OemFlag":true}}}"#,
            )?,
            observed_at,
            generation,
        )
        .with_odata_type(ResourceODataType::parse(
            "#ComputerSystem.v1_20_0.ComputerSystem",
        )?)
        .with_etag(ResourceEtag::parse("W/\"system-1\"")?);
        let item = EndpointInventoryItem::try_new(
            endpoint,
            vec![
                snapshot(
                    endpoint_id,
                    ResourceId::generate(),
                    ResourceFeature::ServiceRoot,
                    "/redfish/v1",
                    r#"{"Id":"RootService","Name":"Root"}"#,
                    observed_at,
                    generation,
                )?,
                system_snapshot,
            ],
        )?;
        let query =
            ResourceDiagnosticsQuery::new(MockRepository::ok(vec![item]), endpoint_id, resource_id);
        let diagnostics = query.execute().await?.ok_or("resource must exist")?;

        assert_eq!(diagnostics.endpoint_id(), endpoint_id);
        assert_eq!(diagnostics.resource_id(), resource_id);
        assert_eq!(diagnostics.odata_id().as_str(), "/redfish/v1/Systems/1");
        assert_eq!(
            diagnostics.odata_type().map(ResourceODataType::as_str),
            Some("#ComputerSystem.v1_20_0.ComputerSystem")
        );
        assert_eq!(
            diagnostics.etag().map(ResourceEtag::as_str),
            Some("W/\"system-1\"")
        );
        assert_eq!(diagnostics.feature(), ResourceFeature::Systems);
        // The typed payload arrives verbatim — canonicalized at snapshot
        // construction, unmodified by the projection — so the OEM namespace
        // section the decoded response carried survives into the diagnostics.
        assert_eq!(
            diagnostics.typed_payload(),
            r#"{"Id":"1","Name":"System One","Oem":{"Vendor":{"OemFlag":true}}}"#
        );
        assert_eq!(diagnostics.generation(), generation);
        Ok(())
    }

    #[tokio::test]
    async fn distinguishes_missing_endpoint_resource_and_repository_states()
    -> Result<(), Box<dyn Error>> {
        let endpoint = endpoint()?;
        let endpoint_id = endpoint.id();
        let generation = RefreshGeneration::new(3)?;
        let observed_at = endpoint.updated_at();
        let item = EndpointInventoryItem::try_new(
            endpoint,
            vec![snapshot(
                endpoint_id,
                ResourceId::generate(),
                ResourceFeature::ServiceRoot,
                "/redfish/v1",
                r#"{"Id":"RootService","Name":"Root"}"#,
                observed_at,
                generation,
            )?],
        )?;
        let unknown_resource = ResourceId::generate();

        // An endpoint that is not in the inventory is indistinguishable from a
        // resource that is not in the current Generation: both are `None`, so
        // delivery layers map both to the same not-found response.
        assert!(
            ResourceDiagnosticsQuery::new(
                MockRepository::ok(vec![item.clone()]),
                EndpointId::generate(),
                unknown_resource,
            )
            .execute()
            .await?
            .is_none()
        );
        assert!(
            ResourceDiagnosticsQuery::new(
                MockRepository::ok(vec![item]),
                endpoint_id,
                unknown_resource,
            )
            .execute()
            .await?
            .is_none()
        );

        assert!(matches!(
            ResourceDiagnosticsQuery::new(MockRepository::failed(), endpoint_id, unknown_resource,)
                .execute()
                .await,
            Err(ResourceDiagnosticsQueryError::Inventory(
                EndpointInventoryQueryError::Repository(_)
            ))
        ));
        Ok(())
    }

    fn endpoint() -> Result<Endpoint, Box<dyn Error>> {
        Ok(Endpoint::try_new(
            EndpointId::generate(),
            EndpointDisplayName::parse("Diagnostics BMC")?,
            EndpointAddress::parse("https://192.0.2.95")?,
            TlsTrust::PinnedCertificate {
                certificate: TlsCertificate::from_der(b"diagnostics test certificate".to_vec())?,
                trusted_at: OffsetDateTime::UNIX_EPOCH,
            },
            CredentialId::generate(),
            OffsetDateTime::UNIX_EPOCH,
            OffsetDateTime::UNIX_EPOCH,
        )?)
    }

    fn snapshot(
        endpoint_id: EndpointId,
        resource_id: ResourceId,
        feature: ResourceFeature,
        odata_id: &str,
        payload: &str,
        observed_at: OffsetDateTime,
        generation: RefreshGeneration,
    ) -> Result<ResourceSnapshot, Box<dyn Error>> {
        Ok(ResourceSnapshot::new(
            resource_id,
            endpoint_id,
            feature,
            ResourceODataId::parse(odata_id)?,
            ResourceSnapshotPayload::parse(payload)?,
            observed_at,
            generation,
        ))
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct MockError;

    impl fmt::Display for MockError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("mock resource diagnostics failure")
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
