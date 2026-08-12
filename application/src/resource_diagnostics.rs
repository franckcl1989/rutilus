use std::error::Error;

use rutilus_domain::{
    EndpointId, RefreshGeneration, ResourceEtag, ResourceFeature, ResourceId, ResourceODataId,
    ResourceODataType, ResourceSnapshot,
};
use thiserror::Error;

use crate::{EndpointInventoryQuery, EndpointInventoryQueryError, EndpointInventoryRepository};

/// The maximum length of one `ExtendedInfo` text field retained for display.
pub const RESOURCE_EXTENDED_INFO_TEXT_MAX_CHARS: usize = 1024;

/// The maximum number of `RelatedProperties` entries retained per
/// `ExtendedInfo` entry.
pub const RESOURCE_EXTENDED_INFO_RELATED_PROPERTIES_MAX: usize = 32;

/// The maximum length of one decode-failure OEM namespace retained for
/// display.
pub const RESOURCE_DECODE_FAILURE_OEM_NAMESPACE_MAX_CHARS: usize = 512;

/// The maximum length of one decode-failure summary retained for display.
pub const RESOURCE_DECODE_FAILURE_SUMMARY_MAX_CHARS: usize = 2048;

/// One Redfish `@Message.ExtendedInfo` entry retained by a gateway-mapped
/// snapshot (§7.6: Redfish `ExtendedInfo` is preserved, never flattened into
/// a plain string).
///
/// The entry is a domain-shaped projection of the upstream shape: the fields
/// Redfish defines (`MessageId`, `Message`, `Severity`, `Resolution`,
/// `RelatedProperties`) are validated structurally, while any vendor-added
/// extra properties are ignored — the diagnostics view displays the defined
/// fields, and a payload that does not round-trip them is an internal fault
/// instead of a fabricated entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceExtendedInfo {
    message_id: String,
    message: Option<String>,
    severity: Option<String>,
    resolution: Option<String>,
    related_properties: Vec<String>,
}

impl ResourceExtendedInfo {
    #[must_use]
    pub const fn new(
        message_id: String,
        message: Option<String>,
        severity: Option<String>,
        resolution: Option<String>,
        related_properties: Vec<String>,
    ) -> Self {
        Self {
            message_id,
            message,
            severity,
            resolution,
            related_properties,
        }
    }

    #[must_use]
    pub fn message_id(&self) -> &str {
        &self.message_id
    }

    #[must_use]
    pub fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }

    #[must_use]
    pub fn severity(&self) -> Option<&str> {
        self.severity.as_deref()
    }

    #[must_use]
    pub fn resolution(&self) -> Option<&str> {
        self.resolution.as_deref()
    }

    #[must_use]
    pub fn related_properties(&self) -> &[String] {
        &self.related_properties
    }

    /// Parses one Redfish `@Message.ExtendedInfo` entry strictly.
    ///
    /// `MessageId` is mandatory and must be a non-empty string; every other
    /// defined field must be a string when present (or an array of strings
    /// for `RelatedProperties`), and every retained text is length-bounded.
    /// Unknown entry properties are ignored.
    ///
    /// # Errors
    ///
    /// Returns [`ResourceExtendedInfoError`] when the entry violates the
    /// defined shape.
    pub fn try_parse(value: &serde_json::Value) -> Result<Self, ResourceExtendedInfoError> {
        let object = value
            .as_object()
            .ok_or(ResourceExtendedInfoError::EntryNotAnObject)?;
        let message_id = object
            .get("MessageId")
            .and_then(serde_json::Value::as_str)
            .filter(|text| !text.is_empty())
            .ok_or(ResourceExtendedInfoError::InvalidMessageId)?;
        if message_id.len() > RESOURCE_EXTENDED_INFO_TEXT_MAX_CHARS {
            return Err(ResourceExtendedInfoError::InvalidMessageId);
        }
        let message = parse_optional_text(
            object.get("Message"),
            ResourceExtendedInfoError::InvalidMessage,
        )?;
        let severity = parse_optional_text(
            object.get("Severity"),
            ResourceExtendedInfoError::InvalidSeverity,
        )?;
        let resolution = parse_optional_text(
            object.get("Resolution"),
            ResourceExtendedInfoError::InvalidResolution,
        )?;
        let related_properties = match object.get("RelatedProperties") {
            None => Vec::new(),
            Some(value) => {
                let properties = value
                    .as_array()
                    .ok_or(ResourceExtendedInfoError::InvalidRelatedProperties)?;
                if properties.len() > RESOURCE_EXTENDED_INFO_RELATED_PROPERTIES_MAX {
                    return Err(ResourceExtendedInfoError::InvalidRelatedProperties);
                }
                properties
                    .iter()
                    .map(|property| {
                        let text = property
                            .as_str()
                            .ok_or(ResourceExtendedInfoError::InvalidRelatedProperties)?;
                        if text.len() > RESOURCE_EXTENDED_INFO_TEXT_MAX_CHARS {
                            return Err(ResourceExtendedInfoError::InvalidRelatedProperties);
                        }
                        Ok(text.to_owned())
                    })
                    .collect::<Result<Vec<_>, ResourceExtendedInfoError>>()?
            }
        };
        Ok(Self {
            message_id: message_id.to_owned(),
            message,
            severity,
            resolution,
            related_properties,
        })
    }

    /// Extracts every `@Message.ExtendedInfo` entry a stored typed payload
    /// carries.
    ///
    /// The payload root is guaranteed to be a JSON object by
    /// [`ResourceSnapshot`] construction; the array and every entry are
    /// parsed strictly, so a payload that does not round-trip the defined
    /// shape surfaces as an internal fault instead of a fabricated entry.
    ///
    /// # Errors
    ///
    /// Returns [`ResourceExtendedInfoError`] when the payload is not JSON,
    /// its root is not an object, or a carried `@Message.ExtendedInfo` array
    /// violates the defined shape.
    pub fn from_payload(payload: &str) -> Result<Vec<Self>, ResourceExtendedInfoError> {
        let root: serde_json::Value =
            serde_json::from_str(payload).map_err(ResourceExtendedInfoError::Payload)?;
        Self::from_value(&root)
    }

    /// Extracts every `@Message.ExtendedInfo` entry an already-parsed typed
    /// payload value carries.
    ///
    /// The delivery layer re-parses the stored payload anyway for the verbatim
    /// `typed_payload` field; this method lets that one parse feed both the
    /// response value and the strict entry extraction, so the two can never
    /// disagree.
    ///
    /// # Errors
    ///
    /// Returns [`ResourceExtendedInfoError`] when the root is not an object
    /// or a carried `@Message.ExtendedInfo` array violates the defined shape.
    pub fn from_value(root: &serde_json::Value) -> Result<Vec<Self>, ResourceExtendedInfoError> {
        let object = root
            .as_object()
            .ok_or(ResourceExtendedInfoError::NotAnObject)?;
        let Some(entries) = object.get("@Message.ExtendedInfo") else {
            return Ok(Vec::new());
        };
        let entries = entries
            .as_array()
            .ok_or(ResourceExtendedInfoError::InvalidArray)?;
        entries.iter().map(Self::try_parse).collect()
    }
}

/// One optional `ExtendedInfo` text field, validated like `MessageId`
/// (bounds included) with the caller's variant on violation.
fn parse_optional_text(
    value: Option<&serde_json::Value>,
    invalid: ResourceExtendedInfoError,
) -> Result<Option<String>, ResourceExtendedInfoError> {
    match value {
        None => Ok(None),
        Some(value) => match value.as_str() {
            Some(text) if text.len() <= RESOURCE_EXTENDED_INFO_TEXT_MAX_CHARS => {
                Ok(Some(text.to_owned()))
            }
            Some(_) | None => Err(invalid),
        },
    }
}

/// A controlled failure while projecting one Redfish `ExtendedInfo` entry.
#[derive(Debug, Error)]
pub enum ResourceExtendedInfoError {
    #[error("the stored typed payload is not JSON: {0}")]
    Payload(#[source] serde_json::Error),
    #[error("the stored typed payload root is not a JSON object")]
    NotAnObject,
    #[error("the stored typed payload carries an invalid @Message.ExtendedInfo array")]
    InvalidArray,
    #[error("an ExtendedInfo entry must be a JSON object")]
    EntryNotAnObject,
    #[error("an ExtendedInfo entry carries an invalid MessageId")]
    InvalidMessageId,
    #[error("an ExtendedInfo entry carries an invalid Message")]
    InvalidMessage,
    #[error("an ExtendedInfo entry carries an invalid Severity")]
    InvalidSeverity,
    #[error("an ExtendedInfo entry carries an invalid Resolution")]
    InvalidResolution,
    #[error("an ExtendedInfo entry carries invalid RelatedProperties")]
    InvalidRelatedProperties,
}

/// One member whose typed Schema decoding failed during the endpoint's
/// current refresh Generation, retained for §12.4 diagnostics.
///
/// The record is deliberately a sibling of the decoded snapshots, not a
/// replacement: the member was skipped as one odd member (§0.2.0), the
/// endpoint and its other resources stay fully usable, and diagnostics
/// distinguish the member-level decode failure from a whole-endpoint
/// unavailability by construction — the endpoint still has an inventory item
/// and a current Generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceDecodeFailure {
    odata_uri: ResourceODataId,
    odata_type: Option<ResourceODataType>,
    feature: ResourceFeature,
    oem_namespace: Option<String>,
    error_summary: String,
    extended_info: Vec<ResourceExtendedInfo>,
}

impl ResourceDecodeFailure {
    /// Constructs one decode-failure record from validated parts.
    ///
    /// # Errors
    ///
    /// Returns [`ResourceDecodeFailureError`] when the OEM namespace or the
    /// error summary is empty or exceeds its bound.
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        odata_uri: ResourceODataId,
        odata_type: Option<ResourceODataType>,
        feature: ResourceFeature,
        oem_namespace: Option<String>,
        error_summary: String,
        extended_info: Vec<ResourceExtendedInfo>,
    ) -> Result<Self, ResourceDecodeFailureError> {
        if let Some(namespace) = &oem_namespace {
            if namespace.is_empty() {
                return Err(ResourceDecodeFailureError::EmptyOemNamespace);
            }
            if namespace.len() > RESOURCE_DECODE_FAILURE_OEM_NAMESPACE_MAX_CHARS {
                return Err(ResourceDecodeFailureError::OemNamespaceTooLong {
                    max: RESOURCE_DECODE_FAILURE_OEM_NAMESPACE_MAX_CHARS,
                });
            }
        }
        if error_summary.is_empty() {
            return Err(ResourceDecodeFailureError::EmptyErrorSummary);
        }
        if error_summary.len() > RESOURCE_DECODE_FAILURE_SUMMARY_MAX_CHARS {
            return Err(ResourceDecodeFailureError::ErrorSummaryTooLong {
                max: RESOURCE_DECODE_FAILURE_SUMMARY_MAX_CHARS,
            });
        }
        Ok(Self {
            odata_uri,
            odata_type,
            feature,
            oem_namespace,
            error_summary,
            extended_info,
        })
    }

    #[must_use]
    pub const fn odata_uri(&self) -> &ResourceODataId {
        &self.odata_uri
    }

    #[must_use]
    pub const fn odata_type(&self) -> Option<&ResourceODataType> {
        self.odata_type.as_ref()
    }

    #[must_use]
    pub const fn feature(&self) -> ResourceFeature {
        self.feature
    }

    #[must_use]
    pub fn oem_namespace(&self) -> Option<&str> {
        self.oem_namespace.as_deref()
    }

    #[must_use]
    pub fn error_summary(&self) -> &str {
        &self.error_summary
    }

    /// Borrows the Redfish `@Message.ExtendedInfo` entries the failed
    /// response carried (§7.6), when the gateway retained them.
    #[must_use]
    pub fn extended_info(&self) -> &[ResourceExtendedInfo] {
        &self.extended_info
    }
}

/// A controlled failure while constructing one decode-failure record.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ResourceDecodeFailureError {
    #[error("the OEM namespace must be a non-empty string")]
    EmptyOemNamespace,
    #[error("the OEM namespace exceeds {max} characters")]
    OemNamespaceTooLong { max: usize },
    #[error("the decode error summary must be a non-empty string")]
    EmptyErrorSummary,
    #[error("the decode error summary exceeds {max} characters")]
    ErrorSummaryTooLong { max: usize },
}

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
/// `extended_info` carries the Redfish `@Message.ExtendedInfo` entries the
/// stored typed payload itself retains (§7.6), derived strictly from the
/// gateway-mapped snapshot — the delivery layer never fabricates an entry a
/// store did not round-trip. `decode_failures` carries the endpoint's current
/// Generation member decode failures (§12.4 decode-error path): members whose
/// typed decoding failed at refresh time were skipped as odd members
/// (§0.2.0) without disabling the endpoint, and these records keep that path
/// visible instead of silently dropping it.
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
    extended_info: Vec<ResourceExtendedInfo>,
    decode_failures: Vec<ResourceDecodeFailure>,
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
            extended_info: Vec::new(),
            decode_failures: Vec::new(),
        }
    }

    /// Attaches the Redfish `@Message.ExtendedInfo` entries the requested
    /// resource's stored typed payload retains.
    #[must_use]
    pub fn with_extended_info(mut self, extended_info: Vec<ResourceExtendedInfo>) -> Self {
        self.extended_info = extended_info;
        self
    }

    /// Attaches the endpoint's current Generation member decode-failure
    /// records (§12.4 decode-error path).
    #[must_use]
    pub fn with_decode_failures(mut self, decode_failures: Vec<ResourceDecodeFailure>) -> Self {
        self.decode_failures = decode_failures;
        self
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

    /// Borrows the Redfish `@Message.ExtendedInfo` entries the requested
    /// resource's stored typed payload retains (§7.6).
    #[must_use]
    pub fn extended_info(&self) -> &[ResourceExtendedInfo] {
        &self.extended_info
    }

    /// Borrows the endpoint's current Generation member decode-failure
    /// records (§12.4 decode-error path).
    #[must_use]
    pub fn decode_failures(&self) -> &[ResourceDecodeFailure] {
        &self.decode_failures
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
        // The resource's own ExtendedInfo comes strictly from the stored
        // typed payload — the gateway-mapped domain snapshot — never from a
        // fabricated entry; a payload that does not round-trip the defined
        // shape is an internal fault, exactly like a payload that does not
        // re-parse in the delivery layer.
        let extended_info = ResourceExtendedInfo::from_payload(snapshot.payload().as_str())
            .map_err(ResourceDiagnosticsQueryError::ExtendedInfo)?;
        Ok(Some(
            ResourceDiagnostics::from_snapshot(snapshot)
                .with_extended_info(extended_info)
                .with_decode_failures(item.decode_failures().to_vec()),
        ))
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
    #[error("the stored snapshot carries invalid Redfish ExtendedInfo: {0}")]
    ExtendedInfo(#[source] ResourceExtendedInfoError),
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
        assert!(diagnostics.extended_info().is_empty());
        assert!(diagnostics.decode_failures().is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn derives_extended_info_from_the_stored_payload() -> Result<(), Box<dyn Error>> {
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
                r#"{"Id":"1","Name":"System One","@Message.ExtendedInfo":[{"MessageId":"Base.1.13.Success","Severity":"OK","Resolution":"No action required","RelatedProperties":["Id"],"VendorExtra":true}]}"#,
            )?,
            observed_at,
            generation,
        );
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

        let entries = diagnostics.extended_info();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].message_id(), "Base.1.13.Success");
        assert_eq!(entries[0].severity(), Some("OK"));
        assert_eq!(entries[0].message(), None);
        assert_eq!(entries[0].resolution(), Some("No action required"));
        // The vendor-added property is ignored by design: the view displays
        // the Redfish-defined fields, and the entry still round-trips them.
        assert_eq!(entries[0].related_properties(), &["Id".to_owned()]);
        Ok(())
    }

    #[tokio::test]
    async fn malformed_extended_info_in_a_stored_payload_is_an_internal_fault()
    -> Result<(), Box<dyn Error>> {
        let endpoint = endpoint()?;
        let endpoint_id = endpoint.id();
        let resource_id = ResourceId::generate();
        let generation = RefreshGeneration::new(7)?;
        let observed_at = endpoint.updated_at();
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
                snapshot(
                    endpoint_id,
                    resource_id,
                    ResourceFeature::Systems,
                    "/redfish/v1/Systems/1",
                    // A MessageId that is not a string violates the defined
                    // ExtendedInfo shape: the store round-tripped a payload
                    // that the diagnostics layer cannot honestly display.
                    r#"{"Id":"1","Name":"System One","@Message.ExtendedInfo":[{"MessageId":7}]}"#,
                    observed_at,
                    generation,
                )?,
            ],
        )?;
        let query =
            ResourceDiagnosticsQuery::new(MockRepository::ok(vec![item]), endpoint_id, resource_id);

        assert!(matches!(
            query.execute().await,
            Err(ResourceDiagnosticsQueryError::ExtendedInfo(
                ResourceExtendedInfoError::InvalidMessageId
            ))
        ));
        Ok(())
    }

    #[tokio::test]
    async fn carries_the_current_generations_decode_failure_records() -> Result<(), Box<dyn Error>>
    {
        let endpoint = endpoint()?;
        let endpoint_id = endpoint.id();
        let resource_id = ResourceId::generate();
        let generation = RefreshGeneration::new(7)?;
        let observed_at = endpoint.updated_at();
        let decode_failure = ResourceDecodeFailure::try_new(
            ResourceODataId::parse("/redfish/v1/Systems/2")?,
            Some(ResourceODataType::parse(
                "#ComputerSystem.v1_20_0.ComputerSystem",
            )?),
            ResourceFeature::Systems,
            Some("Vendor".to_owned()),
            "schema decode failed: missing required field".to_owned(),
            vec![ResourceExtendedInfo::new(
                "Base.1.13.ResourceNotFound".to_owned(),
                Some("The requested resource could not be found.".to_owned()),
                Some("Critical".to_owned()),
                Some("Remove and re-add the resource.".to_owned()),
                vec!["MemberId".to_owned()],
            )],
        )?;
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
                snapshot(
                    endpoint_id,
                    resource_id,
                    ResourceFeature::Systems,
                    "/redfish/v1/Systems/1",
                    r#"{"Id":"1","Name":"System One"}"#,
                    observed_at,
                    generation,
                )?,
            ],
        )?
        .with_decode_failures(vec![decode_failure]);
        let query =
            ResourceDiagnosticsQuery::new(MockRepository::ok(vec![item]), endpoint_id, resource_id);
        let diagnostics = query.execute().await?.ok_or("resource must exist")?;

        // The endpoint stays fully usable: its snapshot is served with its
        // current Generation, and the member decode failure is a sibling
        // record, not an endpoint-wide condition (§0.2.0 / §2.0).
        let failures = diagnostics.decode_failures();
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].odata_uri().as_str(), "/redfish/v1/Systems/2");
        assert_eq!(
            failures[0].odata_type().map(ResourceODataType::as_str),
            Some("#ComputerSystem.v1_20_0.ComputerSystem")
        );
        assert_eq!(failures[0].feature(), ResourceFeature::Systems);
        assert_eq!(failures[0].oem_namespace(), Some("Vendor"));
        assert_eq!(
            failures[0].error_summary(),
            "schema decode failed: missing required field"
        );
        let entries = failures[0].extended_info();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].message_id(), "Base.1.13.ResourceNotFound");
        assert_eq!(entries[0].severity(), Some("Critical"));
        assert_eq!(
            entries[0].resolution(),
            Some("Remove and re-add the resource.")
        );
        assert_eq!(entries[0].related_properties(), &["MemberId".to_owned()]);
        Ok(())
    }

    #[test]
    fn decode_failure_records_reject_empty_or_oversized_fields() -> Result<(), Box<dyn Error>> {
        let odata_uri = ResourceODataId::parse("/redfish/v1/Systems/2")?;
        let feature = ResourceFeature::Systems;
        assert!(matches!(
            ResourceDecodeFailure::try_new(
                odata_uri.clone(),
                None,
                feature,
                Some(String::new()),
                "summary".to_owned(),
                vec![],
            ),
            Err(ResourceDecodeFailureError::EmptyOemNamespace)
        ));
        assert!(matches!(
            ResourceDecodeFailure::try_new(
                odata_uri.clone(),
                None,
                feature,
                Some("v".repeat(RESOURCE_DECODE_FAILURE_OEM_NAMESPACE_MAX_CHARS + 1)),
                "summary".to_owned(),
                vec![],
            ),
            Err(ResourceDecodeFailureError::OemNamespaceTooLong { .. })
        ));
        assert!(matches!(
            ResourceDecodeFailure::try_new(
                odata_uri.clone(),
                None,
                feature,
                None,
                String::new(),
                vec![],
            ),
            Err(ResourceDecodeFailureError::EmptyErrorSummary)
        ));
        assert!(matches!(
            ResourceDecodeFailure::try_new(
                odata_uri,
                None,
                feature,
                None,
                "s".repeat(RESOURCE_DECODE_FAILURE_SUMMARY_MAX_CHARS + 1),
                vec![],
            ),
            Err(ResourceDecodeFailureError::ErrorSummaryTooLong { .. })
        ));
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
