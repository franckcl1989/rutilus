use std::{error::Error, fmt, str::FromStr};

use serde_json::Value;
use time::OffsetDateTime;

use crate::{EndpointId, ResourceId};

const MAX_ODATA_ID_BYTES: usize = 4 * 1024;
const MAX_ODATA_TYPE_BYTES: usize = 512;
const MAX_ETAG_BYTES: usize = 512;
const MAX_TYPED_PAYLOAD_BYTES: usize = 4 * 1024 * 1024;

/// The typed Redfish feature that produced a resource snapshot.
///
/// Every variant's `as_str()` code is the §2.1 feature name and equals the
/// matching [`EndpointCapability`] product code, so snapshot and ledger
/// projections never translate the same wire string twice.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ResourceFeature {
    ServiceRoot,
    Systems,
    Chassis,
    Managers,
    /// The §2.1 `processors` feature, added as a typed resource family in the
    /// 0.2 snapshot; the code matches the `EndpointCapability` product code so
    /// both inventories address the same wire surface.
    Processors,
    /// The §2.1 `memory` feature, added as a typed resource family in the 0.2
    /// snapshot; the code matches the `EndpointCapability` product code so
    /// both inventories address the same wire surface.
    Memory,
    /// The §2.1 `storages` feature, added as a typed resource family in the
    /// 0.2 snapshot; the code matches the `EndpointCapability` product code so
    /// both inventories address the same wire surface.
    Storages,
    /// The §2.1 `network-adapters` feature, added as a typed resource family
    /// in the 0.2 snapshot; the code matches the `EndpointCapability` product
    /// code so both inventories address the same wire surface.
    NetworkAdapters,
    /// The §2.1 `ethernet-interfaces` feature, added as a typed resource
    /// family in the 0.2 snapshot; the code matches the `EndpointCapability`
    /// product code so both inventories address the same wire surface.
    EthernetInterfaces,
    /// The §2.1 `accounts` feature, added as a typed resource family in the
    /// 0.2 snapshot; the code matches the `EndpointCapability` product code so
    /// both inventories address the same wire surface.
    Accounts,
    /// The §2.1 `bios` feature, added as a typed resource family in the 0.2
    /// snapshot; the code matches the `EndpointCapability` product code so
    /// both inventories address the same wire surface.
    Bios,
    /// The §2.1 `boot-options` feature, added as a typed resource family in
    /// the 0.2 snapshot; the code matches the `EndpointCapability` product
    /// code so both inventories address the same wire surface.
    BootOptions,
    /// The §2.1 `secure-boot` feature, added as a typed resource family in
    /// the 0.2 snapshot; the code matches the `EndpointCapability` product
    /// code so both inventories address the same wire surface.
    SecureBoot,
}

impl ResourceFeature {
    /// Returns the stable product code used by persistence and protocols.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ServiceRoot => "service-root",
            Self::Systems => "systems",
            Self::Chassis => "chassis",
            Self::Managers => "managers",
            Self::Processors => "processors",
            Self::Memory => "memory",
            Self::Storages => "storages",
            Self::NetworkAdapters => "network-adapters",
            Self::EthernetInterfaces => "ethernet-interfaces",
            Self::Accounts => "accounts",
            Self::Bios => "bios",
            Self::BootOptions => "boot-options",
            Self::SecureBoot => "secure-boot",
        }
    }
}

impl fmt::Display for ResourceFeature {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for ResourceFeature {
    type Err = ResourceFeatureParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "service-root" => Ok(Self::ServiceRoot),
            "systems" => Ok(Self::Systems),
            "chassis" => Ok(Self::Chassis),
            "managers" => Ok(Self::Managers),
            "processors" => Ok(Self::Processors),
            "memory" => Ok(Self::Memory),
            "storages" => Ok(Self::Storages),
            "network-adapters" => Ok(Self::NetworkAdapters),
            "ethernet-interfaces" => Ok(Self::EthernetInterfaces),
            "accounts" => Ok(Self::Accounts),
            "bios" => Ok(Self::Bios),
            "boot-options" => Ok(Self::BootOptions),
            "secure-boot" => Ok(Self::SecureBoot),
            _ => Err(ResourceFeatureParseError),
        }
    }
}

/// A persisted resource feature is unknown to this product build.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceFeatureParseError;

impl fmt::Display for ResourceFeatureParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("unknown resource feature code")
    }
}

impl Error for ResourceFeatureParseError {}

/// An opaque Redfish `@odata.id` discovered through typed navigation.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ResourceODataId(String);

impl ResourceODataId {
    /// Validates a discovered identifier without interpreting or constructing
    /// a resource path.
    ///
    /// # Errors
    ///
    /// Returns [`ResourceODataIdError`] for empty, whitespace-padded,
    /// control-containing, or oversized values.
    pub fn parse(value: &str) -> Result<Self, ResourceODataIdError> {
        validate_exact_text(value, MAX_ODATA_ID_BYTES).map_err(map_odata_id_error)?;
        Ok(Self(value.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ResourceODataId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for ResourceODataId {
    type Err = ResourceODataIdError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

/// Why a discovered `@odata.id` cannot be represented safely.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceODataIdError {
    Empty,
    SurroundingWhitespace,
    ControlCharacter,
    TooLong { actual: usize, maximum: usize },
}

impl fmt::Display for ResourceODataIdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_exact_text_error(formatter, "resource @odata.id", exact_from_odata_id(*self))
    }
}

impl Error for ResourceODataIdError {}

/// An exact Redfish `@odata.type` observed in a typed resource payload.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ResourceODataType(String);

impl ResourceODataType {
    /// Validates an observed type annotation.
    ///
    /// # Errors
    ///
    /// Returns [`ResourceODataTypeError`] for malformed text or when the value
    /// does not begin with the Redfish `#` type marker.
    pub fn parse(value: &str) -> Result<Self, ResourceODataTypeError> {
        validate_exact_text(value, MAX_ODATA_TYPE_BYTES).map_err(map_odata_type_error)?;
        if !value.starts_with('#') {
            return Err(ResourceODataTypeError::MissingTypeMarker);
        }
        Ok(Self(value.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ResourceODataType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for ResourceODataType {
    type Err = ResourceODataTypeError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

/// Why an observed Redfish type annotation is invalid.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceODataTypeError {
    Empty,
    SurroundingWhitespace,
    ControlCharacter,
    TooLong { actual: usize, maximum: usize },
    MissingTypeMarker,
}

impl fmt::Display for ResourceODataTypeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingTypeMarker => {
                formatter.write_str("resource @odata.type must begin with '#'")
            }
            other => write_exact_text_error(
                formatter,
                "resource @odata.type",
                exact_from_odata_type(*other),
            ),
        }
    }
}

impl Error for ResourceODataTypeError {}

/// An opaque Redfish entity tag used for later conditional operations.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ResourceEtag(String);

impl ResourceEtag {
    /// Validates an observed entity tag without changing its exact value.
    ///
    /// # Errors
    ///
    /// Returns [`ResourceEtagError`] for empty, whitespace-padded,
    /// control-containing, or oversized values.
    pub fn parse(value: &str) -> Result<Self, ResourceEtagError> {
        validate_exact_text(value, MAX_ETAG_BYTES).map_err(map_etag_error)?;
        Ok(Self(value.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ResourceEtag {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for ResourceEtag {
    type Err = ResourceEtagError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

/// Why an observed Redfish entity tag is invalid.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceEtagError {
    Empty,
    SurroundingWhitespace,
    ControlCharacter,
    TooLong { actual: usize, maximum: usize },
}

impl fmt::Display for ResourceEtagError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_exact_text_error(formatter, "resource ETag", exact_from_etag(*self))
    }
}

impl Error for ResourceEtagError {}

/// A bounded JSON object produced after successful typed Redfish decoding.
#[derive(Clone, Eq, PartialEq)]
pub struct ResourceSnapshotPayload(String);

impl ResourceSnapshotPayload {
    /// Parses and canonicalizes a typed resource projection.
    ///
    /// # Errors
    ///
    /// Returns [`ResourceSnapshotPayloadError`] when the payload exceeds four
    /// MiB, is not valid JSON, or is not a JSON object.
    pub fn parse(value: &str) -> Result<Self, ResourceSnapshotPayloadError> {
        let actual = value.len();
        if actual > MAX_TYPED_PAYLOAD_BYTES {
            return Err(ResourceSnapshotPayloadError::TooLarge {
                actual,
                maximum: MAX_TYPED_PAYLOAD_BYTES,
            });
        }
        let parsed: Value =
            serde_json::from_str(value).map_err(ResourceSnapshotPayloadError::InvalidJson)?;
        if !parsed.is_object() {
            return Err(ResourceSnapshotPayloadError::NotObject);
        }
        let canonical =
            serde_json::to_string(&parsed).map_err(ResourceSnapshotPayloadError::Canonicalize)?;
        Ok(Self(canonical))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ResourceSnapshotPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResourceSnapshotPayload")
            .field("bytes", &self.0.len())
            .finish_non_exhaustive()
    }
}

/// Why a typed resource projection cannot be stored.
#[derive(Debug)]
pub enum ResourceSnapshotPayloadError {
    TooLarge { actual: usize, maximum: usize },
    InvalidJson(serde_json::Error),
    NotObject,
    Canonicalize(serde_json::Error),
}

impl fmt::Display for ResourceSnapshotPayloadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge { actual, maximum } => write!(
                formatter,
                "typed resource payload has {actual} bytes; maximum is {maximum}"
            ),
            Self::InvalidJson(_) => formatter.write_str("typed resource payload is not valid JSON"),
            Self::NotObject => formatter.write_str("typed resource payload must be a JSON object"),
            Self::Canonicalize(_) => {
                formatter.write_str("typed resource payload could not be canonicalized")
            }
        }
    }
}

impl Error for ResourceSnapshotPayloadError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidJson(source) | Self::Canonicalize(source) => Some(source),
            Self::TooLarge { .. } | Self::NotObject => None,
        }
    }
}

/// A positive, SQLite-compatible endpoint refresh generation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RefreshGeneration(u64);

impl RefreshGeneration {
    /// Validates a generation for storage in a signed `SQLite` integer.
    ///
    /// # Errors
    ///
    /// Returns [`RefreshGenerationError`] for zero or values above `i64::MAX`.
    pub fn new(value: u64) -> Result<Self, RefreshGenerationError> {
        if value == 0 {
            return Err(RefreshGenerationError::Zero);
        }
        if value > i64::MAX as u64 {
            return Err(RefreshGenerationError::TooLarge { value });
        }
        Ok(Self(value))
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Why a refresh generation cannot be represented safely.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RefreshGenerationError {
    Zero,
    TooLarge { value: u64 },
}

impl fmt::Display for RefreshGenerationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Zero => formatter.write_str("refresh generation must be positive"),
            Self::TooLarge { value } => write!(
                formatter,
                "refresh generation {value} exceeds SQLite's signed integer range"
            ),
        }
    }
}

impl Error for RefreshGenerationError {}

/// One immutable, typed observation of a discovered Redfish resource.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceSnapshot {
    resource_id: ResourceId,
    endpoint_id: EndpointId,
    feature: ResourceFeature,
    odata_id: ResourceODataId,
    odata_type: Option<ResourceODataType>,
    etag: Option<ResourceEtag>,
    payload: ResourceSnapshotPayload,
    observed_at: OffsetDateTime,
    generation: RefreshGeneration,
}

impl ResourceSnapshot {
    #[must_use]
    pub fn new(
        resource_id: ResourceId,
        endpoint_id: EndpointId,
        feature: ResourceFeature,
        odata_id: ResourceODataId,
        payload: ResourceSnapshotPayload,
        observed_at: OffsetDateTime,
        generation: RefreshGeneration,
    ) -> Self {
        Self {
            resource_id,
            endpoint_id,
            feature,
            odata_id,
            odata_type: None,
            etag: None,
            payload,
            observed_at,
            generation,
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

    #[must_use]
    pub const fn resource_id(&self) -> ResourceId {
        self.resource_id
    }

    #[must_use]
    pub const fn endpoint_id(&self) -> EndpointId {
        self.endpoint_id
    }

    #[must_use]
    pub const fn feature(&self) -> ResourceFeature {
        self.feature
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
    pub const fn payload(&self) -> &ResourceSnapshotPayload {
        &self.payload
    }

    #[must_use]
    pub const fn observed_at(&self) -> OffsetDateTime {
        self.observed_at
    }

    #[must_use]
    pub const fn generation(&self) -> RefreshGeneration {
        self.generation
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExactTextError {
    Empty,
    SurroundingWhitespace,
    ControlCharacter,
    TooLong { actual: usize, maximum: usize },
}

fn validate_exact_text(value: &str, maximum: usize) -> Result<(), ExactTextError> {
    if value.is_empty() {
        return Err(ExactTextError::Empty);
    }
    if value.trim() != value {
        return Err(ExactTextError::SurroundingWhitespace);
    }
    if value.chars().any(char::is_control) {
        return Err(ExactTextError::ControlCharacter);
    }
    let actual = value.len();
    if actual > maximum {
        return Err(ExactTextError::TooLong { actual, maximum });
    }
    Ok(())
}

fn map_odata_id_error(error: ExactTextError) -> ResourceODataIdError {
    match error {
        ExactTextError::Empty => ResourceODataIdError::Empty,
        ExactTextError::SurroundingWhitespace => ResourceODataIdError::SurroundingWhitespace,
        ExactTextError::ControlCharacter => ResourceODataIdError::ControlCharacter,
        ExactTextError::TooLong { actual, maximum } => {
            ResourceODataIdError::TooLong { actual, maximum }
        }
    }
}

fn exact_from_odata_id(error: ResourceODataIdError) -> ExactTextError {
    match error {
        ResourceODataIdError::Empty => ExactTextError::Empty,
        ResourceODataIdError::SurroundingWhitespace => ExactTextError::SurroundingWhitespace,
        ResourceODataIdError::ControlCharacter => ExactTextError::ControlCharacter,
        ResourceODataIdError::TooLong { actual, maximum } => {
            ExactTextError::TooLong { actual, maximum }
        }
    }
}

fn map_odata_type_error(error: ExactTextError) -> ResourceODataTypeError {
    match error {
        ExactTextError::Empty => ResourceODataTypeError::Empty,
        ExactTextError::SurroundingWhitespace => ResourceODataTypeError::SurroundingWhitespace,
        ExactTextError::ControlCharacter => ResourceODataTypeError::ControlCharacter,
        ExactTextError::TooLong { actual, maximum } => {
            ResourceODataTypeError::TooLong { actual, maximum }
        }
    }
}

fn exact_from_odata_type(error: ResourceODataTypeError) -> ExactTextError {
    match error {
        ResourceODataTypeError::Empty | ResourceODataTypeError::MissingTypeMarker => {
            ExactTextError::Empty
        }
        ResourceODataTypeError::SurroundingWhitespace => ExactTextError::SurroundingWhitespace,
        ResourceODataTypeError::ControlCharacter => ExactTextError::ControlCharacter,
        ResourceODataTypeError::TooLong { actual, maximum } => {
            ExactTextError::TooLong { actual, maximum }
        }
    }
}

fn map_etag_error(error: ExactTextError) -> ResourceEtagError {
    match error {
        ExactTextError::Empty => ResourceEtagError::Empty,
        ExactTextError::SurroundingWhitespace => ResourceEtagError::SurroundingWhitespace,
        ExactTextError::ControlCharacter => ResourceEtagError::ControlCharacter,
        ExactTextError::TooLong { actual, maximum } => {
            ResourceEtagError::TooLong { actual, maximum }
        }
    }
}

fn exact_from_etag(error: ResourceEtagError) -> ExactTextError {
    match error {
        ResourceEtagError::Empty => ExactTextError::Empty,
        ResourceEtagError::SurroundingWhitespace => ExactTextError::SurroundingWhitespace,
        ResourceEtagError::ControlCharacter => ExactTextError::ControlCharacter,
        ResourceEtagError::TooLong { actual, maximum } => {
            ExactTextError::TooLong { actual, maximum }
        }
    }
}

fn write_exact_text_error(
    formatter: &mut fmt::Formatter<'_>,
    field: &str,
    error: ExactTextError,
) -> fmt::Result {
    match error {
        ExactTextError::Empty => write!(formatter, "{field} cannot be empty"),
        ExactTextError::SurroundingWhitespace => {
            write!(formatter, "{field} cannot contain surrounding whitespace")
        }
        ExactTextError::ControlCharacter => {
            write!(formatter, "{field} cannot contain control characters")
        }
        ExactTextError::TooLong { actual, maximum } => {
            write!(
                formatter,
                "{field} has {actual} bytes; maximum is {maximum}"
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::EndpointCapability;

    use super::*;

    #[test]
    fn resource_feature_codes_are_stable() {
        let features = [
            ResourceFeature::ServiceRoot,
            ResourceFeature::Systems,
            ResourceFeature::Chassis,
            ResourceFeature::Managers,
            ResourceFeature::Processors,
            ResourceFeature::Memory,
            ResourceFeature::Storages,
            ResourceFeature::NetworkAdapters,
            ResourceFeature::EthernetInterfaces,
            ResourceFeature::Accounts,
            ResourceFeature::Bios,
            ResourceFeature::BootOptions,
            ResourceFeature::SecureBoot,
        ];

        for feature in features {
            assert_eq!(feature.as_str().parse(), Ok(feature));
        }
        assert_eq!(
            "unknown".parse::<ResourceFeature>(),
            Err(ResourceFeatureParseError)
        );
    }

    #[test]
    fn typed_family_codes_round_trip_and_match_the_capability_ledger() {
        // The snapshot feature and the §2.1 capability ledger must speak the
        // same wire string, so persistence and protocol layers never translate
        // between two inventories for the same surface. Every typed resource
        // family (0.2 Processors/Memory and the Storage/Network iteration) is
        // asserted here so a new family cannot land with a private code.
        let families = [
            (ResourceFeature::Processors, EndpointCapability::Processors),
            (ResourceFeature::Memory, EndpointCapability::Memory),
            (ResourceFeature::Storages, EndpointCapability::Storages),
            (
                ResourceFeature::NetworkAdapters,
                EndpointCapability::NetworkAdapters,
            ),
            (
                ResourceFeature::EthernetInterfaces,
                EndpointCapability::EthernetInterfaces,
            ),
            (ResourceFeature::Accounts, EndpointCapability::Accounts),
            (ResourceFeature::Bios, EndpointCapability::Bios),
            (
                ResourceFeature::BootOptions,
                EndpointCapability::BootOptions,
            ),
            (ResourceFeature::SecureBoot, EndpointCapability::SecureBoot),
        ];
        for (feature, capability) in families {
            assert_eq!(feature.as_str(), capability.as_str());
            assert_eq!(feature.as_str().parse(), Ok(feature));
            assert_eq!(
                feature.as_str().parse::<EndpointCapability>(),
                Ok(capability)
            );
        }
    }

    #[test]
    fn rejects_unknown_and_near_miss_feature_codes() {
        // Singular forms and trailing punctuation would silently address a
        // different collection, so they must stay unparseable until a matching
        // resource family actually exists.
        for code in [
            "processor",
            "memories",
            "mem",
            "processors/",
            "memory-",
            "Processors",
            "Memory",
            "storage",
            "network-adapter",
            "ethernet-interface",
            "storages/",
            "network-adapters/",
            "ethernet-interfaces-",
            "Storages",
            "NetworkAdapters",
            "EthernetInterfaces",
            "account",
            "accounts/",
            "Accounts",
            "bios/",
            "BIOS",
            "bios-config",
            "boot-option",
            "boot-options/",
            "bootoptions",
            "BootOptions",
            "secure-boot/",
            "secureboot",
            "SecureBoot",
        ] {
            assert_eq!(
                code.parse::<ResourceFeature>(),
                Err(ResourceFeatureParseError),
                "{code} must not parse as a resource feature"
            );
        }
    }

    #[test]
    fn validates_exact_redfish_metadata_without_constructing_paths() -> Result<(), Box<dyn Error>> {
        let odata_id = ResourceODataId::parse("/redfish/v1/Systems/System.Embedded.1")?;
        let odata_type = ResourceODataType::parse("#ComputerSystem.v1_20_0.ComputerSystem")?;
        let etag = ResourceEtag::parse("W/\"generation-7\"")?;

        assert_eq!(odata_id.as_str(), "/redfish/v1/Systems/System.Embedded.1");
        assert_eq!(
            odata_type.as_str(),
            "#ComputerSystem.v1_20_0.ComputerSystem"
        );
        assert_eq!(etag.as_str(), "W/\"generation-7\"");
        assert_eq!(
            ResourceODataId::parse(" /redfish/v1/Systems/1"),
            Err(ResourceODataIdError::SurroundingWhitespace)
        );
        assert_eq!(
            ResourceODataType::parse("ComputerSystem.v1_20_0.ComputerSystem"),
            Err(ResourceODataTypeError::MissingTypeMarker)
        );
        assert_eq!(
            ResourceEtag::parse("generation\n7"),
            Err(ResourceEtagError::ControlCharacter)
        );
        Ok(())
    }

    #[test]
    fn canonicalizes_only_bounded_json_objects() -> Result<(), Box<dyn Error>> {
        let payload = ResourceSnapshotPayload::parse(r#"{ "Name": "System", "Id": "1" }"#)?;

        assert_eq!(payload.as_str(), r#"{"Id":"1","Name":"System"}"#);
        assert_eq!(
            format!("{payload:?}"),
            "ResourceSnapshotPayload { bytes: 26, .. }"
        );
        assert!(matches!(
            ResourceSnapshotPayload::parse("not json"),
            Err(ResourceSnapshotPayloadError::InvalidJson(_))
        ));
        assert!(matches!(
            ResourceSnapshotPayload::parse("[]"),
            Err(ResourceSnapshotPayloadError::NotObject)
        ));
        assert!(matches!(
            ResourceSnapshotPayload::parse(&format!(
                "{{\"value\":\"{}\"}}",
                "x".repeat(MAX_TYPED_PAYLOAD_BYTES)
            )),
            Err(ResourceSnapshotPayloadError::TooLarge { .. })
        ));
        Ok(())
    }

    #[test]
    fn snapshots_keep_identity_metadata_and_generation_together() -> Result<(), Box<dyn Error>> {
        let observed_at = OffsetDateTime::now_utc();
        let generation = RefreshGeneration::new(7)?;
        let snapshot = ResourceSnapshot::new(
            ResourceId::generate(),
            EndpointId::generate(),
            ResourceFeature::Systems,
            ResourceODataId::parse("/redfish/v1/Systems/1")?,
            ResourceSnapshotPayload::parse(r#"{"Id":"1","Name":"System"}"#)?,
            observed_at,
            generation,
        )
        .with_odata_type(ResourceODataType::parse(
            "#ComputerSystem.v1_20_0.ComputerSystem",
        )?)
        .with_etag(ResourceEtag::parse("\"seven\"")?);

        assert_eq!(snapshot.feature(), ResourceFeature::Systems);
        assert_eq!(snapshot.odata_id().as_str(), "/redfish/v1/Systems/1");
        assert_eq!(
            snapshot.odata_type().map(ResourceODataType::as_str),
            Some("#ComputerSystem.v1_20_0.ComputerSystem")
        );
        assert_eq!(snapshot.etag().map(ResourceEtag::as_str), Some("\"seven\""));
        assert_eq!(snapshot.payload().as_str(), r#"{"Id":"1","Name":"System"}"#);
        assert_eq!(snapshot.observed_at(), observed_at);
        assert_eq!(snapshot.generation(), generation);
        Ok(())
    }

    #[test]
    fn refresh_generations_are_positive_and_sqlite_compatible() {
        assert_eq!(RefreshGeneration::new(0), Err(RefreshGenerationError::Zero));
        assert_eq!(RefreshGeneration::new(1).map(RefreshGeneration::get), Ok(1));
        assert!(matches!(
            RefreshGeneration::new(i64::MAX as u64 + 1),
            Err(RefreshGenerationError::TooLarge { .. })
        ));
    }
}
