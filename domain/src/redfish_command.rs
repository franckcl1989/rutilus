//! The typed write surface of the product (§7.5, §13.1).
//!
//! Every write the product can perform is expressed as one value of
//! [`RedfishCommand`]. §7.5 makes business commands `enum`s so that the
//! compiler forces every exhaustive match site to handle a newly added
//! family; commands are never abstracted behind `Trait`s.
//!
//! The payloads are the domain's own typed projection of the corresponding
//! Redfish CSDL member sets. The domain re-declares the enums instead of
//! importing `nv-redfish` schema types because §7.2 keeps `nv-redfish` types
//! behind the Redfish Gateway and never inside the domain crate; the gateway
//! maps between the two vocabularies when dispatching. The member sets
//! follow the CSDL files shipped with `nv-redfish-schema` 0.13.0 exactly,
//! and the const member-set tests in this module fail when an upstream
//! member is added, renamed, or removed.
//!
//! A command is persisted inside an [`Operation`](crate::Operation) as its
//! serde JSON serialization (the §9.4 typed-payload rule applied to
//! commands). The serde wire names of the payload fields are the domain
//! projection; the gateway translates them to the CSDL property names (for
//! example `BootSourceOverrideTarget`) when dispatching.

use std::{error::Error, fmt, str::FromStr};

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::ArtifactId;

/// The reset action argument used by system, manager, and chassis resets.
///
/// The member set follows `nv-redfish-schema` 0.13.0's `Resource_v1.xml`
/// `ResetType` enum (compiled upstream as `nv_redfish::schema::resource::ResetType`),
/// including the deliberate absence of a plain `Off` member: `ResetType` has
/// no `Off` in the CSDL (`PowerState` does), so the member set mirrors the
/// schema exactly. The const member-set test keeps this aligned with the
/// CSDL.
// The variant names are the exact CSDL member names; renaming them would
// break the wire contract, so the shared `Force` prefix is accepted.
#[allow(clippy::enum_variant_names)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Deserialize, Serialize)]
pub enum ResetType {
    /// Turns the resource on.
    On,
    /// Turns the resource off immediately, without a graceful shutdown.
    ForceOff,
    /// Shuts the resource down gracefully.
    GracefulShutdown,
    /// Restarts the resource gracefully.
    GracefulRestart,
    /// Restarts the resource immediately, without a graceful shutdown.
    ForceRestart,
    /// Triggers a non-maskable interrupt.
    Nmi,
    /// Turns the resource on, forcing the power state.
    ForceOn,
    /// Simulates pressing the physical power button.
    PushPowerButton,
    /// Cycles power off and back on.
    PowerCycle,
    /// Suspends the resource to a low-power state.
    Suspend,
    /// Pauses the resource.
    Pause,
    /// Resumes the resource from pause or suspend.
    Resume,
    /// Removes power from the resource completely before restoring it.
    FullPowerCycle,
}

impl ResetType {
    /// Returns the exact CSDL member name, which is also the serde wire value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::On => "On",
            Self::ForceOff => "ForceOff",
            Self::GracefulShutdown => "GracefulShutdown",
            Self::GracefulRestart => "GracefulRestart",
            Self::ForceRestart => "ForceRestart",
            Self::Nmi => "Nmi",
            Self::ForceOn => "ForceOn",
            Self::PushPowerButton => "PushPowerButton",
            Self::PowerCycle => "PowerCycle",
            Self::Suspend => "Suspend",
            Self::Pause => "Pause",
            Self::Resume => "Resume",
            Self::FullPowerCycle => "FullPowerCycle",
        }
    }
}

impl fmt::Display for ResetType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The boot source selected by a boot source override.
///
/// The member set follows `nv-redfish-schema` 0.13.0's `ComputerSystem_v1.xml`
/// `BootSource` enum. The CSDL also defines the companion
/// `UefiTargetBootSourceOverride` property, which carries the concrete target
/// for [`Self::UefiTarget`]; the product does not set it in the first
/// iteration.
// The variant names are the exact CSDL member names; renaming them would
// break the wire contract, so the shared `Uefi` prefix is accepted.
#[allow(clippy::enum_variant_names)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Deserialize, Serialize)]
pub enum BootSource {
    /// No boot source is specified.
    None,
    /// Boots from a PXE network source.
    Pxe,
    /// Boots from a floppy drive.
    Floppy,
    /// Boots from a CD/DVD/optical drive.
    Cd,
    /// Boots from a USB device.
    Usb,
    /// Boots from a hard disk drive.
    Hdd,
    /// Boots into the BIOS setup utility.
    BiosSetup,
    /// Boots into a utility program.
    Utilities,
    /// Boots into a diagnostic program.
    Diags,
    /// Boots into the UEFI shell.
    UefiShell,
    /// Boots to the UEFI target named by the CSDL `UefiTargetBootSourceOverride`
    /// property.
    UefiTarget,
    /// Boots from an SD card.
    #[serde(rename = "SDCard")]
    SdCard,
    /// Boots from a UEFI HTTP network source.
    UefiHttp,
    /// Boots from a remote drive.
    RemoteDrive,
    /// Boots from the next UEFI boot option.
    UefiBootNext,
    /// Boots into a recovery mode.
    Recovery,
}

impl BootSource {
    /// Returns the exact CSDL member name, which is also the serde wire value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "None",
            Self::Pxe => "Pxe",
            Self::Floppy => "Floppy",
            Self::Cd => "Cd",
            Self::Usb => "Usb",
            Self::Hdd => "Hdd",
            Self::BiosSetup => "BiosSetup",
            Self::Utilities => "Utilities",
            Self::Diags => "Diags",
            Self::UefiShell => "UefiShell",
            Self::UefiTarget => "UefiTarget",
            Self::SdCard => "SDCard",
            Self::UefiHttp => "UefiHttp",
            Self::RemoteDrive => "RemoteDrive",
            Self::UefiBootNext => "UefiBootNext",
            Self::Recovery => "Recovery",
        }
    }
}

impl fmt::Display for BootSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// How long a boot source override applies.
///
/// The member set follows `nv-redfish-schema` 0.13.0's `ComputerSystem_v1.xml`
/// `BootSourceOverrideEnabled` enum.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Deserialize, Serialize)]
pub enum BootSourceOverrideEnabled {
    /// The boot source override is disabled.
    Disabled,
    /// Applies the override once, then reverts to the normal boot order.
    Once,
    /// Applies the override continuously until disabled.
    Continuous,
}

impl BootSourceOverrideEnabled {
    /// Returns the exact CSDL member name, which is also the serde wire value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "Disabled",
            Self::Once => "Once",
            Self::Continuous => "Continuous",
        }
    }
}

impl fmt::Display for BootSourceOverrideEnabled {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The boot mode a boot source override applies to.
///
/// The member set follows `nv-redfish-schema` 0.13.0's `ComputerSystem_v1.xml`
/// `BootSourceOverrideMode` enum; note that the CSDL member is `UEFI` (all
/// caps), not `Uefi`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Deserialize, Serialize)]
pub enum BootSourceOverrideMode {
    /// The override applies to legacy BIOS boot.
    Legacy,
    /// The override applies to UEFI boot.
    #[serde(rename = "UEFI")]
    Uefi,
}

impl BootSourceOverrideMode {
    /// Returns the exact CSDL member name, which is also the serde wire value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Legacy => "Legacy",
            Self::Uefi => "UEFI",
        }
    }
}

impl fmt::Display for BootSourceOverrideMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The key set reset requested from the Secure Boot service.
///
/// The member set follows `nv-redfish-schema` 0.13.0's `SecureBoot_v1.xml`
/// `ResetKeysType` enum (compiled upstream as the argument of the
/// `SecureBoot#ResetKeys` action).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Deserialize, Serialize)]
pub enum ResetKeysType {
    /// Resets all Secure Boot keys to their manufacturer defaults.
    ResetAllKeysToDefault,
    /// Deletes all Secure Boot keys.
    DeleteAllKeys,
    /// Deletes only the Platform Key (`PK`).
    #[serde(rename = "DeletePK")]
    DeletePk,
}

impl ResetKeysType {
    /// Returns the exact CSDL member name, which is also the serde wire value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ResetAllKeysToDefault => "ResetAllKeysToDefault",
            Self::DeleteAllKeys => "DeleteAllKeys",
            Self::DeletePk => "DeletePK",
        }
    }
}

impl fmt::Display for ResetKeysType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The protocol an event subscription delivers events through.
///
/// The member set follows `nv-redfish-schema` 0.13.0's `EventDestination_v1.xml`
/// `EventDestinationProtocol` enum.
// The variant names are the exact CSDL member names; renaming them would
// break the wire contract, so the shared `Syslog`/`SNMP` prefixes are
// accepted.
#[allow(clippy::enum_variant_names)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Deserialize, Serialize)]
pub enum EventDestinationProtocol {
    /// Delivers via Redfish event.
    Redfish,
    /// Delivers via Apache Kafka.
    Kafka,
    /// Delivers via `SNMPv1` traps.
    #[serde(rename = "SNMPv1")]
    Snmpv1,
    /// Delivers via `SNMPv2c` traps.
    #[serde(rename = "SNMPv2c")]
    Snmpv2c,
    /// Delivers via `SNMPv3`.
    #[serde(rename = "SNMPv3")]
    Snmpv3,
    /// Delivers via `SMTP` email.
    #[serde(rename = "SMTP")]
    Smtp,
    /// Delivers via syslog over TLS.
    #[serde(rename = "SyslogTLS")]
    SyslogTls,
    /// Delivers via syslog over TCP.
    #[serde(rename = "SyslogTCP")]
    SyslogTcp,
    /// Delivers via syslog over UDP.
    #[serde(rename = "SyslogUDP")]
    SyslogUdp,
    /// Delivers via syslog over RELP.
    #[serde(rename = "SyslogRELP")]
    SyslogRelp,
    /// Delivers via an OEM-defined protocol.
    #[serde(rename = "OEM")]
    Oem,
}

impl EventDestinationProtocol {
    /// Returns the exact CSDL member name, which is also the serde wire value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Redfish => "Redfish",
            Self::Kafka => "Kafka",
            Self::Snmpv1 => "SNMPv1",
            Self::Snmpv2c => "SNMPv2c",
            Self::Snmpv3 => "SNMPv3",
            Self::Smtp => "SMTP",
            Self::SyslogTls => "SyslogTLS",
            Self::SyslogTcp => "SyslogTCP",
            Self::SyslogUdp => "SyslogUDP",
            Self::SyslogRelp => "SyslogRELP",
            Self::Oem => "OEM",
        }
    }
}

impl fmt::Display for EventDestinationProtocol {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The Redfish event type an event subscription requests.
///
/// The member set follows `nv-redfish-schema` 0.13.0's `Event_v1.xml`
/// `EventType` enum.
// The variant names are the exact CSDL member names; renaming them would
// break the wire contract, so the shared `Resource` prefix is accepted.
#[allow(clippy::enum_variant_names)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Deserialize, Serialize)]
pub enum EventType {
    /// A resource status changed.
    StatusChange,
    /// A resource was updated.
    ResourceUpdated,
    /// A resource was added.
    ResourceAdded,
    /// A resource was removed.
    ResourceRemoved,
    /// An alert condition occurred.
    Alert,
    /// A metric report was produced.
    MetricReport,
    /// An event that matches no other type.
    Other,
}

impl EventType {
    /// Returns the exact CSDL member name, which is also the serde wire value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StatusChange => "StatusChange",
            Self::ResourceUpdated => "ResourceUpdated",
            Self::ResourceAdded => "ResourceAdded",
            Self::ResourceRemoved => "ResourceRemoved",
            Self::Alert => "Alert",
            Self::MetricReport => "MetricReport",
            Self::Other => "Other",
        }
    }
}

impl fmt::Display for EventType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The payload of [`BootCommand::SetBootSourceOverride`].
///
/// The three fields mirror the CSDL `Boot` object properties
/// `BootSourceOverrideTarget`, `BootSourceOverrideEnabled`, and
/// `BootSourceOverrideMode` (`ComputerSystem_v1.xml`). The CSDL marks each
/// property optional for a PATCH-style diff; a product command is the
/// complete intent, so all three are required — a partial override cannot be
/// expressed (§7.1).
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SetBootSourceOverride {
    source: BootSource,
    enabled: BootSourceOverrideEnabled,
    mode: BootSourceOverrideMode,
}

impl SetBootSourceOverride {
    /// Constructs a complete boot source override.
    #[must_use]
    pub const fn new(
        source: BootSource,
        enabled: BootSourceOverrideEnabled,
        mode: BootSourceOverrideMode,
    ) -> Self {
        Self {
            source,
            enabled,
            mode,
        }
    }

    /// Returns the boot source to override to (CSDL `BootSourceOverrideTarget`).
    #[must_use]
    pub const fn source(&self) -> BootSource {
        self.source
    }

    /// Returns how long the override applies.
    #[must_use]
    pub const fn enabled(&self) -> BootSourceOverrideEnabled {
        self.enabled
    }

    /// Returns the boot mode the override applies to.
    #[must_use]
    pub const fn mode(&self) -> BootSourceOverrideMode {
        self.mode
    }
}

/// The payload of [`EventCommand::CreateSubscription`].
///
/// `destination` is the subscription target URL, `protocol` the delivery
/// protocol, and `event_types` the set of events requested. Redfish CSDL
/// (`EventDestination_v1.xml`) marks `EventTypes` optional, but a
/// subscription that requests no events can never deliver anything, so the
/// product rejects it at construction.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateSubscription {
    destination: String,
    protocol: EventDestinationProtocol,
    event_types: Vec<EventType>,
}

impl CreateSubscription {
    /// Constructs a subscription request, rejecting empty event type sets.
    ///
    /// # Errors
    ///
    /// Returns [`EventSubscriptionError::EmptyEventTypes`] when no event type
    /// is requested.
    pub fn try_new(
        destination: String,
        protocol: EventDestinationProtocol,
        event_types: Vec<EventType>,
    ) -> Result<Self, EventSubscriptionError> {
        if event_types.is_empty() {
            return Err(EventSubscriptionError::EmptyEventTypes);
        }
        Ok(Self {
            destination,
            protocol,
            event_types,
        })
    }

    /// Returns the subscription target URL.
    #[must_use]
    pub const fn destination(&self) -> &str {
        self.destination.as_str()
    }

    /// Returns the delivery protocol.
    #[must_use]
    pub const fn protocol(&self) -> EventDestinationProtocol {
        self.protocol
    }

    /// Returns the requested event types.
    #[must_use]
    pub const fn event_types(&self) -> &[EventType] {
        self.event_types.as_slice()
    }
}

/// Why an event subscription request cannot be represented safely.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventSubscriptionError {
    /// A subscription must request at least one event type.
    EmptyEventTypes,
}

impl fmt::Display for EventSubscriptionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyEventTypes => {
                formatter.write_str("an event subscription must request at least one event type")
            }
        }
    }
}

impl Error for EventSubscriptionError {}

/// The payload of [`EventCommand::DeleteSubscription`].
///
/// `subscription_id` is the last path segment of the `EventSubscription`
/// resource's `@odata.id` (the segment after `.../EventSubscriptions/`),
/// kept as a string because Redfish does not define a typed identifier for
/// subscriptions.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeleteSubscription {
    subscription_id: String,
}

impl DeleteSubscription {
    /// Constructs a subscription deletion for one existing subscription.
    #[must_use]
    pub const fn new(subscription_id: String) -> Self {
        Self { subscription_id }
    }

    /// Returns the `@odata.id` tail segment of the subscription to delete.
    #[must_use]
    pub const fn subscription_id(&self) -> &str {
        self.subscription_id.as_str()
    }
}

/// The maximum length of one account id in Unicode scalar values.
///
/// The CSDL defines no bound on the `ManagerAccount` `Id` property, so the
/// bound is a product decision: an id is a short stable label, and the
/// product's own bounds stay generous enough for every id a BMC can
/// reasonably serve.
pub const MAX_ACCOUNT_ID_CHARS: usize = 128;

/// The maximum length of one account user name in Unicode scalar values.
///
/// The same product bound as [`crate::CredentialUsername`], because a
/// `ManagerAccount` `UserName` is the same kind of label the product already
/// sends to BMC authentication services.
pub const MAX_ACCOUNT_USER_NAME_CHARS: usize = 256;

/// The maximum length of one account password in Unicode scalar values.
///
/// The CSDL defines no bound on the `ManagerAccount` `Password` property
/// (an `Edm.String` marked `Redfish.RequiredOnCreate`), so the bound is a
/// product decision sized to the longest password a BMC can reasonably
/// store.
pub const MAX_ACCOUNT_PASSWORD_CHARS: usize = 256;

/// The maximum length of one role id in Unicode scalar values.
///
/// The CSDL defines no bound on the `ManagerAccount` `RoleId` property (an
/// `Edm.String` marked `Nullable=false`), so the bound is a product decision
/// sized to the role names Redfish defines and the custom roles a BMC can
/// add.
pub const MAX_ROLE_ID_CHARS: usize = 128;

/// The Redfish `Id` of one `ManagerAccount` collection member.
///
/// The id is the last path segment of the account's `@odata.id` — the same
/// identity the verification re-read matches against — so only one plain
/// segment may participate: the charset is ASCII alphanumerics, `-`, and
/// `_`, which excludes the separators and escape characters (`/`, `\`, `?`,
/// `#`, `%`) and the dot segments (`.`, `..`) that could redirect a
/// constructed URI outside the collection, and excludes whitespace and
/// control characters that could smuggle request structure. This is the
/// exact rule [`DeleteSubscription`] applies to subscription ids.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AccountId(String);

impl AccountId {
    /// Validates an account id as a single safe URI path segment.
    ///
    /// # Errors
    ///
    /// Returns [`AccountIdError`] for an empty id, a character outside the
    /// safe-segment charset, or an id longer than
    /// [`MAX_ACCOUNT_ID_CHARS`] Unicode scalar values.
    pub fn parse(value: &str) -> Result<Self, AccountIdError> {
        if value.is_empty() {
            return Err(AccountIdError::Empty);
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        {
            return Err(AccountIdError::UnsafeCharacter);
        }
        let actual = value.chars().count();
        if actual > MAX_ACCOUNT_ID_CHARS {
            return Err(AccountIdError::TooLong {
                actual,
                maximum: MAX_ACCOUNT_ID_CHARS,
            });
        }
        Ok(Self(value.to_owned()))
    }

    /// Returns the account id as its plain string form.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AccountId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for AccountId {
    type Err = AccountIdError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl Serialize for AccountId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for AccountId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

/// Why an account id cannot be used.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountIdError {
    /// The id is empty.
    Empty,
    /// The id contains a character outside the safe URI segment charset.
    UnsafeCharacter,
    /// The id is longer than the product bound.
    TooLong { actual: usize, maximum: usize },
}

impl fmt::Display for AccountIdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("account id cannot be empty"),
            Self::UnsafeCharacter => formatter
                .write_str("account id can only contain ASCII letters, digits, '-', and '_'"),
            Self::TooLong { actual, maximum } => write!(
                formatter,
                "account id has {actual} characters; maximum is {maximum}"
            ),
        }
    }
}

impl Error for AccountIdError {}

/// The `UserName` of one `ManagerAccount` (the CSDL `UserName` property, an
/// `Edm.String` marked `Nullable=false`).
///
/// The validation mirrors [`crate::CredentialUsername`] exactly: the user
/// name is a label sent to the BMC's account service, so the same bounds
/// apply.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AccountUserName(String);

impl AccountUserName {
    /// Validates an account user name without changing significant
    /// whitespace.
    ///
    /// # Errors
    ///
    /// Returns [`AccountUserNameError`] for an empty user name, a control
    /// character, or a value longer than
    /// [`MAX_ACCOUNT_USER_NAME_CHARS`] Unicode scalar values.
    pub fn parse(value: &str) -> Result<Self, AccountUserNameError> {
        if value.trim().is_empty() {
            return Err(AccountUserNameError::Empty);
        }
        if value.chars().any(char::is_control) {
            return Err(AccountUserNameError::ControlCharacter);
        }
        let actual = value.chars().count();
        if actual > MAX_ACCOUNT_USER_NAME_CHARS {
            return Err(AccountUserNameError::TooLong {
                actual,
                maximum: MAX_ACCOUNT_USER_NAME_CHARS,
            });
        }
        Ok(Self(value.to_owned()))
    }

    /// Returns the user name as its plain string form.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AccountUserName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for AccountUserName {
    type Err = AccountUserNameError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl Serialize for AccountUserName {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for AccountUserName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

/// Why an account user name cannot be used.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountUserNameError {
    /// The user name is empty.
    Empty,
    /// The user name contains a control character.
    ControlCharacter,
    /// The user name is longer than the product bound.
    TooLong { actual: usize, maximum: usize },
}

impl fmt::Display for AccountUserNameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("account user name cannot be empty"),
            Self::ControlCharacter => {
                formatter.write_str("account user name cannot contain control characters")
            }
            Self::TooLong { actual, maximum } => write!(
                formatter,
                "account user name has {actual} characters; maximum is {maximum}"
            ),
        }
    }
}

impl Error for AccountUserNameError {}

/// The `RoleId` of one `ManagerAccount` (the CSDL `RoleId` property, an
/// `Edm.String` marked `Nullable=false`).
///
/// A role id names one role of the BMC's `Role` collection; the product
/// treats it as an opaque label exactly like the CSDL (it never interprets
/// or renames a role).
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RoleId(String);

impl RoleId {
    /// Validates a role id without changing significant whitespace.
    ///
    /// # Errors
    ///
    /// Returns [`RoleIdError`] for an empty role id, a control character, or
    /// a value longer than [`MAX_ROLE_ID_CHARS`] Unicode scalar values.
    pub fn parse(value: &str) -> Result<Self, RoleIdError> {
        if value.trim().is_empty() {
            return Err(RoleIdError::Empty);
        }
        if value.chars().any(char::is_control) {
            return Err(RoleIdError::ControlCharacter);
        }
        let actual = value.chars().count();
        if actual > MAX_ROLE_ID_CHARS {
            return Err(RoleIdError::TooLong {
                actual,
                maximum: MAX_ROLE_ID_CHARS,
            });
        }
        Ok(Self(value.to_owned()))
    }

    /// Returns the role id as its plain string form.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RoleId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for RoleId {
    type Err = RoleIdError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl Serialize for RoleId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for RoleId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

/// Why a role id cannot be used.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RoleIdError {
    /// The role id is empty.
    Empty,
    /// The role id contains a control character.
    ControlCharacter,
    /// The role id is longer than the product bound.
    TooLong { actual: usize, maximum: usize },
}

impl fmt::Display for RoleIdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("role id cannot be empty"),
            Self::ControlCharacter => {
                formatter.write_str("role id cannot contain control characters")
            }
            Self::TooLong { actual, maximum } => write!(
                formatter,
                "role id has {actual} characters; maximum is {maximum}"
            ),
        }
    }
}

impl Error for RoleIdError {}

/// The password of one `ManagerAccount` — a §10 secret.
///
/// The value is wrapped in [`SecretString`] so it is zeroized on drop,
/// redacted in `Debug`, and never exposed through `Display`. The serde wire
/// form carries the exposed value exactly like every other payload field:
/// the command JSON is the §9.4 typed-payload contract shared by persistence
/// and the center protocol, and the at-rest protection of the command column
/// is the persistence crate's concern — the same split §10 keeps for the
/// endpoint credential, whose at-rest encryption lives in the persistence
/// crate and never in the domain command.
///
/// `PartialEq`/`Eq` compare the exposed values: command payloads are
/// compared for round-trip and state equality, never for authentication, so
/// a plain comparison is the honest implementation (the constant-time
/// comparison of §16 passwords lives in [`crate::Argon2IdHash::verify`]).
#[derive(Clone)]
pub struct AccountPassword(SecretString);

impl AccountPassword {
    /// Validates an account password.
    ///
    /// # Errors
    ///
    /// Returns [`AccountPasswordError`] for an empty password (a password
    /// that secures nothing) or a value longer than
    /// [`MAX_ACCOUNT_PASSWORD_CHARS`] Unicode scalar values.
    pub fn parse(value: String) -> Result<Self, AccountPasswordError> {
        if value.is_empty() {
            return Err(AccountPasswordError::Empty);
        }
        let actual = value.chars().count();
        if actual > MAX_ACCOUNT_PASSWORD_CHARS {
            return Err(AccountPasswordError::TooLong {
                actual,
                maximum: MAX_ACCOUNT_PASSWORD_CHARS,
            });
        }
        Ok(Self(SecretString::from(value)))
    }

    /// Returns the exposed password value; callers must never log it.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        self.0.expose_secret()
    }
}

impl fmt::Debug for AccountPassword {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AccountPassword([REDACTED])")
    }
}

impl PartialEq for AccountPassword {
    fn eq(&self, other: &Self) -> bool {
        self.expose_secret() == other.expose_secret()
    }
}

impl Eq for AccountPassword {}

impl Serialize for AccountPassword {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.expose_secret())
    }
}

impl<'de> Deserialize<'de> for AccountPassword {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(serde::de::Error::custom)
    }
}

/// Why an account password cannot be used.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountPasswordError {
    /// The password is empty.
    Empty,
    /// The password is longer than the product bound.
    TooLong { actual: usize, maximum: usize },
}

impl fmt::Display for AccountPasswordError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("account password cannot be empty"),
            Self::TooLong { actual, maximum } => write!(
                formatter,
                "account password has {actual} characters; maximum is {maximum}"
            ),
        }
    }
}

impl Error for AccountPasswordError {}

/// The payload of [`AccountCommand::CreateAccount`].
///
/// The three fields mirror the CSDL `ManagerAccount` create-required
/// properties `UserName`, `Password`, and `RoleId` (each marked
/// `Redfish.RequiredOnCreate` in `ManagerAccount_v1.xml`). Every other
/// create property of the CSDL is optional, so it stays out of the first-cut
/// typed projection: a product command is the complete intent, and a create
/// that leaves the identity, credential, or role open cannot be expressed
/// (§7.1).
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateAccount {
    user_name: AccountUserName,
    password: AccountPassword,
    role_id: RoleId,
}

impl CreateAccount {
    /// Constructs one account creation with the user name, password, and
    /// role.
    #[must_use]
    pub const fn new(
        user_name: AccountUserName,
        password: AccountPassword,
        role_id: RoleId,
    ) -> Self {
        Self {
            user_name,
            password,
            role_id,
        }
    }

    /// Returns the user name of the account to create.
    #[must_use]
    pub const fn user_name(&self) -> &AccountUserName {
        &self.user_name
    }

    /// Returns the password of the account to create.
    #[must_use]
    pub fn password(&self) -> &AccountPassword {
        &self.password
    }

    /// Returns the role of the account to create.
    #[must_use]
    pub const fn role_id(&self) -> &RoleId {
        &self.role_id
    }
}

/// The payload of [`AccountCommand::UpdateAccount`].
///
/// `account_id` names the existing `ManagerAccount` by its Redfish `Id`, and
/// `role_id` is the role the account must be changed to. The update is the
/// complete intent: a role change with an open target or an open role cannot
/// be expressed (§7.1).
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateAccount {
    account_id: AccountId,
    role_id: RoleId,
}

impl UpdateAccount {
    /// Constructs one role update of an existing account.
    #[must_use]
    pub const fn new(account_id: AccountId, role_id: RoleId) -> Self {
        Self {
            account_id,
            role_id,
        }
    }

    /// Returns the id of the account whose role is updated.
    #[must_use]
    pub const fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    /// Returns the role the account is changed to.
    #[must_use]
    pub const fn role_id(&self) -> &RoleId {
        &self.role_id
    }
}

/// The payload of [`AccountCommand::UpdateAccountPassword`].
///
/// `account_id` names the existing `ManagerAccount` by its Redfish `Id`, and
/// `password` is the new password. The CSDL `Password` property is
/// write-only (it is `null` in responses), so the verification re-read can
/// only confirm the account remains readable, never the stored password.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateAccountPassword {
    account_id: AccountId,
    password: AccountPassword,
}

impl UpdateAccountPassword {
    /// Constructs one password change of an existing account.
    #[must_use]
    pub const fn new(account_id: AccountId, password: AccountPassword) -> Self {
        Self {
            account_id,
            password,
        }
    }

    /// Returns the id of the account whose password is changed.
    #[must_use]
    pub const fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    /// Returns the new password.
    #[must_use]
    pub fn password(&self) -> &AccountPassword {
        &self.password
    }
}

/// The payload of [`AccountCommand::UpdateAccountUserName`].
///
/// `account_id` names the existing `ManagerAccount` by its Redfish `Id`, and
/// `user_name` is the new user name. The account `Id` itself is unchanged by
/// a rename on the BMCs the typed `nv-redfish` API targets, so the id stays
/// the identity the verification re-read matches against.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateAccountUserName {
    account_id: AccountId,
    user_name: AccountUserName,
}

impl UpdateAccountUserName {
    /// Constructs one user name change of an existing account.
    #[must_use]
    pub const fn new(account_id: AccountId, user_name: AccountUserName) -> Self {
        Self {
            account_id,
            user_name,
        }
    }

    /// Returns the id of the account whose user name is changed.
    #[must_use]
    pub const fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    /// Returns the new user name.
    #[must_use]
    pub const fn user_name(&self) -> &AccountUserName {
        &self.user_name
    }
}

/// The payload of [`AccountCommand::DeleteAccount`].
///
/// `account_id` names the existing `ManagerAccount` by its Redfish `Id`, the
/// same identity the verification re-read matches against.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeleteAccount {
    account_id: AccountId,
}

impl DeleteAccount {
    /// Constructs an account deletion for one existing account.
    #[must_use]
    pub const fn new(account_id: AccountId) -> Self {
        Self { account_id }
    }

    /// Returns the id of the account to delete.
    #[must_use]
    pub const fn account_id(&self) -> &AccountId {
        &self.account_id
    }
}

/// Serializes [`ArtifactId`] as its uuid string, the §9.4 typed-payload rule
/// applied to the command wire contract.
///
/// The id type itself stays serialization-free (it is a `Uuid` wrapper with
/// `Display`/`FromStr`), so the payload declares the wire form explicitly
/// instead of the domain exporting a serde surface for one field.
mod artifact_id_serde {
    use std::str::FromStr;

    use serde::{Deserialize, Deserializer, Serializer};

    use crate::ArtifactId;

    pub fn serialize<S>(artifact_id: &ArtifactId, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&artifact_id.to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<ArtifactId, D::Error>
    where
        D: Deserializer<'de>,
    {
        let text = String::deserialize(deserializer)?;
        ArtifactId::from_str(&text).map_err(serde::de::Error::custom)
    }
}

/// The payload of [`UpdateCommand::StartUpdate`].
///
/// `artifact_id` names a persisted, `Ready` firmware artifact (§14.3) whose
/// bytes the execution flow resolves from the artifact store at dispatch
/// time — the command carries only the database-serializable identity, never
/// file content. `push_uri` selects the submission method of §14.3: when the
/// BMC's `UpdateService` advertises a public HTTP push URI, the gateway
/// submits the artifact bytes to that URI directly; `None` selects the
/// multipart upload through the `UpdateService`'s `MultipartHttpPushUri`
/// action. The product never invents a push URI — the value comes from the
/// operator or from the BMC's own advertisement (§14.3 选择可用更新方法).
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StartUpdate {
    #[serde(with = "artifact_id_serde")]
    artifact_id: ArtifactId,
    /// The BMC's advertised HTTP push URI; `None` selects the multipart
    /// submission method and stays absent from the wire form.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    push_uri: Option<String>,
}

impl StartUpdate {
    /// Constructs one firmware-update start with the artifact to upload and
    /// the optional public push URI of the target `UpdateService`.
    #[must_use]
    pub const fn new(artifact_id: ArtifactId, push_uri: Option<String>) -> Self {
        Self {
            artifact_id,
            push_uri,
        }
    }

    /// Returns the identity of the artifact whose bytes must be uploaded.
    #[must_use]
    pub const fn artifact_id(&self) -> ArtifactId {
        self.artifact_id
    }

    /// Returns the BMC's advertised HTTP push URI, when one was supplied.
    #[must_use]
    pub fn push_uri(&self) -> Option<&str> {
        self.push_uri.as_deref()
    }
}

/// Commands against a system (`ComputerSystem`) resource (§7.5).
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub enum SystemCommand {
    /// Resets the system.
    Reset(ResetType),
}

/// Commands against a manager (`Manager`) resource (§7.5).
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub enum ManagerCommand {
    /// Resets the manager.
    Reset(ResetType),
}

/// Commands against a chassis (`Chassis`) resource (§7.5).
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub enum ChassisCommand {
    /// Resets the chassis.
    Reset(ResetType),
}

/// Commands against a system's boot configuration (§7.5).
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub enum BootCommand {
    /// Overrides the system boot source.
    SetBootSourceOverride(SetBootSourceOverride),
}

/// Commands against a system's Secure Boot configuration (§7.5).
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub enum SecureBootCommand {
    /// Enables Secure Boot.
    Enable,
    /// Disables Secure Boot.
    Disable,
    /// Resets one or more Secure Boot key sets.
    ResetKeys(ResetKeysType),
}

/// Commands against the event service (§7.5).
///
/// Redfish models subscriptions as `EventDestination` resources; see
/// [`crate::ResourceFeature::EventSubscription`] for the matching read
/// surface.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub enum EventCommand {
    /// Creates one event subscription.
    CreateSubscription(CreateSubscription),
    /// Deletes one existing event subscription.
    DeleteSubscription(DeleteSubscription),
}

/// Commands against the account service (§7.5).
///
/// Redfish models accounts as `ManagerAccount` resources under the
/// `AccountService` `Accounts` collection; see
/// [`crate::ResourceFeature::Accounts`] for the matching read surface.
/// The five writes mirror the typed `nv-redfish` 0.13.0 account API
/// (`AccountCollection::create_account`, `Account::update`,
/// `Account::update_password`, `Account::update_user_name`, and
/// `Account::delete`) one-to-one, so the gateway maps the domain payloads
/// onto the compiled `ManagerAccountCreate`/`ManagerAccountUpdate` types
/// without inventing a wire shape (§7.4).
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub enum AccountCommand {
    /// Creates one account with a user name, password, and role.
    CreateAccount(CreateAccount),
    /// Changes the role of one existing account.
    UpdateAccount(UpdateAccount),
    /// Changes the password of one existing account.
    UpdateAccountPassword(UpdateAccountPassword),
    /// Renames one existing account.
    UpdateAccountUserName(UpdateAccountUserName),
    /// Deletes one existing account.
    DeleteAccount(DeleteAccount),
}

/// Commands against the update service (§7.5, §14.3).
///
/// Redfish models firmware updates through the `UpdateService`; see
/// [`crate::ResourceFeature::SoftwareInventory`] for the matching read
/// surface.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub enum UpdateCommand {
    /// Starts a firmware update with one previously uploaded, ready artifact.
    StartUpdate(StartUpdate),
}

/// The debug token type requested by the [`NvidiaDebugTokenCommand`] actions.
///
/// The member set follows `nv-redfish-schema` 0.13.0's
/// `NvidiaDebugTokenManagement_v1.xml` `TokenType` enum. The variant names
/// are the exact CSDL member names; the all-caps acronym members (`FRC`,
/// `CRCS`, `CRDT`, `MTDT`, `NVJtagControl`, ...) carry serde renames because
/// the Rust identifiers stay readable while the wire form is pinned by the
/// member-set test, exactly like `SDCard` and `SyslogTLS`.
// The variant names are the exact CSDL member names; renaming them would
// break the wire contract, so the shared `Debug`/`Unlock`/`Capability`
// suffixes are accepted.
#[allow(clippy::enum_variant_names)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Deserialize, Serialize)]
pub enum TokenType {
    /// The `FRC` token type.
    #[serde(rename = "FRC")]
    Frc,
    /// The `CRCS` token type.
    #[serde(rename = "CRCS")]
    Crcs,
    /// The `CRDT` token type.
    #[serde(rename = "CRDT")]
    Crdt,
    /// The `DebugFirmwareRunning` token type.
    DebugFirmwareRunning,
    /// The `DebugFirmwareUnlock` token type.
    DebugFirmwareUnlock,
    /// The `OTPDumpEnable` token type.
    #[serde(rename = "OTPDumpEnable")]
    OtpDumpEnable,
    /// The `JtagUnlock` token type.
    JtagUnlock,
    /// The `HardwareUnlock` token type.
    HardwareUnlock,
    /// The `RuntimeDebugUnlock` token type.
    RuntimeDebugUnlock,
    /// The `FeatureUnlock` token type.
    FeatureUnlock,
    /// The `MTDT` token type.
    #[serde(rename = "MTDT")]
    Mtdt,
    /// The `CcplexArmJtagDebugCont` token type.
    CcplexArmJtagDebugCont,
    /// The `NVJtagControl` token type.
    #[serde(rename = "NVJtagControl")]
    NvJtagControl,
    /// The `DiagnosticBoot` token type.
    DiagnosticBoot,
    /// The `BpmpFirmwareDebugFS` token type.
    #[serde(rename = "BpmpFirmwareDebugFS")]
    BpmpFirmwareDebugFs,
    /// The `FirmwareDebugKnobs` token type.
    FirmwareDebugKnobs,
    /// The `FirewallLifting` token type.
    FirewallLifting,
    /// The `Verbosity` token type.
    Verbosity,
    /// The `SMADebugCapability` token type.
    #[serde(rename = "SMADebugCapability")]
    SmaDebugCapability,
    /// The `CpldDebugCapability` token type.
    CpldDebugCapability,
}

impl TokenType {
    /// Returns the exact CSDL member name, which is also the serde wire value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Frc => "FRC",
            Self::Crcs => "CRCS",
            Self::Crdt => "CRDT",
            Self::DebugFirmwareRunning => "DebugFirmwareRunning",
            Self::DebugFirmwareUnlock => "DebugFirmwareUnlock",
            Self::OtpDumpEnable => "OTPDumpEnable",
            Self::JtagUnlock => "JtagUnlock",
            Self::HardwareUnlock => "HardwareUnlock",
            Self::RuntimeDebugUnlock => "RuntimeDebugUnlock",
            Self::FeatureUnlock => "FeatureUnlock",
            Self::Mtdt => "MTDT",
            Self::CcplexArmJtagDebugCont => "CcplexArmJtagDebugCont",
            Self::NvJtagControl => "NVJtagControl",
            Self::DiagnosticBoot => "DiagnosticBoot",
            Self::BpmpFirmwareDebugFs => "BpmpFirmwareDebugFS",
            Self::FirmwareDebugKnobs => "FirmwareDebugKnobs",
            Self::FirewallLifting => "FirewallLifting",
            Self::Verbosity => "Verbosity",
            Self::SmaDebugCapability => "SMADebugCapability",
            Self::CpldDebugCapability => "CpldDebugCapability",
        }
    }
}

impl fmt::Display for TokenType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The erase scope of [`NvidiaDebugTokenCommand::EraseToken`].
///
/// The member set follows `nv-redfish-schema` 0.13.0's
/// `NvidiaDebugTokenManagement_v1.xml` `EraseType` enum. The `TokenType`
/// member erases the installed tokens of the token type named by the action's
/// `TokenType` parameter; its variant name is the CSDL member name and
/// deliberately collides with the [`TokenType`] enum's own name.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Deserialize, Serialize)]
pub enum EraseType {
    /// Erases all installed tokens from the endpoint device.
    EraseAll,
    /// Erases all installed tokens and increments the ratchet counter.
    EraseAllAndRatchetCounterIncreased,
    /// Erases the installed tokens of the token type named by the action's
    /// `TokenType` parameter.
    TokenType,
}

impl EraseType {
    /// Returns the exact CSDL member name, which is also the serde wire value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EraseAll => "EraseAll",
            Self::EraseAllAndRatchetCounterIncreased => "EraseAllAndRatchetCounterIncreased",
            Self::TokenType => "TokenType",
        }
    }
}

impl fmt::Display for EraseType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The payload of [`NvidiaSystemConfigProfileCommand::Update`].
///
/// `profile_file` is the JSON string of the profile file (the CSDL
/// `ProfileFile` parameter, an `Edm.String` marked `Nullable=false`): the
/// profile carries the metadata whose delete and activation flags decide
/// whether the update adds, activates, or deletes the profile. The domain
/// requires the file content exactly like the boot override requires all
/// three of its fields — a profile-less update cannot be expressed (§7.1).
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileFile {
    profile_file: String,
}

impl ProfileFile {
    /// Constructs one profile update with the JSON profile file content.
    #[must_use]
    pub const fn new(profile_file: String) -> Self {
        Self { profile_file }
    }

    /// Returns the JSON string of the profile file.
    #[must_use]
    pub const fn profile_file(&self) -> &str {
        self.profile_file.as_str()
    }
}

/// The payload of [`NvidiaDebugTokenCommand::InstallToken`].
///
/// `token_data` is the Base64-encoded string of the token data (the CSDL
/// `TokenData` parameter, an `Edm.String` marked `Nullable=false`). The
/// product treats the value as an opaque Base64 payload exactly like the
/// CSDL; it never decodes or re-encodes the token (§11.5 two-way rule).
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TokenData {
    token_data: String,
}

impl TokenData {
    /// Constructs one token installation with the Base64 token data.
    #[must_use]
    pub const fn new(token_data: String) -> Self {
        Self { token_data }
    }

    /// Returns the Base64-encoded token data.
    #[must_use]
    pub const fn token_data(&self) -> &str {
        self.token_data.as_str()
    }
}

/// The payload of [`NvidiaDebugTokenCommand::EraseToken`].
///
/// The two fields mirror the CSDL `EraseToken` action parameters `EraseType`
/// and `TokenType` (`NvidiaDebugTokenManagement_v1.xml`); both are marked
/// `Nullable=false`, and a product command is the complete intent, so both
/// are required — an erase that leaves the scope open cannot be expressed
/// (§7.1).
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EraseToken {
    erase_type: EraseType,
    token_type: TokenType,
}

impl EraseToken {
    /// Constructs one token erase with the erase scope and token type.
    #[must_use]
    pub const fn new(erase_type: EraseType, token_type: TokenType) -> Self {
        Self {
            erase_type,
            token_type,
        }
    }

    /// Returns the erase scope.
    #[must_use]
    pub const fn erase_type(&self) -> EraseType {
        self.erase_type
    }

    /// Returns the token type whose tokens are erased.
    #[must_use]
    pub const fn token_type(&self) -> TokenType {
        self.token_type
    }
}

/// The payload of [`NvidiaPowerSmoothingCommand::ActivatePresetProfile`].
///
/// `profile_id` mirrors the CSDL `ActivatePresetProfile` action parameter
/// `ProfileId` (`NvidiaPowerSmoothing_v1.xml`, an `Edm.Int64`). The CSDL
/// marks the parameter optional, but a product command is the complete
/// intent, so the domain requires the id — an activation without a target
/// profile cannot be expressed (§7.1).
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileId {
    profile_id: i64,
}

impl ProfileId {
    /// Constructs one preset-profile activation with the profile id.
    #[must_use]
    pub const fn new(profile_id: i64) -> Self {
        Self { profile_id }
    }

    /// Returns the id of the preset profile to activate.
    #[must_use]
    pub const fn profile_id(&self) -> i64 {
        self.profile_id
    }
}

/// Commands against the NVIDIA system config profile service (§11.5, the
/// §0.5.0 `oem-nvidia-profiles` write surface).
///
/// The face targets the `NvidiaSystemConfigProfile` chain root of the
/// system's `Oem.Nvidia` segment: `Update` and `FactoryReset` run the two
/// CSDL actions of the profile service document, and `ActivateProfile` runs
/// the `#NvidiaSystemProfile.Activate` action of the first member of the
/// service's `Profiles` collection — the endpoint-scoped write rule of
/// [`crate::ResourceFeature`], exactly like the reset families' first-member
/// targeting.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub enum NvidiaSystemConfigProfileCommand {
    /// Adds, activates, or deletes one profile from its JSON file content.
    Update(ProfileFile),
    /// Performs a factory reset of the system, including the DPU and NIC,
    /// re-activating the default profile when one is installed.
    FactoryReset,
    /// Activates the endpoint's first profile member and applies its
    /// configuration.
    ActivateProfile,
}

/// Commands against the NVIDIA debug token surfaces (§11.5, the §0.5.0
/// `oem-nvidia-security` write surface).
///
/// `GenerateToken`, `InstallToken`, and `DisableToken` run the CSDL actions
/// of the device `NvidiaDebugToken` document behind the system's
/// `Oem.Nvidia` `CPUDebugToken` navigation; `EraseToken` runs the
/// `#NvidiaDebugTokenManagement.EraseToken` action of the manager's
/// `Oem.Nvidia` `DebugTokenManagement` document.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub enum NvidiaDebugTokenCommand {
    /// Generates a debug-token challenge of one token type.
    GenerateToken(TokenType),
    /// Installs one Base64-encoded debug token.
    InstallToken(TokenData),
    /// Disables the currently active token.
    DisableToken,
    /// Erases installed tokens, scoped to one token type when requested.
    EraseToken(EraseToken),
}

/// Commands against the NVIDIA power smoothing resource (§11.5, the §0.5.0
/// `oem-nvidia-power-management` write surface).
///
/// The face targets the `NvidiaPowerSmoothing` document behind the chassis's
/// `Oem.Nvidia` segment and runs its two CSDL actions.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub enum NvidiaPowerSmoothingCommand {
    /// Activates one preset power profile by its id.
    ActivatePresetProfile(ProfileId),
    /// Applies all cached administrator override values at runtime.
    ApplyAdminOverrides,
}

/// The vendor write faces of the `Oem` command family (§7.5, §11.5).
///
/// Every variant is a compiled upstream vendor family whose CSDL actions are
/// typed by `nv-redfish-schema` 0.13.0; the §7.5 deferred-list note below
/// names the vendors whose write surfaces stay uncompiled. The three faces
/// are deliberately independent types: they target different CSDL resources
/// (`NvidiaSystemConfigProfile`, `NvidiaDebugToken` /
/// `NvidiaDebugTokenManagement`, `NvidiaPowerSmoothing`) whose action sets
/// diverge, exactly like the three reset families.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub enum OemCommand {
    /// A command against the NVIDIA system config profile service.
    SystemConfigProfile(NvidiaSystemConfigProfileCommand),
    /// A command against the NVIDIA debug token surfaces.
    DebugToken(NvidiaDebugTokenCommand),
    /// A command against the NVIDIA power smoothing resource.
    PowerSmoothing(NvidiaPowerSmoothingCommand),
}

/// One typed write command — the exhaustive §7.5 command surface.
///
/// Every write the product performs is one value of this enum, and every
/// dispatch, persistence, and audit site matches it exhaustively, so adding
/// an upstream feature compiles only after every match site handles the new
/// family. The three reset families are deliberately independent types:
/// [`SystemCommand::Reset`], [`ManagerCommand::Reset`], and
/// [`ChassisCommand::Reset`] target different CSDL resources whose action
/// sets diverge, and sharing one variant would let a match site conflate
/// them.
///
/// The §7.5 families that are absent from this iteration are not stubbed as
/// empty enums: a variant is added only when a real typed command exists,
/// because an arm that no payload can ever fill would only mislead the
/// exhaustive matches. The deferred families and their reasons:
///
/// - `Bios` — BIOS writes are an unbounded attribute bag (the CSDL
///   `Attributes` property), which conflicts with the strict typed projection
///   of this module; the surface lands when a bounded attribute projection
///   exists.
/// - `Storage` — storage writes (volume and `RAID` operations) have no
///   first-cut product flow.
/// - `Telemetry` — telemetry writes (metric report subscription lifecycle)
///   build on the event-service surface and land with it.
///
/// The `Account` family is no longer deferred: account writes carry
/// passwords, which are §10 secrets handled by the secret infrastructure
/// that landed with the credential milestone — the domain wraps them in
/// [`AccountPassword`] (a zeroizing `SecretString` with a redacted `Debug`),
/// and the §10 at-rest encryption of the persisted command column is the
/// persistence crate's concern, exactly like the endpoint credential.
///
/// The `Oem` family is no longer deferred either: upstream NVIDIA typed
/// actions are compiled in (see [`OemCommand`]), and the remaining vendors'
/// OEM write surfaces land as their actions get compiled.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub enum RedfishCommand {
    /// A command against the account service.
    Account(AccountCommand),
    /// A command against a system resource.
    System(SystemCommand),
    /// A command against a manager resource.
    Manager(ManagerCommand),
    /// A command against a chassis resource.
    Chassis(ChassisCommand),
    /// A command against a system's boot configuration.
    Boot(BootCommand),
    /// A command against a system's Secure Boot configuration.
    SecureBoot(SecureBootCommand),
    /// A command against the event service.
    Event(EventCommand),
    /// A command against the update service.
    Update(UpdateCommand),
    /// A command against a compiled vendor OEM surface (§11.5).
    Oem(OemCommand),
}

impl RedfishCommand {
    /// Returns the stable product code of the command family.
    ///
    /// The codes are the wire contract used by persistence and protocols and
    /// never change across milestones. The `event` code is deliberately
    /// narrower than the §2.1 `event-service` capability code: the capability
    /// covers the whole event-service surface, while the command family
    /// covers only the write operations — the same narrowing as the
    /// subsidiary read families of [`crate::ResourceFeature`].
    ///
    /// There is no `FromStr` counterpart: a code alone cannot reconstruct a
    /// command because every family payload is required, so the serde
    /// `Deserialize` of the full typed command is the rehydration path.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Account(_) => "account",
            Self::System(_) => "system",
            Self::Manager(_) => "manager",
            Self::Chassis(_) => "chassis",
            Self::Boot(_) => "boot",
            Self::SecureBoot(_) => "secure-boot",
            Self::Event(_) => "event",
            Self::Update(_) => "update",
            Self::Oem(_) => "oem",
        }
    }
}

impl fmt::Display for RedfishCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use std::{error::Error, fmt};

    use uuid::Uuid;

    use super::*;

    /// The exact `ResetType` member set of `nv-redfish-schema` 0.13.0
    /// `Resource_v1.xml` (compiled upstream as
    /// `nv_redfish::schema::resource::ResetType`).
    const RESET_TYPE_MEMBERS: [(ResetType, &str); 13] = [
        (ResetType::On, "On"),
        (ResetType::ForceOff, "ForceOff"),
        (ResetType::GracefulShutdown, "GracefulShutdown"),
        (ResetType::GracefulRestart, "GracefulRestart"),
        (ResetType::ForceRestart, "ForceRestart"),
        (ResetType::Nmi, "Nmi"),
        (ResetType::ForceOn, "ForceOn"),
        (ResetType::PushPowerButton, "PushPowerButton"),
        (ResetType::PowerCycle, "PowerCycle"),
        (ResetType::Suspend, "Suspend"),
        (ResetType::Pause, "Pause"),
        (ResetType::Resume, "Resume"),
        (ResetType::FullPowerCycle, "FullPowerCycle"),
    ];

    /// The exact `BootSource` member set of `nv-redfish-schema` 0.13.0
    /// `ComputerSystem_v1.xml`.
    const BOOT_SOURCE_MEMBERS: [(BootSource, &str); 16] = [
        (BootSource::None, "None"),
        (BootSource::Pxe, "Pxe"),
        (BootSource::Floppy, "Floppy"),
        (BootSource::Cd, "Cd"),
        (BootSource::Usb, "Usb"),
        (BootSource::Hdd, "Hdd"),
        (BootSource::BiosSetup, "BiosSetup"),
        (BootSource::Utilities, "Utilities"),
        (BootSource::Diags, "Diags"),
        (BootSource::UefiShell, "UefiShell"),
        (BootSource::UefiTarget, "UefiTarget"),
        (BootSource::SdCard, "SDCard"),
        (BootSource::UefiHttp, "UefiHttp"),
        (BootSource::RemoteDrive, "RemoteDrive"),
        (BootSource::UefiBootNext, "UefiBootNext"),
        (BootSource::Recovery, "Recovery"),
    ];

    /// The exact `BootSourceOverrideEnabled` member set of
    /// `nv-redfish-schema` 0.13.0 `ComputerSystem_v1.xml`.
    const BOOT_SOURCE_OVERRIDE_ENABLED_MEMBERS: [(BootSourceOverrideEnabled, &str); 3] = [
        (BootSourceOverrideEnabled::Disabled, "Disabled"),
        (BootSourceOverrideEnabled::Once, "Once"),
        (BootSourceOverrideEnabled::Continuous, "Continuous"),
    ];

    /// The exact `BootSourceOverrideMode` member set of `nv-redfish-schema`
    /// 0.13.0 `ComputerSystem_v1.xml`; note the all-caps `UEFI` member.
    const BOOT_SOURCE_OVERRIDE_MODE_MEMBERS: [(BootSourceOverrideMode, &str); 2] = [
        (BootSourceOverrideMode::Legacy, "Legacy"),
        (BootSourceOverrideMode::Uefi, "UEFI"),
    ];

    /// The exact `ResetKeysType` member set of `nv-redfish-schema` 0.13.0
    /// `SecureBoot_v1.xml`; note the `DeletePK` member.
    const RESET_KEYS_TYPE_MEMBERS: [(ResetKeysType, &str); 3] = [
        (
            ResetKeysType::ResetAllKeysToDefault,
            "ResetAllKeysToDefault",
        ),
        (ResetKeysType::DeleteAllKeys, "DeleteAllKeys"),
        (ResetKeysType::DeletePk, "DeletePK"),
    ];

    /// The exact `EventDestinationProtocol` member set of
    /// `nv-redfish-schema` 0.13.0 `EventDestination_v1.xml`.
    const EVENT_DESTINATION_PROTOCOL_MEMBERS: [(EventDestinationProtocol, &str); 11] = [
        (EventDestinationProtocol::Redfish, "Redfish"),
        (EventDestinationProtocol::Kafka, "Kafka"),
        (EventDestinationProtocol::Snmpv1, "SNMPv1"),
        (EventDestinationProtocol::Snmpv2c, "SNMPv2c"),
        (EventDestinationProtocol::Snmpv3, "SNMPv3"),
        (EventDestinationProtocol::Smtp, "SMTP"),
        (EventDestinationProtocol::SyslogTls, "SyslogTLS"),
        (EventDestinationProtocol::SyslogTcp, "SyslogTCP"),
        (EventDestinationProtocol::SyslogUdp, "SyslogUDP"),
        (EventDestinationProtocol::SyslogRelp, "SyslogRELP"),
        (EventDestinationProtocol::Oem, "OEM"),
    ];

    /// The exact `EventType` member set of `nv-redfish-schema` 0.13.0
    /// `Event_v1.xml`.
    const EVENT_TYPE_MEMBERS: [(EventType, &str); 7] = [
        (EventType::StatusChange, "StatusChange"),
        (EventType::ResourceUpdated, "ResourceUpdated"),
        (EventType::ResourceAdded, "ResourceAdded"),
        (EventType::ResourceRemoved, "ResourceRemoved"),
        (EventType::Alert, "Alert"),
        (EventType::MetricReport, "MetricReport"),
        (EventType::Other, "Other"),
    ];

    /// The exact `TokenType` member set of `nv-redfish-schema` 0.13.0
    /// `NvidiaDebugTokenManagement_v1.xml`; note the all-caps acronym members
    /// (`FRC`, `CRCS`, `CRDT`, `MTDT`, `NVJtagControl`, ...).
    const TOKEN_TYPE_MEMBERS: [(TokenType, &str); 20] = [
        (TokenType::Frc, "FRC"),
        (TokenType::Crcs, "CRCS"),
        (TokenType::Crdt, "CRDT"),
        (TokenType::DebugFirmwareRunning, "DebugFirmwareRunning"),
        (TokenType::DebugFirmwareUnlock, "DebugFirmwareUnlock"),
        (TokenType::OtpDumpEnable, "OTPDumpEnable"),
        (TokenType::JtagUnlock, "JtagUnlock"),
        (TokenType::HardwareUnlock, "HardwareUnlock"),
        (TokenType::RuntimeDebugUnlock, "RuntimeDebugUnlock"),
        (TokenType::FeatureUnlock, "FeatureUnlock"),
        (TokenType::Mtdt, "MTDT"),
        (TokenType::CcplexArmJtagDebugCont, "CcplexArmJtagDebugCont"),
        (TokenType::NvJtagControl, "NVJtagControl"),
        (TokenType::DiagnosticBoot, "DiagnosticBoot"),
        (TokenType::BpmpFirmwareDebugFs, "BpmpFirmwareDebugFS"),
        (TokenType::FirmwareDebugKnobs, "FirmwareDebugKnobs"),
        (TokenType::FirewallLifting, "FirewallLifting"),
        (TokenType::Verbosity, "Verbosity"),
        (TokenType::SmaDebugCapability, "SMADebugCapability"),
        (TokenType::CpldDebugCapability, "CpldDebugCapability"),
    ];

    /// The exact `EraseType` member set of `nv-redfish-schema` 0.13.0
    /// `NvidiaDebugTokenManagement_v1.xml`; note the `TokenType` member.
    const ERASE_TYPE_MEMBERS: [(EraseType, &str); 3] = [
        (EraseType::EraseAll, "EraseAll"),
        (
            EraseType::EraseAllAndRatchetCounterIncreased,
            "EraseAllAndRatchetCounterIncreased",
        ),
        (EraseType::TokenType, "TokenType"),
    ];

    /// Asserts that every member serializes to exactly its CSDL wire name,
    /// deserializes back from it, and that unknown member names are rejected.
    fn assert_csdl_member_set<T>(members: &[(T, &str)]) -> Result<(), Box<dyn Error>>
    where
        T: Copy + fmt::Display + fmt::Debug + PartialEq + Serialize + for<'de> Deserialize<'de>,
    {
        let mut seen = Vec::new();
        for (member, wire) in members {
            assert!(!wire.is_empty(), "CSDL member names must not be empty");
            assert!(
                !seen.contains(wire),
                "wire name {wire} is used by more than one member"
            );
            seen.push(wire);
            assert_eq!(member.to_string(), *wire);
            assert_eq!(serde_json::to_string(member)?, format!("\"{wire}\""));
            assert_eq!(serde_json::from_str::<T>(&format!("\"{wire}\""))?, *member);
        }
        assert!(
            serde_json::from_str::<T>("\"Unknown\"").is_err(),
            "an unknown member must be rejected, not silently accepted"
        );
        Ok(())
    }

    #[test]
    fn reset_type_members_follow_the_csdl() -> Result<(), Box<dyn Error>> {
        assert_csdl_member_set(&RESET_TYPE_MEMBERS)
    }

    #[test]
    fn boot_source_members_follow_the_csdl() -> Result<(), Box<dyn Error>> {
        assert_csdl_member_set(&BOOT_SOURCE_MEMBERS)
    }

    #[test]
    fn boot_source_override_enabled_members_follow_the_csdl() -> Result<(), Box<dyn Error>> {
        assert_csdl_member_set(&BOOT_SOURCE_OVERRIDE_ENABLED_MEMBERS)
    }

    #[test]
    fn boot_source_override_mode_members_follow_the_csdl() -> Result<(), Box<dyn Error>> {
        assert_csdl_member_set(&BOOT_SOURCE_OVERRIDE_MODE_MEMBERS)
    }

    #[test]
    fn reset_keys_type_members_follow_the_csdl() -> Result<(), Box<dyn Error>> {
        assert_csdl_member_set(&RESET_KEYS_TYPE_MEMBERS)
    }

    #[test]
    fn event_destination_protocol_members_follow_the_csdl() -> Result<(), Box<dyn Error>> {
        assert_csdl_member_set(&EVENT_DESTINATION_PROTOCOL_MEMBERS)
    }

    #[test]
    fn event_type_members_follow_the_csdl() -> Result<(), Box<dyn Error>> {
        assert_csdl_member_set(&EVENT_TYPE_MEMBERS)
    }

    #[test]
    fn token_type_members_follow_the_csdl() -> Result<(), Box<dyn Error>> {
        assert_csdl_member_set(&TOKEN_TYPE_MEMBERS)
    }

    #[test]
    fn erase_type_members_follow_the_csdl() -> Result<(), Box<dyn Error>> {
        assert_csdl_member_set(&ERASE_TYPE_MEMBERS)
    }

    /// One representative command per family with its expected family code.
    ///
    /// The nine entries are the exhaustive §7.5 family list for this
    /// iteration; adding a family must add an entry here or the
    /// exhaustiveness tests fail.
    fn all_families() -> Result<Vec<(RedfishCommand, &'static str)>, Box<dyn Error>> {
        Ok(vec![
            (
                RedfishCommand::Account(AccountCommand::CreateAccount(CreateAccount::new(
                    AccountUserName::parse("jane")?,
                    AccountPassword::parse("initial-secret".to_owned())?,
                    RoleId::parse("Operator")?,
                ))),
                "account",
            ),
            (
                RedfishCommand::System(SystemCommand::Reset(ResetType::PowerCycle)),
                "system",
            ),
            (
                RedfishCommand::Manager(ManagerCommand::Reset(ResetType::GracefulRestart)),
                "manager",
            ),
            (
                RedfishCommand::Chassis(ChassisCommand::Reset(ResetType::ForceOff)),
                "chassis",
            ),
            (
                RedfishCommand::Boot(BootCommand::SetBootSourceOverride(
                    SetBootSourceOverride::new(
                        BootSource::Pxe,
                        BootSourceOverrideEnabled::Once,
                        BootSourceOverrideMode::Uefi,
                    ),
                )),
                "boot",
            ),
            (
                RedfishCommand::SecureBoot(SecureBootCommand::ResetKeys(
                    ResetKeysType::ResetAllKeysToDefault,
                )),
                "secure-boot",
            ),
            (
                RedfishCommand::Event(EventCommand::CreateSubscription(
                    CreateSubscription::try_new(
                        "https://192.0.2.10/events".to_owned(),
                        EventDestinationProtocol::Redfish,
                        vec![EventType::Alert],
                    )?,
                )),
                "event",
            ),
            (
                RedfishCommand::Update(UpdateCommand::StartUpdate(StartUpdate::new(
                    ArtifactId::generate(),
                    None,
                ))),
                "update",
            ),
            (
                RedfishCommand::Oem(OemCommand::SystemConfigProfile(
                    NvidiaSystemConfigProfileCommand::Update(ProfileFile::new(
                        r#"{"UUID":"11111111-2222-3333-4444-555555555555"}"#.to_owned(),
                    )),
                )),
                "oem",
            ),
        ])
    }

    #[test]
    fn family_codes_are_stable_unique_and_match_the_expected_vocabulary()
    -> Result<(), Box<dyn Error>> {
        let mut seen = Vec::new();
        for (command, expected) in all_families()? {
            let code = command.as_str();
            assert!(!code.is_empty(), "command family codes must not be empty");
            assert!(
                !seen.contains(&code),
                "family code {code} is used by more than one command family"
            );
            seen.push(code);
            assert_eq!(code, expected);
            assert_eq!(command.to_string(), code);
        }
        assert_eq!(
            seen.len(),
            9,
            "add the new family to `all_families` when a variant is added"
        );
        // The deferred §7.5 families must not be claimed by an existing code.
        for deferred in ["bios", "storage", "telemetry"] {
            assert!(
                !seen.contains(&deferred),
                "the deferred family code {deferred} must not be claimed"
            );
        }
        Ok(())
    }

    #[test]
    fn every_family_variant_is_matched_in_an_exhaustive_position() -> Result<(), Box<dyn Error>> {
        // A second exhaustive match site inside the tests, so adding a family
        // forces reviewing both this match and `RedfishCommand::as_str`.
        for (command, expected) in all_families()? {
            let matched = match command {
                RedfishCommand::Account(_) => "account",
                RedfishCommand::System(_) => "system",
                RedfishCommand::Manager(_) => "manager",
                RedfishCommand::Chassis(_) => "chassis",
                RedfishCommand::Boot(_) => "boot",
                RedfishCommand::SecureBoot(_) => "secure-boot",
                RedfishCommand::Event(_) => "event",
                RedfishCommand::Update(_) => "update",
                RedfishCommand::Oem(_) => "oem",
            };
            assert_eq!(matched, expected);
            assert_eq!(command.as_str(), matched);
        }
        Ok(())
    }

    #[test]
    fn every_family_round_trips_through_serde_and_unknown_families_are_rejected()
    -> Result<(), Box<dyn Error>> {
        for (command, _) in all_families()? {
            let json = serde_json::to_string(&command)?;
            assert_eq!(serde_json::from_str::<RedfishCommand>(&json)?, command);
        }
        // Each deferred §7.5 family is rejected as a complete literal, so
        // the wire contract cannot drift into accepting a family no payload
        // can fill — regardless of the payload shape under it.
        for unknown in [
            r#"{"Bios":{"SetAttributes":{}}}"#,
            r#"{"Storage":{"Format":{}}}"#,
            r#"{"Telemetry":{"SubmitTestMetricReport":{}}}"#,
        ] {
            assert!(
                serde_json::from_str::<RedfishCommand>(unknown).is_err(),
                "{unknown} must not deserialize as a command"
            );
        }
        // The `Oem` family is compiled, but an unknown vendor face under it
        // stays rejected, so the wire contract cannot drift into accepting a
        // face no payload can fill.
        assert!(
            serde_json::from_str::<RedfishCommand>(r#"{"Oem":{"Custom":{}}}"#).is_err(),
            "an unknown OEM face must not deserialize as a command"
        );
        Ok(())
    }

    /// Pins the complete wire contract of every command family as exact
    /// literals.
    ///
    /// The gateway translates `nv-redfish` types to and from these serde
    /// shapes, so the literals are the boundary it must not drift against:
    /// any change to the serialized form (variant names, payload field
    /// names, enum member names, or nesting) fails this test until the
    /// translation boundary is reviewed.
    //
    // One literal per command of every family; the line count grows with the
    // §7.5 surface, so the lint is scoped here like the other family
    // enumeration tests.
    #[allow(clippy::too_many_lines)]
    #[test]
    fn golden_wire_contracts_pin_every_command_family() -> Result<(), Box<dyn Error>> {
        let commands = [
            (
                RedfishCommand::Account(AccountCommand::CreateAccount(CreateAccount::new(
                    AccountUserName::parse("jane")?,
                    AccountPassword::parse("initial-secret".to_owned())?,
                    RoleId::parse("Operator")?,
                ))),
                r#"{"Account":{"CreateAccount":{"user_name":"jane","password":"initial-secret","role_id":"Operator"}}}"#,
            ),
            (
                RedfishCommand::Account(AccountCommand::UpdateAccount(UpdateAccount::new(
                    AccountId::parse("admin")?,
                    RoleId::parse("Administrator")?,
                ))),
                r#"{"Account":{"UpdateAccount":{"account_id":"admin","role_id":"Administrator"}}}"#,
            ),
            (
                RedfishCommand::Account(AccountCommand::UpdateAccountPassword(
                    UpdateAccountPassword::new(
                        AccountId::parse("jane")?,
                        AccountPassword::parse("new-secret".to_owned())?,
                    ),
                )),
                r#"{"Account":{"UpdateAccountPassword":{"account_id":"jane","password":"new-secret"}}}"#,
            ),
            (
                RedfishCommand::Account(AccountCommand::UpdateAccountUserName(
                    UpdateAccountUserName::new(
                        AccountId::parse("jane")?,
                        AccountUserName::parse("jane.doe")?,
                    ),
                )),
                r#"{"Account":{"UpdateAccountUserName":{"account_id":"jane","user_name":"jane.doe"}}}"#,
            ),
            (
                RedfishCommand::Account(AccountCommand::DeleteAccount(DeleteAccount::new(
                    AccountId::parse("jane")?,
                ))),
                r#"{"Account":{"DeleteAccount":{"account_id":"jane"}}}"#,
            ),
            (
                RedfishCommand::System(SystemCommand::Reset(ResetType::On)),
                r#"{"System":{"Reset":"On"}}"#,
            ),
            (
                RedfishCommand::Manager(ManagerCommand::Reset(ResetType::GracefulRestart)),
                r#"{"Manager":{"Reset":"GracefulRestart"}}"#,
            ),
            (
                RedfishCommand::Chassis(ChassisCommand::Reset(ResetType::ForceOff)),
                r#"{"Chassis":{"Reset":"ForceOff"}}"#,
            ),
            (
                RedfishCommand::Boot(BootCommand::SetBootSourceOverride(
                    SetBootSourceOverride::new(
                        BootSource::Pxe,
                        BootSourceOverrideEnabled::Once,
                        BootSourceOverrideMode::Uefi,
                    ),
                )),
                r#"{"Boot":{"SetBootSourceOverride":{"source":"Pxe","enabled":"Once","mode":"UEFI"}}}"#,
            ),
            (
                RedfishCommand::SecureBoot(SecureBootCommand::ResetKeys(
                    ResetKeysType::ResetAllKeysToDefault,
                )),
                r#"{"SecureBoot":{"ResetKeys":"ResetAllKeysToDefault"}}"#,
            ),
            (
                RedfishCommand::Event(EventCommand::CreateSubscription(
                    CreateSubscription::try_new(
                        "https://example.com/hook".to_owned(),
                        EventDestinationProtocol::Redfish,
                        vec![EventType::Alert],
                    )?,
                )),
                r#"{"Event":{"CreateSubscription":{"destination":"https://example.com/hook","protocol":"Redfish","event_types":["Alert"]}}}"#,
            ),
            (
                RedfishCommand::Update(UpdateCommand::StartUpdate(StartUpdate::new(
                    ArtifactId::from_uuid(Uuid::parse_str("0198a0c5-9f5e-7b42-8d2e-5a4b6c7d8e9f")?),
                    Some("https://192.0.2.10/upload".to_owned()),
                ))),
                r#"{"Update":{"StartUpdate":{"artifact_id":"0198a0c5-9f5e-7b42-8d2e-5a4b6c7d8e9f","push_uri":"https://192.0.2.10/upload"}}}"#,
            ),
            (
                RedfishCommand::Oem(OemCommand::SystemConfigProfile(
                    NvidiaSystemConfigProfileCommand::Update(ProfileFile::new(
                        r#"{"UUID":"11111111-2222-3333-4444-555555555555"}"#.to_owned(),
                    )),
                )),
                r#"{"Oem":{"SystemConfigProfile":{"Update":{"profile_file":"{\"UUID\":\"11111111-2222-3333-4444-555555555555\"}"}}}}"#,
            ),
            (
                RedfishCommand::Oem(OemCommand::SystemConfigProfile(
                    NvidiaSystemConfigProfileCommand::FactoryReset,
                )),
                r#"{"Oem":{"SystemConfigProfile":"FactoryReset"}}"#,
            ),
            (
                RedfishCommand::Oem(OemCommand::DebugToken(
                    NvidiaDebugTokenCommand::GenerateToken(TokenType::Frc),
                )),
                r#"{"Oem":{"DebugToken":{"GenerateToken":"FRC"}}}"#,
            ),
            (
                RedfishCommand::Oem(OemCommand::DebugToken(
                    NvidiaDebugTokenCommand::InstallToken(TokenData::new(
                        "dG9rZW4tZGF0YQ==".to_owned(),
                    )),
                )),
                r#"{"Oem":{"DebugToken":{"InstallToken":{"token_data":"dG9rZW4tZGF0YQ=="}}}}"#,
            ),
            (
                RedfishCommand::Oem(OemCommand::DebugToken(NvidiaDebugTokenCommand::EraseToken(
                    EraseToken::new(EraseType::EraseAll, TokenType::Crdt),
                ))),
                r#"{"Oem":{"DebugToken":{"EraseToken":{"erase_type":"EraseAll","token_type":"CRDT"}}}}"#,
            ),
            (
                RedfishCommand::Oem(OemCommand::PowerSmoothing(
                    NvidiaPowerSmoothingCommand::ActivatePresetProfile(ProfileId::new(3)),
                )),
                r#"{"Oem":{"PowerSmoothing":{"ActivatePresetProfile":{"profile_id":3}}}}"#,
            ),
            (
                RedfishCommand::Oem(OemCommand::PowerSmoothing(
                    NvidiaPowerSmoothingCommand::ApplyAdminOverrides,
                )),
                r#"{"Oem":{"PowerSmoothing":"ApplyAdminOverrides"}}"#,
            ),
        ];
        for (command, golden) in commands {
            assert_eq!(serde_json::to_string(&command)?, golden);
        }
        Ok(())
    }

    #[test]
    fn boot_override_payload_round_trips_and_denies_unknown_fields() -> Result<(), Box<dyn Error>> {
        let override_value = SetBootSourceOverride::new(
            BootSource::Pxe,
            BootSourceOverrideEnabled::Once,
            BootSourceOverrideMode::Uefi,
        );
        assert_eq!(override_value.source(), BootSource::Pxe);
        assert_eq!(override_value.enabled(), BootSourceOverrideEnabled::Once);
        assert_eq!(override_value.mode(), BootSourceOverrideMode::Uefi);

        let json = serde_json::to_string(&override_value)?;
        assert_eq!(json, r#"{"source":"Pxe","enabled":"Once","mode":"UEFI"}"#);
        assert_eq!(
            serde_json::from_str::<SetBootSourceOverride>(&json)?,
            override_value
        );
        assert!(
            serde_json::from_str::<SetBootSourceOverride>(
                r#"{"source":"Pxe","enabled":"Once","mode":"UEFI","target":3}"#
            )
            .is_err(),
            "unknown payload fields must be rejected"
        );
        Ok(())
    }

    #[test]
    fn event_subscriptions_require_at_least_one_event_type() -> Result<(), Box<dyn Error>> {
        assert_eq!(
            CreateSubscription::try_new(
                "https://192.0.2.10/events".to_owned(),
                EventDestinationProtocol::Redfish,
                Vec::new(),
            ),
            Err(EventSubscriptionError::EmptyEventTypes)
        );
        let subscription = CreateSubscription::try_new(
            "https://192.0.2.10/events".to_owned(),
            EventDestinationProtocol::Redfish,
            vec![EventType::Alert, EventType::StatusChange],
        )?;
        assert_eq!(subscription.destination(), "https://192.0.2.10/events");
        assert_eq!(subscription.protocol(), EventDestinationProtocol::Redfish);
        assert_eq!(
            subscription.event_types(),
            &[EventType::Alert, EventType::StatusChange]
        );

        let json = serde_json::to_string(&subscription)?;
        assert_eq!(
            json,
            r#"{"destination":"https://192.0.2.10/events","protocol":"Redfish","event_types":["Alert","StatusChange"]}"#
        );
        assert_eq!(
            serde_json::from_str::<CreateSubscription>(&json)?,
            subscription
        );
        assert!(
            serde_json::from_str::<CreateSubscription>(
                r#"{"destination":"https://192.0.2.10/events","protocol":"Redfish","event_types":["Alert"],"context":"extra"}"#
            )
            .is_err(),
            "unknown payload fields must be rejected"
        );
        Ok(())
    }

    #[test]
    fn delete_subscription_payload_round_trips_and_denies_unknown_fields()
    -> Result<(), Box<dyn Error>> {
        let deletion = DeleteSubscription::new("Sub-1".to_owned());
        assert_eq!(deletion.subscription_id(), "Sub-1");

        let json = serde_json::to_string(&deletion)?;
        assert_eq!(json, r#"{"subscription_id":"Sub-1"}"#);
        assert_eq!(serde_json::from_str::<DeleteSubscription>(&json)?, deletion);
        assert!(
            serde_json::from_str::<DeleteSubscription>(r#"{"subscription_id":"Sub-1","id":2}"#)
                .is_err(),
            "unknown payload fields must be rejected"
        );
        Ok(())
    }

    #[test]
    fn start_update_payload_round_trips_and_denies_unknown_fields() -> Result<(), Box<dyn Error>> {
        let artifact_id =
            ArtifactId::from_uuid(Uuid::parse_str("0198a0c5-9f5e-7b42-8d2e-5a4b6c7d8e9f")?);
        let update = StartUpdate::new(artifact_id, Some("https://192.0.2.10/upload".to_owned()));
        assert_eq!(update.artifact_id(), artifact_id);
        assert_eq!(update.push_uri(), Some("https://192.0.2.10/upload"));

        let json = serde_json::to_string(&update)?;
        assert_eq!(
            json,
            r#"{"artifact_id":"0198a0c5-9f5e-7b42-8d2e-5a4b6c7d8e9f","push_uri":"https://192.0.2.10/upload"}"#
        );
        assert_eq!(serde_json::from_str::<StartUpdate>(&json)?, update);
        assert!(
            serde_json::from_str::<StartUpdate>(r#"{"artifact_id":"not-a-uuid","push_uri":null}"#)
                .is_err(),
            "the artifact id must deserialize as a uuid string"
        );
        assert!(
            serde_json::from_str::<StartUpdate>(r#"{"artifact_id":"0198a0c5-9f5e-7b42-8d2e-5a4b6c7d8e9f","push_uri":"https://192.0.2.10/upload","name":"extra"}"#)
                .is_err(),
            "unknown payload fields must be rejected"
        );

        // The multipart fallback (no public push URI) stays absent from the
        // wire form and deserializes back as `None`.
        let multipart = StartUpdate::new(artifact_id, None);
        assert_eq!(multipart.push_uri(), None);
        let multipart_json = serde_json::to_string(&multipart)?;
        assert_eq!(
            multipart_json,
            r#"{"artifact_id":"0198a0c5-9f5e-7b42-8d2e-5a4b6c7d8e9f"}"#
        );
        assert_eq!(
            serde_json::from_str::<StartUpdate>(&multipart_json)?,
            multipart
        );
        Ok(())
    }

    #[test]
    fn reset_commands_round_trip_per_resource_family() -> Result<(), Box<dyn Error>> {
        for command in [
            RedfishCommand::System(SystemCommand::Reset(ResetType::PowerCycle)),
            RedfishCommand::Manager(ManagerCommand::Reset(ResetType::GracefulRestart)),
            RedfishCommand::Chassis(ChassisCommand::Reset(ResetType::ForceOff)),
        ] {
            let json = serde_json::to_string(&command)?;
            assert_eq!(serde_json::from_str::<RedfishCommand>(&json)?, command);
        }
        Ok(())
    }

    #[test]
    fn secure_boot_commands_round_trip() -> Result<(), Box<dyn Error>> {
        for command in [
            RedfishCommand::SecureBoot(SecureBootCommand::Enable),
            RedfishCommand::SecureBoot(SecureBootCommand::Disable),
            RedfishCommand::SecureBoot(SecureBootCommand::ResetKeys(ResetKeysType::DeleteAllKeys)),
        ] {
            let json = serde_json::to_string(&command)?;
            assert_eq!(serde_json::from_str::<RedfishCommand>(&json)?, command);
        }
        Ok(())
    }

    #[test]
    fn oem_commands_round_trip_per_face() -> Result<(), Box<dyn Error>> {
        for command in [
            RedfishCommand::Oem(OemCommand::SystemConfigProfile(
                NvidiaSystemConfigProfileCommand::FactoryReset,
            )),
            RedfishCommand::Oem(OemCommand::SystemConfigProfile(
                NvidiaSystemConfigProfileCommand::ActivateProfile,
            )),
            RedfishCommand::Oem(OemCommand::DebugToken(
                NvidiaDebugTokenCommand::GenerateToken(TokenType::BpmpFirmwareDebugFs),
            )),
            RedfishCommand::Oem(OemCommand::DebugToken(
                NvidiaDebugTokenCommand::DisableToken,
            )),
            RedfishCommand::Oem(OemCommand::PowerSmoothing(
                NvidiaPowerSmoothingCommand::ApplyAdminOverrides,
            )),
        ] {
            let json = serde_json::to_string(&command)?;
            assert_eq!(serde_json::from_str::<RedfishCommand>(&json)?, command);
        }
        Ok(())
    }

    #[test]
    fn profile_file_payload_round_trips_and_denies_unknown_fields() -> Result<(), Box<dyn Error>> {
        let profile =
            ProfileFile::new(r#"{"UUID":"11111111-2222-3333-4444-555555555555"}"#.to_owned());
        assert_eq!(
            profile.profile_file(),
            r#"{"UUID":"11111111-2222-3333-4444-555555555555"}"#
        );

        let json = serde_json::to_string(&profile)?;
        assert_eq!(
            json,
            r#"{"profile_file":"{\"UUID\":\"11111111-2222-3333-4444-555555555555\"}"}"#
        );
        assert_eq!(serde_json::from_str::<ProfileFile>(&json)?, profile);
        assert!(
            serde_json::from_str::<ProfileFile>(r#"{"profile_file":"{}","metadata":true}"#)
                .is_err(),
            "unknown payload fields must be rejected"
        );
        Ok(())
    }

    #[test]
    fn token_data_payload_round_trips_and_denies_unknown_fields() -> Result<(), Box<dyn Error>> {
        let token = TokenData::new("dG9rZW4tZGF0YQ==".to_owned());
        assert_eq!(token.token_data(), "dG9rZW4tZGF0YQ==");

        let json = serde_json::to_string(&token)?;
        assert_eq!(json, r#"{"token_data":"dG9rZW4tZGF0YQ=="}"#);
        assert_eq!(serde_json::from_str::<TokenData>(&json)?, token);
        assert!(
            serde_json::from_str::<TokenData>(r#"{"token_data":"AA==","binary":true}"#).is_err(),
            "unknown payload fields must be rejected"
        );
        Ok(())
    }

    #[test]
    fn erase_token_payload_round_trips_and_denies_unknown_fields() -> Result<(), Box<dyn Error>> {
        let erase = EraseToken::new(EraseType::TokenType, TokenType::Mtdt);
        assert_eq!(erase.erase_type(), EraseType::TokenType);
        assert_eq!(erase.token_type(), TokenType::Mtdt);

        let json = serde_json::to_string(&erase)?;
        assert_eq!(json, r#"{"erase_type":"TokenType","token_type":"MTDT"}"#);
        assert_eq!(serde_json::from_str::<EraseToken>(&json)?, erase);
        assert!(
            serde_json::from_str::<EraseToken>(
                r#"{"erase_type":"EraseAll","token_type":"FRC","scope":1}"#
            )
            .is_err(),
            "unknown payload fields must be rejected"
        );
        Ok(())
    }

    #[test]
    fn profile_id_payload_round_trips_and_denies_unknown_fields() -> Result<(), Box<dyn Error>> {
        let profile_id = ProfileId::new(3);
        assert_eq!(profile_id.profile_id(), 3);

        let json = serde_json::to_string(&profile_id)?;
        assert_eq!(json, r#"{"profile_id":3}"#);
        assert_eq!(serde_json::from_str::<ProfileId>(&json)?, profile_id);
        assert!(
            serde_json::from_str::<ProfileId>(r#"{"profile_id":3,"name":"eco"}"#).is_err(),
            "unknown payload fields must be rejected"
        );
        Ok(())
    }

    #[test]
    fn account_ids_are_safe_single_path_segments() -> Result<(), Box<dyn Error>> {
        for valid in ["admin", "user-1", "jane_doe", "A1b2C3"] {
            let id = AccountId::parse(valid)?;
            assert_eq!(id.as_str(), valid);
            assert_eq!(id.to_string().parse::<AccountId>()?, id);
        }
        for invalid in ["..", ".", "a/b", "a\\b", "a?b", "a#b", "a%b", "a b", "a\tb"] {
            assert_eq!(
                AccountId::parse(invalid),
                Err(AccountIdError::UnsafeCharacter),
                "account id {invalid:?} must be rejected"
            );
        }
        assert_eq!(AccountId::parse(""), Err(AccountIdError::Empty));
        let long = "x".repeat(MAX_ACCOUNT_ID_CHARS + 1);
        assert_eq!(
            AccountId::parse(&long),
            Err(AccountIdError::TooLong {
                actual: MAX_ACCOUNT_ID_CHARS + 1,
                maximum: MAX_ACCOUNT_ID_CHARS
            })
        );
        Ok(())
    }

    #[test]
    fn account_user_names_reject_empty_control_and_oversized_values() -> Result<(), Box<dyn Error>>
    {
        for valid in ["jane", "jane.doe", "JANE_1"] {
            let name = AccountUserName::parse(valid)?;
            assert_eq!(name.as_str(), valid);
            assert_eq!(name.to_string().parse::<AccountUserName>(), Ok(name));
        }
        assert_eq!(AccountUserName::parse(""), Err(AccountUserNameError::Empty));
        assert_eq!(
            AccountUserName::parse("  "),
            Err(AccountUserNameError::Empty)
        );
        assert_eq!(
            AccountUserName::parse("jane\ndoe"),
            Err(AccountUserNameError::ControlCharacter)
        );
        let long = "x".repeat(MAX_ACCOUNT_USER_NAME_CHARS + 1);
        assert_eq!(
            AccountUserName::parse(&long),
            Err(AccountUserNameError::TooLong {
                actual: MAX_ACCOUNT_USER_NAME_CHARS + 1,
                maximum: MAX_ACCOUNT_USER_NAME_CHARS
            })
        );
        Ok(())
    }

    #[test]
    fn role_ids_reject_empty_control_and_oversized_values() -> Result<(), Box<dyn Error>> {
        for valid in ["Administrator", "Operator", "ReadOnly"] {
            let role = RoleId::parse(valid)?;
            assert_eq!(role.as_str(), valid);
            assert_eq!(role.to_string().parse::<RoleId>(), Ok(role));
        }
        assert_eq!(RoleId::parse(""), Err(RoleIdError::Empty));
        assert_eq!(RoleId::parse("  "), Err(RoleIdError::Empty));
        assert_eq!(
            RoleId::parse("Admin\0strator"),
            Err(RoleIdError::ControlCharacter)
        );
        let long = "x".repeat(MAX_ROLE_ID_CHARS + 1);
        assert_eq!(
            RoleId::parse(&long),
            Err(RoleIdError::TooLong {
                actual: MAX_ROLE_ID_CHARS + 1,
                maximum: MAX_ROLE_ID_CHARS
            })
        );
        Ok(())
    }

    #[test]
    fn account_passwords_are_secrets_redacted_and_bounded() -> Result<(), Box<dyn Error>> {
        let password = AccountPassword::parse("s3cret-value".to_owned())?;
        assert_eq!(password.expose_secret(), "s3cret-value");
        assert_eq!(
            format!("{password:?}"),
            "AccountPassword([REDACTED])",
            "a password must never print its value"
        );
        assert_eq!(
            AccountPassword::parse(String::new()),
            Err(AccountPasswordError::Empty)
        );
        let long = "x".repeat(MAX_ACCOUNT_PASSWORD_CHARS + 1);
        assert_eq!(
            AccountPassword::parse(long),
            Err(AccountPasswordError::TooLong {
                actual: MAX_ACCOUNT_PASSWORD_CHARS + 1,
                maximum: MAX_ACCOUNT_PASSWORD_CHARS
            })
        );

        // The serde wire form carries the exposed value (the §9.4 typed
        // payload contract), and the value round-trips through it.
        let json = serde_json::to_string(&password)?;
        assert_eq!(json, r#""s3cret-value""#);
        assert_eq!(serde_json::from_str::<AccountPassword>(&json)?, password);
        assert!(
            serde_json::from_str::<AccountPassword>("\"\"").is_err(),
            "an empty password must not deserialize"
        );
        Ok(())
    }

    #[test]
    fn create_account_payload_round_trips_and_denies_unknown_fields() -> Result<(), Box<dyn Error>>
    {
        let create = CreateAccount::new(
            AccountUserName::parse("jane")?,
            AccountPassword::parse("initial-secret".to_owned())?,
            RoleId::parse("Operator")?,
        );
        assert_eq!(create.user_name().as_str(), "jane");
        assert_eq!(create.password().expose_secret(), "initial-secret");
        assert_eq!(create.role_id().as_str(), "Operator");

        let json = serde_json::to_string(&create)?;
        assert_eq!(
            json,
            r#"{"user_name":"jane","password":"initial-secret","role_id":"Operator"}"#
        );
        assert_eq!(serde_json::from_str::<CreateAccount>(&json)?, create);
        assert!(
            serde_json::from_str::<CreateAccount>(
                r#"{"user_name":"jane","password":"initial-secret","role_id":"Operator","enabled":true}"#
            )
            .is_err(),
            "unknown payload fields must be rejected"
        );
        Ok(())
    }

    #[test]
    fn account_update_payloads_round_trip_and_deny_unknown_fields() -> Result<(), Box<dyn Error>> {
        let update = UpdateAccount::new(AccountId::parse("admin")?, RoleId::parse("Operator")?);
        assert_eq!(update.account_id().as_str(), "admin");
        assert_eq!(update.role_id().as_str(), "Operator");
        let json = serde_json::to_string(&update)?;
        assert_eq!(json, r#"{"account_id":"admin","role_id":"Operator"}"#);
        assert_eq!(serde_json::from_str::<UpdateAccount>(&json)?, update);
        assert!(
            serde_json::from_str::<UpdateAccount>(
                r#"{"account_id":"admin","role_id":"Operator","locked":true}"#
            )
            .is_err(),
            "unknown payload fields must be rejected"
        );

        let password = UpdateAccountPassword::new(
            AccountId::parse("jane")?,
            AccountPassword::parse("new-secret".to_owned())?,
        );
        assert_eq!(password.account_id().as_str(), "jane");
        assert_eq!(password.password().expose_secret(), "new-secret");
        let json = serde_json::to_string(&password)?;
        assert_eq!(json, r#"{"account_id":"jane","password":"new-secret"}"#);
        assert_eq!(
            serde_json::from_str::<UpdateAccountPassword>(&json)?,
            password
        );
        assert!(
            serde_json::from_str::<UpdateAccountPassword>(
                r#"{"account_id":"jane","password":"new-secret","expires":true}"#
            )
            .is_err(),
            "unknown payload fields must be rejected"
        );

        let rename = UpdateAccountUserName::new(
            AccountId::parse("jane")?,
            AccountUserName::parse("jane.doe")?,
        );
        assert_eq!(rename.account_id().as_str(), "jane");
        assert_eq!(rename.user_name().as_str(), "jane.doe");
        let json = serde_json::to_string(&rename)?;
        assert_eq!(json, r#"{"account_id":"jane","user_name":"jane.doe"}"#);
        assert_eq!(
            serde_json::from_str::<UpdateAccountUserName>(&json)?,
            rename
        );
        assert!(
            serde_json::from_str::<UpdateAccountUserName>(
                r#"{"account_id":"jane","user_name":"jane.doe","email":"j@x"}"#
            )
            .is_err(),
            "unknown payload fields must be rejected"
        );

        let deletion = DeleteAccount::new(AccountId::parse("jane")?);
        assert_eq!(deletion.account_id().as_str(), "jane");
        let json = serde_json::to_string(&deletion)?;
        assert_eq!(json, r#"{"account_id":"jane"}"#);
        assert_eq!(serde_json::from_str::<DeleteAccount>(&json)?, deletion);
        assert!(
            serde_json::from_str::<DeleteAccount>(r#"{"account_id":"jane","force":true}"#).is_err(),
            "unknown payload fields must be rejected"
        );
        Ok(())
    }

    #[test]
    fn account_commands_round_trip_per_operation() -> Result<(), Box<dyn Error>> {
        for command in [
            RedfishCommand::Account(AccountCommand::CreateAccount(CreateAccount::new(
                AccountUserName::parse("jane")?,
                AccountPassword::parse("initial-secret".to_owned())?,
                RoleId::parse("Operator")?,
            ))),
            RedfishCommand::Account(AccountCommand::UpdateAccount(UpdateAccount::new(
                AccountId::parse("admin")?,
                RoleId::parse("ReadOnly")?,
            ))),
            RedfishCommand::Account(AccountCommand::UpdateAccountPassword(
                UpdateAccountPassword::new(
                    AccountId::parse("jane")?,
                    AccountPassword::parse("new-secret".to_owned())?,
                ),
            )),
            RedfishCommand::Account(AccountCommand::UpdateAccountUserName(
                UpdateAccountUserName::new(
                    AccountId::parse("jane")?,
                    AccountUserName::parse("jane.doe")?,
                ),
            )),
            RedfishCommand::Account(AccountCommand::DeleteAccount(DeleteAccount::new(
                AccountId::parse("jane")?,
            ))),
        ] {
            let json = serde_json::to_string(&command)?;
            assert_eq!(serde_json::from_str::<RedfishCommand>(&json)?, command);
        }
        Ok(())
    }
}
