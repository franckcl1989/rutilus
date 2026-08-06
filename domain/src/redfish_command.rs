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

use std::{error::Error, fmt};

use serde::{Deserialize, Serialize};

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
/// - `Account` — account writes carry passwords, which are §10 secrets that
///   must be encrypted before persistence; the write surface lands together
///   with the secret-handling iteration.
/// - `Bios` — BIOS writes are an unbounded attribute bag (the CSDL
///   `Attributes` property), which conflicts with the strict typed projection
///   of this module; the surface lands when a bounded attribute projection
///   exists.
/// - `Storage` — storage writes (volume and `RAID` operations) have no
///   first-cut product flow.
/// - `Update` — firmware upload is a multipart flow (§14.3) scheduled for a
///   later iteration.
/// - `Telemetry` — telemetry writes (metric report subscription lifecycle)
///   build on the event-service surface and land with it.
/// - `Oem` — OEM writes have no standardized shape (§11.5) and stay deferred
///   until an upstream OEM command family is compiled in.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub enum RedfishCommand {
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
            Self::System(_) => "system",
            Self::Manager(_) => "manager",
            Self::Chassis(_) => "chassis",
            Self::Boot(_) => "boot",
            Self::SecureBoot(_) => "secure-boot",
            Self::Event(_) => "event",
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

    /// One representative command per family with its expected family code.
    ///
    /// The six entries are the exhaustive §7.5 family list for this
    /// iteration; adding a family must add an entry here or the
    /// exhaustiveness tests fail.
    fn all_families() -> Result<Vec<(RedfishCommand, &'static str)>, EventSubscriptionError> {
        Ok(vec![
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
            6,
            "add the new family to `all_families` when a variant is added"
        );
        // The deferred §7.5 families must not be claimed by an existing code.
        for deferred in ["account", "bios", "storage", "update", "telemetry", "oem"] {
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
                RedfishCommand::System(_) => "system",
                RedfishCommand::Manager(_) => "manager",
                RedfishCommand::Chassis(_) => "chassis",
                RedfishCommand::Boot(_) => "boot",
                RedfishCommand::SecureBoot(_) => "secure-boot",
                RedfishCommand::Event(_) => "event",
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
            r#"{"Account":{"Create":{}}}"#,
            r#"{"Bios":{"SetAttributes":{}}}"#,
            r#"{"Storage":{"Format":{}}}"#,
            r#"{"Update":{"StartUpdate":{}}}"#,
            r#"{"Telemetry":{"SubmitTestMetricReport":{}}}"#,
            r#"{"Oem":{"Custom":{}}}"#,
        ] {
            assert!(
                serde_json::from_str::<RedfishCommand>(unknown).is_err(),
                "{unknown} must not deserialize as a command"
            );
        }
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
    #[test]
    fn golden_wire_contracts_pin_every_command_family() -> Result<(), Box<dyn Error>> {
        let commands = [
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
}
