//! The frozen 0.8.0 release baseline of the upstream `nv-redfish` surface
//! (§2.3/§2.4 of the product design).
//!
//! The product enters the 0.8.0 capability freeze with this module as the
//! machine-readable `NvRedfishReleaseBaseline` record: the exact crate
//! version, the enabled public feature inventory, the schema version record,
//! the public module inventory with a product decision for every entry, the
//! public operation inventory with an explicit mapping status for every
//! entry, and the capability-ledger hash snapshot. The committed `Cargo.lock`
//! is the fifth artifact of the freeze and is verified against this record
//! by the tests in this module.
//!
//! # Version record
//!
//! The freeze pins [`NV_REDFISH_RELEASE_BASELINE_VERSION`] = `0.13.0`, the
//! version the workspace compiles today
//! ([`crate::NV_REDFISH_DEVELOPMENT_BASELINE`]). The crates.io index known to
//! this machine also carries `0.14.1` (published 2026-08-07, not yanked) —
//! a newer stable release that was published after the development baseline
//! was validated. Per §2.3 the freeze chooses the latest *validated* stable
//! version, so `0.13.0` stays frozen and the `0.14.1` upgrade decision is
//! recorded in [`NV_REDFISH_KNOWN_NEWER_STABLE_VERSION`] and left to the
//! freeze review; the record does not assert `DEVELOPMENT == RELEASE` as an
//! invariant because the development baseline is allowed to move ahead of the
//! frozen version during the review.
//!
//! # Audit mode for unmapped operations
//!
//! The 0.8.0 acceptance criterion requires `未映射公开操作 = 0` (no public
//! operation without a product mapping). At this point in the 0.8.0 work the
//! parallel write-surface work items are still implementing several families
//! (account, control, log clear, telemetry CRUD, ...), so this gate runs in
//! **audit mode**: the operation inventory lists every upstream typed write
//! operation with an explicit status, and the gate asserts the inventory is
//! internally consistent and that the unmapped count equals the frozen
//! record [`FROZEN_UNMAPPED_OPERATION_COUNT`] — it does *not* assert the
//! count is zero. When the parallel work items land, the count is updated
//! deliberately (each entry flips to `Mapped`), and the final 0.8.0 gate
//! switches the assertion to zero by making the frozen count `0`.
//!
//! # Where the inventories come from
//!
//! Every inventory in this module was enumerated from the vendored source of
//! `nv-redfish` 0.13.0 in the local cargo registry
//! (`$CARGO_HOME/registry/src/*/nv-redfish-0.13.0/`): the module list from
//! its `src/lib.rs` `pub mod` declarations and `pub use ... as` re-exports,
//! the feature universe from its `Cargo.toml` `[features]` table, and the
//! operation list from its public typed write methods plus the typed CSDL
//! action families compiled by `nv-redfish-schema` 0.13.0. The tests verify
//! the module list against the vendored `src/lib.rs` at runtime and the
//! feature list against the workspace manifests, so the record cannot drift
//! from either source without a failing gate.

use rutilus_domain::CAPABILITY_LEDGER_ORDER;
use sha2::{Digest, Sha256};

/// The exact upstream crate version frozen by the 0.8.0 capability freeze
/// (§2.3).
pub const NV_REDFISH_RELEASE_BASELINE_VERSION: &str = "0.13.0";

/// A newer stable `nv-redfish` release known to the freeze record.
///
/// `0.14.1` was published on 2026-08-07 (after `0.13.0`, 2026-08-04) and is
/// not yanked. §2.3 freezes the latest *validated* stable version, so the
/// record keeps `0.13.0` and leaves the upgrade decision to the freeze
/// review. `None` records that no newer stable release was known when the
/// record was written.
pub const NV_REDFISH_KNOWN_NEWER_STABLE_VERSION: Option<&str> = Some("0.14.1");

/// The public `nv-redfish` features explicitly enabled in the workspace
/// manifests: the 16 features of the root `Cargo.toml` `nv-redfish`
/// declaration (in manifest order) plus the `update-service-deprecated`
/// feature added by this crate's manifest (§0.4.0 legacy update
/// compatibility).
///
/// The [`release_baseline_explicit_features_match_the_workspace_manifests`]
/// test proves this list equals the union of both manifest feature lists in
/// both directions — an extra or a missing feature fails the gate.
pub const RELEASE_BASELINE_EXPLICIT_FEATURES: [&str; 17] = [
    "bmc-http",
    "std-redfish",
    "oem-ami",
    "oem-dell",
    "oem-dell-attributes",
    "oem-delta",
    "oem-hpe",
    "oem-lenovo",
    "oem-liteon",
    "oem-nvidia",
    "oem-nvidia-cper",
    "oem-nvidia-fabrics",
    "oem-nvidia-power-management",
    "oem-nvidia-profiles",
    "oem-nvidia-security",
    "oem-supermicro",
    "update-service-deprecated",
];

/// The complete set of public `nv-redfish` 0.13.0 features compiled by this
/// product: the [`RELEASE_BASELINE_EXPLICIT_FEATURES`] plus every feature
/// they enable transitively (`std-redfish` expands to 30 service features,
/// the `oem-*` chain enables `oem`, and the service features enable the
/// `patch`/`impl-entity-link`/`impl-nv-bmc-expand`/`resource-status`/
/// `environment-metrics` helpers), resolved against the 0.13.0 `[features]`
/// table. The only feature the universe defines that is *not* compiled is
/// `default` (the workspace builds with `default-features = false`).
///
/// This is the §2.3 "启用的全部公开 feature" freeze artifact; the tests pin
/// the exact set (universe minus `default`) and prove every module gating
/// feature and every operation feature below is compiled.
pub const RELEASE_BASELINE_ENABLED_FEATURES: [&str; 58] = [
    "accounts",
    "assembly",
    "bios",
    "bmc-http",
    "boot-options",
    "chassis",
    "computer-systems",
    "controls",
    "environment-metrics",
    "ethernet-interfaces",
    "event-service",
    "host-interfaces",
    "impl-entity-link",
    "impl-nv-bmc-expand",
    "log-services",
    "manager-network-protocol",
    "managers",
    "memory",
    "network-adapters",
    "network-device-functions",
    "oem",
    "oem-ami",
    "oem-dell",
    "oem-dell-attributes",
    "oem-delta",
    "oem-hpe",
    "oem-lenovo",
    "oem-liteon",
    "oem-nvidia",
    "oem-nvidia-cper",
    "oem-nvidia-fabrics",
    "oem-nvidia-power-management",
    "oem-nvidia-profiles",
    "oem-nvidia-security",
    "oem-supermicro",
    "patch",
    "patch-collection",
    "patch-collection-create",
    "patch-payload",
    "patch-payload-get",
    "patch-payload-update",
    "pcie-devices",
    "ports",
    "power",
    "power-equipment",
    "power-supplies",
    "processors",
    "resource-status",
    "secure-boot",
    "sensors",
    "session-service",
    "std-redfish",
    "storages",
    "task-service",
    "telemetry-service",
    "thermal",
    "update-service",
    "update-service-deprecated",
];

/// Every public feature defined by `nv-redfish` 0.13.0's `[features]` table
/// (from the vendored `Cargo.toml`, in table order).
///
/// The enabled-feature test uses this as the typo universe: an enabled
/// feature that does not exist upstream fails the gate.
pub const NV_REDFISH_0_13_0_FEATURE_UNIVERSE: [&str; 59] = [
    "accounts",
    "assembly",
    "bios",
    "bmc-http",
    "boot-options",
    "chassis",
    "computer-systems",
    "controls",
    "default",
    "environment-metrics",
    "ethernet-interfaces",
    "event-service",
    "host-interfaces",
    "impl-entity-link",
    "impl-nv-bmc-expand",
    "log-services",
    "manager-network-protocol",
    "managers",
    "memory",
    "network-adapters",
    "network-device-functions",
    "oem",
    "oem-ami",
    "oem-dell",
    "oem-dell-attributes",
    "oem-delta",
    "oem-hpe",
    "oem-lenovo",
    "oem-liteon",
    "oem-nvidia",
    "oem-nvidia-cper",
    "oem-nvidia-fabrics",
    "oem-nvidia-power-management",
    "oem-nvidia-profiles",
    "oem-nvidia-security",
    "oem-supermicro",
    "patch",
    "patch-collection",
    "patch-collection-create",
    "patch-payload",
    "patch-payload-get",
    "patch-payload-update",
    "pcie-devices",
    "ports",
    "power",
    "power-equipment",
    "power-supplies",
    "processors",
    "resource-status",
    "secure-boot",
    "sensors",
    "session-service",
    "std-redfish",
    "storages",
    "task-service",
    "telemetry-service",
    "thermal",
    "update-service",
    "update-service-deprecated",
];

/// The schema-layer crate versions frozen with the baseline (§2.3 "Schema
/// 版本信息").
///
/// All four crates ride the same 0.13.0 line as `nv-redfish` itself; the
/// [`release_baseline_schema_versions_match_the_committed_lockfile`] test
/// proves each against the committed `Cargo.lock`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReleaseSchemaVersions {
    schema: &'static str,
    core: &'static str,
    bmc_http: &'static str,
    csdl_compiler: &'static str,
}

impl ReleaseSchemaVersions {
    /// Returns the frozen `nv-redfish-schema` version.
    #[must_use]
    pub const fn schema(self) -> &'static str {
        self.schema
    }

    /// Returns the frozen `nv-redfish-core` version.
    #[must_use]
    pub const fn core(self) -> &'static str {
        self.core
    }

    /// Returns the frozen `nv-redfish-bmc-http` version.
    #[must_use]
    pub const fn bmc_http(self) -> &'static str {
        self.bmc_http
    }

    /// Returns the frozen `nv-redfish-csdl-compiler` version.
    #[must_use]
    pub const fn csdl_compiler(self) -> &'static str {
        self.csdl_compiler
    }
}

/// The frozen schema-layer versions of the baseline.
pub const RELEASE_SCHEMA_VERSIONS: ReleaseSchemaVersions = ReleaseSchemaVersions {
    schema: "0.13.0",
    core: "0.13.0",
    bmc_http: "0.13.0",
    csdl_compiler: "0.13.0",
};

/// How one public `nv-redfish` module relates to the capability ledger
/// (§2.4).
///
/// This is the *module* axis of the freeze record, distinct from the
/// domain-ledger `CapabilityClassification` (which classifies capabilities,
/// not modules). The 0.8.0 acceptance criterion `未分类公开模块 = 0` is
/// proven by [`release_baseline_every_module_is_classified_with_a_decision`]:
/// every module entry carries one of these four classes and a documented
/// product decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BaselineModuleClassification {
    /// The module's gating feature is a §2.1 capability-ledger entry.
    LedgerMapped,
    /// Transport/schema plumbing (HTTP transport, schema surface, service
    /// root, shared resource API) that backs product operations but is not
    /// itself a capability.
    Infrastructure,
    /// Upstream surface retained for legacy device compatibility.
    LegacyCompatibility,
    /// Module organization or primitives used only inside the product.
    Internal,
}

impl BaselineModuleClassification {
    /// Returns the stable classification code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LedgerMapped => "ledger-mapped",
            Self::Infrastructure => "infrastructure",
            Self::LegacyCompatibility => "legacy-compatibility",
            Self::Internal => "internal",
        }
    }
}

/// One public module of the frozen `nv-redfish` 0.13.0 surface.
///
/// `gating_feature` is the `#[cfg(feature = "...")]` that compiles the
/// module, `None` for unconditionally compiled modules. `decision` records
/// the product decision that justifies the classification (the §2.4
/// "产品决策" requirement applied to modules).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BaselineModule {
    name: &'static str,
    gating_feature: Option<&'static str>,
    classification: BaselineModuleClassification,
    decision: &'static str,
}

impl BaselineModule {
    /// Returns the module path (`nv_redfish::{name}`).
    #[must_use]
    pub const fn name(self) -> &'static str {
        self.name
    }

    /// Returns the feature that compiles this module, when gated.
    #[must_use]
    pub const fn gating_feature(self) -> Option<&'static str> {
        self.gating_feature
    }

    /// Returns the §2.4 module classification.
    #[must_use]
    pub const fn classification(self) -> BaselineModuleClassification {
        self.classification
    }

    /// Returns the recorded product decision for this classification.
    #[must_use]
    pub const fn decision(self) -> &'static str {
        self.decision
    }
}

/// The public module inventory of `nv-redfish` 0.13.0 as compiled by this
/// product: the 26 `pub mod` declarations of the vendored `src/lib.rs` (all
/// feature gates are enabled in this build) plus the three module-shaped
/// `pub use ... as` re-exports (`core`, `bmc_http`, `schema`).
///
/// [`release_baseline_module_inventory_matches_the_vendored_lib_rs`] proves
/// the names against the vendored `src/lib.rs` at runtime, and
/// [`release_baseline_every_module_is_classified_with_a_decision`] proves
/// there is no unclassified entry.
pub const RELEASE_BASELINE_MODULES: [BaselineModule; 29] = [
    BaselineModule {
        name: "error",
        gating_feature: None,
        classification: BaselineModuleClassification::Infrastructure,
        decision: "crate-wide error type; transport-level plumbing, not a §2.1 capability",
    },
    BaselineModule {
        name: "service_root",
        gating_feature: None,
        classification: BaselineModuleClassification::Infrastructure,
        decision: "entry point of the §3.1 service-and-connection surface; the gateway consumes it for discovery and it has no ledger entry of its own",
    },
    BaselineModule {
        name: "resource",
        gating_feature: None,
        classification: BaselineModuleClassification::Infrastructure,
        decision: "shared Resource trait and ResourceProvidesStatus API for every resource; common surface, not a capability",
    },
    BaselineModule {
        name: "hardware_id",
        gating_feature: None,
        classification: BaselineModuleClassification::Infrastructure,
        decision: "hardware-identifier parsing consumed by the §11.3 probe; no capability of its own",
    },
    BaselineModule {
        name: "mac_address",
        gating_feature: None,
        classification: BaselineModuleClassification::Infrastructure,
        decision: "MAC-address parsing used by read projections; no capability of its own",
    },
    BaselineModule {
        name: "account",
        gating_feature: Some("accounts"),
        classification: BaselineModuleClassification::LedgerMapped,
        decision: "§2.1 accounts ledger entry; writes deferred with the secret-handling iteration (§7.5)",
    },
    BaselineModule {
        name: "chassis",
        gating_feature: Some("chassis"),
        classification: BaselineModuleClassification::LedgerMapped,
        decision: "§2.1 chassis ledger entry",
    },
    BaselineModule {
        name: "computer_system",
        gating_feature: Some("computer-systems"),
        classification: BaselineModuleClassification::LedgerMapped,
        decision: "§2.1 computer-systems ledger entry (product code 'systems')",
    },
    BaselineModule {
        name: "control",
        gating_feature: Some("controls"),
        classification: BaselineModuleClassification::LedgerMapped,
        decision: "§2.1 controls ledger entry",
    },
    BaselineModule {
        name: "manager",
        gating_feature: Some("managers"),
        classification: BaselineModuleClassification::LedgerMapped,
        decision: "§2.1 managers ledger entry",
    },
    BaselineModule {
        name: "update_service",
        gating_feature: Some("update-service"),
        classification: BaselineModuleClassification::LedgerMapped,
        decision: "§2.1 update-service ledger entry; also carries the deprecated HttpPushUri surface, which is LegacyCompatibility at the operation level (§0.4.0)",
    },
    BaselineModule {
        name: "assembly",
        gating_feature: Some("assembly"),
        classification: BaselineModuleClassification::LedgerMapped,
        decision: "§2.1 assembly ledger entry",
    },
    BaselineModule {
        name: "ethernet_interface",
        gating_feature: Some("ethernet-interfaces"),
        classification: BaselineModuleClassification::LedgerMapped,
        decision: "§2.1 ethernet-interfaces ledger entry",
    },
    BaselineModule {
        name: "event_service",
        gating_feature: Some("event-service"),
        classification: BaselineModuleClassification::LedgerMapped,
        decision: "§2.1 event-service ledger entry",
    },
    BaselineModule {
        name: "host_interface",
        gating_feature: Some("host-interfaces"),
        classification: BaselineModuleClassification::LedgerMapped,
        decision: "§2.1 host-interfaces ledger entry",
    },
    BaselineModule {
        name: "log_service",
        gating_feature: Some("log-services"),
        classification: BaselineModuleClassification::LedgerMapped,
        decision: "§2.1 log-services ledger entry",
    },
    BaselineModule {
        name: "network_device_function",
        gating_feature: Some("network-device-functions"),
        classification: BaselineModuleClassification::LedgerMapped,
        decision: "§2.1 network-device-functions ledger entry",
    },
    BaselineModule {
        name: "pcie_device",
        gating_feature: Some("pcie-devices"),
        classification: BaselineModuleClassification::LedgerMapped,
        decision: "§2.1 pcie-devices ledger entry",
    },
    BaselineModule {
        name: "port",
        gating_feature: Some("ports"),
        classification: BaselineModuleClassification::LedgerMapped,
        decision: "standard surface new in 0.13.0 (absent from the §2.1 0.12.1 inventory): the §0.8.0 ledger must gain the Ports entry — recorded as PENDING_LEDGER_FEATURES until the domain ledger lands it",
    },
    BaselineModule {
        name: "power_equipment",
        gating_feature: Some("power-equipment"),
        classification: BaselineModuleClassification::LedgerMapped,
        decision: "§2.1 power-equipment ledger entry",
    },
    BaselineModule {
        name: "sensor",
        gating_feature: Some("sensors"),
        classification: BaselineModuleClassification::LedgerMapped,
        decision: "§2.1 sensors ledger entry",
    },
    BaselineModule {
        name: "session_service",
        gating_feature: Some("session-service"),
        classification: BaselineModuleClassification::LedgerMapped,
        decision: "§2.1 session-service ledger entry; §2.4 classifies the capability as Infrastructure, but the module is still a ledger entry",
    },
    BaselineModule {
        name: "task_service",
        gating_feature: Some("task-service"),
        classification: BaselineModuleClassification::LedgerMapped,
        decision: "§2.1 task-service ledger entry; §2.4 classifies the capability as Infrastructure, but the module is still a ledger entry",
    },
    BaselineModule {
        name: "telemetry_service",
        gating_feature: Some("telemetry-service"),
        classification: BaselineModuleClassification::LedgerMapped,
        decision: "§2.1 telemetry-service ledger entry",
    },
    BaselineModule {
        name: "oem",
        gating_feature: Some("oem"),
        classification: BaselineModuleClassification::Internal,
        decision: "module container for the §2.1 OEM surfaces; the container itself is product-internal organization and each vendor surface inside is tracked by its own oem-* ledger entry",
    },
    BaselineModule {
        name: "entity_link",
        gating_feature: Some("impl-entity-link"),
        classification: BaselineModuleClassification::Internal,
        decision: "generic EntityLink fetch/delete primitive for navigation-owned resources (for example, boot options); no capability of its own",
    },
    BaselineModule {
        name: "core",
        gating_feature: None,
        classification: BaselineModuleClassification::Infrastructure,
        decision: "re-export of nv-redfish-core: the transport-agnostic Bmc trait and ODataId primitives that back every operation",
    },
    BaselineModule {
        name: "bmc_http",
        gating_feature: Some("bmc-http"),
        classification: BaselineModuleClassification::Infrastructure,
        decision: "re-export of nv-redfish-bmc-http: the HTTP transport behind the Bmc trait (§3.1 service-and-connection)",
    },
    BaselineModule {
        name: "schema",
        gating_feature: None,
        classification: BaselineModuleClassification::Infrastructure,
        decision: "re-export of the generated CSDL schema surface; the typed layer every read and write is projected onto, not itself a capability",
    },
];

/// The mapping status of one public write operation in the freeze record.
///
/// `Mapped` and `CompiledCsdlOnly` name the §7.5 command family (one of
/// [`REDFISH_COMMAND_FAMILIES`]); `Unmapped` marks an upstream typed
/// operation without a product command yet (the audit-mode list of the
/// 0.8.0 `未映射公开操作 = 0` criterion); `Infrastructure` and `Internal`
/// mark operations the product uses outside the command surface.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationMapping {
    /// The operation is dispatched by the named `RedfishCommand` family.
    Mapped { command: &'static str },
    /// No product command exists yet; listed explicitly for the 0.8.0
    /// audit gate.
    Unmapped,
    /// Used by product plumbing (for example, the authentication flow),
    /// never through a command family.
    Infrastructure,
    /// An internal primitive with no command surface.
    Internal,
    /// A product command whose upstream surface is the compiled CSDL member
    /// set only — `nv-redfish` 0.13.0 exposes no typed wrapper for it.
    CompiledCsdlOnly { command: &'static str },
}

impl OperationMapping {
    /// Reports whether this operation has no product mapping yet.
    #[must_use]
    pub const fn is_unmapped(self) -> bool {
        matches!(self, Self::Unmapped)
    }
}

/// One public typed write operation of the frozen baseline.
///
/// `code` is the stable operation code of the freeze record, `upstream_surface`
/// names the upstream method or CSDL action, `feature` the public feature that
/// compiles it, `mapping` its product status, and `note` the product decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BaselineOperation {
    code: &'static str,
    upstream_surface: &'static str,
    feature: &'static str,
    mapping: OperationMapping,
    note: &'static str,
}

impl BaselineOperation {
    /// Returns the stable freeze-record code of this operation.
    #[must_use]
    pub const fn code(self) -> &'static str {
        self.code
    }

    /// Returns the upstream surface (method or CSDL action) behind it.
    #[must_use]
    pub const fn upstream_surface(self) -> &'static str {
        self.upstream_surface
    }

    /// Returns the public feature that compiles it.
    #[must_use]
    pub const fn feature(self) -> &'static str {
        self.feature
    }

    /// Returns the product mapping status.
    #[must_use]
    pub const fn mapping(self) -> OperationMapping {
        self.mapping
    }

    /// Returns the recorded product decision for this operation.
    #[must_use]
    pub const fn note(self) -> &'static str {
        self.note
    }
}

/// The §7.5 command family codes of `rutilus_domain::RedfishCommand`, frozen
/// here so the operation inventory can reference them without constructing
/// command values. The domain crate pins these codes itself; a new family
/// must be added to both places.
pub const REDFISH_COMMAND_FAMILIES: [&str; 8] = [
    "system",
    "manager",
    "chassis",
    "boot",
    "secure-boot",
    "event",
    "update",
    "oem",
];

/// The public typed write operation inventory of `nv-redfish` 0.13.0
/// (§2.3 "公开操作清单"): every typed write method of the vendored source,
/// plus the NVIDIA OEM action families compiled by `nv-redfish-schema`
/// 0.13.0 (the §0.5.0 OEM write surfaces), plus the six product command
/// surfaces upstream exposes only through compiled CSDL member sets.
///
/// The audit gate
/// [`release_baseline_unmapped_operation_count_is_frozen`] pins
/// [`FROZEN_UNMAPPED_OPERATION_COUNT`] instead of asserting zero until the
/// parallel write-surface work items land; the final 0.8.0 gate flips the
/// frozen count to `0`. The non-NVIDIA OEM modules (AMI, Dell, Delta, HPE,
/// Lenovo, `LiteOn`, Supermicro) expose no typed write surface in 0.13.0
/// (read navigation only), so they contribute no operation entries.
pub const RELEASE_BASELINE_OPERATIONS: [BaselineOperation; 43] = [
    BaselineOperation {
        code: "account.create",
        upstream_surface: "account::AccountCollection::create_account",
        feature: "accounts",
        mapping: OperationMapping::Unmapped,
        note: "account writes carry passwords (§10 secrets) and land with the secret-handling iteration (§7.5)",
    },
    BaselineOperation {
        code: "account.update",
        upstream_surface: "account::Account::update",
        feature: "accounts",
        mapping: OperationMapping::Unmapped,
        note: "deferred with the §7.5 Account family",
    },
    BaselineOperation {
        code: "account.update-password",
        upstream_surface: "account::Account::update_password",
        feature: "accounts",
        mapping: OperationMapping::Unmapped,
        note: "deferred with the §7.5 Account family",
    },
    BaselineOperation {
        code: "account.update-user-name",
        upstream_surface: "account::Account::update_user_name",
        feature: "accounts",
        mapping: OperationMapping::Unmapped,
        note: "deferred with the §7.5 Account family",
    },
    BaselineOperation {
        code: "account.delete",
        upstream_surface: "account::Account::delete",
        feature: "accounts",
        mapping: OperationMapping::Unmapped,
        note: "deferred with the §7.5 Account family",
    },
    BaselineOperation {
        code: "control.update",
        upstream_surface: "control::Control::update",
        feature: "controls",
        mapping: OperationMapping::Unmapped,
        note: "no control command family yet (power capping, fan control)",
    },
    BaselineOperation {
        code: "manager.reset",
        upstream_surface: "manager::Manager::reset",
        feature: "managers",
        mapping: OperationMapping::Mapped { command: "manager" },
        note: "RedfishCommand::Manager(ManagerCommand::Reset)",
    },
    BaselineOperation {
        code: "manager.reset-to-defaults",
        upstream_surface: "manager::Manager::reset_to_defaults",
        feature: "managers",
        mapping: OperationMapping::Unmapped,
        note: "no command variant for the ResetToDefaults action",
    },
    BaselineOperation {
        code: "system.reset",
        upstream_surface: "computer_system::ComputerSystem::reset",
        feature: "computer-systems",
        mapping: OperationMapping::Mapped { command: "system" },
        note: "RedfishCommand::System(SystemCommand::Reset)",
    },
    BaselineOperation {
        code: "system.set-boot-order",
        upstream_surface: "computer_system::ComputerSystem::set_boot_order",
        feature: "computer-systems",
        mapping: OperationMapping::Unmapped,
        note: "the product maps the BootSourceOverride PATCH (Boot family), not the persistent boot order",
    },
    BaselineOperation {
        code: "chassis.reset",
        upstream_surface: "chassis::Chassis::reset",
        feature: "chassis",
        mapping: OperationMapping::Mapped { command: "chassis" },
        note: "RedfishCommand::Chassis(ChassisCommand::Reset)",
    },
    BaselineOperation {
        code: "power-supply.reset",
        upstream_surface: "chassis::PowerSupply::reset",
        feature: "chassis",
        mapping: OperationMapping::Unmapped,
        note: "no command variant for the power-supply Reset action",
    },
    BaselineOperation {
        code: "log.clear",
        upstream_surface: "log_service::LogService::clear_log",
        feature: "log-services",
        mapping: OperationMapping::Unmapped,
        note: "no log command family yet",
    },
    BaselineOperation {
        code: "update.simple",
        upstream_surface: "update_service::UpdateService::simple_update",
        feature: "update-service",
        mapping: OperationMapping::Unmapped,
        note: "image-URI flow; §14.3 submits artifact bytes, never a remote image URI",
    },
    BaselineOperation {
        code: "update.start",
        upstream_surface: "update_service::UpdateService::start_update",
        feature: "update-service",
        mapping: OperationMapping::Unmapped,
        note: "the StartUpdate action (apply on start request); no product flow invokes it",
    },
    BaselineOperation {
        code: "update.patch",
        upstream_surface: "update_service::UpdateService::update",
        feature: "update-service-deprecated",
        mapping: OperationMapping::Unmapped,
        note: "deprecated UpdateServiceUpdate PATCH; compiled for §0.4.0 legacy compatibility only",
    },
    BaselineOperation {
        code: "update.http-push",
        upstream_surface: "update_service::UpdateService::http_push_uri_update(_from_reader)",
        feature: "update-service-deprecated",
        mapping: OperationMapping::Mapped { command: "update" },
        note: "RedfishCommand::Update(UpdateCommand::StartUpdate) with an advertised push URI (§14.3); the deprecated LegacyCompatibility surface (§0.4.0)",
    },
    BaselineOperation {
        code: "update.multipart",
        upstream_surface: "update_service::UpdateService::multipart_update(_from_reader)",
        feature: "update-service",
        mapping: OperationMapping::Mapped { command: "update" },
        note: "RedfishCommand::Update(UpdateCommand::StartUpdate) without a push URI (§14.3)",
    },
    BaselineOperation {
        code: "telemetry.set-enabled",
        upstream_surface: "telemetry_service::TelemetryService::set_enabled",
        feature: "telemetry-service",
        mapping: OperationMapping::Unmapped,
        note: "telemetry writes are deferred (§7.5) and land with the event-service write surface",
    },
    BaselineOperation {
        code: "telemetry.create-metric-definition",
        upstream_surface: "telemetry_service::TelemetryService::create_metric_definition",
        feature: "telemetry-service",
        mapping: OperationMapping::Unmapped,
        note: "telemetry writes are deferred (§7.5)",
    },
    BaselineOperation {
        code: "telemetry.update-metric-definition",
        upstream_surface: "telemetry_service::MetricDefinition::update",
        feature: "telemetry-service",
        mapping: OperationMapping::Unmapped,
        note: "telemetry writes are deferred (§7.5)",
    },
    BaselineOperation {
        code: "telemetry.delete-metric-definition",
        upstream_surface: "telemetry_service::MetricDefinition::delete",
        feature: "telemetry-service",
        mapping: OperationMapping::Unmapped,
        note: "telemetry writes are deferred (§7.5)",
    },
    BaselineOperation {
        code: "telemetry.create-metric-report-definition",
        upstream_surface: "telemetry_service::TelemetryService::create_metric_report_definition",
        feature: "telemetry-service",
        mapping: OperationMapping::Unmapped,
        note: "telemetry writes are deferred (§7.5)",
    },
    BaselineOperation {
        code: "telemetry.update-metric-report-definition",
        upstream_surface: "telemetry_service::MetricReportDefinition::update",
        feature: "telemetry-service",
        mapping: OperationMapping::Unmapped,
        note: "telemetry writes are deferred (§7.5)",
    },
    BaselineOperation {
        code: "telemetry.delete-metric-report-definition",
        upstream_surface: "telemetry_service::MetricReportDefinition::delete",
        feature: "telemetry-service",
        mapping: OperationMapping::Unmapped,
        note: "telemetry writes are deferred (§7.5)",
    },
    BaselineOperation {
        code: "session.create",
        upstream_surface: "session_service::SessionCollection::create_session",
        feature: "session-service",
        mapping: OperationMapping::Infrastructure,
        note: "gateway authentication flow (§7.8); never a command family",
    },
    BaselineOperation {
        code: "session.delete",
        upstream_surface: "session_service::Session::delete",
        feature: "session-service",
        mapping: OperationMapping::Infrastructure,
        note: "gateway session cleanup after every operation",
    },
    BaselineOperation {
        code: "entity-link.delete",
        upstream_surface: "entity_link::EntityLink::delete",
        feature: "impl-entity-link",
        mapping: OperationMapping::Internal,
        note: "generic delete primitive for navigation-owned resources; no command surface",
    },
    BaselineOperation {
        code: "oem-nvidia.profile-update",
        upstream_surface: "NvidiaSystemConfigProfile#Update action (CSDL)",
        feature: "oem-nvidia-profiles",
        mapping: OperationMapping::Mapped { command: "oem" },
        note: "RedfishCommand::Oem(OemCommand::SystemConfigProfile(Update))",
    },
    BaselineOperation {
        code: "oem-nvidia.profile-factory-reset",
        upstream_surface: "NvidiaSystemConfigProfile#FactoryReset action (CSDL)",
        feature: "oem-nvidia-profiles",
        mapping: OperationMapping::Mapped { command: "oem" },
        note: "RedfishCommand::Oem(OemCommand::SystemConfigProfile(FactoryReset))",
    },
    BaselineOperation {
        code: "oem-nvidia.profile-activate",
        upstream_surface: "NvidiaSystemProfile#Activate action (CSDL)",
        feature: "oem-nvidia-profiles",
        mapping: OperationMapping::Mapped { command: "oem" },
        note: "RedfishCommand::Oem(OemCommand::SystemConfigProfile(ActivateProfile))",
    },
    BaselineOperation {
        code: "oem-nvidia.debug-token-generate",
        upstream_surface: "NvidiaDebugToken#GenerateToken action (CSDL)",
        feature: "oem-nvidia-security",
        mapping: OperationMapping::Mapped { command: "oem" },
        note: "RedfishCommand::Oem(OemCommand::DebugToken(GenerateToken))",
    },
    BaselineOperation {
        code: "oem-nvidia.debug-token-install",
        upstream_surface: "NvidiaDebugToken#InstallToken action (CSDL)",
        feature: "oem-nvidia-security",
        mapping: OperationMapping::Mapped { command: "oem" },
        note: "RedfishCommand::Oem(OemCommand::DebugToken(InstallToken))",
    },
    BaselineOperation {
        code: "oem-nvidia.debug-token-disable",
        upstream_surface: "NvidiaDebugToken#DisableToken action (CSDL)",
        feature: "oem-nvidia-security",
        mapping: OperationMapping::Mapped { command: "oem" },
        note: "RedfishCommand::Oem(OemCommand::DebugToken(DisableToken))",
    },
    BaselineOperation {
        code: "oem-nvidia.debug-token-erase",
        upstream_surface: "NvidiaDebugTokenManagement#EraseToken action (CSDL)",
        feature: "oem-nvidia-security",
        mapping: OperationMapping::Mapped { command: "oem" },
        note: "RedfishCommand::Oem(OemCommand::DebugToken(EraseToken))",
    },
    BaselineOperation {
        code: "oem-nvidia.power-smoothing.activate-preset-profile",
        upstream_surface: "NvidiaPowerSmoothing#ActivatePresetProfile action (CSDL)",
        feature: "oem-nvidia-power-management",
        mapping: OperationMapping::Mapped { command: "oem" },
        note: "RedfishCommand::Oem(OemCommand::PowerSmoothing(ActivatePresetProfile))",
    },
    BaselineOperation {
        code: "oem-nvidia.power-smoothing.apply-admin-overrides",
        upstream_surface: "NvidiaPowerSmoothing#ApplyAdminOverrides action (CSDL)",
        feature: "oem-nvidia-power-management",
        mapping: OperationMapping::Mapped { command: "oem" },
        note: "RedfishCommand::Oem(OemCommand::PowerSmoothing(ApplyAdminOverrides))",
    },
    BaselineOperation {
        code: "boot.set-boot-source-override",
        upstream_surface: "ComputerSystem Boot PATCH (CSDL BootSourceOverride* member set)",
        feature: "computer-systems",
        mapping: OperationMapping::CompiledCsdlOnly { command: "boot" },
        note: "RedfishCommand::Boot(BootCommand::SetBootSourceOverride); upstream 0.13.0 exposes no typed wrapper, the gateway patches the compiled Boot member set",
    },
    BaselineOperation {
        code: "secure-boot.enable",
        upstream_surface: "SecureBoot SecureBootEnable PATCH (CSDL)",
        feature: "secure-boot",
        mapping: OperationMapping::CompiledCsdlOnly {
            command: "secure-boot",
        },
        note: "RedfishCommand::SecureBoot(SecureBootCommand::Enable); no typed wrapper upstream, the gateway patches the compiled property",
    },
    BaselineOperation {
        code: "secure-boot.disable",
        upstream_surface: "SecureBoot SecureBootEnable PATCH (CSDL)",
        feature: "secure-boot",
        mapping: OperationMapping::CompiledCsdlOnly {
            command: "secure-boot",
        },
        note: "RedfishCommand::SecureBoot(SecureBootCommand::Disable); no typed wrapper upstream",
    },
    BaselineOperation {
        code: "secure-boot.reset-keys",
        upstream_surface: "SecureBoot#ResetKeys action (CSDL)",
        feature: "secure-boot",
        mapping: OperationMapping::CompiledCsdlOnly {
            command: "secure-boot",
        },
        note: "RedfishCommand::SecureBoot(SecureBootCommand::ResetKeys); no typed wrapper upstream, the gateway invokes the compiled action",
    },
    BaselineOperation {
        code: "event.create-subscription",
        upstream_surface: "EventService Subscriptions collection POST (EventDestination CSDL)",
        feature: "event-service",
        mapping: OperationMapping::CompiledCsdlOnly { command: "event" },
        note: "RedfishCommand::Event(EventCommand::CreateSubscription); upstream 0.13.0 exposes no subscription wrapper, the gateway POSTs the typed CSDL projection",
    },
    BaselineOperation {
        code: "event.delete-subscription",
        upstream_surface: "EventSubscription DELETE (CSDL)",
        feature: "event-service",
        mapping: OperationMapping::CompiledCsdlOnly { command: "event" },
        note: "RedfishCommand::Event(EventCommand::DeleteSubscription); upstream 0.13.0 exposes no subscription wrapper",
    },
];

/// The frozen number of upstream typed write operations without a product
/// mapping yet.
///
/// The 0.8.0 acceptance criterion `未映射公开操作 = 0` is met when this
/// count is `0`; until the parallel write-surface work items land, the audit
/// gate asserts the inventory reports exactly this documented count so the
/// record cannot grow silently. The count matches the `Unmapped` entries of
/// [`RELEASE_BASELINE_OPERATIONS`].
pub const FROZEN_UNMAPPED_OPERATION_COUNT: usize = 20;

/// The frozen capability-ledger hash snapshot (§2.3 "能力账本 Hash").
///
/// The digest of the `as_str()` product codes of
/// [`rutilus_domain::CAPABILITY_LEDGER_ORDER`] concatenated in ledger order
/// with no separator — the exact §15.3 algorithm the center negotiates with.
/// [`release_baseline_ledger_hash_matches_the_negotiation_golden`] proves the
/// snapshot equals both the freshly computed digest and the golden digest
/// pinned by `rutilus-center-protocol`'s negotiation tests.
pub const RELEASE_BASELINE_LEDGER_HASH: [u8; 32] = [
    0x1C, 0xEB, 0x3C, 0xEB, 0x0D, 0x6E, 0xB4, 0xF2, 0xB7, 0x0B, 0xA2, 0x0C, 0x16, 0x51, 0x66, 0x3A,
    0xC3, 0x83, 0x21, 0x95, 0xEE, 0x75, 0x63, 0xB6, 0x07, 0x2D, 0x27, 0x2B, 0xF6, 0xBE, 0xE8, 0x0E,
];

/// Computes the §15.3 capability-ledger hash over the current domain ledger.
///
/// This is a local re-implementation of
/// `rutilus_center_protocol::negotiation::capability_ledger_hash` (the
/// freeze record must not depend on the center-protocol crate): the same
/// SHA-256 over the concatenated ledger codes. Both sides of the connection
/// compute identically, and the golden test pins the digest.
#[must_use]
pub fn capability_ledger_hash() -> [u8; 32] {
    let mut hasher = Sha256::new();
    for capability in CAPABILITY_LEDGER_ORDER {
        hasher.update(capability.as_str());
    }
    hasher.finalize().into()
}

/// The complete frozen release baseline (§2.3).
///
/// The aggregate record that the 0.8.0 freeze gates against: version,
/// known-newer-stable record, explicit and complete feature inventories,
/// schema versions, module inventory, operation inventory, and the
/// capability-ledger hash snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NvRedfishReleaseBaseline {
    version: &'static str,
    known_newer_stable: Option<&'static str>,
    explicit_features: &'static [&'static str],
    enabled_features: &'static [&'static str],
    modules: &'static [BaselineModule],
    operations: &'static [BaselineOperation],
    schema_versions: ReleaseSchemaVersions,
    ledger_hash: [u8; 32],
}

impl NvRedfishReleaseBaseline {
    /// Returns the frozen exact crate version.
    #[must_use]
    pub const fn version(self) -> &'static str {
        self.version
    }

    /// Returns the newer stable release recorded for the freeze review.
    #[must_use]
    pub const fn known_newer_stable(self) -> Option<&'static str> {
        self.known_newer_stable
    }

    /// Returns the explicitly enabled public features.
    #[must_use]
    pub const fn explicit_features(self) -> &'static [&'static str] {
        self.explicit_features
    }

    /// Returns the complete set of compiled public features.
    #[must_use]
    pub const fn enabled_features(self) -> &'static [&'static str] {
        self.enabled_features
    }

    /// Returns the public module inventory.
    #[must_use]
    pub const fn modules(self) -> &'static [BaselineModule] {
        self.modules
    }

    /// Returns the public operation inventory.
    #[must_use]
    pub const fn operations(self) -> &'static [BaselineOperation] {
        self.operations
    }

    /// Returns the frozen schema-layer versions.
    #[must_use]
    pub const fn schema_versions(self) -> ReleaseSchemaVersions {
        self.schema_versions
    }

    /// Returns the frozen capability-ledger hash snapshot.
    #[must_use]
    pub const fn ledger_hash(self) -> [u8; 32] {
        self.ledger_hash
    }

    /// Returns how many public operations have no product mapping yet — the
    /// audit-mode number behind the 0.8.0 `未映射公开操作 = 0` criterion.
    #[must_use]
    pub const fn unmapped_operation_count(self) -> usize {
        let mut count = 0;
        let mut index = 0;
        while index < self.operations.len() {
            if self.operations[index].mapping.is_unmapped() {
                count += 1;
            }
            index += 1;
        }
        count
    }
}

/// The frozen 0.8.0 release baseline of the upstream `nv-redfish` surface.
pub const NV_REDFISH_RELEASE_BASELINE: NvRedfishReleaseBaseline = NvRedfishReleaseBaseline {
    version: NV_REDFISH_RELEASE_BASELINE_VERSION,
    known_newer_stable: NV_REDFISH_KNOWN_NEWER_STABLE_VERSION,
    explicit_features: &RELEASE_BASELINE_EXPLICIT_FEATURES,
    enabled_features: &RELEASE_BASELINE_ENABLED_FEATURES,
    modules: &RELEASE_BASELINE_MODULES,
    operations: &RELEASE_BASELINE_OPERATIONS,
    schema_versions: RELEASE_SCHEMA_VERSIONS,
    ledger_hash: RELEASE_BASELINE_LEDGER_HASH,
};

#[cfg(test)]
mod tests {
    use std::{error::Error, fs, path::Path};

    use rutilus_domain::{CAPABILITY_LEDGER_ORDER, OEM_CAPABILITY_LEDGER_ORDER};

    use super::*;

    /// The golden digest pinned by
    /// `rutilus-center-protocol/src/negotiation.rs` (`GOLDEN_LEDGER_HASH`),
    /// copied here so the freeze record and the wire contract cannot drift
    /// apart unnoticed: any change on either side fails this test or the
    /// negotiation test.
    const NEGOTIATION_GOLDEN_LEDGER_HASH: [u8; 32] = [
        0x1C, 0xEB, 0x3C, 0xEB, 0x0D, 0x6E, 0xB4, 0xF2, 0xB7, 0x0B, 0xA2, 0x0C, 0x16, 0x51, 0x66,
        0x3A, 0xC3, 0x83, 0x21, 0x95, 0xEE, 0x75, 0x63, 0xB6, 0x07, 0x2D, 0x27, 0x2B, 0xF6, 0xBE,
        0xE8, 0x0E,
    ];

    /// The §2.1 standard ledger features that compile through the generated
    /// schema surface instead of a top-level wrapper module (`computer_system::bios`,
    /// `chassis::power`, ...); `environment-metrics` is enabled through
    /// `controls`/`sensors` and has no module either. The ledger-mapping test
    /// proves these are exactly the standard ledger features without a
    /// [`BaselineModule`].
    const LEDGER_FEATURES_WITHOUT_TOP_LEVEL_MODULE: [&str; 12] = [
        "bios",
        "boot-options",
        "environment-metrics",
        "manager-network-protocol",
        "memory",
        "network-adapters",
        "power",
        "power-supplies",
        "processors",
        "secure-boot",
        "storages",
        "thermal",
    ];

    /// Standard features compiled by the product whose domain-ledger entry is
    /// still pending (§0.8.0: "纳入从 0.12.1 到冻结版本新增的所有公开
    /// feature").
    ///
    /// `ports` is new in 0.13.0 — the §2.1 inventory was written against
    /// 0.12.1 and the domain ledger has no `Ports` variant yet. The freeze
    /// record classifies the module and keeps this list non-empty so the
    /// 0.8.0 ledger work cannot drop the entry; once the domain ledger lands
    /// it, the ledger-coverage test fails and the entry must move out of this
    /// list into the mapped inventory.
    const PENDING_LEDGER_FEATURES: [&str; 1] = ["ports"];

    /// Reads one workspace file relative to this crate's manifest.
    fn read_workspace_file(relative: &str) -> Result<String, Box<dyn Error>> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(relative);
        Ok(fs::read_to_string(path)?)
    }

    /// Returns the manifest line that declares the `nv-redfish` dependency.
    fn nv_redfish_declaration(manifest: &str) -> Result<String, Box<dyn Error>> {
        let lines: Vec<&str> = manifest.lines().collect();
        let declaration = lines
            .iter()
            .find(|line| line.contains("nv-redfish = {"))
            .ok_or("no `nv-redfish = {` declaration in the manifest")?;
        Ok((*declaration).to_owned())
    }

    /// Extracts the `features = [...]` list of one dependency declaration.
    fn feature_list(declaration: &str) -> Result<Vec<String>, Box<dyn Error>> {
        let start = declaration
            .find("features = [")
            .ok_or("no `features = [` in the declaration")?;
        let rest = &declaration[start + "features = [".len()..];
        let end = rest.find(']').ok_or("unterminated feature list")?;
        Ok(rest[..end]
            .split(',')
            .map(|item| item.trim().trim_matches('"').to_owned())
            .filter(|item| !item.is_empty())
            .collect())
    }

    /// Extracts the pinned version string of one dependency declaration
    /// (for example `=0.13.0`).
    fn pinned_version(declaration: &str) -> Result<String, Box<dyn Error>> {
        let start = declaration
            .find("version = \"")
            .ok_or("no pinned version in the declaration")?;
        let rest = &declaration[start + "version = \"".len()..];
        let end = rest.find('"').ok_or("unterminated pinned version")?;
        Ok(rest[..end].to_owned())
    }

    /// Returns the `version` line value of one `[[package]]` entry of the
    /// committed lockfile.
    fn lockfile_version(lockfile: &str, package: &str) -> Result<String, Box<dyn Error>> {
        let lines: Vec<&str> = lockfile.lines().collect();
        let position = lines
            .iter()
            .position(|line| *line == format!("name = \"{package}\""))
            .ok_or(format!("package {package} missing from Cargo.lock"))?;
        let version_line = lines
            .get(position + 1)
            .ok_or("Cargo.lock entry has no version line")?;
        let version = version_line
            .strip_prefix("version = \"")
            .and_then(|rest| rest.strip_suffix('"'))
            .map(str::to_owned)
            .ok_or("Cargo.lock version line is malformed")?;
        Ok(version)
    }

    /// Returns the vendored `nv-redfish` `src/lib.rs` of the frozen version,
    /// when the cargo registry source is available.
    ///
    /// The registry directory carries a machine-specific hash suffix
    /// (`index.crates.io-*`), so the location is discovered by walking
    /// `$CARGO_HOME/registry/src/` at runtime instead of baking an absolute
    /// path into the build. When `CARGO_HOME` is unset (a non-standard cargo
    /// invocation) the comparison is skipped; every normal cargo build sets
    /// it, including CI.
    fn vendored_lib_rs() -> Option<String> {
        let cargo_home = std::env::var("CARGO_HOME").ok()?;
        let registry_src = Path::new(&cargo_home).join("registry").join("src");
        let entries = fs::read_dir(registry_src).ok()?;
        for entry in entries.flatten() {
            let candidate = entry
                .path()
                .join(format!("nv-redfish-{NV_REDFISH_RELEASE_BASELINE_VERSION}"))
                .join("src")
                .join("lib.rs");
            if candidate.is_file() {
                return fs::read_to_string(candidate).ok();
            }
        }
        None
    }

    /// Extracts every `pub mod NAME;` declaration of the vendored `lib.rs`.
    fn public_module_names(lib_rs: &str) -> Vec<String> {
        lib_rs
            .lines()
            .filter_map(|line| {
                let line = line.trim();
                let rest = line.strip_prefix("pub mod ")?;
                rest.strip_suffix(';').map(|name| name.trim().to_owned())
            })
            .collect()
    }

    /// Extracts every module-shaped `pub use ... as NAME;` re-export of the
    /// vendored `lib.rs` (the `core`, `bmc_http`, and `schema` re-exports;
    /// the type re-exports of the file never use `as`).
    fn module_reexport_names(lib_rs: &str) -> Vec<String> {
        lib_rs
            .lines()
            .filter_map(|line| {
                let line = line.trim();
                let rest = line.strip_prefix("pub use ")?;
                let (_, name) = rest.split_once(" as ")?;
                name.strip_suffix(';').map(|name| name.trim().to_owned())
            })
            .collect()
    }

    #[test]
    fn release_baseline_version_is_recorded_with_the_newer_stable() {
        assert!(!NV_REDFISH_RELEASE_BASELINE_VERSION.is_empty());
        assert_eq!(
            NV_REDFISH_RELEASE_BASELINE_VERSION,
            NV_REDFISH_RELEASE_BASELINE.version()
        );
        assert_eq!(
            NV_REDFISH_RELEASE_BASELINE.known_newer_stable(),
            NV_REDFISH_KNOWN_NEWER_STABLE_VERSION
        );
        // The known-newer-stable record, when present, must differ from the
        // frozen version and look like a semver: the upgrade decision is a
        // freeze-review item, never an unrecorded version bump.
        if let Some(newer) = NV_REDFISH_KNOWN_NEWER_STABLE_VERSION {
            assert_ne!(newer, NV_REDFISH_RELEASE_BASELINE_VERSION);
            let parts: Vec<&str> = newer.split('.').collect();
            assert_eq!(
                parts.len(),
                3,
                "the recorded newer stable must be a version"
            );
            for part in parts {
                assert!(
                    part.chars().all(|c| c.is_ascii_digit()),
                    "the recorded newer stable must be numeric"
                );
            }
        }
    }

    #[test]
    fn release_baseline_version_matches_the_pinned_manifest() -> Result<(), Box<dyn Error>> {
        let root_manifest = read_workspace_file("../Cargo.toml")?;
        let declaration = nv_redfish_declaration(&root_manifest)?;
        let expected_pin = format!("={NV_REDFISH_RELEASE_BASELINE_VERSION}");
        assert_eq!(
            pinned_version(&declaration)?,
            expected_pin,
            "the workspace must pin exactly the frozen version"
        );
        Ok(())
    }

    #[test]
    fn release_baseline_explicit_features_match_the_workspace_manifests_bidirectionally()
    -> Result<(), Box<dyn Error>> {
        let root_manifest = read_workspace_file("../Cargo.toml")?;
        let infra_manifest = read_workspace_file("Cargo.toml")?;
        let mut manifest_features = Vec::new();
        for declaration in [
            nv_redfish_declaration(&root_manifest)?,
            nv_redfish_declaration(&infra_manifest)?,
        ] {
            for feature in feature_list(&declaration)? {
                if !manifest_features.contains(&feature) {
                    manifest_features.push(feature);
                }
            }
        }
        let mut expected = RELEASE_BASELINE_EXPLICIT_FEATURES.to_vec();
        manifest_features.sort_unstable();
        expected.sort_unstable();
        assert_eq!(
            manifest_features, expected,
            "the explicit feature inventory must equal the union of both manifest feature lists \
             in both directions: an extra or a missing feature fails the freeze gate"
        );
        Ok(())
    }

    #[test]
    fn release_baseline_enabled_features_are_the_complete_compiled_surface() {
        // Every enabled feature exists upstream (typo universe) ...
        for feature in RELEASE_BASELINE_ENABLED_FEATURES {
            assert!(
                NV_REDFISH_0_13_0_FEATURE_UNIVERSE.contains(&feature),
                "enabled feature {feature} is not defined by nv-redfish 0.13.0"
            );
        }
        // ... and every explicit feature is enabled.
        for feature in RELEASE_BASELINE_EXPLICIT_FEATURES {
            assert!(
                RELEASE_BASELINE_ENABLED_FEATURES.contains(&feature),
                "explicit feature {feature} is missing from the enabled inventory"
            );
        }
        // The enabled set is the universe minus exactly `default`
        // (default-features = false): the complete compiled public feature
        // surface, nothing more and nothing less.
        let mut enabled = RELEASE_BASELINE_ENABLED_FEATURES.to_vec();
        let mut universe = NV_REDFISH_0_13_0_FEATURE_UNIVERSE.to_vec();
        enabled.sort_unstable();
        universe.sort_unstable();
        let not_enabled: Vec<&str> = universe
            .iter()
            .copied()
            .filter(|feature| !enabled.contains(feature))
            .collect();
        assert_eq!(
            not_enabled,
            ["default"],
            "the only non-compiled public feature must be `default`"
        );
    }

    #[test]
    fn release_baseline_every_module_gating_feature_is_compiled() {
        for module in RELEASE_BASELINE_MODULES {
            let Some(feature) = module.gating_feature() else {
                continue;
            };
            assert!(
                RELEASE_BASELINE_ENABLED_FEATURES.contains(&feature),
                "module {} is gated by {feature}, which is not compiled",
                module.name()
            );
        }
    }

    #[test]
    fn release_baseline_every_module_is_classified_with_a_decision() {
        let mut names = Vec::new();
        let mut ledger_mapped = 0;
        let mut infrastructure = 0;
        let mut legacy_compatibility = 0;
        let mut internal = 0;
        for module in RELEASE_BASELINE_MODULES {
            let name = module.name();
            assert!(!name.is_empty(), "module names must not be empty");
            assert!(
                !names.contains(&name),
                "module {name} is listed more than once"
            );
            names.push(name);
            assert!(
                !module.decision().is_empty(),
                "module {name} must carry a product decision"
            );
            assert!(
                module.gating_feature().is_some()
                    || module.classification() != BaselineModuleClassification::LedgerMapped,
                "a ledger-mapped module must be feature-gated"
            );
            match module.classification() {
                BaselineModuleClassification::LedgerMapped => ledger_mapped += 1,
                BaselineModuleClassification::Infrastructure => infrastructure += 1,
                BaselineModuleClassification::LegacyCompatibility => legacy_compatibility += 1,
                BaselineModuleClassification::Internal => internal += 1,
            }
        }
        // The §2.4 rule "上游已经公开但产品没人知道有没有使用" must be
        // mechanically impossible: every entry is one of the four classes
        // with a decision, so there is no unclassified module by
        // construction — the counts below freeze the distribution.
        assert_eq!(ledger_mapped, 19);
        assert_eq!(infrastructure, 8);
        assert_eq!(
            legacy_compatibility, 0,
            "the legacy surface lives at the operation level (update.http-push), \
             no module is purely legacy"
        );
        assert_eq!(internal, 2);
        assert_eq!(names.len(), RELEASE_BASELINE_MODULES.len());
    }

    #[test]
    fn release_baseline_ledger_mapped_modules_are_exactly_the_ledger_features() {
        let mut standard_ledger_features: Vec<&str> = CAPABILITY_LEDGER_ORDER
            .iter()
            .filter(|capability| !OEM_CAPABILITY_LEDGER_ORDER.contains(capability))
            .map(|capability| capability.upstream_feature())
            .collect();
        let mut mapped_features = Vec::new();
        for module in RELEASE_BASELINE_MODULES {
            if module.classification() != BaselineModuleClassification::LedgerMapped {
                continue;
            }
            let Some(feature) = module.gating_feature() else {
                // The pairing assertion in
                // `every_module_is_classified_with_a_decision` already fails
                // for a ledger-mapped module without a gating feature; this
                // branch additionally makes the coverage equality below
                // fail, so the record cannot degrade silently.
                continue;
            };
            assert!(
                standard_ledger_features.contains(&feature)
                    || PENDING_LEDGER_FEATURES.contains(&feature),
                "module {} maps feature {feature}, which has no standard ledger entry \
                 and is not recorded as pending",
                module.name()
            );
            assert!(
                !mapped_features.contains(&feature),
                "feature {feature} is mapped by more than one module"
            );
            mapped_features.push(feature);
        }
        // The pending entries must really be pending: the moment a parallel
        // work item lands the ledger entry, this assertion fails and the
        // entry must move out of the pending list into the mapped inventory.
        for pending in PENDING_LEDGER_FEATURES {
            assert!(
                !standard_ledger_features.contains(&pending),
                "pending feature {pending} is now in the ledger; move it out of \
                 PENDING_LEDGER_FEATURES"
            );
        }
        // Coverage: module features plus the documented schema-surface list
        // must cover the standard ledger plus the pending entries exactly
        // once each — the compiled standard surface of 0.13.0 (the
        // `std-redfish` group plus `environment-metrics`, which moved out of
        // `std-redfish` in 0.13.0 and is enabled through controls/sensors).
        let mut covered = mapped_features;
        covered.extend(LEDGER_FEATURES_WITHOUT_TOP_LEVEL_MODULE);
        covered.sort_unstable();
        standard_ledger_features.extend(PENDING_LEDGER_FEATURES);
        standard_ledger_features.sort_unstable();
        assert_eq!(
            covered, standard_ledger_features,
            "every standard feature must be covered by a module or the documented schema-surface \
             list, exactly once, and the pending entries must equal the ledger gap exactly"
        );
    }

    #[test]
    fn release_baseline_ledger_hash_matches_the_negotiation_golden() {
        let computed = capability_ledger_hash();
        assert_eq!(computed, RELEASE_BASELINE_LEDGER_HASH);
        assert_eq!(
            computed, NEGOTIATION_GOLDEN_LEDGER_HASH,
            "the frozen snapshot must equal the golden digest pinned by \
             rutilus-center-protocol/src/negotiation.rs"
        );
        assert_eq!(NV_REDFISH_RELEASE_BASELINE.ledger_hash(), computed);
    }

    #[test]
    fn release_baseline_module_inventory_matches_the_vendored_lib_rs() {
        let Some(lib_rs) = vendored_lib_rs() else {
            eprintln!(
                "skipping the vendored-source comparison: the nv-redfish-{NV_REDFISH_RELEASE_BASELINE_VERSION} \
                 source was not found under $CARGO_HOME/registry/src/"
            );
            return;
        };
        let declared_modules = public_module_names(&lib_rs);
        let mut declared_reexports = module_reexport_names(&lib_rs);
        declared_reexports.sort_unstable();
        let expected_reexports = ["bmc_http", "core", "schema"];
        assert_eq!(
            declared_reexports, expected_reexports,
            "the vendored lib.rs must re-export exactly the three module surfaces of the record"
        );
        let inventory_names: Vec<&str> = RELEASE_BASELINE_MODULES
            .iter()
            .map(|module| BaselineModule::name(*module))
            .collect();
        // Every inventory entry must exist in the vendored source.
        for name in &inventory_names {
            assert!(
                declared_modules.contains(&(*name).to_owned())
                    || declared_reexports.contains(&(*name).to_owned()),
                "module {name} is recorded but absent from the vendored src/lib.rs"
            );
        }
        // Every public module of the vendored source must be recorded.
        for declared in &declared_modules {
            assert!(
                inventory_names.contains(&declared.as_str()),
                "public module {declared} of the vendored src/lib.rs is missing from the record"
            );
        }
        // Every recorded gating feature must gate a module in the source.
        for module in RELEASE_BASELINE_MODULES {
            let Some(feature) = module.gating_feature() else {
                continue;
            };
            assert!(
                lib_rs.contains(&format!("feature = \"{feature}\"")),
                "module {} records gating feature {feature}, which gates nothing in the source",
                module.name()
            );
        }
    }

    #[test]
    fn release_baseline_operations_inventory_is_internally_consistent() {
        let mut codes = Vec::new();
        let mut covered_families = Vec::new();
        for operation in RELEASE_BASELINE_OPERATIONS {
            let code = operation.code();
            assert!(!code.is_empty(), "operation codes must not be empty");
            assert!(
                !codes.contains(&code),
                "operation code {code} is listed more than once"
            );
            codes.push(code);
            assert!(
                !operation.upstream_surface().is_empty(),
                "operation {code} must name its upstream surface"
            );
            assert!(
                RELEASE_BASELINE_ENABLED_FEATURES.contains(&operation.feature()),
                "operation {code} uses feature {}, which is not compiled",
                operation.feature()
            );
            if let Some(command) = operation.command_family() {
                assert!(
                    REDFISH_COMMAND_FAMILIES.contains(&command),
                    "operation {code} names unknown command family {command}"
                );
                if !covered_families.contains(&command) {
                    covered_families.push(command);
                }
            }
        }
        // Every §7.5 family must be covered by at least one operation entry
        // (mapped or compiled-CSDL-only): the reverse direction of the
        // mapping table.
        covered_families.sort_unstable();
        let mut families = REDFISH_COMMAND_FAMILIES.to_vec();
        families.sort_unstable();
        assert_eq!(
            covered_families, families,
            "every RedfishCommand family must be covered by an operation entry"
        );
        assert_eq!(codes.len(), RELEASE_BASELINE_OPERATIONS.len());
    }

    #[test]
    fn release_baseline_unmapped_operation_count_is_frozen() {
        let unmapped = RELEASE_BASELINE_OPERATIONS
            .iter()
            .filter(|operation| operation.mapping().is_unmapped())
            .count();
        assert_eq!(
            unmapped, FROZEN_UNMAPPED_OPERATION_COUNT,
            "the audit-mode record freezes the unmapped count; change both sides deliberately \
             when a parallel write-surface work item lands"
        );
        assert_eq!(
            NV_REDFISH_RELEASE_BASELINE.unmapped_operation_count(),
            FROZEN_UNMAPPED_OPERATION_COUNT
        );
    }

    #[test]
    fn release_baseline_schema_versions_match_the_committed_lockfile() -> Result<(), Box<dyn Error>>
    {
        let lockfile = read_workspace_file("../Cargo.lock")?;
        assert_eq!(
            lockfile_version(&lockfile, "nv-redfish")?,
            NV_REDFISH_RELEASE_BASELINE_VERSION
        );
        assert_eq!(
            lockfile_version(&lockfile, "nv-redfish-schema")?,
            RELEASE_SCHEMA_VERSIONS.schema()
        );
        assert_eq!(
            lockfile_version(&lockfile, "nv-redfish-core")?,
            RELEASE_SCHEMA_VERSIONS.core()
        );
        assert_eq!(
            lockfile_version(&lockfile, "nv-redfish-bmc-http")?,
            RELEASE_SCHEMA_VERSIONS.bmc_http()
        );
        assert_eq!(
            lockfile_version(&lockfile, "nv-redfish-csdl-compiler")?,
            RELEASE_SCHEMA_VERSIONS.csdl_compiler()
        );
        assert_eq!(RELEASE_SCHEMA_VERSIONS.schema(), "0.13.0");
        Ok(())
    }

    #[test]
    fn release_baseline_aggregate_links_every_inventory() {
        let baseline = NV_REDFISH_RELEASE_BASELINE;
        assert_eq!(baseline.version(), NV_REDFISH_RELEASE_BASELINE_VERSION);
        assert_eq!(
            baseline.explicit_features(),
            &RELEASE_BASELINE_EXPLICIT_FEATURES
        );
        assert_eq!(
            baseline.enabled_features(),
            &RELEASE_BASELINE_ENABLED_FEATURES
        );
        assert_eq!(baseline.modules(), &RELEASE_BASELINE_MODULES);
        assert_eq!(baseline.operations(), &RELEASE_BASELINE_OPERATIONS);
        assert_eq!(baseline.schema_versions(), RELEASE_SCHEMA_VERSIONS);
        assert_eq!(baseline.ledger_hash(), RELEASE_BASELINE_LEDGER_HASH);
        assert_eq!(baseline.explicit_features().len(), 17);
        assert_eq!(baseline.enabled_features().len(), 58);
        assert_eq!(baseline.modules().len(), 29);
        assert_eq!(baseline.operations().len(), 43);
    }

    impl BaselineOperation {
        /// Returns the `RedfishCommand` family this operation maps to, when
        /// its mapping names one.
        const fn command_family(self) -> Option<&'static str> {
            match self.mapping {
                OperationMapping::Mapped { command }
                | OperationMapping::CompiledCsdlOnly { command } => Some(command),
                OperationMapping::Unmapped
                | OperationMapping::Infrastructure
                | OperationMapping::Internal => None,
            }
        }
    }
}
