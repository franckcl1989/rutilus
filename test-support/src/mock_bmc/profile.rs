//! Vendor fixture profiles of the Mock BMC (design section 0.5.0 vendor
//! profiles).
//!
//! A profile fixes the whole fixture tree's vendor identity: the Service Root
//! `Vendor`/`Product` strings, which documents advertise an `Oem` namespace,
//! and which OEM documents the tree serves. The Mock BMC serves the default
//! [`MockProfile::Rutilus`] tree (the historic single fixture) through
//! [`MockBmc::start`](crate::MockBmc::start), and any other profile through
//! [`MockBmc::start_with_profile`](crate::MockBmc::start_with_profile); the
//! `mock-bmc` binary picks one with `--profile`.
//!
//! The profile type is deliberately a per-vendor variant list rather than a
//! combination of orthogonal flags: a real vendor's fixture tree is one
//! coherent bundle (identity strings, `Oem` namespaces, and the documents
//! behind them change together), and a per-vendor variant leaves no way to
//! serve a half-merged tree. A vendor that serves no OEM surface -- the
//! 0.5.0 xFusion/Inspur standard-pattern verification basis, realized by
//! [`MockProfile::XFusion`] and [`MockProfile::Inspur`] -- is simply a
//! variant that changes the identity strings and carries no `Oem` fixtures at
//! all, so the capability probe keeps reporting every §2.1 OEM capability
//! `NotAdvertised` exactly like the default tree. The NVIDIA profile is the
//! first vendor surface carried by a System member (`Oem.Nvidia` on
//! `Systems/1`, the 0.5.0 NVIDIA OEM surface), where the Dell and Lenovo
//! profiles carry their surfaces on the manager; the per-profile routing
//! gates the chain documents exactly like the Dell Attributes routes.
//!
//! A vendor profile's identity replacement is deliberately scoped to the
//! Service Root strings (and the `Oem` namespaces), never to the
//! hardware-level identity fields of the shared documents: the System,
//! Chassis, and Manager `Manufacturer` values stay "Rutilus Test". The
//! product's probe and read layers tell vendors apart only through the
//! Service Root identity and the decoded `Oem` keys -- the single
//! `Manufacturer`-gated surface is the `LiteOn` chassis probe, which keys on
//! the exact value `LITE-ON TECHNOLOGY CORP.` that no other profile's
//! chassis carries, so a shared "Rutilus Test" hardware id can never falsely
//! trigger a vendor gate. Swapping the identity strings and namespaces is
//! therefore sufficient to exercise a vendor surface, and sharing every
//! other document is the deliberate minimalism that keeps the tree single
//! instead of duplicated per vendor.

/// One vendor fixture profile the Mock BMC can serve.
///
/// The default profile keeps the historic single fixture tree byte-identical:
/// Vendor "Rutilus Test" / Product "Mock BMC" with no `Oem` namespace
/// anywhere, so every §2.1 OEM capability probes `NotAdvertised`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MockProfile {
    /// The default fixture tree: Vendor "Rutilus Test" / Product "Mock BMC",
    /// no vendor `Oem` namespace on any document.
    #[default]
    Rutilus,
    /// The Dell iDRAC fixture tree: Vendor "Dell Inc." / Product
    /// `PowerEdge R750`, `Managers/1` advertises `Oem.Dell`, and the §11.5
    /// `DellAttributes` document is served at
    /// `{manager}/Oem/Dell/DellAttributes/{id}`. Every other document of the
    /// tree is shared with the default profile.
    Dell,
    /// The NVIDIA `BlueField` fixture tree: Vendor "NVIDIA" / Product
    /// `BlueField-3`, `Systems/1` and `Managers/1` both advertise
    /// `Oem.Nvidia` (which flips the `oem-nvidia*` capability probe to
    /// `Supported`), and the §11.5 chains are served — the
    /// system-config-profile chain (the profile service document, its status
    /// singleton, the profile collection, one profile member, and its
    /// profile file) plus the manager-scoped power-compliance chain (the
    /// compliance manager document, its power domain collection member, the
    /// two policy singletons, the managed entity group collection member,
    /// the power state group with its PSC and PSU state collection members,
    /// and the PSU redundancy singleton) and the managed-entity chain (the
    /// entity collection member behind the group). Every other document of
    /// the tree is shared with the default profile.
    Nvidia,
    /// The Lenovo XCC fixture tree: Vendor "Lenovo" / Product
    /// `ThinkSystem SR650`, `Managers/1` advertises `Oem.Lenovo` (which flips
    /// the `oem-lenovo` capability probe to `Supported`), and the §11.5
    /// `SecurityService` document is served at the embedded `Security`
    /// navigation of the `Oem.Lenovo` segment. Every other document of the
    /// tree is shared with the default profile.
    Lenovo,
    /// The xFusion standard-pattern fixture tree: Vendor "xFusion" / Product
    /// `2288H V7`, with no `Oem` namespace on any document. This is the
    /// §21 0.5.0 no-OEM verification basis: because no vendor `Oem`
    /// namespace is served, every §2.1 OEM capability probes `NotAdvertised`
    /// exactly like the default tree, and no other vendor's surface can
    /// mis-display. Every document of the tree is shared with the default
    /// profile except the Service Root identity strings.
    XFusion,
    /// The Inspur standard-pattern fixture tree: Vendor "Inspur" / Product
    /// `NF5280M6`, with no `Oem` namespace on any document. This is the
    /// second §21 0.5.0 no-OEM verification basis, exercising the same
    /// standard pattern as [`MockProfile::XFusion`] against a different
    /// vendor identity. Every document of the tree is shared with the
    /// default profile except the Service Root identity strings.
    Inspur,
}

impl MockProfile {
    /// The lowercase profile name, matching the `mock-bmc` `--profile`
    /// values (`rutilus` | `dell` | `nvidia` | `lenovo` | `xfusion` |
    /// `inspur`).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Rutilus => "rutilus",
            Self::Dell => "dell",
            Self::Nvidia => "nvidia",
            Self::Lenovo => "lenovo",
            Self::XFusion => "xfusion",
            Self::Inspur => "inspur",
        }
    }
}
