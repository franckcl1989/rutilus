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
//! 0.5.0 xFusion/Inspur standard-pattern verification basis -- is simply a
//! variant that changes the identity strings and carries no `Oem` fixtures at
//! all, so the capability probe keeps reporting every §2.1 OEM capability
//! `NotAdvertised` exactly like the default tree.
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
}

impl MockProfile {
    /// The lowercase profile name, matching the `mock-bmc` `--profile`
    /// values (`rutilus` | `dell`).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Rutilus => "rutilus",
            Self::Dell => "dell",
        }
    }
}
