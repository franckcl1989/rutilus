//! The `mock-bmc` development binary: runs the deterministic HTTPS Mock
//! Redfish BMC on loopback and prints the endpoint URL and SHA-256
//! fingerprint for the demo and for the product's endpoint trust dialog.
//!
//! Usage: `mock-bmc [--port <port>] [--profile <profile>]`, or the
//! positional shorthand `mock-bmc <port> [profile]` (for example
//! `mock-bmc 9443 dell`). The long options win when both spellings are
//! given, so the two forms can never disagree; the defaults are unchanged:
//! port `0` selects a free port and the profile is `rutilus`. Run
//! `mock-bmc --help` for the accepted profile names.
//!
//! This is a development and demo tool only, not a product CLI: the product
//! binary is `rutilus` (the `app` crate). The fingerprint is identical on
//! every run because the Mock BMC serves a deterministic certificate.

#![forbid(unsafe_code)]

use std::error::Error;

use clap::Parser;
use rutilus_test_support::{MockBmc, MockProfile};

#[derive(Debug, Parser)]
#[command(
    name = "mock-bmc",
    about = "Runs the deterministic Rutilus Mock Redfish BMC on loopback"
)]
struct Cli {
    /// Loopback TCP port to listen on; `0` (the default) selects a free
    /// port.
    ///
    /// The positional shorthand `mock-bmc <port> [profile]` is equivalent:
    /// when both spellings are given, the long option wins, so they can
    /// never disagree about the effective port.
    #[arg(long)]
    port: Option<u16>,

    /// Positional shorthand for `--port`; ignored when `--port` is given
    /// explicitly.
    #[arg(value_name = "PORT")]
    port_pos: Option<u16>,

    /// Vendor fixture profile to serve: `rutilus` (the default, no vendor
    /// `Oem` namespace), `dell` (Dell identity plus the §11.5
    /// `DellAttributes` surface), `nvidia` (NVIDIA identity plus the §11.5
    /// chains), `lenovo` (Lenovo identity plus the §11.5
    /// `SecurityService` surface), `xfusion` (xFusion identity, no OEM
    /// surface), `inspur` (Inspur identity, no OEM surface), `ami` (AMI
    /// identity plus the §11.5 `AmiServiceRoot` and `ConfigBmc` surfaces),
    /// `hpe` (HPE identity plus the §11.5 `HpeiLoServiceExt` and `HpeiLo`
    /// segments), `liteon` (`LiteOn` identity plus the §11.5 `LiteOn`
    /// power-supply chain), `delta` (Delta identity plus the §11.5 Delta
    /// power-supply chain), or `supermicro` (Supermicro identity plus the
    /// §11.5 `SysLockdown` / `KcsInterface` surfaces).
    ///
    /// The positional shorthand `mock-bmc <port> [profile]` is equivalent:
    /// when both spellings are given, the long option wins, so they can
    /// never disagree about the effective profile.
    #[arg(long, value_parser = ["rutilus", "dell", "nvidia", "lenovo", "xfusion", "inspur", "ami", "hpe", "liteon", "delta", "supermicro"])]
    profile: Option<String>,

    /// Positional shorthand for `--profile`; ignored when `--profile` is
    /// given explicitly.
    #[arg(value_name = "PROFILE", value_parser = ["rutilus", "dell", "nvidia", "lenovo", "xfusion", "inspur", "ami", "hpe", "liteon", "delta", "supermicro"])]
    profile_pos: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();
    // The positional `<port> [profile]` form is a shorthand for `--port` /
    // `--profile`; the long options win when both spellings are given, so
    // the two forms can never disagree (`mock-bmc 9443 dell --port 8443`
    // listens on 8443, not on 9443). The defaults are unchanged: `0`
    // selects a free port and the profile falls back to `rutilus`.
    let port = cli.port.or(cli.port_pos).unwrap_or(0);
    // `clap` validates both spellings of the value against the documented
    // names at parse time (an unknown profile exits with an error before
    // this code runs), so the wildcard arm below is a defensive fallback
    // that cannot be reached; it keeps the match total instead of
    // unwrap-ping the option.
    let profile = match cli.profile.as_deref().or(cli.profile_pos.as_deref()) {
        Some("dell") => MockProfile::Dell,
        Some("nvidia") => MockProfile::Nvidia,
        Some("lenovo") => MockProfile::Lenovo,
        Some("xfusion") => MockProfile::XFusion,
        Some("inspur") => MockProfile::Inspur,
        Some("ami") => MockProfile::Ami,
        Some("hpe") => MockProfile::Hpe,
        Some("liteon") => MockProfile::LiteOn,
        Some("delta") => MockProfile::Delta,
        Some("supermicro") => MockProfile::Supermicro,
        _ => MockProfile::Rutilus,
    };
    let mock = MockBmc::bind_with_profile(port, profile).await?;
    println!(
        "Rutilus Mock Redfish BMC (profile: {}) listening at {}",
        profile.name(),
        mock.url()
    );
    println!("SHA-256 fingerprint: {}", mock.fingerprint_text());
    println!("Pin this fingerprint when Rutilus asks for the TLS identity.");
    println!("Press Ctrl-C to stop the mock.");
    tokio::signal::ctrl_c().await?;
    println!("Stopping the mock BMC...");
    mock.stop().await?;
    println!("Mock BMC stopped.");
    Ok(())
}
