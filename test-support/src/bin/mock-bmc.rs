//! The `mock-bmc` development binary: runs the deterministic HTTPS Mock
//! Redfish BMC on loopback and prints the endpoint URL and SHA-256
//! fingerprint for the demo and for the product's endpoint trust dialog.
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
    /// Loopback TCP port to listen on; 0 (the default) selects a free port.
    #[arg(long, default_value_t = 0)]
    port: u16,

    /// Vendor fixture profile to serve: `rutilus` (the default, no vendor
    /// `Oem` namespace), `dell` (Dell identity plus the §11.5
    /// `DellAttributes` surface), `nvidia` (NVIDIA identity plus the §11.5
    /// chains), `lenovo` (Lenovo identity plus the §11.5
    /// `SecurityService` surface), `xfusion` (xFusion identity, no OEM
    /// surface), `inspur` (Inspur identity, no OEM surface), `ami` (AMI
    /// identity plus the §11.5 `AmiServiceRoot` and `ConfigBmc` surfaces),
    /// `hpe` (HPE identity plus the §11.5 `HpeiLoServiceExt` and `HpeiLo`
    /// segments), `liteon` (`LiteOn` identity plus the §11.5 `LiteOn`
    /// power-supply chain), or `delta` (Delta identity plus the §11.5 Delta
    /// power-supply chain).
    #[arg(long, default_value = "rutilus", value_parser = ["rutilus", "dell", "nvidia", "lenovo", "xfusion", "inspur", "ami", "hpe", "liteon", "delta"])]
    profile: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();
    // `clap` restricts the value to the documented names, so any other
    // spelling falls back to the default profile.
    let profile = match cli.profile.as_str() {
        "dell" => MockProfile::Dell,
        "nvidia" => MockProfile::Nvidia,
        "lenovo" => MockProfile::Lenovo,
        "xfusion" => MockProfile::XFusion,
        "inspur" => MockProfile::Inspur,
        "ami" => MockProfile::Ami,
        "hpe" => MockProfile::Hpe,
        "liteon" => MockProfile::LiteOn,
        "delta" => MockProfile::Delta,
        _ => MockProfile::Rutilus,
    };
    let mock = MockBmc::bind_with_profile(cli.port, profile).await?;
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
