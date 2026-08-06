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
use rutilus_test_support::MockBmc;

#[derive(Debug, Parser)]
#[command(
    name = "mock-bmc",
    about = "Runs the deterministic Rutilus Mock Redfish BMC on loopback"
)]
struct Cli {
    /// Loopback TCP port to listen on; 0 (the default) selects a free port.
    #[arg(long, default_value_t = 0)]
    port: u16,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();
    let mock = MockBmc::bind(cli.port).await?;
    println!("Rutilus Mock Redfish BMC listening at {}", mock.url());
    println!("SHA-256 fingerprint: {}", mock.fingerprint_text());
    println!("Pin this fingerprint when Rutilus asks for the TLS identity.");
    println!("Press Ctrl-C to stop the mock.");
    tokio::signal::ctrl_c().await?;
    println!("Stopping the mock BMC...");
    mock.stop().await?;
    println!("Mock BMC stopped.");
    Ok(())
}
