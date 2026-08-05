#![forbid(unsafe_code)]

use std::error::Error;

use clap::{Parser, Subcommand};
use rutilus::{StandaloneRunOptions, run_standalone};
use rutilus_infra_redfish::NV_REDFISH_DEVELOPMENT_BASELINE;

const PRODUCT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Parser)]
#[command(name = "rutilus", about = "Unified multi-vendor Redfish management")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the foreground Standalone Web console on an ephemeral loopback port.
    Run {
        /// Do not open the system default browser after binding succeeds.
        #[arg(long)]
        no_open: bool,
    },
    /// Print the product and upstream development-baseline versions.
    Version,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    match cli.command {
        Command::Run { no_open } => {
            run_standalone(StandaloneRunOptions::new(!no_open)).await?;
        }
        Command::Version => print_version(),
    }
    Ok(())
}

fn print_version() {
    println!("rutilus {PRODUCT_VERSION}");
    println!("nv-redfish development baseline {NV_REDFISH_DEVELOPMENT_BASELINE}");
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::{Cli, Command};

    #[test]
    fn parses_the_documented_version_subcommand() {
        let parsed = Cli::try_parse_from(["rutilus", "version"]);

        assert!(matches!(
            parsed,
            Ok(Cli {
                command: Command::Version
            })
        ));
    }

    #[test]
    fn parses_the_loopback_standalone_run_subcommand() {
        let parsed = Cli::try_parse_from(["rutilus", "run", "--no-open"]);

        assert!(matches!(
            parsed,
            Ok(Cli {
                command: Command::Run { no_open: true }
            })
        ));
    }
}
