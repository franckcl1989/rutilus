#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};
use rutilus_domain::NV_REDFISH_DEVELOPMENT_BASELINE;

const PRODUCT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Parser)]
#[command(name = "rutilus", about = "Unified multi-vendor Redfish management")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Print the product and upstream development-baseline versions.
    Version,
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::Version => print_version(),
    }
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
}
