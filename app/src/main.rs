#![forbid(unsafe_code)]

use std::{error::Error, io};

use clap::{Parser, Subcommand};
use console::Term;
use rutilus::{
    StandaloneRunOptions, StandaloneUnlock, initialize_standalone, run_initialized_standalone,
};
use rutilus_infra_redfish::NV_REDFISH_DEVELOPMENT_BASELINE;
use rutilus_platform::DataLocation;
use secrecy::SecretString;

const PRODUCT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Parser)]
#[command(name = "rutilus", about = "Unified multi-vendor Redfish management")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Initialize a protected Standalone data directory.
    Init {
        /// Store data beside the executable instead of the installed user-data location.
        #[arg(long)]
        portable: bool,
    },
    /// Run the foreground Standalone Web console on an ephemeral loopback port.
    Run {
        /// Use the data directory beside the executable.
        #[arg(long)]
        portable: bool,
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
        Command::Init { portable } => initialize(portable).await?,
        Command::Run { portable, no_open } => run(portable, no_open).await?,
        Command::Version => print_version(),
    }
    Ok(())
}

async fn run(portable: bool, no_open: bool) -> Result<(), Box<dyn Error>> {
    let location = if portable {
        DataLocation::Portable
    } else {
        DataLocation::Installed
    };
    let paths = location.resolve()?;
    let terminal = Term::stderr();
    let passphrase = prompt_secret(&terminal, "Local unlock passphrase: ")?;
    let unlock = StandaloneUnlock::existing(passphrase)?;
    run_initialized_standalone(&paths, &unlock, StandaloneRunOptions::new(!no_open)).await?;
    Ok(())
}

async fn initialize(portable: bool) -> Result<(), Box<dyn Error>> {
    let location = if portable {
        DataLocation::Portable
    } else {
        DataLocation::Installed
    };
    let paths = location.resolve()?;
    let terminal = Term::stderr();
    let passphrase = prompt_secret(&terminal, "Local unlock passphrase: ")?;
    let confirmation = prompt_secret(&terminal, "Confirm local unlock passphrase: ")?;
    let unlock = StandaloneUnlock::confirm(passphrase, &confirmation)?;
    let outcome = initialize_standalone(&paths, &unlock).await?;
    println!(
        "Rutilus Standalone initialization {outcome:?} at {}",
        paths.data_directory().display()
    );
    Ok(())
}

fn prompt_secret(terminal: &Term, prompt: &str) -> io::Result<SecretString> {
    if !terminal.is_term() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "local unlock requires an interactive terminal",
        ));
    }
    terminal.write_str(prompt)?;
    terminal.flush()?;
    terminal.read_secure_line().map(SecretString::from)
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
        let parsed = Cli::try_parse_from(["rutilus", "run", "--portable", "--no-open"]);

        assert!(matches!(
            parsed,
            Ok(Cli {
                command: Command::Run {
                    portable: true,
                    no_open: true,
                }
            })
        ));
    }

    #[test]
    fn parses_installed_and_portable_initialization() {
        assert!(matches!(
            Cli::try_parse_from(["rutilus", "init"]),
            Ok(Cli {
                command: Command::Init { portable: false }
            })
        ));
        assert!(matches!(
            Cli::try_parse_from(["rutilus", "init", "--portable"]),
            Ok(Cli {
                command: Command::Init { portable: true }
            })
        ));
    }
}
