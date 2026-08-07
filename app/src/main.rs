#![forbid(unsafe_code)]

use std::{error::Error, io, path::PathBuf};

use clap::{Args, Parser, Subcommand};
use console::Term;
use rutilus::{
    BackupKeyUnlock, ListenAddress, SiteRunOptions, StandaloneRunOptions, StandaloneUnlock,
    console_stop_signal, has_system_master_key, initialize_standalone, rewrap_to_system_unlock,
    run_initialized_standalone, run_site,
};
use rutilus_infra_redfish::NV_REDFISH_DEVELOPMENT_BASELINE;
use rutilus_platform::{
    DataLocation, InstanceMarkerFile, InstanceMarkerState, RuntimePaths, ServiceArguments,
};
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
    /// Run the foreground Standalone or Site Web console.
    Run {
        /// Use the data directory beside the executable.
        #[arg(long)]
        portable: bool,
        /// Do not open the system default browser after binding succeeds.
        #[arg(long)]
        no_open: bool,
        #[command(flatten)]
        site: Option<SiteArgs>,
    },
    /// Install, uninstall, or run the system service.
    Service {
        #[command(subcommand)]
        command: ServiceCommand,
    },
    /// Create or restore one encrypted product backup package.
    Backup {
        #[command(subcommand)]
        command: BackupCommand,
    },
    /// Self-check the data directory, database, master key, service, and TLS.
    Doctor {
        /// Use the data directory beside the executable.
        #[arg(long)]
        portable: bool,
    },
    /// Print the third-party licenses of this build.
    Licenses,
    /// Print the product and upstream development-baseline versions.
    Version,
}

#[derive(Debug, Subcommand)]
enum BackupCommand {
    /// Write one encrypted backup package of the stopped instance (§20.1).
    Create {
        /// Use the data directory beside the executable.
        #[arg(long)]
        portable: bool,
        /// Write the package to this path instead of the default backups/ directory.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Restore one backup package into the data directory, offline (§20.2).
    ///
    /// A backup is encrypted with the source instance's master key, so a
    /// cross-machine restore requires first copying the source machine's
    /// passphrase envelope over this machine's envelope and then restoring
    /// with the source passphrase. Instances protected by the operating
    /// system's envelope (DPAPI/Keychain) cannot restore across machines.
    Restore {
        /// Use the data directory beside the executable.
        #[arg(long)]
        portable: bool,
        /// The backup package file to restore.
        path: PathBuf,
    },
}

/// The 0.6.0 Site flags shared by `run --site` and the service subcommands.
#[derive(Debug, Args)]
struct SiteArgs {
    /// Run as a Site on the management network (HTTPS required off loopback).
    #[arg(long, requires = "listen")]
    site: bool,
    /// The Site listen address, HOST:PORT (required with --site).
    #[arg(long, requires = "site")]
    listen: Option<ListenAddress>,
    /// TLS certificate chain PEM (with --site; requires --key).
    #[arg(long, requires_all = ["key", "site"])]
    cert: Option<PathBuf>,
    /// TLS private key PEM (with --site; requires --cert).
    #[arg(long, requires = "cert")]
    key: Option<PathBuf>,
}

impl SiteArgs {
    fn site_options(&self) -> Result<SiteRunOptions, rutilus::SiteConfigError> {
        let listen = self
            .listen
            .clone()
            .ok_or(rutilus::SiteConfigError::ListenAddress(
                rutilus::ListenAddressError::MissingPort,
            ))?;
        SiteRunOptions::new(listen, self.cert.clone(), self.key.clone())
    }
}

#[derive(Debug, Subcommand)]
enum ServiceCommand {
    /// Install the product as a system service (Windows SCM, launchd, or systemd).
    Install {
        #[command(flatten)]
        site: SiteArgs,
        /// Portable data directories cannot back a system service.
        #[arg(long, hide = true)]
        portable: bool,
    },
    /// Remove the installed system service.
    Uninstall,
    /// Run the service body (internal; the service manager starts this).
    #[command(hide = true)]
    Run {
        #[command(flatten)]
        site: SiteArgs,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    match cli.command {
        Command::Init { portable } => initialize(portable).await?,
        Command::Run {
            portable,
            no_open,
            site,
        } => run(portable, no_open, site).await?,
        Command::Service { command } => service(command).await?,
        Command::Backup { command } => backup(command).await?,
        Command::Doctor { portable } => doctor(portable).await?,
        Command::Licenses => print_licenses(),
        Command::Version => print_version(),
    }
    Ok(())
}

async fn backup(command: BackupCommand) -> Result<(), Box<dyn Error>> {
    match command {
        BackupCommand::Create { portable, output } => {
            let paths = resolve_location(portable)?;
            let unlock = prompt_backup_unlock(&paths)?;
            let outcome = rutilus::create_backup(&paths, &unlock, output.as_deref()).await?;
            println!(
                "Backup written to {} ({} entries, schema version {})",
                outcome.path().display(),
                outcome.entry_count(),
                outcome.schema_version()
            );
        }
        BackupCommand::Restore { portable, path } => {
            let paths = resolve_location(portable)?;
            let unlock = prompt_backup_unlock(&paths)?;
            let outcome = rutilus::restore_backup(&paths, &unlock, &path).await?;
            println!(
                "Restore complete: {} entries restored; {} pending migrations will apply at the next start",
                outcome.restored_entries(),
                outcome.pending_migrations()
            );
        }
    }
    Ok(())
}

/// The backup commands' unlock: the OS-protected envelope when present,
/// otherwise the interactive local unlock passphrase.
fn prompt_backup_unlock(paths: &RuntimePaths) -> Result<BackupKeyUnlock, Box<dyn Error>> {
    if has_system_master_key(paths) {
        return Ok(BackupKeyUnlock::System);
    }
    let terminal = Term::stderr();
    let passphrase = prompt_secret(&terminal, "Local unlock passphrase: ")?;
    Ok(BackupKeyUnlock::Passphrase(passphrase))
}

fn resolve_location(portable: bool) -> Result<RuntimePaths, Box<dyn Error>> {
    let location = if portable {
        DataLocation::Portable
    } else {
        DataLocation::Installed
    };
    location
        .resolve()
        .map_err(|error| -> Box<dyn Error> { error.into() })
}

async fn doctor(portable: bool) -> Result<(), Box<dyn Error>> {
    let location = if portable {
        DataLocation::Portable
    } else {
        DataLocation::Installed
    };
    let report = rutilus::run_doctor(location).await;
    for check in report.checks() {
        println!(
            "[{}] {}: {}",
            check.level().tag(),
            check.label(),
            check.detail()
        );
    }
    if report.has_failure() {
        let failures = report
            .checks()
            .iter()
            .filter(|check| check.level() == rutilus::CheckLevel::Fail)
            .count();
        Err(format!("doctor found {failures} failing check(s)").into())
    } else {
        Ok(())
    }
}

fn print_licenses() {
    print!("{}", rutilus::licenses_text());
}

async fn run(portable: bool, no_open: bool, site: Option<SiteArgs>) -> Result<(), Box<dyn Error>> {
    let location = if portable {
        DataLocation::Portable
    } else {
        DataLocation::Installed
    };
    let paths = location.resolve()?;
    let Some(site) = site else {
        // The Standalone foreground console.
        let terminal = Term::stderr();
        let passphrase = prompt_secret(&terminal, "Local unlock passphrase: ")?;
        let unlock = StandaloneUnlock::existing(passphrase)?;
        run_initialized_standalone(&paths, &unlock, StandaloneRunOptions::new(!no_open)).await?;
        return Ok(());
    };
    // The Site foreground console never opens a browser. An instance that
    // already carries an OS-protected envelope unlocks unattended; otherwise
    // the operator unlocks with the passphrase, as in Standalone.
    let options = site.site_options()?;
    let unlock = if has_system_master_key(&paths) {
        None
    } else {
        let terminal = Term::stderr();
        let passphrase = prompt_secret(&terminal, "Local unlock passphrase: ")?;
        Some(StandaloneUnlock::existing(passphrase)?)
    };
    run_site(&paths, &options, unlock.as_ref(), console_stop_signal()).await?;
    Ok(())
}

async fn service(command: ServiceCommand) -> Result<(), Box<dyn Error>> {
    match command {
        ServiceCommand::Install { site, portable } => install_service(&site, portable).await?,
        ServiceCommand::Uninstall => {
            rutilus_platform::uninstall().map_err(|error| -> Box<dyn Error> { error.into() })?;
            println!("Rutilus service uninstalled");
        }
        ServiceCommand::Run { site } => run_service(&site).await?,
    }
    Ok(())
}

/// Installs the system service. A 0.6.0 service is always a Site: the
/// instance's master key is re-wrapped to the operating system's secret
/// store at install time (unless it already is), so the service boots
/// unattended.
async fn install_service(site: &SiteArgs, portable: bool) -> Result<(), Box<dyn Error>> {
    if portable {
        return Err("system services cannot use portable data directories".into());
    }
    if !site.site {
        return Err("a 0.6.0 system service must be a Site; pass --site with --listen".into());
    }
    let paths = DataLocation::Installed.resolve()?;
    let marker = InstanceMarkerFile::new(paths.instance_marker_path());
    match marker
        .state()
        .map_err(|error| -> Box<dyn Error> { error.into() })?
    {
        InstanceMarkerState::Missing => {
            return Err("this data directory is not initialized; run `rutilus init` first".into());
        }
        InstanceMarkerState::Complete => {}
    }
    if !has_system_master_key(&paths) {
        let terminal = Term::stderr();
        let passphrase = prompt_secret(&terminal, "Local unlock passphrase: ")?;
        rewrap_to_system_unlock(&paths, &passphrase).await?;
    }
    let options = site.site_options()?;
    let executable = std::env::current_exe()?;
    let arguments = ServiceArguments::new(
        options.listen().to_string(),
        options
            .cert()
            .map(|path| path.to_string_lossy().into_owned()),
        options
            .key()
            .map(|path| path.to_string_lossy().into_owned()),
    )?;
    rutilus_platform::install(&arguments, &executable, paths.data_directory())?;
    println!("Rutilus service installed");
    Ok(())
}

/// Runs the service body: the Site console with the operating-system unlock
/// and no interactive prompts. On Windows this registers with the SCM and
/// stops through the SCM stop control; elsewhere the service manager
/// supervises the same foreground process.
async fn run_service(site: &SiteArgs) -> Result<(), Box<dyn Error>> {
    let options = site.site_options()?;
    let paths = DataLocation::Installed.resolve()?;
    #[cfg(windows)]
    {
        run_windows_service(&paths, &options).await
    }
    #[cfg(not(windows))]
    {
        run_site(&paths, &options, None, console_stop_signal())
            .await
            .map_err(Into::into)
    }
}

/// Runs the Site body under the SCM: dispatches the service, waits for the
/// control handler to be registered, then serves until the SCM requests a
/// stop (or the console stop signal fires), drains, and releases the SCM
/// thread.
#[cfg(windows)]
async fn run_windows_service(
    paths: &rutilus_platform::RuntimePaths,
    options: &SiteRunOptions,
) -> Result<(), Box<dyn Error>> {
    use std::sync::Arc;

    use rutilus_platform::{ServiceControl, dispatch_service};
    use tokio::sync::oneshot;

    let control = Arc::new(ServiceControl::new());
    let (ready_sender, ready_receiver) = oneshot::channel();
    let mut dispatch = {
        let control = Arc::clone(&control);
        tokio::task::spawn_blocking(move || dispatch_service(control, ready_sender))
    };
    tokio::select! {
        ready = ready_receiver => {
            ready.map_err(|_| io::Error::other("the service dispatcher ended before registering"))??;
        }
        ended = &mut dispatch => {
            ended.map_err(|error| -> Box<dyn Error> { error.into() })??;
            return Err("the service dispatcher exited immediately; is this process running under the Windows service manager?".into());
        }
    }
    let result = run_site(paths, options, None, service_stop_signal(control.clone())).await;
    control.finish();
    match dispatch.await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => eprintln!("The service dispatcher failed: {error}"),
        Err(error) => eprintln!("The service dispatcher task failed: {error}"),
    }
    result.map_err(|error| -> Box<dyn Error> { error.into() })
}

/// The Site service's stop future: the SCM stop control, or the console
/// stop signal.
#[cfg(windows)]
async fn service_stop_signal(
    control: std::sync::Arc<rutilus_platform::ServiceControl>,
) -> io::Result<()> {
    tokio::select! {
        signal = console_stop_signal() => signal,
        () = control.wait_stop() => Ok(()),
    }
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

    use super::{BackupCommand, Cli, Command, ListenAddress, ServiceCommand, SiteArgs};

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
                    site: None,
                }
            })
        ));
    }

    #[test]
    fn parses_the_site_run_subcommand_with_tls_material() -> Result<(), clap::Error> {
        let parsed = Cli::try_parse_from([
            "rutilus",
            "run",
            "--site",
            "--listen",
            "0.0.0.0:8443",
            "--cert",
            "cert.pem",
            "--key",
            "key.pem",
        ])?;

        let Command::Run {
            site: Some(site), ..
        } = parsed.command
        else {
            return Err(clap::Error::raw(
                clap::error::ErrorKind::InvalidValue,
                "expected the Site run subcommand",
            ));
        };
        assert!(site.site);
        assert_eq!(
            site.listen.map(|listen| listen.to_string()).as_deref(),
            Some("0.0.0.0:8443")
        );
        assert_eq!(site.cert.as_deref(), Some(std::path::Path::new("cert.pem")));
        assert_eq!(site.key.as_deref(), Some(std::path::Path::new("key.pem")));
        Ok(())
    }

    #[test]
    fn site_flags_enforce_listen_and_pairing_dependencies() {
        assert!(Cli::try_parse_from(["rutilus", "run", "--site"]).is_err());
        assert!(Cli::try_parse_from(["rutilus", "run", "--listen", "127.0.0.1:8080"]).is_err());
        assert!(
            Cli::try_parse_from([
                "rutilus",
                "run",
                "--site",
                "--listen",
                "127.0.0.1:8080",
                "--cert",
                "cert.pem",
            ])
            .is_err()
        );
    }

    #[test]
    fn parses_service_install_uninstall_and_hidden_run() {
        let install = Cli::try_parse_from([
            "rutilus",
            "service",
            "install",
            "--site",
            "--listen",
            "0.0.0.0:8443",
        ]);
        assert!(matches!(
            install,
            Ok(Cli {
                command: Command::Service {
                    command: ServiceCommand::Install { .. }
                }
            })
        ));

        let uninstall = Cli::try_parse_from(["rutilus", "service", "uninstall"]);
        assert!(matches!(
            uninstall,
            Ok(Cli {
                command: Command::Service {
                    command: ServiceCommand::Uninstall
                }
            })
        ));

        let run = Cli::try_parse_from([
            "rutilus",
            "service",
            "run",
            "--site",
            "--listen",
            "0.0.0.0:8443",
            "--cert",
            "cert.pem",
            "--key",
            "key.pem",
        ]);
        assert!(matches!(
            run,
            Ok(Cli {
                command: Command::Service {
                    command: ServiceCommand::Run { .. }
                }
            })
        ));
    }

    #[test]
    fn parses_backup_create_and_restore_subcommands() {
        let create = Cli::try_parse_from([
            "rutilus",
            "backup",
            "create",
            "--portable",
            "--output",
            "backup.rut",
        ]);
        assert!(matches!(
            create,
            Ok(Cli {
                command: Command::Backup {
                    command: BackupCommand::Create {
                        portable: true,
                        output: Some(_)
                    }
                }
            })
        ));

        let default_output = Cli::try_parse_from(["rutilus", "backup", "create"]);
        assert!(matches!(
            default_output,
            Ok(Cli {
                command: Command::Backup {
                    command: BackupCommand::Create {
                        portable: false,
                        output: None
                    }
                }
            })
        ));

        let restore = Cli::try_parse_from(["rutilus", "backup", "restore", "backup.rut"]);
        assert!(matches!(
            restore,
            Ok(Cli {
                command: Command::Backup {
                    command: BackupCommand::Restore {
                        portable: false,
                        path: _
                    }
                }
            })
        ));
        assert!(Cli::try_parse_from(["rutilus", "backup", "restore"]).is_err());
        assert!(Cli::try_parse_from(["rutilus", "backup"]).is_err());
    }

    #[test]
    fn parses_doctor_and_licenses_subcommands() {
        assert!(matches!(
            Cli::try_parse_from(["rutilus", "doctor"]),
            Ok(Cli {
                command: Command::Doctor { portable: false }
            })
        ));
        assert!(matches!(
            Cli::try_parse_from(["rutilus", "doctor", "--portable"]),
            Ok(Cli {
                command: Command::Doctor { portable: true }
            })
        ));
        assert!(matches!(
            Cli::try_parse_from(["rutilus", "licenses"]),
            Ok(Cli {
                command: Command::Licenses
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

    #[test]
    fn listen_addresses_parse_through_the_cli() -> Result<(), clap::Error> {
        let listen = ListenAddress::parse("127.0.0.1:8443").map_err(|error| {
            clap::Error::raw(clap::error::ErrorKind::InvalidValue, error.to_string())
        })?;
        let site = SiteArgs {
            site: true,
            listen: Some(listen),
            cert: None,
            key: None,
        };
        let options = site.site_options().map_err(|error| {
            clap::Error::raw(clap::error::ErrorKind::InvalidValue, error.to_string())
        })?;
        assert_eq!(options.listen().to_string(), "127.0.0.1:8443");
        Ok(())
    }
}
