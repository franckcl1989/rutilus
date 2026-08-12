#![forbid(unsafe_code)]

use std::{error::Error, io, path::PathBuf};

use clap::{Args, Parser, Subcommand, ValueEnum};
use console::Term;
use rutilus::{
    BackupKeyUnlock, CenterRunOptions, ListenAddress, SiteRunOptions, StandaloneRunOptions,
    StandaloneUnlock, TelemetryRetention, console_stop_signal, has_system_master_key,
    initialize_standalone, rewrap_to_system_unlock, run_center, run_initialized_standalone,
    run_site,
};
use rutilus_infra_redfish::NV_REDFISH_DEVELOPMENT_BASELINE;
use rutilus_platform::{
    DataLocation, InstanceMarkerFile, InstanceMarkerState, RuntimePaths, ServiceArguments,
};
use secrecy::SecretString;
use tracing::instrument;

/// The product version, derived from the single source of truth: the
/// workspace `[workspace.package] version` (root `Cargo.toml`). The
/// 0.1.0→1.0.0 numbers of design §二十一 are product release phases and the
/// workspace version tracks the current phase (0.9.0 production candidate,
/// 1.0.0 formal release), so a release bump touches exactly one file and
/// every consumer — this output, the build-embedded version, and the
/// version/log-format integration tests — follows automatically.
const PRODUCT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Parser)]
#[command(name = "rutilus", about = "Unified multi-vendor Redfish management")]
struct Cli {
    #[command(subcommand)]
    command: Command,
    /// The diagnostic log format: `text` (default) or `json` (one
    /// newline-delimited structured record per line). Applies to the
    /// stderr diagnostics only — the CLI's user-facing stdout output is
    /// unaffected (§7.6 user information vs. diagnostic information).
    #[arg(long, global = true, value_name = "FORMAT", default_value = "text")]
    log_format: LogFormat,
}

/// The stderr diagnostic log format (§6.2).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
enum LogFormat {
    /// Human-readable text lines (the default).
    #[default]
    Text,
    /// One newline-delimited structured JSON record per diagnostic.
    Json,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Initialize a protected Standalone data directory.
    Init {
        /// Store data beside the executable instead of the installed user-data location.
        #[arg(long)]
        portable: bool,
    },
    /// Run the foreground Standalone, Site, or Center console.
    Run {
        /// Use the data directory beside the executable.
        #[arg(long)]
        portable: bool,
        /// Do not open the system default browser after binding succeeds.
        #[arg(long)]
        no_open: bool,
        /// Keep each telemetry series' history for this many days
        /// (default 7; validated 1–365). Applies to the local sampling
        /// loop of Standalone and Site runs; the Center runs no local
        /// sampler.
        #[arg(long, value_name = "DAYS")]
        telemetry_retention_days: Option<TelemetryRetention>,
        #[command(flatten)]
        posture: Option<PostureArgs>,
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
    /// Remove the site's center binding and material (offline).
    ///
    /// The running site also converges on its own: a center that refuses
    /// the site's connection as not bound revokes the local binding and
    /// stops the sync engine (0.7.0 F4). This command is the operator path
    /// that ends the center relationship without the center; like backup,
    /// it refuses to run while the site console owns the instance.
    Unbind {
        /// Use the data directory beside the executable.
        #[arg(long)]
        portable: bool,
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

/// The 0.6.0 Site and 0.7.0 Center flags shared by `run` and the service
/// subcommands. The console flags (`--listen`, `--cert`, `--key`) are
/// shared by both postures; the center protocol listener is Center-only.
#[derive(Debug, Args)]
struct PostureArgs {
    /// Run as a Site on the management network (HTTPS required off loopback).
    #[arg(long, conflicts_with = "center")]
    site: bool,
    /// Run as the Center aggregation service (mTLS site connections).
    #[arg(long)]
    center: bool,
    /// The web console listen address, HOST:PORT.
    #[arg(long)]
    listen: Option<ListenAddress>,
    /// The center protocol (mTLS) listen address, HOST:PORT (with --center).
    #[arg(long, requires = "center", conflicts_with = "site")]
    center_listen: Option<ListenAddress>,
    /// TLS certificate chain PEM (requires --key).
    #[arg(long, requires = "key")]
    cert: Option<PathBuf>,
    /// TLS private key PEM (requires --cert).
    #[arg(long, requires = "cert")]
    key: Option<PathBuf>,
}

impl PostureArgs {
    fn site_options(&self) -> Result<SiteRunOptions, rutilus::SiteConfigError> {
        let listen = self
            .listen
            .clone()
            .ok_or(rutilus::SiteConfigError::ListenAddress(
                rutilus::ListenAddressError::MissingPort,
            ))?;
        SiteRunOptions::new(listen, self.cert.clone(), self.key.clone())
    }

    fn center_options(&self) -> Result<CenterRunOptions, rutilus::SiteConfigError> {
        let listen = self
            .listen
            .clone()
            .ok_or(rutilus::SiteConfigError::ListenAddress(
                rutilus::ListenAddressError::MissingPort,
            ))?;
        let center_listen =
            self.center_listen
                .clone()
                .ok_or(rutilus::SiteConfigError::ListenAddress(
                    rutilus::ListenAddressError::MissingPort,
                ))?;
        CenterRunOptions::new(
            SiteRunOptions::new(listen, self.cert.clone(), self.key.clone())?,
            center_listen,
        )
    }
}

/// The run or installed service posture with its resolved options.
#[derive(Clone, Debug)]
enum Posture {
    Site(SiteRunOptions),
    Center(CenterRunOptions),
}

#[derive(Debug, Subcommand)]
enum ServiceCommand {
    /// Install the product as a system service (Windows SCM, launchd, or systemd).
    Install {
        #[command(flatten)]
        posture: Option<PostureArgs>,
        /// Keep each telemetry series' history for this many days
        /// (default 7; validated 1–365). Written into the registered
        /// service command line.
        #[arg(long, value_name = "DAYS")]
        telemetry_retention_days: Option<TelemetryRetention>,
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
        posture: Option<PostureArgs>,
        /// Keep each telemetry series' history for this many days
        /// (default 7; validated 1–365). Applies to the local sampling
        /// loop of Standalone and Site runs; the Center runs no local
        /// sampler.
        #[arg(long, value_name = "DAYS")]
        telemetry_retention_days: Option<TelemetryRetention>,
    },
}

/// Initializes the §6.2 diagnostic logging: a `fmt` subscriber writing to
/// stderr, filtered by the `RUST_LOG` environment variable (defaulting to
/// `info` when unset or invalid). `format` selects the human-readable text
/// layer or the newline-delimited structured JSON layer; the text layer is
/// the default, so the documented §8.1 behavior is unchanged without the
/// `--log-format` flag. Diagnostics therefore never mix with the CLI's
/// user-facing stdout output (§7.6 user information vs. diagnostic
/// information separation).
fn init_tracing(format: LogFormat) {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    match format {
        LogFormat::Text => {
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_writer(std::io::stderr)
                .init();
        }
        LogFormat::Json => {
            tracing_subscriber::fmt()
                .json()
                .with_env_filter(filter)
                .with_writer(std::io::stderr)
                .init();
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // The CLI is parsed before the subscriber initializes so the
    // `--log-format` choice can select the diagnostic layer.
    let cli = Cli::parse();
    init_tracing(cli.log_format);

    match cli.command {
        Command::Init { portable } => initialize(portable).await?,
        Command::Run {
            portable,
            no_open,
            telemetry_retention_days,
            posture,
        } => run(portable, no_open, telemetry_retention_days, posture).await?,
        Command::Service { command } => service(command).await?,
        Command::Backup { command } => backup(command).await?,
        Command::Unbind { portable } => unbind(portable).await?,
        Command::Doctor { portable } => doctor(portable).await?,
        Command::Licenses => print_licenses(),
        Command::Version => print_version(),
    }
    Ok(())
}

#[instrument(skip_all, fields(command = ?command))]
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

/// The unbind command (0.7.0 F4): the offline operator path that ends the
/// site's center relationship, mirroring the backup commands' unlock
/// discipline and refusing to run while the site console owns the
/// instance.
#[instrument(fields(portable))]
async fn unbind(portable: bool) -> Result<(), Box<dyn Error>> {
    let paths = resolve_location(portable)?;
    let unlock = if has_system_master_key(&paths) {
        None
    } else {
        let terminal = Term::stderr();
        let passphrase = prompt_secret(&terminal, "Local unlock passphrase: ")?;
        Some(StandaloneUnlock::existing(passphrase)?)
    };
    match rutilus::unbind_from_center(&paths, unlock.as_ref()).await? {
        rutilus::UnbindOutcome::Unbound => {
            println!("The site's center binding was revoked and its center material removed.");
        }
        rutilus::UnbindOutcome::AlreadyUnbound => {
            println!("The site has no center binding in force; nothing changed.");
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

#[instrument(fields(portable))]
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

#[instrument(skip_all, fields(portable, no_open, telemetry_retention_days = ?telemetry_retention_days, posture = ?posture))]
async fn run(
    portable: bool,
    no_open: bool,
    telemetry_retention_days: Option<TelemetryRetention>,
    posture: Option<PostureArgs>,
) -> Result<(), Box<dyn Error>> {
    let location = if portable {
        DataLocation::Portable
    } else {
        DataLocation::Installed
    };
    let paths = location.resolve()?;
    let retention = telemetry_retention_days.unwrap_or_default();
    let Some(posture) = posture else {
        // The Standalone foreground console.
        let terminal = Term::stderr();
        let passphrase = prompt_secret(&terminal, "Local unlock passphrase: ")?;
        let unlock = StandaloneUnlock::existing(passphrase)?;
        run_initialized_standalone(
            &paths,
            &unlock,
            StandaloneRunOptions::new(!no_open, retention),
        )
        .await?;
        return Ok(());
    };
    // The unlock discipline is shared by the Site and Center postures: an
    // instance that already carries an OS-protected envelope unlocks
    // unattended; otherwise the operator unlocks with the passphrase.
    let unlock = if has_system_master_key(&paths) {
        None
    } else {
        let terminal = Term::stderr();
        let passphrase = prompt_secret(&terminal, "Local unlock passphrase: ")?;
        Some(StandaloneUnlock::existing(passphrase)?)
    };
    match resolve_posture(&posture)? {
        Posture::Site(options) => {
            // The Site foreground console never opens a browser.
            run_site(
                &paths,
                &options,
                retention,
                unlock.as_ref(),
                console_stop_signal(),
            )
            .await?;
        }
        Posture::Center(options) => {
            run_center(&paths, &options, unlock.as_ref(), console_stop_signal()).await?;
        }
    }
    Ok(())
}

/// Resolves the posture flags into the concrete run options; a posture
/// flag without its listen flags is a configuration error.
///
/// # Errors
///
/// Returns [`rutilus::SiteConfigError::ListenAddress`] when the posture's
/// listen flags are missing.
fn resolve_posture(args: &PostureArgs) -> Result<Posture, rutilus::SiteConfigError> {
    if args.center {
        return args.center_options().map(Posture::Center);
    }
    if args.site {
        return args.site_options().map(Posture::Site);
    }
    Err(rutilus::SiteConfigError::ListenAddress(
        rutilus::ListenAddressError::MissingPort,
    ))
}

#[instrument(skip_all, fields(command = ?command))]
async fn service(command: ServiceCommand) -> Result<(), Box<dyn Error>> {
    match command {
        ServiceCommand::Install {
            posture,
            telemetry_retention_days,
            portable,
        } => {
            install_service(posture.as_ref(), portable, telemetry_retention_days).await?;
        }
        ServiceCommand::Uninstall => {
            rutilus_platform::uninstall().map_err(|error| -> Box<dyn Error> { error.into() })?;
            println!("Rutilus service uninstalled");
        }
        ServiceCommand::Run {
            posture,
            telemetry_retention_days,
        } => run_service(posture.as_ref(), telemetry_retention_days).await?,
    }
    Ok(())
}

/// Installs the system service. A 0.6.0 service is always a Site: the
/// instance's master key is re-wrapped to the operating system's secret
/// store at install time (unless it already is), so the service boots
/// unattended.
///
/// A configured telemetry retention rides into the registered command line
/// (`--telemetry-retention-days`), so the service honors the operator's
/// value from its first start.
#[instrument(skip_all, fields(portable, telemetry_retention_days = ?telemetry_retention_days))]
async fn install_service(
    posture: Option<&PostureArgs>,
    portable: bool,
    telemetry_retention_days: Option<TelemetryRetention>,
) -> Result<(), Box<dyn Error>> {
    if portable {
        return Err("system services cannot use portable data directories".into());
    }
    let Some(args) = posture else {
        return Err(
            "a system service must be a Site or a Center; pass --site with --listen, or \
             --center with --listen and --center-listen"
                .into(),
        );
    };
    let posture = resolve_posture(args)?;
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
    let executable = std::env::current_exe()?;
    let arguments = match posture {
        Posture::Site(options) => {
            let arguments = ServiceArguments::new(
                options.listen().to_string(),
                options
                    .cert()
                    .map(|path| path.to_string_lossy().into_owned()),
                options
                    .key()
                    .map(|path| path.to_string_lossy().into_owned()),
            )?;
            // The site's local sampling loop honors the configured window
            // from the service's first start; the center runs no sampler.
            if let Some(retention) = telemetry_retention_days {
                arguments.with_telemetry_retention_days(retention.days())
            } else {
                arguments
            }
        }
        Posture::Center(options) => ServiceArguments::for_center(
            options.console().listen().to_string(),
            options.center_listen().to_string(),
            options
                .console()
                .cert()
                .map(|path| path.to_string_lossy().into_owned()),
            options
                .console()
                .key()
                .map(|path| path.to_string_lossy().into_owned()),
        )?,
    };
    rutilus_platform::install(&arguments, &executable, paths.data_directory())?;
    println!("Rutilus service installed");
    Ok(())
}

/// Runs the service body: the Site or Center console with the
/// operating-system unlock
/// and no interactive prompts. On Windows this registers with the SCM and
/// stops through the SCM stop control; elsewhere the service manager
/// supervises the same foreground process.
#[instrument(skip_all)]
async fn run_service(
    posture: Option<&PostureArgs>,
    telemetry_retention_days: Option<TelemetryRetention>,
) -> Result<(), Box<dyn Error>> {
    let paths = DataLocation::Installed.resolve()?;
    // The posture is decided before the closure so the service body owns
    // its resolved options; the retention is Copy, so the closure captures
    // it by value.
    let retention = telemetry_retention_days.unwrap_or_default();
    let posture = match posture {
        Some(args) => resolve_posture(args)?,
        None => {
            return Err(
                "a system service must be a Site or a Center; pass --site with --listen, or \
                 --center with --listen and --center-listen"
                    .into(),
            );
        }
    };
    #[cfg(windows)]
    {
        run_windows_service(&paths, |paths, control| {
            let posture = posture.clone();
            Box::pin(async move {
                match posture {
                    Posture::Site(options) => run_site(
                        paths,
                        &options,
                        retention,
                        None,
                        service_stop_signal(control.clone()),
                    )
                    .await
                    .map_err(Into::into),
                    Posture::Center(options) => {
                        run_center(paths, &options, None, service_stop_signal(control.clone()))
                            .await
                            .map_err(Into::into)
                    }
                }
            })
        })
        .await
    }
    #[cfg(not(windows))]
    {
        match posture {
            Posture::Site(options) => {
                run_site(&paths, &options, retention, None, console_stop_signal())
                    .await
                    .map_err(Into::into)
            }
            Posture::Center(options) => run_center(&paths, &options, None, console_stop_signal())
                .await
                .map_err(Into::into),
        }
    }
}

/// Runs the Site body under the SCM: dispatches the service, waits for the
/// control handler to be registered, then serves until the SCM requests a
/// stop (or the console stop signal fires), drains, and releases the SCM
/// thread.
#[cfg(windows)]
#[instrument(skip_all)]
async fn run_windows_service(
    paths: &rutilus_platform::RuntimePaths,
    run_body: impl FnOnce(
        &rutilus_platform::RuntimePaths,
        std::sync::Arc<rutilus_platform::ServiceControl>,
    ) -> rutilus_application::BoundaryFuture<'_, Result<(), Box<dyn Error>>>,
) -> Result<(), Box<dyn Error>> {
    use rutilus_platform::{ServiceControl, dispatch_service};
    use tokio::sync::oneshot;

    let control = std::sync::Arc::new(ServiceControl::new());
    let (ready_sender, ready_receiver) = oneshot::channel();
    let mut dispatch = {
        let control = std::sync::Arc::clone(&control);
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
    let result = run_body(paths, control.clone()).await;
    control.finish();
    match dispatch.await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => tracing::error!("The service dispatcher failed: {error}"),
        Err(error) => tracing::error!("The service dispatcher task failed: {error}"),
    }
    result
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

#[instrument(fields(portable))]
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

    use super::{
        BackupCommand, Cli, Command, ListenAddress, LogFormat, PostureArgs, ServiceCommand,
        TelemetryRetention,
    };

    #[test]
    fn parses_the_documented_version_subcommand() {
        let parsed = Cli::try_parse_from(["rutilus", "version"]);

        assert!(matches!(
            parsed,
            Ok(Cli {
                command: Command::Version,
                ..
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
                    telemetry_retention_days: None,
                    posture: None,
                },
                ..
            })
        ));
    }

    #[test]
    fn parses_the_telemetry_retention_days_flag() -> Result<(), clap::Error> {
        let parsed = Cli::try_parse_from([
            "rutilus",
            "run",
            "--portable",
            "--telemetry-retention-days",
            "30",
        ])?;

        let Command::Run {
            telemetry_retention_days,
            ..
        } = parsed.command
        else {
            return Err(clap::Error::raw(
                clap::error::ErrorKind::InvalidValue,
                "expected the Run subcommand",
            ));
        };
        assert_eq!(
            telemetry_retention_days,
            Some(TelemetryRetention::try_new(30).map_err(|error| {
                clap::Error::raw(clap::error::ErrorKind::InvalidValue, error.to_string())
            })?)
        );
        Ok(())
    }

    #[test]
    fn rejects_invalid_telemetry_retention_days() {
        // The CLI rejects windows that would erase the whole history (0),
        // unbound the store (366), or are not a whole number of days.
        for bad in ["0", "366", "abc", "-1"] {
            assert!(
                Cli::try_parse_from(["rutilus", "run", "--telemetry-retention-days", bad,])
                    .is_err(),
                "{bad} must be rejected"
            );
        }
        assert!(
            Cli::try_parse_from([
                "rutilus",
                "service",
                "install",
                "--site",
                "--listen",
                "127.0.0.1:8080",
                "--telemetry-retention-days",
                "0",
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "rutilus",
                "service",
                "run",
                "--site",
                "--listen",
                "127.0.0.1:8080",
                "--telemetry-retention-days",
                "366",
            ])
            .is_err()
        );
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
            posture: Some(posture),
            ..
        } = parsed.command
        else {
            return Err(clap::Error::raw(
                clap::error::ErrorKind::InvalidValue,
                "expected the Site run subcommand",
            ));
        };
        assert!(posture.site);
        assert_eq!(
            posture.listen.as_ref().map(ToString::to_string).as_deref(),
            Some("0.0.0.0:8443")
        );
        assert_eq!(
            posture.cert.as_deref(),
            Some(std::path::Path::new("cert.pem"))
        );
        assert_eq!(
            posture.key.as_deref(),
            Some(std::path::Path::new("key.pem"))
        );
        Ok(())
    }

    #[test]
    fn parses_the_center_run_subcommand_with_the_protocol_listener() -> Result<(), clap::Error> {
        let parsed = Cli::try_parse_from([
            "rutilus",
            "run",
            "--center",
            "--listen",
            "0.0.0.0:8443",
            "--center-listen",
            "0.0.0.0:8444",
        ])?;

        let Command::Run {
            posture: Some(posture),
            ..
        } = parsed.command
        else {
            return Err(clap::Error::raw(
                clap::error::ErrorKind::InvalidValue,
                "expected the Center run subcommand",
            ));
        };
        assert!(posture.center);
        assert_eq!(
            posture.listen.as_ref().map(ToString::to_string).as_deref(),
            Some("0.0.0.0:8443")
        );
        assert_eq!(
            posture
                .center_listen
                .as_ref()
                .map(ToString::to_string)
                .as_deref(),
            Some("0.0.0.0:8444")
        );
        let options = posture.center_options().map_err(|error| {
            clap::Error::raw(clap::error::ErrorKind::InvalidValue, error.to_string())
        })?;
        assert_eq!(options.console().listen().to_string(), "0.0.0.0:8443");
        assert_eq!(options.center_listen().to_string(), "0.0.0.0:8444");
        Ok(())
    }

    #[test]
    fn posture_flags_enforce_the_pairing_dependencies() {
        // --center-listen requires --center.
        assert!(
            Cli::try_parse_from([
                "rutilus",
                "run",
                "--site",
                "--listen",
                "127.0.0.1:8080",
                "--center-listen",
                "127.0.0.1:8444",
            ])
            .is_err()
        );
        // --cert requires --key (and vice versa).
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
        assert!(
            Cli::try_parse_from([
                "rutilus",
                "run",
                "--site",
                "--listen",
                "127.0.0.1:8080",
                "--key",
                "key.pem",
            ])
            .is_err()
        );
        // The postures are mutually exclusive.
        assert!(
            Cli::try_parse_from([
                "rutilus",
                "run",
                "--site",
                "--center",
                "--listen",
                "127.0.0.1:8080",
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
                },
                ..
            })
        ));

        let center_install = Cli::try_parse_from([
            "rutilus",
            "service",
            "install",
            "--center",
            "--listen",
            "0.0.0.0:8443",
            "--center-listen",
            "0.0.0.0:8444",
        ]);
        assert!(matches!(
            center_install,
            Ok(Cli {
                command: Command::Service {
                    command: ServiceCommand::Install { .. }
                },
                ..
            })
        ));

        let uninstall = Cli::try_parse_from(["rutilus", "service", "uninstall"]);
        assert!(matches!(
            uninstall,
            Ok(Cli {
                command: Command::Service {
                    command: ServiceCommand::Uninstall
                },
                ..
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
                },
                ..
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
                },
                ..
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
                },
                ..
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
                },
                ..
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
                command: Command::Doctor { portable: false },
                ..
            })
        ));
        assert!(matches!(
            Cli::try_parse_from(["rutilus", "doctor", "--portable"]),
            Ok(Cli {
                command: Command::Doctor { portable: true },
                ..
            })
        ));
        assert!(matches!(
            Cli::try_parse_from(["rutilus", "licenses"]),
            Ok(Cli {
                command: Command::Licenses,
                ..
            })
        ));
    }

    #[test]
    fn parses_installed_and_portable_initialization() {
        assert!(matches!(
            Cli::try_parse_from(["rutilus", "init"]),
            Ok(Cli {
                command: Command::Init { portable: false },
                ..
            })
        ));
        assert!(matches!(
            Cli::try_parse_from(["rutilus", "init", "--portable"]),
            Ok(Cli {
                command: Command::Init { portable: true },
                ..
            })
        ));
    }

    #[test]
    fn listen_addresses_parse_through_the_cli() -> Result<(), clap::Error> {
        let listen = ListenAddress::parse("127.0.0.1:8443").map_err(|error| {
            clap::Error::raw(clap::error::ErrorKind::InvalidValue, error.to_string())
        })?;
        let posture = PostureArgs {
            site: true,
            center: false,
            listen: Some(listen),
            center_listen: None,
            cert: None,
            key: None,
        };
        let options = posture.site_options().map_err(|error| {
            clap::Error::raw(clap::error::ErrorKind::InvalidValue, error.to_string())
        })?;
        assert_eq!(options.listen().to_string(), "127.0.0.1:8443");
        Ok(())
    }

    #[test]
    fn log_format_defaults_to_text() {
        // Without the flag the documented §8.1 text layer is selected, so
        // the default behavior is unchanged.
        let parsed = Cli::try_parse_from(["rutilus", "version"]);
        assert!(matches!(
            parsed,
            Ok(Cli {
                command: Command::Version,
                log_format: LogFormat::Text,
            })
        ));
    }

    #[test]
    fn parses_the_global_log_format_flag() {
        // The flag is global: it is accepted before or after any subcommand.
        for argv in [
            vec!["rutilus", "version", "--log-format", "json"],
            vec!["rutilus", "--log-format", "json", "version"],
            vec!["rutilus", "run", "--portable", "--log-format", "json"],
            vec!["rutilus", "backup", "create", "--log-format", "text"],
        ] {
            let parsed = Cli::try_parse_from(argv);
            assert!(
                matches!(
                    parsed,
                    Ok(Cli {
                        log_format: LogFormat::Json | LogFormat::Text,
                        ..
                    })
                ),
                "--log-format must parse in every position"
            );
        }
    }

    #[test]
    fn rejects_unknown_log_formats() {
        for value in ["yaml", "JSON", ""] {
            assert!(
                Cli::try_parse_from(["rutilus", "version", "--log-format", value]).is_err(),
                "{value:?} must be rejected"
            );
        }
    }

    /// A test `io::Write` target appending into an in-memory buffer, so the
    /// JSON layer's records can be captured without a global subscriber.
    struct CaptureWriter(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for CaptureWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn the_json_subscriber_emits_structured_records() -> Result<(), Box<dyn std::error::Error>> {
        // The `--log-format json` layer must emit one newline-delimited JSON
        // record per diagnostic, with the recorded fields intact.
        let buffer = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let writer_buffer = std::sync::Arc::clone(&buffer);
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_writer(move || CaptureWriter(std::sync::Arc::clone(&writer_buffer)))
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(endpoint_id = 7, "a structured record");
        });
        let captured = String::from_utf8(
            buffer
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone(),
        )
        .map_err(|error| std::io::Error::other(error.to_string()))?;
        let record: serde_json::Value = serde_json::from_str(captured.trim())?;
        assert_eq!(record["fields"]["message"], "a structured record");
        assert_eq!(record["fields"]["endpoint_id"].as_i64(), Some(7));
        Ok(())
    }
}
