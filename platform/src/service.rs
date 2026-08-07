//! System service registration and lifecycle (design 18.3, 0.6.0 S3).
//!
//! One binary registers itself with the platform's service manager — the
//! Windows SCM (`CreateServiceW`), `launchd` (a `LaunchAgent` plist), or
//! systemd (a user unit plus `daemon-reload`). The registered command line is
//! the current executable plus the hidden `service run` subcommand carrying
//! the Site arguments, so the service starts the same foreground Site runtime
//! a human runs, supervised by the platform.
//!
//! The lifecycle is complete on every platform: [`install`] registers **and
//! activates** the service (SCM `StartServiceW`, `launchctl bootstrap`,
//! `systemctl --user enable --now`), and [`uninstall`] deactivates it before
//! removing the registration (SCM stop-then-delete, `launchctl bootout`,
//! `systemctl --user disable --now`). Activation commands run best-effort —
//! the unit/plist file is the durable artifact, and the service manager may
//! be unavailable in the current session — while Windows start failures are
//! hard errors because the SCM is the authority there.
//!
//! The pure argument/unit rendering below is shared by every platform and is
//! unit-tested on each of them; the platform-specific registration lives in
//! the `windows` module and the cfg-gated functions at the bottom.

use std::path::Path;

use thiserror::Error;

// The registration errors carry the unit file paths on macOS and Linux only.
#[cfg(not(windows))]
use std::path::PathBuf;

/// The registered service's SCM name, unit name, and display identity.
// The name is consumed by the Windows SCM module and by the unit file
// renderers' consumers.
#[cfg_attr(not(windows), allow(dead_code))]
pub const SERVICE_NAME: &str = "rutilus";
pub const SERVICE_DISPLAY_NAME: &str = "Rutilus Site Service";
/// The launchd agent label.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub const LAUNCHD_LABEL: &str = "com.rutilus.site";
/// The systemd user unit file name.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub const SYSTEMD_UNIT_NAME: &str = "rutilus.service";

/// Site runtime arguments serialized into a registered service command line.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceArguments {
    listen: String,
    cert: Option<String>,
    key: Option<String>,
}

impl ServiceArguments {
    /// Builds the Site arguments for one registration.
    ///
    /// # Errors
    ///
    /// Returns [`ServiceArgumentsError::CertificateWithoutKey`] when exactly
    /// one of `cert`/`key` is supplied, or [`ServiceArgumentsError::Empty`]
    /// for an empty listen address.
    pub fn new(
        listen: impl Into<String>,
        cert: Option<impl Into<String>>,
        key: Option<impl Into<String>>,
    ) -> Result<Self, ServiceArgumentsError> {
        let listen = listen.into();
        let cert = cert.map(Into::into);
        let key = key.map(Into::into);
        if cert.is_some() != key.is_some() {
            return Err(ServiceArgumentsError::CertificateWithoutKey);
        }
        if listen.is_empty() {
            return Err(ServiceArgumentsError::Empty);
        }
        Ok(Self { listen, cert, key })
    }

    #[must_use]
    pub fn listen(&self) -> &str {
        &self.listen
    }

    #[must_use]
    pub fn cert(&self) -> Option<&str> {
        self.cert.as_deref()
    }

    #[must_use]
    pub fn key(&self) -> Option<&str> {
        self.key.as_deref()
    }

    /// The registered argv: `service run --site --listen ADDR [--cert ...]`.
    #[must_use]
    pub fn to_argv(&self) -> Vec<String> {
        let mut argv = vec![
            "service".to_owned(),
            "run".to_owned(),
            "--site".to_owned(),
            "--listen".to_owned(),
            self.listen.clone(),
        ];
        if let (Some(cert), Some(key)) = (&self.cert, &self.key) {
            argv.push("--cert".to_owned());
            argv.push(cert.clone());
            argv.push("--key".to_owned());
            argv.push(key.clone());
        }
        argv
    }

    /// The `CreateServiceW` binary path: the executable plus the registered
    /// argv, quoting every token that needs it.
    ///
    /// # Errors
    ///
    /// Returns [`ServiceArgumentsError::EmbeddedQuote`] when a token contains
    /// a `"`, which Windows command lines cannot represent safely.
    pub fn to_windows_command_line(
        &self,
        executable: &Path,
    ) -> Result<String, ServiceArgumentsError> {
        let mut tokens = Vec::with_capacity(self.to_argv().len() + 1);
        tokens.push(windows_quote(&executable.to_string_lossy())?);
        for argument in self.to_argv() {
            tokens.push(windows_quote(&argument)?);
        }
        Ok(tokens.join(" "))
    }

    /// The systemd `ExecStart=` value: executable plus argv with systemd's
    /// quoting rules.
    #[must_use]
    pub fn to_systemd_exec_start(&self, executable: &Path) -> String {
        let mut tokens = vec![executable.to_string_lossy().into_owned()];
        tokens.extend(self.to_argv());
        tokens
            .iter()
            .map(|token| systemd_quote(token))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// The launchd `ProgramArguments` for the agent plist.
    #[must_use]
    pub fn to_launchd_program_arguments(&self, executable: &Path) -> Vec<String> {
        let mut argv = vec![executable.to_string_lossy().into_owned()];
        argv.extend(self.to_argv());
        argv
    }
}

/// A controlled failure while building a registered service command line.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum ServiceArgumentsError {
    #[error("a service TLS certificate requires its private key and vice versa")]
    CertificateWithoutKey,
    #[error("the service listen address cannot be empty")]
    Empty,
    #[error("a service command-line token contains an unrepresentable quote character")]
    EmbeddedQuote,
}

/// Quotes one Windows command-line token: whitespace needs wrapping quotes,
/// and a literal quote cannot be represented safely.
fn windows_quote(token: &str) -> Result<String, ServiceArgumentsError> {
    if token.contains('"') {
        return Err(ServiceArgumentsError::EmbeddedQuote);
    }
    if token.chars().any(char::is_whitespace) {
        Ok(format!("\"{token}\""))
    } else {
        Ok(token.to_owned())
    }
}

/// Quotes one systemd `ExecStart=` token per systemd.syntax rules: a token
/// containing whitespace or one of `"` `'` `` ` `` `$` `\` is wrapped in
/// double quotes, escaping `"` `\` `$` and backticks inside.
fn systemd_quote(token: &str) -> String {
    if !token
        .chars()
        .any(|c| c.is_whitespace() || matches!(c, '"' | '\'' | '`' | '$' | '\\'))
    {
        return token.to_owned();
    }
    let mut quoted = String::with_capacity(token.len() + 2);
    quoted.push('"');
    for character in token.chars() {
        match character {
            '"' | '\\' | '$' | '`' => {
                quoted.push('\\');
                quoted.push(character);
            }
            other => quoted.push(other),
        }
    }
    quoted.push('"');
    quoted
}

/// Renders the `launchd` `LaunchAgent` plist for one registration.
///
/// Compiled on every platform: the pure renderer is unit-tested everywhere,
/// even though only macOS consumes it at install time.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
#[must_use]
pub fn launchd_plist_content(
    arguments: &ServiceArguments,
    executable: &Path,
    data_directory: &Path,
) -> String {
    let program = arguments
        .to_launchd_program_arguments(executable)
        .iter()
        .map(|token| format!("        <string>{}</string>", xml_escape(token)))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n\
         <dict>\n\
         \x20   <key>Label</key>\n\
         \x20   <string>{LAUNCHD_LABEL}</string>\n\
         \x20   <key>ProgramArguments</key>\n\
         \x20   <array>\n\
         {program}\n\
         \x20   </array>\n\
         \x20   <key>RunAtLoad</key>\n\
         \x20   <true/>\n\
         \x20   <key>KeepAlive</key>\n\
         \x20   <true/>\n\
         \x20   <key>WorkingDirectory</key>\n\
         \x20   <string>{}</string>\n\
         \x20   <key>ProcessType</key>\n\
         \x20   <string>Background</string>\n\
         </dict>\n\
         </plist>\n",
        xml_escape(&data_directory.to_string_lossy()),
    )
}

/// Renders the systemd user unit for one registration.
///
/// Compiled on every platform: the pure renderer is unit-tested everywhere,
/// even though only Linux consumes it at install time.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[must_use]
pub fn systemd_unit_content(
    arguments: &ServiceArguments,
    executable: &Path,
    data_directory: &Path,
) -> String {
    format!(
        "[Unit]\n\
         Description={SERVICE_DISPLAY_NAME}\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         WorkingDirectory={}\n\
         ExecStart={}\n\
         Restart=on-failure\n\
         \n\
         [Install]\n\
         WantedBy=default.target\n",
        systemd_quote(&data_directory.to_string_lossy()),
        arguments.to_systemd_exec_start(executable),
    )
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn xml_escape(value: &str) -> String {
    value
        .chars()
        .flat_map(|character| match character {
            '&' => "&amp;".chars().collect::<Vec<_>>(),
            '<' => "&lt;".chars().collect::<Vec<_>>(),
            '>' => "&gt;".chars().collect::<Vec<_>>(),
            other => vec![other],
        })
        .collect()
}

#[cfg(windows)]
mod windows;

#[cfg(windows)]
pub use windows::{ServiceControl, dispatch_service};

/// Installs the system service on the current platform.
///
/// # Errors
///
/// Returns [`ServiceInstallError`] when the platform's service manager
/// refuses the registration.
pub fn install(
    arguments: &ServiceArguments,
    executable: &Path,
    data_directory: &Path,
) -> Result<(), ServiceInstallError> {
    platform_install(arguments, executable, data_directory)
}

/// Removes the system service installed by [`install`].
///
/// # Errors
///
/// Returns [`ServiceUninstallError`] when the platform's service manager
/// refuses the removal. The master key and data directory are never touched.
pub fn uninstall() -> Result<(), ServiceUninstallError> {
    platform_uninstall()
}

#[cfg(windows)]
fn platform_install(
    arguments: &ServiceArguments,
    executable: &Path,
    _data_directory: &Path,
) -> Result<(), ServiceInstallError> {
    windows::install_service(arguments, executable)
}

#[cfg(windows)]
fn platform_uninstall() -> Result<(), ServiceUninstallError> {
    windows::uninstall_service()
}

#[cfg(target_os = "macos")]
fn platform_install(
    arguments: &ServiceArguments,
    executable: &Path,
    data_directory: &Path,
) -> Result<(), ServiceInstallError> {
    let home = std::env::var_os("HOME").ok_or(ServiceInstallError::HomeUnavailable)?;
    let agents = PathBuf::from(home).join("Library").join("LaunchAgents");
    std::fs::create_dir_all(&agents).map_err(|source| ServiceInstallError::AgentDirectory {
        path: agents.clone(),
        source,
    })?;
    let plist = agents.join(format!("{LAUNCHD_LABEL}.plist"));
    let content = launchd_plist_content(arguments, executable, data_directory);
    std::fs::write(&plist, content).map_err(|source| ServiceInstallError::Plist {
        path: plist.clone(),
        source,
    })?;
    // Activate the agent now: `bootstrap` loads and starts the job in the
    // user's GUI domain, so the service is running right after install.
    if let Some(uid) = launchd_uid() {
        run_activation_command(
            "launchctl",
            &[
                "bootstrap".to_owned(),
                format!("gui/{uid}"),
                plist.to_string_lossy().into_owned(),
            ],
        );
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn platform_uninstall() -> Result<(), ServiceUninstallError> {
    let home = std::env::var_os("HOME").ok_or(ServiceUninstallError::HomeUnavailable)?;
    let plist = PathBuf::from(home)
        .join("Library")
        .join("LaunchAgents")
        .join(format!("{LAUNCHD_LABEL}.plist"));
    if !plist.is_file() {
        return Err(ServiceUninstallError::NotInstalled { path: plist });
    }
    // Stop and unload the running job before removing the plist, so the
    // service does not linger after uninstall.
    if let Some(uid) = launchd_uid() {
        run_activation_command(
            "launchctl",
            &[
                "bootout".to_owned(),
                format!("gui/{uid}"),
                LAUNCHD_LABEL.to_owned(),
            ],
        );
    }
    std::fs::remove_file(&plist).map_err(|source| ServiceUninstallError::Plist {
        path: plist,
        source,
    })
}

/// The current user's launchd GUI domain id (`id -u`), when available.
#[cfg(target_os = "macos")]
fn launchd_uid() -> Option<String> {
    let output = std::process::Command::new("id").arg("-u").output().ok()?;
    if !output.status.success() {
        return None;
    }
    let uid = String::from_utf8(output.stdout).ok()?;
    let uid = uid.trim();
    if uid.is_empty() {
        None
    } else {
        Some(uid.to_owned())
    }
}

#[cfg(target_os = "linux")]
fn platform_install(
    arguments: &ServiceArguments,
    executable: &Path,
    data_directory: &Path,
) -> Result<(), ServiceInstallError> {
    let home = std::env::var_os("HOME").ok_or(ServiceInstallError::HomeUnavailable)?;
    let unit_directory = PathBuf::from(home)
        .join(".config")
        .join("systemd")
        .join("user");
    std::fs::create_dir_all(&unit_directory).map_err(|source| {
        ServiceInstallError::UnitDirectory {
            path: unit_directory.clone(),
            source,
        }
    })?;
    let unit = unit_directory.join(SYSTEMD_UNIT_NAME);
    let content = systemd_unit_content(arguments, executable, data_directory);
    std::fs::write(&unit, content).map_err(|source| ServiceInstallError::Unit {
        path: unit.clone(),
        source,
    })?;
    // Reload and activate the unit, so the service runs right after install.
    // The unit file is the durable artifact; an activation failure (for
    // example without a systemd user session) only defers the start, so it
    // is reported, not fatal.
    run_activation_command(
        "systemctl",
        &["--user".to_owned(), "daemon-reload".to_owned()],
    );
    run_activation_command(
        "systemctl",
        &[
            "--user".to_owned(),
            "enable".to_owned(),
            "--now".to_owned(),
            SYSTEMD_UNIT_NAME.to_owned(),
        ],
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn platform_uninstall() -> Result<(), ServiceUninstallError> {
    let home = std::env::var_os("HOME").ok_or(ServiceUninstallError::HomeUnavailable)?;
    let unit = PathBuf::from(home)
        .join(".config")
        .join("systemd")
        .join("user")
        .join(SYSTEMD_UNIT_NAME);
    if !unit.is_file() {
        return Err(ServiceUninstallError::NotInstalled { path: unit });
    }
    // Stop and disable the running unit before removing it, so the service
    // does not linger (or get resurrected at the next boot) after uninstall.
    run_activation_command(
        "systemctl",
        &[
            "--user".to_owned(),
            "disable".to_owned(),
            "--now".to_owned(),
            SYSTEMD_UNIT_NAME.to_owned(),
        ],
    );
    run_activation_command(
        "systemctl",
        &["--user".to_owned(), "daemon-reload".to_owned()],
    );
    std::fs::remove_file(&unit).map_err(|source| ServiceUninstallError::Unit { path: unit, source })
}

/// Runs one service-manager activation command and reports failures without
/// failing the install: the unit/plist file is the durable artifact, and the
/// service manager may be unavailable in the current session (containers,
/// ssh, locked GUI domains).
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn run_activation_command(program: &str, args: &[String]) {
    match std::process::Command::new(program).args(args).output() {
        Ok(output) if output.status.success() => {}
        Ok(output) => eprintln!(
            "{program} {} failed (status {:?}): {}",
            args.join(" "),
            output.status.code(),
            String::from_utf8_lossy(&output.stderr).trim()
        ),
        Err(source) => eprintln!("could not invoke {program}: {source}"),
    }
}

#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
fn platform_install(
    _arguments: &ServiceArguments,
    _executable: &Path,
    _data_directory: &Path,
) -> Result<(), ServiceInstallError> {
    Err(ServiceInstallError::UnsupportedPlatform)
}

#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
fn platform_uninstall() -> Result<(), ServiceUninstallError> {
    Err(ServiceUninstallError::UnsupportedPlatform)
}

/// A controlled failure while registering the system service.
#[derive(Debug, Error)]
pub enum ServiceInstallError {
    #[error("failed to render the service command line: {0}")]
    CommandLine(#[from] ServiceArgumentsError),
    #[cfg(windows)]
    #[error("the Windows service manager refused the registration: {0}")]
    Scm(#[source] std::io::Error),
    #[cfg(windows)]
    #[error("the Windows service manager refused the command-line update: {0}")]
    ScmUpdate(#[source] std::io::Error),
    #[cfg(windows)]
    #[error("the Windows service manager could not start the service: {0}")]
    ScmStart(#[source] std::io::Error),
    #[cfg(target_os = "macos")]
    #[error("the launchd agent directory is unavailable (no HOME)")]
    HomeUnavailable,
    #[cfg(target_os = "macos")]
    #[error("failed to create the launchd agent directory {path}: {source}")]
    AgentDirectory {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[cfg(target_os = "macos")]
    #[error("failed to write the launchd agent plist at {path}: {source}")]
    Plist {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[cfg(target_os = "linux")]
    #[error("the systemd unit directory is unavailable (no HOME)")]
    HomeUnavailable,
    #[cfg(target_os = "linux")]
    #[error("failed to create the systemd unit directory {path}: {source}")]
    UnitDirectory {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[cfg(target_os = "linux")]
    #[error("failed to write the systemd unit at {path}: {source}")]
    Unit {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("this platform has no supported service manager")]
    UnsupportedPlatform,
}

/// A controlled failure while removing the system service.
#[derive(Debug, Error)]
pub enum ServiceUninstallError {
    #[cfg(windows)]
    #[error("the Windows service manager refused the removal: {0}")]
    Scm(#[source] std::io::Error),
    #[cfg(windows)]
    #[error("the Windows service manager could not stop the service: {0}")]
    ScmStop(#[source] std::io::Error),
    #[cfg(windows)]
    #[error("no Windows service named {name} is installed")]
    NotInstalled { name: &'static str },
    #[cfg(target_os = "macos")]
    #[error("the launchd agent path is unavailable (no HOME)")]
    HomeUnavailable,
    #[cfg(target_os = "macos")]
    #[error("failed to remove the launchd agent plist at {path}: {source}")]
    Plist {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[cfg(target_os = "macos")]
    #[error("no launchd agent plist is installed at {path}")]
    NotInstalled { path: PathBuf },
    #[cfg(target_os = "linux")]
    #[error("the systemd unit path is unavailable (no HOME)")]
    HomeUnavailable,
    #[cfg(target_os = "linux")]
    #[error("failed to remove the systemd unit at {path}: {source}")]
    Unit {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[cfg(target_os = "linux")]
    #[error("no systemd unit is installed at {path}")]
    NotInstalled { path: PathBuf },
    #[error("this platform has no supported service manager")]
    UnsupportedPlatform,
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn arguments() -> Result<ServiceArguments, ServiceArgumentsError> {
        ServiceArguments::new(
            "0.0.0.0:8443",
            Some("C:\\Program Files\\rutilus\\site cert.pem"),
            Some("C:\\Program Files\\rutilus\\site key.pem"),
        )
    }

    #[test]
    fn validates_certificate_key_pairing_and_listen() -> Result<(), ServiceArgumentsError> {
        assert!(matches!(
            ServiceArguments::new("0.0.0.0:8443", Some("cert.pem"), None::<String>),
            Err(ServiceArgumentsError::CertificateWithoutKey)
        ));
        assert!(matches!(
            ServiceArguments::new("", None::<String>, None::<String>),
            Err(ServiceArgumentsError::Empty)
        ));
        let plain = ServiceArguments::new("127.0.0.1:8080", None::<String>, None::<String>)?;
        assert_eq!(plain.cert(), None);
        Ok(())
    }

    #[test]
    fn renders_the_registered_argv() -> Result<(), ServiceArgumentsError> {
        let arguments = arguments()?;

        assert_eq!(
            arguments.to_argv(),
            vec![
                "service",
                "run",
                "--site",
                "--listen",
                "0.0.0.0:8443",
                "--cert",
                "C:\\Program Files\\rutilus\\site cert.pem",
                "--key",
                "C:\\Program Files\\rutilus\\site key.pem",
            ]
        );
        Ok(())
    }

    #[test]
    fn renders_the_windows_command_line_with_quoting() -> Result<(), ServiceArgumentsError> {
        let arguments = arguments()?;
        let executable = PathBuf::from("C:\\Program Files\\rutilus\\rutilus.exe");

        let command_line = arguments.to_windows_command_line(&executable)?;

        assert_eq!(
            command_line,
            "\"C:\\Program Files\\rutilus\\rutilus.exe\" service run --site --listen 0.0.0.0:8443 --cert \"C:\\Program Files\\rutilus\\site cert.pem\" --key \"C:\\Program Files\\rutilus\\site key.pem\""
        );

        let without_cert = ServiceArguments::new("127.0.0.1:8080", None::<String>, None::<String>)?;
        assert_eq!(
            without_cert.to_windows_command_line(&executable)?,
            "\"C:\\Program Files\\rutilus\\rutilus.exe\" service run --site --listen 127.0.0.1:8080"
        );

        assert!(matches!(
            ServiceArguments::new("127.0.0.1:8080", Some("bad\"cert.pem"), Some("key.pem"),)
                .and_then(|arguments| arguments.to_windows_command_line(&executable)),
            Err(ServiceArgumentsError::EmbeddedQuote)
        ));
        Ok(())
    }

    #[test]
    fn renders_the_systemd_exec_start_with_quoting() -> Result<(), ServiceArgumentsError> {
        let arguments = arguments()?;
        let executable = PathBuf::from("/opt/rutilus/bin/rutilus");

        let exec_start = arguments.to_systemd_exec_start(&executable);

        assert_eq!(
            exec_start,
            "/opt/rutilus/bin/rutilus service run --site --listen 0.0.0.0:8443 --cert \"C:\\\\Program Files\\\\rutilus\\\\site cert.pem\" --key \"C:\\\\Program Files\\\\rutilus\\\\site key.pem\""
        );

        // systemd-special characters are escaped inside the quotes.
        let tricky = ServiceArguments::new(
            "0.0.0.0:8443",
            Some("/opt/rutilus/site$cert.pem"),
            Some("/opt/rutilus/site`key.pem"),
        )?;
        let exec_start = tricky.to_systemd_exec_start(&executable);
        assert!(exec_start.contains("\"/opt/rutilus/site\\$cert.pem\""));
        assert!(exec_start.contains("\"/opt/rutilus/site\\`key.pem\""));
        Ok(())
    }

    #[test]
    fn renders_the_launchd_program_arguments() -> Result<(), ServiceArgumentsError> {
        let arguments = arguments()?;
        let executable = PathBuf::from("/Applications/Rutilus.app/Contents/MacOS/rutilus");

        let program = arguments.to_launchd_program_arguments(&executable);

        assert_eq!(
            program,
            vec![
                "/Applications/Rutilus.app/Contents/MacOS/rutilus",
                "service",
                "run",
                "--site",
                "--listen",
                "0.0.0.0:8443",
                "--cert",
                "C:\\Program Files\\rutilus\\site cert.pem",
                "--key",
                "C:\\Program Files\\rutilus\\site key.pem",
            ]
        );
        Ok(())
    }

    #[test]
    fn renders_a_complete_launchd_plist() -> Result<(), ServiceArgumentsError> {
        let arguments = ServiceArguments::new("0.0.0.0:8443", None::<String>, None::<String>)?;
        let executable = PathBuf::from("/opt/rutilus/bin/rutilus");
        let data_directory = PathBuf::from("/Users/rutilus/Library/Application Support/rutilus");

        let plist = launchd_plist_content(&arguments, &executable, &data_directory);

        assert!(plist.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
        assert!(plist.contains("<key>Label</key>"));
        assert!(plist.contains("<string>com.rutilus.site</string>"));
        assert!(plist.contains("<string>/opt/rutilus/bin/rutilus</string>"));
        assert!(plist.contains("<string>0.0.0.0:8443</string>"));
        assert!(plist.contains("<key>RunAtLoad</key>"));
        assert!(plist.contains("<true/>"));
        assert!(plist.contains(&format!(
            "<string>{}</string>",
            xml_escape(&data_directory.to_string_lossy())
        )));
        Ok(())
    }

    #[test]
    fn renders_a_complete_systemd_unit() -> Result<(), ServiceArgumentsError> {
        let arguments = ServiceArguments::new("0.0.0.0:8443", None::<String>, None::<String>)?;
        let executable = PathBuf::from("/opt/rutilus/bin/rutilus");
        let data_directory = PathBuf::from("/home/rutilus/.local/share/rutilus");

        let unit = systemd_unit_content(&arguments, &executable, &data_directory);

        assert!(unit.contains("[Unit]"));
        assert!(unit.contains("Description=Rutilus Site Service"));
        assert!(unit.contains("[Service]"));
        assert!(unit.contains("Type=simple"));
        assert!(unit.contains("WorkingDirectory=/home/rutilus/.local/share/rutilus"));
        assert!(unit.contains(
            "ExecStart=/opt/rutilus/bin/rutilus service run --site --listen 0.0.0.0:8443"
        ));
        assert!(unit.contains("[Install]"));
        assert!(unit.contains("WantedBy=default.target"));
        Ok(())
    }

    #[test]
    fn xml_escape_protects_special_characters() {
        assert_eq!(xml_escape("a&b<c>d"), "a&amp;b&lt;c&gt;d");
        assert_eq!(xml_escape("plain"), "plain");
    }

    #[test]
    fn systemd_quote_leaves_plain_tokens_alone() {
        assert_eq!(systemd_quote("plain"), "plain");
        assert_eq!(systemd_quote("has space"), "\"has space\"");
    }
}
