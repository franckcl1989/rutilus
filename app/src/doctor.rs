//! The `rutilus doctor` self-check (§18.1, 0.6.0 debt S0).
//!
//! Every check reports OK, WARN, or FAIL; the command exits nonzero when any
//! check failed. The checks cover the data directory, the instance
//! initialization state, the database file and its migration state (read
//! only — the doctor never migrates), the master-key envelope
//! recoverability, the system-service registration, and the Site TLS
//! certificate fingerprint.

use std::fs;

use rutilus_platform::{
    DataLocation, InstanceMarkerFile, InstanceMarkerState, MasterKeyFile, RuntimePaths,
    ServiceStatus, SystemMasterKeyFile, service_status,
};
use rutilus_security::SystemProtectedMasterKey;

use crate::site_runtime;

/// The verdict of one doctor check.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckLevel {
    Ok,
    Warn,
    Fail,
}

impl CheckLevel {
    /// The short tag printed in the `[OK]`/`[WARN]`/`[FAIL]` prefix.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Ok => "OK",
            Self::Warn => "WARN",
            Self::Fail => "FAIL",
        }
    }
}

/// One labeled doctor finding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DoctorCheck {
    label: &'static str,
    level: CheckLevel,
    detail: String,
}

impl DoctorCheck {
    #[must_use]
    pub const fn label(&self) -> &'static str {
        self.label
    }

    #[must_use]
    pub const fn level(&self) -> CheckLevel {
        self.level
    }

    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

/// The complete self-check report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DoctorReport {
    checks: Vec<DoctorCheck>,
}

impl DoctorReport {
    #[must_use]
    pub fn checks(&self) -> &[DoctorCheck] {
        &self.checks
    }

    /// Whether any check failed; the command exits nonzero then.
    #[must_use]
    pub fn has_failure(&self) -> bool {
        self.checks
            .iter()
            .any(|check| check.level == CheckLevel::Fail)
    }
}

/// Runs every self-check for one data location.
///
/// The function never fails: resolution and inspection failures become
/// failed checks in the report.
pub async fn run_doctor(location: DataLocation) -> DoctorReport {
    let mut checks = Vec::new();
    let paths = match location.resolve() {
        Ok(paths) => {
            checks.push(check(
                "data directory",
                CheckLevel::Ok,
                paths.data_directory().display().to_string(),
            ));
            paths
        }
        Err(error) => {
            checks.push(check("data directory", CheckLevel::Fail, error.to_string()));
            return DoctorReport { checks };
        }
    };
    let mut report = run_doctor_for_paths(&paths).await;
    checks.append(&mut report.checks);
    DoctorReport { checks }
}

/// Runs every check below one resolved path set (crate-internal so tests can
/// drive an arbitrary directory).
pub(crate) async fn run_doctor_for_paths(paths: &RuntimePaths) -> DoctorReport {
    let mut checks = Vec::new();
    let marker_state = match InstanceMarkerFile::new(paths.instance_marker_path()).state() {
        Ok(state) => state,
        Err(error) => {
            checks.push(check("instance state", CheckLevel::Fail, error.to_string()));
            checks.extend(service_and_tls_checks(paths));
            return DoctorReport { checks };
        }
    };
    match marker_state {
        InstanceMarkerState::Missing => {
            checks.push(check(
                "instance state",
                CheckLevel::Warn,
                "not initialized; run `rutilus init` first",
            ));
            // Without initialization the database, key, and migration checks
            // have nothing to inspect.
            checks.extend(service_and_tls_checks(paths));
            return DoctorReport { checks };
        }
        InstanceMarkerState::Complete => {
            checks.push(check("instance state", CheckLevel::Ok, "initialized"));
        }
    }
    check_database_file(paths, &mut checks);
    check_migrations(paths, &mut checks).await;
    check_master_key(paths, &mut checks);
    checks.extend(service_and_tls_checks(paths));
    DoctorReport { checks }
}

fn check_database_file(paths: &RuntimePaths, checks: &mut Vec<DoctorCheck>) {
    let metadata = match fs::symlink_metadata(paths.database_path()) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            checks.push(check(
                "database file",
                CheckLevel::Fail,
                format!("missing at {}", paths.database_path().display()),
            ));
            return;
        }
        Err(error) => {
            checks.push(check(
                "database file",
                CheckLevel::Fail,
                format!("cannot inspect: {error}"),
            ));
            return;
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        checks.push(check(
            "database file",
            CheckLevel::Fail,
            format!("not a regular file at {}", paths.database_path().display()),
        ));
    } else {
        checks.push(check(
            "database file",
            CheckLevel::Ok,
            format!("{} bytes", metadata.len()),
        ));
    }
}

async fn check_migrations(paths: &RuntimePaths, checks: &mut Vec<DoctorCheck>) {
    match rutilus_persistence::migration_counts(paths.database_path()).await {
        Ok(counts) if counts.pending == 0 => {
            checks.push(check(
                "database migrations",
                CheckLevel::Ok,
                format!("{} applied, none pending", counts.applied),
            ));
        }
        Ok(counts) => {
            checks.push(check(
                "database migrations",
                CheckLevel::Warn,
                format!(
                    "{} applied, {} pending (the next start will migrate)",
                    counts.applied, counts.pending
                ),
            ));
        }
        Err(error) => {
            checks.push(check(
                "database migrations",
                CheckLevel::Fail,
                format!("cannot inspect: {error}"),
            ));
        }
    }
}

fn check_master_key(paths: &RuntimePaths, checks: &mut Vec<DoctorCheck>) {
    if let Ok(envelope) = SystemMasterKeyFile::new(paths.system_master_key_path()).load() {
        match SystemProtectedMasterKey::from_bytes(envelope.into_bytes()) {
            Ok(_) => checks.push(check(
                "master key",
                CheckLevel::Ok,
                "system-protected envelope is valid",
            )),
            Err(error) => checks.push(check(
                "master key",
                CheckLevel::Fail,
                format!("system-protected envelope is invalid: {error}"),
            )),
        }
        return;
    }
    match MasterKeyFile::new(paths.master_key_path()).load() {
        Ok(_) => checks.push(check(
            "master key",
            CheckLevel::Ok,
            "passphrase envelope is intact",
        )),
        Err(error) => checks.push(check(
            "master key",
            CheckLevel::Fail,
            format!("passphrase envelope is not recoverable: {error}"),
        )),
    }
}

fn service_and_tls_checks(paths: &RuntimePaths) -> Vec<DoctorCheck> {
    let mut checks = Vec::new();
    match service_status() {
        Ok(ServiceStatus::Installed) => checks.push(check(
            "system service",
            CheckLevel::Ok,
            "registered with the platform service manager",
        )),
        Ok(ServiceStatus::NotInstalled) => checks.push(check(
            "system service",
            CheckLevel::Warn,
            "not installed (a foreground console is unaffected)",
        )),
        Ok(ServiceStatus::UnsupportedPlatform) => checks.push(check(
            "system service",
            CheckLevel::Warn,
            "no supported service manager on this platform",
        )),
        Err(error) => checks.push(check(
            "system service",
            CheckLevel::Warn,
            format!("cannot query the service manager: {error}"),
        )),
    }
    checks.push(tls_check(paths));
    checks
}

fn tls_check(paths: &RuntimePaths) -> DoctorCheck {
    let cert_path = paths.tls_directory().join("cert.pem");
    if !cert_path.is_file() {
        return check(
            "TLS certificate",
            CheckLevel::Warn,
            "not configured (the loopback console runs without TLS)",
        );
    }
    match site_runtime::read_certificate(&cert_path) {
        Ok(certificate) => check(
            "TLS certificate",
            CheckLevel::Ok,
            format!("SHA-256 {}", site_runtime::fingerprint(&certificate)),
        ),
        Err(error) => check(
            "TLS certificate",
            CheckLevel::Fail,
            format!("cannot parse {}: {error}", cert_path.display()),
        ),
    }
}

fn check(label: &'static str, level: CheckLevel, detail: impl Into<String>) -> DoctorCheck {
    DoctorCheck {
        label,
        level,
        detail: detail.into(),
    }
}

#[cfg(test)]
mod tests {
    use std::{error::Error, fs};

    use rutilus_platform::RuntimePaths;
    use secrecy::SecretString;

    use crate::{StandaloneUnlock, initialize_standalone};

    use super::*;

    fn unlock(value: &str) -> Result<StandaloneUnlock, crate::StandaloneUnlockError> {
        StandaloneUnlock::existing(SecretString::from(value.to_owned()))
    }

    #[tokio::test]
    async fn reports_every_ok_check_for_a_healthy_instance() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let paths = RuntimePaths::from_root(directory.path().join("instance"))?;
        initialize_standalone(&paths, &unlock("correct local unlock phrase")?).await?;

        let report = run_doctor_for_paths(&paths).await;

        assert!(
            report
                .checks()
                .iter()
                .any(|check| check.label() == "instance state" && check.level() == CheckLevel::Ok)
        );
        assert!(
            report
                .checks()
                .iter()
                .any(|check| check.label() == "database file" && check.level() == CheckLevel::Ok)
        );
        assert!(
            report
                .checks()
                .iter()
                .any(|check| check.label() == "database migrations"
                    && check.level() == CheckLevel::Ok)
        );
        assert!(
            report
                .checks()
                .iter()
                .any(|check| check.label() == "master key" && check.level() == CheckLevel::Ok)
        );
        assert!(!report.has_failure());
        Ok(())
    }

    #[tokio::test]
    async fn reports_failures_for_a_corrupted_instance() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let paths = RuntimePaths::from_root(directory.path().join("instance"))?;
        initialize_standalone(&paths, &unlock("correct local unlock phrase")?).await?;
        fs::remove_file(paths.master_key_path())?;
        fs::write(paths.database_path(), b"not a database")?;

        let report = run_doctor_for_paths(&paths).await;

        let failing = report
            .checks()
            .iter()
            .filter(|check| check.level() == CheckLevel::Fail)
            .map(DoctorCheck::label)
            .collect::<Vec<_>>();
        assert!(failing.contains(&"master key"));
        assert!(failing.contains(&"database migrations"));
        assert!(report.has_failure());
        Ok(())
    }

    #[tokio::test]
    async fn warns_about_an_uninitialized_directory() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let paths = RuntimePaths::from_root(directory.path().join("fresh"))?;

        let report = run_doctor_for_paths(&paths).await;

        assert!(
            report
                .checks()
                .iter()
                .any(|check| check.label() == "instance state" && check.level() == CheckLevel::Warn)
        );
        assert!(!report.has_failure());
        Ok(())
    }
}
