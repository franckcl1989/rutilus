//! macOS Keychain protection through the `security(1)` command-line tool
//! (0.6.0 S3).
//!
//! The master key is stored as a Keychain generic-password item addressed by
//! fixed service/account constants. The secret travels through the process
//! pipes (`-w` on stdin for `add-generic-password`, `-w` on stdout for
//! `find-generic-password`), never through the argument list. Callers run
//! these blocking subprocess calls under `spawn_blocking`.

use std::{
    io::{self, Write as _},
    process::{Command, Stdio},
};

use thiserror::Error;

const KEYCHAIN_SERVICE: &str = "rutilus-master-key";
const KEYCHAIN_ACCOUNT: &str = "rutilus";

/// Stores `plaintext` as the product's Keychain generic-password item,
/// replacing any previous item (`-U`).
///
/// # Errors
///
/// Returns [`KeychainCliError`] when `security(1)` cannot be invoked or
/// refuses the item.
pub(crate) fn store(plaintext: &[u8]) -> Result<(), KeychainCliError> {
    let operation = "add-generic-password";
    let mut child = Command::new("security")
        .args([
            operation,
            "-U",
            "-a",
            KEYCHAIN_ACCOUNT,
            "-s",
            KEYCHAIN_SERVICE,
            "-w",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|source| KeychainCliError::Spawn { operation, source })?;
    let mut stdin = child.stdin.take().ok_or_else(|| KeychainCliError::Spawn {
        operation,
        source: io::Error::other("security(1) stdin was not piped"),
    })?;
    stdin
        .write_all(plaintext)
        .map_err(|source| KeychainCliError::Write { operation, source })?;
    drop(stdin);
    finish(operation, child.wait_with_output())
}

/// Reads the product's Keychain generic-password item.
///
/// # Errors
///
/// Returns [`KeychainCliError`] when `security(1)` cannot be invoked or the
/// item does not exist; no plaintext is released on failure.
pub(crate) fn load() -> Result<Vec<u8>, KeychainCliError> {
    let operation = "find-generic-password";
    let output = Command::new("security")
        .args([
            operation,
            "-a",
            KEYCHAIN_ACCOUNT,
            "-s",
            KEYCHAIN_SERVICE,
            "-w",
        ])
        .output()
        .map_err(|source| KeychainCliError::Spawn { operation, source })?;
    if !output.status.success() {
        return Err(KeychainCliError::Failed {
            operation,
            status: exit_status(output.status),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }
    Ok(output.stdout)
}

fn finish(
    operation: &'static str,
    result: io::Result<std::process::Output>,
) -> Result<(), KeychainCliError> {
    let output = result.map_err(|source| KeychainCliError::Spawn { operation, source })?;
    if !output.status.success() {
        return Err(KeychainCliError::Failed {
            operation,
            status: exit_status(output.status),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }
    Ok(())
}

// `ExitStatus` is a 4-byte `Copy` type; the macOS clippy gate
// (trivially_copy_pass_by_ref, `-D warnings`) demands by-value.
fn exit_status(status: std::process::ExitStatus) -> String {
    status.code().map_or_else(
        || "terminated by signal".to_owned(),
        |code| code.to_string(),
    )
}

/// A controlled failure of one `security(1)` invocation.
#[derive(Debug, Error)]
pub enum KeychainCliError {
    #[error("failed to invoke `security(1)` for {operation}: {source}")]
    Spawn {
        operation: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("failed to pass the Keychain item to `security(1)` {operation}: {source}")]
    Write {
        operation: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("`security(1)` {operation} exited with status {status}: {stderr}")]
    Failed {
        operation: &'static str,
        status: String,
        stderr: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_errors_are_secret_safe_and_source_typed() {
        let error = KeychainCliError::Failed {
            operation: "find-generic-password",
            status: "44".to_owned(),
            stderr: "item not found".to_owned(),
        };

        assert!(
            error.to_string().contains("find-generic-password"),
            "the operation stage must be diagnosable"
        );
        assert!(!error.to_string().contains("plaintext"));
        let _: &(dyn std::error::Error + 'static) = &error;
    }
}
