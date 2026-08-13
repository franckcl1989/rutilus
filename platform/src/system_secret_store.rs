//! The operating system's secret store for the master key (0.6.0 S3).
//!
//! [`UnlockSource::System`] protects the master key inside the OS instead of
//! with an operator-entered passphrase, so a Site service can start
//! unattended. The store here is the per-platform byte-level protector the
//! security crate's envelope consumes:
//!
//! - **Windows**: DPAPI (`CryptProtectData`/`CryptUnprotectData`) under the
//!   current Windows user; the persisted envelope carries the DPAPI blob.
//! - **macOS**: a Keychain generic-password item written and read through
//!   `security(1)`; the command is spawned under `spawn_blocking` and the
//!   secret travels through stdin/stdout, never the process argument list.
//!   The Keychain item is authoritative; the persisted envelope mirrors it
//!   for backup and Doctor.
//! - **Linux**: the operating system provides no keychain, so the 0600
//!   `system-master-key.rut` file is the protection and this store is an
//!   identity pass-through that keeps the unlock flow uniform across
//!   platforms. [`SystemMasterKeyFile`](crate::SystemMasterKeyFile) enforces
//!   the 0600 creation and load checks.
//!
//! # Limitations
//!
//! - On macOS the persisted envelope mirrors the Keychain item and therefore
//!   carries the raw key bytes, restricted only by the user data directory's
//!   permissions. The Keychain item is authoritative for recovery, and the
//!   mirror has no restore consumer yet — a future backup restore must
//!   re-create the Keychain item, not just the file.
//! - The macOS path spawns `security(1)` and therefore depends on the test
//!   environment having a logged-in, unlocked user Keychain; the current
//!   macOS tests deliberately avoid real Keychain calls and cover the CLI
//!   error surface only.

#[cfg(target_os = "macos")]
mod macos_keychain;
#[cfg(windows)]
mod windows_dpapi;

pub use rutilus_security::UnlockSource;

use rutilus_security::SystemKeyProtector;
use thiserror::Error;

/// The operating system's master-key secret store for the current platform.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemSecretStore;

impl SystemSecretStore {
    /// Creates the current platform's store.
    ///
    /// The store itself is stateless: Windows DPAPI is a pure transform, the
    /// macOS Keychain item is addressed by fixed constants, and the Linux
    /// protection lives in the 0600 envelope file.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Protects `plaintext` inside the operating system's store.
    ///
    /// # Errors
    ///
    /// Returns [`SystemSecretStoreError`] when the store cannot protect the
    /// bytes; the input is never echoed in the error.
    pub async fn protect(&self, plaintext: &[u8]) -> Result<Vec<u8>, SystemSecretStoreError> {
        platform_protect(plaintext).await
    }

    /// Recovers the original bytes of an OS-protected payload.
    ///
    /// # Errors
    ///
    /// Returns [`SystemSecretStoreError`] when the store cannot recover the
    /// payload; no plaintext is released on failure.
    pub async fn unprotect(&self, payload: &[u8]) -> Result<Vec<u8>, SystemSecretStoreError> {
        platform_unprotect(payload).await
    }
}

impl SystemKeyProtector for SystemSecretStore {
    type Error = SystemSecretStoreError;

    async fn protect(&self, plaintext: &[u8]) -> Result<Vec<u8>, Self::Error> {
        self.protect(plaintext).await
    }

    async fn unprotect(&self, payload: &[u8]) -> Result<Vec<u8>, Self::Error> {
        self.unprotect(payload).await
    }
}

#[cfg(windows)]
async fn platform_protect(plaintext: &[u8]) -> Result<Vec<u8>, SystemSecretStoreError> {
    // DPAPI is a blocking Win32 call with heap allocation; keep it off the
    // async runtime's worker threads.
    let plaintext = plaintext.to_vec();
    tokio::task::spawn_blocking(move || windows_dpapi::protect(&plaintext))
        .await
        .map_err(SystemSecretStoreError::BlockingTask)?
        .map_err(|code| SystemSecretStoreError::Dpapi {
            operation: "protect",
            code,
        })
}

#[cfg(windows)]
async fn platform_unprotect(payload: &[u8]) -> Result<Vec<u8>, SystemSecretStoreError> {
    let payload = payload.to_vec();
    tokio::task::spawn_blocking(move || windows_dpapi::unprotect(&payload))
        .await
        .map_err(SystemSecretStoreError::BlockingTask)?
        .map_err(|code| SystemSecretStoreError::Dpapi {
            operation: "unprotect",
            code,
        })
}

#[cfg(target_os = "macos")]
async fn platform_protect(plaintext: &[u8]) -> Result<Vec<u8>, SystemSecretStoreError> {
    // `security(1)` is a blocking subprocess; the Keychain item is the
    // protection, so the payload returns unchanged for uniform framing.
    let plaintext = plaintext.to_vec();
    tokio::task::spawn_blocking({
        let plaintext = plaintext.clone();
        move || macos_keychain::store(&plaintext)
    })
    .await
    .map_err(SystemSecretStoreError::BlockingTask)?
    .map_err(SystemSecretStoreError::Keychain)?;
    Ok(plaintext)
}

#[cfg(target_os = "macos")]
async fn platform_unprotect(_payload: &[u8]) -> Result<Vec<u8>, SystemSecretStoreError> {
    // The Keychain item is authoritative; the persisted payload is only a
    // mirror artifact and is not consulted for recovery.
    tokio::task::spawn_blocking(macos_keychain::load)
        .await
        .map_err(SystemSecretStoreError::BlockingTask)?
        .map_err(SystemSecretStoreError::Keychain)
}

#[cfg(target_os = "linux")]
#[allow(clippy::unused_async)]
async fn platform_protect(plaintext: &[u8]) -> Result<Vec<u8>, SystemSecretStoreError> {
    // Linux has no OS keychain: the 0600 envelope file (written and checked
    // by SystemMasterKeyFile) is the protection, so the bytes pass through.
    // The async signature mirrors the Windows and macOS twins, which must
    // await `spawn_blocking`; the pass-through keeps the unlock flow uniform
    // and the `SystemSecretStore` call sites cfg-free.
    Ok(plaintext.to_vec())
}

#[cfg(target_os = "linux")]
#[allow(clippy::unused_async)]
async fn platform_unprotect(payload: &[u8]) -> Result<Vec<u8>, SystemSecretStoreError> {
    Ok(payload.to_vec())
}

/// A secret-safe failure of the operating system's master-key store.
#[derive(Debug, Error)]
pub enum SystemSecretStoreError {
    #[cfg(windows)]
    #[error("Windows DPAPI {operation} failed (Win32 error {code})")]
    Dpapi { operation: &'static str, code: u32 },
    #[cfg(target_os = "macos")]
    #[error("Keychain `security(1)` failed: {0}")]
    Keychain(#[source] macos_keychain::KeychainCliError),
    #[error("the OS secret-store task failed: {0}")]
    BlockingTask(#[source] tokio::task::JoinError),
}

#[cfg(test)]
mod tests {
    // The three tests below are cfg'd off on macOS (the macOS-specific
    // Keychain CLI tests live in the macos_keychain submodule), leaving the
    // module with no body on that platform — gate the imports the same way
    // or clippy fails the macOS job on unused-imports.
    #[cfg(not(target_os = "macos"))]
    use std::error::Error;

    #[cfg(not(target_os = "macos"))]
    use super::*;

    #[cfg(not(target_os = "macos"))]
    #[tokio::test]
    async fn store_round_trips_os_protected_bytes() -> Result<(), Box<dyn Error>> {
        let store = SystemSecretStore::new();
        let plaintext = [0x5a_u8; 32];

        let protected = store.protect(&plaintext).await?;
        let recovered = store.unprotect(&protected).await?;

        assert_eq!(recovered, plaintext);
        Ok(())
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_dpapi_obfuscates_and_is_independent_per_call() -> Result<(), Box<dyn Error>> {
        let store = SystemSecretStore::new();
        let plaintext = [0x6b_u8; 32];

        let first = store.protect(&plaintext).await?;
        let second = store.protect(&plaintext).await?;

        assert_ne!(first, plaintext, "DPAPI must not persist plaintext");
        assert_ne!(first, second, "DPAPI salts every protection");
        assert_eq!(store.unprotect(&first).await?, plaintext);
        assert_eq!(store.unprotect(&second).await?, plaintext);
        Ok(())
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_dpapi_rejects_foreign_or_tampered_payloads() -> Result<(), Box<dyn Error>> {
        let store = SystemSecretStore::new();

        // Bytes that were never produced by DPAPI must be refused.
        assert!(matches!(
            store.unprotect(&[0_u8; 32]).await,
            Err(SystemSecretStoreError::Dpapi {
                operation: "unprotect",
                ..
            })
        ));

        // A valid blob with one flipped byte must be refused too.
        let protected = store.protect(&[0x6c_u8; 32]).await?;
        let mut tampered = protected;
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(matches!(
            store.unprotect(&tampered).await,
            Err(SystemSecretStoreError::Dpapi {
                operation: "unprotect",
                ..
            })
        ));
        Ok(())
    }
}
