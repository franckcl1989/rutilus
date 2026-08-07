//! Shared TLS material file primitives of the connection layers (the Site
//! listener, the center CA, and the center acceptor): bounded PEM reads and
//! atomic mode-0600 persistence.
//!
//! Every certificate and private-key file the product touches is small, so
//! every read is bounded; every private key is written atomically — a
//! temporary file, fsync, rename — with mode 0600 on Unix applied before
//! any secret bytes are written, so a crash never leaves a partial pair
//! and a peer process never observes a world-readable key.

use std::{
    io,
    path::{Path, PathBuf},
};

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tempfile::NamedTempFile;
use thiserror::Error;

/// The defensive bound for one TLS material file: certificates and keys
/// are small.
pub(crate) const MAX_TLS_FILE_BYTES: u64 = 1024 * 1024;

/// A controlled failure while reading or persisting one TLS material file.
#[derive(Debug, Error)]
pub enum TlsMaterialError {
    #[error("failed to read the TLS material file {path}: {source}")]
    ReadFile {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("TLS material file {path} exceeds the size bound")]
    FileTooLarge { path: PathBuf },
    #[error("invalid TLS certificate {path}: {source}")]
    InvalidCertificate {
        path: PathBuf,
        #[source]
        source: rustls::pki_types::pem::Error,
    },
    #[error("invalid TLS private key {path}: {source}")]
    InvalidPrivateKey {
        path: PathBuf,
        #[source]
        source: rustls::pki_types::pem::Error,
    },
    #[error("the TLS private key type is unsupported")]
    UnsupportedPrivateKey,
    #[error("failed to persist the TLS material at {path}: {source}")]
    Persist {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, TlsMaterialError> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|source| TlsMaterialError::ReadFile {
            path: path.to_path_buf(),
            source,
        })?;
    if metadata.len() > MAX_TLS_FILE_BYTES {
        return Err(TlsMaterialError::FileTooLarge {
            path: path.to_path_buf(),
        });
    }
    let bytes = std::fs::read(path).map_err(|source| TlsMaterialError::ReadFile {
        path: path.to_path_buf(),
        source,
    })?;
    if bytes.len() as u64 > MAX_TLS_FILE_BYTES {
        return Err(TlsMaterialError::FileTooLarge {
            path: path.to_path_buf(),
        });
    }
    Ok(bytes)
}

/// Reads one bounded PEM certificate file.
///
/// # Errors
///
/// Returns [`TlsMaterialError`] when the file is missing, oversized, or not
/// a valid PEM certificate.
pub(crate) fn read_certificate(path: &Path) -> Result<CertificateDer<'static>, TlsMaterialError> {
    use rustls::pki_types::pem::PemObject as _;

    let bytes = read_bounded(path)?;
    CertificateDer::from_pem_slice(&bytes).map_err(|source| TlsMaterialError::InvalidCertificate {
        path: path.to_path_buf(),
        source,
    })
}

/// Reads one bounded PEM private key file.
///
/// # Errors
///
/// Returns [`TlsMaterialError`] when the file is missing, oversized, or not
/// a valid PEM private key.
pub(crate) fn read_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, TlsMaterialError> {
    use rustls::pki_types::pem::PemObject as _;

    let bytes = read_bounded(path)?;
    PrivateKeyDer::from_pem_slice(&bytes).map_err(|source| TlsMaterialError::InvalidPrivateKey {
        path: path.to_path_buf(),
        source,
    })
}

/// Persists one PEM text atomically. The private key's 0600 restriction is
/// applied to the temporary file before any secret bytes are written.
///
/// # Errors
///
/// Returns [`TlsMaterialError::Persist`] retaining the exact I/O stage.
pub(crate) fn persist_text(path: &Path, content: &str) -> Result<(), TlsMaterialError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| TlsMaterialError::Persist {
            path: path.to_path_buf(),
            source: io::Error::new(
                io::ErrorKind::InvalidInput,
                "TLS material path has no parent directory",
            ),
        })?;
    std::fs::create_dir_all(parent).map_err(|source| TlsMaterialError::Persist {
        path: path.to_path_buf(),
        source,
    })?;
    let mut temporary =
        NamedTempFile::new_in(parent).map_err(|source| TlsMaterialError::Persist {
            path: path.to_path_buf(),
            source,
        })?;
    restrict_private_key_permissions(temporary.path())?;
    std::io::Write::write_all(&mut temporary, content.as_bytes()).map_err(|source| {
        TlsMaterialError::Persist {
            path: path.to_path_buf(),
            source,
        }
    })?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|source| TlsMaterialError::Persist {
            path: path.to_path_buf(),
            source,
        })?;
    let persisted = temporary
        .persist(path)
        .map_err(|error| TlsMaterialError::Persist {
            path: path.to_path_buf(),
            source: error.error,
        })?;
    persisted
        .sync_all()
        .map_err(|source| TlsMaterialError::Persist {
            path: path.to_path_buf(),
            source,
        })?;
    Ok(())
}

/// Restricts a freshly created TLS temporary file to mode 0600 before any
/// secret bytes are written (Unix only; Windows has no POSIX modes).
#[cfg(unix)]
fn restrict_private_key_permissions(path: &Path) -> Result<(), TlsMaterialError> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(|source| {
        TlsMaterialError::Persist {
            path: path.to_path_buf(),
            source,
        }
    })
}

// The non-Unix twin mirrors the Unix signature so the call sites stay
// cfg-free; Windows has no POSIX modes to enforce.
#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)]
fn restrict_private_key_permissions(_path: &Path) -> Result<(), TlsMaterialError> {
    Ok(())
}

/// The PEM label and base64 payload of one DER value: `CERTIFICATE` or
/// `PRIVATE KEY`.
pub(crate) fn pem_encode(label: &str, der: &[u8]) -> String {
    use base64::Engine as _;
    use std::fmt::Write as _;

    let encoded = base64::engine::general_purpose::STANDARD.encode(der);
    let mut pem = String::with_capacity(encoded.len() + 64);
    let _ = writeln!(pem, "-----BEGIN {label}-----");
    for chunk in encoded.as_bytes().chunks(64) {
        // Base64 output is pure ASCII, so bytes map one-to-one to characters.
        pem.extend(chunk.iter().map(|byte| *byte as char));
        pem.push('\n');
    }
    let _ = writeln!(pem, "-----END {label}-----");
    pem
}

/// The DER bytes of one private key, for PEM persistence.
///
/// # Errors
///
/// Returns [`TlsMaterialError::UnsupportedPrivateKey`] for an encoding this
/// product does not persist.
pub(crate) fn key_der_bytes<'a>(key: &'a PrivateKeyDer<'a>) -> Result<&'a [u8], TlsMaterialError> {
    match key {
        PrivateKeyDer::Pkcs8(key) => Ok(key.secret_pkcs8_der()),
        PrivateKeyDer::Pkcs1(key) => Ok(key.secret_pkcs1_der()),
        PrivateKeyDer::Sec1(key) => Ok(key.secret_sec1_der()),
        // `#[non_exhaustive]`: a future key encoding has no PEM form in this
        // release, so it cannot be persisted.
        _ => Err(TlsMaterialError::UnsupportedPrivateKey),
    }
}
