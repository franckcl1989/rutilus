//! The encrypted product backup package (design §20.1).
//!
//! One file carries the complete product state:
//!
//! ```text
//! magic (8, "RUTBK001") | format version (1) | manifest length (4, LE)
//! | manifest JSON | nonce (24) | authenticated ciphertext (entries + tag)
//! ```
//!
//! The manifest lists every entry (name, kind, byte length, SHA-256). The
//! payload is the concatenated entry contents, protected with the same
//! `XChaCha20-Poly1305` primitive the credential ciphertext uses, with the
//! instance master key directly as the AEAD key — the `encrypt_credential`
//! pattern, not a new key-derivation step (design §10.3). The header and the
//! manifest are authenticated as associated data, so tampering with the
//! entry list fails authentication before a single byte is decrypted; every
//! decrypted entry is additionally verified against its manifest SHA-256.
//!
//! The protected master-key envelope rides inside the payload as an ordinary
//! entry — never the plaintext key (§10.3: the package's key wrapping never
//! appears in clear). The package itself never contains plaintext secrets:
//! the database entry carries already-encrypted credential ciphertext, and
//! the key entries are the existing protected envelopes.

use std::{error::Error, fmt};

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::MasterKey;

/// The versioned magic framing the package, following the `RUTMK002` and
/// `RUTOSK001` envelope precedents.
pub const BACKUP_PACKAGE_MAGIC: [u8; 8] = *b"RUTBK001";
/// The format version carried after the magic; the only supported version.
pub const BACKUP_PACKAGE_FORMAT_VERSION: u8 = 1;
/// Defensive upper bound for one entry name: names are opaque identifiers.
pub const MAX_ENTRY_NAME_LENGTH: usize = 255;
/// Defensive upper bound for the entry count of one package.
pub const MAX_ENTRIES: usize = 1024;
/// Defensive upper bound for one serialized manifest.
pub const MAX_MANIFEST_LENGTH: usize = 1024 * 1024;

const FORMAT_VERSION_BYTES: usize = 1;
const MANIFEST_LENGTH_BYTES: usize = 4;
const NONCE_LENGTH: usize = 24;
const AUTHENTICATION_TAG_LENGTH: usize = 16;
const HEADER_LENGTH: usize =
    BACKUP_PACKAGE_MAGIC.len() + FORMAT_VERSION_BYTES + MANIFEST_LENGTH_BYTES;
const MINIMUM_PACKAGE_LENGTH: usize = HEADER_LENGTH + NONCE_LENGTH + AUTHENTICATION_TAG_LENGTH;

/// The product artifact one backup entry carries.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BackupEntryKind {
    /// The consistent `SQLite` main database file.
    Database,
    /// The durable `SQLite` write-ahead-log sidecar, when present.
    DatabaseWal,
    /// The passphrase-protected master-key envelope (`RUTMK002`).
    MasterKey,
    /// The OS-protected master-key envelope (`RUTOSK001`).
    SystemMasterKey,
    /// The instance completion marker (`instance.rut`).
    InstanceMarker,
    /// A Site TLS certificate chain (`tls/cert.pem`).
    TlsCertificate,
    /// A Site TLS private key (`tls/key.pem`).
    TlsPrivateKey,
    /// One uploaded artifact file below `artifacts/`.
    ArtifactFile,
}

/// One plaintext entry offered to a backup package.
#[derive(Clone, Eq, PartialEq)]
pub struct BackupEntry {
    name: String,
    kind: BackupEntryKind,
    content: Vec<u8>,
}

impl BackupEntry {
    /// Builds one named entry, validating the name bound.
    ///
    /// # Errors
    ///
    /// Returns [`BackupPackageError::EmptyEntryName`], [`BackupPackageError::EntryNameTooLong`],
    /// or [`BackupPackageError::InvalidEntryName`] for an unusable name.
    pub fn new(
        name: impl Into<String>,
        kind: BackupEntryKind,
        content: Vec<u8>,
    ) -> Result<Self, BackupPackageError> {
        let name = name.into();
        validate_entry_name(&name)?;
        Ok(Self {
            name,
            kind,
            content,
        })
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub const fn kind(&self) -> BackupEntryKind {
        self.kind
    }

    #[must_use]
    pub fn content(&self) -> &[u8] {
        &self.content
    }

    #[must_use]
    pub fn into_content(self) -> Vec<u8> {
        self.content
    }
}

impl fmt::Debug for BackupEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BackupEntry")
            .field("name", &self.name)
            .field("kind", &self.kind)
            .field("content", &"[REDACTED]")
            .finish()
    }
}

/// One decrypted package entry, ready for restore.
#[derive(Clone, Eq, PartialEq)]
pub struct DecryptedEntry {
    name: String,
    kind: BackupEntryKind,
    content: Vec<u8>,
}

impl DecryptedEntry {
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub const fn kind(&self) -> BackupEntryKind {
        self.kind
    }

    #[must_use]
    pub fn content(&self) -> &[u8] {
        &self.content
    }

    #[must_use]
    pub fn into_content(self) -> Vec<u8> {
        self.content
    }
}

impl fmt::Debug for DecryptedEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DecryptedEntry")
            .field("name", &self.name)
            .field("kind", &self.kind)
            .field("content", &"[REDACTED]")
            .finish()
    }
}

/// The authenticated result of opening one backup package.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecryptedBackup {
    product_version: String,
    schema_version: u32,
    entries: Vec<DecryptedEntry>,
}

impl DecryptedBackup {
    #[must_use]
    pub fn product_version(&self) -> &str {
        &self.product_version
    }

    #[must_use]
    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    #[must_use]
    pub fn entries(&self) -> &[DecryptedEntry] {
        &self.entries
    }

    /// Finds one entry by its manifest name.
    #[must_use]
    pub fn entry(&self, name: &str) -> Option<&DecryptedEntry> {
        self.entries.iter().find(|entry| entry.name == name)
    }
}

/// The serialized manifest of one package.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct BackupManifest {
    product_version: String,
    schema_version: u32,
    entries: Vec<BackupManifestEntry>,
}

/// One manifest line: name, kind, length, and SHA-256 of the plaintext.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct BackupManifestEntry {
    name: String,
    kind: BackupEntryKind,
    length: u64,
    sha256: String,
}

/// Encrypts a set of product entries into one versioned backup package.
///
/// The package's AEAD key is the instance master key itself — the direct-key
/// pattern of the credential ciphertext — so the package invents no key
/// derivation and its confidentiality is exactly the master key's. The
/// header and manifest are authenticated as associated data, and every entry
/// is fingerprinted in the manifest with SHA-256.
///
/// # Errors
///
/// Returns [`BackupPackageError`] for invalid product identity, unusable or
/// duplicate entry names, an oversized entry set or manifest, unavailable
/// randomness, or encryption failure.
pub fn create_backup_package(
    master_key: &MasterKey,
    product_version: &str,
    schema_version: u32,
    entries: &[BackupEntry],
) -> Result<Vec<u8>, BackupPackageError> {
    if product_version.is_empty() {
        return Err(BackupPackageError::EmptyProductVersion);
    }
    if entries.len() > MAX_ENTRIES {
        return Err(BackupPackageError::TooManyEntries {
            count: entries.len(),
        });
    }
    ensure_unique_names(entries)?;

    let manifest = BackupManifest {
        product_version: product_version.to_owned(),
        schema_version,
        entries: entries
            .iter()
            .map(|entry| BackupManifestEntry {
                name: entry.name.clone(),
                kind: entry.kind,
                length: entry.content.len() as u64,
                sha256: hex_sha256(&entry.content),
            })
            .collect(),
    };
    let manifest_bytes =
        serde_json::to_vec(&manifest).map_err(BackupPackageError::InvalidManifest)?;
    if manifest_bytes.len() > MAX_MANIFEST_LENGTH {
        return Err(BackupPackageError::ManifestTooLong {
            length: manifest_bytes.len(),
        });
    }

    let payload_length = entries.iter().try_fold(0_u64, |total, entry| {
        total
            .checked_add(entry.content.len() as u64)
            .ok_or(BackupPackageError::PayloadTooLarge)
    })?;
    let payload_length =
        usize::try_from(payload_length).map_err(|_| BackupPackageError::PayloadLengthMismatch {
            declared: payload_length,
            payload: 0,
        })?;
    let mut payload = Vec::with_capacity(payload_length);
    for entry in entries {
        payload.extend_from_slice(&entry.content);
    }

    let mut nonce = [0_u8; NONCE_LENGTH];
    getrandom::fill(&mut nonce).map_err(BackupPackageError::RandomnessUnavailable)?;

    let cipher = XChaCha20Poly1305::new_from_slice(master_key.expose())
        .map_err(|_| BackupPackageError::InvalidMasterKeyLength)?;
    let associated_data = framed_header_and_manifest(&manifest_bytes)?;
    let ciphertext = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: &payload,
                aad: &associated_data,
            },
        )
        .map_err(|_| BackupPackageError::EncryptionFailed)?;

    let mut package = associated_data;
    package.extend_from_slice(&nonce);
    package.extend_from_slice(&ciphertext);
    Ok(package)
}

/// Authenticates, decrypts, and verifies one backup package.
///
/// # Errors
///
/// Returns [`BackupPackageError`] for a truncated, unsupported, tampered, or
/// malformed package, a wrong master key, or a manifest whose entries do not
/// match the decrypted payload. No entry bytes are released on failure.
pub fn open_backup_package(
    master_key: &MasterKey,
    package: &[u8],
) -> Result<DecryptedBackup, BackupPackageError> {
    if package.len() < MINIMUM_PACKAGE_LENGTH {
        return Err(BackupPackageError::PackageTooShort {
            length: package.len(),
        });
    }
    if !package.starts_with(&BACKUP_PACKAGE_MAGIC) {
        return Err(BackupPackageError::UnsupportedFormat);
    }
    if package[BACKUP_PACKAGE_MAGIC.len()] != BACKUP_PACKAGE_FORMAT_VERSION {
        return Err(BackupPackageError::UnsupportedFormat);
    }

    let manifest_length = read_manifest_length(package)?.try_into().map_err(|_| {
        BackupPackageError::PackageTooShort {
            length: package.len(),
        }
    })?;
    let manifest_end =
        HEADER_LENGTH
            .checked_add(manifest_length)
            .ok_or(BackupPackageError::PackageTooShort {
                length: package.len(),
            })?;
    if package.len() < manifest_end + NONCE_LENGTH + AUTHENTICATION_TAG_LENGTH {
        return Err(BackupPackageError::PackageTooShort {
            length: package.len(),
        });
    }

    let manifest: BackupManifest = serde_json::from_slice(&package[HEADER_LENGTH..manifest_end])
        .map_err(BackupPackageError::InvalidManifest)?;
    if manifest.entries.len() > MAX_ENTRIES {
        return Err(BackupPackageError::TooManyEntries {
            count: manifest.entries.len(),
        });
    }
    for entry in &manifest.entries {
        validate_entry_name(&entry.name)?;
    }
    ensure_unique_manifest_names(&manifest.entries)?;

    let cipher = XChaCha20Poly1305::new_from_slice(master_key.expose())
        .map_err(|_| BackupPackageError::InvalidMasterKeyLength)?;
    let mut nonce = [0_u8; NONCE_LENGTH];
    nonce.copy_from_slice(&package[manifest_end..manifest_end + NONCE_LENGTH]);
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &package[manifest_end + NONCE_LENGTH..],
                    aad: &package[..manifest_end],
                },
            )
            .map_err(|_| BackupPackageError::AuthenticationFailed)?,
    );

    let declared_total = manifest.entries.iter().try_fold(0_u64, |total, entry| {
        total
            .checked_add(entry.length)
            .ok_or(BackupPackageError::PayloadLengthMismatch {
                declared: total,
                payload: plaintext.len(),
            })
    })?;
    if declared_total != plaintext.len() as u64 {
        return Err(BackupPackageError::PayloadLengthMismatch {
            declared: declared_total,
            payload: plaintext.len(),
        });
    }

    let mut entries = Vec::with_capacity(manifest.entries.len());
    let mut offset = 0_usize;
    for entry in &manifest.entries {
        let length = usize::try_from(entry.length).map_err(|_| {
            BackupPackageError::PayloadLengthMismatch {
                declared: declared_total,
                payload: plaintext.len(),
            }
        })?;
        let content = plaintext[offset..offset + length].to_vec();
        if hex_sha256(&content) != entry.sha256 {
            return Err(BackupPackageError::Sha256Mismatch {
                name: entry.name.clone(),
            });
        }
        entries.push(DecryptedEntry {
            name: entry.name.clone(),
            kind: entry.kind,
            content,
        });
        offset += length;
    }

    Ok(DecryptedBackup {
        product_version: manifest.product_version,
        schema_version: manifest.schema_version,
        entries,
    })
}

/// The authenticated prefix of the package: magic, version, length, manifest.
///
/// The length field always fits `u32` because the manifest was already
/// bounded by [`MAX_MANIFEST_LENGTH`]; the conversion error is mapped to
/// [`BackupPackageError::ManifestTooLong`] for completeness.
fn framed_header_and_manifest(manifest_bytes: &[u8]) -> Result<Vec<u8>, BackupPackageError> {
    let manifest_length =
        u32::try_from(manifest_bytes.len()).map_err(|_| BackupPackageError::ManifestTooLong {
            length: manifest_bytes.len(),
        })?;
    let mut prefix = Vec::with_capacity(HEADER_LENGTH + manifest_bytes.len());
    prefix.extend_from_slice(&BACKUP_PACKAGE_MAGIC);
    prefix.push(BACKUP_PACKAGE_FORMAT_VERSION);
    prefix.extend_from_slice(&manifest_length.to_le_bytes());
    prefix.extend_from_slice(manifest_bytes);
    Ok(prefix)
}

/// The manifest length field, validated against the manifest bound.
fn read_manifest_length(package: &[u8]) -> Result<u32, BackupPackageError> {
    let mut bytes = [0_u8; MANIFEST_LENGTH_BYTES];
    bytes.copy_from_slice(
        &package[BACKUP_PACKAGE_MAGIC.len() + FORMAT_VERSION_BYTES..HEADER_LENGTH],
    );
    let length = u32::from_le_bytes(bytes);
    if length as usize > MAX_MANIFEST_LENGTH {
        return Err(BackupPackageError::InvalidManifestLength { length });
    }
    Ok(length)
}

fn validate_entry_name(name: &str) -> Result<(), BackupPackageError> {
    if name.is_empty() {
        return Err(BackupPackageError::EmptyEntryName);
    }
    if name.len() > MAX_ENTRY_NAME_LENGTH {
        return Err(BackupPackageError::EntryNameTooLong { length: name.len() });
    }
    if name.as_bytes().contains(&0) {
        return Err(BackupPackageError::InvalidEntryName {
            name: name.to_owned(),
        });
    }
    Ok(())
}

fn ensure_unique_names(entries: &[BackupEntry]) -> Result<(), BackupPackageError> {
    let mut names = std::collections::HashSet::with_capacity(entries.len());
    for entry in entries {
        if !names.insert(entry.name.as_str()) {
            return Err(BackupPackageError::DuplicateEntryName {
                name: entry.name.clone(),
            });
        }
    }
    Ok(())
}

fn ensure_unique_manifest_names(entries: &[BackupManifestEntry]) -> Result<(), BackupPackageError> {
    let mut names = std::collections::HashSet::with_capacity(entries.len());
    for entry in entries {
        if !names.insert(entry.name.as_str()) {
            return Err(BackupPackageError::DuplicateEntryName {
                name: entry.name.clone(),
            });
        }
    }
    Ok(())
}

fn hex_sha256(content: &[u8]) -> String {
    let digest = Sha256::digest(content);
    digest
        .iter()
        .fold(String::with_capacity(digest.len() * 2), |mut hex, byte| {
            let _ = std::fmt::Write::write_fmt(&mut hex, format_args!("{byte:02x}"));
            hex
        })
}

/// A controlled failure while creating or opening a backup package.
#[derive(Debug)]
pub enum BackupPackageError {
    /// The product identity recorded in the manifest cannot be empty.
    EmptyProductVersion,
    /// An entry name is empty.
    EmptyEntryName,
    /// An entry name exceeds [`MAX_ENTRY_NAME_LENGTH`].
    EntryNameTooLong { length: usize },
    /// An entry name contains an unrepresentable character.
    InvalidEntryName { name: String },
    /// Two entries carry the same name.
    DuplicateEntryName { name: String },
    /// The entry count exceeds [`MAX_ENTRIES`].
    TooManyEntries { count: usize },
    /// The serialized manifest exceeds [`MAX_MANIFEST_LENGTH`].
    ManifestTooLong { length: usize },
    /// The concatenated plaintext payload exceeds the addressable range.
    PayloadTooLarge,
    /// The operating system did not provide cryptographically secure randomness.
    RandomnessUnavailable(getrandom::Error),
    /// The supplied master key is not the algorithm's required length.
    InvalidMasterKeyLength,
    /// Authenticated encryption could not produce the payload ciphertext.
    EncryptionFailed,
    /// The package is shorter than the smallest possible valid package.
    PackageTooShort { length: usize },
    /// The package magic or format version is unknown.
    UnsupportedFormat,
    /// The manifest length field exceeds the defensive bound.
    InvalidManifestLength { length: u32 },
    /// The manifest is not valid JSON for the package format.
    InvalidManifest(serde_json::Error),
    /// The package ciphertext or associated data failed authentication.
    AuthenticationFailed,
    /// The manifest's declared payload total does not match the ciphertext.
    PayloadLengthMismatch { declared: u64, payload: usize },
    /// A decrypted entry does not match its manifest SHA-256.
    Sha256Mismatch { name: String },
}

impl fmt::Display for BackupPackageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyProductVersion => {
                formatter.write_str("backup package product version cannot be empty")
            }
            Self::EmptyEntryName => {
                formatter.write_str("backup package entry name cannot be empty")
            }
            Self::EntryNameTooLong { length } => write!(
                formatter,
                "backup package entry name exceeds the {MAX_ENTRY_NAME_LENGTH}-byte bound ({length} bytes)"
            ),
            Self::InvalidEntryName { name } => {
                write!(
                    formatter,
                    "backup package entry name {name:?} is not usable"
                )
            }
            Self::DuplicateEntryName { name } => {
                write!(
                    formatter,
                    "backup package contains duplicate entry name {name:?}"
                )
            }
            Self::TooManyEntries { count } => write!(
                formatter,
                "backup package entry count {count} exceeds the {MAX_ENTRIES} bound"
            ),
            Self::ManifestTooLong { length } => write!(
                formatter,
                "backup package manifest exceeds the {MAX_MANIFEST_LENGTH}-byte bound ({length} bytes)"
            ),
            Self::PayloadTooLarge => formatter.write_str("backup package payload is too large"),
            Self::RandomnessUnavailable(_) => {
                formatter.write_str("cryptographic randomness is unavailable")
            }
            Self::InvalidMasterKeyLength => {
                formatter.write_str("backup package master key has an invalid length")
            }
            Self::EncryptionFailed => formatter.write_str("backup package encryption failed"),
            Self::PackageTooShort { length } => write!(
                formatter,
                "backup package is too short to be valid ({length} bytes)"
            ),
            Self::UnsupportedFormat => {
                formatter.write_str("backup package format or version is unsupported")
            }
            Self::InvalidManifestLength { length } => write!(
                formatter,
                "backup package manifest length {length} exceeds the defensive bound"
            ),
            Self::InvalidManifest(_) => formatter.write_str("backup package manifest is invalid"),
            Self::AuthenticationFailed => {
                formatter.write_str("backup package authentication failed")
            }
            Self::PayloadLengthMismatch { declared, payload } => write!(
                formatter,
                "backup package payload length mismatch: manifest declares {declared} bytes, ciphertext holds {payload}"
            ),
            Self::Sha256Mismatch { name } => write!(
                formatter,
                "backup package entry {name:?} failed its SHA-256 verification"
            ),
        }
    }
}

impl Error for BackupPackageError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::RandomnessUnavailable(source) => Some(source),
            Self::InvalidManifest(source) => Some(source),
            Self::EmptyProductVersion
            | Self::EmptyEntryName
            | Self::EntryNameTooLong { .. }
            | Self::InvalidEntryName { .. }
            | Self::DuplicateEntryName { .. }
            | Self::TooManyEntries { .. }
            | Self::ManifestTooLong { .. }
            | Self::PayloadTooLarge
            | Self::InvalidMasterKeyLength
            | Self::EncryptionFailed
            | Self::PackageTooShort { .. }
            | Self::UnsupportedFormat
            | Self::InvalidManifestLength { .. }
            | Self::AuthenticationFailed
            | Self::PayloadLengthMismatch { .. }
            | Self::Sha256Mismatch { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::*;

    fn test_key(byte: u8) -> MasterKey {
        MasterKey::from_boxed_bytes(Box::new([byte; 32]))
    }

    fn sample_entries() -> Result<Vec<BackupEntry>, BackupPackageError> {
        Ok(vec![
            BackupEntry::new(
                "database",
                BackupEntryKind::Database,
                b"sqlite-bytes".to_vec(),
            )?,
            BackupEntry::new("master-key", BackupEntryKind::MasterKey, vec![0x5a; 96])?,
            BackupEntry::new(
                "config",
                BackupEntryKind::InstanceMarker,
                b"RUTINS01".to_vec(),
            )?,
        ])
    }

    #[test]
    fn round_trips_every_entry_and_version() -> Result<(), Box<dyn Error>> {
        let key = test_key(0x51);
        let package = create_backup_package(&key, "0.6.0", 19, &sample_entries()?)?;

        assert!(package.starts_with(&BACKUP_PACKAGE_MAGIC));
        let opened = open_backup_package(&key, &package)?;

        assert_eq!(opened.product_version(), "0.6.0");
        assert_eq!(opened.schema_version(), 19);
        assert_eq!(opened.entries().len(), 3);
        assert_eq!(
            opened
                .entry("database")
                .ok_or("missing database entry")?
                .content(),
            b"sqlite-bytes"
        );
        assert_eq!(
            opened
                .entry("master-key")
                .ok_or("missing master-key entry")?
                .content(),
            &[0x5a; 96]
        );
        assert_eq!(
            opened
                .entry("config")
                .ok_or("missing instance entry")?
                .content(),
            b"RUTINS01"
        );
        assert_eq!(
            opened
                .entry("database")
                .ok_or("missing database entry")?
                .kind(),
            BackupEntryKind::Database
        );
        Ok(())
    }

    #[test]
    fn rejects_tampering_in_the_ciphertext_and_the_manifest() -> Result<(), Box<dyn Error>> {
        let key = test_key(0x52);
        let package = create_backup_package(&key, "0.6.0", 19, &sample_entries()?)?;

        let mut tampered_payload = package.clone();
        let payload_index = tampered_payload.len() - 1;
        tampered_payload[payload_index] ^= 1;
        assert!(matches!(
            open_backup_package(&key, &tampered_payload),
            Err(BackupPackageError::AuthenticationFailed)
        ));

        // A flip inside the manifest keeps the JSON parseable (a digit
        // becomes another digit), so the tamper must be caught by the
        // associated-data authentication of the header and manifest.
        let mut tampered_manifest = package;
        let manifest = &tampered_manifest[HEADER_LENGTH..HEADER_LENGTH + 26];
        let digit = manifest
            .iter()
            .position(u8::is_ascii_digit)
            .ok_or("the sample manifest has no digit to tamper")?;
        tampered_manifest[HEADER_LENGTH + digit] ^= 1;
        assert!(matches!(
            open_backup_package(&key, &tampered_manifest),
            Err(BackupPackageError::AuthenticationFailed)
        ));
        Ok(())
    }

    #[test]
    fn rejects_unknown_magic_versions_and_truncation() -> Result<(), Box<dyn Error>> {
        let key = test_key(0x53);
        let package = create_backup_package(&key, "0.6.0", 19, &sample_entries()?)?;

        let mut wrong_magic = package.clone();
        wrong_magic[0] ^= 1;
        assert!(matches!(
            open_backup_package(&key, &wrong_magic),
            Err(BackupPackageError::UnsupportedFormat)
        ));

        let mut wrong_version = package.clone();
        wrong_version[BACKUP_PACKAGE_MAGIC.len()] = 2;
        assert!(matches!(
            open_backup_package(&key, &wrong_version),
            Err(BackupPackageError::UnsupportedFormat)
        ));

        for cut in [0_usize, 1, MINIMUM_PACKAGE_LENGTH - 1, package.len() - 1] {
            let truncated = &package[..cut];
            assert!(
                matches!(
                    open_backup_package(&key, truncated),
                    Err(BackupPackageError::PackageTooShort { .. })
                ) || matches!(
                    open_backup_package(&key, truncated),
                    Err(BackupPackageError::AuthenticationFailed)
                ),
                "cut at {cut} must be rejected"
            );
        }
        Ok(())
    }

    #[test]
    fn rejects_a_wrong_master_key_without_releasing_bytes() -> Result<(), Box<dyn Error>> {
        let key = test_key(0x54);
        let wrong_key = test_key(0x55);
        let package = create_backup_package(&key, "0.6.0", 19, &sample_entries()?)?;

        assert!(matches!(
            open_backup_package(&wrong_key, &package),
            Err(BackupPackageError::AuthenticationFailed)
        ));
        Ok(())
    }

    #[test]
    fn uses_an_independent_nonce_for_each_package() -> Result<(), Box<dyn Error>> {
        let key = test_key(0x56);

        let first = create_backup_package(&key, "0.6.0", 19, &sample_entries()?)?;
        let second = create_backup_package(&key, "0.6.0", 19, &sample_entries()?)?;

        assert_ne!(first, second);
        Ok(())
    }

    #[test]
    fn validates_names_counts_and_product_identity() -> Result<(), BackupPackageError> {
        let key = test_key(0x57);

        assert!(matches!(
            create_backup_package(&key, "", 19, &sample_entries()?),
            Err(BackupPackageError::EmptyProductVersion)
        ));
        assert!(matches!(
            BackupEntry::new("", BackupEntryKind::Database, vec![]),
            Err(BackupPackageError::EmptyEntryName)
        ));
        assert!(matches!(
            BackupEntry::new(
                "x".repeat(MAX_ENTRY_NAME_LENGTH + 1),
                BackupEntryKind::Database,
                vec![]
            ),
            Err(BackupPackageError::EntryNameTooLong { .. })
        ));
        assert!(matches!(
            BackupEntry::new("bad\0name", BackupEntryKind::Database, vec![]),
            Err(BackupPackageError::InvalidEntryName { .. })
        ));

        let duplicate = vec![
            BackupEntry::new("same", BackupEntryKind::Database, vec![])?,
            BackupEntry::new("same", BackupEntryKind::MasterKey, vec![])?,
        ];
        assert!(matches!(
            create_backup_package(&key, "0.6.0", 19, &duplicate),
            Err(BackupPackageError::DuplicateEntryName { .. })
        ));

        let mut too_many = Vec::with_capacity(MAX_ENTRIES + 1);
        for index in 0..=MAX_ENTRIES {
            too_many.push(BackupEntry::new(
                format!("entry-{index}"),
                BackupEntryKind::ArtifactFile,
                vec![],
            )?);
        }
        assert!(matches!(
            create_backup_package(&key, "0.6.0", 19, &too_many),
            Err(BackupPackageError::TooManyEntries { .. })
        ));
        Ok(())
    }

    #[test]
    fn debug_output_is_redacted() -> Result<(), Box<dyn Error>> {
        let entry = BackupEntry::new(
            "secret-entry",
            BackupEntryKind::MasterKey,
            b"never log this".to_vec(),
        )?;
        let debug = format!("{entry:?}");

        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("never log this"));
        Ok(())
    }
}
