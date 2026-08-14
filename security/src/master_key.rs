use std::{error::Error, fmt};

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use secrecy::{ExposeSecret, SecretBox, SecretString};
use zeroize::Zeroizing;

const MASTER_KEY_LENGTH: usize = 32;
/// Format marker of the current passphrase-protected master-key envelope:
/// the wrapping key is derived with the product password baseline's
/// Argon2id parameters (64 MiB / three passes / one lane — the
/// `rutilus_domain::ARGON2ID_*` constants).
const ENVELOPE_MAGIC: [u8; 8] = *b"RUTMK002";
/// Format marker of the legacy version-one envelope, whose wrapping key was
/// derived with the Argon2id library defaults (19 MiB / two passes / one
/// lane). Legacy envelopes are still accepted by [`recover_master_key`] and
/// are re-protected under the current format by [`rewrap_master_key`].
const LEGACY_ENVELOPE_MAGIC: [u8; 8] = *b"RUTMK001";
const SALT_LENGTH: usize = 16;
const NONCE_LENGTH: usize = 24;
const AUTHENTICATION_TAG_LENGTH: usize = 16;
const ENCRYPTED_MASTER_KEY_LENGTH: usize = MASTER_KEY_LENGTH + AUTHENTICATION_TAG_LENGTH;
const SALT_OFFSET: usize = ENVELOPE_MAGIC.len();
const NONCE_OFFSET: usize = SALT_OFFSET + SALT_LENGTH;
const CIPHERTEXT_OFFSET: usize = NONCE_OFFSET + NONCE_LENGTH;
/// Exact byte length of the passphrase-protected master-key envelope (both
/// the current `RUTMK002` format and the legacy `RUTMK001` format share the
/// layout).
pub const MASTER_KEY_ENVELOPE_LENGTH: usize = CIPHERTEXT_OFFSET + ENCRYPTED_MASTER_KEY_LENGTH;

/// Version marker of the system-protected master-key envelope.
pub const SYSTEM_KEY_ENVELOPE_MAGIC: [u8; 9] = *b"RUTOSK001";
/// Defensive upper bound for one OS-protected payload: DPAPI blobs are small,
/// and every read of the persisted envelope must stay bounded.
pub const MAX_SYSTEM_KEY_PAYLOAD_LENGTH: usize = 64 * 1024;
const SYSTEM_KEY_ENVELOPE_MAGIC_LENGTH: usize = SYSTEM_KEY_ENVELOPE_MAGIC.len();

/// Where the master key's protection secret comes from.
///
/// [`Passphrase`](Self::Passphrase) protects the key with a key derived from
/// an operator-entered local unlock passphrase; [`System`](Self::System)
/// delegates protection to the operating system's secret store (DPAPI,
/// Keychain, or a private key file).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnlockSource {
    Passphrase,
    System,
}

/// The operating-system secret-store seam the master-key envelope needs.
///
/// Implemented by the platform crate (`SystemSecretStore`); the security
/// crate only consumes the protected byte payloads, so the seam stays
/// platform-free and the OS store can change without touching the envelope.
///
/// The trait is deliberately generic (`P: SystemKeyProtector`) rather than
/// trait-object based, so the auto-trait bounds of the returned futures are
/// inferred from the concrete protector at each call site.
#[allow(async_fn_in_trait)]
pub trait SystemKeyProtector {
    /// A secret-safe failure of the operating system's store.
    type Error: Error + Send + Sync + 'static;

    /// Protects `plaintext` inside the operating system's store.
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] when the store cannot protect the bytes.
    async fn protect(&self, plaintext: &[u8]) -> Result<Vec<u8>, Self::Error>;

    /// Recovers the original bytes of a protected payload.
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] when the store cannot recover the payload; no
    /// plaintext is released on failure.
    async fn unprotect(&self, payload: &[u8]) -> Result<Vec<u8>, Self::Error>;
}

/// A process-local master key used to protect persisted credentials.
pub struct MasterKey(SecretBox<[u8; MASTER_KEY_LENGTH]>);

impl MasterKey {
    /// Generates a master key from the operating system's cryptographic random source.
    ///
    /// # Errors
    ///
    /// Returns [`crate::CredentialProtectionError::RandomnessUnavailable`] when the operating
    /// system cannot supply cryptographically secure random bytes.
    pub fn generate() -> Result<Self, crate::CredentialProtectionError> {
        let mut generation_result = Ok(());
        let secret: SecretBox<[u8; MASTER_KEY_LENGTH]> =
            SecretBox::init_with_mut(|bytes: &mut [u8; MASTER_KEY_LENGTH]| {
                generation_result = getrandom::fill(bytes);
            });
        generation_result.map_err(crate::CredentialProtectionError::RandomnessUnavailable)?;
        Ok(Self(secret))
    }

    /// Takes ownership of an already protected, exactly sized key allocation.
    #[must_use]
    pub fn from_boxed_bytes(bytes: Box<[u8; MASTER_KEY_LENGTH]>) -> Self {
        Self(SecretBox::new(bytes))
    }

    pub(crate) fn expose(&self) -> &[u8; MASTER_KEY_LENGTH] {
        self.0.expose_secret()
    }
}

impl fmt::Debug for MasterKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MasterKey([REDACTED])")
    }
}

/// A validated, versioned envelope that is safe to persist outside the database.
#[derive(Clone, Eq, PartialEq)]
pub struct ProtectedMasterKey([u8; MASTER_KEY_ENVELOPE_LENGTH]);

impl ProtectedMasterKey {
    /// Validates and copies a persisted envelope: the current `RUTMK002`
    /// format and the legacy `RUTMK001` format are both accepted (a legacy
    /// envelope still unlocks and is migrated by [`rewrap_master_key`]).
    ///
    /// # Errors
    ///
    /// Returns [`MasterKeyProtectionError::InvalidEnvelopeLength`] for a truncated or
    /// extended value, or [`MasterKeyProtectionError::UnsupportedEnvelope`] for an
    /// unknown format or version.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MasterKeyProtectionError> {
        if bytes.len() != MASTER_KEY_ENVELOPE_LENGTH {
            return Err(MasterKeyProtectionError::InvalidEnvelopeLength);
        }
        if !bytes.starts_with(&ENVELOPE_MAGIC) && !bytes.starts_with(&LEGACY_ENVELOPE_MAGIC) {
            return Err(MasterKeyProtectionError::UnsupportedEnvelope);
        }

        let mut envelope = [0_u8; MASTER_KEY_ENVELOPE_LENGTH];
        envelope.copy_from_slice(bytes);
        Ok(Self(envelope))
    }

    /// Whether the envelope uses the legacy `RUTMK001` format (derived with
    /// the library-default Argon2id parameters). A legacy envelope unlocks
    /// normally; the unlock path re-protects it under the current format.
    #[must_use]
    pub fn is_legacy(&self) -> bool {
        self.0[..LEGACY_ENVELOPE_MAGIC.len()] == LEGACY_ENVELOPE_MAGIC
    }

    /// Returns the complete public envelope for durable storage.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; MASTER_KEY_ENVELOPE_LENGTH] {
        &self.0
    }
}

impl fmt::Debug for ProtectedMasterKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProtectedMasterKey([REDACTED])")
    }
}

/// Protects a generated master key with a key derived from the local unlock passphrase.
///
/// The current format (`RUTMK002`) fixes the Argon2id v1.3 parameters of the
/// product password baseline (64 MiB / three passes / one lane — the
/// `rutilus_domain::ARGON2ID_*` constants, so the two derivations cannot
/// drift apart) and authenticates its format marker and random salt as
/// associated data. The passphrase and both key values remain
/// secret-wrapped or zeroized in memory.
///
/// # Errors
///
/// Returns [`MasterKeyProtectionError`] when the passphrase is empty, randomness is
/// unavailable, key derivation fails, or authenticated encryption cannot complete.
pub fn protect_master_key(
    master_key: &MasterKey,
    passphrase: &SecretString,
) -> Result<ProtectedMasterKey, MasterKeyProtectionError> {
    ensure_passphrase(passphrase)?;
    let mut salt = [0_u8; SALT_LENGTH];
    getrandom::fill(&mut salt).map_err(MasterKeyProtectionError::RandomnessUnavailable)?;
    let mut nonce = [0_u8; NONCE_LENGTH];
    getrandom::fill(&mut nonce).map_err(MasterKeyProtectionError::RandomnessUnavailable)?;

    let wrapping_key = derive_wrapping_key(passphrase, &salt)?;
    let cipher = XChaCha20Poly1305::new_from_slice(wrapping_key.as_ref())
        .map_err(|_| MasterKeyProtectionError::InvalidWrappingKeyLength)?;
    let associated_data = associated_data(ENVELOPE_MAGIC, &salt);
    let ciphertext = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: master_key.expose(),
                aad: &associated_data,
            },
        )
        .map_err(|_| MasterKeyProtectionError::EncryptionFailed)?;
    if ciphertext.len() != ENCRYPTED_MASTER_KEY_LENGTH {
        return Err(MasterKeyProtectionError::InvalidEncryptedKeyLength);
    }

    let mut envelope = [0_u8; MASTER_KEY_ENVELOPE_LENGTH];
    envelope[..SALT_OFFSET].copy_from_slice(&ENVELOPE_MAGIC);
    envelope[SALT_OFFSET..NONCE_OFFSET].copy_from_slice(&salt);
    envelope[NONCE_OFFSET..CIPHERTEXT_OFFSET].copy_from_slice(&nonce);
    envelope[CIPHERTEXT_OFFSET..].copy_from_slice(&ciphertext);
    Ok(ProtectedMasterKey(envelope))
}

/// Authenticates and recovers a process-local master key from a persisted envelope.
///
/// # Errors
///
/// Returns [`MasterKeyProtectionError::AuthenticationFailed`] for a wrong passphrase
/// or modified ciphertext. No key bytes are released on failure.
pub fn recover_master_key(
    protected: &ProtectedMasterKey,
    passphrase: &SecretString,
) -> Result<MasterKey, MasterKeyProtectionError> {
    ensure_passphrase(passphrase)?;
    let mut salt = [0_u8; SALT_LENGTH];
    salt.copy_from_slice(&protected.0[SALT_OFFSET..NONCE_OFFSET]);
    let mut nonce = [0_u8; NONCE_LENGTH];
    nonce.copy_from_slice(&protected.0[NONCE_OFFSET..CIPHERTEXT_OFFSET]);

    // A legacy `RUTMK001` envelope was derived with the library-default
    // Argon2id parameters and authenticated the legacy magic; both must be
    // reproduced exactly to unlock it.
    let legacy = protected.is_legacy();
    let wrapping_key = if legacy {
        derive_wrapping_key_v1(passphrase, &salt)?
    } else {
        derive_wrapping_key(passphrase, &salt)?
    };
    let cipher = XChaCha20Poly1305::new_from_slice(wrapping_key.as_ref())
        .map_err(|_| MasterKeyProtectionError::InvalidWrappingKeyLength)?;
    let associated_data = if legacy {
        associated_data(LEGACY_ENVELOPE_MAGIC, &salt)
    } else {
        associated_data(ENVELOPE_MAGIC, &salt)
    };
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &protected.0[CIPHERTEXT_OFFSET..],
                    aad: &associated_data,
                },
            )
            .map_err(|_| MasterKeyProtectionError::AuthenticationFailed)?,
    );
    if plaintext.len() != MASTER_KEY_LENGTH {
        return Err(MasterKeyProtectionError::InvalidEncryptedKeyLength);
    }

    let mut master_key = Box::new([0_u8; MASTER_KEY_LENGTH]);
    master_key.copy_from_slice(&plaintext);
    Ok(MasterKey::from_boxed_bytes(master_key))
}

/// A validated envelope that is safe to persist outside the database.
///
/// The version-one system envelope is the `RUTOSK001` marker followed by the
/// operating-system-protected payload. The payload's protection belongs to the
/// platform's [`SystemKeyProtector`]; the envelope itself only frames and
/// version-marks the persisted bytes.
#[derive(Clone, Eq, PartialEq)]
pub struct SystemProtectedMasterKey(Vec<u8>);

impl SystemProtectedMasterKey {
    /// Validates and copies a persisted envelope.
    ///
    /// # Errors
    ///
    /// Returns [`SystemMasterKeyEnvelopeError::EnvelopeTooShort`] for a
    /// truncated value, [`SystemMasterKeyEnvelopeError::UnsupportedEnvelope`]
    /// for an unknown format or version, and
    /// [`SystemMasterKeyEnvelopeError::EnvelopeTooLong`] for an oversized
    /// payload.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, SystemMasterKeyEnvelopeError> {
        if bytes.len() < SYSTEM_KEY_ENVELOPE_MAGIC_LENGTH {
            return Err(SystemMasterKeyEnvelopeError::EnvelopeTooShort);
        }
        if !bytes.starts_with(&SYSTEM_KEY_ENVELOPE_MAGIC) {
            return Err(SystemMasterKeyEnvelopeError::UnsupportedEnvelope);
        }
        let payload_length = bytes.len() - SYSTEM_KEY_ENVELOPE_MAGIC_LENGTH;
        if payload_length > MAX_SYSTEM_KEY_PAYLOAD_LENGTH {
            return Err(SystemMasterKeyEnvelopeError::EnvelopeTooLong);
        }
        Ok(Self(bytes))
    }

    /// Returns the complete envelope for durable storage.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consumes this value into its persisted bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl fmt::Debug for SystemProtectedMasterKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SystemProtectedMasterKey([REDACTED])")
    }
}

/// Protects a generated master key inside the operating system's secret store.
///
/// The OS-protected payload is framed with the `RUTOSK001` marker; the framed
/// envelope is what the operator persists. The plaintext key never leaves this
/// function's stack.
///
/// # Errors
///
/// Returns [`SystemMasterKeyError::Protect`] when the OS store rejects the
/// plaintext, or [`SystemMasterKeyError::Envelope`] when framing fails.
pub async fn protect_master_key_system<P: SystemKeyProtector>(
    master_key: &MasterKey,
    protector: &P,
) -> Result<SystemProtectedMasterKey, SystemMasterKeyError<P::Error>> {
    let payload = protector
        .protect(master_key.expose())
        .await
        .map_err(SystemMasterKeyError::Protect)?;
    let mut envelope = Vec::with_capacity(SYSTEM_KEY_ENVELOPE_MAGIC_LENGTH + payload.len());
    envelope.extend_from_slice(&SYSTEM_KEY_ENVELOPE_MAGIC);
    envelope.extend_from_slice(&payload);
    SystemProtectedMasterKey::from_bytes(envelope).map_err(SystemMasterKeyError::Envelope)
}

/// Authenticates and recovers a process-local master key from a
/// system-protected envelope.
///
/// # Errors
///
/// Returns [`SystemMasterKeyError::Unprotect`] when the OS store rejects the
/// payload, [`SystemMasterKeyError::Envelope`] for an invalid envelope, or
/// [`SystemMasterKeyError::InvalidKeyLength`] when the recovered bytes are not
/// a master key. No key bytes are released on failure.
pub async fn recover_master_key_system<P: SystemKeyProtector>(
    protected: &SystemProtectedMasterKey,
    protector: &P,
) -> Result<MasterKey, SystemMasterKeyError<P::Error>> {
    let payload = Zeroizing::new(
        protector
            .unprotect(&protected.0[SYSTEM_KEY_ENVELOPE_MAGIC_LENGTH..])
            .await
            .map_err(SystemMasterKeyError::Unprotect)?,
    );
    if payload.len() != MASTER_KEY_LENGTH {
        return Err(SystemMasterKeyError::InvalidKeyLength);
    }
    let mut master_key = Box::new([0_u8; MASTER_KEY_LENGTH]);
    master_key.copy_from_slice(&payload);
    Ok(MasterKey::from_boxed_bytes(master_key))
}

/// The outcome of re-protecting one recovered master key.
#[derive(Clone, Eq, PartialEq)]
pub enum RewrappedMasterKey {
    /// The key is protected by a derived passphrase key.
    Passphrase(ProtectedMasterKey),
    /// The key is protected inside the operating system's secret store.
    System(SystemProtectedMasterKey),
}

impl fmt::Debug for RewrappedMasterKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Passphrase(_) => {
                formatter.write_str("RewrappedMasterKey::Passphrase([REDACTED])")
            }
            Self::System(_) => formatter.write_str("RewrappedMasterKey::System([REDACTED])"),
        }
    }
}

/// Recovers a passphrase-protected master key and re-protects it under
/// [`UnlockSource`] `target`.
///
/// The source is always the passphrase envelope — the one protection that an
/// operator can recover interactively. Re-protecting a legacy `RUTMK001`
/// envelope under [`UnlockSource::Passphrase`] is the format migration: the
/// recovered key is written in the current `RUTMK002` format, so the unlock
/// path migrates a legacy envelope simply by re-wrapping it with the same
/// passphrase. The target's credentials are validated:
/// [`UnlockSource::Passphrase`] requires `target_passphrase` and
/// [`UnlockSource::System`] requires `target_protector`; an extra credential
/// for the other target is ignored.
///
/// # Errors
///
/// Returns [`RewrapError`] when the source passphrase is wrong, a target
/// credential is missing, or either protection step fails. No key bytes are
/// released on failure.
pub async fn rewrap_master_key<P: SystemKeyProtector>(
    protected: &ProtectedMasterKey,
    passphrase: &SecretString,
    target: UnlockSource,
    target_passphrase: Option<&SecretString>,
    target_protector: Option<&P>,
) -> Result<RewrappedMasterKey, RewrapError<P::Error>> {
    let master_key = recover_master_key(protected, passphrase).map_err(RewrapError::Recover)?;
    match target {
        UnlockSource::Passphrase => {
            let target_passphrase =
                target_passphrase.ok_or(RewrapError::MissingTargetPassphrase)?;
            let protected =
                protect_master_key(&master_key, target_passphrase).map_err(RewrapError::Protect)?;
            Ok(RewrappedMasterKey::Passphrase(protected))
        }
        UnlockSource::System => {
            let target_protector = target_protector.ok_or(RewrapError::MissingTargetProtector)?;
            let protected = protect_master_key_system(&master_key, target_protector)
                .await
                .map_err(RewrapError::SystemProtect)?;
            Ok(RewrappedMasterKey::System(protected))
        }
    }
}

fn ensure_passphrase(passphrase: &SecretString) -> Result<(), MasterKeyProtectionError> {
    if passphrase.expose_secret().is_empty() {
        return Err(MasterKeyProtectionError::EmptyPassphrase);
    }
    Ok(())
}

/// Derives the wrapping key for the current `RUTMK002` format: Argon2id
/// v1.3 with the product password baseline's parameters (64 MiB / three
/// passes / one lane), taken from the domain crate's `ARGON2ID_*`
/// constants so the master-key derivation and the password derivation
/// cannot drift apart.
fn derive_wrapping_key(
    passphrase: &SecretString,
    salt: &[u8; SALT_LENGTH],
) -> Result<Zeroizing<[u8; MASTER_KEY_LENGTH]>, MasterKeyProtectionError> {
    let params = Params::new(
        rutilus_domain::ARGON2ID_MEMORY_KIB,
        rutilus_domain::ARGON2ID_TIME_COST,
        rutilus_domain::ARGON2ID_PARALLELISM,
        Some(MASTER_KEY_LENGTH),
    )
    .map_err(MasterKeyProtectionError::KeyDerivation)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut wrapping_key = Zeroizing::new([0_u8; MASTER_KEY_LENGTH]);
    argon2
        .hash_password_into(
            passphrase.expose_secret().as_bytes(),
            salt,
            wrapping_key.as_mut(),
        )
        .map_err(MasterKeyProtectionError::KeyDerivation)?;
    Ok(wrapping_key)
}

/// Derives the wrapping key of the legacy `RUTMK001` format: the Argon2id
/// library defaults (19 MiB / two passes / one lane) the version-one
/// envelope was protected with. Kept only so a persisted legacy envelope
/// still unlocks; the migration re-protects it under the current format.
fn derive_wrapping_key_v1(
    passphrase: &SecretString,
    salt: &[u8; SALT_LENGTH],
) -> Result<Zeroizing<[u8; MASTER_KEY_LENGTH]>, MasterKeyProtectionError> {
    let params = Params::new(
        Params::DEFAULT_M_COST,
        Params::DEFAULT_T_COST,
        Params::DEFAULT_P_COST,
        Some(MASTER_KEY_LENGTH),
    )
    .map_err(MasterKeyProtectionError::KeyDerivation)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut wrapping_key = Zeroizing::new([0_u8; MASTER_KEY_LENGTH]);
    argon2
        .hash_password_into(
            passphrase.expose_secret().as_bytes(),
            salt,
            wrapping_key.as_mut(),
        )
        .map_err(MasterKeyProtectionError::KeyDerivation)?;
    Ok(wrapping_key)
}

fn associated_data(magic: [u8; 8], salt: &[u8; SALT_LENGTH]) -> [u8; SALT_OFFSET + SALT_LENGTH] {
    let mut associated_data = [0_u8; SALT_OFFSET + SALT_LENGTH];
    associated_data[..SALT_OFFSET].copy_from_slice(&magic);
    associated_data[SALT_OFFSET..].copy_from_slice(salt);
    associated_data
}

/// A secret-safe failure while wrapping or recovering the product master key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MasterKeyProtectionError {
    EmptyPassphrase,
    RandomnessUnavailable(getrandom::Error),
    KeyDerivation(argon2::Error),
    InvalidWrappingKeyLength,
    EncryptionFailed,
    InvalidEnvelopeLength,
    UnsupportedEnvelope,
    AuthenticationFailed,
    InvalidEncryptedKeyLength,
}

impl fmt::Display for MasterKeyProtectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPassphrase => formatter.write_str("master-key passphrase cannot be empty"),
            Self::RandomnessUnavailable(_) => {
                formatter.write_str("cryptographic randomness is unavailable")
            }
            Self::KeyDerivation(_) => formatter.write_str("master-key derivation failed"),
            Self::InvalidWrappingKeyLength => {
                formatter.write_str("master-key wrapping key has an invalid length")
            }
            Self::EncryptionFailed => formatter.write_str("master-key encryption failed"),
            Self::InvalidEnvelopeLength => {
                formatter.write_str("master-key envelope has an invalid length")
            }
            Self::UnsupportedEnvelope => {
                formatter.write_str("master-key envelope format or version is unsupported")
            }
            Self::AuthenticationFailed => {
                formatter.write_str("master-key envelope authentication failed")
            }
            Self::InvalidEncryptedKeyLength => {
                formatter.write_str("encrypted master key has an invalid length")
            }
        }
    }
}

impl Error for MasterKeyProtectionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::RandomnessUnavailable(error) => Some(error),
            Self::EmptyPassphrase
            | Self::KeyDerivation(_)
            | Self::InvalidWrappingKeyLength
            | Self::EncryptionFailed
            | Self::InvalidEnvelopeLength
            | Self::UnsupportedEnvelope
            | Self::AuthenticationFailed
            | Self::InvalidEncryptedKeyLength => None,
        }
    }
}

/// A validated-envelope failure of the system-protected master-key format.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SystemMasterKeyEnvelopeError {
    EnvelopeTooShort,
    UnsupportedEnvelope,
    EnvelopeTooLong,
}

impl fmt::Display for SystemMasterKeyEnvelopeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EnvelopeTooShort => {
                formatter.write_str("system-protected master-key envelope is too short")
            }
            Self::UnsupportedEnvelope => formatter
                .write_str("system-protected master-key envelope format or version is unsupported"),
            Self::EnvelopeTooLong => formatter
                .write_str("system-protected master-key envelope payload exceeds the bound"),
        }
    }
}

impl Error for SystemMasterKeyEnvelopeError {}

/// A controlled failure while protecting or recovering a master key through
/// the operating system's secret store.
#[derive(Debug)]
pub enum SystemMasterKeyError<E: Error + Send + Sync + 'static> {
    Protect(E),
    Unprotect(E),
    InvalidKeyLength,
    Envelope(SystemMasterKeyEnvelopeError),
}

impl<E: Error + Send + Sync + 'static> fmt::Display for SystemMasterKeyError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protect(_) => {
                formatter.write_str("operating system rejected the master-key protection")
            }
            Self::Unprotect(_) => {
                formatter.write_str("operating system rejected the master-key recovery")
            }
            Self::InvalidKeyLength => {
                formatter.write_str("operating system recovered an invalid master-key length")
            }
            Self::Envelope(error) => {
                write!(
                    formatter,
                    "invalid system-protected master-key envelope: {error}"
                )
            }
        }
    }
}

impl<E: Error + Send + Sync + 'static> Error for SystemMasterKeyError<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Protect(source) | Self::Unprotect(source) => Some(source),
            Self::Envelope(source) => Some(source),
            Self::InvalidKeyLength => None,
        }
    }
}

/// A controlled failure while re-protecting one master key under a new
/// unlock source.
#[derive(Debug)]
pub enum RewrapError<E: Error + Send + Sync + 'static> {
    Recover(MasterKeyProtectionError),
    Protect(MasterKeyProtectionError),
    SystemProtect(SystemMasterKeyError<E>),
    MissingTargetPassphrase,
    MissingTargetProtector,
}

impl<E: Error + Send + Sync + 'static> fmt::Display for RewrapError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Recover(_) => {
                formatter.write_str("failed to authenticate the master key during re-wrapping")
            }
            Self::Protect(_) => {
                formatter.write_str("failed to protect the master key under the new unlock source")
            }
            Self::SystemProtect(_) => {
                formatter.write_str("operating system rejected the master key during re-wrapping")
            }
            Self::MissingTargetPassphrase => {
                formatter.write_str("re-wrapping to the Passphrase source requires a passphrase")
            }
            Self::MissingTargetProtector => formatter.write_str(
                "re-wrapping to the System source requires an operating-system protector",
            ),
        }
    }
}

impl<E: Error + Send + Sync + 'static> Error for RewrapError<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Recover(source) | Self::Protect(source) => Some(source),
            Self::SystemProtect(source) => Some(source),
            Self::MissingTargetPassphrase | Self::MissingTargetProtector => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use rutilus_domain::{CredentialId, CredentialVersionId};
    use secrecy::{ExposeSecret, SecretString};

    use crate::{decrypt_credential, encrypt_credential};

    use super::*;

    #[test]
    fn round_trips_a_master_key_without_exposing_it() -> Result<(), Box<dyn Error>> {
        let original = MasterKey::from_boxed_bytes(Box::new([0x72; MASTER_KEY_LENGTH]));
        let passphrase: SecretString = String::from("local unlock phrase").into();
        let protected = protect_master_key(&original, &passphrase)?;
        let persisted = protected.as_bytes().to_vec();
        let parsed = ProtectedMasterKey::from_bytes(&persisted)?;
        let recovered = recover_master_key(&parsed, &passphrase)?;
        let credential_id = CredentialId::generate();
        let version_id = CredentialVersionId::generate();
        let secret: SecretString = String::from("credential secret").into();
        let encrypted = encrypt_credential(&original, credential_id, version_id, &secret)?;
        let decrypted = decrypt_credential(&recovered, &encrypted)?;

        assert_eq!(decrypted.expose_secret(), secret.expose_secret());
        assert_eq!(persisted.len(), MASTER_KEY_ENVELOPE_LENGTH);
        assert!(persisted.starts_with(&ENVELOPE_MAGIC));
        assert!(!protected.is_legacy());
        assert_eq!(format!("{original:?}"), "MasterKey([REDACTED])");
        assert_eq!(format!("{protected:?}"), "ProtectedMasterKey([REDACTED])");
        Ok(())
    }

    #[test]
    fn uses_independent_salt_and_nonce_for_each_envelope() -> Result<(), Box<dyn Error>> {
        let master_key = MasterKey::from_boxed_bytes(Box::new([0x73; MASTER_KEY_LENGTH]));
        let passphrase: SecretString = String::from("same local unlock phrase").into();

        let first = protect_master_key(&master_key, &passphrase)?;
        let second = protect_master_key(&master_key, &passphrase)?;

        assert_ne!(first, second);
        Ok(())
    }

    #[test]
    fn rejects_wrong_passphrase_and_tampering_without_leaking_secrets() -> Result<(), Box<dyn Error>>
    {
        let master_key = MasterKey::from_boxed_bytes(Box::new([0x74; MASTER_KEY_LENGTH]));
        let passphrase: SecretString = String::from("correct local unlock phrase").into();
        let wrong_passphrase: SecretString = String::from("incorrect local unlock phrase").into();
        let protected = protect_master_key(&master_key, &passphrase)?;

        let wrong_error = recover_master_key(&protected, &wrong_passphrase)
            .err()
            .ok_or("wrong passphrase unexpectedly recovered the master key")?;
        let mut tampered = protected.as_bytes().to_vec();
        tampered[CIPHERTEXT_OFFSET] ^= 1;
        let tampered = ProtectedMasterKey::from_bytes(&tampered)?;
        let tamper_error = recover_master_key(&tampered, &passphrase)
            .err()
            .ok_or("tampered envelope unexpectedly recovered the master key")?;

        assert_eq!(wrong_error, MasterKeyProtectionError::AuthenticationFailed);
        assert_eq!(tamper_error, MasterKeyProtectionError::AuthenticationFailed);
        assert!(!wrong_error.to_string().contains("incorrect"));
        assert!(!tamper_error.to_string().contains("correct"));
        Ok(())
    }

    #[test]
    fn rejects_empty_passphrase_and_invalid_envelopes() {
        let master_key = MasterKey::from_boxed_bytes(Box::new([0x75; MASTER_KEY_LENGTH]));
        let empty: SecretString = String::new().into();
        assert_eq!(
            protect_master_key(&master_key, &empty),
            Err(MasterKeyProtectionError::EmptyPassphrase)
        );
        assert_eq!(
            ProtectedMasterKey::from_bytes(&[0_u8; MASTER_KEY_ENVELOPE_LENGTH - 1]),
            Err(MasterKeyProtectionError::InvalidEnvelopeLength)
        );
        assert_eq!(
            ProtectedMasterKey::from_bytes(&[0_u8; MASTER_KEY_ENVELOPE_LENGTH]),
            Err(MasterKeyProtectionError::UnsupportedEnvelope)
        );
    }

    /// A deterministic in-memory stand-in for the platform's OS store: the
    /// payload is complemented bitwise, so protect and unprotect are both
    /// invertible and neither fails.
    #[derive(Clone, Copy, Debug)]
    struct ComplementProtector;

    impl SystemKeyProtector for ComplementProtector {
        type Error = std::convert::Infallible;

        async fn protect(&self, plaintext: &[u8]) -> Result<Vec<u8>, Self::Error> {
            Ok(plaintext.iter().map(|byte| !byte).collect())
        }

        async fn unprotect(&self, payload: &[u8]) -> Result<Vec<u8>, Self::Error> {
            Ok(payload.iter().map(|byte| !byte).collect())
        }
    }

    /// A protector that always refuses, exercising the store-failure paths.
    #[derive(Clone, Copy, Debug)]
    struct RefusingProtector;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct RefusingError;

    impl fmt::Display for RefusingError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("test protector refused the operation")
        }
    }

    impl Error for RefusingError {}

    impl SystemKeyProtector for RefusingProtector {
        type Error = RefusingError;

        async fn protect(&self, _plaintext: &[u8]) -> Result<Vec<u8>, Self::Error> {
            Err(RefusingError)
        }

        async fn unprotect(&self, _payload: &[u8]) -> Result<Vec<u8>, Self::Error> {
            Err(RefusingError)
        }
    }

    #[tokio::test]
    async fn system_envelope_round_trips_with_the_os_store() -> Result<(), Box<dyn Error>> {
        let master_key = MasterKey::from_boxed_bytes(Box::new([0x76; MASTER_KEY_LENGTH]));
        let protector = ComplementProtector;

        let protected = protect_master_key_system(&master_key, &protector).await?;
        let persisted = protected.clone().into_bytes();
        assert!(persisted.starts_with(&SYSTEM_KEY_ENVELOPE_MAGIC));
        assert!(
            !persisted
                .windows(MASTER_KEY_LENGTH)
                .any(|window| window == [0x76; MASTER_KEY_LENGTH])
        );
        let parsed = SystemProtectedMasterKey::from_bytes(persisted)?;
        let recovered = recover_master_key_system(&parsed, &protector).await?;
        let credential_id = CredentialId::generate();
        let version_id = CredentialVersionId::generate();
        let secret: SecretString = String::from("system-protected secret").into();
        let encrypted = encrypt_credential(&recovered, credential_id, version_id, &secret)?;
        let decrypted = decrypt_credential(&master_key, &encrypted)?;

        assert_eq!(decrypted.expose_secret(), secret.expose_secret());
        assert_eq!(
            format!("{protected:?}"),
            "SystemProtectedMasterKey([REDACTED])"
        );
        Ok(())
    }

    #[test]
    fn system_envelope_validation_bounds_framing_and_payload() {
        assert_eq!(
            SystemProtectedMasterKey::from_bytes(b"short".to_vec()),
            Err(SystemMasterKeyEnvelopeError::EnvelopeTooShort)
        );
        let wrong_magic = {
            let mut bytes = vec![0_u8; SYSTEM_KEY_ENVELOPE_MAGIC_LENGTH + 32];
            bytes[0] = b'X';
            bytes
        };
        assert_eq!(
            SystemProtectedMasterKey::from_bytes(wrong_magic),
            Err(SystemMasterKeyEnvelopeError::UnsupportedEnvelope)
        );
        let oversized = {
            let mut bytes =
                vec![0_u8; SYSTEM_KEY_ENVELOPE_MAGIC_LENGTH + MAX_SYSTEM_KEY_PAYLOAD_LENGTH + 1];
            bytes[..SYSTEM_KEY_ENVELOPE_MAGIC_LENGTH].copy_from_slice(&SYSTEM_KEY_ENVELOPE_MAGIC);
            bytes
        };
        assert_eq!(
            SystemProtectedMasterKey::from_bytes(oversized),
            Err(SystemMasterKeyEnvelopeError::EnvelopeTooLong)
        );
    }

    #[tokio::test]
    async fn system_store_failures_release_no_master_key() -> Result<(), Box<dyn Error>> {
        let master_key = MasterKey::from_boxed_bytes(Box::new([0x77; MASTER_KEY_LENGTH]));

        assert!(matches!(
            protect_master_key_system(&master_key, &RefusingProtector).await,
            Err(SystemMasterKeyError::Protect(RefusingError))
        ));
        let protected = protect_master_key_system(&master_key, &ComplementProtector).await?;
        assert!(matches!(
            recover_master_key_system(&protected, &RefusingProtector).await,
            Err(SystemMasterKeyError::Unprotect(RefusingError))
        ));
        Ok(())
    }

    #[tokio::test]
    async fn rewrap_moves_a_passphrase_key_to_either_source() -> Result<(), Box<dyn Error>> {
        let master_key = MasterKey::from_boxed_bytes(Box::new([0x78; MASTER_KEY_LENGTH]));
        let passphrase: SecretString = String::from("original local unlock phrase").into();
        let protected = protect_master_key(&master_key, &passphrase)?;

        // Passphrase -> System.
        let rewrapped = rewrap_master_key(
            &protected,
            &passphrase,
            UnlockSource::System,
            None,
            Some(&ComplementProtector),
        )
        .await?;
        let RewrappedMasterKey::System(system) = rewrapped else {
            return Err("expected a system-protected master key".into());
        };
        let recovered = recover_master_key_system(&system, &ComplementProtector).await?;
        let credential_id = CredentialId::generate();
        let version_id = CredentialVersionId::generate();
        let secret: SecretString = String::from("rewrapped secret").into();
        let encrypted = encrypt_credential(&recovered, credential_id, version_id, &secret)?;
        assert_eq!(
            decrypt_credential(&master_key, &encrypted)?.expose_secret(),
            secret.expose_secret()
        );

        // Passphrase -> Passphrase with a fresh passphrase.
        let new_passphrase: SecretString = String::from("replacement local unlock phrase").into();
        let rewrapped = rewrap_master_key(
            &protected,
            &passphrase,
            UnlockSource::Passphrase,
            Some(&new_passphrase),
            Some(&ComplementProtector),
        )
        .await?;
        let RewrappedMasterKey::Passphrase(new_envelope) = rewrapped else {
            return Err("expected a passphrase-protected master key".into());
        };
        let recovered = recover_master_key(&new_envelope, &new_passphrase)?;
        let encrypted = encrypt_credential(&recovered, credential_id, version_id, &secret)?;
        assert_eq!(
            decrypt_credential(&master_key, &encrypted)?.expose_secret(),
            secret.expose_secret()
        );
        Ok(())
    }

    /// Reproduces the legacy version-one envelope format — `RUTMK001`
    /// magic, library-default Argon2id parameters, legacy-magic associated
    /// data — exactly as `protect_master_key` wrote it before the
    /// RUTMK002 bump. Kept in the test module so the migration path is
    /// exercised against a genuine legacy envelope.
    fn protect_master_key_legacy_for_test(
        master_key: &MasterKey,
        passphrase: &SecretString,
    ) -> Result<ProtectedMasterKey, MasterKeyProtectionError> {
        let mut salt = [0_u8; SALT_LENGTH];
        getrandom::fill(&mut salt).map_err(MasterKeyProtectionError::RandomnessUnavailable)?;
        let mut nonce = [0_u8; NONCE_LENGTH];
        getrandom::fill(&mut nonce).map_err(MasterKeyProtectionError::RandomnessUnavailable)?;

        let wrapping_key = derive_wrapping_key_v1(passphrase, &salt)?;
        let cipher = XChaCha20Poly1305::new_from_slice(wrapping_key.as_ref())
            .map_err(|_| MasterKeyProtectionError::InvalidWrappingKeyLength)?;
        let ciphertext = cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: master_key.expose(),
                    aad: &associated_data(LEGACY_ENVELOPE_MAGIC, &salt),
                },
            )
            .map_err(|_| MasterKeyProtectionError::EncryptionFailed)?;

        let mut envelope = [0_u8; MASTER_KEY_ENVELOPE_LENGTH];
        envelope[..SALT_OFFSET].copy_from_slice(&LEGACY_ENVELOPE_MAGIC);
        envelope[SALT_OFFSET..NONCE_OFFSET].copy_from_slice(&salt);
        envelope[NONCE_OFFSET..CIPHERTEXT_OFFSET].copy_from_slice(&nonce);
        envelope[CIPHERTEXT_OFFSET..].copy_from_slice(&ciphertext);
        Ok(ProtectedMasterKey(envelope))
    }

    /// R6-S-11: a legacy `RUTMK001` envelope still unlocks with its
    /// passphrase (and only with it), and re-protecting it under the
    /// `Passphrase` source migrates it to the current `RUTMK002` format —
    /// the unlock path's migration step.
    #[tokio::test]
    async fn legacy_v1_envelope_unlocks_and_rewraps_to_the_current_format()
    -> Result<(), Box<dyn Error>> {
        let master_key = MasterKey::from_boxed_bytes(Box::new([0x7a; MASTER_KEY_LENGTH]));
        let passphrase: SecretString = String::from("legacy local unlock phrase").into();

        let legacy = protect_master_key_legacy_for_test(&master_key, &passphrase)?;
        assert!(legacy.is_legacy());
        assert!(legacy.as_bytes().starts_with(&LEGACY_ENVELOPE_MAGIC));
        // The envelope round-trips through from_bytes like a persisted file.
        let parsed = ProtectedMasterKey::from_bytes(legacy.as_bytes())?;
        assert!(parsed.is_legacy());

        // The legacy envelope unlocks with the same passphrase...
        let recovered = recover_master_key(&legacy, &passphrase)?;
        assert_eq!(recovered.expose(), master_key.expose());
        // ...and only with it: a wrong passphrase still authenticates
        // against the legacy derivation and fails cleanly.
        let wrong: SecretString = String::from("wrong legacy phrase").into();
        let wrong_error = recover_master_key(&legacy, &wrong)
            .err()
            .ok_or("wrong passphrase unexpectedly recovered the legacy master key")?;
        assert_eq!(wrong_error, MasterKeyProtectionError::AuthenticationFailed);

        // Migration: rewrap under the same passphrase re-protects the key
        // in the current format.
        let rewrapped = rewrap_master_key::<ComplementProtector>(
            &legacy,
            &passphrase,
            UnlockSource::Passphrase,
            Some(&passphrase),
            None,
        )
        .await?;
        let RewrappedMasterKey::Passphrase(current) = rewrapped else {
            return Err("expected a passphrase-protected master key".into());
        };
        assert!(!current.is_legacy());
        assert!(current.as_bytes().starts_with(&ENVELOPE_MAGIC));
        let recovered = recover_master_key(&current, &passphrase)?;
        assert_eq!(recovered.expose(), master_key.expose());
        Ok(())
    }

    #[tokio::test]
    async fn rewrap_validates_target_credentials_and_source_passphrase()
    -> Result<(), Box<dyn Error>> {
        let master_key = MasterKey::from_boxed_bytes(Box::new([0x79; MASTER_KEY_LENGTH]));
        let passphrase: SecretString = String::from("correct rewrap unlock phrase").into();
        let wrong: SecretString = String::from("incorrect rewrap unlock phrase").into();
        let protected = protect_master_key(&master_key, &passphrase)?;

        assert!(matches!(
            rewrap_master_key::<ComplementProtector>(
                &protected,
                &passphrase,
                UnlockSource::System,
                None,
                None,
            )
            .await,
            Err(RewrapError::MissingTargetProtector)
        ));
        assert!(matches!(
            rewrap_master_key::<ComplementProtector>(
                &protected,
                &passphrase,
                UnlockSource::Passphrase,
                None,
                None,
            )
            .await,
            Err(RewrapError::MissingTargetPassphrase)
        ));
        assert!(matches!(
            rewrap_master_key(
                &protected,
                &wrong,
                UnlockSource::System,
                None,
                Some(&ComplementProtector),
            )
            .await,
            Err(RewrapError::Recover(
                MasterKeyProtectionError::AuthenticationFailed
            ))
        ));
        Ok(())
    }
}
