use std::{error::Error, fmt};

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use secrecy::{ExposeSecret, SecretBox, SecretString};
use zeroize::Zeroizing;

const MASTER_KEY_LENGTH: usize = 32;
const ENVELOPE_MAGIC: [u8; 8] = *b"RUTMK001";
const SALT_LENGTH: usize = 16;
const NONCE_LENGTH: usize = 24;
const AUTHENTICATION_TAG_LENGTH: usize = 16;
const ENCRYPTED_MASTER_KEY_LENGTH: usize = MASTER_KEY_LENGTH + AUTHENTICATION_TAG_LENGTH;
const SALT_OFFSET: usize = ENVELOPE_MAGIC.len();
const NONCE_OFFSET: usize = SALT_OFFSET + SALT_LENGTH;
const CIPHERTEXT_OFFSET: usize = NONCE_OFFSET + NONCE_LENGTH;
/// Exact byte length of the version-one passphrase-protected master-key envelope.
pub const MASTER_KEY_ENVELOPE_LENGTH: usize = CIPHERTEXT_OFFSET + ENCRYPTED_MASTER_KEY_LENGTH;

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
    /// Validates and copies a persisted envelope.
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
        if !bytes.starts_with(&ENVELOPE_MAGIC) {
            return Err(MasterKeyProtectionError::UnsupportedEnvelope);
        }

        let mut envelope = [0_u8; MASTER_KEY_ENVELOPE_LENGTH];
        envelope.copy_from_slice(bytes);
        Ok(Self(envelope))
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
/// The version-one format fixes Argon2id v1.3 parameters and authenticates its format
/// marker and random salt as associated data. The passphrase and both key values remain
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
    let associated_data = associated_data(&salt);
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

    let wrapping_key = derive_wrapping_key(passphrase, &salt)?;
    let cipher = XChaCha20Poly1305::new_from_slice(wrapping_key.as_ref())
        .map_err(|_| MasterKeyProtectionError::InvalidWrappingKeyLength)?;
    let associated_data = associated_data(&salt);
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

fn ensure_passphrase(passphrase: &SecretString) -> Result<(), MasterKeyProtectionError> {
    if passphrase.expose_secret().is_empty() {
        return Err(MasterKeyProtectionError::EmptyPassphrase);
    }
    Ok(())
}

fn derive_wrapping_key(
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

fn associated_data(salt: &[u8; SALT_LENGTH]) -> [u8; SALT_OFFSET + SALT_LENGTH] {
    let mut associated_data = [0_u8; SALT_OFFSET + SALT_LENGTH];
    associated_data[..SALT_OFFSET].copy_from_slice(&ENVELOPE_MAGIC);
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
}
