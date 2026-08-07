#![forbid(unsafe_code)]

use std::{error::Error, fmt};

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use rutilus_domain::{CredentialId, CredentialVersionId};
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

mod backup_package;
mod binding_code;
mod bootstrap_code;
mod master_key;
mod password_hash;
mod session_token;
mod totp;

pub use backup_package::{
    BACKUP_PACKAGE_FORMAT_VERSION, BACKUP_PACKAGE_MAGIC, BackupEntry, BackupEntryKind,
    BackupPackageError, DecryptedBackup, DecryptedEntry, MAX_ENTRIES, MAX_ENTRY_NAME_LENGTH,
    MAX_MANIFEST_LENGTH, create_backup_package, open_backup_package,
};
pub use binding_code::{BindingCodeError, generate_binding_code};
pub use bootstrap_code::{
    BOOTSTRAP_CODE_CHARACTERS, BootstrapCodeError, generate_bootstrap_code, hash_bootstrap_code,
};
pub use master_key::{
    MASTER_KEY_ENVELOPE_LENGTH, MAX_SYSTEM_KEY_PAYLOAD_LENGTH, MasterKey, MasterKeyProtectionError,
    ProtectedMasterKey, RewrapError, RewrappedMasterKey, SYSTEM_KEY_ENVELOPE_MAGIC,
    SystemKeyProtector, SystemMasterKeyEnvelopeError, SystemMasterKeyError,
    SystemProtectedMasterKey, UnlockSource, protect_master_key, protect_master_key_system,
    recover_master_key, recover_master_key_system, rewrap_master_key,
};
pub use password_hash::{PasswordHashError, hash_password, verify_password};
pub use session_token::{CsrfToken, SessionToken, SessionTokenError, TOKEN_LENGTH};
pub use totp::{TotpSecretError, TotpUriError, generate_totp_secret, totp_uri, verify_code};

/// Byte length of every persisted `XChaCha20-Poly1305` credential nonce.
pub const CREDENTIAL_NONCE_LENGTH: usize = 24;
const AUTHENTICATION_TAG_LENGTH: usize = 16;

/// Persistable authenticated ciphertext for one credential version.
#[derive(Clone, Eq, PartialEq)]
struct EncryptedCredential {
    nonce: [u8; CREDENTIAL_NONCE_LENGTH],
    ciphertext: Vec<u8>,
}

impl EncryptedCredential {
    /// Reconstructs validated encrypted credential data read from persistence.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialProtectionError::CiphertextTooShort`] when the ciphertext
    /// cannot contain an authentication tag.
    pub fn from_parts(
        nonce: [u8; CREDENTIAL_NONCE_LENGTH],
        ciphertext: Vec<u8>,
    ) -> Result<Self, CredentialProtectionError> {
        if ciphertext.len() < AUTHENTICATION_TAG_LENGTH {
            return Err(CredentialProtectionError::CiphertextTooShort);
        }

        Ok(Self { nonce, ciphertext })
    }

    /// Returns the public, per-message nonce.
    #[must_use]
    pub const fn nonce(&self) -> &[u8; CREDENTIAL_NONCE_LENGTH] {
        &self.nonce
    }

    /// Returns the authenticated ciphertext and its appended tag.
    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Consumes this value into persistence-ready parts.
    #[must_use]
    pub fn into_parts(self) -> ([u8; CREDENTIAL_NONCE_LENGTH], Vec<u8>) {
        (self.nonce, self.ciphertext)
    }
}

impl fmt::Debug for EncryptedCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncryptedCredential")
            .field("nonce", &"[REDACTED]")
            .field("ciphertext", &"[REDACTED]")
            .finish()
    }
}

/// Authenticated credential ciphertext bound to its typed persistence identity.
#[derive(Clone, Eq, PartialEq)]
pub struct ProtectedCredentialVersion {
    credential_id: CredentialId,
    version_id: CredentialVersionId,
    encrypted: EncryptedCredential,
}

impl ProtectedCredentialVersion {
    /// Reconstructs a protected version from identity and persistence-ready parts.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialProtectionError::CiphertextTooShort`] when the
    /// ciphertext cannot contain an authentication tag.
    pub fn from_parts(
        credential_id: CredentialId,
        version_id: CredentialVersionId,
        nonce: [u8; CREDENTIAL_NONCE_LENGTH],
        ciphertext: Vec<u8>,
    ) -> Result<Self, CredentialProtectionError> {
        Ok(Self {
            credential_id,
            version_id,
            encrypted: EncryptedCredential::from_parts(nonce, ciphertext)?,
        })
    }

    #[must_use]
    pub const fn credential_id(&self) -> CredentialId {
        self.credential_id
    }

    #[must_use]
    pub const fn version_id(&self) -> CredentialVersionId {
        self.version_id
    }

    #[must_use]
    pub const fn nonce(&self) -> &[u8; CREDENTIAL_NONCE_LENGTH] {
        self.encrypted.nonce()
    }

    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        self.encrypted.ciphertext()
    }

    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        CredentialId,
        CredentialVersionId,
        [u8; CREDENTIAL_NONCE_LENGTH],
        Vec<u8>,
    ) {
        let (nonce, ciphertext) = self.encrypted.into_parts();
        (self.credential_id, self.version_id, nonce, ciphertext)
    }
}

impl fmt::Debug for ProtectedCredentialVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtectedCredentialVersion")
            .field("credential_id", &self.credential_id)
            .field("version_id", &self.version_id)
            .field("encrypted", &self.encrypted)
            .finish()
    }
}

/// Encrypts and authenticates one credential version.
///
/// # Errors
///
/// Returns [`CredentialProtectionError::RandomnessUnavailable`] if a unique nonce
/// cannot be generated, or [`CredentialProtectionError::EncryptionFailed`] if the
/// authenticated encryption operation fails.
pub fn encrypt_credential(
    master_key: &MasterKey,
    credential_id: CredentialId,
    version_id: CredentialVersionId,
    plaintext: &SecretString,
) -> Result<ProtectedCredentialVersion, CredentialProtectionError> {
    let mut nonce = [0_u8; CREDENTIAL_NONCE_LENGTH];
    getrandom::fill(&mut nonce).map_err(CredentialProtectionError::RandomnessUnavailable)?;

    let cipher = cipher(master_key)?;
    let associated_data = associated_data(credential_id, version_id);
    let nonce = XNonce::from(nonce);
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext.expose_secret().as_bytes(),
                aad: &associated_data,
            },
        )
        .map_err(|_| CredentialProtectionError::EncryptionFailed)?;

    ProtectedCredentialVersion::from_parts(credential_id, version_id, nonce.into(), ciphertext)
}

/// Authenticates and decrypts one credential version.
///
/// # Errors
///
/// Returns [`CredentialProtectionError::AuthenticationFailed`] if the ciphertext,
/// nonce, credential identity, or version identity does not match. Returns
/// [`CredentialProtectionError::InvalidPlaintextEncoding`] if authenticated plaintext
/// is not valid UTF-8.
pub fn decrypt_credential(
    master_key: &MasterKey,
    protected: &ProtectedCredentialVersion,
) -> Result<SecretString, CredentialProtectionError> {
    let cipher = cipher(master_key)?;
    let associated_data = associated_data(protected.credential_id, protected.version_id);
    let nonce = XNonce::from(*protected.encrypted.nonce());
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: protected.encrypted.ciphertext(),
                    aad: &associated_data,
                },
            )
            .map_err(|_| CredentialProtectionError::AuthenticationFailed)?,
    );
    let plaintext = std::str::from_utf8(&plaintext)
        .map_err(|_| CredentialProtectionError::InvalidPlaintextEncoding)?;

    Ok(plaintext.to_owned().into())
}

fn cipher(master_key: &MasterKey) -> Result<XChaCha20Poly1305, CredentialProtectionError> {
    XChaCha20Poly1305::new_from_slice(master_key.expose())
        .map_err(|_| CredentialProtectionError::InvalidMasterKeyLength)
}

fn associated_data(credential_id: CredentialId, version_id: CredentialVersionId) -> [u8; 32] {
    let mut associated_data = [0_u8; 32];
    associated_data[..16].copy_from_slice(credential_id.into_uuid().as_bytes());
    associated_data[16..].copy_from_slice(version_id.into_uuid().as_bytes());
    associated_data
}

/// A controlled failure while protecting or recovering credential data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialProtectionError {
    /// The operating system did not provide cryptographically secure randomness.
    RandomnessUnavailable(getrandom::Error),
    /// Authenticated encryption could not produce ciphertext.
    EncryptionFailed,
    /// The supplied master key is not the algorithm's required length.
    InvalidMasterKeyLength,
    /// Ciphertext authentication failed; no plaintext was released.
    AuthenticationFailed,
    /// Persisted ciphertext is too short to contain an authentication tag.
    CiphertextTooShort,
    /// Authenticated plaintext is not a valid product credential string.
    InvalidPlaintextEncoding,
}

impl fmt::Display for CredentialProtectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RandomnessUnavailable(_) => {
                formatter.write_str("cryptographic randomness is unavailable")
            }
            Self::EncryptionFailed => formatter.write_str("credential encryption failed"),
            Self::InvalidMasterKeyLength => {
                formatter.write_str("credential master key has an invalid length")
            }
            Self::AuthenticationFailed => {
                formatter.write_str("credential ciphertext authentication failed")
            }
            Self::CiphertextTooShort => formatter.write_str("credential ciphertext is too short"),
            Self::InvalidPlaintextEncoding => {
                formatter.write_str("credential plaintext is not valid UTF-8")
            }
        }
    }
}

impl Error for CredentialProtectionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::RandomnessUnavailable(error) => Some(error),
            Self::EncryptionFailed
            | Self::InvalidMasterKeyLength
            | Self::AuthenticationFailed
            | Self::CiphertextTooShort
            | Self::InvalidPlaintextEncoding => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use rutilus_domain::{CredentialId, CredentialVersionId};
    use secrecy::{ExposeSecret, SecretString};

    use super::{
        CredentialProtectionError, MasterKey, ProtectedCredentialVersion, decrypt_credential,
        encrypt_credential,
    };

    fn test_key() -> MasterKey {
        MasterKey::from_boxed_bytes(Box::new([0x5a; 32]))
    }

    #[test]
    fn encrypts_and_decrypts_with_bound_identity() -> Result<(), CredentialProtectionError> {
        let key = test_key();
        let credential_id = CredentialId::generate();
        let version_id = CredentialVersionId::generate();
        let plaintext: SecretString = "correct horse battery staple".to_owned().into();

        let encrypted = encrypt_credential(&key, credential_id, version_id, &plaintext)?;
        let decrypted = decrypt_credential(&key, &encrypted)?;

        assert_eq!(encrypted.credential_id(), credential_id);
        assert_eq!(encrypted.version_id(), version_id);
        assert_ne!(encrypted.ciphertext(), plaintext.expose_secret().as_bytes());
        assert_eq!(decrypted.expose_secret(), plaintext.expose_secret());
        Ok(())
    }

    #[test]
    fn uses_an_independent_nonce_for_each_encryption() -> Result<(), CredentialProtectionError> {
        let key = test_key();
        let credential_id = CredentialId::generate();
        let version_id = CredentialVersionId::generate();
        let plaintext: SecretString = "same input".to_owned().into();

        let first = encrypt_credential(&key, credential_id, version_id, &plaintext)?;
        let second = encrypt_credential(&key, credential_id, version_id, &plaintext)?;

        assert_ne!(first.nonce(), second.nonce());
        assert_ne!(first.ciphertext(), second.ciphertext());
        Ok(())
    }

    #[test]
    fn rejects_a_different_credential_or_version() -> Result<(), CredentialProtectionError> {
        let key = test_key();
        let credential_id = CredentialId::generate();
        let version_id = CredentialVersionId::generate();
        let plaintext: SecretString = "bound secret".to_owned().into();
        let encrypted = encrypt_credential(&key, credential_id, version_id, &plaintext)?;
        let (_, _, nonce, ciphertext) = encrypted.clone().into_parts();
        let rebound_credential = ProtectedCredentialVersion::from_parts(
            CredentialId::generate(),
            version_id,
            nonce,
            ciphertext.clone(),
        )?;
        let rebound_version = ProtectedCredentialVersion::from_parts(
            credential_id,
            CredentialVersionId::generate(),
            nonce,
            ciphertext,
        )?;

        assert!(matches!(
            decrypt_credential(&key, &rebound_credential),
            Err(CredentialProtectionError::AuthenticationFailed)
        ));
        assert!(matches!(
            decrypt_credential(&key, &rebound_version),
            Err(CredentialProtectionError::AuthenticationFailed)
        ));
        Ok(())
    }

    #[test]
    fn rejects_tampered_ciphertext() -> Result<(), CredentialProtectionError> {
        let key = test_key();
        let credential_id = CredentialId::generate();
        let version_id = CredentialVersionId::generate();
        let plaintext: SecretString = "unaltered".to_owned().into();
        let encrypted = encrypt_credential(&key, credential_id, version_id, &plaintext)?;
        let (credential_id, version_id, nonce, mut ciphertext) = encrypted.into_parts();
        ciphertext[0] ^= 1;
        let tampered =
            ProtectedCredentialVersion::from_parts(credential_id, version_id, nonce, ciphertext)?;

        assert!(matches!(
            decrypt_credential(&key, &tampered),
            Err(CredentialProtectionError::AuthenticationFailed)
        ));
        Ok(())
    }

    #[test]
    fn debug_output_is_redacted() -> Result<(), CredentialProtectionError> {
        let key = test_key();
        let plaintext: SecretString = "never log this".to_owned().into();
        let encrypted = encrypt_credential(
            &key,
            CredentialId::generate(),
            CredentialVersionId::generate(),
            &plaintext,
        )?;

        assert_eq!(format!("{key:?}"), "MasterKey([REDACTED])");
        assert_eq!(
            format!("{encrypted:?}"),
            format!(
                "ProtectedCredentialVersion {{ credential_id: {:?}, version_id: {:?}, encrypted: EncryptedCredential {{ nonce: \"[REDACTED]\", ciphertext: \"[REDACTED]\" }} }}",
                encrypted.credential_id(),
                encrypted.version_id()
            )
        );
        assert!(!format!("{plaintext:?}").contains("never log this"));
        Ok(())
    }
}
