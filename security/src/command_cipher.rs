//! XChaCha20-Poly1305 protection of persisted operation command payloads.
//!
//! The `operations.command` and `batch_operations.command` columns persist
//! the typed [`rutilus_domain::RedfishCommand`] payloads, which can carry
//! §10 secrets (the `AccountPassword` of `CreateAccount` and
//! `UpdateAccountPassword`). Like the endpoint credential of §10, the
//! command is never stored in the clear: [`encrypt_command`] produces the
//! whole persisted envelope and [`decrypt_command`] recovers the plaintext,
//! both under the instance master key with the same `XChaCha20-Poly1305`
//! construction the credential protection uses.
//!
//! # The persisted envelope
//!
//! The command column is a single `TEXT` column (unlike the credential
//! version rows, which split nonce and ciphertext across two `BLOB`
//! columns), so the envelope is the version-one marker
//! [`COMMAND_CIPHER_ENVELOPE_PREFIX`] followed by the standard base64 of the
//! 24-byte random nonce concatenated with the authenticated ciphertext:
//!
//! ```text
//! RUTC1:<base64(nonce ‖ ciphertext)>
//! ```
//!
//! The marker both versions the format and lets a reader distinguish an
//! encrypted row from a legacy plaintext row written before at-rest
//! encryption (plain serde JSON always starts with `{`, never with the
//! marker).
//!
//! # Associated data
//!
//! The ciphertext is bound to the 16-byte identity of the persisted row
//! whose command it protects — the operation id for `operations` rows and
//! the batch id for `batch_operations` rows — exactly like the credential
//! ciphertext is bound to its `CredentialId`/`VersionId` pair. The binding
//! makes a ciphertext copied into any other row (or into the other table)
//! fail authentication, and it needs nothing beyond the row the reader is
//! already hydrating.

use std::{error::Error, fmt};

use base64::Engine;
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

use crate::MasterKey;

/// Byte length of every persisted `XChaCha20-Poly1305` command nonce.
pub const COMMAND_NONCE_LENGTH: usize = 24;
/// Version-one marker of the persisted command ciphertext envelope.
pub const COMMAND_CIPHER_ENVELOPE_PREFIX: &str = "RUTC1:";
const AUTHENTICATION_TAG_LENGTH: usize = 16;

/// Encrypts and authenticates one operation command payload.
///
/// The returned string is the complete persisted envelope (see the module
/// documentation): the version-one marker, then the base64 of the fresh
/// random nonce concatenated with the authenticated ciphertext. `identity`
/// is the 16-byte id of the persisted row the command belongs to; it is
/// bound as associated data, so the envelope cannot be moved to another row.
///
/// # Errors
///
/// Returns [`CommandProtectionError::RandomnessUnavailable`] if a unique
/// nonce cannot be generated, or [`CommandProtectionError::EncryptionFailed`]
/// if the authenticated encryption operation fails.
pub fn encrypt_command(
    master_key: &MasterKey,
    identity: [u8; 16],
    plaintext: &SecretString,
) -> Result<String, CommandProtectionError> {
    let mut nonce = [0_u8; COMMAND_NONCE_LENGTH];
    getrandom::fill(&mut nonce).map_err(CommandProtectionError::RandomnessUnavailable)?;

    let cipher = cipher(master_key)?;
    let nonce = XNonce::from(nonce);
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext.expose_secret().as_bytes(),
                aad: &identity,
            },
        )
        .map_err(|_| CommandProtectionError::EncryptionFailed)?;

    let mut payload = Vec::with_capacity(COMMAND_NONCE_LENGTH + ciphertext.len());
    payload.extend_from_slice(nonce.as_slice());
    payload.extend_from_slice(&ciphertext);
    Ok(format!(
        "{COMMAND_CIPHER_ENVELOPE_PREFIX}{}",
        base64::engine::general_purpose::STANDARD.encode(payload)
    ))
}

/// Authenticates and decrypts one persisted operation command envelope.
///
/// `identity` must be the same 16-byte row id the envelope was encrypted
/// for; the plaintext is returned secret-wrapped so it is zeroized on drop.
///
/// # Errors
///
/// Returns [`CommandProtectionError::MalformedEnvelope`] when the value is
/// not a version-one envelope, and
/// [`CommandProtectionError::AuthenticationFailed`] when the ciphertext,
/// nonce, or bound identity does not match. Returns
/// [`CommandProtectionError::InvalidPlaintextEncoding`] if authenticated
/// plaintext is not valid UTF-8. No plaintext is released on failure.
pub fn decrypt_command(
    master_key: &MasterKey,
    identity: [u8; 16],
    envelope: &str,
) -> Result<SecretString, CommandProtectionError> {
    let payload = envelope
        .strip_prefix(COMMAND_CIPHER_ENVELOPE_PREFIX)
        .ok_or(CommandProtectionError::MalformedEnvelope)?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(payload)
        .map_err(|_| CommandProtectionError::MalformedEnvelope)?;
    let nonce = decoded
        .get(..COMMAND_NONCE_LENGTH)
        .ok_or(CommandProtectionError::MalformedEnvelope)?;
    let mut nonce_bytes = [0_u8; COMMAND_NONCE_LENGTH];
    nonce_bytes.copy_from_slice(nonce);
    let ciphertext = &decoded[COMMAND_NONCE_LENGTH..];
    if ciphertext.len() < AUTHENTICATION_TAG_LENGTH {
        return Err(CommandProtectionError::MalformedEnvelope);
    }

    let cipher = cipher(master_key)?;
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                &XNonce::from(nonce_bytes),
                Payload {
                    msg: ciphertext,
                    aad: &identity,
                },
            )
            .map_err(|_| CommandProtectionError::AuthenticationFailed)?,
    );
    let plaintext = std::str::from_utf8(&plaintext)
        .map_err(|_| CommandProtectionError::InvalidPlaintextEncoding)?;

    Ok(plaintext.to_owned().into())
}

fn cipher(master_key: &MasterKey) -> Result<XChaCha20Poly1305, CommandProtectionError> {
    XChaCha20Poly1305::new_from_slice(master_key.expose())
        .map_err(|_| CommandProtectionError::InvalidMasterKeyLength)
}

/// A controlled failure while protecting or recovering one command payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandProtectionError {
    /// The operating system did not provide cryptographically secure randomness.
    RandomnessUnavailable(getrandom::Error),
    /// Authenticated encryption could not produce ciphertext.
    EncryptionFailed,
    /// The supplied master key is not the algorithm's required length.
    InvalidMasterKeyLength,
    /// The persisted value is not a version-one command ciphertext envelope.
    MalformedEnvelope,
    /// Ciphertext authentication failed; no plaintext was released.
    AuthenticationFailed,
    /// Authenticated plaintext is not valid product command data.
    InvalidPlaintextEncoding,
}

impl fmt::Display for CommandProtectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RandomnessUnavailable(_) => {
                formatter.write_str("cryptographic randomness is unavailable")
            }
            Self::EncryptionFailed => formatter.write_str("command encryption failed"),
            Self::InvalidMasterKeyLength => {
                formatter.write_str("command master key has an invalid length")
            }
            Self::MalformedEnvelope => {
                formatter.write_str("command ciphertext is not a version-one envelope")
            }
            Self::AuthenticationFailed => {
                formatter.write_str("command ciphertext authentication failed")
            }
            Self::InvalidPlaintextEncoding => {
                formatter.write_str("command plaintext is not valid UTF-8")
            }
        }
    }
}

impl Error for CommandProtectionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::RandomnessUnavailable(error) => Some(error),
            Self::EncryptionFailed
            | Self::InvalidMasterKeyLength
            | Self::MalformedEnvelope
            | Self::AuthenticationFailed
            | Self::InvalidPlaintextEncoding => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use secrecy::{ExposeSecret, SecretString};

    use super::{
        COMMAND_CIPHER_ENVELOPE_PREFIX, CommandProtectionError, MasterKey, decrypt_command,
        encrypt_command,
    };

    fn test_key() -> MasterKey {
        MasterKey::from_boxed_bytes(Box::new([0x5a; 32]))
    }

    fn wrong_key() -> MasterKey {
        MasterKey::from_boxed_bytes(Box::new([0x6a; 32]))
    }

    fn identity() -> [u8; 16] {
        [0x42; 16]
    }

    #[test]
    fn encrypts_and_decrypts_bound_to_the_row_identity() -> Result<(), CommandProtectionError> {
        let plaintext: SecretString = r#"{"Account":{"CreateAccount":{"user_name":"jane","password":"correct horse battery staple","role_id":"Operator"}}}"#
            .to_owned()
            .into();

        let envelope = encrypt_command(&test_key(), identity(), &plaintext)?;
        let decrypted = decrypt_command(&test_key(), identity(), &envelope)?;

        assert!(
            envelope.starts_with(COMMAND_CIPHER_ENVELOPE_PREFIX),
            "the envelope must carry the version-one marker"
        );
        assert!(!envelope.contains("correct horse battery staple"));
        assert_eq!(decrypted.expose_secret(), plaintext.expose_secret());
        Ok(())
    }

    #[test]
    fn uses_an_independent_nonce_for_each_encryption() -> Result<(), CommandProtectionError> {
        let plaintext: SecretString = "same input".to_owned().into();

        let first = encrypt_command(&test_key(), identity(), &plaintext)?;
        let second = encrypt_command(&test_key(), identity(), &plaintext)?;

        assert_ne!(first, second, "each envelope must carry a fresh nonce");
        Ok(())
    }

    #[test]
    fn rejects_a_different_row_identity() -> Result<(), CommandProtectionError> {
        let plaintext: SecretString = "bound secret".to_owned().into();
        let envelope = encrypt_command(&test_key(), identity(), &plaintext)?;

        let mut other_identity = identity();
        other_identity[0] ^= 1;
        assert!(matches!(
            decrypt_command(&test_key(), other_identity, &envelope),
            Err(CommandProtectionError::AuthenticationFailed)
        ));
        Ok(())
    }

    #[test]
    fn rejects_a_different_master_key() -> Result<(), CommandProtectionError> {
        let plaintext: SecretString = "bound secret".to_owned().into();
        let envelope = encrypt_command(&test_key(), identity(), &plaintext)?;

        assert!(matches!(
            decrypt_command(&wrong_key(), identity(), &envelope),
            Err(CommandProtectionError::AuthenticationFailed)
        ));
        Ok(())
    }

    #[test]
    fn rejects_tampered_ciphertext() -> Result<(), CommandProtectionError> {
        let plaintext: SecretString = "unaltered".to_owned().into();
        let envelope = encrypt_command(&test_key(), identity(), &plaintext)?;
        // Flip one base64 character inside the ciphertext region (the first
        // payload character after the 32-character nonce encoding).
        let mut bytes = envelope.into_bytes();
        let payload_offset = COMMAND_CIPHER_ENVELOPE_PREFIX.len() + 32;
        bytes[payload_offset] = if bytes[payload_offset] == b'A' {
            b'B'
        } else {
            b'A'
        };
        let tampered =
            String::from_utf8(bytes).map_err(|_| CommandProtectionError::MalformedEnvelope)?;

        assert!(matches!(
            decrypt_command(&test_key(), identity(), &tampered),
            Err(CommandProtectionError::AuthenticationFailed)
        ));
        Ok(())
    }

    #[test]
    fn rejects_values_that_are_not_version_one_envelopes() {
        let key = test_key();
        assert!(matches!(
            decrypt_command(&key, identity(), r#"{"System":"PowerCycle"}"#),
            Err(CommandProtectionError::MalformedEnvelope)
        ));
        assert!(matches!(
            decrypt_command(&key, identity(), "RUTC1:not-base64!!"),
            Err(CommandProtectionError::MalformedEnvelope)
        ));
        // A decoded payload shorter than the nonce is not an envelope.
        assert!(matches!(
            decrypt_command(&key, identity(), "RUTC1:c2hvcnQ="),
            Err(CommandProtectionError::MalformedEnvelope)
        ));
    }

    #[test]
    fn unknown_envelope_versions_are_refused_not_misread() -> Result<(), CommandProtectionError> {
        let plaintext: SecretString = "future format".to_owned().into();
        let envelope = encrypt_command(&test_key(), identity(), &plaintext)?;
        let future = format!(
            "RUTC2:{}",
            &envelope[COMMAND_CIPHER_ENVELOPE_PREFIX.len()..]
        );

        assert!(matches!(
            decrypt_command(&test_key(), identity(), &future),
            Err(CommandProtectionError::MalformedEnvelope)
        ));
        Ok(())
    }
}
