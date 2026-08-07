//! Local password credentials for product principals (§16.1, §16.2).
//!
//! Passwords are protected with Argon2id (design §16.2: "密码使用 Argon2id").
//! The persisted credential splits the derivation inputs into their own
//! columns — `salt` and `hash` — with a `hash_format` code column naming the
//! algorithm and parameters (the persistence CHECK pins it to `argon2id-1`),
//! so a future format change is a migration concern, not a column rewrite.
//!
//! The `Argon2IdHash` value object carries the salt and the derived hash and
//! is the only judge of whether a presented password matches: verification
//! re-derives the hash with the stored salt and compares the two 32-byte
//! digests without short-circuiting, so a wrong password at the right length
//! costs the same as the right one (see [`Argon2IdHash::verify`]). The
//! derivation parameters are pinned constants of the value object, so a hash
//! can never be re-derived under different parameters than it was created
//! with. Hash *creation* (generating a fresh salt and deriving) is the
//! security crate's job — this module only verifies, exactly like the TOTP
//! module only verifies codes against a secret it never generates.

use std::{error::Error, fmt};

use argon2::{Algorithm, Argon2, Params, Version};
use secrecy::{ExposeSecret, SecretString};
use time::OffsetDateTime;

use crate::PrincipalId;

/// The stable persistence code for the version-one Argon2id credential format.
///
/// `argon2id-1` means: Argon2id v1.3 with [`ARGON2ID_MEMORY_KIB`] memory,
/// [`ARGON2ID_TIME_COST`] iterations, [`ARGON2ID_PARALLELISM`] lanes, a
/// [`ARGON2ID_SALT_LENGTH`]-byte random salt, and a
/// [`ARGON2ID_HASH_LENGTH`]-byte derived hash. The `password_credentials`
/// CHECK constraint pins the column to exactly this code, so a persisted row
/// never silently changes meaning.
pub const ARGON2ID_FORMAT: &str = "argon2id-1";

/// Argon2id memory cost in kibibytes: 64 MiB (design §16.2 baseline).
pub const ARGON2ID_MEMORY_KIB: u32 = 65_536;
/// Argon2id time cost: three passes over the memory.
pub const ARGON2ID_TIME_COST: u32 = 3;
/// Argon2id parallelism: one lane.
pub const ARGON2ID_PARALLELISM: u32 = 1;
/// Byte length of the random per-password salt.
pub const ARGON2ID_SALT_LENGTH: usize = 16;
/// Byte length of the derived hash.
pub const ARGON2ID_HASH_LENGTH: usize = 32;

/// An immutable Argon2id hash with the salt it was derived from.
///
/// The value is the persisted credential material split into its two columns:
/// `salt` and `hash` (the `password_credentials.hash_format` column pins the
/// interpretation to `argon2id-1`). The struct is the only place the format's
/// byte lengths are enforced — a stored row whose columns do not match the
/// format is refused on rehydration instead of being half-understood.
#[derive(Clone, Eq, PartialEq)]
pub struct Argon2IdHash {
    salt: [u8; ARGON2ID_SALT_LENGTH],
    hash: [u8; ARGON2ID_HASH_LENGTH],
}

impl Argon2IdHash {
    /// Builds a hash value from exactly sized persistence parts.
    ///
    /// # Errors
    ///
    /// Returns [`PasswordCredentialError::InvalidHashParts`] when the salt or
    /// hash byte slices do not match the `argon2id-1` format lengths.
    pub fn from_parts(salt: &[u8], hash: &[u8]) -> Result<Self, PasswordCredentialError> {
        if salt.len() != ARGON2ID_SALT_LENGTH || hash.len() != ARGON2ID_HASH_LENGTH {
            return Err(PasswordCredentialError::InvalidHashParts);
        }
        let mut salt_bytes = [0_u8; ARGON2ID_SALT_LENGTH];
        salt_bytes.copy_from_slice(salt);
        let mut hash_bytes = [0_u8; ARGON2ID_HASH_LENGTH];
        hash_bytes.copy_from_slice(hash);
        Ok(Self {
            salt: salt_bytes,
            hash: hash_bytes,
        })
    }

    /// Returns the per-password salt for persistence.
    #[must_use]
    pub const fn salt(&self) -> &[u8; ARGON2ID_SALT_LENGTH] {
        &self.salt
    }

    /// Returns the derived hash for persistence.
    #[must_use]
    pub const fn hash(&self) -> &[u8; ARGON2ID_HASH_LENGTH] {
        &self.hash
    }

    /// Verifies a presented password in constant time.
    ///
    /// The candidate hash is re-derived with this value's salt under the
    /// pinned `argon2id-1` parameters — never under parameters read from the
    /// caller — and compared against the stored hash with a comparison that
    /// never short-circuits. A wrong password therefore costs the same work
    /// as the right one, and the returned `bool` is the only information
    /// released.
    #[must_use]
    pub fn verify(&self, password: &SecretString) -> bool {
        let Ok(params) = params() else {
            return false;
        };
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut candidate = [0_u8; ARGON2ID_HASH_LENGTH];
        if argon2
            .hash_password_into(
                password.expose_secret().as_bytes(),
                &self.salt,
                &mut candidate,
            )
            .is_err()
        {
            return false;
        }
        constant_time_eq(&candidate, &self.hash)
    }
}

impl fmt::Debug for Argon2IdHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Argon2IdHash")
            .field("salt", &"[REDACTED]")
            .field("hash", &"[REDACTED]")
            .finish()
    }
}

/// One local password credential bound to its principal (§16.1).
///
/// The principal's password is a single-row value object: the
/// `password_credentials.principal_id` primary key means a principal has at
/// most one password, and changing it writes a fresh row (a new salt and
/// hash under `argon2id-1`), never an in-place derivation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PasswordCredential {
    principal_id: PrincipalId,
    hash: Argon2IdHash,
    changed_at: OffsetDateTime,
}

impl PasswordCredential {
    /// Builds a credential for a principal from persisted parts.
    ///
    /// # Errors
    ///
    /// Returns [`PasswordCredentialError::InvalidHashParts`] when the stored
    /// salt or hash columns do not match the `argon2id-1` format lengths.
    pub fn try_from_parts(
        principal_id: PrincipalId,
        hash: Argon2IdHash,
        changed_at: OffsetDateTime,
    ) -> Result<Self, PasswordCredentialError> {
        Ok(Self {
            principal_id,
            hash,
            changed_at,
        })
    }

    #[must_use]
    pub const fn principal_id(&self) -> PrincipalId {
        self.principal_id
    }

    #[must_use]
    pub const fn hash(&self) -> &Argon2IdHash {
        &self.hash
    }

    #[must_use]
    pub const fn changed_at(&self) -> OffsetDateTime {
        self.changed_at
    }
}

/// Why a password credential cannot be built from persisted parts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PasswordCredentialError {
    /// The stored salt or hash does not match the `argon2id-1` format.
    InvalidHashParts,
}

impl fmt::Display for PasswordCredentialError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidHashParts => formatter
                .write_str("password credential salt or hash does not match the argon2id-1 format"),
        }
    }
}

impl Error for PasswordCredentialError {}

fn params() -> Result<Params, argon2::Error> {
    Params::new(
        ARGON2ID_MEMORY_KIB,
        ARGON2ID_TIME_COST,
        ARGON2ID_PARALLELISM,
        Some(ARGON2ID_HASH_LENGTH),
    )
}

/// Compares two fixed-length digests without short-circuiting.
///
/// A single `|` accumulates every differing byte into one value that is
/// tested only at the end, so the loop runs the same number of iterations and
/// the same operations for any input pair. This is the comparison `subtle`
/// implements with volatile reads; without `unsafe` the fold is the auditable
/// equivalent, and the workspace forbids the unsafe path.
#[must_use]
pub(crate) fn constant_time_eq(left: &[u8; 32], right: &[u8; 32]) -> bool {
    let mut difference = 0_u8;
    for (a, b) in left.iter().zip(right) {
        difference |= a ^ b;
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use secrecy::SecretString;

    use super::*;

    #[test]
    fn hash_verification_accepts_the_matching_password() -> Result<(), Box<dyn Error>> {
        let hash = hash_of("correct horse battery staple")?;
        let password: SecretString = "correct horse battery staple".to_owned().into();

        assert!(hash.verify(&password));
        Ok(())
    }

    #[test]
    fn hash_verification_rejects_a_different_password() -> Result<(), Box<dyn Error>> {
        let hash = hash_of("correct horse battery staple")?;
        let wrong: SecretString = "incorrect horse battery staple".to_owned().into();

        assert!(!hash.verify(&wrong));
        let wrong_length: SecretString = "wrong".to_owned().into();
        assert!(!hash.verify(&wrong_length));
        Ok(())
    }

    #[test]
    fn hash_parts_are_length_checked_and_redacted() -> Result<(), Box<dyn Error>> {
        let salt = [0x11_u8; ARGON2ID_SALT_LENGTH];
        let hash = [0x22_u8; ARGON2ID_HASH_LENGTH];
        let value = Argon2IdHash::from_parts(&salt, &hash)?;

        assert_eq!(value.salt(), &salt);
        assert_eq!(value.hash(), &hash);
        assert_eq!(
            Argon2IdHash::from_parts(&salt[..5], &hash),
            Err(PasswordCredentialError::InvalidHashParts)
        );
        assert_eq!(
            Argon2IdHash::from_parts(&salt, &hash[..7]),
            Err(PasswordCredentialError::InvalidHashParts)
        );
        assert_eq!(
            format!("{value:?}"),
            "Argon2IdHash { salt: \"[REDACTED]\", hash: \"[REDACTED]\" }"
        );
        Ok(())
    }

    #[test]
    fn password_credential_binds_identity_time_and_hash() -> Result<(), Box<dyn Error>> {
        let principal_id = PrincipalId::generate();
        let changed_at = OffsetDateTime::now_utc();
        let hash = Argon2IdHash::from_parts(&[0x33; 16], &[0x44; 32])?;

        let credential =
            PasswordCredential::try_from_parts(principal_id, hash.clone(), changed_at)?;

        assert_eq!(credential.principal_id(), principal_id);
        assert_eq!(credential.hash(), &hash);
        assert_eq!(credential.changed_at(), changed_at);
        Ok(())
    }

    /// Derives a hash for a fixed password under the pinned parameters —
    /// deliberately the expensive path so the tests exercise the same memory
    /// and passes as production verification.
    fn hash_of(password: &str) -> Result<Argon2IdHash, Box<dyn Error>> {
        let salt = [
            7, 10, 13, 16, 19, 22, 25, 28, 31, 34, 37, 40, 43, 46, 49, 52,
        ];
        let params = params().map_err(|_| "pinned argon2id parameters are invalid")?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut hash = [0_u8; ARGON2ID_HASH_LENGTH];
        argon2
            .hash_password_into(password.as_bytes(), &salt, &mut hash)
            .map_err(|_| "password derivation under pinned parameters failed")?;
        Ok(Argon2IdHash::from_parts(&salt, &hash)?)
    }

    #[test]
    fn constant_time_comparison_detects_any_difference() {
        let left = [0x5a_u8; 32];
        let mut right = [0x5a_u8; 32];
        assert!(constant_time_eq(&left, &right));
        right[31] ^= 1;
        assert!(!constant_time_eq(&left, &right));
        let mut right = [0x5a_u8; 32];
        right[0] ^= 1;
        assert!(!constant_time_eq(&left, &right));
    }
}
