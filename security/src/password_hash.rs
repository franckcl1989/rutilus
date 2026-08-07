//! Password hashing for product principals (§16.2 "密码使用 Argon2id").
//!
//! Hash *creation* lives here: a fresh 16-byte salt is drawn from the
//! operating system and the password is derived with the pinned `argon2id-1`
//! parameters (64 MiB memory, 3 iterations, 1 lane; the constants are the
//! domain's [`rutilus_domain::ARGON2ID_*`] values, so creation and
//! verification can never drift). The resulting [`Argon2IdHash`] value object
//! is the domain's judge of every later verification — re-deriving with the
//! stored salt and comparing in constant time — so this module never sees a
//! plaintext password again after creation, and verification never re-reads
//! the password into anything but the Argon2id computation.
//!
//! The derived salt and hash are stored in separate columns under the
//! `argon2id-1` format code (the `password_credentials` schema pins the
//! code), matching the design's split-column credential model.

use std::{error::Error, fmt};

use argon2::{Algorithm, Argon2, Params, Version};
use rutilus_domain::{
    ARGON2ID_HASH_LENGTH, ARGON2ID_MEMORY_KIB, ARGON2ID_PARALLELISM, ARGON2ID_SALT_LENGTH,
    ARGON2ID_TIME_COST, Argon2IdHash, PasswordCredentialError,
};
use secrecy::{ExposeSecret, SecretString};

/// Derives a fresh `argon2id-1` hash for a password.
///
/// A new random salt is drawn for every call, so the same password never
/// produces the same persisted credential — the derivation is salted exactly
/// as the format pins.
///
/// # Errors
///
/// Returns [`PasswordHashError::RandomnessUnavailable`] when the operating
/// system cannot supply cryptographically secure random bytes, or
/// [`PasswordHashError::Derivation`] when the derivation fails.
pub fn hash_password(password: &SecretString) -> Result<Argon2IdHash, PasswordHashError> {
    let mut salt = [0_u8; ARGON2ID_SALT_LENGTH];
    getrandom::fill(&mut salt).map_err(PasswordHashError::RandomnessUnavailable)?;
    let argon2 = argon2()?;
    let mut hash = [0_u8; ARGON2ID_HASH_LENGTH];
    argon2
        .hash_password_into(password.expose_secret().as_bytes(), &salt, &mut hash)
        .map_err(PasswordHashError::Derivation)?;
    // The byte slices are exactly the format's lengths by construction; the
    // error arm is a totality guard for the value object's persistence-facing
    // constructor.
    Argon2IdHash::from_parts(&salt, &hash).map_err(|_| PasswordHashError::InvalidHashParts)
}

/// Verifies a presented password against a stored hash.
///
/// This is the sign-in surface: the domain value object re-derives the hash
/// with the stored salt and compares in constant time, so the caller never
/// handles a candidate hash of its own.
#[must_use]
pub fn verify_password(hash: &Argon2IdHash, password: &SecretString) -> bool {
    hash.verify(password)
}

fn argon2() -> Result<Argon2<'static>, PasswordHashError> {
    let params = Params::new(
        ARGON2ID_MEMORY_KIB,
        ARGON2ID_TIME_COST,
        ARGON2ID_PARALLELISM,
        Some(ARGON2ID_HASH_LENGTH),
    )
    .map_err(PasswordHashError::Derivation)?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

/// A controlled failure while hashing a password.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PasswordHashError {
    /// The operating system did not provide cryptographically secure randomness.
    RandomnessUnavailable(getrandom::Error),
    /// Argon2id could not derive or validate the pinned parameter set.
    Derivation(argon2::Error),
    /// The derived parts do not match the `argon2id-1` format (unreachable
    /// through this module; the arm exists for totality).
    InvalidHashParts,
}

impl fmt::Display for PasswordHashError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RandomnessUnavailable(_) => {
                formatter.write_str("cryptographic randomness is unavailable")
            }
            Self::Derivation(_) => formatter.write_str("password hash derivation failed"),
            Self::InvalidHashParts => {
                formatter.write_str("derived password hash does not match the argon2id-1 format")
            }
        }
    }
}

impl Error for PasswordHashError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::RandomnessUnavailable(error) => Some(error),
            // The argon2 error type is not a std::error::Error in this
            // configuration, so it is surfaced only through Display — the
            // same treatment the master-key module gives its derivation
            // error.
            Self::Derivation(_) | Self::InvalidHashParts => None,
        }
    }
}

/// The `InvalidHashParts` totality arm converts the value object's
/// persistence-facing error; the two types never interchange anywhere else.
impl From<PasswordCredentialError> for PasswordHashError {
    fn from(_value: PasswordCredentialError) -> Self {
        Self::InvalidHashParts
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use secrecy::SecretString;

    use super::*;

    #[test]
    fn hashes_verify_and_salt_each_derivation() -> Result<(), Box<dyn Error>> {
        let password: SecretString = "correct horse battery staple".to_owned().into();

        let first = hash_password(&password)?;
        let second = hash_password(&password)?;

        assert_ne!(
            first.salt(),
            second.salt(),
            "every derivation must draw a fresh salt"
        );
        assert_ne!(
            first.hash(),
            second.hash(),
            "a fresh salt must produce a different hash"
        );
        assert!(verify_password(&first, &password));
        assert!(verify_password(&second, &password));
        let wrong: SecretString = "wrong horse battery staple".to_owned().into();
        assert!(!verify_password(&first, &wrong));
        Ok(())
    }

    #[test]
    fn debug_never_prints_derived_material() -> Result<(), Box<dyn Error>> {
        let password: SecretString = "never log this password".to_owned().into();
        let hash = hash_password(&password)?;

        assert_eq!(
            format!("{hash:?}"),
            "Argon2IdHash { salt: \"[REDACTED]\", hash: \"[REDACTED]\" }"
        );
        assert!(!format!("{hash:?}").contains("never log this password"));
        Ok(())
    }
}
