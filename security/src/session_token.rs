//! Session bearer tokens and CSRF tokens (§16.2 登录安全).
//!
//! A sign-in issues two random 256-bit secrets: the session token the client
//! presents with every request, and the CSRF token that must accompany state-
//! changing requests ("Session Cookie 使用 Secure、HttpOnly、SameSite；CSRF
//! 防护"). The database stores only the SHA-256 hashes of both (§16.2), so a
//! leaked database never yields a usable session secret.
//!
//! The raw tokens are wrapped in `SecretBox` (zeroized on drop, redacted from
//! `Debug`); the wire form is the unpadded base64url encoding of the 32 raw
//! bytes, and [`SessionToken::from_base64url`] recovers the raw token from
//! the client's presentation so the sign-in middleware can hash it and look
//! up the session row.

use std::{error::Error, fmt};

use base64::Engine;
use secrecy::{ExposeSecret, SecretBox};
use sha2::{Digest, Sha256};

/// Byte length of every session and CSRF token (256 bits).
pub const TOKEN_LENGTH: usize = 32;

/// One random session bearer token, held only in secret memory.
///
/// The `SecretBox` secret is not `CloneableSecret` (secrecy marks only
/// integer primitives cloneable), so `Clone` and the equality comparisons are
/// implemented manually through the one exposure path.
pub struct SessionToken(SecretBox<[u8; TOKEN_LENGTH]>);

impl SessionToken {
    /// Generates a token from the operating system's random source.
    ///
    /// # Errors
    ///
    /// Returns [`SessionTokenError::RandomnessUnavailable`] when the
    /// operating system cannot supply cryptographically secure random bytes.
    pub fn generate() -> Result<Self, SessionTokenError> {
        Ok(Self(random_bytes()?))
    }

    /// Recovers a token from its client-presented base64url form.
    ///
    /// # Errors
    ///
    /// Returns [`SessionTokenError::InvalidEncoding`] when the value is not
    /// valid unpadded base64url of exactly [`TOKEN_LENGTH`] bytes.
    pub fn from_base64url(value: &str) -> Result<Self, SessionTokenError> {
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|_| SessionTokenError::InvalidEncoding)?;
        let bytes = <[u8; TOKEN_LENGTH]>::try_from(decoded.as_slice())
            .map_err(|_| SessionTokenError::InvalidEncoding)?;
        Ok(Self(SecretBox::new(Box::new(bytes))))
    }

    /// Returns the SHA-256 hash stored in the `sessions.token_hash` column.
    #[must_use]
    pub fn hash(&self) -> [u8; 32] {
        digest(self.0.expose_secret())
    }

    /// Returns the client-presented base64url form.
    #[must_use]
    pub fn as_base64url(&self) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(self.0.expose_secret())
    }
}

impl Clone for SessionToken {
    fn clone(&self) -> Self {
        Self(SecretBox::new(Box::new(*self.0.expose_secret())))
    }
}

impl PartialEq for SessionToken {
    fn eq(&self, other: &Self) -> bool {
        self.0.expose_secret() == other.0.expose_secret()
    }
}

impl Eq for SessionToken {}

impl fmt::Debug for SessionToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionToken([REDACTED])")
    }
}

/// One random CSRF token, held only in secret memory.
pub struct CsrfToken(SecretBox<[u8; TOKEN_LENGTH]>);

impl CsrfToken {
    /// Generates a token from the operating system's random source.
    ///
    /// # Errors
    ///
    /// Returns [`SessionTokenError::RandomnessUnavailable`] when the
    /// operating system cannot supply cryptographically secure random bytes.
    pub fn generate() -> Result<Self, SessionTokenError> {
        Ok(Self(random_bytes()?))
    }

    /// Returns the SHA-256 hash stored in the `sessions.csrf_hash` column.
    #[must_use]
    pub fn hash(&self) -> [u8; 32] {
        digest(self.0.expose_secret())
    }

    /// Returns the client-presented base64url form.
    #[must_use]
    pub fn as_base64url(&self) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(self.0.expose_secret())
    }
}

impl Clone for CsrfToken {
    fn clone(&self) -> Self {
        Self(SecretBox::new(Box::new(*self.0.expose_secret())))
    }
}

impl PartialEq for CsrfToken {
    fn eq(&self, other: &Self) -> bool {
        self.0.expose_secret() == other.0.expose_secret()
    }
}

impl Eq for CsrfToken {}

impl fmt::Debug for CsrfToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CsrfToken([REDACTED])")
    }
}

fn random_bytes() -> Result<SecretBox<[u8; TOKEN_LENGTH]>, SessionTokenError> {
    let mut generation_result = Ok(());
    let bytes: SecretBox<[u8; TOKEN_LENGTH]> =
        SecretBox::init_with_mut(|buffer: &mut [u8; TOKEN_LENGTH]| {
            generation_result = getrandom::fill(buffer);
        });
    generation_result.map_err(SessionTokenError::RandomnessUnavailable)?;
    Ok(bytes)
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// A controlled failure while generating or parsing a token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionTokenError {
    /// The operating system did not provide cryptographically secure randomness.
    RandomnessUnavailable(getrandom::Error),
    /// The presented value is not unpadded base64url of exactly 32 bytes.
    InvalidEncoding,
}

impl fmt::Display for SessionTokenError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RandomnessUnavailable(_) => {
                formatter.write_str("cryptographic randomness is unavailable")
            }
            Self::InvalidEncoding => {
                formatter.write_str("session token is not valid base64url of 32 bytes")
            }
        }
    }
}

impl Error for SessionTokenError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::RandomnessUnavailable(error) => Some(error),
            Self::InvalidEncoding => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::*;

    #[test]
    fn session_tokens_round_trip_through_the_wire_form() -> Result<(), Box<dyn Error>> {
        let token = SessionToken::generate()?;
        let wire = token.as_base64url();
        let recovered = SessionToken::from_base64url(&wire)?;

        assert_eq!(recovered, token);
        assert_eq!(recovered.hash(), token.hash());
        assert!(!wire.contains('+'));
        assert!(!wire.contains('/'));
        assert!(!wire.contains('='));
        assert_eq!(format!("{token:?}"), "SessionToken([REDACTED])");
        assert!(!format!("{token:?}").contains(&wire));
        Ok(())
    }

    #[test]
    fn session_tokens_are_independent_and_hash_deterministically() -> Result<(), Box<dyn Error>> {
        let first = SessionToken::generate()?;
        let second = SessionToken::generate()?;

        assert_ne!(first.as_base64url(), second.as_base64url());
        assert_ne!(first.hash(), second.hash());
        assert_eq!(first.hash(), first.hash());
        Ok(())
    }

    #[test]
    fn token_parsing_refuses_anything_but_exactly_32_bytes_of_base64url()
    -> Result<(), Box<dyn Error>> {
        let token = SessionToken::generate()?;
        let wire = token.as_base64url();

        // 32 bytes of base64url decode to a 43-character string; every
        // mutation below is refused.
        assert!(matches!(
            SessionToken::from_base64url(&format!("{wire}x")),
            Err(SessionTokenError::InvalidEncoding)
        ));
        assert!(matches!(
            SessionToken::from_base64url(&wire[1..]),
            Err(SessionTokenError::InvalidEncoding)
        ));
        assert!(matches!(
            SessionToken::from_base64url("not base64!!"),
            Err(SessionTokenError::InvalidEncoding)
        ));
        Ok(())
    }

    #[test]
    fn csrf_tokens_generate_and_hash_without_exposing() -> Result<(), Box<dyn Error>> {
        let first = CsrfToken::generate()?;
        let second = CsrfToken::generate()?;

        assert_ne!(first.hash(), second.hash());
        assert_eq!(format!("{first:?}"), "CsrfToken([REDACTED])");
        Ok(())
    }
}
