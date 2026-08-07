//! TOTP provisioning and sign-in verification for product principals (§16.2
//! "支持可选 TOTP").
//!
//! Secret *generation* lives here: a fresh 160-bit secret is drawn from the
//! operating system and rendered as the `otpauth://` URI the provisioning UI
//! turns into a QR code (RFC 4648 base32, the SHA-1/6-digit/30-second shape
//! the domain pins). Code *verification* is the domain's RFC 6238 core —
//! [`rutilus_domain::verify_totp_code`] — which this module re-exposes on the
//! `SecretBox` the sign-in flow holds, so the algorithm lives exactly once
//! while the application layer keeps one crypto surface to call.

use std::{error::Error, fmt};

use base32::Alphabet;
use rutilus_domain::{
    TOTP_DIGITS, TOTP_PERIOD_SECONDS, TOTP_SECRET_LENGTH, TotpAuthenticatorError, verify_totp_code,
};
use secrecy::{ExposeSecret, SecretBox};
use time::OffsetDateTime;

/// Generates a fresh TOTP secret for provisioning.
///
/// The secret is 160 bits of operating-system randomness, wrapped in a
/// `SecretBox` so it zeroizes on drop and never appears in `Debug` output.
///
/// # Errors
///
/// Returns [`TotpSecretError::RandomnessUnavailable`] when the operating
/// system cannot supply cryptographically secure random bytes.
pub fn generate_totp_secret() -> Result<SecretBox<[u8; TOTP_SECRET_LENGTH]>, TotpSecretError> {
    let mut generation_result = Ok(());
    let secret: SecretBox<[u8; TOTP_SECRET_LENGTH]> =
        SecretBox::init_with_mut(|bytes: &mut [u8; TOTP_SECRET_LENGTH]| {
            generation_result = getrandom::fill(bytes);
        });
    generation_result.map_err(TotpSecretError::RandomnessUnavailable)?;
    Ok(secret)
}

/// Renders the provisioning URI for one secret.
///
/// The returned `otpauth://` URI carries the base32 secret and the product's
/// pinned RFC 6238 parameters, so any standard authenticator app scans and
/// produces the codes this product verifies.
///
/// # Errors
///
/// Returns [`TotpUriError`] when the issuer or account label is empty, too
/// long, or contains a character that would break the URI's label syntax.
pub fn totp_uri(
    secret: &SecretBox<[u8; TOTP_SECRET_LENGTH]>,
    issuer: &str,
    account: &str,
) -> Result<String, TotpUriError> {
    let issuer = validate_label(issuer)?;
    let account = validate_label(account)?;
    let encoded = base32::encode(Alphabet::Rfc4648 { padding: false }, secret.expose_secret());
    Ok(format!(
        "otpauth://totp/{issuer}:{account}?secret={encoded}&issuer={issuer}\
         &algorithm=SHA1&digits={TOTP_DIGITS}&period={TOTP_PERIOD_SECONDS}"
    ))
}

/// Verifies a presented TOTP code in the RFC 6238 window.
///
/// This is the sign-in surface over the domain's verification core: the code
/// must match the current 30-second step within the one-step window and must
/// advance past `last_used_step` (anti-replay). The matched step is returned
/// so the caller can persist it with the same conditional-update discipline
/// as the domain aggregate.
///
/// # Errors
///
/// Returns [`TotpAuthenticatorError`] exactly as the domain core does.
pub fn verify_code(
    secret: &SecretBox<[u8; TOTP_SECRET_LENGTH]>,
    code: &str,
    now: OffsetDateTime,
    last_used_step: Option<u64>,
) -> Result<u64, TotpAuthenticatorError> {
    verify_totp_code(secret.expose_secret(), code, now, last_used_step)
}

/// The longest label segment in a provisioning URI.
const MAX_LABEL_CHARS: usize = 64;

fn validate_label(label: &str) -> Result<&str, TotpUriError> {
    if label.is_empty() {
        return Err(TotpUriError::Empty);
    }
    if label.chars().count() > MAX_LABEL_CHARS {
        return Err(TotpUriError::TooLong {
            maximum: MAX_LABEL_CHARS,
        });
    }
    // The otpauth label syntax is `issuer:account`; any character that could
    // forge a second segment or break the query string is refused.
    if label
        .chars()
        .any(|character| character.is_control() || matches!(character, ':' | '%' | '?' | '&'))
    {
        return Err(TotpUriError::InvalidCharacter);
    }
    Ok(label)
}

/// A controlled failure while provisioning a TOTP secret.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TotpSecretError {
    /// The operating system did not provide cryptographically secure randomness.
    RandomnessUnavailable(getrandom::Error),
}

impl fmt::Display for TotpSecretError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RandomnessUnavailable(_) => {
                formatter.write_str("cryptographic randomness is unavailable")
            }
        }
    }
}

impl Error for TotpSecretError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::RandomnessUnavailable(error) => Some(error),
        }
    }
}

/// Why a provisioning URI label cannot be used.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TotpUriError {
    Empty,
    TooLong { maximum: usize },
    InvalidCharacter,
}

impl fmt::Display for TotpUriError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("TOTP URI label cannot be empty"),
            Self::TooLong { maximum } => {
                write!(formatter, "TOTP URI label exceeds {maximum} characters")
            }
            Self::InvalidCharacter => formatter.write_str(
                "TOTP URI label contains a character that breaks the otpauth URI syntax",
            ),
        }
    }
}

impl Error for TotpUriError {}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::*;

    #[test]
    fn generated_secrets_are_entropy_dense_and_independent() -> Result<(), Box<dyn Error>> {
        let first = generate_totp_secret()?;
        let second = generate_totp_secret()?;

        assert_eq!(first.expose_secret().len(), TOTP_SECRET_LENGTH);
        assert_ne!(first.expose_secret(), second.expose_secret());
        assert_eq!(
            format!("{first:?}"),
            format!("SecretBox<[u8; {TOTP_SECRET_LENGTH}]>([REDACTED])")
        );
        Ok(())
    }

    #[test]
    fn uri_carries_the_pinned_parameters() -> Result<(), Box<dyn Error>> {
        let secret = generate_totp_secret()?;

        let uri = totp_uri(&secret, "Rutilus", "admin")?;

        assert!(uri.starts_with("otpauth://totp/Rutilus:admin?secret="));
        assert!(uri.contains("&issuer=Rutilus"));
        assert!(uri.contains("&algorithm=SHA1"));
        assert!(uri.contains("&digits=6"));
        assert!(uri.contains("&period=30"));
        // The base32 secret decodes back to exactly the generated bytes.
        let encoded = uri
            .split("secret=")
            .nth(1)
            .ok_or("secret parameter is missing")?
            .split('&')
            .next()
            .ok_or("secret parameter is missing")?;
        let decoded = base32::decode(Alphabet::Rfc4648 { padding: false }, encoded)
            .ok_or("encoded secret does not decode")?;
        assert_eq!(decoded, secret.expose_secret().to_vec());
        Ok(())
    }

    #[test]
    fn uri_rejects_labels_that_break_the_syntax() -> Result<(), Box<dyn Error>> {
        let secret = generate_totp_secret()?;

        assert_eq!(totp_uri(&secret, "", "admin"), Err(TotpUriError::Empty));
        assert_eq!(totp_uri(&secret, "Rutilus", ""), Err(TotpUriError::Empty));
        assert_eq!(
            totp_uri(&secret, "Rutilus:evil", "admin"),
            Err(TotpUriError::InvalidCharacter)
        );
        assert_eq!(
            totp_uri(&secret, "Rutilus", "admin?issuer=evil"),
            Err(TotpUriError::InvalidCharacter)
        );
        assert!(matches!(
            totp_uri(&secret, &"i".repeat(MAX_LABEL_CHARS + 1), "admin"),
            Err(TotpUriError::TooLong { .. })
        ));
        Ok(())
    }

    #[test]
    fn verification_matches_the_domain_core() -> Result<(), Box<dyn Error>> {
        // The RFC 6238 appendix B SHA-1 vector: step 1 at time 59, code
        // 287082, against the ASCII RFC test secret.
        let secret = SecretBox::new(Box::new(*b"12345678901234567890"));
        let now = OffsetDateTime::from_unix_timestamp(59)?;

        assert_eq!(verify_code(&secret, "287082", now, None)?, 1);
        assert!(matches!(
            verify_code(&secret, "287082", now, Some(1)),
            Err(TotpAuthenticatorError::Replayed)
        ));
        assert!(matches!(
            verify_code(&secret, "000000", now, None),
            Err(TotpAuthenticatorError::InvalidCode)
        ));
        Ok(())
    }
}
