//! First-startup bootstrap codes (§16.2 "首次启动生成一次性 Bootstrap Code").
//!
//! The one-time bootstrap code is a 20-character code drawn from an
//! unambiguous base32 alphabet — the RFC 4648 alphabet with `0`, `O`, `1`,
//! and `I` removed, so no handwritten code can be misread — that the
//! operator types into the console exactly once to claim the product and set
//! the first password. The database stores only the SHA-256 hash of the code
//! (the `bootstrap_codes.code_hash` column), so a leaked database never
//! yields a usable claim secret; the raw code is generated here, shown to
//! the operator exactly once by the initialization runtime, and never
//! persisted anywhere.
//!
//! The 32-character base32 alphabet yields 5 bits per character, so a
//! 20-character code carries 100 bits of entropy — comfortably beyond the
//! 80-bit floor for a one-time claim secret.

use std::{error::Error, fmt};

use sha2::{Digest, Sha256};

/// Number of characters in every product bootstrap code.
pub const BOOTSTRAP_CODE_CHARACTERS: usize = 20;

/// The unambiguous base32 alphabet: the RFC 4648 alphabet with the four
/// visually confusable characters (`0`, `O`, `1`, `I`) removed.
const CODE_ALPHABET: &[u8; 32] = b"23456789ABCDEFGHJKLMNPQRSTUVWXYZ";

/// Generates a fresh one-time bootstrap code.
///
/// The code is 20 characters drawn uniformly from the unambiguous base32
/// alphabet, so it is safe to hand-copy and never contains a confusable
/// character pair.
///
/// # Errors
///
/// Returns [`BootstrapCodeError::RandomnessUnavailable`] when the operating
/// system cannot supply cryptographically secure random bytes.
pub fn generate_bootstrap_code() -> Result<String, BootstrapCodeError> {
    let mut indices = [0_u8; BOOTSTRAP_CODE_CHARACTERS];
    getrandom::fill(&mut indices).map_err(BootstrapCodeError::RandomnessUnavailable)?;
    let code = indices
        .into_iter()
        .map(|index| CODE_ALPHABET[usize::from(index) % CODE_ALPHABET.len()] as char)
        .collect::<String>();
    Ok(code)
}

/// Returns the SHA-256 hash of a bootstrap code for persistence.
///
/// The code is normalized to its canonical form — surrounding whitespace
/// trimmed, every letter uppercased — before hashing, so a presented code
/// compares exactly like the code that was printed, no matter how it was
/// typed. This is the single normalization point of the comparison path.
#[must_use]
pub fn hash_bootstrap_code(code: &str) -> [u8; 32] {
    let canonical = code.trim().to_ascii_uppercase();
    Sha256::digest(canonical.as_bytes()).into()
}

/// A controlled failure while generating a bootstrap code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootstrapCodeError {
    /// The operating system did not provide cryptographically secure randomness.
    RandomnessUnavailable(getrandom::Error),
}

impl fmt::Display for BootstrapCodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RandomnessUnavailable(_) => {
                formatter.write_str("cryptographic randomness is unavailable")
            }
        }
    }
}

impl Error for BootstrapCodeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::RandomnessUnavailable(error) => Some(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::*;

    #[test]
    fn codes_are_exactly_20_characters_of_the_unambiguous_alphabet() -> Result<(), Box<dyn Error>> {
        for _ in 0..64 {
            let code = generate_bootstrap_code()?;
            assert_eq!(code.len(), BOOTSTRAP_CODE_CHARACTERS);
            assert!(
                code.bytes().all(|byte| CODE_ALPHABET.contains(&byte)),
                "every character must come from the unambiguous alphabet"
            );
            assert!(
                !code
                    .bytes()
                    .any(|byte| matches!(byte, b'0' | b'O' | b'1' | b'I')),
                "the confusable characters must never appear"
            );
        }
        Ok(())
    }

    #[test]
    fn codes_are_high_entropy_and_independent() -> Result<(), Box<dyn Error>> {
        let first = generate_bootstrap_code()?;
        let second = generate_bootstrap_code()?;

        assert_ne!(first, second);
        assert_eq!(hash_bootstrap_code(&first), hash_bootstrap_code(&first));
        assert_ne!(hash_bootstrap_code(&first), hash_bootstrap_code(&second));
        assert_eq!(hash_bootstrap_code(&first).len(), 32);
        Ok(())
    }

    #[test]
    fn hashing_is_deterministic_over_the_canonical_uppercase_form() {
        // The comparison path normalizes a presented code before hashing, so
        // the hash of the normalized form is the stored contract.
        assert_eq!(
            hash_bootstrap_code("ABCD2345EFGH6789JKLM"),
            hash_bootstrap_code("abcd2345efgh6789jklm")
        );
    }
}
