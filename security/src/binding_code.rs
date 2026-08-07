//! One-time site-to-center binding codes (design D2 "绑定码").
//!
//! The one-time binding code is the 20-character claim secret a site
//! presents to the center to bind its registration (the §16.2 bootstrap
//! code is its first-startup sibling). Like the bootstrap code, it is drawn
//! from the unambiguous base32 alphabet, and the database stores only the
//! SHA-256 hash of the code (`center_bindings.binding_code_hash`), so a
//! leaked database never yields a usable claim secret; the raw code is
//! generated here, shown to the operator exactly once, and never persisted
//! anywhere.
//!
//! The 32-character base32 alphabet yields 5 bits per character, so a
//! 20-character code carries 100 bits of entropy — comfortably beyond the
//! 80-bit floor for a one-time claim secret. The alphabet itself lives in
//! the domain crate ([`rutilus_domain::CODE_ALPHABET`]), which is also the
//! authority that validates every parsed code, so the generator and the
//! validator can never drift apart.

use std::{error::Error, fmt};

use rutilus_domain::{BINDING_CODE_CHARACTERS, BindingCode, CODE_ALPHABET};

/// Generates a fresh one-time binding code.
///
/// The code is 20 characters drawn uniformly from the unambiguous base32
/// alphabet, so it is safe to hand-copy and never contains a confusable
/// character pair.
///
/// # Errors
///
/// Returns [`BindingCodeError::RandomnessUnavailable`] when the operating
/// system cannot supply cryptographically secure random bytes.
pub fn generate_binding_code() -> Result<BindingCode, BindingCodeError> {
    let mut indices = [0_u8; BINDING_CODE_CHARACTERS];
    getrandom::fill(&mut indices).map_err(BindingCodeError::RandomnessUnavailable)?;
    let code = indices
        .into_iter()
        .map(|index| CODE_ALPHABET[usize::from(index) % CODE_ALPHABET.len()] as char)
        .collect::<String>();
    code.parse().map_err(|_| BindingCodeError::InvalidAlphabet)
}

/// A controlled failure while generating a binding code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BindingCodeError {
    /// The operating system did not provide cryptographically secure randomness.
    RandomnessUnavailable(getrandom::Error),
    /// The generated text is not in the canonical binding-code shape.
    ///
    /// Unreachable while the generator and the validator read the same
    /// `rutilus_domain::CODE_ALPHABET` and `BINDING_CODE_CHARACTERS`; it
    /// exists so the parse cannot fail with an unexpected error.
    InvalidAlphabet,
}

impl fmt::Display for BindingCodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RandomnessUnavailable(_) => {
                formatter.write_str("cryptographic randomness is unavailable")
            }
            Self::InvalidAlphabet => {
                formatter.write_str("generated binding code is not in the canonical shape")
            }
        }
    }
}

impl Error for BindingCodeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::RandomnessUnavailable(error) => Some(error),
            Self::InvalidAlphabet => None,
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
            let code = generate_binding_code()?;
            assert_eq!(code.as_str().len(), BINDING_CODE_CHARACTERS);
            assert!(
                code.as_str()
                    .bytes()
                    .all(|byte| CODE_ALPHABET.contains(&byte)),
                "every character must come from the unambiguous alphabet"
            );
            assert!(
                !code
                    .as_str()
                    .bytes()
                    .any(|byte| matches!(byte, b'0' | b'O' | b'1' | b'I')),
                "the confusable characters must never appear"
            );
        }
        Ok(())
    }

    #[test]
    fn codes_are_high_entropy_and_independent() -> Result<(), Box<dyn Error>> {
        let first = generate_binding_code()?;
        let second = generate_binding_code()?;

        assert_ne!(first, second);
        assert_eq!(first.hash(), first.hash());
        assert_ne!(first.hash(), second.hash());
        assert_eq!(first.hash().len(), 32);
        assert!(
            first.verify_hash(&first.hash()),
            "a code must verify against its own hash"
        );
        Ok(())
    }
}
