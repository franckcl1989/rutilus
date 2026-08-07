//! Windows DPAPI protection (0.6.0 S3).
//!
//! The only FFI in the platform crate: `CryptProtectData` and
//! `CryptUnprotectData` wrap the raw key bytes under the current Windows
//! user's DPAPI keys. The `#![allow(unsafe_code)]` is deliberately scoped to
//! this module; the wrapper functions below are the safe seam everything
//! else calls.

#![allow(unsafe_code)]

use windows_sys::Win32::{
    Foundation::{ERROR_INVALID_DATA, GetLastError, LocalFree},
    Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
    },
};

/// Defensive upper bound for one DPAPI blob: master-key payloads are small,
/// so a larger output means the call misbehaved and must not be trusted.
const MAX_DPAPI_BLOB_LENGTH: u32 = 1024 * 1024;

/// Protects `plaintext` with DPAPI for the current Windows user.
///
/// The returned blob is opaque; only this account's [`unprotect`] recovers
/// the input. The UI prompt is forbidden, so unattended services never block
/// on a dialog.
///
/// # Errors
///
/// Returns the Win32 error code when DPAPI refuses the protection.
pub(crate) fn protect(plaintext: &[u8]) -> Result<Vec<u8>, u32> {
    let input = blob(plaintext);
    let mut output = CRYPT_INTEGER_BLOB::default();
    let ok = unsafe {
        CryptProtectData(
            std::ptr::from_ref(&input),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            std::ptr::from_mut(&mut output),
        )
    };
    if ok == 0 {
        let code = last_error();
        return Err(code);
    }
    let result = copy_blob(&output);
    unsafe { LocalFree(output.pbData.cast()) };
    result
}

/// Recovers the plaintext of a DPAPI blob produced by [`protect`].
///
/// # Errors
///
/// Returns the Win32 error code when DPAPI refuses the payload; no plaintext
/// is released on failure.
pub(crate) fn unprotect(payload: &[u8]) -> Result<Vec<u8>, u32> {
    let input = blob(payload);
    let mut output = CRYPT_INTEGER_BLOB::default();
    let ok = unsafe {
        CryptUnprotectData(
            std::ptr::from_ref(&input),
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            std::ptr::from_mut(&mut output),
        )
    };
    if ok == 0 {
        let code = last_error();
        return Err(code);
    }
    let result = copy_blob(&output);
    unsafe { LocalFree(output.pbData.cast()) };
    result
}

fn blob(bytes: &[u8]) -> CRYPT_INTEGER_BLOB {
    CRYPT_INTEGER_BLOB {
        // A master-key payload can never approach u32::MAX; saturating keeps
        // the cast infallible and lets DPAPI refuse the impossible length.
        cbData: u32::try_from(bytes.len()).unwrap_or(u32::MAX),
        pbData: bytes.as_ptr().cast_mut(),
    }
}

fn copy_blob(blob: &CRYPT_INTEGER_BLOB) -> Result<Vec<u8>, u32> {
    if blob.cbData > MAX_DPAPI_BLOB_LENGTH {
        return Err(ERROR_INVALID_DATA);
    }
    let length = usize::try_from(blob.cbData).map_err(|_| ERROR_INVALID_DATA)?;
    let mut bytes = Vec::with_capacity(length);
    if length > 0 {
        let source = unsafe { std::slice::from_raw_parts(blob.pbData, length) };
        bytes.extend_from_slice(source);
    }
    Ok(bytes)
}

fn last_error() -> u32 {
    unsafe { GetLastError() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protects_and_recovers_without_plaintext_persistence() -> Result<(), u32> {
        let plaintext = [0x5b_u8; 32];

        let first = protect(&plaintext)?;
        let second = protect(&plaintext)?;

        assert_ne!(first, plaintext);
        assert_ne!(first, second);
        assert_eq!(unprotect(&first)?, plaintext);
        assert_eq!(unprotect(&second)?, plaintext);
        Ok(())
    }

    #[test]
    fn refuses_bytes_that_never_came_from_dpapi() {
        assert!(unprotect(&[0_u8; 32]).is_err());
        assert!(unprotect(b"").is_err());
    }
}
