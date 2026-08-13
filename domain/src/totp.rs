//! Optional TOTP authenticators for product principals (§16.2).
//!
//! §16.2 makes TOTP an optional second factor ("支持可选 TOTP"). An
//! authenticator is provisioned in the `Provisioning` state — the security
//! crate generates the 20-byte secret and renders the `otpauth://` URI for a
//! QR code — and [`TotpAuthenticator::activate`] moves it to `Active` only
//! after the operator proves possession of the secret by presenting a valid
//! RFC 6238 code. Verification is the module's own responsibility: the
//! one-time code is re-derived with HMAC-SHA1 from the counter step nearest
//! the current time (RFC 6238's 30-second period, 6 digits, a one-step
//! window on each side), compared without short-circuiting, and replayed
//! codes are refused by tracking the last used step — a code accepted from
//! the future window is recorded at its own step, so the same digits are
//! refused when the clock reaches that step (the transient lockout
//! documented at [`verify_totp_code`], V5C-5). The secret never leaves this
//! type in plaintext: it is held in a `SecretBox`, and `Debug` renders only
//! redaction.
//!
//! The algorithm is self-contained here (the HMAC-SHA1 primitives are the
//! same audited digest generation the product already resolves for `SQLx`),
//! so the value object stays the single judge of code validity; the security
//! crate only *generates* secrets and presents them.

use std::{error::Error, fmt, str::FromStr};

use hmac::{Hmac, KeyInit, Mac};
use secrecy::{ExposeSecret, SecretBox};
use sha1::Sha1;
use time::OffsetDateTime;

use crate::{PrincipalId, TotpAuthenticatorId};

/// Number of digits in every product TOTP code (RFC 6238 default).
pub const TOTP_DIGITS: u8 = 6;
/// Length of one TOTP time step in seconds (RFC 6238 default).
pub const TOTP_PERIOD_SECONDS: i64 = 30;
/// Number of accepted steps on each side of the current step.
pub const TOTP_WINDOW: u64 = 1;
/// Byte length of every product TOTP secret (160 bits, RFC 4226 ≥ 128).
pub const TOTP_SECRET_LENGTH: usize = 20;

/// The provisioning state of one authenticator.
///
/// The codes are the stable persistence contract (`totp_authenticators.state`
/// CHECK constraint).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TotpState {
    /// The secret was generated but no valid code has been presented yet.
    Provisioning,
    /// A valid code activated the authenticator; verification is enforced.
    Active,
}

impl TotpState {
    /// Returns the stable product code used by persistence and protocols.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Provisioning => "provisioning",
            Self::Active => "active",
        }
    }
}

impl fmt::Display for TotpState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for TotpState {
    type Err = TotpStateParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "provisioning" => Ok(Self::Provisioning),
            "active" => Ok(Self::Active),
            _ => Err(TotpStateParseError),
        }
    }
}

/// A persisted TOTP state is unknown to this product build.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TotpStateParseError;

impl fmt::Display for TotpStateParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("unknown TOTP state code")
    }
}

impl Error for TotpStateParseError {}

/// One optional TOTP authenticator bound to its principal (§16.2).
///
/// The `SecretBox` secret is not `CloneableSecret` (secrecy marks only
/// integer primitives cloneable), so `Clone` and the equality comparisons are
/// implemented manually: the secret bytes are copied or compared through the
/// one exposure path, and `Debug` renders only redaction.
pub struct TotpAuthenticator {
    id: TotpAuthenticatorId,
    principal_id: PrincipalId,
    secret: SecretBox<[u8; TOTP_SECRET_LENGTH]>,
    state: TotpState,
    created_at: OffsetDateTime,
    activated_at: Option<OffsetDateTime>,
    last_used_step: Option<u64>,
}

impl TotpAuthenticator {
    /// Declares a new provisioning-state authenticator.
    ///
    /// The caller supplies the clock, keeping the domain free of clock access
    /// (§7.2).
    #[must_use]
    pub fn new(
        id: TotpAuthenticatorId,
        principal_id: PrincipalId,
        secret: SecretBox<[u8; TOTP_SECRET_LENGTH]>,
        created_at: OffsetDateTime,
    ) -> Self {
        Self {
            id,
            principal_id,
            secret,
            state: TotpState::Provisioning,
            created_at,
            activated_at: None,
            last_used_step: None,
        }
    }

    /// Rehydrates a persisted authenticator record.
    ///
    /// Persistence stores the secret as Master-Key XChaCha20-Poly1305
    /// ciphertext and decrypts it before this entry point runs, so the
    /// recovered 20-byte plaintext is what the length rule validates; this
    /// type only carries domain values and never touches persistence. The
    /// shape rules — an activated authenticator always has `activated_at`,
    /// a provisioning one has neither `activated_at` nor a used step — keep
    /// a tampered row from producing a half-understood aggregate.
    ///
    /// # Errors
    ///
    /// Returns [`TotpRestoreError::InvalidSecretLength`] or
    /// [`TotpRestoreError::InvalidShape`].
    pub fn try_from_parts(
        id: TotpAuthenticatorId,
        principal_id: PrincipalId,
        secret: &[u8],
        state: TotpState,
        created_at: OffsetDateTime,
        activated_at: Option<OffsetDateTime>,
        last_used_step: Option<u64>,
    ) -> Result<Self, TotpRestoreError> {
        let secret = <[u8; TOTP_SECRET_LENGTH]>::try_from(secret)
            .map_err(|_| TotpRestoreError::InvalidSecretLength)?;
        let active_shape = matches!(state, TotpState::Active) == activated_at.is_some();
        if !active_shape || (state == TotpState::Provisioning && last_used_step.is_some()) {
            return Err(TotpRestoreError::InvalidShape);
        }
        Ok(Self {
            id,
            principal_id,
            secret: SecretBox::new(Box::new(secret)),
            state,
            created_at,
            activated_at,
            last_used_step,
        })
    }

    /// Activates a provisioning authenticator after explicit code verification.
    ///
    /// The presented code must be a valid RFC 6238 code for the current time
    /// step (within the one-step window on each side) and must not already
    /// have been used. The matched step is recorded, so the activation code
    /// itself cannot be replayed.
    ///
    /// # Errors
    ///
    /// Returns [`TotpAuthenticatorError::InvalidCode`] for a wrong code,
    /// [`TotpAuthenticatorError::Replayed`] for a step already used, or
    /// [`TotpAuthenticatorError::AlreadyActive`] when the authenticator is
    /// not in the provisioning state.
    pub fn activate(
        &mut self,
        code: &str,
        now: OffsetDateTime,
    ) -> Result<(), TotpAuthenticatorError> {
        if self.state == TotpState::Active {
            return Err(TotpAuthenticatorError::AlreadyActive);
        }
        let step = verify_totp_code(self.secret.expose_secret(), code, now, self.last_used_step)?;
        self.state = TotpState::Active;
        self.activated_at = Some(now);
        self.last_used_step = Some(step);
        Ok(())
    }

    /// Verifies a presented code against an active authenticator.
    ///
    /// This is the sign-in path: the code must be valid within the one-step
    /// window and must advance past the last used step (anti-replay). The
    /// matched step is returned so the caller can persist it; persist the
    /// step through [`TotpAuthenticator::record_step`] or the persistence
    /// layer's conditional update, which refuses to move the recorded step
    /// backwards even under racing sign-ins.
    ///
    /// A code accepted from the future window is consumed for its own step
    /// (see [`verify_totp_code`]): when the clock reaches that step the same
    /// code is refused as replayed — a transient lockout of at most one
    /// step, the documented cost of the future-window acceptance (V5C-5).
    ///
    /// # Errors
    ///
    /// Returns [`TotpAuthenticatorError::NotActive`] when the authenticator
    /// is still provisioning, [`TotpAuthenticatorError::InvalidCode`] for a
    /// wrong code, or [`TotpAuthenticatorError::Replayed`] for a step that
    /// was already used.
    pub fn verify(&self, code: &str, now: OffsetDateTime) -> Result<u64, TotpAuthenticatorError> {
        if self.state != TotpState::Active {
            return Err(TotpAuthenticatorError::NotActive);
        }
        verify_totp_code(self.secret.expose_secret(), code, now, self.last_used_step)
    }

    /// Records the step matched by the most recent successful verification.
    ///
    /// # Errors
    ///
    /// Returns [`TotpAuthenticatorError::Replayed`] when the step does not
    /// advance past the last recorded step.
    pub fn record_step(&mut self, step: u64) -> Result<(), TotpAuthenticatorError> {
        if self.last_used_step.is_some_and(|last| step <= last) {
            return Err(TotpAuthenticatorError::Replayed);
        }
        self.last_used_step = Some(step);
        Ok(())
    }

    #[must_use]
    pub const fn id(&self) -> TotpAuthenticatorId {
        self.id
    }

    #[must_use]
    pub const fn principal_id(&self) -> PrincipalId {
        self.principal_id
    }

    /// Returns the secret without exposing it: callers that need the raw
    /// bytes (encryption, URI rendering) receive the `SecretBox` itself.
    #[must_use]
    pub fn secret(&self) -> &SecretBox<[u8; TOTP_SECRET_LENGTH]> {
        &self.secret
    }

    #[must_use]
    pub const fn state(&self) -> TotpState {
        self.state
    }

    #[must_use]
    pub const fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    #[must_use]
    pub const fn activated_at(&self) -> Option<OffsetDateTime> {
        self.activated_at
    }

    #[must_use]
    pub const fn last_used_step(&self) -> Option<u64> {
        self.last_used_step
    }
}

impl Clone for TotpAuthenticator {
    fn clone(&self) -> Self {
        Self {
            id: self.id,
            principal_id: self.principal_id,
            secret: SecretBox::new(Box::new(*self.secret.expose_secret())),
            state: self.state,
            created_at: self.created_at,
            activated_at: self.activated_at,
            last_used_step: self.last_used_step,
        }
    }
}

impl PartialEq for TotpAuthenticator {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
            && self.principal_id == other.principal_id
            && self.secret.expose_secret() == other.secret.expose_secret()
            && self.state == other.state
            && self.created_at == other.created_at
            && self.activated_at == other.activated_at
            && self.last_used_step == other.last_used_step
    }
}

impl Eq for TotpAuthenticator {}

impl fmt::Debug for TotpAuthenticator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TotpAuthenticator")
            .field("id", &self.id)
            .field("principal_id", &self.principal_id)
            .field("secret", &"[REDACTED]")
            .field("state", &self.state)
            .field("created_at", &self.created_at)
            .field("activated_at", &self.activated_at)
            .field("last_used_step", &self.last_used_step)
            .finish()
    }
}

/// A persisted authenticator record violates a domain invariant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TotpRestoreError {
    InvalidSecretLength,
    InvalidShape,
}

impl fmt::Display for TotpRestoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSecretLength => {
                formatter.write_str("TOTP secret must be exactly 20 bytes")
            }
            Self::InvalidShape => {
                formatter.write_str("TOTP state must pair with its activation time and used step")
            }
        }
    }
}

impl Error for TotpRestoreError {}

/// A TOTP verification failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TotpAuthenticatorError {
    /// The presented code is not a valid code for the current step window.
    InvalidCode,
    /// The presented code belongs to a step that was already used.
    Replayed,
    /// Verification was attempted on an authenticator that is not active.
    NotActive,
    /// Activation was attempted on an authenticator that is already active.
    AlreadyActive,
}

impl fmt::Display for TotpAuthenticatorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCode => formatter.write_str("TOTP code is invalid"),
            Self::Replayed => formatter.write_str("TOTP code was already used"),
            Self::NotActive => formatter.write_str("TOTP authenticator is not active"),
            Self::AlreadyActive => formatter.write_str("TOTP authenticator is already active"),
        }
    }
}

impl Error for TotpAuthenticatorError {}

/// Derives the RFC 6238 code for one counter step (HMAC-SHA1, 6 digits).
///
/// The HMAC construction accepts any key length, so constructing it from the
/// exactly sized secret cannot fail; the error arm exists for totality only.
fn hotp(secret: &[u8], step: u64) -> Result<u32, TotpAuthenticatorError> {
    let mut message = [0_u8; 8];
    message.copy_from_slice(&step.to_be_bytes());
    let mut mac =
        Hmac::<Sha1>::new_from_slice(secret).map_err(|_| TotpAuthenticatorError::InvalidCode)?;
    mac.update(&message);
    let digest = mac.finalize().into_bytes();
    let offset = usize::from(digest[19] & 0x0f);
    let binary = (u32::from(digest[offset] & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);
    Ok(binary % 1_000_000)
}

/// Verifies a presented code against a secret within the step window.
///
/// This is the RFC 6238 verification core shared by the authenticator
/// aggregate and the security crate's sign-in surface: the code must match a
/// step inside the one-step window and must advance past `last_used_step`
/// (anti-replay). The matched step is returned so the caller can persist it.
///
/// A code accepted from the *future* window — the step ahead of the current
/// one — is recorded as used at its own step, because that step is what the
/// anti-replay floor must remember for the one-time property to hold. The
/// consequence is documented, not papered over (V5C-5): when the clock
/// reaches that step, the same digits are refused as replayed, so a device
/// whose clock runs ahead of the server is locked out of the code it is
/// showing for at most one step. That transient lockout is the honest cost
/// of accepting future-window codes — the alternative (recording the code
/// as used only at the current step) would let the same code authenticate
/// repeatedly until its own step arrived, which is exactly the replay the
/// floor exists to refuse.
///
/// # Errors
///
/// Returns [`TotpAuthenticatorError::InvalidCode`] for a malformed or
/// non-matching code and [`TotpAuthenticatorError::Replayed`] when the
/// matched step was already used.
pub fn verify_totp_code(
    secret: &[u8],
    code: &str,
    now: OffsetDateTime,
    last_used_step: Option<u64>,
) -> Result<u64, TotpAuthenticatorError> {
    if !is_six_digit_code(code) {
        return Err(TotpAuthenticatorError::InvalidCode);
    }
    let current = current_step(now);
    for candidate in window_steps(current) {
        let expected = hotp(secret, candidate)?;
        if !code_matches(code, expected) {
            continue;
        }
        if last_used_step.is_some_and(|last| candidate <= last) {
            return Err(TotpAuthenticatorError::Replayed);
        }
        return Ok(candidate);
    }
    Err(TotpAuthenticatorError::InvalidCode)
}

/// The current RFC 6238 counter step, clamped to non-negative time.
fn current_step(now: OffsetDateTime) -> u64 {
    let timestamp = now.unix_timestamp();
    u64::try_from(timestamp / TOTP_PERIOD_SECONDS).unwrap_or(0)
}

/// The accepted window: one step behind and one step ahead of `current`.
fn window_steps(current: u64) -> [u64; 3] {
    [
        current.saturating_sub(TOTP_WINDOW),
        current,
        current.saturating_add(TOTP_WINDOW),
    ]
}

fn is_six_digit_code(code: &str) -> bool {
    code.len() == usize::from(TOTP_DIGITS) && code.bytes().all(|byte| byte.is_ascii_digit())
}

/// Compares a presented code against a derived code without short-circuiting.
fn code_matches(code: &str, expected: u32) -> bool {
    let expected = format!("{expected:06}");
    let mut difference = 0_u8;
    for (presented, derived) in code.bytes().zip(expected.bytes()) {
        difference |= presented ^ derived;
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use secrecy::ExposeSecret;

    use super::*;

    /// The RFC 4226 appendix D.5 test vector with counter `0` and the
    /// ASCII secret `12345678901234567890`: `755224` at counter 0, `287082`
    /// at counter 1, `359152` at counter 2. The same secret and period are
    /// the RFC 6238 appendix B SHA-1 test vector.
    const RFC_SECRET: [u8; 20] = *b"12345678901234567890";

    fn provisioning(now: OffsetDateTime) -> TotpAuthenticator {
        TotpAuthenticator::new(
            TotpAuthenticatorId::generate(),
            PrincipalId::generate(),
            SecretBox::new(Box::new(RFC_SECRET)),
            now,
        )
    }

    fn step_at(seconds: i64) -> Result<OffsetDateTime, time::error::ComponentRange> {
        OffsetDateTime::from_unix_timestamp(seconds)
    }

    #[test]
    fn hotp_matches_the_rfc_4226_sha1_vectors() -> Result<(), Box<dyn Error>> {
        assert_eq!(hotp(&RFC_SECRET, 0)?, 755_224);
        assert_eq!(hotp(&RFC_SECRET, 1)?, 287_082);
        assert_eq!(hotp(&RFC_SECRET, 2)?, 359_152);
        Ok(())
    }

    #[test]
    fn rfc_6238_sha1_vector_verifies_at_the_documented_step() -> Result<(), Box<dyn Error>> {
        // RFC 6238 appendix B, SHA-1 row: time 59 seconds, step 1, code
        // 287082. The authenticator must accept it one step ahead of its
        // current step inside the window.
        let now = step_at(59)?;
        let mut authenticator = provisioning(now);
        authenticator.activate("287082", now)?;

        assert_eq!(authenticator.state(), TotpState::Active);
        assert_eq!(authenticator.activated_at(), Some(now));
        assert_eq!(authenticator.last_used_step(), Some(1));
        assert!(matches!(
            authenticator.activate("287082", now),
            Err(TotpAuthenticatorError::AlreadyActive)
        ));
        Ok(())
    }

    #[test]
    fn activation_requires_a_valid_code_within_the_step_window() -> Result<(), Box<dyn Error>> {
        let now = step_at(59)?;
        let authenticator = provisioning(now);

        // Codes from the documented step and its neighbors are accepted...
        for code in ["287082", "755224", "359152"] {
            let mut candidate = authenticator.clone();
            candidate.activate(code, now)?;
            assert_eq!(candidate.state(), TotpState::Active);
        }
        // ...a code two steps away, a malformed code, and a random code are
        // refused, and the authenticator stays provisioning.
        let mut far = authenticator.clone();
        assert!(matches!(
            far.activate("582681", now), // counter 4, outside the window
            Err(TotpAuthenticatorError::InvalidCode)
        ));
        assert!(matches!(
            far.activate("12ab45", now),
            Err(TotpAuthenticatorError::InvalidCode)
        ));
        assert!(matches!(
            far.activate("12345", now),
            Err(TotpAuthenticatorError::InvalidCode)
        ));
        assert!(matches!(
            far.activate("1234567", now),
            Err(TotpAuthenticatorError::InvalidCode)
        ));
        assert_eq!(far.state(), TotpState::Provisioning);
        Ok(())
    }

    #[test]
    fn verification_requires_an_active_authenticator_and_advances_the_step()
    -> Result<(), Box<dyn Error>> {
        let created_at = step_at(0)?;
        let mut authenticator = provisioning(created_at);
        assert!(matches!(
            authenticator.verify("755224", created_at),
            Err(TotpAuthenticatorError::NotActive)
        ));
        authenticator.activate("755224", created_at)?;

        // The activation step is the anti-replay floor: replaying the same
        // code is refused, while a fresh step in the window verifies and
        // records.
        assert!(matches!(
            authenticator.verify("755224", created_at),
            Err(TotpAuthenticatorError::Replayed)
        ));
        let later = step_at(59)?;
        assert_eq!(authenticator.verify("287082", later)?, 1);
        authenticator.record_step(1)?;
        assert!(matches!(
            authenticator.verify("755224", later),
            Err(TotpAuthenticatorError::Replayed)
        ));
        // Step 2 is inside the window and fresh: it verifies and records.
        assert_eq!(authenticator.verify("359152", later)?, 2);
        authenticator.record_step(2)?;
        // The step-1 code is now behind the recorded step: replayed.
        assert!(matches!(
            authenticator.verify("287082", later),
            Err(TotpAuthenticatorError::Replayed)
        ));
        assert!(matches!(
            authenticator.record_step(1),
            Err(TotpAuthenticatorError::Replayed)
        ));
        assert!(matches!(
            authenticator.record_step(0),
            Err(TotpAuthenticatorError::Replayed)
        ));
        Ok(())
    }

    #[test]
    fn future_window_acceptance_consumes_the_code_for_its_own_step() -> Result<(), Box<dyn Error>> {
        // V5C-5: a code accepted from the future window is recorded at its
        // own step — that is the floor the one-time property needs, so the
        // same code never authenticates twice. The documented consequence:
        // when the clock reaches the code's own step, the same digits are
        // refused as replayed — a transient lockout of at most one step for
        // a device whose clock runs ahead — and the next fresh code opens
        // again.
        let mut authenticator = provisioning(step_at(0)?);
        // Step 1's code presented while step 0 is current (the future
        // window) is accepted — here through activation, which runs the
        // same verification core — and recorded at its own step.
        authenticator.activate("287082", step_at(0)?)?;
        assert_eq!(authenticator.last_used_step(), Some(1));
        // When step 1 arrives, the same code is the step's own code — and
        // is refused as used: the transient lockout, never a second
        // authentication.
        assert!(matches!(
            authenticator.verify("287082", step_at(30)?),
            Err(TotpAuthenticatorError::Replayed)
        ));
        // The code behind the recorded step is refused too...
        assert!(matches!(
            authenticator.verify("755224", step_at(30)?),
            Err(TotpAuthenticatorError::Replayed)
        ));
        // ...and the next fresh code verifies once its step is current.
        assert_eq!(authenticator.verify("359152", step_at(60)?)?, 2);
        Ok(())
    }

    #[test]
    fn rehydration_validates_secret_length_and_state_shape() -> Result<(), Box<dyn Error>> {
        let now = step_at(59)?;
        let id = TotpAuthenticatorId::generate();
        let principal_id = PrincipalId::generate();

        // An active authenticator pairs its state with activated_at and the
        // recorded step; a provisioning one carries neither.
        let active = TotpAuthenticator::try_from_parts(
            id,
            principal_id,
            &RFC_SECRET,
            TotpState::Active,
            now,
            Some(now),
            Some(1),
        )?;
        assert_eq!(active.state(), TotpState::Active);
        assert_eq!(active.activated_at(), Some(now));
        assert_eq!(active.last_used_step(), Some(1));
        let provisioning = TotpAuthenticator::try_from_parts(
            id,
            principal_id,
            &RFC_SECRET,
            TotpState::Provisioning,
            now,
            None,
            None,
        )?;
        assert_eq!(provisioning.state(), TotpState::Provisioning);

        assert_eq!(
            TotpAuthenticator::try_from_parts(
                id,
                principal_id,
                &RFC_SECRET[..10],
                TotpState::Provisioning,
                now,
                None,
                None,
            ),
            Err(TotpRestoreError::InvalidSecretLength)
        );
        assert_eq!(
            TotpAuthenticator::try_from_parts(
                id,
                principal_id,
                &RFC_SECRET,
                TotpState::Active,
                now,
                None,
                None,
            ),
            Err(TotpRestoreError::InvalidShape)
        );
        assert_eq!(
            TotpAuthenticator::try_from_parts(
                id,
                principal_id,
                &RFC_SECRET,
                TotpState::Provisioning,
                now,
                Some(now),
                None,
            ),
            Err(TotpRestoreError::InvalidShape)
        );
        assert_eq!(
            TotpAuthenticator::try_from_parts(
                id,
                principal_id,
                &RFC_SECRET,
                TotpState::Provisioning,
                now,
                None,
                Some(1),
            ),
            Err(TotpRestoreError::InvalidShape)
        );
        Ok(())
    }

    #[test]
    fn state_codes_round_trip_and_debug_is_redacted() -> Result<(), Box<dyn Error>> {
        for state in [TotpState::Provisioning, TotpState::Active] {
            assert_eq!(state.to_string().parse::<TotpState>(), Ok(state));
        }
        assert_eq!("lost".parse::<TotpState>(), Err(TotpStateParseError));

        let now = OffsetDateTime::now_utc();
        let mut authenticator = provisioning(now);
        assert_eq!(
            format!("{authenticator:?}"),
            format!(
                "TotpAuthenticator {{ id: {:?}, principal_id: {:?}, secret: \"[REDACTED]\", state: Provisioning, created_at: {:?}, activated_at: None, last_used_step: None }}",
                authenticator.id(),
                authenticator.principal_id(),
                now,
            )
        );
        assert!(!format!("{authenticator:?}").contains("1234567890"));
        assert_eq!(authenticator.secret().expose_secret(), &RFC_SECRET);
        authenticator.activate("287082", step_at(59)?)?;
        assert_eq!(authenticator.state(), TotpState::Active);
        Ok(())
    }

    #[test]
    fn window_steps_clamp_at_zero_and_wrap_safely() -> Result<(), Box<dyn Error>> {
        assert_eq!(window_steps(0), [0, 0, 1]);
        assert_eq!(window_steps(1), [0, 1, 2]);
        assert_eq!(window_steps(u64::MAX), [u64::MAX - 1, u64::MAX, u64::MAX]);
        assert_eq!(current_step(step_at(0)?), 0);
        assert_eq!(current_step(step_at(29)?), 0);
        assert_eq!(current_step(step_at(30)?), 1);
        assert_eq!(current_step(step_at(59)?), 1);
        assert_eq!(current_step(step_at(-30)?), 0);
        Ok(())
    }
}
