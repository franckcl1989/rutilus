//! The unified persisted firmware artifact model (§9.3, §14.3).
//!
//! An artifact is the manifest of one firmware file uploaded for a §14.3
//! firmware update: identity, normalized label, declared size, the SHA-256
//! digest the complete file must match, and how many bytes have been received
//! so far. The file bytes themselves never live in the domain — per §7.2 the
//! domain carries no storage path and no OS API; persistence derives the
//! on-disk location (`artifact_file_path`) and the application upload use
//! case performs the actual file I/O under `spawn_blocking` (§7.8).
//!
//! The lifecycle is driven exclusively by the three mutating methods on
//! [`Artifact`] (`record_bytes_received`, `mark_ready`, `mark_failed`); there
//! is no other path that changes progress or state (§7.1). A string stored in
//! the database is rehydrated with [`Artifact::try_from_parts`], but changing
//! it still requires the same invariants.

use std::{error::Error, fmt, str::FromStr};

use time::OffsetDateTime;

use crate::ArtifactId;

const SHA256_DIGEST_LENGTH: usize = 32;
const SHA256_HEX_LENGTH: usize = SHA256_DIGEST_LENGTH * 2;
const MAX_ARTIFACT_NAME_CHARS: usize = 128;
const HEX_DIGITS: [u8; 16] = *b"0123456789abcdef";

/// A SHA-256 content digest of an artifact file, in canonical lowercase hex.
///
/// This is its own type rather than a reuse of
/// [`crate::CertificateFingerprint`]: that type stores a TLS certificate
/// identity whose text form is 32 colon-separated uppercase bytes, while the
/// §14.3 flow declares a plain 64-character lowercase hex digest (the api
/// `CreateArtifactRequest.sha256` wire contract). Reusing the fingerprint
/// would force the upload protocol into the fingerprint's wire shape.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Sha256Hex(String);

impl Sha256Hex {
    /// Validates and normalizes a textual SHA-256 digest.
    ///
    /// Both hex cases are accepted and normalized to lowercase, so equality
    /// and hashing never depend on the case a caller happened to use; the
    /// persisted and wire forms are always the canonical lowercase spelling.
    ///
    /// # Errors
    ///
    /// Returns [`Sha256HexParseError`] when the value is not exactly 64
    /// hexadecimal digits.
    pub fn parse(value: &str) -> Result<Self, Sha256HexParseError> {
        let bytes = value.as_bytes();
        if bytes.len() != SHA256_HEX_LENGTH {
            return Err(Sha256HexParseError::InvalidLength {
                actual: bytes.len(),
                expected: SHA256_HEX_LENGTH,
            });
        }
        let mut normalized = String::with_capacity(SHA256_HEX_LENGTH);
        for byte in bytes {
            let digit = decode_hex_digit(*byte).ok_or(Sha256HexParseError::InvalidEncoding)?;
            normalized.push(char::from(HEX_DIGITS[usize::from(digit)]));
        }
        Ok(Self(normalized))
    }

    /// Encodes a raw 32-byte SHA-256 digest in canonical lowercase hex.
    ///
    /// This is the entry point for the upload use case: the file is hashed
    /// under `spawn_blocking` (§7.8) and the resulting digest is compared
    /// with the declared value before [`Artifact::mark_ready`].
    #[must_use]
    pub fn from_bytes(digest: [u8; SHA256_DIGEST_LENGTH]) -> Self {
        let mut encoded = String::with_capacity(SHA256_HEX_LENGTH);
        for byte in digest {
            encoded.push(char::from(HEX_DIGITS[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX_DIGITS[usize::from(byte & 0x0F)]));
        }
        Self(encoded)
    }

    /// Returns the canonical lowercase hex spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Decodes the digest back to its raw 32 bytes.
    ///
    /// The stored string is guaranteed canonical lowercase hex by the type
    /// invariant, so the decoding cannot fail.
    #[must_use]
    pub fn into_bytes(self) -> [u8; SHA256_DIGEST_LENGTH] {
        let bytes = self.0.as_bytes();
        let mut digest = [0_u8; SHA256_DIGEST_LENGTH];
        for (index, byte) in digest.iter_mut().enumerate() {
            let high = hex_digit_value(bytes[index * 2]);
            let low = hex_digit_value(bytes[index * 2 + 1]);
            *byte = (high << 4) | low;
        }
        digest
    }
}

impl fmt::Display for Sha256Hex {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for Sha256Hex {
    type Err = Sha256HexParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

/// Why a textual SHA-256 digest cannot be used for an artifact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Sha256HexParseError {
    InvalidLength { actual: usize, expected: usize },
    InvalidEncoding,
}

impl fmt::Display for Sha256HexParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength { actual, expected } => write!(
                formatter,
                "artifact SHA-256 digest has {actual} characters; expected {expected}"
            ),
            Self::InvalidEncoding => {
                formatter.write_str("artifact SHA-256 digest must be 64 hexadecimal digits")
            }
        }
    }
}

impl Error for Sha256HexParseError {}

/// A normalized human-readable label for one firmware artifact.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ArtifactName(String);

impl ArtifactName {
    /// Validates and normalizes an artifact label.
    ///
    /// # Errors
    ///
    /// Returns [`ArtifactNameError`] for an empty label, a control character,
    /// or a label longer than 128 Unicode scalar values.
    pub fn parse(value: &str) -> Result<Self, ArtifactNameError> {
        let normalized = value.trim();
        if normalized.is_empty() {
            return Err(ArtifactNameError::Empty);
        }
        if normalized.chars().any(char::is_control) {
            return Err(ArtifactNameError::ControlCharacter);
        }
        let actual = normalized.chars().count();
        if actual > MAX_ARTIFACT_NAME_CHARS {
            return Err(ArtifactNameError::TooLong {
                actual,
                maximum: MAX_ARTIFACT_NAME_CHARS,
            });
        }
        Ok(Self(normalized.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ArtifactName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for ArtifactName {
    type Err = ArtifactNameError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

/// Why an artifact label cannot be used.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactNameError {
    Empty,
    ControlCharacter,
    TooLong { actual: usize, maximum: usize },
}

impl fmt::Display for ArtifactNameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("artifact name cannot be empty"),
            Self::ControlCharacter => {
                formatter.write_str("artifact name cannot contain control characters")
            }
            Self::TooLong { actual, maximum } => write!(
                formatter,
                "artifact name has {actual} characters; maximum is {maximum}"
            ),
        }
    }
}

impl Error for ArtifactNameError {}

/// The lifecycle phase of one firmware artifact (§14.3).
///
/// The phase code returned by [`Self::as_str`] is the stable snake-case code
/// used by persistence and the api `ArtifactStateResponse` wire contract; it
/// never changes across milestones.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ArtifactState {
    /// Chunk uploads are still being received; the byte count below the
    /// declared size may be zero or partial, and an interrupted upload
    /// resumes from the persisted `uploaded_bytes` (§0.4.0 大文件断点和进度).
    Uploading,
    /// The complete byte range was received and its SHA-256 digest verified;
    /// the artifact is usable for a §14.3 firmware update.
    Ready,
    /// Verification of the received bytes failed or the upload was damaged;
    /// the artifact is unusable and the failure is explicit (§0.4.0
    /// acceptance: 固件上传中断可恢复或明确失败).
    Failed,
}

impl ArtifactState {
    /// Returns the stable product code used by persistence and protocols.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Uploading => "uploading",
            Self::Ready => "ready",
            Self::Failed => "failed",
        }
    }

    /// Reports whether the artifact lifecycle has finished.
    ///
    /// Terminal states absorb every mutation: after `Ready` or `Failed`, no
    /// further progress or state change is legal, which is what makes an
    /// interrupted upload recoverable — a finished verdict is never
    /// reopened.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Ready | Self::Failed)
    }
}

impl fmt::Display for ArtifactState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for ArtifactState {
    type Err = ArtifactStateParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "uploading" => Ok(Self::Uploading),
            "ready" => Ok(Self::Ready),
            "failed" => Ok(Self::Failed),
            _ => Err(ArtifactStateParseError),
        }
    }
}

/// A persisted artifact state is unknown to this product build.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArtifactStateParseError;

impl fmt::Display for ArtifactStateParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("unknown artifact state code")
    }
}

impl Error for ArtifactStateParseError {}

/// One persisted firmware artifact (§9.3, §14.3).
///
/// The state and progress are private and only change through the three
/// mutating methods, which enforce the lifecycle invariants: progress never
/// regresses, never exceeds the declared size, and a terminal state is never
/// reopened (§7.1). `sha256` is the digest the complete file must match,
/// declared before any byte is transferred (the api `CreateArtifactRequest`
/// contract); the upload use case verifies the stored file against it and
/// only then calls [`Artifact::mark_ready`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Artifact {
    id: ArtifactId,
    name: ArtifactName,
    size_bytes: u64,
    sha256: Sha256Hex,
    state: ArtifactState,
    uploaded_bytes: u64,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

impl Artifact {
    /// Declares a new artifact manifest before any byte is transferred.
    ///
    /// The artifact starts in [`ArtifactState::Uploading`] with zero bytes
    /// received; the caller supplies the declared size and the digest the
    /// complete file must match, both of which are facts of the manifest and
    /// never change afterwards. The update time equals the creation time
    /// until persistence records a write.
    #[must_use]
    pub fn new(
        id: ArtifactId,
        name: ArtifactName,
        size_bytes: u64,
        sha256: Sha256Hex,
        created_at: OffsetDateTime,
    ) -> Self {
        Self {
            id,
            name,
            size_bytes,
            sha256,
            state: ArtifactState::Uploading,
            uploaded_bytes: 0,
            created_at,
            updated_at: created_at,
        }
    }

    /// Rehydrates a persisted artifact record.
    ///
    /// This is the only way to construct an artifact in a non-`Uploading`
    /// state or with partial progress; it is reserved for persistence
    /// loading, which must accept whatever the database stored — but only
    /// what is internally consistent. A stored row with an inverted
    /// timeline, more bytes received than declared, or a `Ready` state with
    /// an incomplete upload is refused as a corrupt aggregate, mirroring the
    /// `Operation::try_from_parts` precedent. Mutations still go through the
    /// three lifecycle methods.
    ///
    /// # Errors
    ///
    /// Returns [`ArtifactRestoreError`] when the record violates the
    /// timeline, progress, or readiness invariants.
    ///
    /// The eight fields are all individually named facts of the persisted
    /// record; grouping them would hide the exact rehydration contract that
    /// mirrors the table columns, so the argument count is the accepted
    /// trade-off (same as `AuditOperationContext::try_new`).
    #[allow(clippy::too_many_arguments)]
    pub fn try_from_parts(
        id: ArtifactId,
        name: ArtifactName,
        size_bytes: u64,
        sha256: Sha256Hex,
        state: ArtifactState,
        uploaded_bytes: u64,
        created_at: OffsetDateTime,
        updated_at: OffsetDateTime,
    ) -> Result<Self, ArtifactRestoreError> {
        if updated_at < created_at {
            return Err(ArtifactRestoreError::InvalidTimeline);
        }
        if uploaded_bytes > size_bytes {
            return Err(ArtifactRestoreError::ProgressExceedsSize {
                uploaded: uploaded_bytes,
                size: size_bytes,
            });
        }
        if state == ArtifactState::Ready && uploaded_bytes != size_bytes {
            return Err(ArtifactRestoreError::ReadyBeforeCompleteUpload {
                uploaded: uploaded_bytes,
                size: size_bytes,
            });
        }
        Ok(Self {
            id,
            name,
            size_bytes,
            sha256,
            state,
            uploaded_bytes,
            created_at,
            updated_at,
        })
    }

    /// Records `received` newly transferred bytes.
    ///
    /// Progress only ever grows: the request is refused when it would push
    /// the received count past the declared size, or when the artifact has
    /// already finished. On error the artifact is left completely unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`ArtifactError::Terminal`] when the artifact already
    /// finished, or [`ArtifactError::ProgressExceedsSize`] when the request
    /// would exceed the declared size.
    pub fn record_bytes_received(&mut self, received: u64) -> Result<(), ArtifactError> {
        self.require_uploading()?;
        let Some(next) = self.uploaded_bytes.checked_add(received) else {
            return Err(ArtifactError::ProgressExceedsSize {
                uploaded: self.uploaded_bytes,
                received,
                size: self.size_bytes,
            });
        };
        if next > self.size_bytes {
            return Err(ArtifactError::ProgressExceedsSize {
                uploaded: self.uploaded_bytes,
                received,
                size: self.size_bytes,
            });
        }
        self.uploaded_bytes = next;
        Ok(())
    }

    /// Marks the artifact usable, which requires every byte to be received.
    ///
    /// `Ready` means the complete byte range was received and the stored
    /// file's SHA-256 matched the declared digest — the upload use case
    /// performs that verification and only then calls this method, so the
    /// invariant that a ready artifact holds its full content never depends
    /// on callers remembering the check.
    ///
    /// # Errors
    ///
    /// Returns [`ArtifactError::IncompleteUpload`] when not all bytes have
    /// been received yet, or [`ArtifactError::Terminal`] when the artifact
    /// already finished.
    pub fn mark_ready(&mut self) -> Result<(), ArtifactError> {
        self.require_uploading()?;
        if self.uploaded_bytes != self.size_bytes {
            return Err(ArtifactError::IncompleteUpload {
                uploaded: self.uploaded_bytes,
                size: self.size_bytes,
            });
        }
        self.state = ArtifactState::Ready;
        Ok(())
    }

    /// Marks the artifact failed because verification or the upload failed.
    ///
    /// # Errors
    ///
    /// Returns [`ArtifactError::Terminal`] when the artifact already
    /// finished; a finished verdict is never overwritten.
    pub fn mark_failed(&mut self) -> Result<(), ArtifactError> {
        self.require_uploading()?;
        self.state = ArtifactState::Failed;
        Ok(())
    }

    fn require_uploading(&self) -> Result<(), ArtifactError> {
        if self.state.is_terminal() {
            return Err(ArtifactError::Terminal { state: self.state });
        }
        Ok(())
    }

    #[must_use]
    pub const fn id(&self) -> ArtifactId {
        self.id
    }

    #[must_use]
    pub const fn name(&self) -> &ArtifactName {
        &self.name
    }

    /// Returns the declared file size in bytes.
    #[must_use]
    pub const fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    /// Returns the digest the complete file must match, cloned for the
    /// caller.
    #[must_use]
    pub fn sha256(&self) -> Sha256Hex {
        self.sha256.clone()
    }

    #[must_use]
    pub const fn state(&self) -> ArtifactState {
        self.state
    }

    /// Returns how many bytes have been received; the resume offset for an
    /// interrupted upload.
    #[must_use]
    pub const fn uploaded_bytes(&self) -> u64 {
        self.uploaded_bytes
    }

    #[must_use]
    pub const fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// Returns when progress or state last changed at the persistence
    /// boundary; equals `created_at` for a fresh artifact.
    #[must_use]
    pub const fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }

    /// Reports whether the artifact lifecycle has finished.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        self.state.is_terminal()
    }
}

/// A lifecycle step was attempted that the artifact invariants refuse (§7.1).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactError {
    /// The artifact already reached a terminal state and cannot be changed.
    Terminal { state: ArtifactState },
    /// The request would push the received byte count past the declared size.
    ProgressExceedsSize {
        uploaded: u64,
        received: u64,
        size: u64,
    },
    /// [`Artifact::mark_ready`] was attempted before every byte was received.
    IncompleteUpload { uploaded: u64, size: u64 },
}

impl fmt::Display for ArtifactError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Terminal { state } => write!(
                formatter,
                "artifact is in terminal state {state} and cannot be changed"
            ),
            Self::ProgressExceedsSize {
                uploaded,
                received,
                size,
            } => write!(
                formatter,
                "receiving {received} more bytes would push the artifact from {uploaded} past the declared size of {size}"
            ),
            Self::IncompleteUpload { uploaded, size } => write!(
                formatter,
                "artifact cannot become ready with only {uploaded} of {size} bytes received"
            ),
        }
    }
}

impl Error for ArtifactError {}

/// A persisted artifact record violates a domain invariant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactRestoreError {
    /// The stored update time precedes the stored creation time.
    InvalidTimeline,
    /// The stored received byte count exceeds the declared size.
    ProgressExceedsSize { uploaded: u64, size: u64 },
    /// The stored row is `Ready` without its complete byte range.
    ReadyBeforeCompleteUpload { uploaded: u64, size: u64 },
}

impl fmt::Display for ArtifactRestoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTimeline => {
                formatter.write_str("artifact update time cannot precede its creation time")
            }
            Self::ProgressExceedsSize { uploaded, size } => write!(
                formatter,
                "stored artifact progress of {uploaded} bytes exceeds the declared size of {size}"
            ),
            Self::ReadyBeforeCompleteUpload { uploaded, size } => write!(
                formatter,
                "stored artifact is ready with only {uploaded} of {size} bytes received"
            ),
        }
    }
}

impl Error for ArtifactRestoreError {}

/// Decodes one hex digit in either case.
fn decode_hex_digit(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

/// Decodes one hex digit from a string guaranteed lowercase by the
/// [`Sha256Hex`] type invariant; the fallback arm is unreachable on
/// type-valid input.
fn hex_digit_value(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        _ => value - b'a' + 10,
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use crate::ArtifactId;

    use super::*;

    /// Every state, so the invariant tests cannot silently miss a variant.
    const ALL_STATES: [ArtifactState; 3] = [
        ArtifactState::Uploading,
        ArtifactState::Ready,
        ArtifactState::Failed,
    ];

    /// The digest of a byte string of all 0xAB values, used to keep tests
    /// focused on lifecycle behavior rather than hash content.
    fn digest() -> Sha256Hex {
        Sha256Hex::from_bytes([0xAB; SHA256_DIGEST_LENGTH])
    }

    /// One uploading artifact of the given declared size.
    fn artifact(size_bytes: u64) -> Result<Artifact, ArtifactNameError> {
        Ok(Artifact::new(
            ArtifactId::generate(),
            ArtifactName::parse("firmware-2024.2.bin")?,
            size_bytes,
            digest(),
            OffsetDateTime::now_utc(),
        ))
    }

    #[test]
    fn state_codes_are_unique_non_empty_and_round_trip() {
        let mut seen = Vec::new();
        for state in ALL_STATES {
            let code = state.as_str();
            assert!(!code.is_empty(), "artifact state codes must not be empty");
            assert!(
                !seen.contains(&code),
                "product code {code} is used by more than one artifact state"
            );
            seen.push(code);
            assert_eq!(code.parse(), Ok(state));
            assert_eq!(state.to_string(), code);
        }
        assert_eq!(
            "paused".parse::<ArtifactState>(),
            Err(ArtifactStateParseError)
        );
    }

    #[test]
    fn ready_and_failed_are_terminal_and_uploading_is_active() {
        for terminal in [ArtifactState::Ready, ArtifactState::Failed] {
            assert!(terminal.is_terminal(), "state {terminal} must be terminal");
        }
        assert!(
            !ArtifactState::Uploading.is_terminal(),
            "uploading must not be terminal"
        );
    }

    #[test]
    fn name_validation_normalizes_and_rejects_bad_labels() -> Result<(), Box<dyn Error>> {
        let name = ArtifactName::parse("  BMC firmware 2024  ")?;
        assert_eq!(name.as_str(), "BMC firmware 2024");
        assert_eq!("  ".parse::<ArtifactName>(), Err(ArtifactNameError::Empty));
        assert_eq!(
            "firmware\n2024".parse::<ArtifactName>(),
            Err(ArtifactNameError::ControlCharacter)
        );
        assert!(matches!(
            ArtifactName::parse(&"n".repeat(MAX_ARTIFACT_NAME_CHARS + 1)),
            Err(ArtifactNameError::TooLong { .. })
        ));
        Ok(())
    }

    #[test]
    fn sha256_parses_both_cases_and_normalizes_to_lowercase() -> Result<(), Box<dyn Error>> {
        let upper = Sha256Hex::parse(&"AB".repeat(32))?;
        let lower = Sha256Hex::parse(&"ab".repeat(32))?;

        assert_eq!(upper, lower, "case must not affect digest equality");
        assert_eq!(upper.as_str(), &"ab".repeat(32));
        assert_eq!(lower.to_string(), "ab".repeat(32));
        assert_eq!(upper.to_string().parse::<Sha256Hex>()?, upper);
        assert_eq!(Sha256Hex::from_bytes([0xAB; 32]), upper);
        Ok(())
    }

    #[test]
    fn sha256_rejects_wrong_lengths_and_non_hex_characters() {
        assert_eq!(
            Sha256Hex::parse("ab"),
            Err(Sha256HexParseError::InvalidLength {
                actual: 2,
                expected: SHA256_HEX_LENGTH
            })
        );
        assert_eq!(
            Sha256Hex::parse(&("ab".repeat(32) + "x")),
            Err(Sha256HexParseError::InvalidLength {
                actual: 65,
                expected: SHA256_HEX_LENGTH
            })
        );
        assert_eq!(
            Sha256Hex::parse(&"g".repeat(64)),
            Err(Sha256HexParseError::InvalidEncoding)
        );
    }

    #[test]
    fn sha256_bytes_and_text_round_trip() {
        let mut bytes = [0x5A; 32];
        bytes[0] = 0x00;
        bytes[1] = 0x01;
        bytes[2] = 0xFE;
        bytes[3] = 0xFF;

        let digest = Sha256Hex::from_bytes(bytes);
        assert_eq!(digest.as_str().len(), SHA256_HEX_LENGTH);
        assert_eq!(digest.into_bytes(), bytes);
    }

    #[test]
    fn new_artifacts_start_uploading_with_zero_bytes() -> Result<(), Box<dyn Error>> {
        let created_at = OffsetDateTime::now_utc();
        let artifact = Artifact::new(
            ArtifactId::generate(),
            ArtifactName::parse("firmware.bin")?,
            1024,
            digest(),
            created_at,
        );

        assert_eq!(artifact.state(), ArtifactState::Uploading);
        assert!(!artifact.is_terminal());
        assert_eq!(artifact.uploaded_bytes(), 0);
        assert_eq!(artifact.size_bytes(), 1024);
        assert_eq!(artifact.sha256(), digest());
        assert_eq!(artifact.created_at(), created_at);
        assert_eq!(artifact.updated_at(), created_at);
        Ok(())
    }

    #[test]
    fn progress_grows_toward_the_declared_size() -> Result<(), Box<dyn Error>> {
        let mut artifact = artifact(100)?;
        artifact.record_bytes_received(40)?;
        assert_eq!(artifact.uploaded_bytes(), 40);
        assert_eq!(artifact.state(), ArtifactState::Uploading);
        artifact.record_bytes_received(60)?;
        assert_eq!(artifact.uploaded_bytes(), 100);
        Ok(())
    }

    #[test]
    fn progress_never_exceeds_the_declared_size_and_never_mutates_on_error()
    -> Result<(), Box<dyn Error>> {
        let mut artifact = artifact(100)?;
        artifact.record_bytes_received(60)?;
        assert_eq!(
            artifact.record_bytes_received(41),
            Err(ArtifactError::ProgressExceedsSize {
                uploaded: 60,
                received: 41,
                size: 100,
            })
        );
        assert_eq!(
            artifact.uploaded_bytes(),
            60,
            "a refused request must not change the artifact"
        );
        Ok(())
    }

    #[test]
    fn arithmetic_overflow_is_rejected_as_progress_beyond_size() -> Result<(), Box<dyn Error>> {
        let mut artifact = artifact(u64::MAX)?;
        artifact.record_bytes_received(u64::MAX - 1)?;
        assert_eq!(
            artifact.record_bytes_received(2),
            Err(ArtifactError::ProgressExceedsSize {
                uploaded: u64::MAX - 1,
                received: 2,
                size: u64::MAX,
            })
        );
        assert_eq!(artifact.uploaded_bytes(), u64::MAX - 1);
        Ok(())
    }

    #[test]
    fn mark_ready_requires_the_upload_to_be_complete() -> Result<(), Box<dyn Error>> {
        let mut artifact = artifact(100)?;
        artifact.record_bytes_received(99)?;
        assert_eq!(
            artifact.mark_ready(),
            Err(ArtifactError::IncompleteUpload {
                uploaded: 99,
                size: 100,
            })
        );
        assert_eq!(artifact.state(), ArtifactState::Uploading);

        artifact.record_bytes_received(1)?;
        artifact.mark_ready()?;
        assert_eq!(artifact.state(), ArtifactState::Ready);
        assert!(artifact.is_terminal());
        Ok(())
    }

    #[test]
    fn zero_byte_artifacts_can_become_ready_without_data() -> Result<(), Box<dyn Error>> {
        let mut artifact = artifact(0)?;
        artifact.mark_ready()?;
        assert_eq!(artifact.state(), ArtifactState::Ready);
        Ok(())
    }

    #[test]
    fn mark_failed_is_legal_from_uploading_only() -> Result<(), Box<dyn Error>> {
        let mut artifact = artifact(100)?;
        artifact.record_bytes_received(10)?;
        artifact.mark_failed()?;
        assert_eq!(artifact.state(), ArtifactState::Failed);
        assert!(artifact.is_terminal());
        Ok(())
    }

    #[test]
    fn terminal_artifacts_reject_every_mutation() -> Result<(), Box<dyn Error>> {
        let mut ready = artifact(10)?;
        ready.record_bytes_received(10)?;
        ready.mark_ready()?;
        assert_eq!(
            ready.record_bytes_received(1),
            Err(ArtifactError::Terminal {
                state: ArtifactState::Ready
            })
        );
        assert_eq!(
            ready.mark_ready(),
            Err(ArtifactError::Terminal {
                state: ArtifactState::Ready
            })
        );
        assert_eq!(
            ready.mark_failed(),
            Err(ArtifactError::Terminal {
                state: ArtifactState::Ready
            })
        );
        assert_eq!(ready.state(), ArtifactState::Ready);

        let mut failed = artifact(10)?;
        failed.mark_failed()?;
        assert_eq!(
            failed.mark_ready(),
            Err(ArtifactError::Terminal {
                state: ArtifactState::Failed
            })
        );
        assert_eq!(failed.state(), ArtifactState::Failed);
        Ok(())
    }

    #[test]
    fn rehydration_restores_persisted_progress_and_state() -> Result<(), Box<dyn Error>> {
        let created_at = OffsetDateTime::now_utc();
        let updated_at = created_at + time::Duration::SECOND;
        let name = ArtifactName::parse("firmware.bin")?;
        let restored = Artifact::try_from_parts(
            ArtifactId::generate(),
            name.clone(),
            100,
            digest(),
            ArtifactState::Uploading,
            40,
            created_at,
            updated_at,
        )?;

        assert_eq!(restored.name(), &name);
        assert_eq!(restored.uploaded_bytes(), 40);
        assert_eq!(restored.state(), ArtifactState::Uploading);
        assert_eq!(restored.created_at(), created_at);
        assert_eq!(restored.updated_at(), updated_at);
        Ok(())
    }

    #[test]
    fn rehydration_refuses_inconsistent_persisted_records() -> Result<(), Box<dyn Error>> {
        let created_at = OffsetDateTime::now_utc();
        let name = ArtifactName::parse("firmware.bin")?;
        let id = ArtifactId::generate();

        let inverted = created_at - time::Duration::SECOND;
        assert_eq!(
            Artifact::try_from_parts(
                id,
                name.clone(),
                100,
                digest(),
                ArtifactState::Uploading,
                0,
                created_at,
                inverted,
            ),
            Err(ArtifactRestoreError::InvalidTimeline)
        );
        assert_eq!(
            Artifact::try_from_parts(
                id,
                name.clone(),
                100,
                digest(),
                ArtifactState::Uploading,
                101,
                created_at,
                created_at,
            ),
            Err(ArtifactRestoreError::ProgressExceedsSize {
                uploaded: 101,
                size: 100,
            })
        );
        assert_eq!(
            Artifact::try_from_parts(
                id,
                name,
                100,
                digest(),
                ArtifactState::Ready,
                50,
                created_at,
                created_at,
            ),
            Err(ArtifactRestoreError::ReadyBeforeCompleteUpload {
                uploaded: 50,
                size: 100,
            })
        );
        Ok(())
    }
}
