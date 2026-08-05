use std::{error::Error, fmt, str::FromStr};

use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use crate::{CredentialId, EndpointAddress, EndpointId};

const FINGERPRINT_LENGTH: usize = 32;
const MAX_DISPLAY_NAME_CHARS: usize = 128;
const MAX_CERTIFICATE_DER_BYTES: usize = 1024 * 1024;

/// A normalized human-readable label for one managed Redfish endpoint.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EndpointDisplayName(String);

impl EndpointDisplayName {
    /// Validates and normalizes an endpoint label.
    ///
    /// # Errors
    ///
    /// Returns [`EndpointDisplayNameError`] for an empty label, a control
    /// character, or a label longer than 128 Unicode scalar values.
    pub fn parse(value: &str) -> Result<Self, EndpointDisplayNameError> {
        let normalized = value.trim();
        if normalized.is_empty() {
            return Err(EndpointDisplayNameError::Empty);
        }
        if normalized.chars().any(char::is_control) {
            return Err(EndpointDisplayNameError::ControlCharacter);
        }
        let actual = normalized.chars().count();
        if actual > MAX_DISPLAY_NAME_CHARS {
            return Err(EndpointDisplayNameError::TooLong {
                actual,
                maximum: MAX_DISPLAY_NAME_CHARS,
            });
        }
        Ok(Self(normalized.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for EndpointDisplayName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for EndpointDisplayName {
    type Err = EndpointDisplayNameError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

/// Why an endpoint label cannot be used.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EndpointDisplayNameError {
    Empty,
    ControlCharacter,
    TooLong { actual: usize, maximum: usize },
}

impl fmt::Display for EndpointDisplayNameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("endpoint display name cannot be empty"),
            Self::ControlCharacter => {
                formatter.write_str("endpoint display name cannot contain control characters")
            }
            Self::TooLong { actual, maximum } => write!(
                formatter,
                "endpoint display name has {actual} characters; maximum is {maximum}"
            ),
        }
    }
}

impl Error for EndpointDisplayNameError {}

/// A SHA-256 identity for an explicitly pinned leaf certificate.
#[repr(transparent)]
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CertificateFingerprint([u8; FINGERPRINT_LENGTH]);

impl CertificateFingerprint {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; FINGERPRINT_LENGTH]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; FINGERPRINT_LENGTH] {
        &self.0
    }

    #[must_use]
    pub const fn into_bytes(self) -> [u8; FINGERPRINT_LENGTH] {
        self.0
    }
}

impl fmt::Display for CertificateFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, byte) in self.0.iter().enumerate() {
            if index > 0 {
                formatter.write_str(":")?;
            }
            write!(formatter, "{byte:02X}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for CertificateFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

/// A TLS leaf certificate and its verified SHA-256 identity.
#[derive(Clone, Eq, PartialEq)]
pub struct TlsCertificate {
    fingerprint: CertificateFingerprint,
    certificate_der: Vec<u8>,
}

impl TlsCertificate {
    /// Computes the identity of certificate DER received from a TLS handshake.
    ///
    /// # Errors
    ///
    /// Returns [`TlsCertificateError`] when the DER is empty or exceeds the
    /// one-megabyte defensive storage limit.
    pub fn from_der(certificate_der: Vec<u8>) -> Result<Self, TlsCertificateError> {
        validate_certificate_length(&certificate_der)?;
        Ok(Self {
            fingerprint: fingerprint(&certificate_der),
            certificate_der,
        })
    }

    /// Reconstructs a pin from persistence and verifies its redundant identity.
    ///
    /// # Errors
    ///
    /// Returns [`TlsCertificateError`] when the DER length is invalid or its
    /// computed SHA-256 identity differs from the persisted fingerprint.
    pub fn from_parts(
        fingerprint: CertificateFingerprint,
        certificate_der: Vec<u8>,
    ) -> Result<Self, TlsCertificateError> {
        validate_certificate_length(&certificate_der)?;
        if fingerprint != self::fingerprint(&certificate_der) {
            return Err(TlsCertificateError::FingerprintMismatch);
        }
        Ok(Self {
            fingerprint,
            certificate_der,
        })
    }

    #[must_use]
    pub const fn fingerprint(&self) -> CertificateFingerprint {
        self.fingerprint
    }

    #[must_use]
    pub fn certificate_der(&self) -> &[u8] {
        &self.certificate_der
    }

    #[must_use]
    pub fn into_parts(self) -> (CertificateFingerprint, Vec<u8>) {
        (self.fingerprint, self.certificate_der)
    }
}

impl fmt::Debug for TlsCertificate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TlsCertificate")
            .field("fingerprint", &self.fingerprint)
            .field("certificate_der_bytes", &self.certificate_der.len())
            .finish()
    }
}

/// Why a pinned certificate cannot become trusted product state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsCertificateError {
    Empty,
    TooLarge { actual: usize, maximum: usize },
    FingerprintMismatch,
}

impl fmt::Display for TlsCertificateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("TLS certificate DER cannot be empty"),
            Self::TooLarge { actual, maximum } => write!(
                formatter,
                "TLS certificate DER has {actual} bytes; maximum is {maximum}"
            ),
            Self::FingerprintMismatch => {
                formatter.write_str("TLS certificate fingerprint does not match its DER")
            }
        }
    }
}

impl Error for TlsCertificateError {}

/// The explicit trust decision made before any BMC credential is transmitted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TlsTrust {
    SystemCa {
        certificate: TlsCertificate,
        verified_at: OffsetDateTime,
    },
    PinnedCertificate {
        certificate: TlsCertificate,
        trusted_at: OffsetDateTime,
    },
}

impl TlsTrust {
    #[must_use]
    pub const fn established_at(&self) -> OffsetDateTime {
        match self {
            Self::SystemCa { verified_at, .. } => *verified_at,
            Self::PinnedCertificate { trusted_at, .. } => *trusted_at,
        }
    }

    /// Borrows the leaf certificate identity approved by this trust decision.
    #[must_use]
    pub const fn certificate(&self) -> &TlsCertificate {
        match self {
            Self::SystemCa { certificate, .. } | Self::PinnedCertificate { certificate, .. } => {
                certificate
            }
        }
    }
}

/// A fully validated, secret-free managed Redfish endpoint aggregate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Endpoint {
    id: EndpointId,
    display_name: EndpointDisplayName,
    address: EndpointAddress,
    trust: TlsTrust,
    credential_id: CredentialId,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

impl Endpoint {
    /// Constructs an endpoint while enforcing trust and timestamp ordering.
    ///
    /// # Errors
    ///
    /// Returns [`EndpointTimelineError`] when the endpoint update time precedes
    /// creation or trust was established outside the endpoint timeline.
    pub fn try_new(
        id: EndpointId,
        display_name: EndpointDisplayName,
        address: EndpointAddress,
        trust: TlsTrust,
        credential_id: CredentialId,
        created_at: OffsetDateTime,
        updated_at: OffsetDateTime,
    ) -> Result<Self, EndpointTimelineError> {
        let trust_established_at = trust.established_at();
        if updated_at < created_at
            || trust_established_at < created_at
            || trust_established_at > updated_at
        {
            return Err(EndpointTimelineError);
        }
        Ok(Self {
            id,
            display_name,
            address,
            trust,
            credential_id,
            created_at,
            updated_at,
        })
    }

    #[must_use]
    pub const fn id(&self) -> EndpointId {
        self.id
    }

    #[must_use]
    pub const fn display_name(&self) -> &EndpointDisplayName {
        &self.display_name
    }

    #[must_use]
    pub const fn address(&self) -> &EndpointAddress {
        &self.address
    }

    #[must_use]
    pub const fn trust(&self) -> &TlsTrust {
        &self.trust
    }

    #[must_use]
    pub const fn credential_id(&self) -> CredentialId {
        self.credential_id
    }

    #[must_use]
    pub const fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    #[must_use]
    pub const fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }
}

/// Persisted endpoint timestamps violate aggregate ordering.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EndpointTimelineError;

impl fmt::Display for EndpointTimelineError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(
            "endpoint update cannot precede creation and trust must fall within its timeline",
        )
    }
}

impl Error for EndpointTimelineError {}

fn validate_certificate_length(certificate_der: &[u8]) -> Result<(), TlsCertificateError> {
    if certificate_der.is_empty() {
        return Err(TlsCertificateError::Empty);
    }
    if certificate_der.len() > MAX_CERTIFICATE_DER_BYTES {
        return Err(TlsCertificateError::TooLarge {
            actual: certificate_der.len(),
            maximum: MAX_CERTIFICATE_DER_BYTES,
        });
    }
    Ok(())
}

fn fingerprint(certificate_der: &[u8]) -> CertificateFingerprint {
    CertificateFingerprint(Sha256::digest(certificate_der).into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_endpoint_labels() -> Result<(), EndpointDisplayNameError> {
        let name = "  Rack A BMC  ".parse::<EndpointDisplayName>()?;
        assert_eq!(name.as_str(), "Rack A BMC");
        assert_eq!(name.to_string(), "Rack A BMC");
        Ok(())
    }

    #[test]
    fn rejects_invalid_endpoint_labels_with_actionable_errors() {
        assert_eq!(
            EndpointDisplayName::parse("  "),
            Err(EndpointDisplayNameError::Empty)
        );
        assert_eq!(
            EndpointDisplayName::parse("rack\nBMC"),
            Err(EndpointDisplayNameError::ControlCharacter)
        );
        assert_eq!(
            EndpointDisplayName::parse(&"界".repeat(MAX_DISPLAY_NAME_CHARS + 1)),
            Err(EndpointDisplayNameError::TooLong {
                actual: MAX_DISPLAY_NAME_CHARS + 1,
                maximum: MAX_DISPLAY_NAME_CHARS,
            })
        );
        assert_eq!(
            EndpointDisplayNameError::Empty.to_string(),
            "endpoint display name cannot be empty"
        );
        assert_eq!(
            EndpointDisplayNameError::ControlCharacter.to_string(),
            "endpoint display name cannot contain control characters"
        );
        assert_eq!(
            EndpointDisplayNameError::TooLong {
                actual: 129,
                maximum: 128,
            }
            .to_string(),
            "endpoint display name has 129 characters; maximum is 128"
        );
    }

    #[test]
    fn computes_and_formats_a_certificate_identity() -> Result<(), TlsCertificateError> {
        let certificate = TlsCertificate::from_der(b"abc".to_vec())?;
        assert_eq!(
            certificate.fingerprint().to_string(),
            "BA:78:16:BF:8F:01:CF:EA:41:41:40:DE:5D:AE:22:23:B0:03:61:A3:96:17:7A:9C:B4:10:FF:61:F2:00:15:AD"
        );
        assert_eq!(certificate.certificate_der(), b"abc");
        assert_eq!(
            format!("{:?}", certificate.fingerprint()),
            certificate.fingerprint().to_string()
        );
        assert_eq!(
            format!("{certificate:?}"),
            format!(
                "TlsCertificate {{ fingerprint: {:?}, certificate_der_bytes: 3 }}",
                certificate.fingerprint()
            )
        );

        let fingerprint_bytes = certificate.fingerprint().into_bytes();
        let fingerprint = CertificateFingerprint::from_bytes(fingerprint_bytes);
        assert_eq!(fingerprint.as_bytes(), &fingerprint_bytes);

        let (fingerprint, certificate_der) = certificate.into_parts();
        let reconstructed = TlsCertificate::from_parts(fingerprint, certificate_der)?;
        assert_eq!(reconstructed.certificate_der(), b"abc");
        Ok(())
    }

    #[test]
    fn rejects_mismatched_or_unbounded_certificate_data() {
        let mismatch = TlsCertificate::from_parts(
            CertificateFingerprint::from_bytes([0_u8; FINGERPRINT_LENGTH]),
            b"certificate".to_vec(),
        );
        assert_eq!(mismatch, Err(TlsCertificateError::FingerprintMismatch));
        assert_eq!(
            TlsCertificate::from_der(Vec::new()),
            Err(TlsCertificateError::Empty)
        );
        assert!(matches!(
            TlsCertificate::from_der(vec![0_u8; MAX_CERTIFICATE_DER_BYTES + 1]),
            Err(TlsCertificateError::TooLarge {
                actual: 1_048_577,
                maximum: 1_048_576,
            })
        ));
        assert_eq!(
            TlsCertificateError::Empty.to_string(),
            "TLS certificate DER cannot be empty"
        );
        assert_eq!(
            TlsCertificateError::TooLarge {
                actual: 1_048_577,
                maximum: 1_048_576,
            }
            .to_string(),
            "TLS certificate DER has 1048577 bytes; maximum is 1048576"
        );
        assert_eq!(
            TlsCertificateError::FingerprintMismatch.to_string(),
            "TLS certificate fingerprint does not match its DER"
        );
    }

    #[test]
    fn constructs_a_secret_free_endpoint_aggregate() -> Result<(), Box<dyn Error>> {
        let now = OffsetDateTime::now_utc();
        let id = EndpointId::generate();
        let credential_id = CredentialId::generate();
        let display_name = EndpointDisplayName::parse("Rack A BMC")?;
        let address = EndpointAddress::parse("https://192.0.2.10/redfish")?;
        let trust = TlsTrust::SystemCa {
            certificate: TlsCertificate::from_der(b"leaf certificate".to_vec())?,
            verified_at: now,
        };
        let endpoint = Endpoint::try_new(
            id,
            display_name.clone(),
            address.clone(),
            trust.clone(),
            credential_id,
            now,
            now,
        )?;

        assert_eq!(endpoint.id(), id);
        assert_eq!(endpoint.display_name(), &display_name);
        assert_eq!(endpoint.address(), &address);
        assert_eq!(endpoint.trust(), &trust);
        assert_eq!(endpoint.trust().established_at(), now);
        assert_eq!(
            endpoint.trust().certificate().certificate_der(),
            b"leaf certificate"
        );
        assert_eq!(endpoint.credential_id(), credential_id);
        assert_eq!(endpoint.created_at(), now);
        assert_eq!(endpoint.updated_at(), now);
        Ok(())
    }

    #[test]
    fn exposes_the_pinned_trust_establishment_time() -> Result<(), TlsCertificateError> {
        let trusted_at = OffsetDateTime::now_utc();
        let trust = TlsTrust::PinnedCertificate {
            certificate: TlsCertificate::from_der(b"leaf certificate".to_vec())?,
            trusted_at,
        };
        assert_eq!(trust.established_at(), trusted_at);
        Ok(())
    }

    #[test]
    fn rejects_endpoint_state_that_predates_creation() -> Result<(), Box<dyn Error>> {
        let created_at = OffsetDateTime::now_utc();
        let trust = TlsTrust::SystemCa {
            certificate: TlsCertificate::from_der(b"leaf certificate".to_vec())?,
            verified_at: created_at - time::Duration::SECOND,
        };
        let endpoint = Endpoint::try_new(
            EndpointId::generate(),
            EndpointDisplayName::parse("Rack A BMC")?,
            EndpointAddress::parse("https://192.0.2.10")?,
            trust,
            CredentialId::generate(),
            created_at,
            created_at,
        );
        assert_eq!(endpoint, Err(EndpointTimelineError));

        let endpoint = Endpoint::try_new(
            EndpointId::generate(),
            EndpointDisplayName::parse("Rack A BMC")?,
            EndpointAddress::parse("https://192.0.2.10")?,
            TlsTrust::SystemCa {
                certificate: TlsCertificate::from_der(b"leaf certificate".to_vec())?,
                verified_at: created_at + time::Duration::SECOND,
            },
            CredentialId::generate(),
            created_at,
            created_at,
        );
        assert_eq!(endpoint, Err(EndpointTimelineError));

        let endpoint = Endpoint::try_new(
            EndpointId::generate(),
            EndpointDisplayName::parse("Rack A BMC")?,
            EndpointAddress::parse("https://192.0.2.10")?,
            TlsTrust::SystemCa {
                certificate: TlsCertificate::from_der(b"leaf certificate".to_vec())?,
                verified_at: created_at,
            },
            CredentialId::generate(),
            created_at,
            created_at - time::Duration::SECOND,
        );
        assert_eq!(endpoint, Err(EndpointTimelineError));
        assert_eq!(
            EndpointTimelineError.to_string(),
            "endpoint update cannot precede creation and trust must fall within its timeline"
        );
        Ok(())
    }
}
