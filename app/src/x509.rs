//! Bounded X.509 DER reading for the center connection layer (design §15).
//!
//! The center reads exactly two things out of a certificate:
//!
//! * the subject common name — the site instance id the center issued the
//!   certificate for, exposed by the acceptor's [`ClientIdentity`];
//! * the product's private-arc *site-identity extension*, which binds the
//!   site's own identity fingerprint to the issued client certificate at
//!   issuance time.
//!
//! This module is a deliberately small DER walker: it parses only the
//! concrete RFC 5280 `Certificate` structure down to those two fields,
//! rejects any deviation, and never allocates more than the input size.
//! The certificates it reads are the center's own CA-issued material, so
//! the strict walker doubles as a format guard for the issuance pipeline.
//!
//! The site-identity extension uses a private enterprise arc
//! (`1.3.6.1.4.1.59745.2.1`) reserved by this product; it is not an
//! IANA-registered arc, and its meaning is defined solely by this
//! implementation on both sides of the wire.
//!
//! [`ClientIdentity`]: crate::ClientIdentity

use rustls::pki_types::CertificateDer;
use rutilus_domain::CertificateFingerprint;
use thiserror::Error;

/// The X.520 OID of the common-name attribute type.
pub(crate) const CN_OID: &[u64] = &[2, 5, 4, 3];

/// The product's private-arc OID of the site-identity extension: a DER
/// OCTET STRING wrapping the site's own identity fingerprint, bound into
/// the client certificate at issuance.
pub(crate) const SITE_IDENTITY_EXTENSION_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 59745, 2, 1];

/// DER tags the walker recognizes.
const TAG_BOOLEAN: u8 = 0x01;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_OID: u8 = 0x06;
const TAG_UTF8_STRING: u8 = 0x0C;
const TAG_PRINTABLE_STRING: u8 = 0x13;
const TAG_IA5_STRING: u8 = 0x16;
const TAG_SEQUENCE: u8 = 0x30;
const TAG_SET: u8 = 0x31;
/// The context-tagged `[3]` extensions field of a `TBSCertificate`
/// (explicitly tagged `SEQUENCE OF Extension`).
const TAG_CONTEXT_3: u8 = 0xA3;

/// Why one certificate cannot be read.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum DerReadError {
    #[error("the DER input ends before the element is complete")]
    Truncated,
    #[error("the DER element uses an indefinite length")]
    IndefiniteLength,
    #[error("the DER length field uses more than 4 bytes")]
    LengthTooLarge,
    #[error("the DER element with tag {actual:02X} is not the expected {expected}")]
    UnexpectedTag { expected: &'static str, actual: u8 },
    #[error("the certificate has bytes after its top-level sequence")]
    TrailingBytes,
    #[error("an attribute is not an OID followed by one value")]
    MalformedAttribute,
    #[error("an OID component does not fit the wire encoding")]
    OidComponentTooLarge,
    #[error("an attribute value string of tag {tag:02X} is not supported")]
    UnsupportedStringTag { tag: u8 },
    #[error("an attribute value is not valid UTF-8: {0}")]
    InvalidUtf8(#[source] std::str::Utf8Error),
    #[error("the site-identity extension does not carry a 32-byte fingerprint")]
    FingerprintLength,
}

/// One parsed attribute of a certificate subject (an X.501
/// `AttributeTypeAndValue`).
pub(crate) struct SubjectAttribute {
    /// The attribute type OID components.
    pub(crate) oid: Vec<u64>,
    /// The attribute value, decoded as text.
    pub(crate) value: String,
}

/// One DER element: a tag, a definite length, and the element's content.
#[derive(Clone, Copy)]
struct Element<'a> {
    tag: u8,
    content: &'a [u8],
}

/// Reads one DER element (tag, definite length, content) and returns it
/// with the total number of consumed bytes.
fn read_element(der: &[u8]) -> Result<(Element<'_>, usize), DerReadError> {
    let Some((&tag, rest)) = der.split_first() else {
        return Err(DerReadError::Truncated);
    };
    let (content_length, length_bytes) = read_length(rest)?;
    let content_start = 1 + length_bytes;
    let content_end = content_start
        .checked_add(content_length)
        .ok_or(DerReadError::Truncated)?;
    let content = der
        .get(content_start..content_end)
        .ok_or(DerReadError::Truncated)?;
    Ok((Element { tag, content }, content_end))
}

/// Reads one DER definite length (short or long form, at most 4 length
/// bytes) and returns it with the number of length bytes consumed.
fn read_length(der: &[u8]) -> Result<(usize, usize), DerReadError> {
    let Some((&first, rest)) = der.split_first() else {
        return Err(DerReadError::Truncated);
    };
    if first & 0x80 == 0 {
        return Ok((usize::from(first), 1));
    }
    let count = usize::from(first & 0x7F);
    if count == 0 {
        return Err(DerReadError::IndefiniteLength);
    }
    if count > 4 {
        return Err(DerReadError::LengthTooLarge);
    }
    let bytes = rest.get(..count).ok_or(DerReadError::Truncated)?;
    let mut length = 0usize;
    for &byte in bytes {
        length = length
            .checked_mul(256)
            .and_then(|shifted| shifted.checked_add(usize::from(byte)))
            .ok_or(DerReadError::LengthTooLarge)?;
    }
    Ok((length, 1 + count))
}

/// Reads the children of one constructed element (SEQUENCE or SET).
fn read_children<'a>(element: &Element<'a>) -> Result<Vec<Element<'a>>, DerReadError> {
    if !matches!(element.tag, TAG_SEQUENCE | TAG_SET) {
        return Err(DerReadError::UnexpectedTag {
            expected: "SEQUENCE or SET",
            actual: element.tag,
        });
    }
    let mut children = Vec::new();
    let mut rest = element.content;
    while !rest.is_empty() {
        let (child, consumed) = read_element(rest)?;
        children.push(child);
        rest = &rest[consumed..];
    }
    Ok(children)
}

/// The `TBSCertificate` of one certificate: the first child of the
/// top-level `Certificate` sequence, which must consume the whole input.
fn tbs_certificate(der: &[u8]) -> Result<Element<'_>, DerReadError> {
    let (top, consumed) = read_element(der)?;
    if top.tag != TAG_SEQUENCE {
        return Err(DerReadError::UnexpectedTag {
            expected: "Certificate SEQUENCE",
            actual: top.tag,
        });
    }
    if consumed != der.len() {
        return Err(DerReadError::TrailingBytes);
    }
    let children = read_children(&top)?;
    let Some(tbs) = children.first() else {
        return Err(DerReadError::Truncated);
    };
    if tbs.tag != TAG_SEQUENCE {
        return Err(DerReadError::UnexpectedTag {
            expected: "TBSCertificate SEQUENCE",
            actual: tbs.tag,
        });
    }
    Ok(*tbs)
}

/// Parses the subject of one certificate into its attribute list, in
/// subject order.
///
/// # Errors
///
/// Returns [`DerReadError`] when the certificate structure deviates from
/// the RFC 5280 shape the walker understands.
pub(crate) fn subject_attributes(
    certificate: &CertificateDer<'_>,
) -> Result<Vec<SubjectAttribute>, DerReadError> {
    let tbs = tbs_certificate(certificate.as_ref())?;
    let fields = read_children(&tbs)?;
    // RFC 5280 A.1: the TBSCertificate fields are version, serialNumber,
    // signature, issuer, validity, subject, subjectPublicKeyInfo, and the
    // optional unique-identifier and extensions fields. The subject is
    // therefore the fourth SEQUENCE field; everything else (including the
    // extensions, context-tagged `[3]`) is filtered out below.
    let mut subject: Option<Element<'_>> = None;
    let mut sequence_index = 0usize;
    for field in &fields {
        if field.tag != TAG_SEQUENCE {
            continue;
        }
        if sequence_index == 3 {
            subject = Some(*field);
            break;
        }
        sequence_index += 1;
    }
    let Some(subject) = subject else {
        return Ok(Vec::new());
    };
    let mut attributes = Vec::new();
    for member in read_children(&subject)? {
        // RDN ::= SET OF AttributeTypeAndValue
        if member.tag != TAG_SET {
            return Err(DerReadError::UnexpectedTag {
                expected: "RDN SET",
                actual: member.tag,
            });
        }
        for attribute in read_children(&member)? {
            let parts = read_children(&attribute)?;
            let [oid, value] = parts.as_slice() else {
                return Err(DerReadError::MalformedAttribute);
            };
            if oid.tag != TAG_OID {
                return Err(DerReadError::UnexpectedTag {
                    expected: "attribute type OID",
                    actual: oid.tag,
                });
            }
            attributes.push(SubjectAttribute {
                oid: decode_oid(oid.content)?,
                value: string_value(value)?,
            });
        }
    }
    Ok(attributes)
}

/// The subject common name of one certificate, when present.
///
/// # Errors
///
/// Returns [`DerReadError`] when the certificate structure deviates from
/// the RFC 5280 shape the walker understands.
pub(crate) fn subject_common_name(
    certificate: &CertificateDer<'_>,
) -> Result<Option<String>, DerReadError> {
    for attribute in subject_attributes(certificate)? {
        if attribute.oid.as_slice() == CN_OID {
            return Ok(Some(attribute.value));
        }
    }
    Ok(None)
}

/// Decodes one OBJECT IDENTIFIER content into its component arcs.
fn decode_oid(content: &[u8]) -> Result<Vec<u64>, DerReadError> {
    let Some((&first, rest)) = content.split_first() else {
        return Err(DerReadError::Truncated);
    };
    // The first content byte encodes the first two arcs as 40 * arc0 +
    // arc1.
    let mut components = vec![u64::from(first / 40), u64::from(first % 40)];
    let mut pending = 0u64;
    let mut continuation = false;
    for &byte in rest {
        pending = pending
            .checked_mul(128)
            .and_then(|shifted| shifted.checked_add(u64::from(byte & 0x7F)))
            .ok_or(DerReadError::OidComponentTooLarge)?;
        continuation = true;
        if byte & 0x80 == 0 {
            components.push(pending);
            pending = 0;
            continuation = false;
        }
    }
    if continuation {
        // A base-128 run without its final byte.
        return Err(DerReadError::Truncated);
    }
    Ok(components)
}

/// Reads one attribute value: the string types rcgen writes for
/// distinguished-name attributes.
fn string_value(element: &Element<'_>) -> Result<String, DerReadError> {
    match element.tag {
        TAG_UTF8_STRING | TAG_PRINTABLE_STRING | TAG_IA5_STRING => {}
        tag => return Err(DerReadError::UnsupportedStringTag { tag }),
    }
    std::str::from_utf8(element.content)
        .map(str::to_owned)
        .map_err(DerReadError::InvalidUtf8)
}

/// Reads the value of the extension with the given OID, when present. The
/// returned bytes are the extension's `extnValue` OCTET STRING content
/// (the DER encoding of the extension value).
fn extension_value(
    certificate: &CertificateDer<'_>,
    oid: &[u64],
) -> Result<Option<Vec<u8>>, DerReadError> {
    let tbs = tbs_certificate(certificate.as_ref())?;
    let fields = read_children(&tbs)?;
    let Some(extensions) = fields.iter().find(|field| field.tag == TAG_CONTEXT_3) else {
        return Ok(None);
    };
    // The `[3]` field is explicitly tagged: its content is the DER of the
    // extensions SEQUENCE.
    let (extension_sequence, consumed) = read_element(extensions.content)?;
    if extension_sequence.tag != TAG_SEQUENCE {
        return Err(DerReadError::UnexpectedTag {
            expected: "extensions SEQUENCE",
            actual: extension_sequence.tag,
        });
    }
    if consumed != extensions.content.len() {
        return Err(DerReadError::TrailingBytes);
    }
    for extension in read_children(&extension_sequence)? {
        // Extension ::= SEQUENCE { extnID OID, critical BOOLEAN DEFAULT
        // FALSE, extnValue OCTET STRING }
        let parts = read_children(&extension)?;
        let mut parts = parts.iter();
        let Some(extension_oid) = parts.next() else {
            return Err(DerReadError::Truncated);
        };
        if extension_oid.tag != TAG_OID {
            return Err(DerReadError::UnexpectedTag {
                expected: "extension type OID",
                actual: extension_oid.tag,
            });
        }
        let mut value: Option<&Element<'_>> = None;
        for part in parts {
            match part.tag {
                TAG_BOOLEAN => {}
                TAG_OCTET_STRING => value = Some(part),
                actual => {
                    return Err(DerReadError::UnexpectedTag {
                        expected: "extension critical BOOLEAN or value OCTET STRING",
                        actual,
                    });
                }
            }
        }
        if decode_oid(extension_oid.content)?.as_slice() == oid {
            return Ok(value.map(|element| element.content.to_vec()));
        }
    }
    Ok(None)
}

/// The site-identity fingerprint of one certificate: the content of the
/// product's site-identity extension, when present. The extension value is
/// the DER encoding of one OCTET STRING wrapping the 32 fingerprint bytes.
///
/// # Errors
///
/// Returns [`DerReadError`] when the extension is present but not shaped
/// as the issuance pipeline writes it.
pub(crate) fn site_identity_fingerprint(
    certificate: &CertificateDer<'_>,
) -> Result<Option<CertificateFingerprint>, DerReadError> {
    let Some(content) = extension_value(certificate, SITE_IDENTITY_EXTENSION_OID)? else {
        return Ok(None);
    };
    let (value, consumed) = read_element(&content)?;
    if value.tag != TAG_OCTET_STRING {
        return Err(DerReadError::UnexpectedTag {
            expected: "site-identity OCTET STRING",
            actual: value.tag,
        });
    }
    if consumed != content.len() {
        return Err(DerReadError::TrailingBytes);
    }
    let bytes: [u8; 32] = value
        .content
        .try_into()
        .map_err(|_| DerReadError::FingerprintLength)?;
    Ok(Some(CertificateFingerprint::from_bytes(bytes)))
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::*;

    /// A certificate fixture: a CA certificate with the single common name
    /// the center CA generation writes.
    fn fixture_ca() -> Result<CertificateDer<'static>, Box<dyn Error>> {
        use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};

        let key_pair = KeyPair::generate()?;
        let mut params = CertificateParams::new(Vec::<String>::new())?;
        params
            .distinguished_name
            .push(DnType::CommonName, "Rutilus Center CA");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let certificate = params.self_signed(&key_pair)?;
        Ok(certificate.der().clone())
    }

    #[test]
    fn reads_the_subject_common_name_of_a_ca_certificate() -> Result<(), Box<dyn Error>> {
        let certificate = fixture_ca()?;
        assert_eq!(
            subject_common_name(&certificate)?,
            Some(String::from("Rutilus Center CA"))
        );
        let attributes = subject_attributes(&certificate)?;
        assert_eq!(attributes.len(), 1);
        assert_eq!(attributes[0].oid.as_slice(), CN_OID);
        assert_eq!(attributes[0].value, "Rutilus Center CA");
        Ok(())
    }

    #[test]
    fn no_subject_extension_is_read_when_absent() -> Result<(), Box<dyn Error>> {
        let certificate = fixture_ca()?;
        assert_eq!(site_identity_fingerprint(&certificate)?, None);
        Ok(())
    }

    #[test]
    fn rejects_truncated_inputs() -> Result<(), Box<dyn Error>> {
        let certificate = fixture_ca()?;
        let der = certificate.as_ref();
        for cut in [0usize, 1, 2, 4, 8, 16] {
            let Some(prefix) = der.get(..cut) else {
                continue;
            };
            let truncated: Vec<u8> = prefix.to_vec();
            // The top-level sequence header survives most cuts, so the
            // error must be one of the walker's controlled failures rather
            // than a panic.
            let result = subject_common_name(&CertificateDer::from(truncated));
            assert!(result.is_err(), "cut at {cut} bytes must fail");
        }
        Ok(())
    }

    #[test]
    fn rejects_trailing_bytes_after_the_certificate() -> Result<(), Box<dyn Error>> {
        let mut der = fixture_ca()?.as_ref().to_vec();
        der.push(0x00);
        let result = subject_common_name(&CertificateDer::from(der));
        assert!(matches!(result, Err(DerReadError::TrailingBytes)));
        Ok(())
    }

    #[test]
    fn rejects_an_indefinite_length() {
        let der = [0x30, 0x80, 0x00, 0x00];
        let result = subject_common_name(&CertificateDer::from(der.to_vec()));
        assert!(matches!(result, Err(DerReadError::IndefiniteLength)));
    }

    #[test]
    fn rejects_an_overlong_length_field() {
        // A length field with five length bytes.
        let der = [0x30, 0x85, 0x00, 0x00, 0x00, 0x00, 0x00];
        let result = subject_common_name(&CertificateDer::from(der.to_vec()));
        assert!(matches!(result, Err(DerReadError::LengthTooLarge)));
    }

    #[test]
    fn rejects_a_first_element_that_is_not_a_sequence() {
        let der = [0x04, 0x02, 0x00, 0x00];
        let result = subject_common_name(&CertificateDer::from(der.to_vec()));
        assert!(matches!(
            result,
            Err(DerReadError::UnexpectedTag {
                expected: "Certificate SEQUENCE",
                actual: 0x04
            })
        ));
    }

    #[test]
    fn decodes_known_oids() -> Result<(), Box<dyn Error>> {
        // 2.5.4.3 encodes as 55 04 03.
        assert_eq!(decode_oid(&[0x55, 0x04, 0x03])?, vec![2, 5, 4, 3]);
        // 1.3.6.1.4.1.59745.2.1 encodes with the base-128 arcs.
        assert_eq!(
            decode_oid(&[0x2B, 0x06, 0x01, 0x04, 0x01, 0x83, 0xD2, 0x61, 0x02, 0x01])?,
            vec![1, 3, 6, 1, 4, 1, 59745, 2, 1]
        );
        Ok(())
    }

    #[test]
    fn rejects_an_unfinished_oid_continuation() {
        assert!(matches!(
            decode_oid(&[0x2B, 0x83]),
            Err(DerReadError::Truncated)
        ));
    }
}
