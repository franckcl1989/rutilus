use std::collections::HashSet;

use csv::{ReaderBuilder, StringRecord, Trim};
use rutilus_domain::{
    CertificateFingerprint, CertificateFingerprintParseError, CredentialId, EndpointAddress,
    EndpointAddressError, EndpointDisplayName, EndpointDisplayNameError,
};
use thiserror::Error;

/// The only accepted endpoint-import columns, in their required order.
pub const ENDPOINT_CSV_HEADERS: [&str; 4] =
    ["display_name", "address", "credential_id", "tls_sha256"];

/// Defensive upper bound for one endpoint-import document.
pub const ENDPOINT_CSV_MAX_BYTES: usize = 1024 * 1024;

/// Defensive upper bound for endpoint records in one import document.
pub const ENDPOINT_CSV_MAX_ROWS: usize = 10_000;

/// The TLS identity that an operator explicitly expects for an imported row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EndpointImportTrust {
    /// The certificate must validate through the configured system CA roots.
    SystemCaOnly,
    /// A credential-free probe must present exactly this SHA-256 leaf identity.
    ExplicitPin(CertificateFingerprint),
}

/// A required column whose value is absent from one otherwise valid record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EndpointCsvRequiredField {
    DisplayName,
    Address,
    CredentialId,
}

impl std::fmt::Display for EndpointCsvRequiredField {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::DisplayName => "display_name",
            Self::Address => "address",
            Self::CredentialId => "credential_id",
        })
    }
}

/// One secret-free, domain-validated endpoint import request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndpointCsvRow {
    record_number: usize,
    display_name: EndpointDisplayName,
    address: EndpointAddress,
    credential_id: CredentialId,
    trust: EndpointImportTrust,
}

impl EndpointCsvRow {
    /// Returns the one-based logical CSV record number, including the header.
    #[must_use]
    pub const fn record_number(&self) -> usize {
        self.record_number
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
    pub const fn credential_id(&self) -> CredentialId {
        self.credential_id
    }

    #[must_use]
    pub const fn trust(&self) -> EndpointImportTrust {
        self.trust
    }
}

/// A bounded endpoint import whose records have all passed domain validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndpointCsvImport(Vec<EndpointCsvRow>);

impl EndpointCsvImport {
    #[must_use]
    pub fn rows(&self) -> &[EndpointCsvRow] {
        &self.0
    }

    #[must_use]
    pub fn into_rows(self) -> Vec<EndpointCsvRow> {
        self.0
    }
}

/// Parses the strict, secret-free endpoint CSV interchange format.
///
/// The four required columns are `display_name`, `address`, `credential_id`,
/// and `tls_sha256`. An empty `tls_sha256` means system-CA validation only;
/// a non-empty value must be an explicit colon-separated SHA-256 fingerprint.
/// Credential material is deliberately not representable.
///
/// # Errors
///
/// Returns [`EndpointCsvImportError`] for an oversized document, a changed
/// schema, malformed CSV, an invalid domain value, duplicate endpoint address,
/// no data records, or more than [`ENDPOINT_CSV_MAX_ROWS`] records.
pub fn parse_endpoint_csv(input: &[u8]) -> Result<EndpointCsvImport, EndpointCsvImportError> {
    if input.len() > ENDPOINT_CSV_MAX_BYTES {
        return Err(EndpointCsvImportError::InputTooLarge {
            actual: input.len(),
            maximum: ENDPOINT_CSV_MAX_BYTES,
        });
    }

    let mut reader = ReaderBuilder::new()
        .has_headers(true)
        .flexible(false)
        .trim(Trim::All)
        .from_reader(input);
    let headers = reader
        .headers()
        .map_err(|_| EndpointCsvImportError::MalformedHeader)?;
    if !has_expected_headers(headers) {
        return Err(EndpointCsvImportError::UnexpectedHeaders);
    }

    let mut rows = Vec::new();
    let mut addresses = HashSet::new();
    for result in reader.records() {
        let record_number = rows.len() + 2;
        if rows.len() == ENDPOINT_CSV_MAX_ROWS {
            return Err(EndpointCsvImportError::TooManyRows {
                maximum: ENDPOINT_CSV_MAX_ROWS,
            });
        }
        let record = result.map_err(|_| EndpointCsvImportError::MalformedRecord {
            record: record_number,
        })?;
        let row = parse_record(&record, record_number)?;
        if !addresses.insert(row.address.clone()) {
            return Err(EndpointCsvImportError::DuplicateAddress {
                record: record_number,
            });
        }
        rows.push(row);
    }

    if rows.is_empty() {
        return Err(EndpointCsvImportError::NoDataRows);
    }
    Ok(EndpointCsvImport(rows))
}

fn has_expected_headers(headers: &StringRecord) -> bool {
    headers.len() == ENDPOINT_CSV_HEADERS.len()
        && headers
            .iter()
            .zip(ENDPOINT_CSV_HEADERS)
            .all(|(actual, expected)| actual == expected)
}

fn parse_record(
    record: &StringRecord,
    record_number: usize,
) -> Result<EndpointCsvRow, EndpointCsvImportError> {
    let display_name = required_field(
        record,
        0,
        record_number,
        EndpointCsvRequiredField::DisplayName,
    )?
    .parse()
    .map_err(|source| EndpointCsvImportError::InvalidDisplayName {
        record: record_number,
        source,
    })?;
    let address: EndpointAddress =
        required_field(record, 1, record_number, EndpointCsvRequiredField::Address)?
            .parse()
            .map_err(|source| EndpointCsvImportError::InvalidAddress {
                record: record_number,
                source,
            })?;
    let credential_id = required_field(
        record,
        2,
        record_number,
        EndpointCsvRequiredField::CredentialId,
    )?
    .parse()
    .map_err(|_| EndpointCsvImportError::InvalidCredentialId {
        record: record_number,
    })?;
    let fingerprint = record
        .get(3)
        .ok_or(EndpointCsvImportError::MalformedRecord {
            record: record_number,
        })?;
    let trust = if fingerprint.is_empty() {
        EndpointImportTrust::SystemCaOnly
    } else {
        EndpointImportTrust::ExplicitPin(fingerprint.parse().map_err(|source| {
            EndpointCsvImportError::InvalidCertificateFingerprint {
                record: record_number,
                source,
            }
        })?)
    };

    Ok(EndpointCsvRow {
        record_number,
        display_name,
        address,
        credential_id,
        trust,
    })
}

fn required_field(
    record: &StringRecord,
    index: usize,
    record_number: usize,
    field: EndpointCsvRequiredField,
) -> Result<&str, EndpointCsvImportError> {
    match record.get(index) {
        Some(value) if !value.is_empty() => Ok(value),
        Some(_) => Err(EndpointCsvImportError::MissingRequiredField {
            record: record_number,
            field,
        }),
        None => Err(EndpointCsvImportError::MalformedRecord {
            record: record_number,
        }),
    }
}

/// A controlled, secret-safe endpoint import failure.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum EndpointCsvImportError {
    #[error("endpoint CSV has {actual} bytes; maximum is {maximum}")]
    InputTooLarge { actual: usize, maximum: usize },
    #[error("endpoint CSV header is malformed UTF-8 or CSV")]
    MalformedHeader,
    #[error("endpoint CSV must contain exactly: display_name,address,credential_id,tls_sha256")]
    UnexpectedHeaders,
    #[error("endpoint CSV record {record} is malformed")]
    MalformedRecord { record: usize },
    #[error("endpoint CSV record {record} is missing required field {field}")]
    MissingRequiredField {
        record: usize,
        field: EndpointCsvRequiredField,
    },
    #[error("endpoint CSV record {record} has an invalid display_name: {source}")]
    InvalidDisplayName {
        record: usize,
        source: EndpointDisplayNameError,
    },
    #[error("endpoint CSV record {record} has an invalid address: {source}")]
    InvalidAddress {
        record: usize,
        source: EndpointAddressError,
    },
    #[error("endpoint CSV record {record} has an invalid credential_id")]
    InvalidCredentialId { record: usize },
    #[error("endpoint CSV record {record} has an invalid tls_sha256: {source}")]
    InvalidCertificateFingerprint {
        record: usize,
        source: CertificateFingerprintParseError,
    },
    #[error("endpoint CSV record {record} repeats an earlier endpoint address")]
    DuplicateAddress { record: usize },
    #[error("endpoint CSV contains no endpoint records")]
    NoDataRows,
    #[error("endpoint CSV contains more than {maximum} endpoint records")]
    TooManyRows { maximum: usize },
}

#[cfg(test)]
mod tests {
    use std::{error::Error, fmt::Write};

    use rutilus_domain::{CertificateFingerprint, EndpointAddressError};

    use super::{
        ENDPOINT_CSV_MAX_BYTES, ENDPOINT_CSV_MAX_ROWS, EndpointCsvImportError,
        EndpointCsvRequiredField, EndpointImportTrust, parse_endpoint_csv,
    };

    const CREDENTIAL_ID: &str = "0198e29f-7800-7000-8000-000000000001";
    const FINGERPRINT: &str = "00:01:02:03:04:05:06:07:08:09:0A:0B:0C:0D:0E:0F:10:11:12:13:14:15:16:17:18:19:1A:1B:1C:1D:1E:1F";

    #[test]
    fn parses_quoted_rows_and_the_two_explicit_trust_modes() -> Result<(), Box<dyn Error>> {
        let input = format!(
            "display_name,address,credential_id,tls_sha256\r\n\
             \"Rack, East\", https://bmc-a.example.test , {CREDENTIAL_ID},\r\n\
             Rack West,https://bmc-b.example.test,{CREDENTIAL_ID},{}\r\n",
            FINGERPRINT.to_ascii_lowercase()
        );

        let parsed = parse_endpoint_csv(input.as_bytes())?;
        assert_eq!(parsed.rows().len(), 2);
        assert_eq!(parsed.rows()[0].record_number(), 2);
        assert_eq!(parsed.rows()[0].display_name().as_str(), "Rack, East");
        assert_eq!(
            parsed.rows()[0].address().to_string(),
            "https://bmc-a.example.test/"
        );
        assert_eq!(parsed.rows()[0].trust(), EndpointImportTrust::SystemCaOnly);
        assert_eq!(
            parsed.rows()[1].trust(),
            EndpointImportTrust::ExplicitPin(FINGERPRINT.parse::<CertificateFingerprint>()?)
        );
        assert_eq!(parsed.into_rows().len(), 2);
        Ok(())
    }

    #[test]
    fn requires_the_exact_secret_free_schema_and_at_least_one_record() {
        assert_eq!(
            parse_endpoint_csv(b"address,display_name,credential_id,tls_sha256\n"),
            Err(EndpointCsvImportError::UnexpectedHeaders)
        );
        assert_eq!(
            parse_endpoint_csv(b"display_name,address,credential_id,password\n"),
            Err(EndpointCsvImportError::UnexpectedHeaders)
        );
        assert_eq!(
            parse_endpoint_csv(b"display_name,address,credential_id,tls_sha256\n"),
            Err(EndpointCsvImportError::NoDataRows)
        );
        let missing_address =
            format!("display_name,address,credential_id,tls_sha256\nRack A,,{CREDENTIAL_ID},\n");
        assert_eq!(
            parse_endpoint_csv(missing_address.as_bytes()),
            Err(EndpointCsvImportError::MissingRequiredField {
                record: 2,
                field: EndpointCsvRequiredField::Address,
            })
        );
    }

    #[test]
    fn reports_structural_failures_without_retaining_input() {
        let unequal = format!(
            "display_name,address,credential_id,tls_sha256\nRack A,https://secret-host,{CREDENTIAL_ID}\n"
        );
        let error = parse_endpoint_csv(unequal.as_bytes());
        assert_eq!(
            error,
            Err(EndpointCsvImportError::MalformedRecord { record: 2 })
        );
        assert!(!format!("{error:?}").contains("secret-host"));

        let mut invalid_utf8 = format!(
            "display_name,address,credential_id,tls_sha256\nRack A,https://bmc,{CREDENTIAL_ID},"
        )
        .into_bytes();
        invalid_utf8.push(0xff);
        assert_eq!(
            parse_endpoint_csv(&invalid_utf8),
            Err(EndpointCsvImportError::MalformedRecord { record: 2 })
        );
    }

    #[test]
    fn applies_domain_validation_without_echoing_rejected_values() {
        let credential_url = format!(
            "display_name,address,credential_id,tls_sha256\nRack A,https://admin:password@bmc.example.test,{CREDENTIAL_ID},\n"
        );
        let error = parse_endpoint_csv(credential_url.as_bytes());
        assert_eq!(
            error,
            Err(EndpointCsvImportError::InvalidAddress {
                record: 2,
                source: EndpointAddressError::EmbeddedCredentials,
            })
        );
        let rendered = format!("{error:?}");
        assert!(!rendered.contains("admin"));
        assert!(!rendered.contains("password"));

        let invalid_name = format!(
            "display_name,address,credential_id,tls_sha256\n\"Rack\nA\",https://bmc.example.test,{CREDENTIAL_ID},\n"
        );
        assert!(matches!(
            parse_endpoint_csv(invalid_name.as_bytes()),
            Err(EndpointCsvImportError::InvalidDisplayName { record: 2, .. })
        ));
        let invalid_id = b"display_name,address,credential_id,tls_sha256\nRack A,https://bmc.example.test,not-a-uuid,\n";
        assert_eq!(
            parse_endpoint_csv(invalid_id),
            Err(EndpointCsvImportError::InvalidCredentialId { record: 2 })
        );
        let invalid_pin = format!(
            "display_name,address,credential_id,tls_sha256\nRack A,https://bmc.example.test,{CREDENTIAL_ID},AA:BB\n"
        );
        assert!(matches!(
            parse_endpoint_csv(invalid_pin.as_bytes()),
            Err(EndpointCsvImportError::InvalidCertificateFingerprint { record: 2, .. })
        ));
    }

    #[test]
    fn rejects_duplicate_normalized_addresses() {
        let input = format!(
            "display_name,address,credential_id,tls_sha256\n\
             Rack A,https://BMC.example.test,{CREDENTIAL_ID},\n\
             Rack B,https://bmc.example.test/,{CREDENTIAL_ID},\n"
        );

        assert_eq!(
            parse_endpoint_csv(input.as_bytes()),
            Err(EndpointCsvImportError::DuplicateAddress { record: 3 })
        );
    }

    #[test]
    fn bounds_document_bytes_and_record_count() -> Result<(), Box<dyn Error>> {
        let oversized = vec![b'a'; ENDPOINT_CSV_MAX_BYTES + 1];
        assert_eq!(
            parse_endpoint_csv(&oversized),
            Err(EndpointCsvImportError::InputTooLarge {
                actual: ENDPOINT_CSV_MAX_BYTES + 1,
                maximum: ENDPOINT_CSV_MAX_BYTES,
            })
        );

        let mut too_many = String::from("display_name,address,credential_id,tls_sha256\n");
        for index in 0..=ENDPOINT_CSV_MAX_ROWS {
            writeln!(
                too_many,
                "Rack {index},https://bmc-{index},{CREDENTIAL_ID},"
            )?;
        }
        assert_eq!(
            parse_endpoint_csv(too_many.as_bytes()),
            Err(EndpointCsvImportError::TooManyRows {
                maximum: ENDPOINT_CSV_MAX_ROWS,
            })
        );
        Ok(())
    }
}
