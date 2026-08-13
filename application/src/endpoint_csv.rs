use std::{collections::HashSet, fmt};

use csv::{ReaderBuilder, StringRecord, Trim};
use rutilus_domain::{
    CertificateFingerprintParseError, CredentialId, EndpointAddress, EndpointAddressError,
    EndpointDisplayName, EndpointDisplayNameError,
};

use crate::endpoint_trust::EndpointTrustExpectation;

/// The only accepted endpoint-import columns, in their required order.
pub const ENDPOINT_CSV_HEADERS: [&str; 4] =
    ["display_name", "address", "credential_id", "tls_sha256"];

/// Defensive upper bound for one endpoint-import document.
pub const ENDPOINT_CSV_MAX_BYTES: usize = 1024 * 1024;

/// Defensive upper bound for endpoint records in one import document.
pub const ENDPOINT_CSV_MAX_ROWS: usize = 10_000;

/// The TLS policy imported for one endpoint row.
pub type EndpointImportTrust = EndpointTrustExpectation;

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
pub struct EndpointCsvImport {
    row_count: u32,
    rows: Vec<EndpointCsvRow>,
}

impl EndpointCsvImport {
    #[must_use]
    pub const fn row_count(&self) -> u32 {
        self.row_count
    }

    #[must_use]
    pub fn rows(&self) -> &[EndpointCsvRow] {
        &self.rows
    }

    #[must_use]
    pub fn into_rows(self) -> Vec<EndpointCsvRow> {
        self.rows
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
        .map_err(|source| EndpointCsvImportError::MalformedHeader { source })?;
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
        let record = result.map_err(|source| EndpointCsvImportError::MalformedRecord {
            record: record_number,
            source: Some(source),
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
    let row_count = u32::try_from(rows.len()).map_err(|_| EndpointCsvImportError::TooManyRows {
        maximum: ENDPOINT_CSV_MAX_ROWS,
    })?;
    Ok(EndpointCsvImport { row_count, rows })
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
    .map_err(|source| EndpointCsvImportError::InvalidCredentialId {
        record: record_number,
        source: Box::new(source),
    })?;
    let fingerprint = record
        .get(3)
        .ok_or(EndpointCsvImportError::MalformedRecord {
            record: record_number,
            source: None,
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
            source: None,
        }),
    }
}

/// A controlled, secret-safe endpoint import failure.
///
/// The malformed-CSV variants and the invalid-`credential_id` variant carry
/// the underlying parser error as a diagnostic source: the user-facing
/// classification stays exactly what it was (a header problem, a record
/// problem, an invalid credential id), while the source preserves the
/// parser's own reason — the byte position and the exact malformation — for
/// the operator. The type deliberately does not derive `Clone`/`PartialEq`:
/// `csv::Error` offers neither, and the error's equality is its
/// classification, which the tests assert through `matches!` and `Display`.
#[derive(Debug)]
pub enum EndpointCsvImportError {
    /// The document exceeds the defensive byte bound.
    InputTooLarge { actual: usize, maximum: usize },
    /// The header row is malformed UTF-8 or CSV; the source is the parser's
    /// own error with the byte position of the malformation.
    MalformedHeader { source: csv::Error },
    /// The columns differ from the strict interchange schema.
    UnexpectedHeaders,
    /// A record is malformed — an unequal field count, invalid UTF-8, or
    /// (defensively, against the `flexible(false)` contract) a row shorter
    /// than the schema. The source is the parser's own error when the reader
    /// produced one; the defensive short-row paths carry `None`.
    MalformedRecord {
        record: usize,

        source: Option<csv::Error>,
    },
    /// A required column is empty on one record.
    MissingRequiredField {
        record: usize,
        field: EndpointCsvRequiredField,
    },
    /// The `display_name` value fails the domain validation; the source is
    /// the domain's reason.
    InvalidDisplayName {
        record: usize,

        source: EndpointDisplayNameError,
    },
    /// The `address` value fails the domain validation; the source is the
    /// domain's reason.
    InvalidAddress {
        record: usize,

        source: EndpointAddressError,
    },
    /// The `credential_id` value is not a valid identifier; the source is
    /// the domain's parse error (the `uuid` error of the
    /// `CredentialId::from_str` contract, boxed because the application
    /// crate cannot name the `uuid` error type directly).
    InvalidCredentialId {
        record: usize,

        source: Box<dyn std::error::Error + Send + Sync>,
    },
    /// The `tls_sha256` value fails the fingerprint validation; the source
    /// is the domain's reason.
    InvalidCertificateFingerprint {
        record: usize,

        source: CertificateFingerprintParseError,
    },
    /// The record's normalized address repeats an earlier record's.
    DuplicateAddress { record: usize },
    /// The document carries no endpoint records after the header.
    NoDataRows,
    /// The document exceeds the defensive record bound.
    TooManyRows { maximum: usize },
}

impl fmt::Display for EndpointCsvImportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputTooLarge { actual, maximum } => {
                write!(
                    formatter,
                    "endpoint CSV has {actual} bytes; maximum is {maximum}"
                )
            }
            Self::MalformedHeader { source } => write!(
                formatter,
                "endpoint CSV header is malformed UTF-8 or CSV: {source}"
            ),
            Self::UnexpectedHeaders => formatter.write_str(
                "endpoint CSV must contain exactly: display_name,address,credential_id,tls_sha256",
            ),
            Self::MalformedRecord { record, source } => {
                // The defensive short-row paths have no parser error behind
                // them, so the message keeps the original "is malformed"
                // wording and the parser's reason is appended only when the
                // reader actually produced one.
                write!(formatter, "endpoint CSV record {record} is malformed")?;
                if let Some(source) = source {
                    write!(formatter, ": {source}")?;
                }
                Ok(())
            }
            Self::MissingRequiredField { record, field } => {
                write!(
                    formatter,
                    "endpoint CSV record {record} is missing required field {field}"
                )
            }
            Self::InvalidDisplayName { record, source } => write!(
                formatter,
                "endpoint CSV record {record} has an invalid display_name: {source}"
            ),
            Self::InvalidAddress { record, source } => {
                write!(
                    formatter,
                    "endpoint CSV record {record} has an invalid address: {source}"
                )
            }
            Self::InvalidCredentialId { record, source } => write!(
                formatter,
                "endpoint CSV record {record} has an invalid credential_id: {source}"
            ),
            Self::InvalidCertificateFingerprint { record, source } => write!(
                formatter,
                "endpoint CSV record {record} has an invalid tls_sha256: {source}"
            ),
            Self::DuplicateAddress { record } => {
                write!(
                    formatter,
                    "endpoint CSV record {record} repeats an earlier endpoint address"
                )
            }
            Self::NoDataRows => formatter.write_str("endpoint CSV contains no endpoint records"),
            Self::TooManyRows { maximum } => {
                write!(
                    formatter,
                    "endpoint CSV contains more than {maximum} endpoint records"
                )
            }
        }
    }
}

impl std::error::Error for EndpointCsvImportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::MalformedHeader { source }
            | Self::MalformedRecord {
                source: Some(source),
                ..
            } => Some(source),
            Self::InvalidDisplayName { source, .. } => Some(source),
            Self::InvalidAddress { source, .. } => Some(source),
            // The boxed parse error derefs to the trait object; the
            // auto-trait-dropping coercion from `&(dyn Error + Send + Sync)`
            // to `&dyn Error` needs an explicit `as_ref` step.
            Self::InvalidCredentialId { source, .. } => Some(source.as_ref()),
            Self::InvalidCertificateFingerprint { source, .. } => Some(source),
            _ => None,
        }
    }
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
        assert_eq!(parsed.row_count(), 2);
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
    fn requires_the_exact_secret_free_schema_and_at_least_one_record() -> Result<(), Box<dyn Error>>
    {
        assert!(matches!(
            parse_endpoint_csv(b"address,display_name,credential_id,tls_sha256\n"),
            Err(EndpointCsvImportError::UnexpectedHeaders)
        ));
        assert!(matches!(
            parse_endpoint_csv(b"display_name,address,credential_id,password\n"),
            Err(EndpointCsvImportError::UnexpectedHeaders)
        ));
        assert!(matches!(
            parse_endpoint_csv(b"display_name,address,credential_id,tls_sha256\n"),
            Err(EndpointCsvImportError::NoDataRows)
        ));
        let missing_address =
            format!("display_name,address,credential_id,tls_sha256\nRack A,,{CREDENTIAL_ID},\n");
        let error = parse_endpoint_csv(missing_address.as_bytes());
        assert!(matches!(
            error,
            Err(EndpointCsvImportError::MissingRequiredField {
                record: 2,
                field: EndpointCsvRequiredField::Address,
            })
        ));
        // The Display keeps the exact column name of the missing field, so
        // an operator can fix the precise cell.
        let Err(EndpointCsvImportError::MissingRequiredField { record, field }) = error else {
            return Err(std::io::Error::other("expected a missing-field error").into());
        };
        assert_eq!(record, 2);
        assert_eq!(field, EndpointCsvRequiredField::Address);
        assert_eq!(
            EndpointCsvImportError::MissingRequiredField { record, field }.to_string(),
            "endpoint CSV record 2 is missing required field address"
        );
        Ok(())
    }

    #[test]
    fn reports_structural_failures_without_retaining_input() -> Result<(), Box<dyn Error>> {
        let unequal = format!(
            "display_name,address,credential_id,tls_sha256\nRack A,https://secret-host,{CREDENTIAL_ID}\n"
        );
        let error = parse_endpoint_csv(unequal.as_bytes());
        let debug = format!("{error:?}");
        let Err(
            ref error @ EndpointCsvImportError::MalformedRecord {
                record: 2,
                ref source,
            },
        ) = error
        else {
            return Err(std::io::Error::other("expected a malformed-record error").into());
        };
        let display = error.to_string();
        // The parser's own error rides along as the diagnostic source — the
        // unequal-field-count reason with its byte position — so the Display
        // keeps the logical row number *and* the underlying cause, while
        // the Debug output still retains no record content.
        assert!(
            source.is_some(),
            "the reader produced the malformation, so its error must be carried"
        );
        assert!(
            display.starts_with("endpoint CSV record 2 is malformed: "),
            "the Display must expose the underlying reason: {display}"
        );
        assert!(
            display.contains("found record with 3 fields, but the previous record has 4 fields"),
            "the unequal-field-count reason must surface: {display}"
        );
        assert!(!debug.contains("secret-host"));

        let mut invalid_utf8 = format!(
            "display_name,address,credential_id,tls_sha256\nRack A,https://bmc,{CREDENTIAL_ID},"
        )
        .into_bytes();
        invalid_utf8.push(0xff);
        let error = parse_endpoint_csv(&invalid_utf8);
        let Err(
            ref error @ EndpointCsvImportError::MalformedRecord {
                record: 2,
                ref source,
            },
        ) = error
        else {
            return Err(std::io::Error::other("expected a malformed-record error").into());
        };
        let display = error.to_string();
        assert!(source.is_some());
        assert!(
            display.contains("invalid utf-8"),
            "the underlying UTF-8 reason must surface: {display}"
        );
        Ok(())
    }

    #[test]
    fn malformed_headers_carry_the_parser_error_and_its_byte_position() -> Result<(), Box<dyn Error>>
    {
        // Invalid UTF-8 in the header row: the parser rejects the document
        // at the header, and the error's source preserves the parser's own
        // reason — the record, line, and byte position — for the operator.
        let mut invalid_header = b"display_name,address,credential_id,tls_sha256\n".to_vec();
        invalid_header[0] = 0xff;
        let error = parse_endpoint_csv(&invalid_header);
        let Err(ref error @ EndpointCsvImportError::MalformedHeader { ref source }) = error else {
            return Err(std::io::Error::other("expected a malformed-header error").into());
        };
        let display = error.to_string();
        assert!(
            display.starts_with("endpoint CSV header is malformed UTF-8 or CSV: "),
            "the Display must expose the underlying reason: {display}"
        );
        assert!(
            source.to_string().contains("CSV parse error"),
            "the parser's own error must be carried: {source}"
        );
        assert!(
            source.to_string().contains("invalid utf-8"),
            "the header's UTF-8 reason must surface: {source}"
        );
        Ok(())
    }

    #[test]
    fn applies_domain_validation_without_echoing_rejected_values() -> Result<(), Box<dyn Error>> {
        let credential_url = format!(
            "display_name,address,credential_id,tls_sha256\nRack A,https://admin:password@bmc.example.test,{CREDENTIAL_ID},\n"
        );
        let error = parse_endpoint_csv(credential_url.as_bytes());
        let rendered = format!("{error:?}");
        assert!(matches!(
            error,
            Err(EndpointCsvImportError::InvalidAddress {
                record: 2,
                source: EndpointAddressError::EmbeddedCredentials,
            })
        ));
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
        let error = parse_endpoint_csv(invalid_id);
        let debug = format!("{error:?}");
        let Err(
            ref error @ EndpointCsvImportError::InvalidCredentialId {
                record: 2,
                ref source,
            },
        ) = error
        else {
            return Err(std::io::Error::other("expected an invalid credential id").into());
        };
        let display = error.to_string();
        // The domain's parse reason rides along as the diagnostic source —
        // the rejected character and its position — while neither Display
        // nor Debug echoes the rejected value itself.
        assert!(
            display.starts_with("endpoint CSV record 2 has an invalid credential_id: "),
            "the Display must expose the underlying reason: {display}"
        );
        assert!(
            source.to_string().contains("invalid character"),
            "the uuid parse reason must be carried: {source}"
        );
        assert!(!debug.contains("not-a-uuid"));

        let invalid_pin = format!(
            "display_name,address,credential_id,tls_sha256\nRack A,https://bmc.example.test,{CREDENTIAL_ID},AA:BB\n"
        );
        assert!(matches!(
            parse_endpoint_csv(invalid_pin.as_bytes()),
            Err(EndpointCsvImportError::InvalidCertificateFingerprint { record: 2, .. })
        ));
        Ok(())
    }

    #[test]
    fn rejects_duplicate_normalized_addresses() {
        let input = format!(
            "display_name,address,credential_id,tls_sha256\n\
             Rack A,https://BMC.example.test,{CREDENTIAL_ID},\n\
             Rack B,https://bmc.example.test/,{CREDENTIAL_ID},\n"
        );

        assert!(matches!(
            parse_endpoint_csv(input.as_bytes()),
            Err(EndpointCsvImportError::DuplicateAddress { record: 3 })
        ));
    }

    #[test]
    fn bounds_document_bytes_and_record_count() -> Result<(), Box<dyn Error>> {
        let oversized = vec![b'a'; ENDPOINT_CSV_MAX_BYTES + 1];
        let Err(error) = parse_endpoint_csv(&oversized) else {
            return Err(std::io::Error::other("the oversized document must be rejected").into());
        };
        assert_eq!(
            error.to_string(),
            format!(
                "endpoint CSV has {} bytes; maximum is {}",
                ENDPOINT_CSV_MAX_BYTES + 1,
                ENDPOINT_CSV_MAX_BYTES
            )
        );
        let EndpointCsvImportError::InputTooLarge { actual, maximum } = error else {
            return Err(std::io::Error::other("expected an input-too-large error").into());
        };
        assert_eq!(actual, ENDPOINT_CSV_MAX_BYTES + 1);
        assert_eq!(maximum, ENDPOINT_CSV_MAX_BYTES);

        let mut too_many = String::from("display_name,address,credential_id,tls_sha256\n");
        for index in 0..=ENDPOINT_CSV_MAX_ROWS {
            writeln!(
                too_many,
                "Rack {index},https://bmc-{index},{CREDENTIAL_ID},"
            )?;
        }
        let Err(error) = parse_endpoint_csv(too_many.as_bytes()) else {
            return Err(std::io::Error::other("the record bound must be rejected").into());
        };
        assert_eq!(
            error.to_string(),
            format!("endpoint CSV contains more than {ENDPOINT_CSV_MAX_ROWS} endpoint records")
        );
        let EndpointCsvImportError::TooManyRows { maximum } = error else {
            return Err(std::io::Error::other("expected a too-many-rows error").into());
        };
        assert_eq!(maximum, ENDPOINT_CSV_MAX_ROWS);
        Ok(())
    }
}
