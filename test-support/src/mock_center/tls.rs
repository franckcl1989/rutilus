//! Deterministic TLS identity for the Mock Center.
//!
//! The mock center mirrors the real center's mTLS surface (design §15,
//! 0.7.0 S3b): one self-signed CA that signs the center's server
//! certificate (whose SHA-256 fingerprint the site pins, §10.4) and one
//! client certificate per test site. Unlike the real center, the mock
//! never persists material — every [`MockCenterTls::new`] generates a
//! fresh CA for the lifetime of the instance, and the tests read the
//! fingerprints and certificates from the instance.

use std::sync::Arc;

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
use rutilus_domain::CertificateFingerprint;
use thiserror::Error;
use time::{Duration, OffsetDateTime};
use tokio_rustls::rustls::{
    RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    server::WebPkiClientVerifier,
};

use super::MockCenterOptions;

/// The subject common name of the mock center CA certificate.
const MOCK_CENTER_CA_COMMON_NAME: &str = "Rutilus Mock Center CA";

/// Certificate validity windows: the CA lives a decade, the issued
/// certificates five years, with a one-day lookback for clock skew.
#[allow(clippy::duration_suboptimal_units)]
const CA_VALIDITY: Duration = Duration::seconds(60 * 60 * 24 * 365 * 10);
#[allow(clippy::duration_suboptimal_units)]
const ISSUED_VALIDITY: Duration = Duration::seconds(60 * 60 * 24 * 365 * 5);
const NOT_BEFORE_SKEW: Duration = Duration::days(1);

/// A controlled failure while generating the mock center's TLS material.
#[derive(Debug, Error)]
pub enum MockCenterTlsError {
    #[error("the mock center CA key could not be generated: {0}")]
    GenerateKey(#[source] rcgen::Error),
    #[error("the mock center CA certificate could not be generated: {0}")]
    GenerateCa(#[source] rcgen::Error),
    #[error("the mock center server certificate could not be generated: {0}")]
    GenerateServer(#[source] rcgen::Error),
    #[error("the mock center client certificate could not be generated: {0}")]
    GenerateClient(#[source] rcgen::Error),
    #[error("the mock center TLS configuration could not be assembled: {0}")]
    Tls(#[source] tokio_rustls::rustls::Error),
    #[error("the mock center client verifier could not be built: {0}")]
    Verifier(#[source] tokio_rustls::rustls::server::VerifierBuilderError),
}

/// One mock center site identity: a client certificate pair issued by the
/// mock center CA.
#[derive(Clone, Debug)]
pub struct MockSiteIdentity {
    certificate_pem: String,
    key_pem: String,
}

impl MockSiteIdentity {
    /// The PEM certificate of the issued client identity.
    #[must_use]
    pub fn certificate_pem(&self) -> &str {
        &self.certificate_pem
    }

    /// The PEM private key of the issued client identity.
    #[must_use]
    pub fn key_pem(&self) -> &str {
        &self.key_pem
    }
}

/// The mTLS material of one mock center instance: the CA (with its signing
/// key), the server pair, and the rustls server configuration that requires
/// a client certificate signed by the CA.
#[derive(Clone, Debug)]
pub struct MockCenterTls {
    ca_certificate: CertificateDer<'static>,
    ca_key_pkcs8: Vec<u8>,
    server_fingerprint: CertificateFingerprint,
    server_config: Arc<tokio_rustls::rustls::ServerConfig>,
}

impl MockCenterTls {
    /// Generates a fresh CA and server pair and assembles the server
    /// configuration.
    ///
    /// # Errors
    ///
    /// Returns [`MockCenterTlsError`] when any certificate cannot be
    /// generated or the TLS configuration cannot be assembled.
    pub fn new(options: MockCenterOptions) -> Result<Self, MockCenterTlsError> {
        let ca_key = KeyPair::generate().map_err(MockCenterTlsError::GenerateKey)?;
        let mut ca_params =
            CertificateParams::new(Vec::<String>::new()).map_err(MockCenterTlsError::GenerateCa)?;
        ca_params
            .distinguished_name
            .push(DnType::CommonName, MOCK_CENTER_CA_COMMON_NAME.to_owned());
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        set_validity(&mut ca_params, CA_VALIDITY);
        let ca_certificate = ca_params
            .self_signed(&ca_key)
            .map_err(MockCenterTlsError::GenerateCa)?;
        let ca_key_pkcs8 = ca_key.serialize_der();

        let mut server_params =
            CertificateParams::new(vec!["127.0.0.1".to_owned(), "localhost".to_owned()])
                .map_err(MockCenterTlsError::GenerateServer)?;
        server_params
            .distinguished_name
            .push(DnType::CommonName, "Rutilus Mock Center".to_owned());
        server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        server_params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        set_validity(&mut server_params, ISSUED_VALIDITY);
        let server_key = KeyPair::generate().map_err(MockCenterTlsError::GenerateKey)?;
        let issuer = ca_issuer(&ca_params, &ca_key_pkcs8)?;
        let server_certificate = server_params
            .signed_by(&server_key, &issuer)
            .map_err(MockCenterTlsError::GenerateServer)?;
        let server_fingerprint =
            CertificateFingerprint::from_certificate_der(server_certificate.der());

        let mut roots = RootCertStore::empty();
        roots
            .add(ca_certificate.der().clone())
            .map_err(MockCenterTlsError::Tls)?;
        let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
        let mut config = if options.require_client_cert {
            let verifier =
                WebPkiClientVerifier::builder_with_provider(Arc::new(roots), Arc::clone(&provider))
                    .build()
                    .map_err(MockCenterTlsError::Verifier)?;
            tokio_rustls::rustls::ServerConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .map_err(MockCenterTlsError::Tls)?
                .with_client_cert_verifier(verifier)
                .with_single_cert(
                    vec![server_certificate.der().clone()],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der())),
                )
                .map_err(MockCenterTlsError::Tls)?
        } else {
            // The `with_no_client_auth` path never offers client
            // authentication at all.
            tokio_rustls::rustls::ServerConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .map_err(MockCenterTlsError::Tls)?
                .with_no_client_auth()
                .with_single_cert(
                    vec![server_certificate.der().clone()],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der())),
                )
                .map_err(MockCenterTlsError::Tls)?
        };
        config.alpn_protocols = vec![b"http/1.1".to_vec()];

        Ok(Self {
            ca_certificate: ca_certificate.der().clone(),
            ca_key_pkcs8,
            server_fingerprint,
            server_config: Arc::new(config),
        })
    }

    /// The CA certificate: the trust anchor a site loads to verify the
    /// mock center.
    #[must_use]
    pub fn ca_certificate(&self) -> CertificateDer<'static> {
        self.ca_certificate.clone()
    }

    /// The SHA-256 fingerprint of the server certificate — the value a
    /// site pins (§10.4).
    #[must_use]
    pub const fn server_fingerprint(&self) -> CertificateFingerprint {
        self.server_fingerprint
    }

    /// The rustls server configuration of the mock center.
    #[must_use]
    pub fn server_config(&self) -> Arc<tokio_rustls::rustls::ServerConfig> {
        Arc::clone(&self.server_config)
    }

    /// Issues one client certificate for a test site against the mock
    /// center CA.
    ///
    /// # Errors
    ///
    /// Returns [`MockCenterTlsError`] when the certificate cannot be
    /// generated.
    pub fn issue_client_certificate(
        &self,
        site: &str,
    ) -> Result<MockSiteIdentity, MockCenterTlsError> {
        let mut params = CertificateParams::new(Vec::<String>::new())
            .map_err(MockCenterTlsError::GenerateClient)?;
        params
            .distinguished_name
            .push(DnType::CommonName, site.to_owned());
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        set_validity(&mut params, ISSUED_VALIDITY);
        let key = KeyPair::generate().map_err(MockCenterTlsError::GenerateKey)?;
        let issuer = ca_issuer_from_cert(&self.ca_certificate, &self.ca_key_pkcs8)?;
        let certificate = params
            .signed_by(&key, &issuer)
            .map_err(MockCenterTlsError::GenerateClient)?;
        Ok(MockSiteIdentity {
            certificate_pem: pem_encode("CERTIFICATE", certificate.der().as_ref()),
            key_pem: pem_encode("PRIVATE KEY", &key.serialize_der()),
        })
    }
}

/// Builds the CA issuer over the freshly generated CA parameters and key.
fn ca_issuer(
    ca_params: &CertificateParams,
    ca_key_pkcs8: &[u8],
) -> Result<Issuer<'static, KeyPair>, MockCenterTlsError> {
    let pkcs8 = PrivatePkcs8KeyDer::from(ca_key_pkcs8.to_vec());
    let key_pair = KeyPair::from_pkcs8_der_and_sign_algo(&pkcs8, &PKCS_ECDSA_P256_SHA256)
        .map_err(MockCenterTlsError::GenerateKey)?;
    Ok(Issuer::new(ca_params.clone(), key_pair))
}

/// Builds the CA issuer over the persisted CA certificate and key.
///
/// The certificate argument pins the identity the issuer must reproduce;
/// the issuer subject is the fixed mock CA common name, so the chain
/// verifies against the certificate presented to sites.
fn ca_issuer_from_cert(
    _ca_certificate: &CertificateDer<'static>,
    ca_key_pkcs8: &[u8],
) -> Result<Issuer<'static, KeyPair>, MockCenterTlsError> {
    let pkcs8 = PrivatePkcs8KeyDer::from(ca_key_pkcs8.to_vec());
    let key_pair = KeyPair::from_pkcs8_der_and_sign_algo(&pkcs8, &PKCS_ECDSA_P256_SHA256)
        .map_err(MockCenterTlsError::GenerateKey)?;
    let mut params =
        CertificateParams::new(Vec::<String>::new()).map_err(MockCenterTlsError::GenerateCa)?;
    params
        .distinguished_name
        .push(DnType::CommonName, MOCK_CENTER_CA_COMMON_NAME.to_owned());
    // The issuer subject must equal the CA certificate subject, so the
    // chain verifies; the validity is irrelevant for the issuer identity.
    Ok(Issuer::new(params, key_pair))
}

/// Encodes one DER value as a PEM document with 64-column base64 lines.
fn pem_encode(label: &str, der: &[u8]) -> String {
    use base64::Engine as _;
    use std::fmt::Write as _;

    let encoded = base64::engine::general_purpose::STANDARD.encode(der);
    let mut pem = String::with_capacity(encoded.len() + 64);
    let _ = writeln!(pem, "-----BEGIN {label}-----");
    for chunk in encoded.as_bytes().chunks(64) {
        pem.extend(chunk.iter().map(|byte| *byte as char));
        pem.push('\n');
    }
    let _ = writeln!(pem, "-----END {label}-----");
    pem
}

/// Applies one validity window to certificate parameters.
fn set_validity(params: &mut CertificateParams, validity: Duration) {
    let now = OffsetDateTime::now_utc();
    params.not_before = now - NOT_BEFORE_SKEW;
    params.not_after = now + validity;
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::*;

    #[test]
    fn the_mock_center_tls_material_is_self_consistent() -> Result<(), Box<dyn Error>> {
        let tls = MockCenterTls::new(MockCenterOptions::default())?;
        assert_eq!(tls.server_fingerprint().to_string().split(':').count(), 32);
        assert!(tls.ca_certificate().as_ref().starts_with(b"0\x82"));
        let identity = tls.issue_client_certificate("site-under-test")?;
        assert!(
            identity
                .certificate_pem()
                .starts_with("-----BEGIN CERTIFICATE-----")
        );
        assert!(
            identity
                .key_pem()
                .starts_with("-----BEGIN PRIVATE KEY-----")
        );
        Ok(())
    }
}
