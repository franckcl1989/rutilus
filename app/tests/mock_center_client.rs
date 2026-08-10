#![forbid(unsafe_code)]

//! End-to-end interop between the app's site-side [`CenterClient`] and the
//! scripted [`MockCenter`] of `rutilus-test-support` (0.7.0 S9): the mock
//! serves the real mTLS surface, so the same client code that talks to a
//! real center talks to the mock.
//!
//! Dependency direction: `rutilus-test-support` stays free of the app
//! crate (it depends only on `rutilus-domain` and the center protocol),
//! and this integration test — where both sides are available — proves the
//! interop. The mock's CA issues the site's client certificate, and its
//! script records every frame the client sends.

use std::error::Error;

use rutilus::{CenterClientConfig, CenterClientError, ListenAddress};
use rutilus_center_protocol::{Ack, Envelope, EnvelopeMessage};
use rutilus_domain::InstanceId;
use rutilus_test_support::{MockCenter, MockCenterOptions, MockSiteIdentity, ScriptedAdmission};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

/// The site-side config for one interop test: the mock's CA as the only
/// trust anchor, the mock's server fingerprint as the §10.4 pin, and a
/// client certificate issued by the mock's CA.
///
/// The material is captured before the mock is moved into its serve task,
/// so the builder never borrows the mock.
#[allow(clippy::too_many_arguments)]
fn site_config_from(
    address: &ListenAddress,
    ca_certificate: &CertificateDer<'static>,
    server_fingerprint: rutilus_domain::CertificateFingerprint,
    identity: &MockSiteIdentity,
) -> Result<CenterClientConfig, Box<dyn Error>> {
    let client_certificate = CertificateDer::from(der_from_pem(identity.certificate_pem())?);
    let client_key =
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der_from_pem(identity.key_pem())?));
    Ok(CenterClientConfig::new(
        address.clone(),
        ca_certificate.clone(),
        server_fingerprint,
        client_certificate,
        client_key,
        InstanceId::generate(),
        "Test Site".to_owned(),
    )?)
}

/// Decodes one PEM document back into its DER bytes.
fn der_from_pem(pem: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    use base64::Engine as _;
    let body: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    Ok(base64::engine::general_purpose::STANDARD.decode(body.trim())?)
}

#[tokio::test]
async fn the_mock_center_negotiates_and_acks_the_real_client() -> Result<(), Box<dyn Error>> {
    let center = MockCenter::bind().await?;
    let identity = center.tls().issue_client_certificate("site-under-test")?;
    let ca_certificate = center.tls().ca_certificate();
    let server_fingerprint = center.server_fingerprint();
    let address = ListenAddress::parse(&format!("127.0.0.1:{}", center.address().port()))?;
    let script = center.script();
    let task = center.serve();
    let config = site_config_from(&address, &ca_certificate, server_fingerprint, &identity)?;

    // The full client establishment: TCP, mTLS, the pin check, the
    // WebSocket upgrade on the center path, and the Hello exchange.
    let mut link = config.connect().await?;

    // One content frame (a liveness heartbeat) is acknowledged with the
    // mock's default ack of its sequence.
    link.send_envelope(Envelope {
        sequence: 1,
        acked_sequence: 0,
        message: Some(EnvelopeMessage::Heartbeat(
            rutilus_center_protocol::Heartbeat { sent_at_unix: 0 },
        )),
    })
    .await?;
    let reply = link.receive_envelope().await?.ok_or("no ack frame")?;
    assert!(matches!(
        reply.message,
        Some(EnvelopeMessage::Ack(Ack { sequence: 1 }))
    ));

    // The mock recorded the Hello and the heartbeat, in order.
    let messages = script.received_messages();
    assert_eq!(messages.len(), 2);
    assert!(matches!(messages[0], EnvelopeMessage::Hello(_)));
    assert!(matches!(messages[1], EnvelopeMessage::Heartbeat(_)));
    task.abort();
    Ok(())
}

#[tokio::test]
async fn the_mock_center_not_bound_refusal_classifies_on_the_real_client()
-> Result<(), Box<dyn Error>> {
    let center = MockCenter::bind().await?;
    center
        .script()
        .set_admission(ScriptedAdmission::RefuseNotBound);
    let identity = center.tls().issue_client_certificate("site-under-test")?;
    let ca_certificate = center.tls().ca_certificate();
    let server_fingerprint = center.server_fingerprint();
    let address = ListenAddress::parse(&format!("127.0.0.1:{}", center.address().port()))?;
    let task = center.serve();
    let config = site_config_from(&address, &ca_certificate, server_fingerprint, &identity)?;

    // The client classifies the mock's `not-bound` answer into its own
    // NotBound error — the audit follow-up F4 convergence signal.
    let error = match config.connect().await {
        Ok(_) => return Err("the refusal must fail".into()),
        Err(error) => error,
    };
    assert!(
        matches!(error, CenterClientError::NotBound),
        "expected NotBound, got {error}"
    );
    task.abort();
    Ok(())
}

#[tokio::test]
async fn the_mock_center_accepts_clients_without_certificates_when_configured()
-> Result<(), Box<dyn Error>> {
    let center = MockCenter::bind_with_options(MockCenterOptions {
        require_client_cert: false,
        ..MockCenterOptions::default()
    })
    .await?;
    let identity = center.tls().issue_client_certificate("site-under-test")?;
    let ca_certificate = center.tls().ca_certificate();
    let server_fingerprint = center.server_fingerprint();
    let address = ListenAddress::parse(&format!("127.0.0.1:{}", center.address().port()))?;
    let task = center.serve();
    // The client still presents a certificate (the real site always has
    // one), but the mock does not require it; the negotiation succeeds.
    let config = site_config_from(&address, &ca_certificate, server_fingerprint, &identity)?;
    let _link = config.connect().await?;
    task.abort();
    Ok(())
}
