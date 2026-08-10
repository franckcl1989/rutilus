//! Real-store integration tests of the center-side use cases (0.7.0 S5).
//!
//! The application use cases are tested against in-memory mocks in the
//! application crate; this module drives the same use cases against the
//! real `SqliteStore`, exactly like the site-side `center_sync_integration`
//! module. The binding flow, the session admission, the §15.5 projection,
//! and the §15.6 dispatch and reply tracking all run against one migrated
//! database.

use std::{error::Error, sync::Mutex};

use rutilus_application::{
    CenterBindingFlow, CenterSessionAdmission, CenterTrustAnchor, IssuedSiteCertificate,
    ResolvedSite, SiteCertificateIssuer,
};
use rutilus_domain::{CertificateFingerprint, InstanceId, InstanceKind};
use time::{Duration, OffsetDateTime};

use crate::SqliteStore;

/// A certificate issuer that records the issuance and answers with a
/// deterministic certificate, for the binding-flow integration test.
struct TestIssuer {
    anchor: CenterTrustAnchor,
    issued: Mutex<Vec<(InstanceId, CertificateFingerprint)>>,
}

impl TestIssuer {
    fn new() -> Self {
        Self {
            anchor: CenterTrustAnchor::new(
                CertificateFingerprint::from_bytes([0xAA; 32]),
                CertificateFingerprint::from_bytes([0xBB; 32]),
            ),
            issued: Mutex::new(Vec::new()),
        }
    }
}

impl SiteCertificateIssuer for TestIssuer {
    type Error = std::io::Error;

    fn issue_site_certificate(
        &self,
        site: InstanceId,
        site_fingerprint: CertificateFingerprint,
    ) -> Result<IssuedSiteCertificate, Self::Error> {
        self.issued
            .lock()
            .map_err(|_| std::io::Error::other("the issuer lock was poisoned"))?
            .push((site, site_fingerprint));
        Ok(IssuedSiteCertificate::new(
            String::from("certificate-pem"),
            String::from("key-pem"),
            site_fingerprint,
        ))
    }

    fn center_trust_anchor(&self) -> CenterTrustAnchor {
        self.anchor
    }
}

async fn store_with_directory() -> Result<(tempfile::TempDir, SqliteStore), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let store = SqliteStore::open(directory.path().join("rutilus.db")).await?;
    Ok((directory, store))
}

fn base_time() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap_or(OffsetDateTime::UNIX_EPOCH)
}

fn site_fingerprint() -> CertificateFingerprint {
    CertificateFingerprint::from_bytes([0x42; 32])
}

#[tokio::test]
async fn the_binding_flow_registers_and_binds_a_site_against_the_real_store()
-> Result<(), Box<dyn Error>> {
    let (directory, store) = store_with_directory().await?;
    let issuer = TestIssuer::new();
    let flow = CenterBindingFlow::new(&store, &issuer);
    let base = base_time();

    let registered = flow
        .register_site("https://center.example", "Site One", base)
        .await?;
    // The registration created the instance row and the pending binding.
    let instance = store
        .find_instance(registered.instance_id())
        .await?
        .ok_or("the instance row is missing")?;
    assert_eq!(instance.kind(), InstanceKind::Site);
    assert_eq!(instance.display_name(), "Site One");
    let pending = store
        .find_binding(registered.binding_id())
        .await?
        .ok_or("the pending binding is missing")?;
    assert_eq!(pending.binding_code_hash(), Some(registered.code().hash()));

    let outcome = flow
        .bind_site(
            registered.code().as_str(),
            site_fingerprint(),
            base + Duration::MINUTE,
        )
        .await?;
    assert_eq!(outcome.site_instance_id(), registered.instance_id());
    assert_eq!(
        outcome.issued_certificate().fingerprint(),
        site_fingerprint()
    );
    assert_eq!(
        outcome.trust_anchor(),
        &CenterTrustAnchor::new(
            CertificateFingerprint::from_bytes([0xAA; 32]),
            CertificateFingerprint::from_bytes([0xBB; 32])
        )
    );
    let bound = store
        .find_binding(registered.binding_id())
        .await?
        .ok_or("the bound binding is missing")?;
    assert_eq!(bound.state(), rutilus_domain::CenterBindingState::Bound);
    assert_eq!(bound.site_cert_fingerprint(), Some(site_fingerprint()));

    // A wrong code is refused against the real store.
    let other = flow
        .register_site("https://center.example", "Site Two", base)
        .await?;
    assert!(matches!(
        flow.bind_site(
            "23456789ABCDEFGHJKLN",
            site_fingerprint(),
            base + Duration::MINUTE
        )
        .await,
        Err(rutilus_application::CenterBindingFlowError::CodeMismatch)
    ));
    assert_ne!(other.instance_id(), registered.instance_id());

    store.close().await?;
    drop(directory);
    Ok(())
}

#[tokio::test]
async fn the_session_admission_resolves_bound_sites_against_the_real_store()
-> Result<(), Box<dyn Error>> {
    let (directory, store) = store_with_directory().await?;
    let issuer = TestIssuer::new();
    let flow = CenterBindingFlow::new(&store, &issuer);
    let base = base_time();
    let registered = flow
        .register_site("https://center.example", "Site One", base)
        .await?;
    flow.bind_site(
        registered.code().as_str(),
        site_fingerprint(),
        base + Duration::MINUTE,
    )
    .await?;

    let admission = CenterSessionAdmission::new(&store);
    let matching = rutilus_application::SiteIdentity::from_parts(
        CertificateFingerprint::from_bytes([0x99; 32]),
        Some(registered.instance_id().to_string()),
        Some(site_fingerprint()),
    );
    let verdict = admission.resolve(&matching).await?;
    assert_eq!(
        verdict,
        rutilus_application::AdmissionVerdict::Admitted(ResolvedSite::new(
            registered.instance_id(),
            registered.binding_id(),
            site_fingerprint()
        ))
    );

    // A certificate whose extension matches no bound binding is refused.
    let unknown = rutilus_application::SiteIdentity::from_parts(
        CertificateFingerprint::from_bytes([0x99; 32]),
        Some(registered.instance_id().to_string()),
        Some(CertificateFingerprint::from_bytes([0x43; 32])),
    );
    assert!(matches!(
        admission.resolve(&unknown).await?,
        rutilus_application::AdmissionVerdict::Rejected { .. }
    ));

    store.close().await?;
    drop(directory);
    Ok(())
}

