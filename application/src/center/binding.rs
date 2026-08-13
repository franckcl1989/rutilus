//! The site-to-center binding flow (design D2, §15.1, 0.7.0 S5).
//!
//! The flow binds one registered site to the center with the one-time D2
//! code:
//!
//! 1. **Registration** — [`CenterBindingFlow::register_site`] creates the
//!    site's `instances` row (D6) and a `Pending` binding carrying only the
//!    SHA-256 hash of a freshly generated one-time code, valid for
//!    [`rutilus_domain::BINDING_CODE_TTL`] (15 minutes, D2). The raw code is
//!    returned exactly once for the operator to hand to the site; it is
//!    never persisted anywhere.
//! 2. **Binding** — [`CenterBindingFlow::bind_site`] accepts the code and
//!    the site's own identity fingerprint, verifies them against the domain
//!    [`rutilus_domain::CenterBinding`] (the atomic consumption happens in
//!    the repository), and records the fingerprint in the `bound` row. The
//!    center then issues the site's client certificate
//!    ([`SiteCertificateIssuer`]) with the site's fingerprint bound into the
//!    private-arc extension, and returns it with the center's trust
//!    material — the server and CA fingerprints the site must pin (§10.4
//!    explicit trust) — so the binding result is the §10.4 carrier.
//!
//! # Revoke before re-bind (V5E-2, V5E-5)
//!
//! The site identity fingerprint is the durable fact of the D2 flow: the
//! site presents the same fingerprint on every registration, so a re-bind
//! is recognized by it. [`CenterBindingFlow::bind_site`] looks the
//! fingerprint up before issuing anything: a fingerprint that still holds a
//! `Bound` binding is refused with [`CenterBindingFlowError::BindingStillInForce`]
//! — the operator must revoke the old binding first, or two live sites
//! would claim the same identity and the V4R-7 re-bind self-healing would
//! leave the endpoints frozen under the old site. A fingerprint whose
//! previous binding was revoked is the re-bind the flow exists for: the
//! dead site's pending §15.6 offers are retired (the queue-level TTL
//! termination of [`CenterBindingFlow::retire_site_offers`], V5E-5) so the
//! old instance id's outbox rows do not linger pending forever.
//!
//! # The certificate-identity cross-validation (S3b audit item 1)
//!
//! [`SiteIdentity`] carries the three facts the app layer parses from a
//! presented client certificate: the certificate fingerprint, the subject
//! common name (the site instance id it was issued for), and the
//! private-arc `bound_site_fingerprint` extension. The extension is signed
//! by the center CA, so it is trustworthy in itself — but the acceptance
//! must still cross-validate it against the binding record
//! ([`validate_bound_identity`]): the binding's recorded site fingerprint
//! is the source of truth for which fingerprint this site bound, and the
//! certificate's extension must agree with it, not the other way around. A
//! certificate issued for a revoked or re-bound registration fails the
//! check even though its signature is valid.
//!
//! # Why the certificate is issued before the bind write
//!
//! [`CenterBindingFlow::bind_site`] issues the certificate before the
//! atomic consumption. The issuance is a local, side-effect-free operation,
//! so a failed bind (the code was consumed by a racing consumer) leaves at
//! most a stray in-memory certificate that is never delivered; the reverse
//! order would leave a bound site with no certificate and no way to retry
//! (the code is consumed). The repository's `bind_with_code` remains the
//! atomic guard against double consumption.

use std::error::Error;

use rutilus_domain::{
    BINDING_CODE_TTL, BindingCode, BindingCodeVerificationError, CenterBinding, CenterBindingId,
    CenterBindingState, CertificateFingerprint, InstanceId, InstanceKind, SiteInstance,
};
use rutilus_security::{BindingCodeError, generate_binding_code};
use thiserror::Error;
use time::OffsetDateTime;

use crate::{BoundaryFuture, CenterOutbox};

/// The certificate identity of one inbound center connection (§15.1, S3b).
///
/// The app layer parses this from the presented client certificate: the
/// certificate's SHA-256 fingerprint, its subject common name (the site
/// instance id the certificate was issued for), and the site-identity
/// fingerprint the CA bound into the private-arc extension at issuance.
/// The binding flow and the session admission speak in this value; the
/// concrete certificate parsing stays in the app crate behind the
/// application boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SiteIdentity {
    fingerprint: CertificateFingerprint,
    subject: Option<String>,
    bound_site_fingerprint: Option<CertificateFingerprint>,
}

impl SiteIdentity {
    #[must_use]
    pub const fn from_parts(
        fingerprint: CertificateFingerprint,
        subject: Option<String>,
        bound_site_fingerprint: Option<CertificateFingerprint>,
    ) -> Self {
        Self {
            fingerprint,
            subject,
            bound_site_fingerprint,
        }
    }

    /// The SHA-256 fingerprint of the presented client certificate.
    #[must_use]
    pub const fn fingerprint(&self) -> CertificateFingerprint {
        self.fingerprint
    }

    /// The subject common name of the presented certificate: the site
    /// instance id the certificate was issued for.
    #[must_use]
    pub fn subject(&self) -> Option<&str> {
        self.subject.as_deref()
    }

    /// The site-identity fingerprint bound into the certificate's
    /// private-arc extension at issuance.
    #[must_use]
    pub const fn bound_site_fingerprint(&self) -> Option<CertificateFingerprint> {
        self.bound_site_fingerprint
    }
}

/// Why a presented certificate identity cannot be matched to a binding
/// (S3b audit item 1).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityValidationError {
    /// The binding is not in the `Bound` state (revoked, or still pending).
    NotBound,
    /// The presented certificate carries no site-identity extension.
    ExtensionMissing,
    /// The certificate's bound site fingerprint disagrees with the binding
    /// record: the certificate was issued for a different site identity
    /// than the one this binding recorded.
    ExtensionMismatch,
    /// The certificate's subject common name is not the bound site's
    /// instance id.
    SubjectMismatch,
}

impl std::fmt::Display for IdentityValidationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotBound => formatter.write_str("the binding is not in the bound state"),
            Self::ExtensionMissing => {
                formatter.write_str("the certificate carries no site-identity extension")
            }
            Self::ExtensionMismatch => formatter.write_str(
                "the certificate's site-identity extension disagrees with the binding record",
            ),
            Self::SubjectMismatch => {
                formatter.write_str("the certificate's subject is not the bound site instance")
            }
        }
    }
}

impl Error for IdentityValidationError {}

/// Cross-validates a presented certificate identity against its binding
/// record (S3b audit item 1, §15.1).
///
/// The binding record is the source of truth for the bound site: the site
/// fingerprint it recorded at bind time must equal the fingerprint bound
/// into the presented certificate's private-arc extension, and the
/// certificate's subject common name must name the bound site instance.
/// The binding must also be in the `Bound` state — a certificate whose
/// binding was revoked or never completed is refused even though its CA
/// signature verifies.
///
/// # Errors
///
/// Returns [`IdentityValidationError`] when the binding is not bound, the
/// extension is missing or disagrees with the record, or the subject names
/// a different instance.
pub fn validate_bound_identity(
    binding: &CenterBinding,
    identity: &SiteIdentity,
) -> Result<(), IdentityValidationError> {
    if binding.state() != CenterBindingState::Bound {
        return Err(IdentityValidationError::NotBound);
    }
    let bound_fingerprint = identity
        .bound_site_fingerprint()
        .ok_or(IdentityValidationError::ExtensionMissing)?;
    if binding.site_cert_fingerprint() != Some(bound_fingerprint) {
        return Err(IdentityValidationError::ExtensionMismatch);
    }
    if identity.subject() != Some(binding.site_instance_id().to_string().as_str()) {
        return Err(IdentityValidationError::SubjectMismatch);
    }
    Ok(())
}

/// The client certificate the center issued for one bound site, with the
/// private key generated by the center for delivery to the site.
///
/// The certificate and key travel as PEM text — the exact bytes the site
/// persists below its `tls/` folder — and the certificate fingerprint is
/// the identity the site will present. The center never persists the
/// private key (the app crate's `SiteClientCertificate` contract), so this
/// value is the one-time carrier of the whole material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuedSiteCertificate {
    certificate_pem: String,
    key_pem: String,
    fingerprint: CertificateFingerprint,
}

impl IssuedSiteCertificate {
    #[must_use]
    pub const fn new(
        certificate_pem: String,
        key_pem: String,
        fingerprint: CertificateFingerprint,
    ) -> Self {
        Self {
            certificate_pem,
            key_pem,
            fingerprint,
        }
    }

    /// The issued client certificate as PEM text.
    #[must_use]
    pub fn certificate_pem(&self) -> &str {
        &self.certificate_pem
    }

    /// The issued client certificate's private key as PEM text.
    #[must_use]
    pub fn key_pem(&self) -> &str {
        &self.key_pem
    }

    /// The SHA-256 fingerprint of the issued certificate.
    #[must_use]
    pub const fn fingerprint(&self) -> CertificateFingerprint {
        self.fingerprint
    }
}

/// The center's trust material a bound site must pin (§10.4).
///
/// The server certificate fingerprint is the center's own identity the site
/// pins for the TLS connection; the CA certificate fingerprint is the
/// anchor the site loads to verify the center. Both travel with the binding
/// result so the site can establish explicit trust before its first
/// connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CenterTrustAnchor {
    server_fingerprint: CertificateFingerprint,
    ca_fingerprint: CertificateFingerprint,
}

impl CenterTrustAnchor {
    #[must_use]
    pub const fn new(
        server_fingerprint: CertificateFingerprint,
        ca_fingerprint: CertificateFingerprint,
    ) -> Self {
        Self {
            server_fingerprint,
            ca_fingerprint,
        }
    }

    /// The SHA-256 fingerprint of the center's server certificate.
    #[must_use]
    pub const fn server_fingerprint(&self) -> CertificateFingerprint {
        self.server_fingerprint
    }

    /// The SHA-256 fingerprint of the center CA certificate.
    #[must_use]
    pub const fn ca_fingerprint(&self) -> CertificateFingerprint {
        self.ca_fingerprint
    }
}

/// The certificate-issuance boundary of the binding flow (design §15, S3b).
///
/// The application defines the boundary; the app crate implements it over
/// its `CenterCa` (which owns the signing key and the persisted CA
/// identity). The issued certificate is bound to the site instance id and
/// the site's identity fingerprint, and the trust anchor is the material
/// the app's `CenterAcceptor` publishes.
pub trait SiteCertificateIssuer: Send + Sync {
    /// The issuer's controlled failure type.
    type Error: Error + Send + Sync + 'static;

    /// Issues one client certificate for a bound site.
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] when the CA cannot sign.
    fn issue_site_certificate(
        &self,
        site: InstanceId,
        site_fingerprint: CertificateFingerprint,
    ) -> Result<IssuedSiteCertificate, Self::Error>;

    /// The center's trust material a bound site must pin (§10.4).
    fn center_trust_anchor(&self) -> CenterTrustAnchor;
}

impl<Issuer> SiteCertificateIssuer for &Issuer
where
    Issuer: SiteCertificateIssuer + ?Sized,
{
    type Error = Issuer::Error;

    fn issue_site_certificate(
        &self,
        site: InstanceId,
        site_fingerprint: CertificateFingerprint,
    ) -> Result<IssuedSiteCertificate, Self::Error> {
        Issuer::issue_site_certificate(*self, site, site_fingerprint)
    }

    fn center_trust_anchor(&self) -> CenterTrustAnchor {
        Issuer::center_trust_anchor(*self)
    }
}

/// The site-instance boundary of the center-side use cases (design D6).
///
/// On the center side an `instances` row names one registered site; the
/// binding flow creates it at registration, and the session admission reads
/// it back for the connection's site record.
pub trait InstanceRepository: Send + Sync {
    /// The repository's controlled failure type.
    type Error: Error + Send + Sync + 'static;

    /// Persists one registered deployment identity.
    fn create_instance<'a>(
        &'a self,
        instance: &'a SiteInstance,
    ) -> BoundaryFuture<'a, Result<(), Self::Error>>;

    /// Reads one registered deployment by stable identity.
    fn find_instance(
        &self,
        instance_id: InstanceId,
    ) -> BoundaryFuture<'_, Result<Option<SiteInstance>, Self::Error>>;
}

impl<Store> InstanceRepository for &Store
where
    Store: InstanceRepository + ?Sized,
{
    type Error = Store::Error;

    fn create_instance<'a>(
        &'a self,
        instance: &'a SiteInstance,
    ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
        Store::create_instance(*self, instance)
    }

    fn find_instance(
        &self,
        instance_id: InstanceId,
    ) -> BoundaryFuture<'_, Result<Option<SiteInstance>, Self::Error>> {
        Store::find_instance(*self, instance_id)
    }
}

/// The site-to-center binding boundary of the center-side use cases
/// (design D2, D6).
///
/// The four methods mirror the concrete store surface: the pending
/// registration with its one-time code hash, the atomic code consumption,
/// and the bound-by-fingerprint lookup the session admission keys on. The
/// atomicity contract of `bind_with_code` (re-read, domain verification,
/// conditional update) lives in the implementing repository; the flow's own
/// pre-checks only avoid the side effects of a doomed bind.
pub trait CenterBindingRepository: Send + Sync {
    /// The repository's controlled failure type.
    type Error: Error + Send + Sync + 'static;

    /// Persists one new pending binding.
    fn create_binding<'a>(
        &'a self,
        binding: &'a CenterBinding,
    ) -> BoundaryFuture<'a, Result<(), Self::Error>>;

    /// Matches a presented code hash to its pending registration.
    fn find_pending_binding_by_code_hash(
        &self,
        code_hash: &[u8; 32],
    ) -> BoundaryFuture<'_, Result<Option<CenterBinding>, Self::Error>>;

    /// Binds the site with its one-time code, consuming it atomically.
    fn bind_with_code<'a>(
        &'a self,
        binding_id: CenterBindingId,
        code: &'a BindingCode,
        site_cert_fingerprint: Option<CertificateFingerprint>,
        now: OffsetDateTime,
    ) -> BoundaryFuture<'a, Result<(), Self::Error>>;

    /// Reads the most recent binding recorded for one site identity
    /// fingerprint. The state decides the verdict — the session admission
    /// cross-validates a found binding, so a revoked or re-bound
    /// registration is refused there, never here.
    fn find_binding_by_site_fingerprint(
        &self,
        site_fingerprint: CertificateFingerprint,
    ) -> BoundaryFuture<'_, Result<Option<CenterBinding>, Self::Error>>;
}

impl<Store> CenterBindingRepository for &Store
where
    Store: CenterBindingRepository + ?Sized,
{
    type Error = Store::Error;

    fn create_binding<'a>(
        &'a self,
        binding: &'a CenterBinding,
    ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
        Store::create_binding(*self, binding)
    }

    fn find_pending_binding_by_code_hash(
        &self,
        code_hash: &[u8; 32],
    ) -> BoundaryFuture<'_, Result<Option<CenterBinding>, Self::Error>> {
        Store::find_pending_binding_by_code_hash(*self, code_hash)
    }

    fn bind_with_code<'a>(
        &'a self,
        binding_id: CenterBindingId,
        code: &'a BindingCode,
        site_cert_fingerprint: Option<CertificateFingerprint>,
        now: OffsetDateTime,
    ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
        Store::bind_with_code(*self, binding_id, code, site_cert_fingerprint, now)
    }

    fn find_binding_by_site_fingerprint(
        &self,
        site_fingerprint: CertificateFingerprint,
    ) -> BoundaryFuture<'_, Result<Option<CenterBinding>, Self::Error>> {
        Store::find_binding_by_site_fingerprint(*self, site_fingerprint)
    }
}

/// The center-side site-to-center binding flow (design D2, §15.1).
///
/// `Store` is the persistence boundary (instances and bindings on one
/// store, exactly like every other application use case) and `Issuer` the
/// certificate boundary the app crate implements over its CA.
pub struct CenterBindingFlow<Store, Issuer> {
    store: Store,
    issuer: Issuer,
}

impl<Store, Issuer> CenterBindingFlow<Store, Issuer> {
    #[must_use]
    pub const fn new(store: Store, issuer: Issuer) -> Self {
        Self { store, issuer }
    }
}

/// One registered site: the instance identity, the pending binding, and the
/// one-time code shown to the operator exactly once.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegisteredSite {
    instance_id: InstanceId,
    binding_id: CenterBindingId,
    code: BindingCode,
    expires_at: OffsetDateTime,
}

impl RegisteredSite {
    #[must_use]
    pub const fn new(
        instance_id: InstanceId,
        binding_id: CenterBindingId,
        code: BindingCode,
        expires_at: OffsetDateTime,
    ) -> Self {
        Self {
            instance_id,
            binding_id,
            code,
            expires_at,
        }
    }

    /// The registered site's instance identity.
    #[must_use]
    pub const fn instance_id(&self) -> InstanceId {
        self.instance_id
    }

    /// The pending binding's identity.
    #[must_use]
    pub const fn binding_id(&self) -> CenterBindingId {
        self.binding_id
    }

    /// The one-time binding code; shown to the operator once and never
    /// persisted.
    #[must_use]
    pub fn code(&self) -> &BindingCode {
        &self.code
    }

    /// When the outstanding code stops being usable (D2 TTL).
    #[must_use]
    pub const fn expires_at(&self) -> OffsetDateTime {
        self.expires_at
    }
}

/// The outcome of one successful bind: the bound site identity, the issued
/// client certificate, and the center's §10.4 trust material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BindOutcome {
    site_instance_id: InstanceId,
    binding_id: CenterBindingId,
    issued_certificate: IssuedSiteCertificate,
    trust_anchor: CenterTrustAnchor,
}

impl BindOutcome {
    #[must_use]
    pub const fn new(
        site_instance_id: InstanceId,
        binding_id: CenterBindingId,
        issued_certificate: IssuedSiteCertificate,
        trust_anchor: CenterTrustAnchor,
    ) -> Self {
        Self {
            site_instance_id,
            binding_id,
            issued_certificate,
            trust_anchor,
        }
    }

    /// The bound site's instance identity.
    #[must_use]
    pub const fn site_instance_id(&self) -> InstanceId {
        self.site_instance_id
    }

    /// The now-bound binding's identity.
    #[must_use]
    pub const fn binding_id(&self) -> CenterBindingId {
        self.binding_id
    }

    /// The client certificate the site must load and present on its
    /// connections (§15.1).
    #[must_use]
    pub const fn issued_certificate(&self) -> &IssuedSiteCertificate {
        &self.issued_certificate
    }

    /// The center fingerprints the site must pin (§10.4).
    #[must_use]
    pub const fn trust_anchor(&self) -> &CenterTrustAnchor {
        &self.trust_anchor
    }
}

/// A controlled failure of one binding-flow step.
///
/// The three generic parameters are the instance repository's, the binding
/// repository's, and the certificate issuer's error types, so every
/// boundary failure stays reachable as the source of an error chain. The
/// operator-facing verdicts (`MalformedCode`, `CodeMismatch`, `CodeExpired`)
/// are the flow's own judgments from the presented code and the stored
/// binding; the repository errors that follow a pre-verified bind (a racing
/// consumer consumed the code between the lookup and the write) surface
/// inside `Binding` — the pre-check makes them a race, not an operator
/// mistake.
#[derive(Debug, Error)]
pub enum CenterBindingFlowError<InstanceError, BindingError, IssuerError>
where
    InstanceError: Error + 'static,
    BindingError: Error + 'static,
    IssuerError: Error + 'static,
{
    /// A presented code is not in the canonical D2 shape.
    #[error("the presented binding code is not in the canonical shape")]
    MalformedCode,
    /// The presented code matches no outstanding (pending) registration:
    /// it was never issued, or it was already consumed by an earlier bind.
    #[error("the presented code matches no outstanding registration")]
    CodeMismatch,
    /// The outstanding code has expired at the verification time (D2 TTL).
    #[error("the binding code has expired")]
    CodeExpired,
    /// The binding is not pending, so no code can bind it.
    #[error("the binding is not pending")]
    BindingNotPending,
    /// The presented site identity fingerprint already holds a binding in
    /// force (V5E-2): the operator must revoke that binding before a re-bind
    /// — otherwise two live sites would claim the same identity, and the
    /// endpoints of the old site would stay frozen under it.
    #[error(
        "the site identity is already bound to instance {site}; revoke that binding before binding a new one"
    )]
    BindingStillInForce { site: InstanceId },
    /// A one-time code could not be generated.
    #[error("a binding code could not be generated: {0}")]
    CodeGeneration(#[source] BindingCodeError),
    /// The instance repository failed; carries its own error.
    #[error("the instance repository failed: {0}")]
    Instance(#[source] InstanceError),
    /// The binding repository failed; carries its own error.
    #[error("the binding repository failed: {0}")]
    Binding(#[source] BindingError),
    /// The certificate issuer failed; carries its own error.
    #[error("the certificate issuer failed: {0}")]
    Issuer(#[source] IssuerError),
}

/// The concrete failure type of one binding-flow step.
type FlowError<Store, Issuer> = CenterBindingFlowError<
    <Store as InstanceRepository>::Error,
    <Store as CenterBindingRepository>::Error,
    <Issuer as SiteCertificateIssuer>::Error,
>;

impl<Store, Issuer> CenterBindingFlow<Store, Issuer>
where
    Store: InstanceRepository + CenterBindingRepository,
    Issuer: SiteCertificateIssuer,
{
    /// Registers a new site: the `instances` row (D6) and a `Pending`
    /// binding carrying the hash of a freshly generated one-time code
    /// (D2). The raw code is returned to the operator exactly once and is
    /// never persisted.
    ///
    /// `center_url` is the URL the site must connect to, recorded on the
    /// binding; `now` is the caller-supplied creation time with the usual
    /// monotonic-clock contract.
    ///
    /// # Errors
    ///
    /// Returns [`CenterBindingFlowError::CodeGeneration`] when the one-time
    /// code cannot be drawn from the OS randomness, and the repository
    /// variants when the instance or the pending binding cannot be
    /// persisted. A binding write failure leaves the created instance row
    /// behind (the two writes are not one transaction at this boundary);
    /// the operator retries the registration, which creates a fresh
    /// instance identity.
    pub async fn register_site(
        &self,
        center_url: &str,
        display_name: &str,
        now: OffsetDateTime,
    ) -> Result<RegisteredSite, FlowError<Store, Issuer>> {
        let code = generate_binding_code().map_err(CenterBindingFlowError::CodeGeneration)?;
        let instance_id = InstanceId::generate();
        let instance = SiteInstance::new(
            instance_id,
            display_name.to_owned(),
            InstanceKind::Site,
            now,
        );
        self.store
            .create_instance(&instance)
            .await
            .map_err(CenterBindingFlowError::Instance)?;
        let binding = CenterBinding::new_pending(
            CenterBindingId::generate(),
            center_url.to_owned(),
            instance_id,
            &code,
            now + BINDING_CODE_TTL,
            now,
        );
        let binding_id = binding.id();
        let expires_at = binding.expires_at().unwrap_or(now);
        self.store
            .create_binding(&binding)
            .await
            .map_err(CenterBindingFlowError::Binding)?;
        Ok(RegisteredSite::new(
            instance_id,
            binding_id,
            code,
            expires_at,
        ))
    }
}

impl<Store, Issuer> CenterBindingFlow<Store, Issuer>
where
    Store: InstanceRepository + CenterBindingRepository + CenterOutbox,
    Issuer: SiteCertificateIssuer,
{
    /// Binds a registered site with its one-time code and the site's own
    /// identity fingerprint.
    ///
    /// The presented code is parsed and matched to its pending registration
    /// by hash; the outstanding code must not be expired (D2 TTL). The site
    /// identity fingerprint is then checked against its previous bindings
    /// (V5E-2): a fingerprint that still holds a `Bound` binding is refused
    /// — the operator must revoke the old binding first — and a fingerprint
    /// whose previous binding was revoked is the re-bind path, whose dead
    /// site's pending §15.6 offers are retired (V5E-5). The certificate is
    /// issued after the pre-checks — see the module doc — with the site's
    /// fingerprint bound into the private-arc extension, and the consumption
    /// records the fingerprint on the `bound` row. The result carries the
    /// issued certificate and the center's §10.4 trust material for the site
    /// to pin.
    ///
    /// # Errors
    ///
    /// Returns [`CenterBindingFlowError::MalformedCode`] for a code outside
    /// the canonical D2 shape, [`CenterBindingFlowError::CodeMismatch`]
    /// when the code matches no outstanding registration (wrong, or already
    /// consumed), [`CenterBindingFlowError::CodeExpired`] when the
    /// outstanding code has expired, and the repository and issuer variants
    /// for boundary failures.
    pub async fn bind_site(
        &self,
        presented_code: &str,
        site_fingerprint: CertificateFingerprint,
        now: OffsetDateTime,
    ) -> Result<BindOutcome, FlowError<Store, Issuer>> {
        let code: BindingCode = presented_code
            .parse()
            .map_err(|_| CenterBindingFlowError::MalformedCode)?;
        let Some(binding) = self
            .store
            .find_pending_binding_by_code_hash(&code.hash())
            .await
            .map_err(CenterBindingFlowError::Binding)?
        else {
            return Err(CenterBindingFlowError::CodeMismatch);
        };
        // The pre-verification keeps a doomed bind from receiving a
        // certificate; the repository's atomic consumption re-verifies and
        // remains the guard against double use.
        binding
            .verify_code(&code, now)
            .map_err(|error| match error {
                BindingCodeVerificationError::CodeMismatch => {
                    // Unreachable after the hash-matched lookup; the
                    // constant-time compare cannot disagree with the index.
                    CenterBindingFlowError::CodeMismatch
                }
                BindingCodeVerificationError::Expired => CenterBindingFlowError::CodeExpired,
                BindingCodeVerificationError::NotPending => {
                    CenterBindingFlowError::BindingNotPending
                }
            })?;
        // V5E-2/V5E-5: the site identity fingerprint is the durable fact of
        // the D2 flow — the same site presents it on every registration —
        // so the previous binding it resolves to decides the re-bind. A
        // still-`Bound` previous binding is refused before anything is
        // issued: accepting it would leave two live sites claiming the same
        // identity, and the V4R-7 re-bind self-healing would keep the old
        // site's endpoints frozen under it (a revoked binding is what the
        // re-home path treats as the operator's unbind). A previous binding
        // that was revoked is the re-bind the flow exists for, and the dead
        // site's pending offers are retired below. The pending binding being
        // bound can never match this lookup: the fingerprint is recorded on
        // a binding only at consumption, so the pending row carries `None`.
        if let Some(previous) = self
            .store
            .find_binding_by_site_fingerprint(site_fingerprint)
            .await
            .map_err(CenterBindingFlowError::Binding)?
        {
            if previous.state() == CenterBindingState::Bound {
                return Err(CenterBindingFlowError::BindingStillInForce {
                    site: previous.site_instance_id(),
                });
            }
            // V5E-5: the revoked site can never connect again (admission
            // refuses its certificate), so its pending §15.6 offers are
            // dead — retire them like the flush's TTL retirement instead of
            // leaving the old instance id's queue pending forever.
            self.retire_site_offers(previous.site_instance_id(), now)
                .await;
        }
        let issued = self
            .issuer
            .issue_site_certificate(binding.site_instance_id(), site_fingerprint)
            .map_err(CenterBindingFlowError::Issuer)?;
        let binding_id = binding.id();
        let site_instance_id = binding.site_instance_id();
        self.store
            .bind_with_code(binding_id, &code, Some(site_fingerprint), now)
            .await
            .map_err(CenterBindingFlowError::Binding)?;
        Ok(BindOutcome::new(
            site_instance_id,
            binding_id,
            issued,
            self.issuer.center_trust_anchor(),
        ))
    }

    /// Retires the pending §15.6 offers of a site whose binding was revoked
    /// (V5E-5): the queue-level TTL termination of the old instance id's
    /// outbox rows.
    ///
    /// The center's durable outbox holds exactly the §15.6 offers, and the
    /// revoked site is refused at connection admission forever, so every
    /// pending row of the old id is dead — the same judgment as the flush's
    /// TTL retirement, which only runs for a site that reconnects. The
    /// retirement acknowledges each row, leaving it the same retired
    /// delivered-history state the flush leaves behind; a dispatch retry can
    /// never resurrect it under a fresh id, and the new site's queue is
    /// never touched.
    ///
    /// The retirement is best-effort by design: a failed retire leaves the
    /// dead rows pending exactly as before (the status quo), and a bind must
    /// not fail because a cleanup write failed — the failure is logged at
    /// `warn` so the operator sees it.
    async fn retire_site_offers(&self, site: InstanceId, now: OffsetDateTime) {
        let pending = match self.store.list_pending(site, u64::MAX).await {
            Ok(pending) => pending,
            Err(source) => {
                tracing::warn!(
                    "site {site}: could not read the revoked site's pending offers to retire \
                     them: {source}"
                );
                return;
            }
        };
        for entry in pending {
            if let Err(source) = self.store.acknowledge(entry.id(), now).await {
                tracing::warn!(
                    "site {site}: could not retire the pending offer {}: {source}",
                    entry.id()
                );
            }
        }
    }
}

/// The test-side in-memory store and issuer behind the center-side use-case
/// tests, shared by every `center` module.
#[cfg(test)]
pub(crate) mod test_support {
    use std::{error::Error, sync::Mutex};

    use rutilus_center_protocol::{Envelope, EnvelopeMessage};
    use rutilus_domain::{
        BindingCode, CenterBinding, CenterBindingId, CenterBindingState, CertificateFingerprint,
        InstanceId, OutboxEntry, OutboxEntryId, OutboxEntryState, SiteInstance,
    };
    use time::OffsetDateTime;

    use crate::{BoundaryFuture, CenterOutbox};

    use super::{
        CenterBindingRepository, CenterTrustAnchor, InstanceRepository, IssuedSiteCertificate,
        SiteCertificateIssuer,
    };

    /// A store error that cannot occur: every mock operation succeeds.
    #[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
    #[error("a mock store never fails")]
    pub(crate) struct MockStoreError;

    /// An in-memory store behind the center-side boundaries. The bind
    /// consumes through the domain state machine, so the tests drive the
    /// real `CenterBinding` judgment.
    pub(crate) struct MockBindingStore {
        instances: Mutex<Vec<SiteInstance>>,
        bindings: Mutex<Vec<CenterBinding>>,
        entries: Mutex<Vec<OutboxEntry>>,
    }

    impl MockBindingStore {
        pub(crate) fn new() -> Self {
            Self {
                instances: Mutex::new(Vec::new()),
                bindings: Mutex::new(Vec::new()),
                entries: Mutex::new(Vec::new()),
            }
        }

        /// Revokes one binding row through the domain state machine — the
        /// operator's unbind of the V5E-2 re-bind test.
        pub(crate) fn revoke_binding(
            &self,
            binding_id: CenterBindingId,
        ) -> Result<(), MockStoreError> {
            let mut rows = self.bindings.lock().map_err(|_| MockStoreError)?;
            let binding = rows
                .iter_mut()
                .find(|binding| binding.id() == binding_id)
                .ok_or(MockStoreError)?;
            binding.revoke().map_err(|_| MockStoreError)
        }

        /// Seeds one pending outbox entry for a site — a dispatched §15.6
        /// offer the V5E-5 retirement must retire.
        pub(crate) fn seed_pending_offer(
            &self,
            site: InstanceId,
            now: OffsetDateTime,
        ) -> Result<(), MockStoreError> {
            let envelope = Envelope {
                sequence: 1,
                acked_sequence: 0,
                message: Some(EnvelopeMessage::OperationOffer(
                    rutilus_center_protocol::OperationOffer {
                        operation_id: String::from("operation-1"),
                        endpoint_id: String::from("endpoint-1"),
                        site_id: site.to_string(),
                        command_json: b"{}".to_vec(),
                        target: String::from("/redfish/v1/Systems/1"),
                        expires_at_unix: now.unix_timestamp(),
                        actor_context: String::from("principal-1"),
                    },
                )),
            };
            let payload_json = serde_json::to_string(&envelope).map_err(|_| MockStoreError)?;
            let sequence = i64::try_from(
                self.entries
                    .lock()
                    .map_err(|_| MockStoreError)?
                    .iter()
                    .filter(|entry| entry.instance_id() == site)
                    .count(),
            )
            .unwrap_or(i64::MAX)
            .saturating_add(1);
            self.entries
                .lock()
                .map_err(|_| MockStoreError)?
                .push(OutboxEntry::new(
                    OutboxEntryId::generate(),
                    site,
                    sequence,
                    payload_json,
                    now,
                ));
            Ok(())
        }

        /// The pending outbox entry ids of one site — the observable queue
        /// of the V5E-5 retirement.
        pub(crate) fn pending_offer_ids(
            &self,
            site: InstanceId,
        ) -> Result<Vec<OutboxEntryId>, MockStoreError> {
            Ok(self
                .entries
                .lock()
                .map_err(|_| MockStoreError)?
                .iter()
                .filter(|entry| {
                    entry.instance_id() == site && entry.state() == OutboxEntryState::Pending
                })
                .map(OutboxEntry::id)
                .collect())
        }

        /// Seeds one binding row directly, for admission tests that need a
        /// pre-existing bound or revoked binding.
        pub(crate) fn seed_bound(&self, binding: CenterBinding) {
            self.bindings
                .lock()
                .map_err(|_| std::io::Error::other("the mock store lock was poisoned"))
                .map(|mut rows| rows.push(binding))
                .ok();
        }

        /// The identity of the seeded binding.
        pub(crate) fn seeded_binding_id(&self) -> CenterBindingId {
            self.bindings.lock().map_or_else(
                |_| CenterBindingId::generate(),
                |rows| {
                    rows.first()
                        .map_or(CenterBindingId::generate(), CenterBinding::id)
                },
            )
        }

        pub(crate) fn find_binding_owned(
            &self,
            binding_id: CenterBindingId,
        ) -> Result<Option<CenterBinding>, Box<dyn Error>> {
            Ok(self
                .bindings
                .lock()
                .map_err(|_| std::io::Error::other("the mock store lock was poisoned"))?
                .iter()
                .find(|binding| binding.id() == binding_id)
                .cloned())
        }

        pub(crate) fn find_instance_owned(
            &self,
            instance_id: InstanceId,
        ) -> Result<Option<SiteInstance>, Box<dyn Error>> {
            Ok(self
                .instances
                .lock()
                .map_err(|_| std::io::Error::other("the mock store lock was poisoned"))?
                .iter()
                .find(|instance| instance.id() == instance_id)
                .cloned())
        }
    }

    impl InstanceRepository for MockBindingStore {
        type Error = MockStoreError;

        fn create_instance<'a>(
            &'a self,
            instance: &'a SiteInstance,
        ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
            Box::pin(async move {
                self.instances
                    .lock()
                    .map_err(|_| MockStoreError)?
                    .push(instance.clone());
                Ok(())
            })
        }

        fn find_instance(
            &self,
            instance_id: InstanceId,
        ) -> BoundaryFuture<'_, Result<Option<SiteInstance>, Self::Error>> {
            Box::pin(async move {
                Ok(self
                    .instances
                    .lock()
                    .map_err(|_| MockStoreError)?
                    .iter()
                    .find(|instance| instance.id() == instance_id)
                    .cloned())
            })
        }
    }

    impl CenterBindingRepository for MockBindingStore {
        type Error = MockStoreError;

        fn create_binding<'a>(
            &'a self,
            binding: &'a CenterBinding,
        ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
            Box::pin(async move {
                self.bindings
                    .lock()
                    .map_err(|_| MockStoreError)?
                    .push(binding.clone());
                Ok(())
            })
        }

        fn find_pending_binding_by_code_hash(
            &self,
            code_hash: &[u8; 32],
        ) -> BoundaryFuture<'_, Result<Option<CenterBinding>, Self::Error>> {
            // The hash is copied before the async block: the returned
            // future outlives the borrow of the caller's array.
            let code_hash = *code_hash;
            Box::pin(async move {
                Ok(self
                    .bindings
                    .lock()
                    .map_err(|_| MockStoreError)?
                    .iter()
                    .find(|binding| {
                        binding.state() == CenterBindingState::Pending
                            && binding.binding_code_hash() == Some(code_hash)
                    })
                    .cloned())
            })
        }

        fn bind_with_code<'a>(
            &'a self,
            binding_id: CenterBindingId,
            code: &'a BindingCode,
            site_cert_fingerprint: Option<CertificateFingerprint>,
            now: OffsetDateTime,
        ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
            Box::pin(async move {
                let mut rows = self.bindings.lock().map_err(|_| MockStoreError)?;
                let binding = rows
                    .iter_mut()
                    .find(|binding| binding.id() == binding_id)
                    .ok_or(MockStoreError)?;
                binding.verify_code(code, now).map_err(|_| MockStoreError)?;
                binding
                    .bind(site_cert_fingerprint, now)
                    .map_err(|_| MockStoreError)?;
                Ok(())
            })
        }

        fn find_binding_by_site_fingerprint(
            &self,
            site_fingerprint: CertificateFingerprint,
        ) -> BoundaryFuture<'_, Result<Option<CenterBinding>, Self::Error>> {
            Box::pin(async move {
                Ok(self
                    .bindings
                    .lock()
                    .map_err(|_| MockStoreError)?
                    .iter()
                    .rev()
                    .find(|binding| binding.site_cert_fingerprint() == Some(site_fingerprint))
                    .cloned())
            })
        }
    }

    impl CenterOutbox for MockBindingStore {
        type Error = MockStoreError;

        fn enqueue<'a>(
            &'a self,
            _instance_id: InstanceId,
            _message: &'a EnvelopeMessage,
            _created_at: OffsetDateTime,
        ) -> BoundaryFuture<'a, Result<OutboxEntry, Self::Error>> {
            Box::pin(async move { Err(MockStoreError) })
        }

        fn list_pending(
            &self,
            instance_id: InstanceId,
            limit: u64,
        ) -> BoundaryFuture<'_, Result<Vec<OutboxEntry>, Self::Error>> {
            Box::pin(async move {
                let mut rows = self
                    .entries
                    .lock()
                    .map_err(|_| MockStoreError)?
                    .iter()
                    .filter(|entry| {
                        entry.instance_id() == instance_id
                            && entry.state() == OutboxEntryState::Pending
                    })
                    .cloned()
                    .collect::<Vec<_>>();
                rows.sort_by_key(OutboxEntry::sequence);
                rows.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
                Ok(rows)
            })
        }

        fn list_offers(
            &self,
            instance_id: InstanceId,
        ) -> BoundaryFuture<'_, Result<Vec<OutboxEntry>, Self::Error>> {
            Box::pin(async move {
                let mut rows = self
                    .entries
                    .lock()
                    .map_err(|_| MockStoreError)?
                    .iter()
                    .filter(|entry| entry.instance_id() == instance_id)
                    .cloned()
                    .collect::<Vec<_>>();
                rows.sort_by_key(OutboxEntry::sequence);
                Ok(rows)
            })
        }

        fn acknowledge(
            &self,
            entry_id: OutboxEntryId,
            acked_at: OffsetDateTime,
        ) -> BoundaryFuture<'_, Result<(), Self::Error>> {
            Box::pin(async move {
                let mut rows = self.entries.lock().map_err(|_| MockStoreError)?;
                let entry = rows
                    .iter_mut()
                    .find(|entry| entry.id() == entry_id)
                    .ok_or(MockStoreError)?;
                entry.ack(acked_at).map_err(|_| MockStoreError)
            })
        }
    }

    /// A certificate issuer that records the issuance and answers with a
    /// deterministic certificate and trust anchor.
    pub(crate) struct MockIssuer {
        issued: Mutex<Vec<(InstanceId, CertificateFingerprint)>>,
        anchor: CenterTrustAnchor,
    }

    impl MockIssuer {
        pub(crate) fn new() -> Self {
            Self {
                issued: Mutex::new(Vec::new()),
                anchor: CenterTrustAnchor::new(
                    CertificateFingerprint::from_bytes([0xAA; 32]),
                    CertificateFingerprint::from_bytes([0xBB; 32]),
                ),
            }
        }

        pub(crate) fn issued_owned(
            &self,
        ) -> Result<Vec<(InstanceId, CertificateFingerprint)>, Box<dyn Error>> {
            Ok(self
                .issued
                .lock()
                .map_err(|_| std::io::Error::other("the mock store lock was poisoned"))?
                .clone())
        }
    }

    impl SiteCertificateIssuer for MockIssuer {
        type Error = MockStoreError;

        fn issue_site_certificate(
            &self,
            site: InstanceId,
            site_fingerprint: CertificateFingerprint,
        ) -> Result<IssuedSiteCertificate, Self::Error> {
            self.issued
                .lock()
                .map_err(|_| MockStoreError)?
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
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use rutilus_domain::{
        BINDING_CODE_TTL, BindingCode, CenterBinding, CenterBindingId, CenterBindingState,
        CertificateFingerprint, InstanceId, InstanceKind, SiteInstance,
    };
    use time::{Duration, OffsetDateTime};

    use super::test_support::{MockBindingStore, MockIssuer};
    use super::*;

    fn flow<'a>(
        store: &'a MockBindingStore,
        issuer: &'a MockIssuer,
    ) -> CenterBindingFlow<&'a MockBindingStore, &'a MockIssuer> {
        CenterBindingFlow::new(store, issuer)
    }

    fn base_time() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap_or(OffsetDateTime::UNIX_EPOCH)
    }

    #[tokio::test]
    async fn registration_creates_the_instance_and_a_pending_binding_with_a_ttl_bounded_code()
    -> Result<(), Box<dyn Error>> {
        let store = MockBindingStore::new();
        let issuer = MockIssuer::new();
        let flow = flow(&store, &issuer);
        let base = base_time();

        let registered = flow
            .register_site("https://center.example", "Site One", base)
            .await?;
        assert_eq!(registered.expires_at(), base + BINDING_CODE_TTL);
        assert_eq!(registered.code().as_str().len(), 20);
        // The code is exactly the D2 unambiguous alphabet.
        assert!(
            registered
                .code()
                .as_str()
                .bytes()
                .all(|byte| rutilus_domain::CODE_ALPHABET.contains(&byte))
        );

        let stored = store
            .find_binding_owned(registered.binding_id())?
            .ok_or("the stored binding is missing")?;
        assert_eq!(stored.state(), CenterBindingState::Pending);
        assert_eq!(
            stored.binding_code_hash(),
            Some(registered.code().hash()),
            "only the SHA-256 hash of the code is stored"
        );
        assert_eq!(stored.site_instance_id(), registered.instance_id());
        assert_eq!(stored.expires_at(), Some(base + BINDING_CODE_TTL));
        assert_eq!(stored.center_url(), "https://center.example");

        let instance = store
            .find_instance_owned(registered.instance_id())?
            .ok_or("the stored instance is missing")?;
        assert_eq!(instance.kind(), InstanceKind::Site);
        assert_eq!(instance.display_name(), "Site One");
        assert_eq!(instance.created_at(), base);
        Ok(())
    }

    #[tokio::test]
    async fn bind_consumes_the_code_records_the_fingerprint_and_issues_the_certificate()
    -> Result<(), Box<dyn Error>> {
        let store = MockBindingStore::new();
        let issuer = MockIssuer::new();
        let flow = flow(&store, &issuer);
        let base = base_time();
        let registered = flow
            .register_site("https://center.example", "Site One", base)
            .await?;
        let site_fingerprint = CertificateFingerprint::from_bytes([0x77; 32]);

        let outcome = flow
            .bind_site(
                registered.code().as_str(),
                site_fingerprint,
                base + Duration::MINUTE,
            )
            .await?;
        assert_eq!(outcome.site_instance_id(), registered.instance_id());
        assert_eq!(outcome.binding_id(), registered.binding_id());
        assert_eq!(outcome.issued_certificate().fingerprint(), site_fingerprint);
        assert_eq!(
            outcome.issued_certificate().certificate_pem(),
            "certificate-pem"
        );
        assert_eq!(outcome.issued_certificate().key_pem(), "key-pem");
        assert_eq!(
            outcome.trust_anchor(),
            &CenterTrustAnchor::new(
                CertificateFingerprint::from_bytes([0xAA; 32]),
                CertificateFingerprint::from_bytes([0xBB; 32]),
            )
        );
        // The certificate was issued for the bound site with its fingerprint.
        assert_eq!(
            issuer.issued_owned()?,
            vec![(registered.instance_id(), site_fingerprint)]
        );

        let stored = store
            .find_binding_owned(registered.binding_id())?
            .ok_or("the stored binding is missing")?;
        assert_eq!(stored.state(), CenterBindingState::Bound);
        assert_eq!(
            stored.binding_code_hash(),
            None,
            "the one-time code must be consumed by the bind"
        );
        assert_eq!(stored.expires_at(), None);
        assert_eq!(stored.bound_at(), Some(base + Duration::MINUTE));
        assert_eq!(stored.site_cert_fingerprint(), Some(site_fingerprint));
        Ok(())
    }

    #[tokio::test]
    async fn bind_refuses_malformed_wrong_and_consumed_codes() -> Result<(), Box<dyn Error>> {
        let store = MockBindingStore::new();
        let issuer = MockIssuer::new();
        let flow = flow(&store, &issuer);
        let base = base_time();
        let registered = flow
            .register_site("https://center.example", "Site One", base)
            .await?;
        let site_fingerprint = CertificateFingerprint::from_bytes([0x77; 32]);
        let presented = base + Duration::MINUTE;

        // A code outside the canonical shape is refused before any lookup.
        assert!(matches!(
            flow.bind_site("short", site_fingerprint, presented).await,
            Err(CenterBindingFlowError::MalformedCode)
        ));
        // A well-formed but wrong code matches no outstanding registration.
        let wrong = "23456789ABCDEFGHJKLN";
        assert!(matches!(
            flow.bind_site(wrong, site_fingerprint, presented).await,
            Err(CenterBindingFlowError::CodeMismatch)
        ));
        // The issued code binds exactly once; a second use finds no
        // outstanding registration.
        flow.bind_site(registered.code().as_str(), site_fingerprint, presented)
            .await?;
        assert!(matches!(
            flow.bind_site(
                registered.code().as_str(),
                site_fingerprint,
                presented + Duration::SECOND
            )
            .await,
            Err(CenterBindingFlowError::CodeMismatch)
        ));
        Ok(())
    }

    #[tokio::test]
    async fn bind_refuses_an_expired_outstanding_code() -> Result<(), Box<dyn Error>> {
        let store = MockBindingStore::new();
        let issuer = MockIssuer::new();
        let flow = flow(&store, &issuer);
        let base = base_time();
        let registered = flow
            .register_site("https://center.example", "Site One", base)
            .await?;

        // Past the D2 TTL the outstanding code no longer binds.
        let after_ttl = base + BINDING_CODE_TTL + Duration::SECOND;
        assert!(matches!(
            flow.bind_site(
                registered.code().as_str(),
                CertificateFingerprint::from_bytes([0x77; 32]),
                after_ttl
            )
            .await,
            Err(CenterBindingFlowError::CodeExpired)
        ));
        // The binding stays pending: expiry is a judgment, not a write.
        let stored = store
            .find_binding_owned(registered.binding_id())?
            .ok_or("the stored binding is missing")?;
        assert_eq!(stored.state(), CenterBindingState::Pending);
        Ok(())
    }

    #[tokio::test]
    async fn bind_refuses_a_site_identity_already_bound_until_the_old_binding_is_revoked()
    -> Result<(), Box<dyn Error>> {
        // V5E-2: the site identity fingerprint is the durable fact of the
        // D2 flow, so a re-bind under the same fingerprint while the old
        // binding is still in force is refused — accepting it would leave
        // two live sites claiming one identity, and the V4R-7 re-bind
        // self-healing (which treats a revoked binding as the operator's
        // unbind) would keep the old site's endpoints frozen forever.
        let store = MockBindingStore::new();
        let issuer = MockIssuer::new();
        let flow = flow(&store, &issuer);
        let base = base_time();
        let site_fingerprint = CertificateFingerprint::from_bytes([0x77; 32]);

        // The first site binds under the fingerprint.
        let first = flow
            .register_site("https://center.example", "Site One", base)
            .await?;
        flow.bind_site(
            first.code().as_str(),
            site_fingerprint,
            base + Duration::MINUTE,
        )
        .await?;

        // A second registration under the same fingerprint is refused with
        // the honest verdict naming the live site — before any certificate
        // is issued for it.
        let second = flow
            .register_site(
                "https://center.example",
                "Site Two",
                base + Duration::SECOND,
            )
            .await?;
        assert!(matches!(
            flow.bind_site(
                second.code().as_str(),
                site_fingerprint,
                base + Duration::seconds(2)
            )
            .await,
            Err(CenterBindingFlowError::BindingStillInForce { site })
                if site == first.instance_id()
        ));
        // The refused bind consumed nothing: the second registration's
        // binding is still pending and no certificate was issued for it.
        let stored = store
            .find_binding_owned(second.binding_id())?
            .ok_or("the second binding is missing")?;
        assert_eq!(stored.state(), CenterBindingState::Pending);
        assert_eq!(issuer.issued_owned()?.len(), 1);

        // After the old binding is revoked — the operator's unbind that
        // precedes every re-bind — the same code binds the fingerprint.
        store.revoke_binding(first.binding_id())?;
        let outcome = flow
            .bind_site(
                second.code().as_str(),
                site_fingerprint,
                base + Duration::seconds(3),
            )
            .await?;
        assert_eq!(outcome.site_instance_id(), second.instance_id());
        // A fresh identity on a different fingerprint is never affected.
        let third = flow
            .register_site(
                "https://center.example",
                "Site Three",
                base + Duration::seconds(4),
            )
            .await?;
        flow.bind_site(
            third.code().as_str(),
            CertificateFingerprint::from_bytes([0x88; 32]),
            base + Duration::seconds(5),
        )
        .await?;
        Ok(())
    }

    #[tokio::test]
    async fn bind_retires_the_revoked_site_pending_offers() -> Result<(), Box<dyn Error>> {
        // V5E-5: when a re-bind follows the revocation (the fingerprint's
        // previous binding is revoked), the dead site's pending §15.6
        // offers are retired like the flush's TTL retirement — the revoked
        // site can never connect again, so its outbox rows must not linger
        // pending forever. The new site's queue is never touched.
        let store = MockBindingStore::new();
        let issuer = MockIssuer::new();
        let flow = flow(&store, &issuer);
        let base = base_time();
        let site_fingerprint = CertificateFingerprint::from_bytes([0x77; 32]);

        let first = flow
            .register_site("https://center.example", "Site One", base)
            .await?;
        flow.bind_site(
            first.code().as_str(),
            site_fingerprint,
            base + Duration::MINUTE,
        )
        .await?;
        // The live site's pending offers are left alone.
        store.seed_pending_offer(first.instance_id(), base + Duration::SECOND)?;
        store.seed_pending_offer(first.instance_id(), base + Duration::SECOND)?;
        assert_eq!(
            store.pending_offer_ids(first.instance_id())?.len(),
            2,
            "a live site's pending offers stay pending"
        );

        // The operator revokes the site and it re-binds under a fresh
        // instance identity with the same fingerprint.
        store.revoke_binding(first.binding_id())?;
        let second = flow
            .register_site(
                "https://center.example",
                "Site Two",
                base + Duration::seconds(2),
            )
            .await?;
        flow.bind_site(
            second.code().as_str(),
            site_fingerprint,
            base + Duration::seconds(3),
        )
        .await?;

        // The dead site's queue was retired; the new site's queue is empty.
        assert!(
            store.pending_offer_ids(first.instance_id())?.is_empty(),
            "the revoked site's pending offers must be retired by the re-bind"
        );
        assert!(
            store.pending_offer_ids(second.instance_id())?.is_empty(),
            "the new site's queue is never touched by the retirement"
        );
        Ok(())
    }

    #[test]
    fn a_bound_identity_matches_its_binding_record_and_mismatches_are_refused()
    -> Result<(), Box<dyn Error>> {
        let base = base_time();
        let site = SiteInstance::new(
            InstanceId::generate(),
            String::from("Site One"),
            InstanceKind::Site,
            base,
        );
        let site_fingerprint = CertificateFingerprint::from_bytes([0x42; 32]);
        let mut binding = CenterBinding::new_pending(
            CenterBindingId::generate(),
            String::from("https://center.example"),
            site.id(),
            &"23456789ABCDEFGHJKLM".parse::<BindingCode>()?,
            base + BINDING_CODE_TTL,
            base,
        );
        binding.bind(Some(site_fingerprint), base + Duration::MINUTE)?;

        // The exact identity the center issued: same extension fingerprint,
        // subject naming the bound instance.
        let matching = SiteIdentity::from_parts(
            CertificateFingerprint::from_bytes([0x99; 32]),
            Some(site.id().to_string()),
            Some(site_fingerprint),
        );
        assert_eq!(validate_bound_identity(&binding, &matching), Ok(()));

        // A certificate whose extension disagrees with the record is
        // refused even though its signature would verify (S3b item 1).
        let stale = SiteIdentity::from_parts(
            CertificateFingerprint::from_bytes([0x99; 32]),
            Some(site.id().to_string()),
            Some(CertificateFingerprint::from_bytes([0x43; 32])),
        );
        assert_eq!(
            validate_bound_identity(&binding, &stale),
            Err(IdentityValidationError::ExtensionMismatch)
        );
        // A certificate without the extension cannot be mapped to the site.
        let no_extension = SiteIdentity::from_parts(
            CertificateFingerprint::from_bytes([0x99; 32]),
            Some(site.id().to_string()),
            None,
        );
        assert_eq!(
            validate_bound_identity(&binding, &no_extension),
            Err(IdentityValidationError::ExtensionMissing)
        );
        // A certificate whose subject names another instance is refused.
        let wrong_subject = SiteIdentity::from_parts(
            CertificateFingerprint::from_bytes([0x99; 32]),
            Some(InstanceId::generate().to_string()),
            Some(site_fingerprint),
        );
        assert_eq!(
            validate_bound_identity(&binding, &wrong_subject),
            Err(IdentityValidationError::SubjectMismatch)
        );
        // A revoked binding refuses every certificate: the extension may be
        // flawless, but the binding is no longer in force.
        let mut revoked = binding;
        revoked.revoke()?;
        assert_eq!(
            validate_bound_identity(&revoked, &matching),
            Err(IdentityValidationError::NotBound)
        );
        Ok(())
    }
}
