//! The center-side use cases (design §15, 0.7.0 S5).
//!
//! The center is the receiving side of the site-to-center shape: it binds
//! registered sites (§15.1, D2), admits their inbound connections, projects
//! their reports into the §15.5 center views, and dispatches the §15.6
//! operation offers. Every use case lives behind the application boundaries
//! of this module; the runtime composes one `SqliteStore` plus the app
//! crate's transport and certificate services behind them, exactly like the
//! site-side [`crate::CenterSync`].
//!
//! The modules:
//!
//! - [`binding`] — the one-time-code binding flow: registration, the D2
//!   pending state, the atomic code consumption, the §10.4 trust-anchor
//!   hand-off, and the S3b certificate-identity cross-validation.
//! - [`session`] — the inbound session admission, the per-site online
//!   registry, and the inbound connection engine (§15.4 acknowledgements
//!   and the durable outbox flush).

mod binding;
mod session;

pub use binding::{
    BindOutcome, CenterBindingFlow, CenterBindingFlowError, CenterBindingRepository,
    CenterTrustAnchor, IdentityValidationError, InstanceRepository, IssuedSiteCertificate,
    RegisteredSite, SiteCertificateIssuer, SiteIdentity, validate_bound_identity,
};
pub use session::{
    AdmissionRejection, AdmissionVerdict, CenterFrameConsumer, CenterInboundEngine,
    CenterInboundEngineError, CenterInboundOptions, CenterInboundSession, CenterPresence,
    CenterSessionAdmission, CenterSessionAdmissionError, CenterSessionRegistry,
    CenterSessionRegistryError, ResolvedSite,
};
