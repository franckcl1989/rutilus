//! Deterministic test support for the Rutilus product (design section 8
//! `test-support`: Mock, Fixture, and fault injection): a runnable HTTPS Mock Redfish
//! BMC on loopback, serving a fixed resource tree that the product's
//! trust-first onboarding, 47-capability probe, and typed core resource read
//! can exercise without a real BMC.
//!
//! # Why this crate exists
//!
//! The product only talks to BMCs over HTTPS with an explicit TLS decision,
//! so a fixture that cannot run as a real TLS server cannot demo the
//! onboarding flow. The [`MockBmc`] here is a genuine loopback HTTPS server:
//! the product observes its self-signed leaf, pins its SHA-256 fingerprint,
//! logs in through `SessionService`, probes the 47 §2.1 capabilities, reads
//! the ServiceRoot/Systems/Chassis/Managers/Processors/Memory tree, and
//! cleans up its Session -- exactly the flow a user sees with a real BMC.
//!
//! Every [`MockBmc::start`] run serves the same deterministic certificate
//! (fixed key, subject, serial, and validity embedded in
//! [`mock_bmc::tls`]), so the fingerprint printed by the `mock-bmc` binary
//! and asserted by tests is reproducible across runs. Fixture documents are
//! static JSON mirrors of the shapes the `rutilus-infra-redfish` gateway
//! already decodes in its own tests, so the mock cannot drift from what the
//! product actually parses.
//!
//! The mock records every received request ([`MockBmc::requests`]) so
//! integration tests can assert the exact wire sequence the gateway produces
//! (Session POST before the authenticated reads, Session DELETE at the end),
//! and it tracks its Session ledger ([`MockBmc::active_sessions`]) so a test
//! can prove the product's transient Sessions are cleaned up.
//!
//! The fixture tree is selected by vendor profile ([`MockProfile`]):
//! [`MockBmc::start`] serves the default `Rutilus` tree (Vendor "Rutilus
//! Test", no `Oem` namespace anywhere), while [`MockBmc::start_with_profile`]
//! swaps in a vendor tree -- the `Dell` profile serves the §11.5
//! `DellAttributes` surface behind the manager's `Oem.Dell` segment, and the
//! `XFusion` and `Inspur` profiles realize the 0.5.0 standard pattern: a
//! vendor that serves no OEM surface is a profile variant that only changes
//! the identity strings, so every §2.1 OEM capability stays `NotAdvertised`
//! and no other vendor's surface can mis-display. Vendor-standard integration
//! tests can therefore drive a realistic vendor identity instead of the
//! generic fixture.
//!
//! # Demo flow
//!
//! ```text
//! cargo run -p rutilus-test-support --bin mock-bmc
//! ```
//!
//! prints the listening URL and the SHA-256 fingerprint; `test-support/
//! README.md` walks through the full product demo (init, run, add endpoint,
//! Pin the printed fingerprint, enroll, browse resources and capabilities).
//! `mock-bmc --port 8443 --profile dell` pins the port and selects the Dell
//! profile, and the positional shorthand `mock-bmc 8443 dell` is
//! equivalent: the long options win when both spellings are given.
//!
//! # Test usage
//!
//! Integration tests bind their own Mock BMC on an ephemeral port and drive
//! the real `RedfishGateway`:
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use rutilus_domain::{CredentialUsername, EndpointAddress, TlsTrust};
//! use rutilus_infra_redfish::RedfishGateway;
//! use rutilus_test_support::MockBmc;
//! use secrecy::SecretString;
//! use time::OffsetDateTime;
//!
//! let mock = MockBmc::start().await?;
//! let gateway = RedfishGateway::from_system_roots().await?;
//! let address = mock.endpoint_address();
//! let observation = gateway.observe_tls(&address).await?;
//! let trust = TlsTrust::PinnedCertificate {
//!     certificate: observation.certificate().clone(),
//!     trusted_at: OffsetDateTime::now_utc(),
//! };
//! let summary = gateway
//!     .read_service_root(
//!         &address,
//!         &trust,
//!         &CredentialUsername::parse("admin")?,
//!         &SecretString::from("password"),
//!     )
//!     .await?;
//! assert_eq!(summary.product(), Some("Mock BMC"));
//! # Ok(()) }
//! ```
//!
//! # Mock Center (0.7.0 S9)
//!
//! The scripted [`MockCenter`] serves the site-to-center protocol surface
//! (design §15): a loopback mTLS listener with its own CA, the
//! `Hello`/`NegotiationResult` negotiation, and the binary-frame WebSocket
//! transport. Its [`MockCenterScript`] decides how the negotiation answers
//! (admit, or refuse with the `not-bound` reason), queues scripted replies
//! (operation offers, heartbeats, explicit acks), and records every
//! received frame. The app crate's interop test
//! (`app/tests/mock_center_client.rs`) drives the real [`CenterClient`]
//! against the mock — the mock never depends on the app crate.
//!
//! # Why not `nv-redfish-bmc-mock`
//!
//! Design section 19.1 keeps the upstream `nv-redfish-bmc-mock` (an in-process
//! expectation-style mock implementing the `Bmc` trait) off this iteration's
//! server path: it is not a network endpoint, so the product's HTTPS
//! onboarding cannot reach it. This crate serves the network-shaped fixture
//! the product needs today; the upstream mock becomes relevant after the
//! `BmcFactory` abstraction lands.

#![forbid(unsafe_code)]

pub mod mock_bmc;
pub mod mock_center;

pub use mock_bmc::{
    MockBmc, MockBmcError, MockProfile, MockTlsIdentity, MockTlsIdentityError, RequestRecord,
};
pub use mock_center::{
    MockCenter, MockCenterError, MockCenterOptions, MockCenterTls, MockCenterTlsError,
    MockSiteIdentity, ScriptedAdmission, ScriptedReply,
};
