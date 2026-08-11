//! Version negotiation between a site and the center (§15.3).
//!
//! [`negotiate`] is a pure function over a received [`Hello`]: the
//! `center_protocol_version` must equal [`CENTER_PROTOCOL_VERSION`], the
//! `nv_redfish_baseline` must equal [`NV_REDFISH_BASELINE`], and the
//! `capability_ledger_hash` must equal [`capability_ledger_hash`]. The
//! `product_version` is recorded but never judged. Checks run in that
//! fixed order, so a peer failing several checks reports the first one.
//!
//! The rejection reasons are the stable reason codes of the
//! [`NegotiationResult`] message: `protocol-mismatch`, `baseline-mismatch`,
//! `ledger-mismatch`, and `not-bound` (the 0.7.0 admission refusal — the
//! center answers the `Hello` of a site whose binding is no longer in
//! force with this reason instead of closing the connection silently).

use std::{error::Error, fmt, str::FromStr};

use rutilus_domain::CAPABILITY_LEDGER_ORDER;
use sha2::{Digest, Sha256};

use crate::{CENTER_PROTOCOL_VERSION, Hello, NV_REDFISH_BASELINE};

/// The outcome of a version negotiation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NegotiationDecision {
    /// The site may join the center.
    Compatible,
    /// The site may not join; `reason` names the first failed check.
    Rejected { reason: NegotiationReason },
}

/// The first negotiation check that failed, named by its stable reason
/// code from the [`NegotiationResult`] message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NegotiationReason {
    /// `center_protocol_version` differs from [`CENTER_PROTOCOL_VERSION`].
    ProtocolMismatch,
    /// `nv_redfish_baseline` differs from [`NV_REDFISH_BASELINE`].
    BaselineMismatch,
    /// `capability_ledger_hash` differs from [`capability_ledger_hash`].
    LedgerMismatch,
    /// The site's binding is not in force on the center: it was revoked,
    /// re-bound, or never recorded (0.7.0 admission refusal, audit
    /// follow-up F4). The protocol message contract allows new reason
    /// codes, so this is a vocabulary addition, never a wire change.
    NotBound,
}

impl NegotiationReason {
    /// Returns the stable reason code used by the [`NegotiationResult`]
    /// message on the wire.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProtocolMismatch => "protocol-mismatch",
            Self::BaselineMismatch => "baseline-mismatch",
            Self::LedgerMismatch => "ledger-mismatch",
            Self::NotBound => "not-bound",
        }
    }
}

impl fmt::Display for NegotiationReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for NegotiationReason {
    type Err = NegotiationReasonParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "protocol-mismatch" => Ok(Self::ProtocolMismatch),
            "baseline-mismatch" => Ok(Self::BaselineMismatch),
            "ledger-mismatch" => Ok(Self::LedgerMismatch),
            "not-bound" => Ok(Self::NotBound),
            _ => Err(NegotiationReasonParseError),
        }
    }
}

/// A negotiation reason code on the wire is unknown to this product build.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NegotiationReasonParseError;

impl fmt::Display for NegotiationReasonParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("unknown negotiation reason code")
    }
}

impl Error for NegotiationReasonParseError {}

/// Computes the capability-ledger hash this build negotiates with (§15.3):
/// the SHA-256 digest of the `as_str()` product codes of
/// [`rutilus_domain::CAPABILITY_LEDGER_ORDER`] concatenated in ledger order
/// with no separator.
///
/// Both sides of a connection compute this identically, so any drift in
/// the compiled capability ledger — a reorder, a renamed code, a new or
/// removed capability — changes the hash and the connection is rejected
/// with `ledger-mismatch` instead of silently projecting different
/// capability surfaces. The digest is pinned by a golden-value test.
#[must_use]
pub fn capability_ledger_hash() -> [u8; 32] {
    let mut hasher = Sha256::new();
    for capability in CAPABILITY_LEDGER_ORDER {
        hasher.update(capability.as_str());
    }
    hasher.finalize().into()
}

/// Negotiates a site connection against this build (§15.3).
///
/// Checks run in fixed order and the first failure wins:
/// `center_protocol_version`, then `nv_redfish_baseline`, then
/// `capability_ledger_hash`. `product_version` is recorded by the caller
/// but never participates in the decision.
#[must_use]
pub fn negotiate(hello: &Hello) -> NegotiationDecision {
    if hello.center_protocol_version != CENTER_PROTOCOL_VERSION {
        return NegotiationDecision::Rejected {
            reason: NegotiationReason::ProtocolMismatch,
        };
    }
    if hello.nv_redfish_baseline != NV_REDFISH_BASELINE {
        return NegotiationDecision::Rejected {
            reason: NegotiationReason::BaselineMismatch,
        };
    }
    if hello.capability_ledger_hash != capability_ledger_hash() {
        return NegotiationDecision::Rejected {
            reason: NegotiationReason::LedgerMismatch,
        };
    }
    NegotiationDecision::Compatible
}

#[cfg(test)]
mod tests {
    use super::{
        NegotiationDecision, NegotiationReason, NegotiationReasonParseError,
        capability_ledger_hash, negotiate,
    };
    use crate::{CENTER_PROTOCOL_VERSION, Hello, tests::sample_hello};
    use rutilus_domain::CAPABILITY_LEDGER_ORDER;
    use sha2::{Digest, Sha256};

    /// The digest of the concatenated `CAPABILITY_LEDGER_ORDER` codes at
    /// the time this test was written. Pinning it freezes the wire
    /// contract: any change to the ledger (reorder, rename, add, remove)
    /// changes the hash, so this test fails until the new digest is
    /// reviewed and pinned deliberately.
    ///
    /// This value changed on purpose with the 0.8.0 ledger growth: the three
    /// nv-redfish 0.13.0 additions (`ports`, `bmc-http`,
    /// `update-service-deprecated`) joined the 30 §2.1 standard entries,
    /// so the digest moved from the 44-capability value to the 47-capability
    /// value below. The protocol semantics are unchanged; only the pinned
    /// ledger contents moved.
    const GOLDEN_LEDGER_HASH: [u8; 32] = [
        0x84, 0xCA, 0xF5, 0x58, 0xF9, 0xAE, 0x77, 0xEA, 0x9C, 0xD4, 0xC3, 0xE7, 0xA2, 0x27, 0x1D,
        0xE6, 0x3A, 0x65, 0x25, 0x38, 0x81, 0xFD, 0x70, 0xBB, 0x0A, 0xAE, 0x18, 0x5E, 0x23, 0x56,
        0xD2, 0x4F,
    ];

    #[test]
    fn matching_hello_is_accepted() {
        assert_eq!(negotiate(&sample_hello()), NegotiationDecision::Compatible);
    }

    #[test]
    fn protocol_version_mismatch_is_rejected() {
        let hello = Hello {
            center_protocol_version: CENTER_PROTOCOL_VERSION + 1,
            ..sample_hello()
        };
        assert_eq!(
            negotiate(&hello),
            NegotiationDecision::Rejected {
                reason: NegotiationReason::ProtocolMismatch
            }
        );
    }

    #[test]
    fn baseline_mismatch_is_rejected() {
        let hello = Hello {
            nv_redfish_baseline: String::from("0.12.0"),
            ..sample_hello()
        };
        assert_eq!(
            negotiate(&hello),
            NegotiationDecision::Rejected {
                reason: NegotiationReason::BaselineMismatch
            }
        );
    }

    #[test]
    fn ledger_mismatch_is_rejected() {
        let mut hash = capability_ledger_hash();
        hash[0] ^= 0x01;
        let hello = Hello {
            capability_ledger_hash: hash.to_vec(),
            ..sample_hello()
        };
        assert_eq!(
            negotiate(&hello),
            NegotiationDecision::Rejected {
                reason: NegotiationReason::LedgerMismatch
            }
        );
    }

    #[test]
    fn protocol_mismatch_is_reported_first() {
        // All three checks fail; the fixed order must report the protocol
        // mismatch.
        let hello = Hello {
            center_protocol_version: CENTER_PROTOCOL_VERSION + 1,
            nv_redfish_baseline: String::from("0.12.0"),
            capability_ledger_hash: Vec::new(),
            ..sample_hello()
        };
        assert_eq!(
            negotiate(&hello),
            NegotiationDecision::Rejected {
                reason: NegotiationReason::ProtocolMismatch
            }
        );
    }

    #[test]
    fn baseline_mismatch_is_reported_before_ledger_mismatch() {
        let hello = Hello {
            nv_redfish_baseline: String::from("0.12.0"),
            capability_ledger_hash: Vec::new(),
            ..sample_hello()
        };
        assert_eq!(
            negotiate(&hello),
            NegotiationDecision::Rejected {
                reason: NegotiationReason::BaselineMismatch
            }
        );
    }

    #[test]
    fn product_version_never_influences_the_decision() {
        let hello = Hello {
            product_version: String::from("0.0.1"),
            ..sample_hello()
        };
        assert_eq!(negotiate(&hello), NegotiationDecision::Compatible);
    }

    #[test]
    fn ledger_hash_matches_a_direct_construction_from_the_domain_ledger() {
        let mut hasher = Sha256::new();
        for capability in CAPABILITY_LEDGER_ORDER {
            hasher.update(capability.as_str());
        }
        let direct: [u8; 32] = hasher.finalize().into();
        assert_eq!(capability_ledger_hash(), direct);
    }

    #[test]
    fn ledger_hash_is_stable_and_pinned() {
        assert_eq!(capability_ledger_hash(), GOLDEN_LEDGER_HASH);
    }

    #[test]
    fn reason_codes_round_trip_and_reject_unknown_codes() {
        for reason in [
            NegotiationReason::ProtocolMismatch,
            NegotiationReason::BaselineMismatch,
            NegotiationReason::LedgerMismatch,
            NegotiationReason::NotBound,
        ] {
            assert_eq!(reason.to_string().parse(), Ok(reason));
        }
        assert_eq!(
            "unknown".parse::<NegotiationReason>(),
            Err(NegotiationReasonParseError)
        );
    }
}
