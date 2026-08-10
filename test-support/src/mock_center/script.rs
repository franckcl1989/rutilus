//! The scriptable behavior of the Mock Center: how the negotiation answers
//! a `Hello`, how content frames are answered, and what the mock recorded.
//!
//! The default script mirrors a healthy real center: every `Hello` is
//! admitted, and every content frame is acknowledged (the §15.4 reliable
//! transport needs the `Ack` for the site's outbox flush to progress).
//! Tests program the script to refuse a site with the `not-bound` reason,
//! or to inject specific replies (a §15.6 operation offer, a heartbeat)
//! into the connection.

use std::{
    collections::VecDeque,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU8, Ordering},
    },
};

use rutilus_center_protocol::{Envelope, EnvelopeMessage};

/// How the mock center's negotiation answers one `Hello`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ScriptedAdmission {
    /// Answer `NegotiationResult { accepted: true }`.
    #[default]
    Admit,
    /// Answer `NegotiationResult { accepted: false, reason: "not-bound" }`
    /// — the audit follow-up F4 convergence path.
    RefuseNotBound,
}

/// One scripted reply to a received content frame.
///
/// The reply queue is consumed in order; an empty queue falls back to the
/// default [`EnvelopeMessage::Ack`] of the received frame's sequence, so
/// the §15.4 flush always progresses unless a test deliberately scripts
/// otherwise.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ScriptedReply {
    /// Acknowledge the received frame's sequence explicitly (the default
    /// behavior; kept as a variant so a test can force a duplicate or a
    /// different sequence).
    Ack { sequence: u64 },
    /// Deliver one §15.6 operation offer to the site.
    OperationOffer(rutilus_center_protocol::OperationOffer),
    /// Deliver one liveness heartbeat to the site.
    Heartbeat,
}

/// The scriptable behavior and the recording of one mock center instance.
#[derive(Debug)]
pub struct MockCenterScript {
    admission: AtomicU8,
    replies: Mutex<VecDeque<ScriptedReply>>,
    received: Mutex<Vec<Envelope>>,
}

impl Default for MockCenterScript {
    fn default() -> Self {
        Self::new()
    }
}

impl MockCenterScript {
    /// Builds an empty script: admit every `Hello`, acknowledge every
    /// content frame, and record everything.
    #[must_use]
    pub fn new() -> Self {
        Self {
            admission: AtomicU8::new(ScriptedAdmission::Admit as u8),
            replies: Mutex::new(VecDeque::new()),
            received: Mutex::new(Vec::new()),
        }
    }

    /// Sets how the negotiation answers the next `Hello`.
    pub fn set_admission(&self, admission: ScriptedAdmission) {
        self.admission.store(admission as u8, Ordering::Relaxed);
    }

    /// The configured admission of one `Hello`.
    #[must_use]
    pub fn admission(&self) -> ScriptedAdmission {
        match self.admission.load(Ordering::Relaxed) {
            value if value == ScriptedAdmission::RefuseNotBound as u8 => {
                ScriptedAdmission::RefuseNotBound
            }
            _ => ScriptedAdmission::Admit,
        }
    }

    /// Queues one scripted reply; replies are consumed in queue order, and
    /// an empty queue falls back to acknowledging the received frame.
    pub fn reply_with(&self, reply: ScriptedReply) {
        if let Ok(mut replies) = self.replies.lock() {
            replies.push_back(reply);
        }
    }

    /// The next scripted reply, if any.
    fn next_reply(&self) -> Option<ScriptedReply> {
        self.replies
            .lock()
            .ok()
            .and_then(|mut replies| replies.pop_front())
    }

    /// Records one received frame.
    pub(crate) fn record(&self, envelope: &Envelope) {
        if let Ok(mut received) = self.received.lock() {
            received.push(envelope.clone());
        }
    }

    /// Every received frame, in arrival order.
    #[must_use]
    pub fn received(&self) -> Vec<Envelope> {
        self.received
            .lock()
            .map(|received| received.clone())
            .unwrap_or_default()
    }

    /// Every received message, in arrival order.
    #[must_use]
    pub fn received_messages(&self) -> Vec<EnvelopeMessage> {
        self.received()
            .into_iter()
            .filter_map(|envelope| envelope.message)
            .collect()
    }

    /// The reply the connection sends for one received content frame: the
    /// next scripted reply, or the default acknowledgement.
    #[must_use]
    pub(crate) fn reply_for(&self, envelope: &Envelope) -> EnvelopeMessage {
        match self.next_reply() {
            Some(ScriptedReply::Ack { sequence }) => {
                EnvelopeMessage::Ack(rutilus_center_protocol::Ack { sequence })
            }
            Some(ScriptedReply::OperationOffer(offer)) => EnvelopeMessage::OperationOffer(offer),
            Some(ScriptedReply::Heartbeat) => {
                EnvelopeMessage::Heartbeat(rutilus_center_protocol::Heartbeat { sent_at_unix: 0 })
            }
            None => EnvelopeMessage::Ack(rutilus_center_protocol::Ack {
                sequence: envelope.sequence,
            }),
        }
    }
}

/// One shared script handle: the accept loop owns one clone, the test the
/// other.
pub(crate) type SharedScript = Arc<MockCenterScript>;
