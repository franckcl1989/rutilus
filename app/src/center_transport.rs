//! The app-side implementation of the application transport boundary
//! (0.7.0 S4): [`CenterClientConfig`] is the [`CenterTransport`] and the
//! established [`CenterLink`] is presented as a [`CenterSession`].
//!
//! The application engine owns the §15.4 durable outbox, so the session
//! delivers the envelope exactly as the engine built it — the connection
//! assigns no sequence of its own (the engine's envelope carries the durable
//! sequence) — and the engine's `receive` is one raw frame at a time, with
//! WebSocket control frames absorbed and a clean close reported as `None`.

use rutilus_application::{BoundaryFuture, CenterSession, CenterTransport};
use rutilus_center_protocol::Envelope;

use crate::{CenterClientConfig, CenterClientError, CenterLink};

impl CenterTransport for CenterClientConfig {
    type Session = CenterLinkSession;
    type Error = CenterClientError;

    fn connect(&self) -> BoundaryFuture<'_, Result<Self::Session, Self::Error>> {
        Box::pin(async move { self.connect().await.map(CenterLinkSession) })
    }

    fn is_not_bound(&self, error: &Self::Error) -> bool {
        // The client classifies the `not-bound` admission refusal at
        // negotiation time (audit follow-up F4); every other failure stays
        // transient.
        matches!(error, CenterClientError::NotBound)
    }
}

/// One established site-to-center connection presented as the application's
/// [`CenterSession`] boundary.
pub struct CenterLinkSession(pub(crate) CenterLink);

impl CenterSession for CenterLinkSession {
    type Error = CenterClientError;

    fn send(&mut self, envelope: Envelope) -> BoundaryFuture<'_, Result<(), Self::Error>> {
        Box::pin(async move { self.0.send_envelope(envelope).await })
    }

    fn receive(&mut self) -> BoundaryFuture<'_, Result<Option<Envelope>, Self::Error>> {
        Box::pin(async move { self.0.receive_envelope().await })
    }
}
