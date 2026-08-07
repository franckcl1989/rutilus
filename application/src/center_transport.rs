//! The transport boundary of the site-to-center connection (design §15.1,
//! §15.3; 0.7.0 S3b/S4).
//!
//! [`CenterTransport`] establishes one negotiated connection — TCP, TLS 1.3
//! with the site's client certificate, the §10.4 fingerprint pin, the
//! WebSocket upgrade, and the §15.3 `Hello`/`NegotiationResult` exchange —
//! and [`CenterSession`] carries one established connection: the engine
//! sends and receives raw [`Envelope`]s, and the transport assigns nothing.
//! The envelope's `sequence` and `acked_sequence` come from the engine,
//! which owns the durable §15.4 outbox; the transport only frames and
//! delivers the envelope exactly as given.
//!
//! The boundary is deliberately coarse: connection establishment and frame
//! exchange. Heartbeat timing, the reconnect backoff, the negotiation
//! failure handling (§15.3 — a rejected site keeps running locally and
//! retries), and the resume from the last acknowledged sequence all belong
//! to [`crate::CenterSync`], which drives them against this boundary. The
//! app crate's `CenterClient` implements the trait for the runtime slice
//! (the trait lives here so the engine never depends on the app crate).
//!
//! # Heartbeat frames
//!
//! A [`Heartbeat`] travels as an envelope with `sequence: 0`: it is a
//! liveness frame, not an outbox message, so it never consumes an outbox
//! sequence and the center never acknowledges it. Content messages always
//! carry their durable outbox sequence, which the center acknowledges with
//! an [`Ack`].

use std::error::Error;

use rutilus_center_protocol::Envelope;

use crate::BoundaryFuture;

/// Establishes one negotiated site-to-center connection (§15.1, §15.3).
///
/// `connect` is one attempt with no retry: the engine owns the §15.4
/// reconnect backoff and treats every failure alike — a rejected
/// negotiation (no common protocol version, §15.3) and an unreachable
/// center both keep the site running locally and schedule the next attempt.
pub trait CenterTransport: Send + Sync {
    /// The session type of one established connection.
    type Session: CenterSession<Error = Self::Error> + Send;

    /// The boundary's controlled failure type; every failure is retryable.
    type Error: Error + Send + Sync + 'static;

    /// Establishes one connection and completes the §15.3 negotiation.
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] when the connection cannot be established —
    /// including a center that rejects the negotiation with its stable
    /// reason code.
    fn connect(&self) -> BoundaryFuture<'_, Result<Self::Session, Self::Error>>;
}

impl<Transport> CenterTransport for &Transport
where
    Transport: CenterTransport + ?Sized,
{
    type Session = Transport::Session;
    type Error = Transport::Error;

    fn connect(&self) -> BoundaryFuture<'_, Result<Self::Session, Self::Error>> {
        Transport::connect(*self)
    }
}

/// One established, negotiated site-to-center connection.
///
/// The session is owned by the engine for the lifetime of one connection:
/// [`Self::send`] writes one frame, [`Self::receive`] waits for the next
/// inbound frame, and the session ends when the peer closes the connection
/// ([`Self::receive`] returns `Ok(None)`) or the engine drops it.
pub trait CenterSession: Send {
    /// The boundary's controlled failure type, shared with the transport.
    type Error: Error + Send + Sync + 'static;

    /// Sends one envelope exactly as given.
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] when the transport cannot deliver the frame.
    fn send(&mut self, envelope: Envelope) -> BoundaryFuture<'_, Result<(), Self::Error>>;

    /// Waits for the next inbound frame.
    ///
    /// `Ok(None)` reports a clean close of the connection — the center
    /// disconnected or the transport ended — which the engine treats as the
    /// trigger of the §15.4 reconnect backoff.
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] for transport and protocol failures.
    fn receive(&mut self) -> BoundaryFuture<'_, Result<Option<Envelope>, Self::Error>>;
}

#[cfg(test)]
pub(crate) mod test_support {
    use std::error::Error;

    use rutilus_center_protocol::{Ack, Envelope, EnvelopeMessage};

    use super::*;

    /// A session error that cannot occur: every mock operation succeeds.
    #[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
    #[error("mock center failure")]
    pub(crate) struct MockCenterError;

    /// A channel-backed session, shared by the engine tests: the sent frames
    /// land in one channel and the inbound queue feeds
    /// [`CenterSession::receive`]. The test drives the two channel ends it
    /// keeps; the session never fails.
    pub(crate) struct ChannelSession {
        pub(crate) outbound: tokio::sync::mpsc::UnboundedSender<Envelope>,
        pub(crate) inbound: tokio::sync::mpsc::UnboundedReceiver<Envelope>,
    }

    impl ChannelSession {
        /// Splits a session into the session and the two channel ends the
        /// test drives: `(session, sent_frames, inbound_frames)`.
        pub(crate) fn channel() -> (
            Self,
            tokio::sync::mpsc::UnboundedReceiver<Envelope>,
            tokio::sync::mpsc::UnboundedSender<Envelope>,
        ) {
            let (outbound, outbound_rx) = tokio::sync::mpsc::unbounded_channel();
            let (inbound, inbound_rx) = tokio::sync::mpsc::unbounded_channel();
            (
                Self {
                    outbound,
                    inbound: inbound_rx,
                },
                outbound_rx,
                inbound,
            )
        }
    }

    impl CenterSession for ChannelSession {
        type Error = MockCenterError;

        fn send(&mut self, envelope: Envelope) -> BoundaryFuture<'_, Result<(), Self::Error>> {
            Box::pin(async move {
                let _ = self.outbound.send(envelope);
                Ok(())
            })
        }

        fn receive(&mut self) -> BoundaryFuture<'_, Result<Option<Envelope>, Self::Error>> {
            Box::pin(async move { Ok(self.inbound.recv().await) })
        }
    }

    /// A transport whose sessions are always fresh `ChannelSession`s.
    pub(crate) struct ChannelTransport;

    impl CenterTransport for ChannelTransport {
        type Session = ChannelSession;
        type Error = MockCenterError;

        fn connect(&self) -> BoundaryFuture<'_, Result<Self::Session, Self::Error>> {
            Box::pin(async move {
                let (session, _, _) = ChannelSession::channel();
                Ok(session)
            })
        }
    }

    #[tokio::test]
    async fn sessions_deliver_envelopes_exactly_as_given() -> Result<(), Box<dyn Error>> {
        let (mut session, mut sent_rx, inbound_tx) = ChannelSession::channel();
        let envelope = Envelope {
            sequence: 7,
            acked_sequence: 6,
            message: Some(EnvelopeMessage::Ack(Ack { sequence: 7 })),
        };
        assert_eq!(session.send(envelope.clone()).await, Ok(()));
        assert_eq!(sent_rx.recv().await, Some(envelope));

        // A dropped inbound feed reports a clean close.
        drop(inbound_tx);
        assert_eq!(session.receive().await, Ok(None));
        Ok(())
    }

    /// Connects through a `&Transport` reference, forcing the blanket
    /// reference impl to forward.
    fn connect_via_reference<T>(
        transport: &T,
    ) -> BoundaryFuture<'_, Result<T::Session, T::Error>>
    where
        T: CenterTransport,
    {
        transport.connect()
    }

    #[tokio::test]
    async fn the_transport_trait_forwards_through_references() -> Result<(), Box<dyn Error>> {
        // The engine composes `&Transport` (the runtime keeps the transport
        // behind a shared owner), so the blanket reference impl must forward.
        let session = connect_via_reference(&ChannelTransport).await?;
        let envelope = Envelope {
            sequence: 1,
            acked_sequence: 0,
            message: Some(EnvelopeMessage::Ack(Ack { sequence: 1 })),
        };
        let mut session = session;
        assert_eq!(session.send(envelope.clone()).await, Ok(()));
        // The session owns its outbound end; the test hands it a fresh
        // receiver by replacing the end, then observes the forwarded frame.
        let mut sent_rx = session.outbound_channel_for_test();
        assert_eq!(sent_rx.recv().await, Some(envelope));
        Ok(())
    }

    impl ChannelSession {
        /// Replaces the outbound end with a fresh channel and returns the
        /// receiver of the replaced one, so a test can observe frames sent
        /// after the session was handed to the engine.
        fn outbound_channel_for_test(&mut self) -> tokio::sync::mpsc::UnboundedReceiver<Envelope> {
            let (outbound, outbound_rx) = tokio::sync::mpsc::unbounded_channel();
            self.outbound = outbound;
            outbound_rx
        }
    }
}
