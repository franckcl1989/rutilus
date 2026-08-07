//! The WebSocket transport glue shared by the center connection layers
//! (design §15): the endpoint path, the one-message-one-frame rule, and
//! the frame handler trait.
//!
//! The wire protocol (§15.2, `center-protocol`) frames every envelope with
//! a 4-byte length prefix, and the WebSocket transport carries exactly one
//! frame per binary message (§15 transport semantics). This module is the
//! only place that rule is stated: both the center acceptor and the site
//! client classify inbound WebSocket messages through
//! [`inbound_frame`], so a text message or a raw frame is a protocol
//! violation on both sides, and a ping or pong is transport hygiene that
//! the caller flushes.

use std::future::Future;

use rutilus_center_protocol::{Envelope, FrameError, decode_frame};
use tokio_tungstenite::tungstenite::Message;

/// One inbound WebSocket message classified under the one-message-one-frame
/// rule.
pub(crate) enum InboundFrame {
    /// A binary message carrying exactly one decoded frame.
    Envelope(Envelope),
    /// A ping or pong control message: the transport queues the pong
    /// itself, and the caller flushes it to the wire.
    Control,
    /// A close message, or the stream ended.
    Closed,
    /// A text or raw message: a violation of the frame rule.
    ProtocolViolation,
}

/// Classifies one inbound WebSocket message.
///
/// # Errors
///
/// Returns [`FrameError`] when a binary message does not decode as exactly
/// one frame.
pub(crate) fn inbound_frame(message: Message) -> Result<InboundFrame, FrameError> {
    match message {
        Message::Binary(payload) => decode_frame(&payload).map(InboundFrame::Envelope),
        Message::Ping(_) | Message::Pong(_) => Ok(InboundFrame::Control),
        Message::Close(_) => Ok(InboundFrame::Closed),
        Message::Text(_) | Message::Frame(_) => Ok(InboundFrame::ProtocolViolation),
    }
}

/// Handles the frames of one established site-to-center connection.
///
/// The handler runs on the connection's task and receives the live
/// connection, so it may answer a received frame (for example the §15.4
/// `Ack` the reliable-outbox slice wires) in the order the frame was
/// received.
pub trait CenterFrameHandler<C> {
    /// Handles one received [`Envelope`].
    fn on_frame<'a>(
        &'a mut self,
        connection: &'a mut C,
        envelope: Envelope,
    ) -> impl Future<Output = ()> + Send + 'a;
}
