//! Frame encoding and decoding for the site-to-center wire (§15.2, §15.4).
//!
//! An [`Envelope`] travels between site and center inside a *frame*: a
//! 4-byte big-endian length prefix followed by the envelope's protobuf
//! bytes. The prefix declares the payload length in bytes, and every frame
//! carries exactly one envelope.
//!
//! ```text
//! +--------+--------+--------+--------+----------------------------+
//! |  payload length, big-endian u32  |  protobuf-encoded Envelope  |
//! +--------+--------+--------+--------+----------------------------+
//! ```
//!
//! [`encode_frame`] builds a frame from an envelope; [`decode_frame`] cuts
//! exactly one frame out of a byte sequence and rejects anything that is
//! not exactly one frame.
//!
//! # The `MAX_FRAME_BYTES` bound
//!
//! [`MAX_FRAME_BYTES`] bounds the payload on both sides of the wire:
//!
//! * **Encode** — [`encode_frame`] measures the envelope with
//!   `Message::encoded_len` before any allocation and returns
//!   [`FrameError::EncodeLimit`] for an envelope that would serialize to
//!   more than the limit.
//! * **Decode** — [`decode_frame`] rejects a header declaring more than
//!   the limit with [`FrameError::HeaderTooLarge`] before looking at (or
//!   allocating for) any payload, so a peer cannot force the receiver to
//!   buffer an unbounded frame.
//!
//! The bound is inclusive: a payload of exactly [`MAX_FRAME_BYTES`] is
//! legal on both sides.
//!
//! # WebSocket messages and byte streams
//!
//! On WebSocket, each binary message carries exactly one frame; the
//! transport already delimits messages. The length prefix makes the frame
//! self-delimiting anyway, so the identical codec runs over a raw byte
//! stream (or a debug capture) where no other message boundary exists.
//!
//! # Why a length prefix and not a fixed header with version bits
//!
//! Versioning already lives in the negotiation layer
//! (`Hello.center_protocol_version` versus [`CENTER_PROTOCOL_VERSION`],
//! checked once per connection by [`negotiate`]), so a per-frame version
//! field would duplicate a checked invariant and could drift from it. The
//! protobuf payload is self-describing (every field is tagged), which
//! leaves the frame header exactly one job — delimiting the envelope — and
//! a 4-byte length prefix is the minimal header that does it. The declared
//! length always fits the `u32` field: [`MAX_FRAME_BYTES`] is 8 MiB, three
//! bytes of headroom short of 4 GiB.

use std::{error::Error, fmt};

use prost::Message;

use crate::{Envelope, MAX_FRAME_BYTES};

/// The length prefix of every frame: 4 bytes, big-endian, declaring the
/// payload length in bytes.
pub const FRAME_HEADER_BYTES: usize = 4;

/// Why a frame could not be encoded or decoded. Every length is reported
/// in bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FrameError {
    /// Fewer than [`FRAME_HEADER_BYTES`] bytes: there is no length header
    /// to read.
    TooShort {
        frame_bytes: usize,
        header_bytes: usize,
    },
    /// The header declares a payload longer than [`MAX_FRAME_BYTES`];
    /// rejected before any payload is buffered or decoded.
    HeaderTooLarge {
        declared_bytes: usize,
        max_bytes: usize,
    },
    /// The frame ends before the declared payload: the transport delivered
    /// a partial frame.
    Truncated {
        declared_bytes: usize,
        present_bytes: usize,
    },
    /// Bytes follow the declared payload; a frame is exactly one envelope,
    /// so the extra bytes are not part of it.
    TrailingBytes {
        declared_bytes: usize,
        extra_bytes: usize,
    },
    /// The envelope would serialize to more than [`MAX_FRAME_BYTES`] bytes;
    /// no frame was built.
    EncodeLimit {
        payload_bytes: usize,
        max_bytes: usize,
    },
    /// The payload is not a valid [`Envelope`].
    Decode(prost::DecodeError),
    /// The envelope could not be written into the frame buffer. With the
    /// pre-sized buffer this cannot occur; the variant exists only so
    /// [`encode_frame`] stays total without an `unwrap`.
    Encode(prost::EncodeError),
}

impl fmt::Display for FrameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort {
                frame_bytes,
                header_bytes,
            } => write!(
                formatter,
                "frame of {frame_bytes} bytes is shorter than the {header_bytes}-byte length header"
            ),
            Self::HeaderTooLarge {
                declared_bytes,
                max_bytes,
            } => write!(
                formatter,
                "declared payload length {declared_bytes} bytes exceeds the {max_bytes}-byte frame limit"
            ),
            Self::Truncated {
                declared_bytes,
                present_bytes,
            } => write!(
                formatter,
                "frame declares a {declared_bytes}-byte payload but only {present_bytes} bytes follow the header"
            ),
            Self::TrailingBytes {
                declared_bytes,
                extra_bytes,
            } => write!(
                formatter,
                "frame declares a {declared_bytes}-byte payload but {extra_bytes} extra bytes follow it"
            ),
            Self::EncodeLimit {
                payload_bytes,
                max_bytes,
            } => write!(
                formatter,
                "serialized envelope of {payload_bytes} bytes exceeds the {max_bytes}-byte frame limit"
            ),
            Self::Decode(source) => {
                write!(formatter, "payload is not a valid envelope: {source}")
            }
            Self::Encode(source) => {
                write!(
                    formatter,
                    "envelope could not be written into the frame: {source}"
                )
            }
        }
    }
}

impl Error for FrameError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Decode(source) => Some(source),
            Self::Encode(source) => Some(source),
            _ => None,
        }
    }
}

/// Serializes an [`Envelope`] into one frame: a [`FRAME_HEADER_BYTES`]-byte
/// big-endian length prefix followed by the envelope's protobuf payload.
///
/// The envelope is measured with `Message::encoded_len` before any
/// allocation, so an oversized envelope is rejected without ever
/// serializing it.
///
/// # Errors
///
/// Returns [`FrameError::EncodeLimit`] when the serialized envelope would
/// exceed [`MAX_FRAME_BYTES`]. Returns [`FrameError::Encode`] when the
/// envelope cannot be written into the pre-sized buffer; unreachable with
/// prost's length-exact encoding, and kept only so the function stays
/// total.
pub fn encode_frame(envelope: &Envelope) -> Result<Vec<u8>, FrameError> {
    let payload_bytes = envelope.encoded_len();
    if payload_bytes > MAX_FRAME_BYTES {
        return Err(FrameError::EncodeLimit {
            payload_bytes,
            max_bytes: MAX_FRAME_BYTES,
        });
    }
    // The limit check bounds `payload_bytes` to MAX_FRAME_BYTES (8 MiB), so
    // the u32 header field always fits it; the failure branch keeps the
    // conversion total without an `unwrap`.
    let declared: u32 = u32::try_from(payload_bytes).map_err(|_| FrameError::EncodeLimit {
        payload_bytes,
        max_bytes: MAX_FRAME_BYTES,
    })?;
    let mut frame = Vec::with_capacity(FRAME_HEADER_BYTES + payload_bytes);
    frame.extend_from_slice(&declared.to_be_bytes());
    envelope.encode(&mut frame).map_err(FrameError::Encode)?;
    Ok(frame)
}

/// Decodes exactly one frame into its [`Envelope`].
///
/// The input must be a [`FRAME_HEADER_BYTES`]-byte big-endian length prefix
/// followed by exactly that many payload bytes — nothing fewer, nothing
/// more — so a single frame can be cut out of a byte stream by its own
/// header. The payload of a frame is an envelope exactly as it was
/// serialized; no further transformation is applied.
///
/// # Errors
///
/// * [`FrameError::TooShort`] when fewer than [`FRAME_HEADER_BYTES`] bytes
///   are present;
/// * [`FrameError::HeaderTooLarge`] when the declared payload length
///   exceeds [`MAX_FRAME_BYTES`];
/// * [`FrameError::Truncated`] when the frame ends before the declared
///   payload;
/// * [`FrameError::TrailingBytes`] when bytes follow the declared payload;
/// * [`FrameError::Decode`] when the payload is not a valid [`Envelope`].
pub fn decode_frame(frame: &[u8]) -> Result<Envelope, FrameError> {
    let Some((header, payload)) = frame.split_first_chunk::<FRAME_HEADER_BYTES>() else {
        return Err(FrameError::TooShort {
            frame_bytes: frame.len(),
            header_bytes: FRAME_HEADER_BYTES,
        });
    };
    let declared = u32::from_be_bytes(*header);
    // The conversion is exact on every supported target (usize is at
    // least 32 bits); on a hypothetical 16-bit target the clamped value
    // is rejected as oversized anyway.
    let declared_bytes = usize::try_from(declared).unwrap_or(usize::MAX);
    if declared_bytes > MAX_FRAME_BYTES {
        return Err(FrameError::HeaderTooLarge {
            declared_bytes,
            max_bytes: MAX_FRAME_BYTES,
        });
    }
    if payload.len() < declared_bytes {
        return Err(FrameError::Truncated {
            declared_bytes,
            present_bytes: payload.len(),
        });
    }
    if payload.len() > declared_bytes {
        return Err(FrameError::TrailingBytes {
            declared_bytes,
            extra_bytes: payload.len() - declared_bytes,
        });
    }
    Envelope::decode(payload).map_err(FrameError::Decode)
}

#[cfg(test)]
mod tests {
    use super::{FRAME_HEADER_BYTES, FrameError, decode_frame, encode_frame};
    use crate::tests::sample_hello;
    use crate::{
        Ack, ArtifactChunk, Envelope, EnvelopeMessage, Heartbeat, MAX_FRAME_BYTES,
        NegotiationResult,
    };
    use prost::Message;
    use std::error::Error;

    /// Wraps a message variant in an envelope with a non-trivial
    /// sequence/ack pair.
    fn envelope_with(message: EnvelopeMessage) -> Envelope {
        Envelope {
            sequence: 7,
            acked_sequence: 6,
            message: Some(message),
        }
    }

    /// The length header field is a `u32`; tests express declared lengths
    /// as `usize` and clamp at `u32::MAX`. No test length reaches 4 GiB,
    /// so the clamp never fires.
    fn declared_u32(length: usize) -> u32 {
        u32::try_from(length).unwrap_or(u32::MAX)
    }

    /// Builds a frame by hand from a declared length and raw payload
    /// bytes.
    fn bare_frame(declared: u32, payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::with_capacity(FRAME_HEADER_BYTES + payload.len());
        frame.extend_from_slice(&declared.to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    #[test]
    fn envelopes_round_trip_through_frames() -> Result<(), FrameError> {
        let envelopes = [
            envelope_with(EnvelopeMessage::Hello(sample_hello())),
            envelope_with(EnvelopeMessage::NegotiationResult(NegotiationResult {
                accepted: true,
                reason: String::new(),
            })),
            envelope_with(EnvelopeMessage::Heartbeat(Heartbeat {
                sent_at_unix: 1_700_000_000,
            })),
            envelope_with(EnvelopeMessage::Ack(Ack { sequence: 12 })),
            envelope_with(EnvelopeMessage::ArtifactChunk(ArtifactChunk {
                artifact_id: String::from("artifact-1"),
                index: 3,
                data: vec![0x01, 0x02, 0x03],
            })),
            Envelope {
                sequence: 0,
                acked_sequence: 0,
                message: None,
            },
        ];
        for envelope in &envelopes {
            let frame = encode_frame(envelope)?;
            assert_eq!(decode_frame(&frame), Ok(envelope.clone()));
        }
        Ok(())
    }

    #[test]
    fn a_frame_is_a_big_endian_length_prefix_followed_by_the_payload() -> Result<(), FrameError> {
        let envelope = envelope_with(EnvelopeMessage::Heartbeat(Heartbeat {
            sent_at_unix: 1_700_000_000,
        }));
        let frame = encode_frame(&envelope)?;
        assert_eq!(frame.len(), FRAME_HEADER_BYTES + envelope.encoded_len());
        let header = [frame[0], frame[1], frame[2], frame[3]];
        assert_eq!(
            u32::from_be_bytes(header),
            declared_u32(envelope.encoded_len())
        );
        assert_eq!(&frame[FRAME_HEADER_BYTES..], &envelope.encode_to_vec());
        Ok(())
    }

    #[test]
    fn a_large_chunk_round_trips_within_the_frame_limit() -> Result<(), FrameError> {
        // 1 MiB of chunk data: comfortably under the limit, and large
        // enough that frame-boundary bugs at scale would show.
        let envelope = envelope_with(EnvelopeMessage::ArtifactChunk(ArtifactChunk {
            artifact_id: String::from("artifact-1"),
            index: 0,
            data: vec![0xCD; 1024 * 1024],
        }));
        let frame = encode_frame(&envelope)?;
        assert_eq!(decode_frame(&frame), Ok(envelope));
        Ok(())
    }

    #[test]
    fn a_zero_length_payload_decodes_to_the_default_envelope() {
        assert_eq!(decode_frame(&bare_frame(0, &[])), Ok(Envelope::default()));
    }

    #[test]
    fn encode_rejects_an_envelope_over_the_frame_limit() {
        // Chunk data sized so the serialized payload is exactly
        // MAX_FRAME_BYTES + 1. The fixed envelope overhead for this shape
        // is 14 bytes: sequence tag+varint (2), acked_sequence (2), oneof
        // message tag (1), oneof length varint (4), chunk data tag (1),
        // chunk data length varint (4). The length is asserted first so
        // the test fails loudly if the proto encoding ever changes.
        let envelope = envelope_with(EnvelopeMessage::ArtifactChunk(ArtifactChunk {
            artifact_id: String::new(),
            index: 0,
            data: vec![0xEE; MAX_FRAME_BYTES - 13],
        }));
        assert_eq!(envelope.encoded_len(), MAX_FRAME_BYTES + 1);
        assert_eq!(
            encode_frame(&envelope),
            Err(FrameError::EncodeLimit {
                payload_bytes: MAX_FRAME_BYTES + 1,
                max_bytes: MAX_FRAME_BYTES,
            })
        );
    }

    #[test]
    fn encode_allows_a_payload_of_exactly_the_frame_limit() -> Result<(), FrameError> {
        // Chunk data sized so the serialized payload is exactly
        // MAX_FRAME_BYTES: the boundary value is legal on both sides of
        // the wire (see the 14-byte overhead breakdown in the over-limit
        // test).
        let envelope = envelope_with(EnvelopeMessage::ArtifactChunk(ArtifactChunk {
            artifact_id: String::new(),
            index: 0,
            data: vec![0xDD; MAX_FRAME_BYTES - 14],
        }));
        assert_eq!(envelope.encoded_len(), MAX_FRAME_BYTES);
        let frame = encode_frame(&envelope)?;
        assert_eq!(frame.len(), FRAME_HEADER_BYTES + MAX_FRAME_BYTES);
        assert_eq!(decode_frame(&frame), Ok(envelope));
        Ok(())
    }

    #[test]
    fn decode_rejects_a_header_over_the_frame_limit() {
        // The header check fires before any payload inspection, so an
        // over-limit declaration is rejected even with no payload present.
        assert_eq!(
            decode_frame(&bare_frame(declared_u32(MAX_FRAME_BYTES + 1), &[])),
            Err(FrameError::HeaderTooLarge {
                declared_bytes: MAX_FRAME_BYTES + 1,
                max_bytes: MAX_FRAME_BYTES,
            })
        );
        assert_eq!(
            decode_frame(&bare_frame(u32::MAX, &[])),
            Err(FrameError::HeaderTooLarge {
                declared_bytes: 0xFFFF_FFFF,
                max_bytes: MAX_FRAME_BYTES,
            })
        );
    }

    #[test]
    fn decode_rejects_a_header_at_the_limit_without_the_declared_payload() {
        // The declared length is exactly MAX_FRAME_BYTES: it passes the
        // header check (the bound is inclusive) and the frame is rejected
        // as truncated, not as oversized.
        assert_eq!(
            decode_frame(&bare_frame(declared_u32(MAX_FRAME_BYTES), &[0x00])),
            Err(FrameError::Truncated {
                declared_bytes: MAX_FRAME_BYTES,
                present_bytes: 1,
            })
        );
    }

    #[test]
    fn decode_rejects_a_truncated_payload() {
        assert_eq!(
            decode_frame(&bare_frame(10, b"only-five")),
            Err(FrameError::Truncated {
                declared_bytes: 10,
                present_bytes: 9,
            })
        );
    }

    #[test]
    fn decode_rejects_trailing_bytes() -> Result<(), FrameError> {
        let envelope = envelope_with(EnvelopeMessage::Ack(Ack { sequence: 1 }));
        let mut padded = encode_frame(&envelope)?;
        padded.push(0x00);
        assert_eq!(
            decode_frame(&padded),
            Err(FrameError::TrailingBytes {
                declared_bytes: envelope.encoded_len(),
                extra_bytes: 1,
            })
        );
        Ok(())
    }

    #[test]
    fn decode_rejects_inputs_shorter_than_the_header() {
        for frame_bytes in 0..FRAME_HEADER_BYTES {
            let frame = vec![0x00; frame_bytes];
            assert_eq!(
                decode_frame(&frame),
                Err(FrameError::TooShort {
                    frame_bytes,
                    header_bytes: FRAME_HEADER_BYTES,
                })
            );
        }
    }

    #[test]
    fn decode_rejects_a_payload_that_is_not_an_envelope() {
        // Field 1 (wire type 0) with no value bytes: prost cannot decode
        // it, and the frame error must surface the prost failure as its
        // source.
        let payload = [0x08];
        assert!(Envelope::decode(payload.as_slice()).is_err());
        let frame = bare_frame(declared_u32(payload.len()), &payload);
        let result = decode_frame(&frame);
        assert!(matches!(&result, Err(FrameError::Decode(_))));
        let Err(error) = result else {
            return;
        };
        assert!(error.source().is_some());
        assert!(
            error
                .to_string()
                .starts_with("payload is not a valid envelope: ")
        );
    }

    #[test]
    fn frame_errors_display_each_failure_mode() {
        assert_eq!(
            FrameError::TooShort {
                frame_bytes: 2,
                header_bytes: FRAME_HEADER_BYTES,
            }
            .to_string(),
            "frame of 2 bytes is shorter than the 4-byte length header"
        );
        assert_eq!(
            FrameError::HeaderTooLarge {
                declared_bytes: MAX_FRAME_BYTES + 1,
                max_bytes: MAX_FRAME_BYTES,
            }
            .to_string(),
            "declared payload length 8388609 bytes exceeds the 8388608-byte frame limit"
        );
        assert_eq!(
            FrameError::Truncated {
                declared_bytes: 10,
                present_bytes: 5,
            }
            .to_string(),
            "frame declares a 10-byte payload but only 5 bytes follow the header"
        );
        assert_eq!(
            FrameError::TrailingBytes {
                declared_bytes: 10,
                extra_bytes: 3,
            }
            .to_string(),
            "frame declares a 10-byte payload but 3 extra bytes follow it"
        );
        assert_eq!(
            FrameError::EncodeLimit {
                payload_bytes: MAX_FRAME_BYTES + 1,
                max_bytes: MAX_FRAME_BYTES,
            }
            .to_string(),
            "serialized envelope of 8388609 bytes exceeds the 8388608-byte frame limit"
        );
        // The structural variants carry no source; the prost-wrapping
        // variants do. The Decode source is produced by a real decode
        // failure.
        assert!(
            FrameError::TooShort {
                frame_bytes: 0,
                header_bytes: FRAME_HEADER_BYTES,
            }
            .source()
            .is_none()
        );
        let payload = [0x08];
        let result = decode_frame(&bare_frame(declared_u32(payload.len()), &payload));
        let Err(error) = result else {
            return;
        };
        assert!(matches!(&error, FrameError::Decode(_)));
        assert!(error.source().is_some());
    }
}
