//! Relay protocol v1 frame codec (joiner copy).
//!
//! A relay frame is a 32-byte raw X25519 pubkey prefix followed by an
//! opaque (already-WG-encrypted) payload. The codec is defined
//! INDEPENDENTLY in each crate — the same rule as `HolePunchInitiate` —
//! so the joiner carries no dependency on the coordinator crate. It MUST
//! stay byte-identical to the coordinator's copy; the canonical test
//! vectors below are asserted in BOTH crates to enforce that.
//!
//! Wire layout:
//! ```text
//! bytes [0..32)  peer_pubkey   raw 32-byte X25519 key
//! bytes [32..)   payload       opaque WG transport datagram
//! ```

/// Encode a relay frame: 32-byte pubkey prefix + opaque payload.
#[must_use]
pub fn encode_relay_frame(peer_pubkey: &[u8; 32], payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(32 + payload.len());
    buf.extend_from_slice(peer_pubkey);
    buf.extend_from_slice(payload);
    buf
}

/// Decode a relay frame. `None` when too short (< 32 + 1 bytes).
#[must_use]
pub fn decode_relay_frame(buf: &[u8]) -> Option<([u8; 32], &[u8])> {
    if buf.len() < 33 {
        return None;
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&buf[..32]);
    Some((pk, &buf[32..]))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    /// `encode_relay_frame(&[7u8; 32], b"hello")` → 37 bytes; the first 32
    /// are the pubkey prefix, the rest is the payload verbatim.
    #[test]
    fn encode_prefixes_pubkey_then_payload() {
        let frame = encode_relay_frame(&[7u8; 32], b"hello");
        assert_eq!(frame.len(), 37);
        assert_eq!(&frame[..32], &[7u8; 32]);
        assert_eq!(&frame[32..], b"hello");
    }

    /// `decode_relay_frame` round-trips a frame produced by `encode`.
    #[test]
    fn decode_round_trips_encode() {
        let frame = encode_relay_frame(&[7u8; 32], b"hello");
        let decoded = decode_relay_frame(&frame);
        assert_eq!(decoded, Some(([7u8; 32], b"hello".as_slice())));
    }

    /// A frame with exactly 32 bytes (pubkey, no payload) is too short.
    #[test]
    fn decode_rejects_pubkey_only() {
        assert_eq!(decode_relay_frame(&[0u8; 32]), None);
    }

    /// A frame shorter than the pubkey prefix is too short.
    #[test]
    fn decode_rejects_short_buffer() {
        assert_eq!(decode_relay_frame(&[0u8; 10]), None);
    }
}
