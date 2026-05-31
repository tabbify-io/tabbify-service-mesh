//! Relay protocol v1 frame codec.
//!
//! A relay frame is a 32-byte raw X25519 pubkey prefix followed by an opaque
//! `WireGuard` transport datagram (already encrypted — the relay never sees
//! plaintext). On the uplink (joiner → coordinator) the prefix is the
//! destination pubkey; on the downlink (coordinator → joiner) the coordinator
//! rewrites the prefix to the source pubkey so the receiver demuxes by source.
//!
//! This codec is defined independently in each crate (coordinator + joiner),
//! the same rule as `HolePunchInitiate`: no cross-crate dependency, identical
//! bytes on both sides. The canonical test vectors are asserted in both.

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

    #[test]
    fn encode_prefixes_pubkey_then_payload() {
        let frame = encode_relay_frame(&[7u8; 32], b"hello");
        assert_eq!(frame.len(), 37);
        assert_eq!(&frame[..32], &[7u8; 32]);
        assert_eq!(&frame[32..], b"hello");
    }

    #[test]
    fn decode_roundtrips_encode() {
        let frame = encode_relay_frame(&[7u8; 32], b"hello");
        let (pk, payload) = decode_relay_frame(&frame).expect("valid frame");
        assert_eq!(pk, [7u8; 32]);
        assert_eq!(payload, b"hello");
    }

    #[test]
    fn decode_rejects_pubkey_only_no_payload() {
        assert!(decode_relay_frame(&[0u8; 32]).is_none());
    }

    #[test]
    fn decode_rejects_too_short() {
        assert!(decode_relay_frame(&[0u8; 10]).is_none());
    }
}
