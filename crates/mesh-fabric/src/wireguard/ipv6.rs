//! Synthetic-IPv6 framing for the userspace `WireGuard` data plane.
//!
//! `boringtun`'s `Tunn::encapsulate` and `decapsulate` validate the
//! plaintext as IP datagrams. We're carrying opaque app bytes, not real
//! routed IPv6, so we wrap every payload in a minimal IPv6 header just
//! to satisfy that invariant; the headers never leave this crate.

use crate::trait_def::FabricError;
use std::net::Ipv6Addr;

/// Size of an IPv6 header — boringtun validates decapsulated packets
/// as IP, so we synthesise a minimal IPv6 header in front of every
/// application payload.
pub(super) const IPV6_HEADER_LEN: usize = 40;

/// Build a minimal IPv6 packet wrapping `payload`. The resulting
/// bytes are accepted by boringtun's data-plane validation.
///
/// Layout (RFC 8200):
/// ```text
/// [0]      Version (4) | Traffic Class High (4)  = 0x60
/// [1]      Traffic Class Low (4) | Flow Label H (4)
/// [2-3]    Flow Label (low 16 bits)
/// [4-5]    Payload length (big-endian u16)
/// [6]      Next header (59 = no next header)
/// [7]      Hop limit
/// [8-23]   Source address
/// [24-39]  Destination address
/// [40..]   Payload
/// ```
pub(super) fn build_ipv6_packet(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    payload: &[u8],
) -> Result<Vec<u8>, FabricError> {
    let payload_len: u16 = u16::try_from(payload.len())
        .map_err(|_| FabricError::Encoding(format!("payload {} > u16::MAX", payload.len())))?;
    let mut out = Vec::with_capacity(IPV6_HEADER_LEN + payload.len());
    // version = 6, TC = 0, FL = 0
    out.push(0x60);
    out.push(0x00);
    out.push(0x00);
    out.push(0x00);
    // payload length (big-endian)
    out.extend_from_slice(&payload_len.to_be_bytes());
    // next header = 59 (no next header — payload is opaque)
    out.push(59);
    // hop limit = 64
    out.push(64);
    out.extend_from_slice(&src.octets());
    out.extend_from_slice(&dst.octets());
    out.extend_from_slice(payload);
    Ok(out)
}

/// Strip the IPv6 header. Returns `(src, dst, payload)` on success.
pub(super) fn parse_ipv6_packet(
    bytes: &[u8],
) -> Result<(Ipv6Addr, Ipv6Addr, Vec<u8>), FabricError> {
    if bytes.len() < IPV6_HEADER_LEN {
        return Err(FabricError::Encoding(format!(
            "ipv6 packet too short: {}",
            bytes.len()
        )));
    }
    if bytes[0] >> 4 != 6 {
        return Err(FabricError::Encoding(format!(
            "not an ipv6 packet (version nibble = {})",
            bytes[0] >> 4
        )));
    }
    let payload_len = u16::from_be_bytes([bytes[4], bytes[5]]) as usize;
    if bytes.len() < IPV6_HEADER_LEN + payload_len {
        return Err(FabricError::Encoding(format!(
            "ipv6 length field {} exceeds available {} bytes",
            payload_len,
            bytes.len() - IPV6_HEADER_LEN
        )));
    }
    let mut src_bytes = [0u8; 16];
    let mut dst_bytes = [0u8; 16];
    src_bytes.copy_from_slice(&bytes[8..24]);
    dst_bytes.copy_from_slice(&bytes[24..40]);
    let src = Ipv6Addr::from(src_bytes);
    let dst = Ipv6Addr::from(dst_bytes);
    let payload = bytes[IPV6_HEADER_LEN..IPV6_HEADER_LEN + payload_len].to_vec();
    Ok((src, dst, payload))
}
