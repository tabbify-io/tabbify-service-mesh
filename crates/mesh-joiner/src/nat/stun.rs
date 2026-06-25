//! Minimal RFC 5389 STUN client (Track A-a).
//!
//! Issued FROM the `WireGuard` UDP socket, so the discovered NAT mapping is the
//! WG one — correcting the symmetric-NAT port nuance documented in
//! `mesh-coordinator`'s reflexive resolver (the HTTP control-plane source port
//! is unrelated to the WG UDP mapping). The joiner advertises the
//! STUN-discovered `ip:port` for a flagged direct pair instead of the
//! coordinator's reflexive guess.
//!
//! Scope is deliberately tiny: a 20-byte binding request + parsing the
//! XOR-MAPPED-ADDRESS attribute. No STUN crate dependency (keeps the musl
//! cross-build clean). Best-effort: any timeout / parse failure yields `None`
//! and the caller falls back to the coordinator reflexive guess — relay always
//! remains the floor.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;

/// The fixed STUN magic cookie (`0x2112A442`, RFC 5389 §6).
pub const STUN_MAGIC_COOKIE: u32 = 0x2112_A442;
const STUN_BINDING_REQUEST: u16 = 0x0001;
const STUN_BINDING_SUCCESS: u16 = 0x0101;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

/// Build a 20-byte STUN binding request + its random 12-byte transaction id.
#[must_use]
pub fn build_binding_request() -> (Vec<u8>, [u8; 12]) {
    let mut txid = [0u8; 12];
    // A non-crypto-strong id is fine: it only correlates our request to its
    // response on a connected socket. Use the nanos clock to vary it.
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0u128, |d| d.as_nanos());
    for (i, b) in txid.iter_mut().enumerate() {
        *b = ((seed >> (i * 8)) & 0xff) as u8;
    }
    let mut msg = Vec::with_capacity(20);
    msg.extend_from_slice(&STUN_BINDING_REQUEST.to_be_bytes());
    msg.extend_from_slice(&0u16.to_be_bytes()); // message length = 0 (no attrs)
    msg.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    msg.extend_from_slice(&txid);
    (msg, txid)
}

/// Parse XOR-MAPPED-ADDRESS out of a STUN success response.
///
/// Verifies the transaction id matches `txid`. Returns `None` on any
/// malformation / type mismatch / wrong txid — fail-closed (we never trust an
/// unmatched mapping).
#[must_use]
pub fn parse_xor_mapped_address(resp: &[u8], txid: [u8; 12]) -> Option<SocketAddr> {
    if resp.len() < 20 {
        return None;
    }
    let msg_type = u16::from_be_bytes([resp[0], resp[1]]);
    if msg_type != STUN_BINDING_SUCCESS {
        return None;
    }
    if resp[8..20] != txid {
        return None; // response to a different request — reject
    }
    let mut off = 20;
    while off + 4 <= resp.len() {
        let atype = u16::from_be_bytes([resp[off], resp[off + 1]]);
        let alen = u16::from_be_bytes([resp[off + 2], resp[off + 3]]) as usize;
        let vstart = off + 4;
        if vstart + alen > resp.len() {
            return None;
        }
        if atype == ATTR_XOR_MAPPED_ADDRESS && alen >= 8 {
            let family = resp[vstart + 1];
            let xport = u16::from_be_bytes([resp[vstart + 2], resp[vstart + 3]]);
            let port = xport ^ (STUN_MAGIC_COOKIE >> 16) as u16;
            let cookie = STUN_MAGIC_COOKIE.to_be_bytes();
            return match family {
                0x01 => {
                    // IPv4: XOR the 4 address bytes with the magic cookie.
                    let mut ip = [0u8; 4];
                    for (i, b) in ip.iter_mut().enumerate() {
                        *b = resp[vstart + 4 + i] ^ cookie[i];
                    }
                    Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port))
                }
                0x02 if alen >= 20 => {
                    // IPv6: XOR with magic cookie || transaction id.
                    let mut key = [0u8; 16];
                    key[..4].copy_from_slice(&cookie);
                    key[4..].copy_from_slice(&txid);
                    let mut ip = [0u8; 16];
                    for (i, b) in ip.iter_mut().enumerate() {
                        *b = resp[vstart + 4 + i] ^ key[i];
                    }
                    Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), port))
                }
                _ => None,
            };
        }
        // Attributes are 4-byte aligned.
        off = vstart + alen.div_ceil(4) * 4;
    }
    None
}

/// Issue a STUN binding request over `socket` and return the observed
/// WG-socket mapping.
///
/// Best-effort: a timeout / parse failure yields `None`, and the caller falls
/// back to the coordinator reflexive guess (relay always remains the floor
/// regardless).
pub async fn discover_wg_mapping(
    socket: &UdpSocket,
    stun_server: SocketAddr,
    timeout: Duration,
) -> Option<SocketAddr> {
    let (req, txid) = build_binding_request();
    socket.send_to(&req, stun_server).await.ok()?;
    let mut buf = [0u8; 512];
    let n = tokio::time::timeout(timeout, socket.recv_from(&mut buf))
        .await
        .ok()?
        .ok()?
        .0;
    parse_xor_mapped_address(&buf[..n], txid)
}

#[cfg(test)]
fn synth_success_response(txid: [u8; 12], mapped: SocketAddr) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(&STUN_BINDING_SUCCESS.to_be_bytes());
    let cookie = STUN_MAGIC_COOKIE.to_be_bytes();
    let (attr_len, body): (u16, Vec<u8>) = match mapped {
        SocketAddr::V4(v4) => {
            let mut b = vec![0u8, 0x01];
            let xport = v4.port() ^ (STUN_MAGIC_COOKIE >> 16) as u16;
            b.extend_from_slice(&xport.to_be_bytes());
            for (i, o) in v4.ip().octets().iter().enumerate() {
                b.push(o ^ cookie[i]);
            }
            (8, b)
        }
        SocketAddr::V6(v6) => {
            let mut b = vec![0u8, 0x02];
            let xport = v6.port() ^ (STUN_MAGIC_COOKIE >> 16) as u16;
            b.extend_from_slice(&xport.to_be_bytes());
            let mut key = [0u8; 16];
            key[..4].copy_from_slice(&cookie);
            key[4..].copy_from_slice(&txid);
            for (i, o) in v6.ip().octets().iter().enumerate() {
                b.push(o ^ key[i]);
            }
            (20, b)
        }
    };
    let msg_len = 4 + attr_len;
    msg.extend_from_slice(&msg_len.to_be_bytes());
    msg.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    msg.extend_from_slice(&txid);
    msg.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
    msg.extend_from_slice(&attr_len.to_be_bytes());
    msg.extend_from_slice(&body);
    msg
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    /// A binding request is 20 bytes: magic-cookie + type + zero length + a
    /// 12-byte transaction id. `build_binding_request` returns exactly that and
    /// `parse_xor_mapped_address` round-trips a response we synthesize.
    #[test]
    fn binding_request_then_parse_xor_mapped_round_trips() {
        let (req, txid) = build_binding_request();
        assert_eq!(req.len(), 20, "STUN binding request is 20 bytes");
        assert_eq!(&req[4..8], &STUN_MAGIC_COOKIE.to_be_bytes(), "magic cookie");

        // Synthesize a success response carrying XOR-MAPPED-ADDRESS for
        // 203.0.113.7:51999 with the SAME transaction id, then parse it back.
        let mapped = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 7), 51999));
        let resp = synth_success_response(txid, mapped);
        let got = parse_xor_mapped_address(&resp, txid).expect("parse mapped addr");
        assert_eq!(got, mapped, "XOR-MAPPED-ADDRESS round-trips the WG mapping");
    }

    /// A response with a MISMATCHED transaction id is rejected (anti-spoof):
    /// we only trust a mapping that answers OUR request id.
    #[test]
    fn mismatched_txid_is_rejected() {
        let (_req, txid) = build_binding_request();
        let other = [0xAAu8; 12];
        let mapped = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 5));
        let resp = synth_success_response(other, mapped);
        assert!(
            parse_xor_mapped_address(&resp, txid).is_none(),
            "a response to a different transaction id must be rejected"
        );
    }

    /// SAFETY (relay floor): an unreachable / silent STUN server must yield
    /// `None` *bounded by the timeout* — never a hang, never a panic. This is
    /// what makes `joiner.rs` fall through to the relay floor when STUN is down
    /// or unset: no reflexive mapping is adopted, `relay_enabled` is untouched,
    /// and the advertised endpoint stays exactly what it already was. Direct is
    /// purely additive; its failure can never cost connectivity.
    #[tokio::test]
    async fn unreachable_stun_yields_none_and_does_not_hang() {
        // The joiner's WG socket (the one a real join issues STUN from).
        let wg = UdpSocket::bind("127.0.0.1:0").await.expect("bind wg socket");
        // A bound-but-SILENT peer models a dead/unreachable STUN responder
        // deterministically: it consumes our datagram and never answers (no
        // routing, no ICMP races). `recv` must hit the timeout → `None`.
        let silent = UdpSocket::bind("127.0.0.1:0").await.expect("bind silent peer");
        let dead = silent.local_addr().expect("silent addr");
        let got = discover_wg_mapping(&wg, dead, Duration::from_millis(200)).await;
        assert!(
            got.is_none(),
            "an unreachable STUN server must yield None — the caller keeps the relay floor"
        );
    }
}
