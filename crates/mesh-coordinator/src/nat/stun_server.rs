//! Minimal RFC 5389 STUN BINDING responder (server side), co-located in the
//! coordinator binary.
//!
//! NAT'd joiners issue a BINDING request FROM their
//! `WireGuard` UDP socket (see the joiner's `nat::stun` client) and we reply with
//! the observed source as XOR-MAPPED-ADDRESS — that reflexive `ip:port` is the
//! punch target governed-direct needs (the HTTP-control-plane source port is
//! unrelated to the WG UDP mapping, so coordinator reflexive alone is wrong for
//! port-sensitive NATs).
//!
//! Scope is deliberately tiny: BINDING only, no auth, no other methods. Enabled
//! by `--stun-bind`; absent ⇒ no STUN server (fully back-compat). The encoding
//! mirrors the joiner client's `parse_xor_mapped_address` exactly. The STUN
//! server NEVER touches any relay/punch decision — it only *discovers* an
//! endpoint; direct is still adopted only on real inbound DATA (`confirm_direct`).

use anyhow::{Context, Result};
use std::net::SocketAddr;
use tokio::net::UdpSocket;

const STUN_BINDING_REQUEST: u16 = 0x0001;
const STUN_BINDING_SUCCESS: u16 = 0x0101;
/// RFC 5389 §6 magic cookie.
const STUN_MAGIC_COOKIE: u32 = 0x2112_A442;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

/// Parse a STUN BINDING request and build a BINDING success carrying `source`
/// as XOR-MAPPED-ADDRESS.
///
/// Returns `None` for anything that is not a well-formed BINDING request
/// (fail-closed: an unknown/malformed packet gets no reply).
#[must_use]
pub fn build_binding_response(request: &[u8], source: SocketAddr) -> Option<Vec<u8>> {
    if request.len() < 20 {
        return None;
    }
    if u16::from_be_bytes([request[0], request[1]]) != STUN_BINDING_REQUEST {
        return None;
    }
    if request[4..8] != STUN_MAGIC_COOKIE.to_be_bytes() {
        return None;
    }
    let mut txid = [0u8; 12];
    txid.copy_from_slice(&request[8..20]);

    // XOR-MAPPED-ADDRESS body (RFC 5389 §15.2). Mirrors the joiner decode in
    // `nat::stun::parse_xor_mapped_address`.
    let cookie = STUN_MAGIC_COOKIE.to_be_bytes();
    let (attr_len, body): (u16, Vec<u8>) = match source {
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

    let mut msg = Vec::with_capacity(20 + 4 + attr_len as usize);
    msg.extend_from_slice(&STUN_BINDING_SUCCESS.to_be_bytes());
    msg.extend_from_slice(&(4 + attr_len).to_be_bytes()); // message length = attr header + body
    msg.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    msg.extend_from_slice(&txid);
    msg.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
    msg.extend_from_slice(&attr_len.to_be_bytes());
    msg.extend_from_slice(&body);
    Some(msg)
}

/// Run the STUN BINDING responder on `bind` until the process exits.
///
/// A malformed or non-BINDING datagram is silently dropped (no reply).
/// Best-effort: a recv error is skipped rather than crashing the listener.
pub async fn run_stun_server(bind: SocketAddr) -> Result<()> {
    let sock = UdpSocket::bind(bind)
        .await
        .with_context(|| format!("STUN bind {bind}"))?;
    tracing::info!(%bind, "STUN BINDING responder listening");
    let mut buf = [0u8; 512];
    loop {
        let (n, src) = match sock.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!(error = %e, "STUN recv error, continuing");
                continue;
            }
        };
        if let Some(resp) = build_binding_response(&buf[..n], src) {
            let _ = sock.send_to(&resp, src).await;
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    /// Build a 20-byte BINDING request with the given transaction id (mirrors
    /// the joiner client's `build_binding_request` wire shape).
    fn binding_request(txid: [u8; 12]) -> Vec<u8> {
        let mut req = Vec::with_capacity(20);
        req.extend_from_slice(&STUN_BINDING_REQUEST.to_be_bytes());
        req.extend_from_slice(&0u16.to_be_bytes());
        req.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        req.extend_from_slice(&txid);
        req
    }

    /// Decode XOR-MAPPED-ADDRESS out of a success response — a local mirror of
    /// the joiner client's `parse_xor_mapped_address`, so this test proves the
    /// server's encoding is exactly what the real client will decode.
    fn decode_xma(resp: &[u8], txid: [u8; 12]) -> Option<SocketAddr> {
        if resp.len() < 20 || u16::from_be_bytes([resp[0], resp[1]]) != STUN_BINDING_SUCCESS {
            return None;
        }
        if resp[8..20] != txid {
            return None;
        }
        let cookie = STUN_MAGIC_COOKIE.to_be_bytes();
        let vstart = 24; // 20-byte header + 4-byte attr header
        if resp.len() < vstart + 8 {
            return None;
        }
        let family = resp[vstart + 1];
        let port = u16::from_be_bytes([resp[vstart + 2], resp[vstart + 3]])
            ^ (STUN_MAGIC_COOKIE >> 16) as u16;
        match family {
            0x01 => {
                let mut ip = [0u8; 4];
                for (i, b) in ip.iter_mut().enumerate() {
                    *b = resp[vstart + 4 + i] ^ cookie[i];
                }
                Some(SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::from(ip)), port))
            }
            0x02 => {
                let mut key = [0u8; 16];
                key[..4].copy_from_slice(&cookie);
                key[4..].copy_from_slice(&txid);
                let mut ip = [0u8; 16];
                for (i, b) in ip.iter_mut().enumerate() {
                    *b = resp[vstart + 4 + i] ^ key[i];
                }
                Some(SocketAddr::new(std::net::IpAddr::V6(Ipv6Addr::from(ip)), port))
            }
            _ => None,
        }
    }

    /// A BINDING request yields a BINDING success whose XOR-MAPPED-ADDRESS, when
    /// decoded by the (mirror of the) real client, equals the observed source —
    /// for a realistic NAT'd IPv4 source.
    #[test]
    fn binding_request_yields_source_as_xor_mapped_v4() {
        let txid = [7u8; 12];
        let src = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(146, 255, 233, 163), 51820));
        let resp = build_binding_response(&binding_request(txid), src).expect("a success response");
        assert_eq!(
            u16::from_be_bytes([resp[0], resp[1]]),
            STUN_BINDING_SUCCESS,
            "type is BINDING success"
        );
        assert_eq!(&resp[8..20], &txid, "transaction id is echoed");
        assert_eq!(
            decode_xma(&resp, txid),
            Some(src),
            "XOR-MAPPED-ADDRESS decodes to the observed source"
        );
    }

    /// IPv6 source round-trips too (XOR with cookie||txid).
    #[test]
    fn binding_request_yields_source_as_xor_mapped_v6() {
        let txid = [9u8; 12];
        let src = SocketAddr::V6(SocketAddrV6::new(
            "2001:db8::1".parse::<Ipv6Addr>().unwrap(),
            51821,
            0,
            0,
        ));
        let resp = build_binding_response(&binding_request(txid), src).expect("a success response");
        assert_eq!(decode_xma(&resp, txid), Some(src));
    }

    /// Fail-closed: a too-short packet, a non-BINDING type, or a wrong magic
    /// cookie all get NO reply (returns `None`).
    #[test]
    fn malformed_or_non_binding_gets_no_reply() {
        let src: SocketAddr = "1.2.3.4:1".parse().unwrap();
        assert!(build_binding_response(&[0u8; 10], src).is_none(), "too short");
        let mut wrong_type = binding_request([1u8; 12]);
        wrong_type[0..2].copy_from_slice(&0x0101u16.to_be_bytes()); // a success, not a request
        assert!(
            build_binding_response(&wrong_type, src).is_none(),
            "non-BINDING-request type"
        );
        let mut bad_cookie = binding_request([2u8; 12]);
        bad_cookie[4] ^= 0xff;
        assert!(
            build_binding_response(&bad_cookie, src).is_none(),
            "wrong magic cookie"
        );
    }
}
