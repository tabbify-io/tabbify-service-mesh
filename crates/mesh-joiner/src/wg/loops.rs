// Same lock-then-drop-before-await pattern as the rest of the crate —
// see the top of `session.rs` for the rationale.
#![allow(clippy::significant_drop_tightening)]

//! Background loops that bridge boringtun ↔ TUN ↔ UDP.
//!
//! Split out of [`crate::joiner`] to keep each file under 500 lines and
//! to make the boring socket-and-byte-pump code testable in isolation.
//!
//! All four loops follow the same shape:
//!
//! 1. `tokio::select!` over (shutdown signal, work source).
//! 2. On shutdown, return; on work, dispatch and continue.
//!
//! None of these loops own any data — they hand back to the
//! [`crate::wg::session::SessionTable`] for routing decisions.

use crate::wg::session::{classify_tunn_result, PeerSession, SessionTable, WgAction};
use std::net::Ipv6Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tabbify_mesh_fabric::tun::TunDevice;
use tokio::net::UdpSocket;
use tokio::sync::watch;

/// Count of inbound inner packets dropped because their source address
/// was not in the originating peer's allowed-set (spec §5.5 — the
/// cryptokey-routing invariant boringtun does not enforce). Process-wide
/// so a long-running joiner can surface "how many spoofed packets did we
/// reject" without per-session bookkeeping.
pub(crate) static RX_SOURCE_DENIED: AtomicU64 = AtomicU64::new(0);

/// Maximum encapsulated frame we'll ever read off the UDP socket.
///
/// 9 KiB covers EC2 jumbo MTU + `WireGuard` overhead with room to
/// spare; matches `mesh-fabric::wireguard`.
pub(crate) const MAX_UDP_FRAME: usize = 9_001;

/// Maximum plaintext IPv6 packet we'll read off the TUN device.
///
/// Capped to the same 9 KiB ceiling so a misconfigured MTU can't blow
/// the receive buffer.
pub(crate) const MAX_TUN_FRAME: usize = 9_001;

/// Drain UDP → boringtun → TUN.
pub(crate) async fn udp_recv_loop(
    socket: Arc<UdpSocket>,
    sessions: SessionTable,
    tun: Arc<dyn TunDevice>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut buf = vec![0u8; MAX_UDP_FRAME];
    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    return;
                }
            }
            recv = socket.recv_from(&mut buf) => {
                match recv {
                    Ok((n, peer_addr)) => {
                        let datagram = &buf[..n];
                        // Fast path: known endpoint → known session.
                        if let Some(session) = sessions.by_endpoint(peer_addr) {
                            process_inbound_datagram(&socket, &tun, &session, datagram).await;
                            continue;
                        }
                        // Slow path: unknown source addr. WireGuard
                        // roaming / NAT means a peer can show up from a
                        // port we haven't seen — try every session's
                        // Tunn until one accepts the datagram (boringtun
                        // identifies the peer by pubkey embedded in the
                        // handshake init, not by socket addr). On match
                        // we learn the source so future packets hit the
                        // fast path.
                        let mut accepted = false;
                        for session in sessions.snapshot() {
                            let attempt = {
                                let mut scratch = vec![0u8; MAX_UDP_FRAME];
                                let mut tunn = session.tunn.lock().await;
                                let res = tunn.decapsulate(None, datagram, &mut scratch);
                                classify_tunn_result(res)
                            };
                            if matches!(attempt, WgAction::Error(_) | WgAction::Nothing) {
                                continue;
                            }
                            tracing::debug!(
                                peer = %session.peer_id,
                                %peer_addr,
                                "udp_recv: learned endpoint from successful decapsulate"
                            );
                            sessions.learn_endpoint(&session, peer_addr);
                            apply_wg_action(&socket, &tun, &session, attempt).await;
                            // Drain any queued frames (mirrors process_inbound_datagram).
                            loop {
                                let next = {
                                    let mut scratch = vec![0u8; MAX_UDP_FRAME];
                                    let mut tunn = session.tunn.lock().await;
                                    let res = tunn.decapsulate(None, &[], &mut scratch);
                                    classify_tunn_result(res)
                                };
                                if matches!(next, WgAction::Nothing) {
                                    break;
                                }
                                apply_wg_action(&socket, &tun, &session, next).await;
                            }
                            accepted = true;
                            break;
                        }
                        if !accepted {
                            tracing::trace!(%peer_addr, "udp_recv: no session accepted the datagram, dropping");
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "udp_recv: error");
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                }
            }
        }
    }
}

/// Feed one inbound UDP datagram into `session`'s tunnel, dispatching
/// any emitted plaintext frames to the TUN device and any
/// boringtun-emitted handshake responses back to the wire.
async fn process_inbound_datagram(
    socket: &UdpSocket,
    tun: &Arc<dyn TunDevice>,
    session: &Arc<PeerSession>,
    datagram: &[u8],
) {
    // First call: decapsulate the actual UDP datagram.
    let first = {
        let mut scratch = vec![0u8; MAX_UDP_FRAME];
        let mut tunn = session.tunn.lock().await;
        let res = tunn.decapsulate(None, datagram, &mut scratch);
        classify_tunn_result(res)
    };
    apply_wg_action(socket, tun, session, first).await;

    // boringtun documents that after `WriteToNetwork`, the caller
    // should keep calling `decapsulate` with an empty datagram until
    // `Done` is returned, to drain packets queued behind the
    // handshake.
    loop {
        let next = {
            let mut scratch = vec![0u8; MAX_UDP_FRAME];
            let mut tunn = session.tunn.lock().await;
            let res = tunn.decapsulate(None, &[], &mut scratch);
            classify_tunn_result(res)
        };
        if matches!(next, WgAction::Nothing) {
            break;
        }
        apply_wg_action(socket, tun, session, next).await;
    }
}

async fn apply_wg_action(
    socket: &UdpSocket,
    tun: &Arc<dyn TunDevice>,
    session: &Arc<PeerSession>,
    action: WgAction,
) {
    match action {
        WgAction::Nothing => {}
        WgAction::Error(e) => {
            tracing::debug!(error = %e, peer = %session.peer_id, "boringtun action error");
        }
        WgAction::SendToPeer(bytes) => {
            let Some(endpoint) = session.endpoint() else {
                tracing::trace!(
                    peer = %session.peer_id,
                    "passive peer with bytes to send — buffering by no-op (Stage 2 will add hole-punch)"
                );
                return;
            };
            if let Err(e) = socket.send_to(&bytes, endpoint).await {
                tracing::debug!(error = %e, %endpoint, "udp send failed");
            }
        }
        WgAction::DeliverToTun(bytes) => {
            // spec §5.5 RX enforcement: boringtun decapsulated this
            // inner packet because a known peer's tunnel authenticated
            // it, but boringtun does NOT check that the inner SOURCE
            // address is one this peer is allowed to use. Enforce the
            // cryptokey-routing invariant ourselves — drop the packet if
            // its source is outside the peer's allowed-set.
            if !inner_source_allowed(session, &bytes) {
                return;
            }
            if let Err(e) = tun.write_packet(&bytes).await {
                tracing::debug!(error = %e, "tun write failed");
            }
        }
    }
}

/// Gate one decapsulated inner IPv6 packet against the originating
/// peer's allowed-set. Returns `true` if the packet may be delivered to
/// the TUN, `false` if it must be dropped. A non-IPv6 / truncated packet
/// is dropped (we only carry IPv6 over the overlay). Each drop bumps
/// [`RX_SOURCE_DENIED`] and logs a `warn` with the offending pair.
fn inner_source_allowed(session: &Arc<PeerSession>, packet: &[u8]) -> bool {
    let Some(src) = ipv6_source(packet) else {
        RX_SOURCE_DENIED.fetch_add(1, Ordering::Relaxed);
        tracing::warn!(
            peer = %session.peer_id,
            len = packet.len(),
            "rx: dropping non-ipv6 / truncated inner packet from peer"
        );
        return false;
    };
    if session.is_allowed_source(src) {
        return true;
    }
    RX_SOURCE_DENIED.fetch_add(1, Ordering::Relaxed);
    tracing::warn!(
        peer = %session.peer_id,
        peer_ula = %session.ula,
        inner_src = %src,
        "rx: dropping inner packet — source not in peer allowed-set (spec §5.5)"
    );
    false
}

/// Drain TUN → boringtun → UDP. Reads plaintext IPv6 packets, looks up
/// the destination ULA in the session table, encapsulates, and sends.
pub(crate) async fn tun_read_loop(
    socket: Arc<UdpSocket>,
    sessions: SessionTable,
    tun: Arc<dyn TunDevice>,
    my_ula: Ipv6Addr,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut buf = vec![0u8; MAX_TUN_FRAME];
    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    return;
                }
            }
            read = tun.read_packet(&mut buf) => {
                match read {
                    Ok(n) => {
                        let packet = &buf[..n];
                        let Some(dst) = ipv6_destination(packet) else {
                            tracing::debug!(len = n, "tun_read: not an ipv6 packet, dropping");
                            continue;
                        };
                        if dst == my_ula {
                            // Loopback to our own ULA — the kernel
                            // should normally route this without
                            // hitting the TUN; if it does, drop.
                            tracing::debug!(%dst, "tun_read: loopback to self, drop");
                            continue;
                        }
                        let Some(session) = sessions.by_ula(dst) else {
                            tracing::debug!(%dst, "tun_read: no session for destination ULA");
                            continue;
                        };
                        tracing::debug!(
                            %dst,
                            peer = %session.peer_id,
                            len = n,
                            endpoint = ?session.endpoint(),
                            "tun_read: encapsulating + sending"
                        );
                        encapsulate_and_send(&socket, &session, packet).await;
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "tun_read: error");
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                }
            }
        }
    }
}

async fn encapsulate_and_send(
    socket: &UdpSocket,
    session: &Arc<PeerSession>,
    packet: &[u8],
) {
    let action: WgAction = {
        // Size for the largest WireGuard message, NOT the input packet. When no
        // session exists yet, encapsulate() emits a 148-byte handshake-init
        // whose size is independent of `packet`. `packet.len() + 64` starved it
        // for small packets (a 56-byte ping -> a 120-byte buffer < 148) ->
        // DestinationBufferTooSmall -> the handshake never went out, so no
        // session ever formed and all data-plane traffic hung. MAX_UDP_FRAME is
        // the largest encapsulated frame we'd ever send.
        let mut out = vec![0u8; MAX_UDP_FRAME];
        let mut tunn = session.tunn.lock().await;
        classify_tunn_result(tunn.encapsulate(packet, &mut out))
    };
    match action {
        WgAction::SendToPeer(bytes) => {
            let Some(endpoint) = session.endpoint() else {
                tracing::trace!(
                    peer = %session.peer_id,
                    "passive peer — dropping outbound until they initiate"
                );
                return;
            };
            if let Err(e) = socket.send_to(&bytes, endpoint).await {
                tracing::debug!(error = %e, %endpoint, "tun_read: udp send failed");
            }
        }
        WgAction::Nothing => {
            // boringtun queued the packet behind a handshake — it'll
            // be flushed once the handshake completes.
        }
        WgAction::Error(e) => {
            tracing::debug!(error = %e, peer = %session.peer_id, "tun_read: encapsulate error");
        }
        WgAction::DeliverToTun(_) => {
            // encapsulate should never return a tunnel packet.
            tracing::debug!("tun_read: unexpected DeliverToTun from encapsulate");
        }
    }
}

/// Parse the destination IPv6 address out of a packet. Returns `None`
/// for non-v6 input.
pub(crate) fn ipv6_destination(bytes: &[u8]) -> Option<Ipv6Addr> {
    if bytes.len() < 40 || (bytes[0] >> 4) != 6 {
        return None;
    }
    let mut dst = [0u8; 16];
    dst.copy_from_slice(&bytes[24..40]);
    Some(Ipv6Addr::from(dst))
}

/// Parse the SOURCE IPv6 address out of a packet. Returns `None` for
/// non-v6 / truncated input. Bytes 8..24 are the IPv6 source per RFC
/// 8200. Used by the RX allowed-ips check (spec §5.5).
pub(crate) fn ipv6_source(bytes: &[u8]) -> Option<Ipv6Addr> {
    if bytes.len() < 40 || (bytes[0] >> 4) != 6 {
        return None;
    }
    let mut src = [0u8; 16];
    src.copy_from_slice(&bytes[8..24]);
    Some(Ipv6Addr::from(src))
}

/// Drive each peer's timer state every 200ms. boringtun expects
/// `update_timers` roughly every 250ms; this matches `mesh-fabric`.
pub(crate) async fn timer_loop(
    socket: Arc<UdpSocket>,
    sessions: SessionTable,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(Duration::from_millis(200));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    return;
                }
            }
            _ = interval.tick() => {
                for session in sessions.snapshot() {
                    let outbound: Option<Vec<u8>> = {
                        let mut scratch = vec![0u8; 256];
                        let mut tunn = session.tunn.lock().await;
                        match tunn.update_timers(&mut scratch) {
                            boringtun::noise::TunnResult::WriteToNetwork(bytes) => {
                                Some(bytes.to_vec())
                            }
                            _ => None,
                        }
                    };
                    if let Some(bytes) = outbound {
                        let Some(endpoint) = session.endpoint() else {
                            continue;
                        };
                        if let Err(e) = socket.send_to(&bytes, endpoint).await {
                            tracing::trace!(error = %e, %endpoint, "timer: udp send failed");
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::wg::session::SessionTable;
    use std::collections::HashSet;

    /// `ipv6_destination` returns `None` for too-short or non-v6 input.
    #[test]
    fn ipv6_destination_rejects_short_and_v4() {
        assert!(ipv6_destination(&[0u8; 10]).is_none());
        let mut v4 = vec![0u8; 40];
        v4[0] = 0x45; // ipv4 nibble
        assert!(ipv6_destination(&v4).is_none());
    }

    /// And returns the right address for a well-formed packet.
    #[test]
    fn ipv6_destination_parses_dst_bytes() {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x60; // ipv6 nibble + traffic class 0
        // bytes 24..40 = destination address
        let dst: Ipv6Addr = "fd5a:1f00:1::99".parse().unwrap();
        pkt[24..40].copy_from_slice(&dst.octets());
        assert_eq!(ipv6_destination(&pkt), Some(dst));
    }

    // ---- spec §5.5: RX inner-source check ----

    /// `ipv6_source` rejects truncated / non-v6 input and parses the
    /// source bytes (8..24) for a well-formed packet.
    #[test]
    fn ipv6_source_parses_and_rejects() {
        assert!(ipv6_source(&[0u8; 10]).is_none());
        let mut v4 = vec![0u8; 40];
        v4[0] = 0x45;
        assert!(ipv6_source(&v4).is_none());

        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x60;
        let src: Ipv6Addr = "fd5a:1f00:1::7".parse().unwrap();
        pkt[8..24].copy_from_slice(&src.octets());
        assert_eq!(ipv6_source(&pkt), Some(src));
    }

    /// Build a minimal IPv6 packet carrying `src` as its source address.
    fn ipv6_packet_from(src: Ipv6Addr) -> Vec<u8> {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x60; // version 6
        pkt[8..24].copy_from_slice(&src.octets());
        pkt
    }

    /// Build a real `PeerSession` (via the session table) whose
    /// allowed-set is exactly `{ula}`. Reusing `upsert` keeps the test
    /// honest about how `allowed_ips` is actually populated.
    fn session_allowing(ula: &str) -> Arc<PeerSession> {
        use x25519_dalek::{PublicKey, StaticSecret};
        let me = StaticSecret::from([9u8; 32]);
        let info = crate::peer::PeerInfo {
            peer_id: uuid::Uuid::nil(),
            wg_public_key: *PublicKey::from(&StaticSecret::from([3u8; 32])).as_bytes(),
            ula: ula.parse().unwrap(),
            listen_endpoint: Some("127.0.0.1:51820".parse().unwrap()),
            display_name: "peer".into(),
            tags: vec![],
            joined_at_micros: 0,
        };
        let t = SessionTable::new();
        t.upsert(&me, &info);
        t.by_ula(ula.parse().unwrap()).unwrap()
    }

    /// PASS: an inner packet whose source IS the peer's `/128` is
    /// accepted by the allowed-source gate.
    #[test]
    fn rx_accepts_inner_source_within_peer_128() {
        let session = session_allowing("fd5a:1f00:1::1");
        let pkt = ipv6_packet_from("fd5a:1f00:1::1".parse().unwrap());
        assert!(inner_source_allowed(&session, &pkt));
    }

    /// DROP: an inner packet whose source is OUTSIDE the peer's `/128`
    /// (a different ULA in the same `/48`) is rejected, and the deny
    /// counter advances. This is the spoofing case §5.5 exists to stop.
    ///
    /// `RX_SOURCE_DENIED` is process-wide so concurrently-running deny
    /// tests may bump it too — assert a strict increase rather than an
    /// exact `+1` to stay deterministic under the parallel test runner.
    #[test]
    fn rx_drops_inner_source_outside_peer_128() {
        let session = session_allowing("fd5a:1f00:1::1");
        let before = RX_SOURCE_DENIED.load(Ordering::Relaxed);
        // Spoofed source: a neighbour ULA the peer is NOT allowed to use.
        let pkt = ipv6_packet_from("fd5a:1f00:1::2".parse().unwrap());
        assert!(!inner_source_allowed(&session, &pkt));
        assert!(
            RX_SOURCE_DENIED.load(Ordering::Relaxed) > before,
            "a denied packet must bump the metric"
        );
    }

    /// DROP: a non-IPv6 / truncated inner frame is rejected (we only
    /// carry IPv6 over the overlay) and also counts as a deny.
    #[test]
    fn rx_drops_non_ipv6_inner_frame() {
        let session = session_allowing("fd5a:1f00:1::1");
        let before = RX_SOURCE_DENIED.load(Ordering::Relaxed);
        assert!(!inner_source_allowed(&session, &[0u8; 4]));
        assert!(RX_SOURCE_DENIED.load(Ordering::Relaxed) > before);
    }

    /// Sanity bridge between the parser and the gate: a session that
    /// allows multiple `/128`s accepts each of them and rejects a
    /// fourth. Guards against an off-by-one in the allowed-set lookup.
    #[test]
    fn rx_gate_uses_full_allowed_set() {
        use x25519_dalek::{PublicKey, StaticSecret};
        let a: Ipv6Addr = "fd5a:1f00:1::1".parse().unwrap();
        let b: Ipv6Addr = "fd5a:1f00:1::2".parse().unwrap();
        let denied: Ipv6Addr = "fd5a:1f00:1::3".parse().unwrap();
        // Construct a session directly with a two-element allowed-set to
        // model the future multi-/128 case (policy-permitted extras).
        let session = Arc::new(PeerSession {
            peer_id: uuid::Uuid::nil(),
            ula: a,
            allowed_ips: HashSet::from([a, b]),
            endpoint: parking_lot::RwLock::new(None),
            tunn: tokio::sync::Mutex::new(boringtun::noise::Tunn::new(
                StaticSecret::from([1u8; 32]),
                PublicKey::from(&StaticSecret::from([2u8; 32])),
                None,
                None,
                7,
                None,
            )),
        });
        assert!(inner_source_allowed(&session, &ipv6_packet_from(a)));
        assert!(inner_source_allowed(&session, &ipv6_packet_from(b)));
        assert!(!inner_source_allowed(&session, &ipv6_packet_from(denied)));
    }
}
