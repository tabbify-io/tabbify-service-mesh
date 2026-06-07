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

use crate::relay::RelayHandle;
use crate::wg::session::{PeerSession, SessionTable, WgAction, classify_tunn_result};
use std::net::Ipv6Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
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

/// Current time as unix-micros. Used to stamp direct-path RX timestamps
/// and to drive the staleness downgrade. Saturates to `0` on the
/// impossible pre-epoch clock and to `i64::MAX` on the (year-294247)
/// overflow — both are inert for the staleness arithmetic.
///
/// `pub(crate)` so the connectivity-visibility path
/// ([`crate::joiner::Joiner::peer_paths`] + the heartbeat sender) stamps
/// per-peer ages against the SAME clock the data-plane confirm/downgrade
/// logic uses, rather than duplicating the helper.
pub(crate) fn now_micros() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_micros()).unwrap_or(i64::MAX))
}

/// Send already-encapsulated `WireGuard` bytes to `session` over the best
/// path: a CONFIRMED-direct UDP endpoint, else the relay (the connectivity
/// floor), else — when no relay is configured — a best-effort send to the
/// unconfirmed candidate endpoint (pre-relay behaviour), else drop.
///
/// This is the single TX chokepoint every WG send site routes through, so
/// the direct-vs-relay decision lives in exactly one place. A `Some`
/// endpoint on an UNCONFIRMED session is only a CANDIDATE: until a
/// decrypted data packet proves the direct path bidirectionally
/// (`PeerSession::confirm_direct`), traffic rides the relay so a
/// firewalled/NAT'd peer whose reflexive endpoint the coordinator
/// advertised is reachable rather than black-holed.
async fn send_wire(
    socket: &UdpSocket,
    relay: Option<&RelayHandle>,
    session: &Arc<PeerSession>,
    bytes: Vec<u8>,
) {
    if session.direct_confirmed() {
        if let Some(endpoint) = session.endpoint() {
            tracing::debug!(peer = %session.peer_id, %endpoint, len = bytes.len(), "send_wire: direct (confirmed)");
            if let Err(e) = socket.send_to(&bytes, endpoint).await {
                tracing::debug!(error = %e, %endpoint, "udp send failed");
            }
            return;
        }
    }
    if let Some(relay) = relay {
        tracing::debug!(peer = %session.peer_id, len = bytes.len(), "send_wire: relay");
        relay.try_relay(session.peer_pubkey, bytes);
        return;
    }
    if let Some(endpoint) = session.endpoint() {
        tracing::debug!(peer = %session.peer_id, %endpoint, "send_wire: direct (no relay configured)");
        if let Err(e) = socket.send_to(&bytes, endpoint).await {
            tracing::debug!(error = %e, %endpoint, "udp send failed");
        }
    } else {
        tracing::debug!(peer = %session.peer_id, "send_wire: drop (no direct path, no relay)");
    }
}

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
                        let relay = sessions.relay();
                        // Fast path: known endpoint → known session.
                        // `via_direct = true`: this arrived over the UDP
                        // socket, the only path that can prove a direct route.
                        if let Some(session) = sessions.by_endpoint(peer_addr) {
                            process_inbound_datagram(&socket, relay, true, &tun, &session, datagram).await;
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
                            // Re-peer observability: a datagram from a NOT-yet-known
                            // source addr just decapsulated cleanly under this
                            // session's Tunn — i.e. the peer authenticated from a
                            // new endpoint (NAT roam / re-peer / hole-punch crossing).
                            // This is the live data-plane moment a re-peering NAT'd
                            // peer (the ThinkPad) becomes reachable, so emit a
                            // structured `session_established` with the consistent
                            // (peer_id, ula, endpoint) fields the roster + handshake
                            // events use.
                            tracing::info!(
                                peer_id = %session.peer_id,
                                ula = %session.ula,
                                endpoint = %peer_addr,
                                event = "session_established",
                                "udp_recv: learned endpoint from successful decapsulate"
                            );
                            sessions.learn_endpoint(&session, peer_addr);
                            // A valid datagram just decapsulated over UDP →
                            // refresh the staleness clock (mirrors the
                            // fast-path `note_direct_rx`). This alone does
                            // NOT confirm; a direct DeliverToTun does.
                            session.note_direct_rx(now_micros());
                            // `via_direct = true`: slow path is still UDP.
                            apply_wg_action(&socket, relay, true, &tun, &session, attempt).await;
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
                                apply_wg_action(&socket, relay, true, &tun, &session, next).await;
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
///
/// `via_direct` is `true` when this datagram arrived over the UDP socket
/// (the only path that can prove a direct route) and `false` when it was
/// injected by the relay client — a relayed packet must NEVER confirm or
/// refresh a DIRECT path.
pub(crate) async fn process_inbound_datagram(
    socket: &UdpSocket,
    relay: Option<&RelayHandle>,
    via_direct: bool,
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
    // Per-datagram decap outcome, DEBUG-gated. The single most valuable
    // data-plane signal when chasing "frames arrive but nothing reaches
    // the app": a silent `Nothing` (no matching session index) is
    // otherwise indistinguishable from a delivered packet. It exposed
    // both 2026-06-04 root causes (host firewall + return-path routing)
    // by proving decryption worked — the blocker had to be downstream.
    // Free unless `tabbify_mesh_joiner=debug` is enabled.
    tracing::debug!(
        peer = %session.peer_id,
        in_len = datagram.len(),
        action = first.name(),
        via_direct,
        "rx_decap"
    );
    // A valid WG packet (anything that isn't an error — handshake or data,
    // incl. keepalives) arrived over UDP: refresh the staleness clock so a
    // confirmed-but-idle path doesn't age out. This does NOT confirm; only
    // a direct DeliverToTun (real data) does that, below in apply_wg_action.
    if via_direct && !matches!(first, WgAction::Error(_)) {
        session.note_direct_rx(now_micros());
    }
    apply_wg_action(socket, relay, via_direct, tun, session, first).await;

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
        apply_wg_action(socket, relay, via_direct, tun, session, next).await;
    }
}

async fn apply_wg_action(
    socket: &UdpSocket,
    relay: Option<&RelayHandle>,
    via_direct: bool,
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
            // A handshake init/response — route it through the single TX
            // chokepoint. It must NEVER confirm a direct path: a lone
            // handshake can cross directly even when the return path is
            // blocked, so it stays on the relay floor until DATA proves
            // both directions.
            send_wire(socket, relay, session, bytes).await;
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
            // THE upgrade signal: a real DATA packet was delivered over a
            // DIRECT (non-relayed) UDP path. The sender only emits data
            // after ITS handshake completed — which required our response
            // to reach it — so a direct data packet proves the path works
            // BIDIRECTIONALLY. Confirm so future TX leaves the relay floor.
            if via_direct {
                session.confirm_direct(now_micros());
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
                        encapsulate_and_send(&socket, sessions.relay(), &session, packet).await;
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
    relay: Option<&RelayHandle>,
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
            // Route through the single TX chokepoint: confirmed-direct →
            // UDP, else relay floor, else (no relay) best-effort candidate
            // endpoint, else drop.
            send_wire(socket, relay, session, bytes).await;
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
                let now = now_micros();
                for session in sessions.snapshot() {
                    // Downgrade a confirmed-direct path that has gone silent
                    // past the TTL (NAT rebind / path death) back to the
                    // relay floor — independent of whether the timer emits
                    // anything to send this tick.
                    session.downgrade_direct_if_stale(
                        now,
                        crate::wg::session::peer_session::DIRECT_PATH_TTL_MICROS,
                    );
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
                        // Timer-driven WG output (rekey / keepalive) rides
                        // the same chokepoint: confirmed-direct → UDP, else
                        // relay floor, else best-effort candidate, else drop.
                        send_wire(&socket, sessions.relay(), &session, bytes).await;
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
            hosted_app_ulas: vec![],
            software_version: None,
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
            peer_pubkey: [0u8; 32],
            allowed_ips: parking_lot::RwLock::new(HashSet::from([a, b])),
            endpoint: parking_lot::RwLock::new(None),
            direct_confirmed: std::sync::atomic::AtomicBool::new(false),
            last_direct_rx_micros: std::sync::atomic::AtomicI64::new(0),
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

    // ---- Stage 3: relay the TX drops ----

    /// No-op route sink so a relay-carrying table can be built in tests
    /// without shelling out to `route` / `ifconfig`.
    struct NoopSink;
    impl crate::wg::session::RouteSink for NoopSink {
        fn add_allowed(&self, _ula: Ipv6Addr) {}
        fn remove_allowed(&self, _ula: Ipv6Addr) {}
        fn add_app_route(&self, _app_ula: Ipv6Addr) {}
        fn remove_app_route(&self, _app_ula: Ipv6Addr) {}
    }

    /// Build a `PeerInfo` for a peer with a known pubkey and the given
    /// endpoint, then upsert it into `table` and return its session.
    fn upsert_peer(table: &SessionTable, ula: &str, endpoint: Option<&str>) -> Arc<PeerSession> {
        use x25519_dalek::{PublicKey, StaticSecret};
        let me = StaticSecret::from([9u8; 32]);
        let info = crate::peer::PeerInfo {
            peer_id: uuid::Uuid::nil(),
            wg_public_key: *PublicKey::from(&StaticSecret::from([3u8; 32])).as_bytes(),
            ula: ula.parse().unwrap(),
            listen_endpoint: endpoint.map(|s| s.parse().unwrap()),
            display_name: "peer".into(),
            tags: vec![],
            hosted_app_ulas: vec![],
            software_version: None,
            joined_at_micros: 0,
        };
        table.upsert(&me, &info);
        table.by_ula(ula.parse().unwrap()).unwrap()
    }

    /// When a session has NO direct endpoint and the table carries a relay
    /// handle, `encapsulate_and_send` relays the (encrypted) datagram
    /// instead of dropping it. The relayed payload targets the peer's
    /// pubkey and is non-empty (a WG handshake-init).
    #[tokio::test]
    async fn encapsulate_relays_when_no_endpoint() {
        let (relay, mut rx) = crate::relay::RelayHandle::new();
        let table = SessionTable::with_route_sink_and_relay(Arc::new(NoopSink), Some(relay));
        let session = upsert_peer(&table, "fd5a:1f00:1::1", None); // passive: no endpoint
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        // An inner IPv6 packet destined for the peer triggers a handshake.
        let packet = ipv6_packet_from("fd5a:1f00:1::9".parse().unwrap());

        encapsulate_and_send(&socket, table.relay(), &session, &packet).await;

        let out = rx.recv().await.expect("packet relayed when no endpoint");
        assert_eq!(
            out.dst_pubkey, session.peer_pubkey,
            "relay targets the peer pubkey"
        );
        assert!(
            !out.payload.is_empty(),
            "relayed payload is the WG handshake-init"
        );
    }

    /// REGRESSION (this fix): a `Some` endpoint is only a CANDIDATE, not a
    /// confirmed direct path. With a relay handle present and the session
    /// NOT yet `direct_confirmed`, TX must go over the RELAY — the
    /// connectivity floor — NOT to the unconfirmed candidate endpoint. The
    /// old code sent straight to the candidate endpoint (a black hole for a
    /// firewalled/NAT'd peer whose reflexive endpoint the coordinator
    /// advertised) and never relayed. This test FAILS on the old code.
    #[tokio::test]
    async fn tx_relays_when_endpoint_known_but_unconfirmed() {
        let (relay, mut rx) = crate::relay::RelayHandle::new();
        // Bind a receiver socket so a (wrongly) direct send WOULD land here —
        // letting the test distinguish "relayed" from "sent direct".
        let receiver = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let dst = receiver.local_addr().unwrap();
        let table = SessionTable::with_route_sink_and_relay(Arc::new(NoopSink), Some(relay));
        // Endpoint KNOWN (a candidate) but the direct path is unconfirmed.
        let session = upsert_peer(&table, "fd5a:1f00:1::1", Some(&dst.to_string()));
        assert!(
            !session.direct_confirmed(),
            "a fresh session starts unconfirmed"
        );
        let sender = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let packet = ipv6_packet_from("fd5a:1f00:1::9".parse().unwrap());

        encapsulate_and_send(&sender, table.relay(), &session, &packet).await;

        // The frame went over the RELAY, not the candidate UDP endpoint.
        // Bounded so the OLD (buggy) behaviour — which sends direct and
        // never relays — fails as a clean assertion instead of hanging on
        // an unbounded `recv`.
        let out = tokio::time::timeout(Duration::from_millis(500), rx.recv())
            .await
            .expect("frame must be relayed (not sent direct) while direct is unconfirmed")
            .expect("relay channel delivered the frame");
        assert_eq!(
            out.dst_pubkey, session.peer_pubkey,
            "relay targets the peer pubkey"
        );
        assert!(
            !out.payload.is_empty(),
            "relayed payload is the WG handshake-init"
        );
        let mut buf = vec![0u8; MAX_UDP_FRAME];
        let recv =
            tokio::time::timeout(Duration::from_millis(200), receiver.recv_from(&mut buf)).await;
        assert!(
            recv.is_err(),
            "nothing sent to the unconfirmed candidate endpoint"
        );
    }

    /// Once the direct path is CONFIRMED (a decrypted data packet arrived
    /// over UDP → `confirm_direct`), TX goes over UDP to the endpoint and
    /// does NOT relay. This is the upgrade the Tailscale model performs
    /// after bidirectional direct connectivity is proven.
    #[tokio::test]
    async fn tx_direct_when_confirmed() {
        let (relay, mut rx) = crate::relay::RelayHandle::new();
        // Bind a receiver socket so the UDP send has a live destination.
        let receiver = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let dst = receiver.local_addr().unwrap();
        let table = SessionTable::with_route_sink_and_relay(Arc::new(NoopSink), Some(relay));
        let session = upsert_peer(&table, "fd5a:1f00:1::1", Some(&dst.to_string()));
        // Prove the direct path (the only signal that flips the floor off).
        session.confirm_direct(now_micros());
        assert!(session.direct_confirmed());
        let sender = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let packet = ipv6_packet_from("fd5a:1f00:1::9".parse().unwrap());

        encapsulate_and_send(&sender, table.relay(), &session, &packet).await;

        // The datagram went to UDP, not the relay.
        let mut buf = vec![0u8; MAX_UDP_FRAME];
        let recv =
            tokio::time::timeout(Duration::from_millis(500), receiver.recv_from(&mut buf)).await;
        assert!(
            recv.is_ok(),
            "handshake-init delivered over UDP to the confirmed endpoint"
        );
        assert!(
            rx.try_recv().is_err(),
            "nothing relayed once the direct path is confirmed"
        );
    }

    /// A TUN device that swallows every write — lets the `DeliverToTun` path
    /// run end-to-end without a real interface.
    struct NoopTun;
    #[async_trait::async_trait]
    impl tabbify_mesh_fabric::tun::TunDevice for NoopTun {
        fn name(&self) -> &'static str {
            "noop-tun"
        }
        async fn read_packet(&self, _buf: &mut [u8]) -> std::io::Result<usize> {
            std::future::pending().await
        }
        async fn write_packet(&self, buf: &[u8]) -> std::io::Result<usize> {
            Ok(buf.len())
        }
    }

    /// Confirmation gate: a `DeliverToTun` of REAL data over a DIRECT path
    /// (`via_direct = true`) confirms the direct route (bidirectional proof
    /// — the sender only emits data after its handshake, which needed our
    /// response). The SAME delivery over the RELAY (`via_direct = false`)
    /// must NOT confirm — a relayed packet proves nothing about the direct
    /// path. A `SendToPeer` (handshake) must never confirm either.
    #[tokio::test]
    async fn deliver_to_tun_confirms_only_when_direct() {
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let tun: Arc<dyn TunDevice> = Arc::new(NoopTun);
        let table = SessionTable::new();
        // Allowed-source set is exactly the peer's own ULA, so an inner
        // packet sourced from it passes the §5.5 gate and reaches the
        // confirm branch.
        let ula = "fd5a:1f00:1::1";
        let session = upsert_peer(&table, ula, Some("127.0.0.1:51820"));
        let inner = ipv6_packet_from(ula.parse().unwrap());

        // Relayed data (via_direct = false): delivered to TUN but NOT
        // confirmed — the relay proves nothing about the direct path.
        apply_wg_action(
            &socket,
            None,
            false,
            &tun,
            &session,
            WgAction::DeliverToTun(inner.clone()),
        )
        .await;
        assert!(
            !session.direct_confirmed(),
            "a relayed data delivery must NOT confirm a direct path"
        );

        // A handshake (SendToPeer) over the direct flag must NOT confirm.
        apply_wg_action(
            &socket,
            None,
            true,
            &tun,
            &session,
            WgAction::SendToPeer(vec![1, 2, 3]),
        )
        .await;
        assert!(
            !session.direct_confirmed(),
            "a handshake (SendToPeer) must NEVER confirm a direct path"
        );

        // Direct data (via_direct = true): THE upgrade signal.
        apply_wg_action(
            &socket,
            None,
            true,
            &tun,
            &session,
            WgAction::DeliverToTun(inner),
        )
        .await;
        assert!(
            session.direct_confirmed(),
            "a direct data delivery confirms the direct path"
        );
    }

    /// With NO relay handle, a no-endpoint session keeps the pre-relay
    /// silent-drop behaviour — `encapsulate_and_send` is a no-op that does
    /// not panic.
    #[tokio::test]
    async fn encapsulate_drops_when_no_endpoint_and_no_relay() {
        let table = SessionTable::new();
        let session = upsert_peer(&table, "fd5a:1f00:1::1", None);
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let packet = ipv6_packet_from("fd5a:1f00:1::9".parse().unwrap());
        // No relay handle (table.relay() == None) → drop, must not panic.
        encapsulate_and_send(&socket, table.relay(), &session, &packet).await;
    }

    // ---- per-app-ULA routing: TX lookup + RX source check ----

    /// The TX path's `by_ula(dst)` lookup (used by `tun_read_loop`)
    /// resolves a packet destined for an APP-ULA to the hosting peer's
    /// session via the `app_routes` fallback. This is the lookup the loop
    /// performs at loops.rs ~`tun_read_loop`; assert it directly so the
    /// data path is pinned without spinning real sockets.
    #[test]
    fn tun_read_lookup_resolves_app_ula_to_host_session() {
        use x25519_dalek::StaticSecret;
        let host: Ipv6Addr = "fd5a:1f00:1::1".parse().unwrap();
        let app: Ipv6Addr = "fd5a:1f02:dead:beef:cafe:0:0:1".parse().unwrap();
        let me = StaticSecret::from([42u8; 32]);
        let info = crate::peer::PeerInfo {
            peer_id: uuid::Uuid::nil(),
            wg_public_key: *x25519_dalek::PublicKey::from(&StaticSecret::from([3u8; 32]))
                .as_bytes(),
            ula: host,
            listen_endpoint: Some("127.0.0.1:51820".parse().unwrap()),
            display_name: "host".into(),
            tags: vec![],
            hosted_app_ulas: vec![app],
            software_version: None,
            joined_at_micros: 0,
        };
        let t = SessionTable::new();
        t.upsert(&me, &info);
        t.reconcile_app_routes(host, &[app]);
        // The dst the loop extracts (app-ULA) resolves to the host session.
        let session = t.by_ula(app).expect("app-ULA dst resolves for tun_read");
        assert_eq!(session.ula, host);
    }

    /// RX source check: a RESPONSE inner packet whose SOURCE is the
    /// app-ULA passes once the app-ULA is in the host session's
    /// allowed-set (the reverse direction of per-app-ULA routing). Before
    /// hosting it would be dropped; after, it is accepted.
    #[test]
    fn rx_accepts_response_sourced_from_hosted_app_ula() {
        use x25519_dalek::StaticSecret;
        let host: Ipv6Addr = "fd5a:1f00:1::1".parse().unwrap();
        let app: Ipv6Addr = "fd5a:1f02:dead:beef:cafe:0:0:1".parse().unwrap();
        let me = StaticSecret::from([42u8; 32]);
        let info = crate::peer::PeerInfo {
            peer_id: uuid::Uuid::nil(),
            wg_public_key: *x25519_dalek::PublicKey::from(&StaticSecret::from([3u8; 32]))
                .as_bytes(),
            ula: host,
            listen_endpoint: Some("127.0.0.1:51820".parse().unwrap()),
            display_name: "host".into(),
            tags: vec![],
            hosted_app_ulas: vec![],
            software_version: None,
            joined_at_micros: 0,
        };
        let t = SessionTable::new();
        t.upsert(&me, &info);
        let session = t.by_ula(host).expect("session");
        // Before hosting the app, a response sourced from it is rejected.
        assert!(!inner_source_allowed(&session, &ipv6_packet_from(app)));
        // After hosting, the same response passes.
        t.reconcile_app_routes(host, &[app]);
        assert!(inner_source_allowed(&session, &ipv6_packet_from(app)));
    }
}
