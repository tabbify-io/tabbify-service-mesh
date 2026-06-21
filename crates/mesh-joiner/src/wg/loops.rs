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

/// Minimum spacing between unconfirmed direct PROBES to a single peer (see
/// `send_wire`). One probe per second is ample to win the direct-vs-relay
/// race on a genuinely reachable path (confirmation needs just one direct
/// DATA delivery), while capping the cost of a permanent black-hole
/// candidate at ~1 packet/s instead of a full-rate duplicate stream.
const DIRECT_PROBE_INTERVAL_MICROS: i64 = 1_000_000;

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
/// path:
///   * a CONFIRMED-direct UDP endpoint; else
///   * the relay floor (the delivery guarantee) — AND, while the path is
///     unconfirmed, ALSO a rate-limited direct PROBE at the candidate
///     endpoint so a genuinely reachable path can carry DATA and bootstrap
///     `confirm_direct` (see the relay branch); else
///   * when no relay is configured, a best-effort send to the unconfirmed
///     candidate endpoint (pre-relay behaviour); else drop.
///
/// This is the single TX chokepoint every WG send site routes through, so
/// the direct-vs-relay decision lives in exactly one place. A `Some`
/// endpoint on an UNCONFIRMED session is only a CANDIDATE: the relay floor
/// guarantees delivery even to a firewalled/NAT'd peer whose advertised
/// reflexive endpoint may be a black hole, while the parallel probe lets a
/// genuinely reachable candidate prove itself — a decrypted DATA packet over
/// the direct path flips `PeerSession::confirm_direct` and graduates the
/// session off the floor (the confirmed branch above then owns the path).
async fn send_wire(
    socket: &UdpSocket,
    relay: Option<&RelayHandle>,
    sessions: &SessionTable,
    session: &Arc<PeerSession>,
    bytes: Vec<u8>,
) {
    // Track K: stamp the send-attempt clock at the single TX chokepoint so
    // `dataplane_healthy` can tell an idle node (no TX) from a black hole (TX
    // happening, zero RX). Read-only w.r.t. routing — this never changes the
    // direct-vs-relay decision below.
    sessions.note_send_attempt(now_micros());
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
        // Direct-path PROBE before the relay floor: while the path is
        // UNCONFIRMED we still hold a CANDIDATE endpoint (roster-advertised or
        // learned). Send the SAME bytes direct too, so a real direct path
        // carries DATA and triggers `confirm_direct` on the peer (an inbound
        // direct `DeliverToTun`) — the only thing that lifts a pair off the
        // relay floor. The relay copy below guarantees delivery, so a
        // black-hole candidate never drops the frame; WG anti-replay dedups so
        // the inner packet reaches the app exactly once — whichever copy wins
        // the race (direct wins on a working LAN/punched path). Reaching here
        // with `Some(endpoint)` implies the path is NOT confirmed (the
        // confirmed branch returned above), so this never doubles a
        // steady-state confirmed flow.
        //
        // TWO guards keep the probe safe and cheap:
        //   * NOT relay_only — a relay_only local node declared no direct
        //     plane; probing would direct-dial peers the relay_only contract
        //     keeps off direct (the 2026-06-07 outage class). Suppressing it
        //     here also breaks the chain by construction: a relay_only node
        //     never probes, so its peers never `learn_endpoint` for it and
        //     never probe it back (the coordinator already advertises no
        //     endpoint for relay_only peers).
        //   * NOT in back-off — A-c hysteresis: a candidate that has failed N
        //     consecutive probe intervals is suppressed on an exponential,
        //     capped schedule (`direct_suppressed`), so a black-hole candidate
        //     costs ~1 probe per growing window instead of 1/s forever.
        //   * rate-limited per session — at most one probe per
        //     `DIRECT_PROBE_INTERVAL_MICROS`, so a permanent black-hole
        //     candidate costs ~1 pkt/s, not a full-rate duplicate stream.
        // Probe FIRST (borrow) so the relay enqueue below can MOVE `bytes`
        // without a clone.
        let now = now_micros();
        if !relay.relay_only()
            && !session.direct_suppressed(now)
            && let Some(endpoint) = session.endpoint()
            && session.should_probe_direct(now, DIRECT_PROBE_INTERVAL_MICROS)
        {
            tracing::debug!(peer = %session.peer_id, %endpoint, len = bytes.len(), "send_wire: direct probe (unconfirmed) + relay");
            if let Err(e) = socket.send_to(&bytes, endpoint).await {
                tracing::debug!(error = %e, %endpoint, "udp direct-probe send failed");
            }
            // The probe is our only failure signal without a separate ACK:
            // count this elapsed-interval-still-unconfirmed probe as one failed
            // direct handshake, advancing the back-off. A real direct DATA
            // delivery calls `note_direct_rx`/`confirm_direct`, which RESETS the
            // count — so a working path never accrues a penalty, while a
            // black-hole candidate backs off exponentially.
            session.note_handshake_failure(now);
        } else {
            tracing::debug!(peer = %session.peer_id, len = bytes.len(), "send_wire: relay");
        }
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
                            process_inbound_datagram(&socket, relay, true, &tun, &sessions, &session, datagram).await;
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
                            // Track K: the slow path inlines its own decap, so
                            // refresh the table-global liveness clock here too
                            // (the fast path does it inside
                            // `process_inbound_datagram`).
                            sessions.note_inbound_data_frame(now_micros());
                            // `via_direct = true`: slow path is still UDP.
                            apply_wg_action(&socket, relay, true, &tun, &sessions, &session, attempt).await;
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
                                apply_wg_action(&socket, relay, true, &tun, &sessions, &session, next).await;
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
    sessions: &SessionTable,
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
    // KEYSTONE (Track K): a valid WG decap over ANY path — direct UDP OR
    // relay — proves the data plane is alive. Refresh the TABLE-GLOBAL
    // liveness clock for both. Distinct from the per-session `note_direct_rx`
    // above (which is `via_direct`-gated because only a UDP datagram can prove
    // a DIRECT path): a relayed frame must NOT confirm a direct path, but it
    // DOES prove inbound data reaches us, so it refreshes the global
    // black-hole signal. Fixes the `via_direct=false` blind spot
    // (`relay/client.rs:391`).
    if !matches!(first, WgAction::Error(_)) {
        sessions.note_inbound_data_frame(now_micros());
    }
    apply_wg_action(socket, relay, via_direct, tun, sessions, session, first).await;

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
        apply_wg_action(socket, relay, via_direct, tun, sessions, session, next).await;
    }
}

async fn apply_wg_action(
    socket: &UdpSocket,
    relay: Option<&RelayHandle>,
    via_direct: bool,
    tun: &Arc<dyn TunDevice>,
    sessions: &SessionTable,
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
            send_wire(socket, relay, sessions, session, bytes).await;
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
                        encapsulate_and_send(&socket, sessions.relay(), &sessions, &session, packet).await;
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
    sessions: &SessionTable,
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
            send_wire(socket, relay, sessions, session, bytes).await;
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
                        send_wire(&socket, sessions.relay(), &sessions, &session, bytes).await;
                    }
                }
                // B-fix-1: active idle liveness probe. After the per-session
                // timer pass, if this node is AMBIGUOUSLY IDLE (peers present,
                // no send since the last inbound, RX aged past
                // IDLE_PROBE_AFTER_MICROS) emit ONE keepalive-sized frame so the
                // send clock advances. With the send clock now ahead of a stale
                // RX clock, the UNCHANGED `dataplane_healthy` verdict can detect
                // a genuine black hole within the 90s window — closing the
                // fail-open idle blind spot a trickle of relay control frames
                // exploited on 2026-06-21. Rate-limited to one frame /
                // IDLE_PROBE_INTERVAL_MICROS (no busy-loop).
                maybe_idle_probe(&socket, &sessions, now).await;
            }
        }
    }
}

/// Fire ONE active idle liveness probe when warranted (B-fix-1). GATED to a
/// `relay_only` LOCAL node (Leo's default): a non-`relay_only` node with a live
/// LAN/direct path keeps its RX clock fresh via WG keepalives, so it is never
/// ambiguously idle in this sense and must not pay the extra probe. A
/// `relay_only` node (the MSI black-hole case) rides the relay floor for every
/// frame, so a trickle of relayed control frames can mask a wedged data plane —
/// exactly what the probe forces into the open.
///
/// When [`SessionTable::should_emit_idle_probe`] claims the rate-limit slot,
/// pick an anchor peer ([`SessionTable::idle_probe_target`], prefers a
/// relay-anchored one), force a keepalive-sized frame out of its `Tunn`
/// (`encapsulate(&[], …)` — the same empty-encapsulate boringtun turns into a
/// keepalive / handshake-init), and route it through [`send_wire`]. `send_wire`
/// preserves the relay floor AND stamps `last_send_attempt_ts` — the whole
/// point of the probe. No-op (no claim, no frame) on a non-`relay_only` node, a
/// peerless node, a fresh-RX node, or an already-sending node.
async fn maybe_idle_probe(socket: &UdpSocket, sessions: &SessionTable, now: i64) {
    // Gate: only a relay_only local node probes (see fn doc). No relay handle
    // ⇒ direct-only / `--no-relay` ⇒ not the black-hole class this targets.
    let Some(relay) = sessions.relay() else {
        return;
    };
    if !relay.relay_only() {
        return;
    }
    if !sessions.should_emit_idle_probe(
        now,
        crate::wg::session::IDLE_PROBE_AFTER_MICROS,
        crate::wg::session::IDLE_PROBE_INTERVAL_MICROS,
    ) {
        return;
    }
    let Some(session) = sessions.idle_probe_target() else {
        return; // peerless (already gated, but stay defensive)
    };
    // Force a keepalive-sized frame: an empty-packet encapsulate yields a WG
    // keepalive (or a handshake-init if no session is up yet) — small, and the
    // exact shape the timer's own keepalives take.
    let action: WgAction = {
        let mut out = vec![0u8; MAX_UDP_FRAME];
        let mut tunn = session.tunn.lock().await;
        classify_tunn_result(tunn.encapsulate(&[], &mut out))
    };
    if let WgAction::SendToPeer(bytes) = action {
        tracing::debug!(
            peer = %session.peer_id,
            ula = %session.ula,
            "idle_probe: emitting keepalive to keep the liveness signal honest (B-fix-1)"
        );
        // Rides the relay floor (relay_only ⇒ no direct probe) and stamps
        // `last_send_attempt_ts`, advancing the send clock past a stale RX.
        send_wire(socket, sessions.relay(), sessions, &session, bytes).await;
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
            mesh_version: None,
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
            last_probe_micros: std::sync::atomic::AtomicI64::new(0),
            failed_handshake_count: std::sync::atomic::AtomicU32::new(0),
            direct_suppressed_until: std::sync::atomic::AtomicI64::new(0),
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
            mesh_version: None,
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
        let (relay, mut rx) = crate::relay::RelayHandle::new(false);
        let table = SessionTable::with_route_sink_and_relay(Arc::new(NoopSink), Some(relay));
        let session = upsert_peer(&table, "fd5a:1f00:1::1", None); // passive: no endpoint
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        // An inner IPv6 packet destined for the peer triggers a handshake.
        let packet = ipv6_packet_from("fd5a:1f00:1::9".parse().unwrap());

        encapsulate_and_send(&socket, table.relay(), &table, &session, &packet).await;

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

    /// THE direct-path bootstrap (this fix): a `Some` endpoint on an
    /// UNCONFIRMED session is a CANDIDATE. To let a real direct path carry
    /// DATA — the only signal that flips `confirm_direct` (an inbound direct
    /// `DeliverToTun`) — TX must send the frame over the candidate endpoint
    /// AS WELL AS the relay floor. The relay copy guarantees delivery (no
    /// black-hole for a firewalled/NAT'd peer); the direct copy probes the
    /// candidate. `WireGuard` anti-replay dedups so the inner packet reaches
    /// the app exactly once (whichever copy wins the race); on a working
    /// direct path (LAN / punched) the direct copy wins and a later DATA
    /// delivery confirms, on a black-hole candidate it is simply lost and the
    /// relay still delivers.
    ///
    /// Before this fix the relay floor sent ONLY to the relay and NEVER to
    /// the unconfirmed candidate (to avoid black-holing) — but that made
    /// `confirm_direct` (inbound direct DATA) UNREACHABLE whenever a relay
    /// was configured, since no DATA ever traversed the direct path: every
    /// pair stuck on the relay forever. This test FAILS on that code (the
    /// candidate receives nothing).
    #[tokio::test]
    async fn tx_double_sends_relay_and_direct_probe_while_unconfirmed() {
        let (relay, mut rx) = crate::relay::RelayHandle::new(false);
        // Bind a receiver socket as the candidate endpoint so the direct
        // probe lands somewhere observable.
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

        encapsulate_and_send(&sender, table.relay(), &table, &session, &packet).await;

        // (1) Floor preserved: the frame still goes over the RELAY so a
        // black-hole candidate never drops it.
        let out = tokio::time::timeout(Duration::from_millis(500), rx.recv())
            .await
            .expect("frame must still be relayed (the delivery floor)")
            .expect("relay channel delivered the frame");
        assert_eq!(
            out.dst_pubkey, session.peer_pubkey,
            "relay targets the peer pubkey"
        );
        assert!(
            !out.payload.is_empty(),
            "relayed payload is the WG handshake-init"
        );

        // (2) NEW: the SAME frame is ALSO probed direct at the candidate
        // endpoint — this is what lets a real direct path carry traffic and
        // bootstrap `confirm_direct`. Bounded so the OLD (relay-only)
        // behaviour fails as a clean timeout instead of hanging.
        let mut buf = vec![0u8; MAX_UDP_FRAME];
        let (n, _) = tokio::time::timeout(Duration::from_millis(500), receiver.recv_from(&mut buf))
            .await
            .expect("direct probe must reach the candidate endpoint")
            .expect("candidate socket received the probe");
        assert_eq!(
            &buf[..n],
            &out.payload[..],
            "direct probe carries the same bytes as the relay copy"
        );
    }

    /// The unconfirmed direct probe is RATE-LIMITED per session: two
    /// back-to-back sends relay BOTH frames but probe the candidate only
    /// ONCE (the second is within `DIRECT_PROBE_INTERVAL_MICROS`). This caps
    /// a permanent black-hole candidate at ~1 probe/interval instead of a
    /// full-rate duplicate stream.
    #[tokio::test]
    async fn unconfirmed_direct_probe_is_rate_limited() {
        let (relay, mut rx) = crate::relay::RelayHandle::new(false);
        let receiver = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let dst = receiver.local_addr().unwrap();
        let table = SessionTable::with_route_sink_and_relay(Arc::new(NoopSink), Some(relay));
        let session = upsert_peer(&table, "fd5a:1f00:1::1", Some(&dst.to_string()));
        let sender = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());

        // Two sends well within the 1s probe interval.
        send_wire(&sender, table.relay(), &table, &session, b"first".to_vec()).await;
        send_wire(&sender, table.relay(), &table, &session, b"second".to_vec()).await;

        // The relay floor carried BOTH frames.
        let a = tokio::time::timeout(Duration::from_millis(500), rx.recv())
            .await
            .expect("first frame relayed")
            .expect("relay channel");
        let b = tokio::time::timeout(Duration::from_millis(500), rx.recv())
            .await
            .expect("second frame relayed")
            .expect("relay channel");
        assert_eq!(a.payload, b"first");
        assert_eq!(b.payload, b"second");

        // The candidate received exactly ONE probe (the first); the second
        // send was within the interval and must NOT re-probe.
        let mut buf = vec![0u8; MAX_UDP_FRAME];
        let (n, _) = tokio::time::timeout(Duration::from_millis(500), receiver.recv_from(&mut buf))
            .await
            .expect("first probe reaches the candidate")
            .expect("candidate recv");
        assert_eq!(&buf[..n], b"first");
        let second =
            tokio::time::timeout(Duration::from_millis(200), receiver.recv_from(&mut buf)).await;
        assert!(
            second.is_err(),
            "a second send within the probe interval must not re-probe"
        );
    }

    /// A `relay_only` LOCAL node NEVER probes direct, even with a candidate
    /// endpoint: it declared no direct plane, and dialing direct re-creates
    /// the 2026-06-07 outage class (and would let peers learn its endpoint
    /// and probe it back). TX rides the relay only.
    #[tokio::test]
    async fn relay_only_node_never_probes_direct() {
        let (relay, mut rx) = crate::relay::RelayHandle::new(true); // relay_only
        let receiver = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let dst = receiver.local_addr().unwrap();
        let table = SessionTable::with_route_sink_and_relay(Arc::new(NoopSink), Some(relay));
        let session = upsert_peer(&table, "fd5a:1f00:1::1", Some(&dst.to_string()));
        assert!(
            !session.direct_confirmed(),
            "fresh session starts unconfirmed"
        );
        let sender = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());

        send_wire(&sender, table.relay(), &table, &session, b"x".to_vec()).await;

        // Relayed (the floor) ...
        let out = tokio::time::timeout(Duration::from_millis(500), rx.recv())
            .await
            .expect("frame relayed")
            .expect("relay channel");
        assert_eq!(out.payload, b"x");
        // ... but the candidate endpoint got NOTHING — a relay_only node
        // never dials direct.
        let mut buf = vec![0u8; MAX_UDP_FRAME];
        let probe =
            tokio::time::timeout(Duration::from_millis(200), receiver.recv_from(&mut buf)).await;
        assert!(
            probe.is_err(),
            "a relay_only node must not probe the candidate endpoint"
        );
    }

    /// A-c hysteresis: after enough un-answered probe intervals the candidate
    /// is SUPPRESSED — `send_wire` stops probing it (relay floor still carries
    /// every frame). This is the bounded-probe replacement for the 1/s
    /// forever-probe: a black-hole candidate costs ~1 probe per (growing)
    /// back-off window, not 1/s forever.
    #[tokio::test]
    async fn unconfirmed_probe_suppressed_after_repeated_failures() {
        let (relay, mut rx) = crate::relay::RelayHandle::new(false);
        let receiver = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let dst = receiver.local_addr().unwrap();
        let table = SessionTable::with_route_sink_and_relay(Arc::new(NoopSink), Some(relay));
        let session = upsert_peer(&table, "fd5a:1f00:1::1", Some(&dst.to_string()));
        let sender = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());

        // Drive the candidate into a deep back-off by directly recording
        // several failures (a fresh probe interval that never confirms). Stamp
        // each failure at "now" so the resulting back-off deadline is in the
        // future relative to the `now_micros()` the probe gate reads. Enough
        // failures saturate the window at the cap (5 min), comfortably past the
        // tiny gap between these calls and the gate's clock read.
        let base = now_micros();
        for _ in 0..12 {
            session.note_handshake_failure(base);
        }
        assert!(
            session.direct_suppressed(now_micros()),
            "after repeated failures the candidate is suppressed now"
        );

        // A send while suppressed must NOT probe the candidate (relay only).
        send_wire(&sender, table.relay(), &table, &session, b"x".to_vec()).await;
        let relayed = tokio::time::timeout(Duration::from_millis(500), rx.recv())
            .await
            .expect("frame still relayed (the floor)")
            .expect("relay channel");
        assert_eq!(relayed.payload, b"x");

        let mut buf = vec![0u8; MAX_UDP_FRAME];
        let probe =
            tokio::time::timeout(Duration::from_millis(200), receiver.recv_from(&mut buf)).await;
        assert!(
            probe.is_err(),
            "a suppressed candidate must not be probed while in back-off"
        );
    }

    /// A confirmed-direct delivery RESETS the back-off: even after failures, a
    /// real inbound datagram (`note_direct_rx`) clears suppression so the path
    /// is usable again. Guards against a working path being stuck suppressed.
    #[tokio::test]
    async fn confirmed_rx_clears_probe_suppression() {
        let session = {
            let table = SessionTable::new();
            upsert_peer(&table, "fd5a:1f00:1::1", Some("127.0.0.1:51820"))
        };
        for n in 1..=4 {
            session.note_handshake_failure(i64::from(n) * 1_000_000);
        }
        assert!(session.direct_suppressed(5_000_000));
        // A valid inbound datagram lands.
        session.note_direct_rx(6_000_000);
        assert!(
            !session.direct_suppressed(6_000_000),
            "a valid inbound rx must clear the probe suppression"
        );
        assert_eq!(session.failed_handshake_count(), 0);
    }

    /// Once the direct path is CONFIRMED (a decrypted data packet arrived
    /// over UDP → `confirm_direct`), TX goes over UDP to the endpoint and
    /// does NOT relay. This is the upgrade the Tailscale model performs
    /// after bidirectional direct connectivity is proven.
    #[tokio::test]
    async fn tx_direct_when_confirmed() {
        let (relay, mut rx) = crate::relay::RelayHandle::new(false);
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

        encapsulate_and_send(&sender, table.relay(), &table, &session, &packet).await;

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
            &table,
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
            &table,
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
            &table,
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
        encapsulate_and_send(&socket, table.relay(), &table, &session, &packet).await;
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
            mesh_version: None,
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
            mesh_version: None,
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

    // ---- Track K: data-plane liveness refresh ----

    /// Build a real WG datagram that `session`'s Tunn will decapsulate as a
    /// NON-error frame (a handshake-init from the matched peer Tunn). The peer
    /// Tunn is the mirror of the one `upsert_peer` built: our local static is
    /// `[9u8;32]` (so the peer's REMOTE pubkey is `PublicKey::from([9u8;32])`),
    /// and the peer's own static is `[3u8;32]` (matching the `wg_public_key`
    /// `upsert_peer` advertised). The init decapsulates without error and the
    /// liveness clock refreshes.
    fn make_valid_wg_datagram_for(_session: &Arc<PeerSession>) -> Vec<u8> {
        use boringtun::noise::{Tunn, TunnResult};
        use x25519_dalek::{PublicKey, StaticSecret};
        let peer_static = StaticSecret::from([3u8; 32]);
        let our_pub = PublicKey::from(&StaticSecret::from([9u8; 32]));
        let mut peer_tunn = Tunn::new(peer_static, our_pub, None, None, 99, None);
        let mut out = vec![0u8; MAX_UDP_FRAME];
        // An empty encapsulate triggers a handshake-init emission.
        match peer_tunn.encapsulate(&[], &mut out) {
            TunnResult::WriteToNetwork(b) => b.to_vec(),
            other => panic!("expected handshake-init, got {other:?}"),
        }
    }

    /// KEYSTONE (Track K): an inbound decap over the RELAY path
    /// (`via_direct = false`) MUST refresh the table-global
    /// `last_inbound_data_frame_ts` — fixing the `via_direct=false` blind spot
    /// (`relay/client.rs:391`) where relayed RX never touched any liveness
    /// clock. The session's DIRECT clock must NOT confirm (a relayed frame
    /// proves nothing about the direct path).
    #[tokio::test]
    async fn relay_decap_refreshes_table_liveness_not_direct() {
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let tun: Arc<dyn TunDevice> = Arc::new(NoopTun);
        let table = SessionTable::new();
        let session = upsert_peer(&table, "fd5a:1f00:1::1", Some("127.0.0.1:51820"));

        let datagram = make_valid_wg_datagram_for(&session);

        assert_eq!(table.last_inbound_data_frame_ts(), 0, "clock starts at 0");
        // via_direct = false → the RELAY path.
        process_inbound_datagram(&socket, None, false, &tun, &table, &session, &datagram).await;

        assert!(
            table.last_inbound_data_frame_ts() > 0,
            "a relay decap must refresh the table-global liveness clock"
        );
        assert!(
            !session.direct_confirmed(),
            "a relayed frame must NEVER confirm the direct path"
        );
    }

    /// A `send_wire` attempt stamps the table-global `last_send_attempt_ts`
    /// (the idle-gate for `dataplane_healthy`): before any send the clock is
    /// `0`; after a relayed send it is non-zero.
    #[tokio::test]
    async fn send_wire_stamps_send_attempt_clock() {
        let (relay, mut _rx) = crate::relay::RelayHandle::new(false);
        let table = SessionTable::with_route_sink_and_relay(Arc::new(NoopSink), Some(relay));
        let session = upsert_peer(&table, "fd5a:1f00:1::1", None); // passive → relay
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());

        assert_eq!(table.last_send_attempt_ts(), 0, "no send yet");
        send_wire(&socket, table.relay(), &table, &session, b"frame".to_vec()).await;
        assert!(
            table.last_send_attempt_ts() > 0,
            "send_wire must stamp the send-attempt clock"
        );
    }

    // ---- B-fix-1: active idle liveness probe (timer loop seam) ----

    use crate::wg::session::IDLE_PROBE_AFTER_MICROS;

    /// Build a `relay_only` (or not) table with one passive (relay-floored)
    /// peer that is driven into AMBIGUOUS IDLE: an inbound frame at `rx_at` and
    /// NO later send. Returns the table + a relay receiver to observe probes.
    fn ambiguously_idle_table(
        relay_only: bool,
        rx_at: i64,
    ) -> (SessionTable, crate::relay::client::RelayOutboundRx) {
        let (relay, rx) = crate::relay::RelayHandle::new(relay_only);
        let table = SessionTable::with_route_sink_and_relay(Arc::new(NoopSink), Some(relay));
        let _session = upsert_peer(&table, "fd5a:1f00:1::1", None); // passive → relay floor
        table.note_inbound_data_frame(rx_at);
        (table, rx)
    }

    /// THE fix, end to end at the timer seam: a `relay_only` node that is
    /// AMBIGUOUSLY IDLE (peers present, no send since the last inbound, RX aged
    /// past the window) emits ONE keepalive-sized frame over the relay when
    /// `maybe_idle_probe` runs — advancing `last_send_attempt_ts` so the
    /// black-hole verdict can act. The relayed payload is a real WG frame
    /// (non-empty), and the send clock is stamped.
    #[tokio::test]
    async fn relay_only_idle_node_emits_probe() {
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (table, mut rx) = ambiguously_idle_table(true, 10_000_000);
        let now = 10_000_000 + IDLE_PROBE_AFTER_MICROS + 1;
        assert_eq!(table.last_send_attempt_ts(), 0, "idle: no send yet");

        maybe_idle_probe(&socket, &table, now).await;

        let out = tokio::time::timeout(Duration::from_millis(500), rx.recv())
            .await
            .expect("an ambiguously-idle relay_only node must emit a probe")
            .expect("relay channel delivered the probe");
        assert!(!out.payload.is_empty(), "the probe is a real WG keepalive/init");
        assert!(
            table.last_send_attempt_ts() >= now,
            "the probe must advance the send clock (the whole point)"
        );
    }

    /// NON-`relay_only` node: the active idle probe is GATED OFF (Leo's
    /// default). A node with a live direct/LAN path keeps its RX clock fresh via
    /// WG keepalives, so it is never ambiguously idle in this sense and must not
    /// pay the extra probe. Even when driven into the same idle state, nothing
    /// is relayed and the send clock stays `0`.
    #[tokio::test]
    async fn non_relay_only_idle_node_does_not_probe() {
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (table, mut rx) = ambiguously_idle_table(false, 10_000_000);
        let now = 10_000_000 + IDLE_PROBE_AFTER_MICROS + 1;

        maybe_idle_probe(&socket, &table, now).await;

        assert!(
            tokio::time::timeout(Duration::from_millis(200), rx.recv())
                .await
                .is_err(),
            "a non-relay_only node must never emit the idle probe"
        );
        assert_eq!(
            table.last_send_attempt_ts(),
            0,
            "no probe ⇒ the send clock stays untouched"
        );
    }

    /// A `relay_only` node with GENUINELY FRESH RX (a real frame round-tripped
    /// within the window) must NOT probe — the data plane is provably alive.
    /// This is the "+RX-returns ⇒ no probe" direction at the seam.
    #[tokio::test]
    async fn relay_only_fresh_rx_node_does_not_probe() {
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (table, mut rx) = ambiguously_idle_table(true, 10_000_000);
        // Now is WITHIN the ambiguity window ⇒ RX is fresh ⇒ no probe.
        let now = 10_000_000 + IDLE_PROBE_AFTER_MICROS / 2;

        maybe_idle_probe(&socket, &table, now).await;

        assert!(
            tokio::time::timeout(Duration::from_millis(200), rx.recv())
                .await
                .is_err(),
            "fresh RX ⇒ no idle probe"
        );
    }

    /// No busy-loop at the seam: the 200ms timer pumps `maybe_idle_probe` many
    /// times in quick succession while the node stays idle, but it emits exactly
    /// ONE probe — the rate limiter (and the now-advanced send clock that ends
    /// the idle state) suppress every immediate follow-up. This pins the
    /// "bounded, no unbounded probe" contract. (The interval-elapsed re-arm of
    /// the pure rate limiter is covered by the table-level
    /// `should_emit_idle_probe_is_rate_limited`, which injects clocks instead of
    /// the real wall-clock `send_wire` stamps.)
    #[tokio::test]
    async fn idle_probe_no_busy_loop_at_seam() {
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (table, mut rx) = ambiguously_idle_table(true, 10_000_000);
        let now = 10_000_000 + IDLE_PROBE_AFTER_MICROS + 1;

        // Pump the seam like the 200ms timer would in a single idle stretch.
        for i in 0..10 {
            maybe_idle_probe(&socket, &table, now + i).await;
        }

        // Exactly ONE frame relayed across all those ticks.
        let first = tokio::time::timeout(Duration::from_millis(500), rx.recv())
            .await
            .expect("first probe relayed")
            .expect("relay channel");
        assert!(!first.payload.is_empty(), "the probe is a real WG frame");
        assert!(
            tokio::time::timeout(Duration::from_millis(200), rx.recv())
                .await
                .is_err(),
            "repeated idle ticks must not emit a second probe (no busy-loop)"
        );
    }

    /// A peerless `relay_only` node never probes (mirrors the no-peers fail-open
    /// in `dataplane_healthy`): with no sessions there is nothing to probe.
    #[tokio::test]
    async fn idle_probe_no_op_without_peers() {
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (relay, mut rx) = crate::relay::RelayHandle::new(true);
        let table = SessionTable::with_route_sink_and_relay(Arc::new(NoopSink), Some(relay));
        // No peers, but force the clocks so the only thing stopping a probe is
        // peers-present.
        table.note_inbound_data_frame(10_000_000);
        let now = 10_000_000 + IDLE_PROBE_AFTER_MICROS + 1;

        maybe_idle_probe(&socket, &table, now).await;

        assert!(
            tokio::time::timeout(Duration::from_millis(200), rx.recv())
                .await
                .is_err(),
            "a peerless node must not probe"
        );
    }
}
