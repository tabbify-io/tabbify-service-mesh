//! Relay client: the cheap-clone handle the WG TX seams use to relay a
//! packet, plus (in [`run`]) the persistent WebSocket task that connects
//! to the coordinator's `/v1/mesh/relay` endpoint, drains queued
//! outbound datagrams, and injects relayed inbound datagrams back into
//! boringtun.

use crate::relay::frame::{decode_relay_frame, encode_relay_frame};
use crate::wg::loops::process_inbound_datagram;
use crate::wg::session::SessionTable;
use base64::Engine as _;
// base64url (no padding) for the `?pubkey=` query: standard base64's `+` and
// `/` are unsafe in a URL — `+` decodes to a space in a query string — so the
// coordinator's `Query` extractor would receive a mangled key and reject it.
// base64url uses only `-_` plus alphanumerics, safe to drop straight into a URL.
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use futures_util::{SinkExt, StreamExt};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};
use tokio_tungstenite::tungstenite::Message;

/// One outbound relayed datagram: where to send + the already-WG-encrypted
/// bytes.
pub struct RelayOutbound {
    /// Destination peer's raw 32-byte X25519 WG public key.
    pub dst_pubkey: [u8; 32],
    /// Opaque, already-encrypted WG transport datagram.
    pub payload: Vec<u8>,
}

/// Wire value of `?lane=hi` — the handshake/cookie socket. MUST stay
/// byte-identical to the coordinator's copy (`mesh-coordinator`
/// `http::relay::LANE_HI`); a mismatch silently routes every handshake to the
/// coordinator's legacy `lo` fallback, reviving the `REKEY_TIMEOUT` bug with
/// NO error surfaced. Same independent-copy rule as the relay frame codec.
pub const LANE_HI: &str = "hi";
/// Wire value of `?lane=lo` — the bulk transport-data socket. See [`LANE_HI`].
pub const LANE_LO: &str = "lo";

/// Which of a peer's two dedicated relay sockets a client task drives. Each
/// joiner runs ONE [`run`] task per lane: a [`RelayLane::Hi`] socket carrying
/// ONLY WG handshake/cookie frames and a [`RelayLane::Lo`] socket carrying ONLY
/// bulk transport data. The sockets are physically separate WS/TCP
/// connections, so a saturated bulk transfer on `Lo` (which bufferbloats its
/// kernel send buffer to ~10 s) cannot delay a rekey handshake on the
/// near-empty `Hi` socket.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RelayLane {
    /// Handshake/cookie — the near-empty, never-bloated socket.
    Hi,
    /// Bulk transport data — may bloat, but only ITS own socket.
    Lo,
}

impl RelayLane {
    /// The `?lane=` query value this lane connects with.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Hi => LANE_HI,
            Self::Lo => LANE_LO,
        }
    }
}

/// The producer-side lane split: [`RelayHandle::try_relay`] classifies each
/// frame by WG type and pushes it onto `hi` (handshake/cookie) or `lo` (bulk
/// data). Each receiver feeds a SEPARATE relay client task on its OWN WS
/// socket ([`RelayLane`]), so a saturated bulk transfer on `lo`'s socket
/// cannot bufferbloat `hi`'s — the cause of `REKEY_TIMEOUT` that killed long
/// transfers at the ~2-min rekey. The caller (`joiner.rs`) destructures this
/// into the two single-lane [`RelayTask`]s.
pub struct RelayOutboundRx {
    /// High-priority receiver — drained by the `hi` socket's task.
    pub hi: mpsc::UnboundedReceiver<RelayOutbound>,
    /// Low-priority receiver — drained by the `lo` socket's task.
    pub lo: mpsc::UnboundedReceiver<RelayOutbound>,
}

#[cfg(test)]
impl RelayOutboundRx {
    /// Test helper: receive from either lane, preferring `hi` — mirrors the
    /// production biased drain. Lets tests that only assert THAT a frame was
    /// queued for relay (not which lane) stay agnostic to the priority split.
    pub(crate) async fn recv(&mut self) -> Option<RelayOutbound> {
        tokio::select! {
            biased;
            v = self.hi.recv() => v,
            v = self.lo.recv() => v,
        }
    }

    /// Test helper: non-blocking receive from either lane (`hi` first).
    /// `Err` only when BOTH lanes are empty/closed.
    pub(crate) fn try_recv(&mut self) -> Result<RelayOutbound, mpsc::error::TryRecvError> {
        match self.hi.try_recv() {
            Ok(v) => Ok(v),
            Err(_) => self.lo.try_recv(),
        }
    }
}

/// Cheap-clone handle the WG TX seams use to relay a packet when no direct
/// endpoint is known.
///
/// Backed by an unbounded channel drained by the relay client task.
/// [`Self::try_relay`] never blocks and never fails loudly — if the relay
/// task is gone the packet is dropped (the same outcome as the pre-relay
/// silent drop).
#[derive(Clone)]
pub struct RelayHandle {
    /// HIGH-priority lane: WG handshake/cookie frames (drained before `tx_lo`).
    tx_hi: mpsc::UnboundedSender<RelayOutbound>,
    /// LOW-priority lane: bulk transport-data frames.
    tx_lo: mpsc::UnboundedSender<RelayOutbound>,
    /// `true` when the LOCAL node joined `relay_only` — it declared it has no
    /// usable direct path, so its TX must NEVER attempt a direct probe in
    /// `send_wire`; every frame rides the relay. Direct-dialing from a
    /// `relay_only` node re-creates the class of the 2026-06-07 outage
    /// (dialing peers the `relay_only` contract deliberately keeps off the
    /// direct plane). Carried on the handle because it IS the relay-vs-direct policy
    /// context the single TX chokepoint already holds — no extra plumbing
    /// through every send site.
    relay_only: bool,
}

impl RelayHandle {
    /// Create a handle paired with the receiver the relay task drains.
    /// `relay_only` is the LOCAL node's policy (see the field doc).
    pub(crate) fn new(relay_only: bool) -> (Self, RelayOutboundRx) {
        let (tx_hi, hi) = mpsc::unbounded_channel();
        let (tx_lo, lo) = mpsc::unbounded_channel();
        (
            Self {
                tx_hi,
                tx_lo,
                relay_only,
            },
            RelayOutboundRx { hi, lo },
        )
    }

    /// `true` when the local node is `relay_only` (see the field doc). The TX
    /// chokepoint (`send_wire`) consults this to suppress the unconfirmed
    /// direct probe.
    #[must_use]
    pub(crate) const fn relay_only(&self) -> bool {
        self.relay_only
    }

    /// Queue an already-encrypted WG datagram for relay to `dst_pubkey`.
    /// Best-effort: a send to a closed channel (relay task gone) is
    /// silently dropped.
    pub fn try_relay(&self, dst_pubkey: [u8; 32], payload: Vec<u8>) {
        // WG message type = cleartext first byte: 1=init, 2=resp, 3=cookie → the
        // HIGH lane; 4=transport data → the LOW lane. Prioritising handshakes
        // lets a peer's rekey complete even while this node saturates the relay
        // with bulk data (the cause of REKEY_TIMEOUT that killed long transfers).
        let hi = payload.first().is_some_and(|&t| matches!(t, 1..=3));
        let ch = if hi { &self.tx_hi } else { &self.tx_lo };
        let _ = ch.send(RelayOutbound { dst_pubkey, payload });
    }
}

/// Inputs for the persistent relay client task.
pub struct RelayTask {
    /// Coordinator base URL (used to derive the relay URL when `relay_urls`
    /// is empty).
    pub coordinator_url: String,
    /// HA-relay: the ORDERED, resolved relay endpoint set (primary first) this
    /// task fails over across. Shared (cheap-clone `Arc`) by both lanes so a
    /// fleet-wide list is identical on `hi` and `lo`. Empty ⇒ the single relay
    /// is derived from `coordinator_url` at [`run`] time. A one-element list is
    /// byte-identical to the legacy single-relay behaviour — the failover
    /// branch is unreachable (`(0 + 1) % 1 == 0`).
    pub relay_urls: Arc<Vec<String>>,
    /// Our raw 32-byte X25519 WG public key — sent as the `?pubkey=` query
    /// parameter so the coordinator registers this connection.
    pub my_pubkey: [u8; 32],
    /// `true` when running against a plaintext (`--insecure-no-mtls`)
    /// coordinator. `false` (secure/mTLS) is not yet implemented; the task
    /// logs a warning and returns (relay disabled; direct + hole-punch
    /// still work).
    pub insecure_no_mtls: bool,
    /// Shared session table — used to demux inbound relay frames by source
    /// pubkey and to inject responses back over the relay.
    pub sessions: SessionTable,
    /// WG UDP socket — handed to [`process_inbound_datagram`] so relayed RX
    /// is processed identically to UDP RX.
    pub socket: Arc<UdpSocket>,
    /// TUN device — where decapsulated inner packets are delivered.
    pub tun: Arc<dyn tabbify_mesh_fabric::tun::TunDevice>,
    /// This task's lane — selects the `?lane=` query value and which half of
    /// the [`RelayOutboundRx`] split it drains. The joiner spawns one task per
    /// lane.
    pub lane: RelayLane,
    /// Receiver of the THIS-lane outbound datagrams the WG TX seams queued
    /// (the `hi` or `lo` half of a [`RelayOutboundRx`]).
    pub outbound_rx: mpsc::UnboundedReceiver<RelayOutbound>,
    /// Shutdown signal — the task exits when this flips to `true`.
    pub shutdown: watch::Receiver<bool>,
}

/// Derive the relay WebSocket URL.
///
/// When `relay_url` is `Some` it is used verbatim. Otherwise the URL is
/// derived from `coordinator_url` by swapping the scheme to `ws`/`wss` and
/// appending the relay path. `http`/`https` map to `ws`/`wss`; a URL that
/// is already `ws`/`wss` is preserved; anything else defaults to `ws`.
#[must_use]
pub fn derive_relay_url(coordinator_url: &str, relay_url: Option<&str>) -> String {
    if let Some(url) = relay_url {
        return url.to_owned();
    }
    let trimmed = coordinator_url.trim_end_matches('/');
    let (scheme, rest) = trimmed.split_once("://").map_or(("ws", trimmed), |(s, r)| {
        let ws_scheme = match s {
            "https" | "wss" => "wss",
            _ => "ws",
        };
        (ws_scheme, r)
    });
    format!("{scheme}://{rest}/v1/mesh/relay")
}

/// Resolve the ORDERED relay endpoint set the connectivity floor fails over
/// across (HA-relay C2). This replaces the single-value [`derive_relay_url`] at
/// the wiring layer while preserving its exact semantics for the single-relay
/// case.
///
/// - `configured` EMPTY ⇒ `vec![derive_relay_url(coordinator_url, None)]` — the
///   legacy single-relay derivation, byte-identical to today.
/// - `configured` NON-EMPTY ⇒ each entry verbatim (the "explicit overrides
///   derivation" rule, applied per-entry), de-duplicated while preserving
///   first-seen order so an accidental double-listing cannot conjure a phantom
///   2nd relay (which would falsely arm the failover branch over one endpoint).
///
/// The result is ALWAYS non-empty (a derived single when nothing is
/// configured), so the relay floor always has at least one URL to dial. A
/// one-element result keeps the failover machine's index pinned at 0
/// (`(0 + 1) % 1 == 0`) — the no-op invariant.
#[must_use]
pub fn resolve_relay_urls(coordinator_url: &str, configured: &[String]) -> Vec<String> {
    if configured.is_empty() {
        return vec![derive_relay_url(coordinator_url, None)];
    }
    let mut out: Vec<String> = Vec::with_capacity(configured.len());
    for url in configured {
        if !out.iter().any(|seen| seen == url) {
            out.push(url.clone());
        }
    }
    out
}

/// Persistent relay client task: connect to the coordinator's relay
/// endpoint, drain queued outbound datagrams onto the socket, and inject
/// inbound relayed datagrams back into boringtun. Reconnects with a
/// `[1, 2, 5, 10]` s backoff (mirrors `peer_sync::run`); honors `shutdown`.
pub async fn run(mut task: RelayTask) {
    // Transport TLS (`wss://`) IS supported (tokio-tungstenite rustls feature),
    // so the relay traverses TLS-terminating proxies on :443. CLIENT mTLS for the
    // relay, however, is still unimplemented — so under secure mode (mTLS
    // required) log once and return; direct + hole-punch still provide
    // connectivity. In insecure mode the relay connects over ws:// OR wss://
    // (server-cert-validated, no client cert).
    if !task.insecure_no_mtls {
        tracing::warn!(
            "relay: client mTLS not implemented — relay disabled under secure mode (direct + hole-punch still active)"
        );
        return;
    }

    // Resolve the ordered relay set (HA-relay C4). An EMPTY `relay_urls`
    // derives the single Frankfurt relay from `coordinator_url`; ALWAYS
    // non-empty after resolution, so `relays[current]` never panics.
    let relays = resolve_relay_urls(&task.coordinator_url, &task.relay_urls);
    let pubkey_q = B64URL.encode(task.my_pubkey);

    let backoff = [1u64, 2, 5, 10];
    // `current` indexes the ordered relay list; `attempt` is the per-current
    // backoff cursor (monotonic on the SAME relay, reset only when failover
    // actually advances to a DIFFERENT relay).
    let mut current: usize = 0;
    let mut attempt: usize = 0;

    loop {
        if *task.shutdown.borrow() {
            return;
        }
        // Build the URL for the CURRENT relay. `&lane=` tags which dedicated
        // socket this is so the coordinator registers it on the matching lane
        // (handshakes on `hi`, bulk on `lo`).
        let url = format!(
            "{base}?pubkey={pubkey_q}&lane={lane}",
            base = relays[current],
            lane = task.lane.as_str(),
        );
        match connect_once(&url, &mut task).await {
            ConnOutcome::ShutdownRequested => return,
            ConnOutcome::Disconnected(reason) => {
                let delay = backoff[attempt.min(backoff.len() - 1)];
                tracing::warn!(
                    reason,
                    delay_secs = delay,
                    relay = %relays[current],
                    "relay: disconnected; reconnecting"
                );
                if sleep_or_shutdown(Duration::from_secs(delay), &mut task.shutdown).await {
                    return;
                }
                attempt = attempt.saturating_add(1);
                // FAILOVER: advance to the next relay in the ordered list. With
                // a SINGLE relay `(0 + 1) % 1 == 0` ⇒ `next == current` ⇒ the
                // index never moves and `attempt` keeps climbing monotonically:
                // BYTE-IDENTICAL to the legacy single-relay reconnect loop (the
                // failover branch below is unreachable when `len == 1`). With
                // `>= 2` relays the floor rotates to the next endpoint and
                // resets `attempt` so a fresh relay gets a fast first dial.
                let next = (current + 1) % relays.len();
                if next != current {
                    current = next;
                    attempt = 0;
                }
            }
        }
    }
}

/// Outcome of a single relay WS connection attempt.
enum ConnOutcome {
    /// Shutdown was signalled — exit immediately.
    ShutdownRequested,
    /// The connection ended (connect error / read error / clean close);
    /// the caller backs off and reconnects.
    Disconnected(&'static str),
}

/// One relay connection lifecycle: connect, then concurrently drain
/// `outbound_rx` to the sink and feed inbound frames into boringtun. The
/// backoff counter is owned by [`run`] and is monotonic
/// (`saturating_add`, never reset) — a connection that succeeds and is
/// then dropped does NOT reset the backoff, mirroring `peer_sync::run`.
async fn connect_once(url: &str, task: &mut RelayTask) -> ConnOutcome {
    let ws = tokio::select! {
        biased;
        _ = task.shutdown.changed() => {
            return if *task.shutdown.borrow() { ConnOutcome::ShutdownRequested }
                   else { ConnOutcome::Disconnected("shutdown-flap") };
        }
        // `disable_nagle = true` → `TCP_NODELAY` on the relay socket. The relay
        // tunnels WireGuard frames, many of them small (handshakes, cookies,
        // and — critically — the inner TCP's ACKs riding inside small WG
        // transport frames). Nagle's algorithm would hold those back up to
        // ~40 ms waiting to coalesce, delaying ACK delivery and throttling the
        // inner transfer's window growth (pure overhead on top of the WAN). Off
        // it goes.
        connect = tokio_tungstenite::connect_async_with_config(url, None, true) => match connect {
            Ok((ws, _resp)) => ws,
            Err(e) => {
                tracing::warn!(error = %e, url, "relay: connect failed");
                return ConnOutcome::Disconnected("connect-failed");
            }
        }
    };
    tracing::info!(url, "relay: connected");
    let (mut sink, mut stream) = ws.split();

    // SELF-HEAL liveness. A cellular blip leaves the TCP half-open (no FIN); an
    // IDLE relay lane then observes NO frame, NO error and NO close, so the old
    // loop sat "connected" forever and run()'s reconnect/backoff NEVER fired —
    // the DERP connectivity floor was silently dead until the process was killed
    // (the confirmed root cause of "joiner needs a manual restart after a
    // blip"). Fix: send an app-level Ping on a fixed cadence and require SOME
    // inbound frame (data, Pong, or a server Ping) within an idle deadline;
    // otherwise declare the socket dead so run() redials a FRESH WS (which
    // re-registers this lane with the coordinator).
    let mut liveness = tokio::time::interval(std::time::Duration::from_secs(15));
    liveness.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let idle_deadline = std::time::Duration::from_secs(45);
    let mut last_rx = tokio::time::Instant::now();

    loop {
        tokio::select! {
            biased;
            _ = task.shutdown.changed() => {
                if *task.shutdown.borrow() {
                    return ConnOutcome::ShutdownRequested;
                }
            }
            // Keepalive ping + half-open detection.
            _ = liveness.tick() => {
                if last_rx.elapsed() >= idle_deadline {
                    tracing::warn!(
                        url, idle_s = last_rx.elapsed().as_secs(),
                        "relay: no inbound within idle deadline — half-open, reconnecting"
                    );
                    return ConnOutcome::Disconnected("idle-timeout");
                }
                if let Err(e) = sink.send(Message::Ping(Vec::new())).await {
                    tracing::warn!(error = %e, "relay: keepalive ping send failed");
                    return ConnOutcome::Disconnected("ping-send-failed");
                }
            }
            // Drain THIS lane's outbound queue onto its own socket. There is
            // nothing to prioritise within a socket — priority comes from the
            // SEPARATE sockets (the near-empty `hi` socket never bloats).
            outbound = task.outbound_rx.recv() => {
                let Some(out) = outbound else {
                    // Defensive only: `recv()` yields `None` solely when EVERY
                    // `RelayHandle` sender is dropped, but this task holds a
                    // `SessionTable` clone that OWNS the `RelayHandle`
                    // (tx_hi/tx_lo), so the senders outlive the task. Normal
                    // teardown happens via the `shutdown` watch (the biased arm
                    // above), NOT channel close — do not refactor teardown to
                    // rely on this branch.
                    return ConnOutcome::ShutdownRequested;
                };
                let frame = encode_relay_frame(&out.dst_pubkey, &out.payload);
                if let Err(e) = sink.send(Message::Binary(frame)).await {
                    tracing::warn!(error = %e, "relay: sink send failed");
                    return ConnOutcome::Disconnected("sink-send-failed");
                }
            }
            // Inbound frame from the coordinator → inject into boringtun.
            next = stream.next() => {
                match next {
                    None => return ConnOutcome::Disconnected("stream-ended"),
                    Some(Err(e)) => {
                        tracing::warn!(error = %e, "relay: stream error");
                        return ConnOutcome::Disconnected("stream-error");
                    }
                    Some(Ok(Message::Binary(buf))) => {
                        last_rx = tokio::time::Instant::now();
                        handle_inbound(task, &buf).await;
                    }
                    Some(Ok(Message::Close(_))) => {
                        return ConnOutcome::Disconnected("close");
                    }
                    // Ping/Pong/Text carry no relay payload, but their arrival is
                    // PROOF the socket is alive — refresh the liveness clock so a
                    // busy-but-dataless lane is never torn down as half-open.
                    // (tungstenite auto-replies Pong to server Pings and surfaces
                    // our own Pong replies here.)
                    Some(Ok(_)) => {
                        last_rx = tokio::time::Instant::now();
                    }
                }
            }
        }
    }
}

/// Decode one inbound relay frame and inject its payload into the matching
/// session's tunnel. The frame's 32-byte prefix is the SOURCE pubkey
/// (the coordinator rewrites it to the sender's registered key), so we
/// demux by source. Injecting via the SAME [`process_inbound_datagram`]
/// the UDP recv loop uses makes relayed RX indistinguishable from UDP RX;
/// passing `sessions.relay()` lets a handshake RESPONSE to a relay-only
/// peer also go back over the relay.
async fn handle_inbound(task: &RelayTask, buf: &[u8]) {
    let Some((src, payload)) = decode_relay_frame(buf) else {
        tracing::debug!(len = buf.len(), "relay inbound: malformed frame, ignoring");
        return; // too short — ignore
    };
    let Some(session) = task.sessions.by_pubkey(src) else {
        // Promoted to info: during identity churn a peer rotates its pubkey,
        // so relayed frames briefly arrive keyed to a STALE source key with no
        // matching session. Surfacing this at info lets a `peer_rekey` log be
        // correlated with the transient drop window instead of being buried at
        // debug. Steady state this line should not appear, so it stays
        // low-cardinality.
        tracing::info!(
            event = "relay_rx_no_session",
            src = %B64URL.encode(src),
            "relay inbound: no session for source pubkey, dropping (likely peer re-key in flight)"
        );
        return;
    };
    tracing::debug!(peer = %session.peer_id, len = payload.len(), "relay inbound: injecting into tunnel");
    // `via_direct = false`: a relayed packet must NEVER confirm or refresh
    // a DIRECT path — only true UDP RX can prove the direct route works.
    process_inbound_datagram(
        &task.socket,
        task.sessions.relay(),
        false,
        &task.tun,
        &task.sessions,
        &session,
        payload,
    )
    .await;
}

/// Sleep for `dur` unless `shutdown` fires first. Returns `true` if
/// shutdown was requested.
async fn sleep_or_shutdown(dur: Duration, shutdown: &mut watch::Receiver<bool>) -> bool {
    tokio::select! {
        () = tokio::time::sleep(dur) => false,
        _ = shutdown.changed() => *shutdown.borrow(),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    /// A queued datagram arrives on the receiver verbatim — the channel
    /// the relay task drains carries the destination pubkey + payload.
    /// The payload's first byte is `1` (WG handshake init), so it must land
    /// on the HIGH-priority lane, not the low one.
    #[tokio::test]
    async fn try_relay_queues_outbound() {
        let (handle, mut rx) = RelayHandle::new(false);
        handle.try_relay([9u8; 32], vec![1, 2, 3]);
        let got = rx.hi.recv().await.expect("queued outbound on hi lane");
        assert_eq!(got.dst_pubkey, [9u8; 32]);
        assert_eq!(got.payload, vec![1, 2, 3]);
    }

    /// A transport-data frame (first byte `4`) lands on the LOW lane while
    /// the HIGH lane stays empty — the classifier splits the two correctly.
    #[tokio::test]
    async fn try_relay_routes_transport_data_to_low_lane() {
        let (handle, mut rx) = RelayHandle::new(false);
        handle.try_relay([5u8; 32], vec![4, 0, 0, 0]);
        let got = rx.lo.recv().await.expect("queued outbound on lo lane");
        assert_eq!(got.dst_pubkey, [5u8; 32]);
        assert_eq!(got.payload, vec![4, 0, 0, 0]);
        // The HIGH lane must be empty — a data frame must never ride it.
        assert!(rx.hi.try_recv().is_err(), "hi lane must stay empty");
    }

    /// `try_relay` after the receiver is dropped does not panic — the
    /// packet is silently dropped (relay task gone == pre-relay drop).
    #[tokio::test]
    async fn try_relay_after_rx_dropped_is_silent() {
        let (handle, rx) = RelayHandle::new(false);
        drop(rx);
        handle.try_relay([1u8; 32], vec![0]); // must not panic
    }

    // ---- URL derivation ----

    /// `http` coordinator → `ws` relay; `https` → `wss`; trailing slash is
    /// tolerated; an explicit `relay_url` overrides derivation.
    #[test]
    fn derive_relay_url_maps_scheme_and_path() {
        assert_eq!(
            derive_relay_url("http://3.124.69.92:8888", None),
            "ws://3.124.69.92:8888/v1/mesh/relay"
        );
        assert_eq!(
            derive_relay_url("https://coord.example:8888/", None),
            "wss://coord.example:8888/v1/mesh/relay"
        );
        assert_eq!(
            derive_relay_url("http://x:1", Some("ws://override:9/v1/mesh/relay")),
            "ws://override:9/v1/mesh/relay"
        );
    }

    // ---- multi-relay resolution (HA-relay C2) ----

    /// An EMPTY configured list ⇒ derive the single default from the
    /// coordinator URL — exactly the legacy single-relay behaviour. This is
    /// the back-compat path: a node that never sets `relay_urls` still floors
    /// on the one Frankfurt relay.
    #[test]
    fn resolve_empty_derives_single() {
        assert_eq!(
            resolve_relay_urls("http://3.124.69.92:8888", &[]),
            vec!["ws://3.124.69.92:8888/v1/mesh/relay".to_owned()]
        );
    }

    /// A non-empty list is taken VERBATIM, order preserved (explicit overrides
    /// derivation per-entry). The coordinator URL is ignored when the list is
    /// non-empty.
    #[test]
    fn resolve_keeps_explicit_verbatim() {
        assert_eq!(
            resolve_relay_urls(
                "http://ignored:1",
                &["wss://a/x".to_owned(), "wss://b/x".to_owned()]
            ),
            vec!["wss://a/x".to_owned(), "wss://b/x".to_owned()]
        );
    }

    /// A duplicated entry collapses while preserving first-seen order, so an
    /// accidental double-listing never creates a phantom 2nd relay (which
    /// would arm the failover branch over what is really one endpoint).
    #[test]
    fn resolve_dedups_preserving_order() {
        assert_eq!(
            resolve_relay_urls(
                "http://ignored:1",
                &[
                    "wss://a/x".to_owned(),
                    "wss://b/x".to_owned(),
                    "wss://a/x".to_owned(),
                ]
            ),
            vec!["wss://a/x".to_owned(), "wss://b/x".to_owned()]
        );
    }

    /// THE no-op invariant: a single explicit relay resolves to exactly that
    /// one URL — a one-element list, so the failover machine's `current` can
    /// never advance (`(0+1) % 1 == 0`). Byte-identical to today.
    #[test]
    fn resolve_single_is_identical_to_today() {
        assert_eq!(
            resolve_relay_urls("http://ignored:1", &["wss://a/x".to_owned()]),
            vec!["wss://a/x".to_owned()]
        );
    }

    // ---- relay client task (B5) ----

    use crate::wg::session::SessionTable;
    use async_trait::async_trait;
    use futures_util::{SinkExt, StreamExt};
    use std::sync::Arc;
    use std::time::Duration;
    use tabbify_mesh_fabric::tun::TunDevice;
    use tokio::sync::watch;
    use tokio_tungstenite::tungstenite::Message;

    /// A TUN device that records every written packet — lets a test
    /// observe whether the relay RX path delivered an inner packet.
    struct RecordingTun {
        written: parking_lot::Mutex<Vec<Vec<u8>>>,
    }
    #[async_trait]
    impl TunDevice for RecordingTun {
        fn name(&self) -> &'static str {
            "recording-tun"
        }
        async fn read_packet(&self, _buf: &mut [u8]) -> std::io::Result<usize> {
            // Never produces a packet — the relay task never reads the TUN.
            std::future::pending().await
        }
        async fn write_packet(&self, buf: &[u8]) -> std::io::Result<usize> {
            self.written.lock().push(buf.to_vec());
            Ok(buf.len())
        }
    }

    /// End-to-end against a fake coordinator relay (a loopback WS server):
    /// an outbound datagram queued on the handle is delivered to the server
    /// as an exact `encode_relay_frame(&dst, &payload)`, and a downlink
    /// frame for an UNKNOWN pubkey is consumed without dropping the
    /// connection (the read-loop demuxes by source pubkey and ignores a
    /// frame with no matching session).
    #[tokio::test]
    async fn run_relays_outbound_and_consumes_inbound() {
        // 1) Fake coordinator relay: accept one WS connection, then echo
        //    the protocol the joiner expects.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (srv_got_tx, srv_got_rx) = tokio::sync::oneshot::channel::<Vec<u8>>();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            // Push a downlink frame for an unknown pubkey — must be ignored.
            let downlink = encode_relay_frame(&[200u8; 32], b"opaque-wg-bytes");
            ws.send(Message::Binary(downlink)).await.unwrap();
            // Read the first binary frame the joiner sends (the uplink).
            while let Some(Ok(msg)) = ws.next().await {
                if let Message::Binary(buf) = msg {
                    let _ = srv_got_tx.send(buf);
                    break;
                }
            }
        });

        // 2) The joiner relay task pointed at the fake server (insecure).
        let sessions = SessionTable::new();
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let tun: Arc<dyn TunDevice> = Arc::new(RecordingTun {
            written: parking_lot::Mutex::new(Vec::new()),
        });
        let (handle, outbound_rx) = RelayHandle::new(false);
        // `b"hello"` (first byte 'h') is a DATA frame → the lo lane; drive the
        // lo-lane task.
        let RelayOutboundRx { hi: _hi, lo } = outbound_rx;
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let task = tokio::spawn(run(RelayTask {
            coordinator_url: format!("http://{addr}"),
            relay_urls: Arc::new(vec![]),
            my_pubkey: [42u8; 32],
            insecure_no_mtls: true,
            sessions,
            socket,
            tun,
            lane: RelayLane::Lo,
            outbound_rx: lo,
            shutdown: shutdown_rx,
        }));

        // 3) Queue an outbound datagram → expect the exact frame server-side.
        handle.try_relay([7u8; 32], b"hello".to_vec());
        let got = tokio::time::timeout(Duration::from_secs(5), srv_got_rx)
            .await
            .expect("server received a frame in time")
            .expect("server channel ok");
        assert_eq!(
            got,
            encode_relay_frame(&[7u8; 32], b"hello"),
            "uplink frame is byte-identical to the codec output"
        );

        // 4) Clean shutdown.
        let _ = shutdown_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
        let _ = tokio::time::timeout(Duration::from_secs(2), server).await;
    }

    /// Under secure mode (`insecure_no_mtls == false`) the relay task is a
    /// no-op that returns promptly — wss/mTLS is not yet implemented, so
    /// the task must not hang or attempt a plaintext connection.
    #[tokio::test]
    async fn run_returns_immediately_under_secure_mode() {
        let sessions = SessionTable::new();
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let tun: Arc<dyn TunDevice> = Arc::new(RecordingTun {
            written: parking_lot::Mutex::new(Vec::new()),
        });
        let (_handle, outbound_rx) = RelayHandle::new(false);
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let res = tokio::time::timeout(
            Duration::from_secs(2),
            run(RelayTask {
                coordinator_url: "https://coord.example:8888".into(),
                relay_urls: Arc::new(vec![]),
                my_pubkey: [1u8; 32],
                insecure_no_mtls: false,
                sessions,
                socket,
                tun,
                lane: RelayLane::Hi,
                outbound_rx: outbound_rx.hi,
                shutdown: shutdown_rx,
            }),
        )
        .await;
        assert!(res.is_ok(), "secure-mode relay task must return, not hang");
    }

    /// `as_str` pins the `?lane=` wire values; a drift from the coordinator's
    /// `LANE_HI`/`LANE_LO` would silently route handshakes to the legacy
    /// fallback (the `REKEY_TIMEOUT` bug), so assert them explicitly.
    #[test]
    fn relay_lane_wire_values() {
        assert_eq!(RelayLane::Hi.as_str(), "hi");
        assert_eq!(RelayLane::Lo.as_str(), "lo");
        assert_eq!((LANE_HI, LANE_LO), ("hi", "lo"));
    }

    /// The relay task connects with its lane in the query string: a `Hi` task
    /// builds `…?pubkey=…&lane=hi`. Captures the upgrade request URI on a fake
    /// coordinator and asserts the `lane` param — the joiner half of the
    /// cross-end lane contract.
    #[tokio::test]
    #[allow(clippy::result_large_err)] // tokio-tungstenite's accept_hdr callback signature
    async fn run_connects_with_lane_query() {
        use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (uri_tx, uri_rx) = tokio::sync::oneshot::channel::<String>();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut uri_tx = Some(uri_tx);
            let _ws = tokio_tungstenite::accept_hdr_async(stream, |req: &Request, resp: Response| {
                if let Some(tx) = uri_tx.take() {
                    let _ = tx.send(req.uri().to_string());
                }
                Ok(resp)
            })
            .await
            .unwrap();
        });

        let sessions = SessionTable::new();
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let tun: Arc<dyn TunDevice> = Arc::new(RecordingTun {
            written: parking_lot::Mutex::new(Vec::new()),
        });
        let (_handle, outbound_rx) = RelayHandle::new(false);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let task = tokio::spawn(run(RelayTask {
            coordinator_url: format!("http://{addr}"),
            relay_urls: Arc::new(vec![]),
            my_pubkey: [42u8; 32],
            insecure_no_mtls: true,
            sessions,
            socket,
            tun,
            lane: RelayLane::Hi,
            outbound_rx: outbound_rx.hi,
            shutdown: shutdown_rx,
        }));

        let uri = tokio::time::timeout(Duration::from_secs(5), uri_rx)
            .await
            .expect("server captured the upgrade URI in time")
            .expect("uri channel ok");
        assert!(
            uri.contains("lane=hi"),
            "hi-lane task must connect with &lane=hi; got {uri}"
        );

        let _ = shutdown_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
        let _ = tokio::time::timeout(Duration::from_secs(2), server).await;
    }

    // ---- failover state machine (HA-relay C4) ----

    /// Build a minimal `RelayTask` for a `Lo`-lane failover test against the
    /// given ordered relay list. Returns the task plus the live `RelayHandle`
    /// the caller MUST hold (if every handle drops, the relay task treats the
    /// closed outbound channel as teardown and exits — which would mask the
    /// floor behaviour under test).
    async fn make_failover_task(
        relay_urls: Vec<String>,
        shutdown_rx: watch::Receiver<bool>,
    ) -> (RelayTask, RelayHandle) {
        let sessions = SessionTable::new();
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let tun: Arc<dyn TunDevice> = Arc::new(RecordingTun {
            written: parking_lot::Mutex::new(Vec::new()),
        });
        let (handle, outbound_rx) = RelayHandle::new(false);
        let task = RelayTask {
            coordinator_url: "http://unused:1".into(),
            relay_urls: Arc::new(relay_urls),
            my_pubkey: [3u8; 32],
            insecure_no_mtls: true,
            sessions,
            socket,
            tun,
            lane: RelayLane::Lo,
            outbound_rx: outbound_rx.lo,
            shutdown: shutdown_rx,
        };
        (task, handle)
    }

    /// A fake relay server that accepts WS upgrades on its listener and reports
    /// each connection's count over a channel, then immediately drops the
    /// socket (so the client sees a disconnect and reconnects/fails over).
    /// `accept` set to `false` means: accept the TCP connection but DON'T do a
    /// WS handshake — drop it raw (simulates a refusing/closing relay).
    fn spawn_accept_then_drop(
        listener: tokio::net::TcpListener,
        hits: tokio::sync::mpsc::UnboundedSender<()>,
        do_ws: bool,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let _ = hits.send(());
                if do_ws {
                    // Complete the handshake then drop → client sees a clean
                    // close / stream-ended and reconnects or fails over.
                    if let Ok(ws) = tokio_tungstenite::accept_async(stream).await {
                        drop(ws);
                    }
                } else {
                    drop(stream);
                }
            }
        })
    }

    /// THE no-op invariant (load-bearing): with a SINGLE relay, a disconnect
    /// must reconnect to the SAME relay — the failover index never advances
    /// (`(0 + 1) % 1 == 0`). Drive a fake server that accepts the WS then drops
    /// it; the task must reconnect to that SAME listener at least twice (proving
    /// it redials the identical url, exactly like today's single-relay loop).
    #[tokio::test]
    async fn single_relay_failover_is_noop() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (hits_tx, mut hits_rx) = tokio::sync::mpsc::unbounded_channel::<()>();
        let server = spawn_accept_then_drop(listener, hits_tx, true);

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let relay_urls = vec![format!("ws://{addr}/v1/mesh/relay")];
        let (relay_task, _handle) = make_failover_task(relay_urls, shutdown_rx).await;
        let task = tokio::spawn(run(relay_task));

        // Expect at least TWO connections to the SAME single relay: the initial
        // connect + at least one reconnect after the drop (backoff[0] = 1 s).
        for n in 0..2 {
            tokio::time::timeout(Duration::from_secs(8), hits_rx.recv())
                .await
                .unwrap_or_else(|_| panic!("single relay must be redialed (hit {n})"))
                .expect("hit channel open");
        }

        let _ = shutdown_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(3), task).await;
        server.abort();
    }

    /// With TWO relays, a primary that refuses/closes must fail the floor over
    /// to the SECONDARY, which then carries the connection. Assert the
    /// secondary listener receives a connection.
    #[tokio::test]
    async fn two_relays_fail_over_to_secondary() {
        // Primary: accept the TCP then drop raw (no WS) → `connect-failed` /
        // `stream-ended` → the floor must move on.
        let primary = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let primary_addr = primary.local_addr().unwrap();
        let (p_tx, _p_rx) = tokio::sync::mpsc::unbounded_channel::<()>();
        let p_srv = spawn_accept_then_drop(primary, p_tx, false);

        // Secondary: accept the WS and hold it.
        let secondary = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let secondary_addr = secondary.local_addr().unwrap();
        let (s_tx, mut s_rx) = tokio::sync::mpsc::unbounded_channel::<()>();
        let s_srv = spawn_accept_then_drop(secondary, s_tx, true);

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let relay_urls = vec![
            format!("ws://{primary_addr}/v1/mesh/relay"),
            format!("ws://{secondary_addr}/v1/mesh/relay"),
        ];
        let (relay_task, _handle) = make_failover_task(relay_urls, shutdown_rx).await;
        let task = tokio::spawn(run(relay_task));

        // The secondary MUST receive a connection within a few backoff steps.
        tokio::time::timeout(Duration::from_secs(10), s_rx.recv())
            .await
            .expect("failover must reach the secondary relay")
            .expect("secondary hit channel open");

        let _ = shutdown_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(3), task).await;
        p_srv.abort();
        s_srv.abort();
    }

    /// Both relays down then the PRIMARY recovers: the floor cycles through the
    /// list and lands back on the primary (`% relays.len()` wraps). Bind the
    /// primary listener but only START accepting after the floor has cycled
    /// past the (closed) secondary — assert the primary ultimately connects.
    #[tokio::test]
    async fn failover_wraps_back_to_primary() {
        let primary = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let primary_addr = primary.local_addr().unwrap();
        let (p_tx, mut p_rx) = tokio::sync::mpsc::unbounded_channel::<()>();
        // Primary accepts the WS and holds — but we delay binding-to-accept by
        // spawning the acceptor immediately; the floor reaches it after wrap.
        let p_srv = spawn_accept_then_drop(primary, p_tx, true);

        // Secondary: bound but immediately closed (its acceptor drops raw).
        let secondary = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let secondary_addr = secondary.local_addr().unwrap();
        let (s_tx, _s_rx) = tokio::sync::mpsc::unbounded_channel::<()>();
        let s_srv = spawn_accept_then_drop(secondary, s_tx, false);

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let relay_urls = vec![
            format!("ws://{primary_addr}/v1/mesh/relay"),
            format!("ws://{secondary_addr}/v1/mesh/relay"),
        ];
        let (relay_task, _handle) = make_failover_task(relay_urls, shutdown_rx).await;
        let task = tokio::spawn(run(relay_task));

        // After the initial primary-drop + secondary-fail, the index wraps and
        // the primary is dialed AGAIN — assert at least two primary hits.
        for n in 0..2 {
            tokio::time::timeout(Duration::from_secs(12), p_rx.recv())
                .await
                .unwrap_or_else(|_| panic!("primary must be re-dialed after wrap (hit {n})"))
                .expect("primary hit channel open");
        }

        let _ = shutdown_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(3), task).await;
        p_srv.abort();
        s_srv.abort();
    }

    /// Relay-is-floor: while `shutdown` is false and a relay is reachable, the
    /// `run` task NEVER returns — it is always either connected or dialing. We
    /// hold a healthy single relay open and assert the task is still alive
    /// after a grace period (it does not exit on its own).
    #[tokio::test]
    async fn relay_is_floor_throughout_failover() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // A server that accepts the WS and HOLDS it open (never drops).
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            // Hold the socket; pend forever.
            let _held = ws;
            std::future::pending::<()>().await;
        });

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let relay_urls = vec![format!("ws://{addr}/v1/mesh/relay")];
        let (relay_task, _handle) = make_failover_task(relay_urls, shutdown_rx).await;
        let task = tokio::spawn(run(relay_task));

        // Give it time to connect and sit. The task must NOT have completed.
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(!task.is_finished(), "relay floor task must not exit while connected");

        let _ = shutdown_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(3), task).await;
        server.abort();
    }

    /// HA-relay C3/C4: a [`RelayTask`] carries the FULL ordered relay list as an
    /// `Arc<Vec<String>>` and `run` MUST dial the PRIMARY (index 0) FIRST.
    ///
    /// This genuinely proves the start-index-0 ordering — NOT just "we connected
    /// somewhere". BOTH relays are real, accepting listeners that HOLD the WS
    /// open; since the primary stays healthy, the sticky floor never advances, so
    /// the SECONDARY must receive **zero** connections. A drifted start index
    /// (`current = 1`) would dial the secondary first → it would record a hit →
    /// this test FAILS. (With the old single-`uri.contains("lane=lo")` assertion
    /// and an unroutable secondary, a `current = 1` start merely failed over back
    /// to the primary inside the timeout and went undetected — the coverage gap
    /// this test closes.)
    #[tokio::test]
    #[allow(clippy::result_large_err)] // tokio-tungstenite's accept_hdr callback signature
    async fn run_connects_to_first_of_relay_urls() {
        use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};

        // Primary fake relay — captures its upgrade URI then HOLDS the WS open
        // (a healthy primary the sticky floor must never leave).
        let primary = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let primary_addr = primary.local_addr().unwrap();
        let (uri_tx, uri_rx) = tokio::sync::oneshot::channel::<String>();
        let primary_srv = tokio::spawn(async move {
            let (stream, _) = primary.accept().await.unwrap();
            let mut uri_tx = Some(uri_tx);
            let ws = tokio_tungstenite::accept_hdr_async(stream, |req: &Request, resp: Response| {
                if let Some(tx) = uri_tx.take() {
                    let _ = tx.send(req.uri().to_string());
                }
                Ok(resp)
            })
            .await
            .unwrap();
            // Hold the socket open forever — the floor must stay here.
            let _held = ws;
            std::future::pending::<()>().await;
        });

        // Secondary — a REAL, accepting listener that records every connection.
        // On the correct (index-0-first, sticky) path it must receive NONE.
        let secondary = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let secondary_addr = secondary.local_addr().unwrap();
        let (s_hits_tx, mut s_hits_rx) = tokio::sync::mpsc::unbounded_channel::<()>();
        let secondary_srv = spawn_accept_then_drop(secondary, s_hits_tx, true);

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let relay_urls = vec![
            format!("ws://{primary_addr}/v1/mesh/relay"),
            format!("ws://{secondary_addr}/v1/mesh/relay"),
        ];
        let (relay_task, _handle) = make_failover_task(relay_urls, shutdown_rx).await;
        let task = tokio::spawn(run(relay_task));

        // The PRIMARY must capture the very first upgrade (index 0 dialed first).
        let uri = tokio::time::timeout(Duration::from_secs(5), uri_rx)
            .await
            .expect("primary must be dialed first (index 0)")
            .expect("uri channel ok");
        assert!(
            uri.contains("lane=lo"),
            "lo-lane task must connect with lane=lo; got {uri}"
        );

        // Stickiness + index-0 proof: while the healthy primary holds the floor,
        // the secondary must NEVER be reached. A drifted start index (or a
        // non-sticky failover) would land a connection here.
        tokio::time::sleep(Duration::from_millis(750)).await;
        assert!(
            s_hits_rx.try_recv().is_err(),
            "secondary must receive ZERO connections while the primary is healthy \
             (proves index-0-first + sticky floor)"
        );

        let _ = shutdown_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
        primary_srv.abort();
        secondary_srv.abort();
    }
}
