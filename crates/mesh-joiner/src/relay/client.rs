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
    /// Coordinator base URL (used to derive the relay URL when `relay_url`
    /// is `None`).
    pub coordinator_url: String,
    /// Explicit relay endpoint URL; `None` derives it from
    /// `coordinator_url`.
    pub relay_url: Option<String>,
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

    let base = derive_relay_url(&task.coordinator_url, task.relay_url.as_deref());
    let pubkey_q = B64URL.encode(task.my_pubkey);
    // `&lane=` tags which dedicated socket this is so the coordinator registers
    // it on the matching lane (handshakes on `hi`, bulk on `lo`).
    let url = format!("{base}?pubkey={pubkey_q}&lane={}", task.lane.as_str());

    let backoff = [1u64, 2, 5, 10];
    let mut attempt: usize = 0;

    loop {
        if *task.shutdown.borrow() {
            return;
        }
        match connect_once(&url, &mut task).await {
            ConnOutcome::ShutdownRequested => return,
            ConnOutcome::Disconnected(reason) => {
                let delay = backoff[attempt.min(backoff.len() - 1)];
                tracing::warn!(
                    reason,
                    delay_secs = delay,
                    "relay: disconnected; reconnecting"
                );
                if sleep_or_shutdown(Duration::from_secs(delay), &mut task.shutdown).await {
                    return;
                }
                attempt = attempt.saturating_add(1);
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

    loop {
        tokio::select! {
            biased;
            _ = task.shutdown.changed() => {
                if *task.shutdown.borrow() {
                    return ConnOutcome::ShutdownRequested;
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
                        handle_inbound(task, &buf).await;
                    }
                    Some(Ok(Message::Close(_))) => {
                        return ConnOutcome::Disconnected("close");
                    }
                    // Ping/Pong handled by the protocol layer; Text is not
                    // part of the relay contract — ignore.
                    Some(Ok(_)) => {}
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
            relay_url: None,
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
                relay_url: None,
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
            relay_url: None,
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
}
