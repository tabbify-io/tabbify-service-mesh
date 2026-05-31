//! Relay client: the cheap-clone handle the WG TX seams use to relay a
//! packet, plus (in [`run`]) the persistent WebSocket task that connects
//! to the coordinator's `/v1/mesh/relay` endpoint, drains queued
//! outbound datagrams, and injects relayed inbound datagrams back into
//! boringtun.

use crate::relay::frame::{decode_relay_frame, encode_relay_frame};
use crate::wg::loops::process_inbound_datagram;
use crate::wg::session::SessionTable;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
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

/// Cheap-clone handle the WG TX seams use to relay a packet when no direct
/// endpoint is known.
///
/// Backed by an unbounded channel drained by the relay client task.
/// [`Self::try_relay`] never blocks and never fails loudly — if the relay
/// task is gone the packet is dropped (the same outcome as the pre-relay
/// silent drop).
#[derive(Clone)]
pub struct RelayHandle {
    tx: mpsc::UnboundedSender<RelayOutbound>,
}

impl RelayHandle {
    /// Create a handle paired with the receiver the relay task drains.
    pub(crate) fn new() -> (Self, mpsc::UnboundedReceiver<RelayOutbound>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (Self { tx }, rx)
    }

    /// Queue an already-encrypted WG datagram for relay to `dst_pubkey`.
    /// Best-effort: a send to a closed channel (relay task gone) is
    /// silently dropped.
    pub fn try_relay(&self, dst_pubkey: [u8; 32], payload: Vec<u8>) {
        let _ = self.tx.send(RelayOutbound { dst_pubkey, payload });
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
    /// Receiver the WG TX seams queue outbound relayed datagrams on.
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
    let (scheme, rest) = trimmed
        .split_once("://")
        .map_or(("ws", trimmed), |(s, r)| {
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
    // The wss/mTLS relay path is structured-for but not yet implemented.
    // Under secure mode, log once and return — direct + hole-punch still
    // provide connectivity; only the relay floor is unavailable.
    if !task.insecure_no_mtls {
        tracing::warn!(
            "relay: wss/mTLS not implemented — relay disabled (direct + hole-punch still active)"
        );
        return;
    }

    let base = derive_relay_url(&task.coordinator_url, task.relay_url.as_deref());
    let pubkey_q = B64.encode(task.my_pubkey);
    let url = format!("{base}?pubkey={pubkey_q}");

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
                tracing::warn!(reason, delay_secs = delay, "relay: disconnected; reconnecting");
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
/// `outbound_rx` to the sink and feed inbound frames into boringtun. On a
/// successful connect the backoff counter is implicitly reset by the
/// caller treating each `connect_once` call freshly.
async fn connect_once(url: &str, task: &mut RelayTask) -> ConnOutcome {
    let ws = tokio::select! {
        biased;
        _ = task.shutdown.changed() => {
            return if *task.shutdown.borrow() { ConnOutcome::ShutdownRequested }
                   else { ConnOutcome::Disconnected("shutdown-flap") };
        }
        connect = tokio_tungstenite::connect_async(url) => match connect {
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
            // Drain one queued outbound datagram → relay frame on the wire.
            outbound = task.outbound_rx.recv() => {
                let Some(out) = outbound else {
                    // The handle was dropped (joiner tearing down) — exit.
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
        return; // too short — ignore
    };
    let Some(session) = task.sessions.by_pubkey(src) else {
        tracing::trace!("relay: inbound frame for unknown source pubkey, dropping");
        return;
    };
    process_inbound_datagram(
        &task.socket,
        task.sessions.relay(),
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
    #[tokio::test]
    async fn try_relay_queues_outbound() {
        let (handle, mut rx) = RelayHandle::new();
        handle.try_relay([9u8; 32], vec![1, 2, 3]);
        let got = rx.recv().await.expect("queued outbound");
        assert_eq!(got.dst_pubkey, [9u8; 32]);
        assert_eq!(got.payload, vec![1, 2, 3]);
    }

    /// `try_relay` after the receiver is dropped does not panic — the
    /// packet is silently dropped (relay task gone == pre-relay drop).
    #[tokio::test]
    async fn try_relay_after_rx_dropped_is_silent() {
        let (handle, rx) = RelayHandle::new();
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
        let (handle, outbound_rx) = RelayHandle::new();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let task = tokio::spawn(run(RelayTask {
            coordinator_url: format!("http://{addr}"),
            relay_url: None,
            my_pubkey: [42u8; 32],
            insecure_no_mtls: true,
            sessions,
            socket,
            tun,
            outbound_rx,
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
        let (_handle, outbound_rx) = RelayHandle::new();
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
                outbound_rx,
                shutdown: shutdown_rx,
            }),
        )
        .await;
        assert!(res.is_ok(), "secure-mode relay task must return, not hang");
    }
}
