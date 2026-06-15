//! `GET /v1/mesh/relay` — DERP-style WebSocket relay endpoint.
//!
//! Each joiner keeps one persistent `WebSocket` to this endpoint keyed by its
//! `WireGuard` public key (`?pubkey=<base64url (URL-safe, no padding)>`). It forwards opaque,
//! already-`WireGuard`-encrypted frames by destination pubkey: an uplink frame
//! `{dst_pubkey, payload}` from connection `S` is rewritten to `{src=S, payload}`
//! and delivered to `dst`'s connection, so the receiver demuxes by source. The
//! relay never decrypts a payload and never an ACL bypass — every forward is
//! gated by [`Coordinator::can_relay`] (same policy as direct sessions).
//!
//! The relay registry is NOT event-sourced: a live socket can't be replayed.
//! A connection is dropped from the registry on `WebSocket` close (id-matched,
//! so a newer reconnect under the same pubkey is never clobbered) and on
//! `apply_peer_left` (the peer left the roster).
//!
//! Posture (POC): plaintext `ws://` under `--insecure-no-mtls`. Registration is
//! unauthenticated in insecure mode (matches the current register posture); the
//! claimed pubkey must still resolve to a registered peer.

use crate::relay::{Lane, decode_relay_frame, encode_relay_frame};
use crate::roster::coordinator::Coordinator;
use base64::Engine as _;
// base64url (no padding): the pubkey rides in the URL query, where standard
// base64's `+`/`/` are unsafe (`+` decodes to a space). The joiner encodes the
// `?pubkey=` value with the SAME alphabet — keep these two in lockstep.
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::response::IntoResponse;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use futures::{SinkExt, StreamExt};
use std::time::Duration;
use tokio::sync::mpsc;

/// Keepalive cadence — mirrors the SSE `KeepAlive` interval. The send task
/// emits a `WebSocket` `Ping` this often; a dead connection is detected when
/// the sink errors and the connection is torn down.
const RELAY_PING_INTERVAL: Duration = Duration::from_secs(15);

/// Bounded capacity of a peer's HI (handshake/cookie) downlink channel. Large
/// on purpose: handshakes are tiny and infrequent and drain over the dedicated
/// near-empty `hi` socket, so this never fills in practice — it exists only so
/// `hi` and `lo` share one bounded `Sender` type while guaranteeing handshakes
/// are never dropped under steady-state load.
const RELAY_HI_CAP: usize = 1024;

/// Bounded capacity of a peer's LO (bulk transport) downlink channel. SMALL on
/// purpose — this IS the bufferbloat debloat. The coordinator must not buffer
/// more than a fraction of a second of bulk for a peer whose downlink can't
/// keep up: when this channel fills, `RelayRegistry::forward` DROPS new frames,
/// so the inner TCP sees the loss, shrinks its congestion window, and the
/// lane's RTT stays low (~ms) instead of ballooning to ~10 s (which starved
/// the inner transfer and EOF'd large pulls). ~256 × 1.4 KB ≈ 360 KB, far
/// below the multi-MB / ~10 s backlog the unbounded channel used to grow.
const RELAY_LO_CAP: usize = 256;

/// Per-lane bounded-channel capacity (see [`RELAY_HI_CAP`] / [`RELAY_LO_CAP`]).
const fn lane_channel_cap(lane: Lane) -> usize {
    match lane {
        Lane::Hi => RELAY_HI_CAP,
        Lane::Lo => RELAY_LO_CAP,
    }
}

/// Wire value of `?lane=hi` — the handshake/cookie socket. Any OTHER value
/// (including `lo`, an unknown string, or absence) is treated as the legacy /
/// `lo` lane, so this is the ONLY lane string the coordinator must recognise.
///
/// MUST stay byte-identical to the joiner's copy (`mesh-joiner` `relay::client`
/// `LANE_HI`). A mismatch (e.g. `"high"`) silently routes every handshake to
/// the legacy `lo` fallback, reviving the `REKEY_TIMEOUT` bug with NO error
/// surfaced. Same independent-copy rule as the relay frame codec.
pub const LANE_HI: &str = "hi";

/// Query string for the relay upgrade: the connecting peer's WG public key and
/// the lane this socket serves.
#[derive(serde::Deserialize)]
pub struct RelayQuery {
    /// base64url (URL-safe, no padding) of the connecting peer's 32-byte WG public key.
    pubkey: String,
    /// Which lane this socket carries: [`LANE_HI`] (`"hi"`, handshake/cookie)
    /// or `"lo"` (bulk data). ABSENT — a legacy single-WS joiner that
    /// multiplexes everything over one socket — is treated as [`Lane::Lo`],
    /// and the registry's hi→lo fallback still delivers handshakes to it.
    /// Any unrecognised value also degrades to `Lo` (never a 400, so a legacy
    /// joiner is never rejected during a mixed-version rollout).
    #[serde(default)]
    lane: Option<String>,
}

/// Map the `?lane=` query value to a [`Lane`]. `Some("hi")` → `Hi`; absent or
/// anything else → `Lo` (legacy / data).
fn parse_lane(lane: Option<&str>) -> Lane {
    if lane == Some(LANE_HI) {
        Lane::Hi
    } else {
        Lane::Lo
    }
}

/// Route one decoded uplink frame: decode → ACL-check → build the
/// source-rewritten downlink → forward to the destination's connection.
///
/// Pure and synchronous so the relay routing is unit-tested without a full
/// `WebSocket` upgrade. Returns the downlink frame that was forwarded
/// (`Some`) — `None` when the frame is too short, the pair is policy-denied,
/// or the destination has no live connection. `my_pubkey` is the registered
/// pubkey of the connection that sent `buf`; it becomes the downlink prefix.
pub fn route_uplink(
    coordinator: &Coordinator,
    my_pubkey: &[u8; 32],
    buf: &[u8],
) -> Option<Vec<u8>> {
    let (dst, payload) = decode_relay_frame(buf)?;
    if !coordinator.can_relay(my_pubkey, &dst) {
        tracing::warn!(
            src = %B64URL.encode(my_pubkey),
            dst = %B64URL.encode(dst),
            "relay: ACL denied — frame dropped"
        );
        return None;
    }
    // WireGuard message type = cleartext first byte of the inner packet:
    // 1=handshake init, 2=handshake response, 3=cookie reply, 4=transport data.
    // Handshake/cookie frames take the HIGH-priority lane so a saturated bulk
    // transfer (e.g. a multi-MB OCI pull) can't starve a peer's rekey handshake
    // behind thousands of data frames — the cause of REKEY_TIMEOUT mid-transfer
    // (the tunnel then dies and the long transfer EOFs).
    let hi_prio = payload.first().is_some_and(|&t| matches!(t, 1..=3));
    let downlink = encode_relay_frame(my_pubkey, payload);
    if coordinator.relay().forward(&dst, downlink.clone(), hi_prio) {
        tracing::debug!(
            src = %B64URL.encode(my_pubkey),
            dst = %B64URL.encode(dst),
            len = downlink.len(),
            "relay: forwarded"
        );
        Some(downlink)
    } else {
        // Not forwarded to a live socket. Either (a) no live connection → the
        // frame was SPOOLED (held briefly) and delivered the instant the
        // destination's WS (re)registers — bridging the post-reconnect race
        // that otherwise stranded WireGuard handshakes (the REKEY_TIMEOUT
        // storm); or (b) the destination's bounded `lo` channel was FULL → the
        // bulk frame was DROPPED (congestion debloat), and the inner TCP will
        // retransmit it.
        tracing::debug!(
            src = %B64URL.encode(my_pubkey),
            dst = %B64URL.encode(dst),
            "relay: not forwarded (destination not yet connected → spooled, or lo congested → dropped)"
        );
        None
    }
}

/// `WebSocket` relay upgrade. Validates the claimed pubkey (must be 32 raw
/// bytes belonging to a registered peer) before upgrading; then registers the
/// connection and forwards frames by pubkey for its lifetime.
#[utoipa::path(
    get,
    path = "/v1/mesh/relay",
    tag = "mesh",
    params(
        ("pubkey" = String, Query,
            description = "base64url (URL-safe, no padding) of the connecting peer's 32-byte WireGuard public key. This is a WebSocket upgrade endpoint (documented as GET; OpenAPI cannot model the WS protocol). The connection relays opaque, already-encrypted WireGuard frames by destination pubkey; every forward is ACL-gated by the same policy as direct sessions."),
        ("lane" = Option<String>, Query,
            description = "Which lane this socket carries: 'hi' (WireGuard handshake/cookie, types 1-3) or 'lo' (bulk transport data, type 4). Each joiner opens TWO sockets, one per lane, so a bulk transfer on 'lo' cannot bufferbloat the handshake socket. ABSENT (legacy single-WS joiner) or any unrecognised value is treated as 'lo'; the registry's hi→lo fallback still delivers handshakes to a lo-only peer."),
    ),
    responses(
        (status = 101, description = "Switching Protocols — WebSocket relay established."),
        (status = 400, description = "Malformed pubkey query parameter."),
        (status = 403, description = "Pubkey does not belong to a registered peer."),
    ),
)]
pub async fn relay_ws_handler(
    State(coordinator): State<Coordinator>,
    Query(q): Query<RelayQuery>,
    ws: WebSocketUpgrade,
) -> axum::response::Response {
    let Ok(pubkey_bytes) = B64URL.decode(&q.pubkey) else {
        return (axum::http::StatusCode::BAD_REQUEST, "bad pubkey").into_response();
    };
    let Ok(my_pubkey): Result<[u8; 32], _> = pubkey_bytes.try_into() else {
        return (axum::http::StatusCode::BAD_REQUEST, "bad pubkey").into_response();
    };
    if !coordinator.is_registered_pubkey(&my_pubkey) {
        return (axum::http::StatusCode::FORBIDDEN, "unknown pubkey").into_response();
    }
    let lane = parse_lane(q.lane.as_deref());
    ws.on_upgrade(move |socket| relay_conn(coordinator, my_pubkey, lane, socket))
}

/// Per-connection loop for ONE lane's socket: register the sender under
/// `(pubkey, lane)`, then split the socket into a send-task (drains the
/// registry channel + emits keepalive pings) and a recv-loop (decodes uplink
/// frames and forwards them). Cleans up on exit.
///
/// Each joiner opens TWO of these (a `hi` socket and a `lo` socket), so this
/// function carries exactly one lane — there is nothing to prioritise WITHIN a
/// socket; priority is achieved by the SEPARATE sockets (the near-empty `hi`
/// socket never bufferbloats under a bulk transfer on `lo`).
async fn relay_conn(coordinator: Coordinator, my_pubkey: [u8; 32], lane: Lane, socket: WebSocket) {
    // BOUNDED channel: a small `lo` capacity caps how much bulk the coordinator
    // buffers for this peer's downlink, so `forward` drops (rather than bloats)
    // under congestion. `hi` is sized large so handshakes are never dropped.
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(lane_channel_cap(lane));
    let id = coordinator.relay().register(&my_pubkey, lane, tx);
    tracing::info!(pubkey = %B64URL.encode(my_pubkey), conn_id = id, ?lane, "relay: peer connected");
    let (mut sink, mut stream) = socket.split();

    // Send task: forward this lane's downlink frames + heartbeat pings to the
    // peer. The `hi` socket still needs its own ping so a dead handshake lane
    // is detected and reaped independently of the `lo` lane.
    let send_task = tokio::spawn(async move {
        let mut ping = tokio::time::interval(RELAY_PING_INTERVAL);
        loop {
            tokio::select! {
                frame = rx.recv() => {
                    let Some(frame) = frame else { break };
                    if sink.send(Message::Binary(frame)).await.is_err() {
                        break;
                    }
                }
                _ = ping.tick() => {
                    if sink.send(Message::Ping(Vec::new())).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    // Recv loop: decode uplink frames and forward them to the destination. The
    // frame's destination LANE is derived from its WireGuard type in
    // `route_uplink` (NOT from which socket it arrived on), so an uplink may
    // arrive on either of this peer's sockets and still route correctly.
    while let Some(Ok(msg)) = stream.next().await {
        match msg {
            Message::Binary(buf) => {
                // `route_uplink` decodes, ACL-checks, and forwards; the
                // return value (forwarded downlink) is unused on the hot path.
                let _ = route_uplink(&coordinator, &my_pubkey, &buf);
            }
            Message::Close(_) => break,
            // Ping/Pong/Text are handled by the split halves / ignored.
            Message::Ping(_) | Message::Pong(_) | Message::Text(_) => {}
        }
    }

    // Tear down: drop ONLY this lane's registry slot (id-matched, so a newer
    // reconnect on this lane is never clobbered, and the peer's OTHER lane is
    // left intact) + stop the send task so its sink half is released.
    coordinator.relay().unregister(&my_pubkey, lane, id);
    tracing::info!(pubkey = %B64URL.encode(my_pubkey), conn_id = id, ?lane, "relay: peer disconnected");
    send_task.abort();
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::http::api::RegisterRequest;
    use crate::policy::{AclRule, Policy, PolicyStore};
    use crate::publisher::NoopPublisher;
    use std::sync::Arc;
    use std::time::Duration;

    fn pubkey_b64(seed: u8) -> String {
        base64::engine::general_purpose::STANDARD.encode([seed; 32])
    }

    /// Policy: user-a and svc see each other; user-a and user-b are isolated.
    fn policy() -> Policy {
        Policy::new(vec![
            AclRule::accept(&["tag:user-a"], &["tag:svc"]),
            AclRule::accept(&["tag:svc"], &["tag:user-a"]),
        ])
    }

    fn coordinator() -> Coordinator {
        Coordinator::with_policy(
            Arc::new(NoopPublisher),
            Duration::from_secs(60),
            PolicyStore::new(policy()),
        )
    }

    fn req(seed: u8, name: &str, network: &str, tags: &[&str]) -> RegisterRequest {
        RegisterRequest {
            wg_public_key: pubkey_b64(seed),
            listen_endpoint: Some("127.0.0.1:51820".into()),
            wg_listen_port: Some(51820),
            display_name: name.into(),
            network: network.into(),
            tags: tags.iter().map(|s| (*s).to_owned()).collect(),
            hosted_app_ulas: vec![],
            kind: "peer".into(),
            parent: None,
            app_uuid: None,
            requested_ula: None,
            software_version: None,
            mesh_version: None,
            relay_only: false,
        }
    }

    /// An allowed pair: A uplinks to B; B's registered relay conn receives the
    /// source-rewritten downlink (`A`-prefixed) carrying the same payload.
    #[tokio::test]
    async fn route_uplink_forwards_allowed_pair_with_source_rewrite() {
        let c = coordinator();
        let _ = c
            .register(req(1, "a", "a", &["tag:user-a"]))
            .await
            .expect("a");
        let _ = c
            .register(req(2, "b", "svc", &["tag:svc"]))
            .await
            .expect("b");
        let a_pubkey = [1u8; 32];
        let b_pubkey = [2u8; 32];

        // `b"ping"` (first byte 'p') is a DATA frame → the lo lane.
        let (b_lo, mut b_rx) = mpsc::channel(16);
        c.relay().register(&b_pubkey, Lane::Lo, b_lo);

        let uplink = encode_relay_frame(&b_pubkey, b"ping");
        let forwarded = route_uplink(&c, &a_pubkey, &uplink).expect("forwarded");
        // Downlink prefix is the SOURCE pubkey (A), payload preserved.
        assert_eq!(&forwarded[..32], &a_pubkey);
        assert_eq!(&forwarded[32..], b"ping");
        let received = b_rx.try_recv().expect("b received the downlink");
        assert_eq!(received, forwarded);
    }

    /// Rollout back-compat at the routing layer: a HANDSHAKE-typed uplink
    /// (first byte 1) to a destination that registered ONLY a lo lane (a
    /// legacy single-WS joiner) is delivered via the hi→lo fallback.
    #[tokio::test]
    async fn route_uplink_handshake_falls_back_to_legacy_lo_only_peer() {
        let c = coordinator();
        let _ = c
            .register(req(1, "a", "a", &["tag:user-a"]))
            .await
            .expect("a");
        let _ = c
            .register(req(2, "b", "svc", &["tag:svc"]))
            .await
            .expect("b");
        let a_pubkey = [1u8; 32];
        let b_pubkey = [2u8; 32];

        // Legacy peer: only the lo lane (no ?lane=hi socket).
        let (b_lo, mut b_rx) = mpsc::channel(16);
        c.relay().register(&b_pubkey, Lane::Lo, b_lo);

        // A WireGuard handshake-init (type 1) must still reach the legacy peer.
        let uplink = encode_relay_frame(&b_pubkey, &[1u8, 2, 3, 4]);
        let forwarded = route_uplink(&c, &a_pubkey, &uplink).expect("forwarded via fallback");
        let received = b_rx.try_recv().expect("legacy peer got the handshake on lo");
        assert_eq!(received, forwarded);
    }

    /// A policy-denied pair forwards nothing (relay is never an ACL bypass).
    #[tokio::test]
    async fn route_uplink_denies_isolated_pair() {
        let c = coordinator();
        let _ = c
            .register(req(1, "a", "a", &["tag:user-a"]))
            .await
            .expect("a");
        let _ = c
            .register(req(3, "b", "b", &["tag:user-b"]))
            .await
            .expect("b");
        let a_pubkey = [1u8; 32];
        let b_pubkey = [3u8; 32];

        let (b_lo, mut b_rx) = mpsc::channel(16);
        c.relay().register(&b_pubkey, Lane::Lo, b_lo);

        let uplink = encode_relay_frame(&b_pubkey, b"ping");
        assert!(route_uplink(&c, &a_pubkey, &uplink).is_none());
        assert!(
            b_rx.try_recv().is_err(),
            "isolated dst must receive nothing"
        );
    }

    /// An unknown destination (not a registered peer) forwards nothing.
    #[tokio::test]
    async fn route_uplink_drops_unknown_destination() {
        let c = coordinator();
        let _ = c
            .register(req(1, "a", "a", &["tag:user-a"]))
            .await
            .expect("a");
        let a_pubkey = [1u8; 32];
        let unknown = [9u8; 32];
        let uplink = encode_relay_frame(&unknown, b"ping");
        assert!(route_uplink(&c, &a_pubkey, &uplink).is_none());
    }

    /// A too-short frame (< 33 bytes) is ignored.
    #[tokio::test]
    async fn route_uplink_ignores_short_frame() {
        let c = coordinator();
        let _ = c
            .register(req(1, "a", "a", &["tag:user-a"]))
            .await
            .expect("a");
        let a_pubkey = [1u8; 32];
        assert!(route_uplink(&c, &a_pubkey, &[0u8; 10]).is_none());
    }

    /// The `?lane=` contract: only the exact string [`LANE_HI`] selects the hi
    /// lane; the lo wire value, an unknown string, and ABSENCE (legacy joiner)
    /// all degrade to `Lo` — never a rejection. The `LANE_HI` literal is pinned
    /// here so a drift from the joiner's copy fails a test rather than silently
    /// reviving the bug.
    #[test]
    fn parse_lane_maps_only_hi_to_hi_else_legacy_lo() {
        assert_eq!(LANE_HI, "hi", "the hi wire value must match the joiner");
        assert_eq!(parse_lane(Some("hi")), Lane::Hi);
        assert_eq!(parse_lane(Some("lo")), Lane::Lo);
        assert_eq!(parse_lane(None), Lane::Lo, "legacy no-lane → lo");
        assert_eq!(parse_lane(Some("garbage")), Lane::Lo, "unknown → lo, never reject");
    }
}
