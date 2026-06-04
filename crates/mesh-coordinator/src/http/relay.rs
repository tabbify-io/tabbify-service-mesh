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

use crate::relay::{decode_relay_frame, encode_relay_frame};
use crate::roster::coordinator::Coordinator;
use base64::Engine as _;
// base64url (no padding): the pubkey rides in the URL query, where standard
// base64's `+`/`/` are unsafe (`+` decodes to a space). The joiner encodes the
// `?pubkey=` value with the SAME alphabet — keep these two in lockstep.
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::response::IntoResponse;
use futures::{SinkExt, StreamExt};
use std::time::Duration;
use tokio::sync::mpsc;

/// Keepalive cadence — mirrors the SSE `KeepAlive` interval. The send task
/// emits a `WebSocket` `Ping` this often; a dead connection is detected when
/// the sink errors and the connection is torn down.
const RELAY_PING_INTERVAL: Duration = Duration::from_secs(15);

/// Query string for the relay upgrade: the connecting peer's WG public key.
#[derive(serde::Deserialize)]
pub struct RelayQuery {
    /// base64url (URL-safe, no padding) of the connecting peer's 32-byte WG public key.
    pubkey: String,
}

/// Route one decoded uplink frame: decode → ACL-check → build the
/// source-rewritten downlink → forward to the destination's connection.
///
/// Pure and synchronous so the relay routing is unit-tested without a full
/// `WebSocket` upgrade. Returns the downlink frame that was forwarded
/// (`Some`) — `None` when the frame is too short, the pair is policy-denied,
/// or the destination has no live connection. `my_pubkey` is the registered
/// pubkey of the connection that sent `buf`; it becomes the downlink prefix.
pub fn route_uplink(coordinator: &Coordinator, my_pubkey: &[u8; 32], buf: &[u8]) -> Option<Vec<u8>> {
    let (dst, payload) = decode_relay_frame(buf)?;
    if !coordinator.can_relay(my_pubkey, &dst) {
        tracing::warn!(
            src = %B64URL.encode(my_pubkey),
            dst = %B64URL.encode(dst),
            "relay: ACL denied — frame dropped"
        );
        return None;
    }
    let downlink = encode_relay_frame(my_pubkey, payload);
    if coordinator.relay().forward(&dst, downlink.clone()) {
        tracing::debug!(
            src = %B64URL.encode(my_pubkey),
            dst = %B64URL.encode(dst),
            len = downlink.len(),
            "relay: forwarded"
        );
        Some(downlink)
    } else {
        // Destination has no live relay connection — nothing forwarded.
        tracing::warn!(
            src = %B64URL.encode(my_pubkey),
            dst = %B64URL.encode(dst),
            "relay: destination has no live connection — frame dropped"
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
    ws.on_upgrade(move |socket| relay_conn(coordinator, my_pubkey, socket))
}

/// Per-connection loop: register the sender, then split the socket into a
/// send-task (drains the registry channel + emits keepalive pings) and a
/// recv-loop (decodes uplink frames and forwards them). Cleans up on exit.
async fn relay_conn(coordinator: Coordinator, my_pubkey: [u8; 32], socket: WebSocket) {
    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let id = coordinator.relay().register(my_pubkey.to_vec(), tx);
    tracing::info!(pubkey = %B64URL.encode(my_pubkey), conn_id = id, "relay: peer connected");
    let (mut sink, mut stream) = socket.split();

    // Send task: forward downlink frames + heartbeat pings to the peer.
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

    // Recv loop: decode uplink frames and forward them to the destination.
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

    // Tear down: drop our registry entry (only if still ours) + stop the
    // send task so its sink half is released.
    coordinator.relay().unregister(&my_pubkey, id);
    tracing::info!(pubkey = %B64URL.encode(my_pubkey), conn_id = id, "relay: peer disconnected");
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
            relay_only: false,
        }
    }

    /// An allowed pair: A uplinks to B; B's registered relay conn receives the
    /// source-rewritten downlink (`A`-prefixed) carrying the same payload.
    #[tokio::test]
    async fn route_uplink_forwards_allowed_pair_with_source_rewrite() {
        let c = coordinator();
        let _ = c.register(req(1, "a", "a", &["tag:user-a"])).await.expect("a");
        let _ = c.register(req(2, "b", "svc", &["tag:svc"])).await.expect("b");
        let a_pubkey = [1u8; 32];
        let b_pubkey = [2u8; 32];

        let (b_tx, mut b_rx) = mpsc::unbounded_channel();
        c.relay().register(b_pubkey.to_vec(), b_tx);

        let uplink = encode_relay_frame(&b_pubkey, b"ping");
        let forwarded = route_uplink(&c, &a_pubkey, &uplink).expect("forwarded");
        // Downlink prefix is the SOURCE pubkey (A), payload preserved.
        assert_eq!(&forwarded[..32], &a_pubkey);
        assert_eq!(&forwarded[32..], b"ping");
        let received = b_rx.try_recv().expect("b received the downlink");
        assert_eq!(received, forwarded);
    }

    /// A policy-denied pair forwards nothing (relay is never an ACL bypass).
    #[tokio::test]
    async fn route_uplink_denies_isolated_pair() {
        let c = coordinator();
        let _ = c.register(req(1, "a", "a", &["tag:user-a"])).await.expect("a");
        let _ = c.register(req(3, "b", "b", &["tag:user-b"])).await.expect("b");
        let a_pubkey = [1u8; 32];
        let b_pubkey = [3u8; 32];

        let (b_tx, mut b_rx) = mpsc::unbounded_channel();
        c.relay().register(b_pubkey.to_vec(), b_tx);

        let uplink = encode_relay_frame(&b_pubkey, b"ping");
        assert!(route_uplink(&c, &a_pubkey, &uplink).is_none());
        assert!(b_rx.try_recv().is_err(), "isolated dst must receive nothing");
    }

    /// An unknown destination (not a registered peer) forwards nothing.
    #[tokio::test]
    async fn route_uplink_drops_unknown_destination() {
        let c = coordinator();
        let _ = c.register(req(1, "a", "a", &["tag:user-a"])).await.expect("a");
        let a_pubkey = [1u8; 32];
        let unknown = [9u8; 32];
        let uplink = encode_relay_frame(&unknown, b"ping");
        assert!(route_uplink(&c, &a_pubkey, &uplink).is_none());
    }

    /// A too-short frame (< 33 bytes) is ignored.
    #[tokio::test]
    async fn route_uplink_ignores_short_frame() {
        let c = coordinator();
        let _ = c.register(req(1, "a", "a", &["tag:user-a"])).await.expect("a");
        let a_pubkey = [1u8; 32];
        assert!(route_uplink(&c, &a_pubkey, &[0u8; 10]).is_none());
    }
}
