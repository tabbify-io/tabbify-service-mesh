//! Cross-crate relay integration test: drives the REAL `/v1/mesh/relay`
//! WebSocket endpoint over a loopback TCP socket with a real WS client
//! (`tokio-tungstenite`, the same crate + feature set the joiner relay
//! client uses).
//!
//! Two acceptance properties of the relay wire contract (spec Stage 3):
//! - **forward + source rewrite**: an uplink frame from A addressed to B is
//!   delivered to B's socket with the 32-byte prefix REWRITTEN to A's
//!   pubkey (so the receiver demuxes by source) and the payload intact.
//! - **ACL enforcement**: a frame from an isolated peer C addressed to A is
//!   dropped — A receives nothing (the relay is never an ACL bypass).
//!
//! The router, registration, and policy setup mirror `policy_acl.rs` /
//! `http_smoke.rs`; the only addition is opening genuine WebSocket
//! connections and asserting the exact bytes on the wire.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use base64::Engine;
use futures::{SinkExt, StreamExt};
use serde_json::Value;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tabbify_mesh_coordinator::{
    AclRule, Coordinator, NoopPublisher, Policy, PolicyStore, build_router,
    relay::encode_relay_frame,
};
use tokio_tungstenite::tungstenite::Message;

/// Per-test hard timeout: any hang (lost frame, never-completing recv) fails
/// fast instead of stalling the suite.
const TIMEOUT: Duration = Duration::from_secs(5);
/// Short window for asserting a frame is NOT delivered (ACL deny): a recv
/// that does not resolve within this budget proves nothing was forwarded.
const DENY_TIMEOUT: Duration = Duration::from_secs(1);

/// The 32-byte raw WG pubkey for a given seed (matches the base64 the test
/// registers with, so coordinator-side pubkey lookups resolve).
const fn raw_pubkey(seed: u8) -> [u8; 32] {
    [seed; 32]
}

fn pubkey_b64(seed: u8) -> String {
    base64::engine::general_purpose::STANDARD.encode(raw_pubkey(seed))
}

/// Policy mirroring `policy_acl.rs`: A (`tag:user-a`) and B (`tag:svc`) are
/// mutually visible; C (`tag:user-b`) has no edge to A or B (isolated).
fn relay_policy() -> Policy {
    Policy::new(vec![
        AclRule::accept(&["tag:user-a"], &["tag:svc"]),
        AclRule::accept(&["tag:svc"], &["tag:user-a"]),
    ])
}

async fn spawn() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    // No validator: `with_policy` trusts request-supplied tags, so register
    // needs no join token (same posture as the other integration tests).
    let coord = Coordinator::with_policy(
        Arc::new(NoopPublisher),
        Duration::from_secs(60),
        PolicyStore::new(relay_policy()),
    );
    let router = build_router(coord);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let handle = tokio::spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .expect("serve");
    });
    (addr, handle)
}

async fn register(
    client: &reqwest::Client,
    base: &str,
    seed: u8,
    name: &str,
    network: &str,
    tags: &[&str],
) -> Value {
    let resp = client
        .post(format!("{base}/v1/mesh/register"))
        .json(&serde_json::json!({
            "wg_public_key": pubkey_b64(seed),
            "display_name": name,
            "network": network,
            "tags": tags,
        }))
        .send()
        .await
        .expect("register send");
    assert_eq!(resp.status(), 200, "register {name}");
    resp.json().await.expect("register json")
}

/// Open a real relay WebSocket for `seed`'s registered pubkey.
async fn open_relay(
    addr: SocketAddr,
    seed: u8,
) -> tokio_tungstenite::WebSocketStream<
    tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
> {
    let url = format!(
        "ws://{addr}/v1/mesh/relay?pubkey={}",
        pubkey_b64(seed)
    );
    let (ws, _resp) = tokio::time::timeout(TIMEOUT, tokio_tungstenite::connect_async(url))
        .await
        .expect("relay WS connect did not time out")
        .expect("relay WS connected");
    ws
}

/// An allowed pair (A → B): the frame is forwarded and the coordinator
/// rewrites the 32-byte prefix to the SENDER's (A's) pubkey, payload intact.
#[tokio::test]
async fn relay_forwards_with_source_rewrite() {
    let (addr, _s) = spawn().await;
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();

    // A (user-a) and B (svc) are mutually visible; C (user-b) is isolated.
    let _ = register(&client, &base, 1, "a", "a", &["tag:user-a"]).await;
    let _ = register(&client, &base, 2, "b", "svc", &["tag:svc"]).await;
    let _ = register(&client, &base, 3, "c", "b", &["tag:user-b"]).await;

    let a_pubkey = raw_pubkey(1);
    let b_pubkey = raw_pubkey(2);

    let mut a_ws = open_relay(addr, 1).await;
    let mut b_ws = open_relay(addr, 2).await;

    // A sends an uplink frame addressed to B.
    let payload: &[u8] = b"ping-payload";
    a_ws.send(Message::Binary(encode_relay_frame(&b_pubkey, payload)))
        .await
        .expect("A uplink sent");

    // B must receive a binary frame whose prefix is rewritten to A's pubkey
    // and whose payload is the original bytes — i.e. exactly
    // `encode_relay_frame(&a_pubkey, payload)`.
    let expected = encode_relay_frame(&a_pubkey, payload);
    let got = recv_binary(&mut b_ws)
        .await
        .expect("B received a forwarded binary frame within the timeout");
    assert_eq!(
        got, expected,
        "downlink prefix must be rewritten to the SENDER (A) and payload preserved"
    );
}

/// An isolated peer (C) addressing A is dropped by the ACL — A receives
/// nothing. C's WS still upgrades (it is a registered peer), but no forward
/// crosses the policy boundary.
#[tokio::test]
async fn relay_denies_isolated_peer() {
    let (addr, _s) = spawn().await;
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();

    let _ = register(&client, &base, 1, "a", "a", &["tag:user-a"]).await;
    let _ = register(&client, &base, 2, "b", "svc", &["tag:svc"]).await;
    let _ = register(&client, &base, 3, "c", "b", &["tag:user-b"]).await;

    let a_pubkey = raw_pubkey(1);

    let mut a_ws = open_relay(addr, 1).await;
    let mut c_ws = open_relay(addr, 3).await;

    // C sends a frame addressed to A — the policy has no C→A edge.
    c_ws.send(Message::Binary(encode_relay_frame(&a_pubkey, b"should-be-dropped")))
        .await
        .expect("C uplink sent");

    // A must receive NOTHING: recv times out (no frame crossed the ACL).
    let result = tokio::time::timeout(DENY_TIMEOUT, recv_binary(&mut a_ws)).await;
    assert!(
        result.is_err(),
        "ACL-denied frame must not be delivered; A unexpectedly received: {result:?}"
    );
}

/// Read the next BINARY frame from a relay WS, skipping protocol pings/pongs
/// the coordinator emits as keepalive. Wrapped by the caller in a timeout so
/// a never-arriving frame fails fast. Returns `None` on clean close / end.
async fn recv_binary<S>(ws: &mut tokio_tungstenite::WebSocketStream<S>) -> Option<Vec<u8>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    loop {
        match ws.next().await {
            Some(Ok(Message::Binary(buf))) => return Some(buf),
            Some(Ok(Message::Ping(_) | Message::Pong(_) | Message::Text(_) | Message::Frame(_))) => {
                // Keepalive / non-relay frame — keep waiting for a binary.
            }
            // Clean close, stream end, or a transport error: no relay frame.
            Some(Ok(Message::Close(_)) | Err(_)) | None => return None,
        }
    }
}
