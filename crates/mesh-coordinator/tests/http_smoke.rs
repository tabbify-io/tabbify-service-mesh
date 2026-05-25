//! End-to-end HTTP smoke test: spin the axum router on a random port,
//! drive it with reqwest, and verify register → peers → heartbeat →
//! deregister against the canonical wire contract.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use base64::Engine;
use serde_json::Value;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tabbify_mesh_coordinator::{
    AclRule, Coordinator, NoopPublisher, Policy, PolicyStore, build_router,
};

fn pubkey(seed: u8) -> String {
    base64::engine::general_purpose::STANDARD.encode([seed; 32])
}

/// Permissive policy used by the peer-contract smoke tests: every node can
/// see every other (`* → *`). ACL filtering itself is covered by the
/// dedicated `policy_*` / roster-filter tests; here we exercise the
/// register/heartbeat/deregister/SSE *wire contract* without ACL hiding
/// peers from each other.
fn permissive_policy() -> Policy {
    Policy::new(vec![AclRule::accept(&["*"], &["*"])])
}

async fn spawn_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let coord = Coordinator::with_policy(
        Arc::new(NoopPublisher),
        Duration::from_secs(60),
        PolicyStore::new(permissive_policy()),
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

async fn post_json(client: &reqwest::Client, url: &str, body: Value) -> reqwest::Response {
    client
        .post(url)
        .json(&body)
        .send()
        .await
        .expect("post send")
}

async fn json_body(resp: reqwest::Response) -> Value {
    resp.json().await.expect("json decode")
}

#[tokio::test]
async fn http_register_round_trip_is_idempotent_per_pubkey() {
    let (addr, _server) = spawn_server().await;
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();

    let body = json_body(
        post_json(
            &client,
            &format!("{base}/v1/mesh/register"),
            serde_json::json!({
                "wg_public_key": pubkey(1),
                "listen_endpoint": "127.0.0.1:51820",
                "display_name": "alice",
                "tags": ["dev-machine"],
            }),
        )
        .await,
    )
    .await;
    let peer_id_a = body["peer_id"].as_str().expect("peer_id").to_owned();
    let ula_a = body["ula"].as_str().expect("ula").to_owned();
    // Default (unnamed) network → network slot 0 → fd5a:1f00:0:<idx>::1.
    assert!(
        ula_a.starts_with("fd5a:1f00:0:"),
        "unexpected ULA layout: {ula_a}",
    );
    // The register response excludes the registrant itself, so the very
    // first peer sees an empty roster.
    assert_eq!(body["peers"].as_array().expect("peers").len(), 0);

    // Re-register with the same pubkey returns the same peer_id + ULA.
    let body = json_body(
        post_json(
            &client,
            &format!("{base}/v1/mesh/register"),
            serde_json::json!({
                "wg_public_key": pubkey(1),
                "listen_endpoint": "127.0.0.1:51821",
                "display_name": "alice-renamed",
                "tags": ["renamed"],
            }),
        )
        .await,
    )
    .await;
    assert_eq!(body["peer_id"].as_str().expect("peer_id"), peer_id_a);
    assert_eq!(body["ula"].as_str().expect("ula"), ula_a);
    assert_eq!(
        body["peers"].as_array().expect("peers").len(),
        0,
        "still only self in roster (excluded) after idempotent re-register",
    );
}

#[tokio::test]
async fn http_heartbeat_and_deregister_flow() {
    let (addr, _server) = spawn_server().await;
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();

    // Register two peers so we can distinguish remove-A from delete-all.
    let body = json_body(
        post_json(
            &client,
            &format!("{base}/v1/mesh/register"),
            serde_json::json!({
                "wg_public_key": pubkey(1),
                "display_name": "alice",
                "tags": [],
            }),
        )
        .await,
    )
    .await;
    let peer_id_a = body["peer_id"].as_str().expect("peer_a").to_owned();

    let body = json_body(
        post_json(
            &client,
            &format!("{base}/v1/mesh/register"),
            serde_json::json!({
                "wg_public_key": pubkey(2),
                "display_name": "bob",
                "tags": [],
            }),
        )
        .await,
    )
    .await;
    let peer_id_b = body["peer_id"].as_str().expect("peer_b").to_owned();

    // Heartbeat for known peer returns roster.
    let resp = post_json(
        &client,
        &format!("{base}/v1/mesh/heartbeat"),
        serde_json::json!({ "peer_id": peer_id_a }),
    )
    .await;
    assert_eq!(resp.status(), 200);
    let body = json_body(resp).await;
    // Heartbeat roster is ACL-filtered + self-excluded: A sees only B.
    assert_eq!(body["peers"].as_array().expect("peers").len(), 1);

    // Heartbeat for unknown peer returns 404.
    let bogus = uuid::Uuid::now_v7().to_string();
    let resp = post_json(
        &client,
        &format!("{base}/v1/mesh/heartbeat"),
        serde_json::json!({ "peer_id": bogus }),
    )
    .await;
    assert_eq!(resp.status(), 404);

    // GET snapshot path.
    let resp = client
        .get(format!("{base}/v1/mesh/peers"))
        .send()
        .await
        .expect("get peers");
    assert_eq!(resp.status(), 200);
    let body = json_body(resp).await;
    assert_eq!(body["peers"].as_array().expect("peers").len(), 2);

    // Deregister A (then again, idempotent 204).
    for _ in 0..2 {
        let resp = post_json(
            &client,
            &format!("{base}/v1/mesh/deregister"),
            serde_json::json!({ "peer_id": peer_id_a }),
        )
        .await;
        assert_eq!(resp.status(), 204);
    }

    let resp = client
        .get(format!("{base}/v1/mesh/peers"))
        .send()
        .await
        .expect("get peers final");
    let body = json_body(resp).await;
    let peers = body["peers"].as_array().expect("peers");
    assert_eq!(peers.len(), 1, "only peer B should remain");
    assert_eq!(peers[0]["peer_id"].as_str().expect("peer_id"), peer_id_b);
}

/// End-to-end reflexive-endpoint wire contract over a real TCP socket
/// (so `ConnectInfo` is populated). The connection is loopback, so the
/// observed source IP is `127.0.0.1` (private) — the reflexive override
/// does NOT fire and a self-reported PUBLIC endpoint is preserved while
/// the response still echoes the peer its observed IP. This locks the new
/// `wg_listen_port` request field + `observed_ip` / `observed_endpoint`
/// response fields through the HTTP layer. (The reflexive *rewrite* itself
/// can't be exercised over loopback; it is covered by the coordinator unit
/// tests that inject a synthetic public observed addr.)
#[tokio::test]
async fn http_register_reflects_observed_fields() {
    let (addr, _server) = spawn_server().await;
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();

    // Register with an explicit PUBLIC advertise-endpoint + a WG port.
    let body = json_body(
        post_json(
            &client,
            &format!("{base}/v1/mesh/register"),
            serde_json::json!({
                "wg_public_key": pubkey(1),
                "listen_endpoint": "203.0.113.50:51820",
                "wg_listen_port": 51820,
                "display_name": "public-peer",
                "tags": ["dev-machine"],
            }),
        )
        .await,
    )
    .await;
    let peer_id = body["peer_id"].as_str().expect("peer_id").to_owned();
    // The coordinator echoes our observed source IP (loopback over a local
    // TCP connection) ...
    assert_eq!(
        body["observed_ip"].as_str(),
        Some("127.0.0.1"),
        "observed_ip should echo the loopback source: {body}"
    );
    // ... and the stored reflexive endpoint, which here equals the
    // self-reported PUBLIC endpoint (preserved, not clobbered).
    assert_eq!(
        body["observed_endpoint"].as_str(),
        Some("203.0.113.50:51820"),
        "explicit public advertise-endpoint must be preserved: {body}"
    );

    // The peer's roster entry carries that same endpoint for other peers.
    let resp = client
        .get(format!("{base}/v1/mesh/peers"))
        .send()
        .await
        .expect("get peers");
    let body = json_body(resp).await;
    let peer = &body["peers"].as_array().expect("peers")[0];
    assert_eq!(peer["listen_endpoint"].as_str(), Some("203.0.113.50:51820"));

    // Heartbeat carrying wg_listen_port must succeed + echo observed_ip.
    let resp = post_json(
        &client,
        &format!("{base}/v1/mesh/heartbeat"),
        serde_json::json!({ "peer_id": peer_id, "wg_listen_port": 51820 }),
    )
    .await;
    assert_eq!(resp.status(), 200);
    let hb = json_body(resp).await;
    assert_eq!(hb["observed_ip"].as_str(), Some("127.0.0.1"));
    assert_eq!(hb["observed_endpoint"].as_str(), Some("203.0.113.50:51820"));
}

/// Back-compat: a register body WITHOUT the new `wg_listen_port` field (an
/// older joiner) must still succeed and behave as before — the field is
/// `#[serde(default)]`.
#[tokio::test]
async fn http_register_back_compat_without_wg_port() {
    let (addr, _server) = spawn_server().await;
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();

    let resp = post_json(
        &client,
        &format!("{base}/v1/mesh/register"),
        // No wg_listen_port, no listen_endpoint — pre-NAT-traversal shape.
        serde_json::json!({
            "wg_public_key": pubkey(2),
            "display_name": "legacy",
            "tags": [],
        }),
    )
    .await;
    assert_eq!(resp.status(), 200, "old-shape register must still work");
    let body = json_body(resp).await;
    assert!(body["peer_id"].as_str().is_some());
    // No self-report, observed is loopback (private), no port → passive.
    assert!(
        body["observed_endpoint"].is_null() || body.get("observed_endpoint").is_none(),
        "no endpoint derivable → passive: {body}"
    );
}

#[tokio::test]
async fn sse_stream_bootstraps_existing_peers() {
    let (addr, _server) = spawn_server().await;
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();

    // Pre-register one peer so the SSE bootstrap has something to deliver.
    let _ = post_json(
        &client,
        &format!("{base}/v1/mesh/register"),
        serde_json::json!({
            "wg_public_key": pubkey(9),
            "display_name": "preexisting",
            "tags": [],
        }),
    )
    .await;

    let mut resp = client
        .get(format!("{base}/v1/mesh/peers/stream"))
        .header("accept", "text/event-stream")
        .send()
        .await
        .expect("get stream");
    assert_eq!(resp.status(), 200);

    let mut buf = String::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while tokio::time::Instant::now() < deadline {
        // We only react to a successful chunk; timeout / IO errors fall
        // through and the outer loop retries until the deadline.
        if let Ok(Ok(Some(chunk))) =
            tokio::time::timeout(Duration::from_millis(300), resp.chunk()).await
        {
            buf.push_str(&String::from_utf8_lossy(&chunk));
        }
        if buf.contains("peer_added") && buf.contains("preexisting") {
            break;
        }
    }
    assert!(
        buf.contains("event: peer_added"),
        "expected peer_added SSE event in {buf:?}",
    );
    assert!(
        buf.contains("preexisting"),
        "expected display_name in SSE payload: {buf:?}",
    );
}
