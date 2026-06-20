//! End-to-end HTTP smoke for the Track-C admin command API: admin-gated POST
//! enqueue + GET status. The coordinator relays an already-signed body; it
//! never verifies the signature (that is the node's job).
//!
//! Same shape as `http_smoke.rs` — spin the axum router on a random port and
//! drive it with reqwest — so the test exercises the real wire contract
//! (router wiring + the fail-closed admin gate) end to end.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use base64::Engine;
use serde_json::Value;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tabbify_mesh_coordinator::{
    AclRule, Coordinator, NoopPublisher, Policy, PolicyStore, build_router_with_admin,
};

const ADMIN: &str = "test-admin-token";

fn pubkey(seed: u8) -> String {
    base64::engine::general_purpose::STANDARD.encode([seed; 32])
}

fn permissive_policy() -> Policy {
    Policy::new(vec![AclRule::accept(&["*"], &["*"])])
}

/// Spin a coordinator with the admin command API enabled (admin token set).
async fn spawn_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let coord = Coordinator::with_policy(
        Arc::new(NoopPublisher),
        Duration::from_secs(60),
        PolicyStore::new(permissive_policy()),
    );
    let router = build_router_with_admin(coord, Some(ADMIN.to_owned()));
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

/// Register a peer through the public roster API + return its id string.
async fn register_peer(client: &reqwest::Client, base: &str) -> String {
    let resp: Value = client
        .post(format!("{base}/v1/mesh/register"))
        .json(&serde_json::json!({
            "wg_public_key": pubkey(3),
            "listen_endpoint": "127.0.0.1:51820",
            "display_name": "node-1",
            "tags": [],
        }))
        .send()
        .await
        .expect("register send")
        .json()
        .await
        .expect("register json");
    resp["peer_id"].as_str().expect("peer_id").to_owned()
}

#[tokio::test]
async fn post_command_requires_admin_token() {
    let (addr, _server) = spawn_server().await;
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();
    let peer = register_peer(&client, &base).await;

    // No bearer → 401 (fail-closed).
    let res = client
        .post(format!("{base}/v1/mesh/peers/{peer}/commands"))
        .json(&serde_json::json!({
            "command_id": "c1",
            "verb": "restart_joiner",
            "peer_id": "x",
            "nonce": "n",
            "issued_at": 1,
            "expiry": 9_999_999_999_999i64,
            "signature": "ab",
        }))
        .send()
        .await
        .expect("post send");
    assert_eq!(res.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn post_then_get_shows_pending_command() {
    let (addr, _server) = spawn_server().await;
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();
    let peer = register_peer(&client, &base).await;

    let res = client
        .post(format!("{base}/v1/mesh/peers/{peer}/commands"))
        .bearer_auth(ADMIN)
        .json(&serde_json::json!({
            "command_id": "c1",
            "verb": "restart_joiner",
            "peer_id": peer,
            "nonce": "n1",
            "issued_at": 1,
            "expiry": 9_999_999_999_999i64,
            "signature": "ab",
        }))
        .send()
        .await
        .expect("post send");
    assert_eq!(res.status(), reqwest::StatusCode::ACCEPTED);

    // GET status shows the pending command_id.
    let res = client
        .get(format!("{base}/v1/mesh/peers/{peer}/commands"))
        .bearer_auth(ADMIN)
        .send()
        .await
        .expect("get send");
    assert_eq!(res.status(), reqwest::StatusCode::OK);
    let json: Value = res.json().await.expect("get json");
    assert_eq!(json["pending"][0], "c1");
}

/// GET status is admin-gated too — no token → 401.
#[tokio::test]
async fn get_commands_requires_admin_token() {
    let (addr, _server) = spawn_server().await;
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();
    let peer = register_peer(&client, &base).await;

    let res = client
        .get(format!("{base}/v1/mesh/peers/{peer}/commands"))
        .send()
        .await
        .expect("get send");
    assert_eq!(res.status(), reqwest::StatusCode::UNAUTHORIZED);
}
