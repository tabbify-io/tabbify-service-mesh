//! HTTP integration: join-token validation on `POST /v1/mesh/register`
//! (spec §8 / E4).
//!
//! Drives the real axum router (with a configured [`AuthValidator`])
//! against a `wiremock` fake auth service, exercising the full path:
//! joiner `Authorization: Bearer` header → coordinator → auth `/v1/validate`
//! → admit-with-claims / 401-reject. This complements the unit tests in
//! `roster::coordinator::jwt_tests` by proving the HTTP header extraction
//! + status mapping, not just the in-process method.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use base64::Engine;
use serde_json::Value;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tabbify_mesh_coordinator::{
    AclRule, AuthValidator, Coordinator, NoopPublisher, Policy, PolicyStore,
    build_router_with_admin,
};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn pubkey(seed: u8) -> String {
    base64::engine::general_purpose::STANDARD.encode([seed; 32])
}

fn permissive() -> PolicyStore {
    PolicyStore::new(Policy::new(vec![AclRule::accept(&["*"], &["*"])]))
}

/// Spawn the coordinator HTTP server with a join-token validator pointing
/// at `auth_uri`.
/// Admin bearer for reading the roster back (`GET /v1/mesh/peers` is
/// admin-gated — it spans every tenant). Unrelated to the join JWT under
/// test here, which authenticates REGISTER.
const ADMIN_TOKEN: &str = "jwt-test-admin-token";

async fn spawn_with_validator(auth_uri: &str) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let validator = AuthValidator::new(auth_uri).unwrap();
    let coord = Coordinator::with_policy_and_validator(
        Arc::new(NoopPublisher),
        Duration::from_secs(60),
        permissive(),
        Some(validator),
    );
    let router = build_router_with_admin(coord, Some(ADMIN_TOKEN.to_owned()));
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

async fn mock_validate(server: &MockServer, body: Value) {
    Mock::given(method("POST"))
        .and(path("/v1/validate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(server)
        .await;
}

/// Valid Bearer token → 200, and the registered node's tags + network in
/// the response roster come from the CLAIMS even though the request asked
/// for something else.
#[tokio::test]
async fn register_with_valid_bearer_admits_with_claims() {
    let auth = MockServer::start().await;
    mock_validate(
        &auth,
        serde_json::json!({
            "valid": true,
            "subject": "node-alice",
            "network": "alice",
            "tags": ["tag:user-alice"],
            "kind": "join",
            "exp": 1_900_000_000_i64,
        }),
    )
    .await;
    let (addr, _server) = spawn_with_validator(&auth.uri()).await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("http://{addr}/v1/mesh/register"))
        .bearer_auth("good-join-token")
        .json(&serde_json::json!({
            "wg_public_key": pubkey(1),
            "display_name": "alice",
            // Spoofed: request asks for bob + admin, must be ignored.
            "network": "bob",
            "tags": ["tag:user-bob", "tag:admin"],
        }))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 200);

    // The registrant is excluded from its own roster, so to observe the
    // stamped tags we read them back via GET /v1/mesh/peers (unfiltered).
    let peers: Value = client
        .get(format!("http://{addr}/v1/mesh/peers"))
        .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
        .send()
        .await
        .expect("get peers")
        .json()
        .await
        .expect("json");
    let entry = &peers["peers"][0];
    assert_eq!(
        entry["tags"],
        serde_json::json!(["tag:user-alice"]),
        "tags must come from claims, not the spoofed request"
    );
    assert_eq!(
        entry["network"], "alice",
        "network must come from claims, not the spoofed request"
    );
}

/// `valid: false` from the auth service → the register is rejected with
/// HTTP 401 and nothing lands in the roster.
#[tokio::test]
async fn register_with_revoked_bearer_is_401() {
    let auth = MockServer::start().await;
    mock_validate(
        &auth,
        serde_json::json!({
            "valid": false,
            "subject": "",
            "network": "",
            "tags": [],
            "kind": "join",
            "exp": 0,
        }),
    )
    .await;
    let (addr, _server) = spawn_with_validator(&auth.uri()).await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("http://{addr}/v1/mesh/register"))
        .bearer_auth("revoked-token")
        .json(&serde_json::json!({
            "wg_public_key": pubkey(2),
            "display_name": "mallory",
            "tags": [],
        }))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 401);

    let peers: Value = client
        .get(format!("http://{addr}/v1/mesh/peers"))
        .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
        .send()
        .await
        .expect("get peers")
        .json()
        .await
        .expect("json");
    assert_eq!(
        peers["peers"].as_array().expect("peers").len(),
        0,
        "rejected register must leave no roster state"
    );
}

/// No `Authorization` header at all, with a validator configured → 401.
#[tokio::test]
async fn register_without_bearer_is_401_when_validator_configured() {
    // The auth service should never be hit; start one anyway for a valid URL.
    let auth = MockServer::start().await;
    let (addr, _server) = spawn_with_validator(&auth.uri()).await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("http://{addr}/v1/mesh/register"))
        .json(&serde_json::json!({
            "wg_public_key": pubkey(3),
            "display_name": "no-token",
            "tags": [],
        }))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 401);
}
