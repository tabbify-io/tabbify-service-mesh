//! HTTP integration tests for the ACL feature (spec §5, §7).
//!
//! Two areas:
//! - **Policy admin API** — `GET`/`PUT` `/v1/policy`, admin-token auth
//!   (401), `ETag` optimistic concurrency (412), and that a successful
//!   `PUT` converges connected SSE subscribers.
//! - **Roster filtering** — the `register` response and the `peers/stream`
//!   SSE only reveal policy-permitted peers, with the two-user +
//!   shared-service isolation scenario asserted end-to-end over HTTP.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use base64::Engine;
use serde_json::Value;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tabbify_mesh_coordinator::{
    AclRule, Coordinator, NoopPublisher, Policy, PolicyStore, build_router_with_admin,
};

const ADMIN_TOKEN: &str = "s3cret-admin-token";

fn pubkey(seed: u8) -> String {
    base64::engine::general_purpose::STANDARD.encode([seed; 32])
}

/// The §5 two-scenario policy: each user-group sees itself, every user
/// reaches `tag:svc`, distinct user-groups have no edge (mutual deny).
fn shared_service_policy() -> Policy {
    Policy::new(vec![
        AclRule::accept(&["tag:user-a"], &["tag:user-a"]),
        AclRule::accept(&["tag:user-b"], &["tag:user-b"]),
        AclRule::accept(&["tag:user-*"], &["tag:svc"]),
    ])
}

async fn spawn(
    policy: Policy,
    admin_token: Option<String>,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let coord = Coordinator::with_policy(
        Arc::new(NoopPublisher),
        Duration::from_secs(60),
        PolicyStore::new(policy),
    );
    let router = build_router_with_admin(coord, admin_token);
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
            "wg_public_key": pubkey(seed),
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

fn peer_names(body: &Value) -> Vec<String> {
    body["peers"]
        .as_array()
        .expect("peers array")
        .iter()
        .map(|p| p["display_name"].as_str().expect("name").to_owned())
        .collect()
}

// ---------------------------------------------------------------------
// Roster filtering over HTTP (acceptance: isolation).
// ---------------------------------------------------------------------

#[tokio::test]
async fn register_response_is_acl_filtered_isolation() {
    let (addr, _s) = spawn(shared_service_policy(), None).await;
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();

    // Seed svc + a1 + b1 first, then register a2 and b2 and inspect THEIR
    // responses (whose roster reflects everyone registered so far).
    let _svc = register(&client, &base, 4, "svc1", "svc", &["tag:svc"]).await;
    let _a1 = register(&client, &base, 1, "a1", "a", &["tag:user-a"]).await;
    let _b1 = register(&client, &base, 3, "b1", "b", &["tag:user-b"]).await;

    // a2 registers: must see a1 + svc, never b1.
    let a2 = register(&client, &base, 2, "a2", "a", &["tag:user-a"]).await;
    let a2_peers = peer_names(&a2);
    assert!(
        a2_peers.contains(&"a1".to_owned()),
        "a2 sees a1: {a2_peers:?}"
    );
    assert!(
        a2_peers.contains(&"svc1".to_owned()),
        "a2 sees svc: {a2_peers:?}"
    );
    assert!(
        !a2_peers.contains(&"b1".to_owned()),
        "a2 must NOT see b1: {a2_peers:?}"
    );
    assert!(
        !a2_peers.contains(&"a2".to_owned()),
        "a2 not in its own roster"
    );

    // b2 registers: must see b1 + svc, never a1/a2 (symmetric isolation).
    let b2 = register(&client, &base, 5, "b2", "b", &["tag:user-b"]).await;
    let b2_peers = peer_names(&b2);
    assert!(
        b2_peers.contains(&"b1".to_owned()),
        "b2 sees b1: {b2_peers:?}"
    );
    assert!(
        b2_peers.contains(&"svc1".to_owned()),
        "b2 sees svc: {b2_peers:?}"
    );
    assert!(
        !b2_peers.contains(&"a1".to_owned()),
        "b2 must NOT see a1: {b2_peers:?}"
    );
    assert!(
        !b2_peers.contains(&"a2".to_owned()),
        "b2 must NOT see a2: {b2_peers:?}"
    );
}

#[tokio::test]
async fn sse_stream_is_acl_filtered_per_viewer() {
    let (addr, _s) = spawn(shared_service_policy(), None).await;
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();

    // Register a1 (the viewer), a2 (visible), b1 (denied), svc (visible).
    let a1 = register(&client, &base, 1, "a1", "a", &["tag:user-a"]).await;
    let _a2 = register(&client, &base, 2, "a2", "a", &["tag:user-a"]).await;
    let _b1 = register(&client, &base, 3, "b1", "b", &["tag:user-b"]).await;
    let _svc = register(&client, &base, 4, "svc1", "svc", &["tag:svc"]).await;
    let a1_id = a1["peer_id"].as_str().expect("a1 id").to_owned();

    // Open a1's filtered SSE stream (viewer identified by ?peer_id).
    let mut resp = client
        .get(format!("{base}/v1/mesh/peers/stream?peer_id={a1_id}"))
        .header("accept", "text/event-stream")
        .send()
        .await
        .expect("stream");
    assert_eq!(resp.status(), 200);

    // Match on the precise `"display_name":"<name>"` token rather than a
    // bare substring: a bare `"b1"` (etc.) can collide with the random hex
    // of a peer_id UUID v7 in the payload, which made this assertion
    // intermittently false-positive. Keying on the display_name field is
    // exact and stable.
    let has_name = |b: &str, n: &str| b.contains(&format!("\"display_name\":\"{n}\""));
    let buf = read_sse_until(&mut resp, |b| has_name(b, "svc1") && has_name(b, "a2"), 2).await;
    assert!(has_name(&buf, "a2"), "a1 stream must include a2: {buf}");
    assert!(has_name(&buf, "svc1"), "a1 stream must include svc: {buf}");
    assert!(
        !has_name(&buf, "b1"),
        "a1 stream must NOT include b1: {buf}"
    );
    assert!(!has_name(&buf, "a1"), "a1 not in own stream");
}

#[tokio::test]
async fn policy_put_converges_sse_subscribers() {
    // Start permissive-for-a-only, then widen to include svc and observe
    // the new peer arrive on an already-open stream after PUT.
    let initial = Policy::new(vec![AclRule::accept(&["tag:user-a"], &["tag:user-a"])]);
    let (addr, _s) = spawn(initial, Some(ADMIN_TOKEN.to_owned())).await;
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();

    let a1 = register(&client, &base, 1, "a1", "a", &["tag:user-a"]).await;
    let _svc = register(&client, &base, 4, "svc1", "svc", &["tag:svc"]).await;
    let a1_id = a1["peer_id"].as_str().expect("a1 id").to_owned();

    // Open a1's stream; svc must NOT be visible yet (no user→svc edge).
    let mut resp = client
        .get(format!("{base}/v1/mesh/peers/stream?peer_id={a1_id}"))
        .header("accept", "text/event-stream")
        .send()
        .await
        .expect("stream");
    // Drain the initial burst briefly; svc should be absent.
    let early = read_sse_until(&mut resp, |_| false, 1).await;
    assert!(
        !early.contains("svc1"),
        "svc must be hidden before PUT: {early}"
    );

    // Fetch current ETag, then widen the policy to add user-*→svc.
    let get = client
        .get(format!("{base}/v1/policy"))
        .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
        .send()
        .await
        .expect("get policy");
    let etag = get
        .headers()
        .get("etag")
        .expect("etag header")
        .to_str()
        .unwrap()
        .to_owned();

    let put = client
        .put(format!("{base}/v1/policy"))
        .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
        .header("if-match", &etag)
        .json(&serde_json::json!({
            "acls": [
                { "action": "accept", "src": ["tag:user-a"], "dst": ["tag:user-a"] },
                { "action": "accept", "src": ["tag:user-*"], "dst": ["tag:svc"] }
            ]
        }))
        .send()
        .await
        .expect("put policy");
    assert_eq!(put.status(), 200, "policy PUT should succeed");

    // After PUT, the coordinator resyncs; svc should now arrive on the
    // already-open stream as a peer_added frame.
    let after = read_sse_until(&mut resp, |b| b.contains("svc1"), 3).await;
    assert!(
        after.contains("svc1"),
        "svc must converge onto the open stream after PUT: {after}"
    );
}

// ---------------------------------------------------------------------
// Policy admin API: auth + ETag concurrency.
// ---------------------------------------------------------------------

#[tokio::test]
async fn get_policy_requires_admin_token() {
    let (addr, _s) = spawn(shared_service_policy(), Some(ADMIN_TOKEN.to_owned())).await;
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();

    // No token → 401.
    let resp = client
        .get(format!("{base}/v1/policy"))
        .send()
        .await
        .expect("get");
    assert_eq!(resp.status(), 401, "missing token must be 401");

    // Wrong token → 401.
    let resp = client
        .get(format!("{base}/v1/policy"))
        .header("authorization", "Bearer wrong")
        .send()
        .await
        .expect("get");
    assert_eq!(resp.status(), 401, "wrong token must be 401");

    // Correct token → 200 + ETag + policy body.
    let resp = client
        .get(format!("{base}/v1/policy"))
        .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
        .send()
        .await
        .expect("get");
    assert_eq!(resp.status(), 200);
    assert!(resp.headers().get("etag").is_some(), "ETag header present");
    let body: Value = resp.json().await.expect("json");
    assert_eq!(body["policy"]["acls"].as_array().expect("acls").len(), 3);
}

#[tokio::test]
async fn put_policy_enforces_etag_concurrency() {
    let (addr, _s) = spawn(Policy::default(), Some(ADMIN_TOKEN.to_owned())).await;
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();

    // Grab the current ETag.
    let get = client
        .get(format!("{base}/v1/policy"))
        .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
        .send()
        .await
        .expect("get");
    let etag = get
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();

    let new_policy = serde_json::json!({
        "acls": [ { "action": "accept", "src": ["tag:user-*"], "dst": ["tag:svc"] } ]
    });

    // Missing If-Match → 428.
    let resp = client
        .put(format!("{base}/v1/policy"))
        .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
        .json(&new_policy)
        .send()
        .await
        .expect("put no if-match");
    assert_eq!(resp.status(), 428, "missing If-Match must be 428");

    // Stale If-Match → 412.
    let resp = client
        .put(format!("{base}/v1/policy"))
        .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
        .header("if-match", "\"stale-etag\"")
        .json(&new_policy)
        .send()
        .await
        .expect("put stale");
    assert_eq!(resp.status(), 412, "stale If-Match must be 412");

    // Correct If-Match → 200, and the ETag changes.
    let resp = client
        .put(format!("{base}/v1/policy"))
        .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
        .header("if-match", &etag)
        .json(&new_policy)
        .send()
        .await
        .expect("put fresh");
    assert_eq!(resp.status(), 200);
    let new_etag = resp
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    assert_ne!(new_etag, etag, "ETag must change after a successful PUT");

    // The now-stale original ETag fails a second PUT (lost-update guard).
    let resp = client
        .put(format!("{base}/v1/policy"))
        .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
        .header("if-match", &etag)
        .json(&new_policy)
        .send()
        .await
        .expect("put stale-again");
    assert_eq!(resp.status(), 412, "reusing the old ETag must be 412");
}

#[tokio::test]
async fn put_policy_requires_admin_token() {
    let (addr, _s) = spawn(Policy::default(), Some(ADMIN_TOKEN.to_owned())).await;
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();
    let resp = client
        .put(format!("{base}/v1/policy"))
        .header("if-match", "\"whatever\"")
        .json(&serde_json::json!({ "acls": [] }))
        .send()
        .await
        .expect("put no auth");
    assert_eq!(resp.status(), 401, "PUT without token must be 401");
}

#[tokio::test]
async fn policy_api_disabled_when_no_admin_token() {
    // No admin token configured → endpoints fail-closed at 401 even with a
    // bearer header.
    let (addr, _s) = spawn(shared_service_policy(), None).await;
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{base}/v1/policy"))
        .header("authorization", "Bearer anything")
        .send()
        .await
        .expect("get");
    assert_eq!(
        resp.status(),
        401,
        "disabled admin API must reject all calls"
    );
}

// ---------------------------------------------------------------------
// SSE helper.
// ---------------------------------------------------------------------

/// Read SSE chunks into a buffer until `done(&buf)` is true or `secs`
/// elapse. Returns whatever was accumulated.
async fn read_sse_until(
    resp: &mut reqwest::Response,
    done: impl Fn(&str) -> bool,
    secs: u64,
) -> String {
    let mut buf = String::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    while tokio::time::Instant::now() < deadline {
        if let Ok(Ok(Some(chunk))) =
            tokio::time::timeout(Duration::from_millis(200), resp.chunk()).await
        {
            buf.push_str(&String::from_utf8_lossy(&chunk));
            if done(&buf) {
                break;
            }
        }
    }
    buf
}
