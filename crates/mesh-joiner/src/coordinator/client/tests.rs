//! Wire-shape, transport, and mTLS-builder tests for
//! [`super::CoordinatorClient`]. Drives the client against a wiremock
//! fake coordinator.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use super::*;
use crate::peer::RemotePeer;
use std::net::Ipv6Addr;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn sample_pubkey_b64() -> (String, [u8; 32]) {
    let raw: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];
    (B64.encode(raw), raw)
}

#[test]
fn decode_pubkey_round_trip() {
    let (encoded, raw) = sample_pubkey_b64();
    let got = decode_pubkey(&encoded).unwrap();
    assert_eq!(got, raw);
}

#[test]
fn decode_pubkey_rejects_wrong_length() {
    let short = B64.encode([0u8; 16]);
    let err = decode_pubkey(&short).unwrap_err();
    assert!(matches!(err, JoinerError::MalformedPeer(_)));
}

#[test]
fn decode_pubkey_rejects_garbage_base64() {
    let err = decode_pubkey("!!! not base64 !!!").unwrap_err();
    assert!(matches!(err, JoinerError::MalformedPeer(_)));
}

/// Fix D wire round-trip: a relay-only register body serializes
/// `relay_only: true`, and a body that OMITS the field deserializes to
/// `false` (back-compat with a coordinator/replay that predates it). Same
/// for the heartbeat body. `relay_only` is a plain `bool` (no
/// `skip_serializing_if`), so it is always present on the wire when set.
#[test]
fn relay_only_round_trips_and_defaults_false() {
    let (b64, _) = sample_pubkey_b64();

    let reg = RegisterRequest {
        wg_public_key: b64.clone(),
        listen_endpoint: None,
        wg_listen_port: Some(51820),
        display_name: "node-in-netns".into(),
        tags: vec![],
        hosted_app_ulas: vec![],
        requested_ula: None,
        kind: None,
        parent: None,
        app_uuid: None,
        software_version: None,
        mesh_version: None,
        relay_only: true,
    };
    let v = serde_json::to_value(&reg).unwrap();
    assert_eq!(v["relay_only"], true, "relay_only must serialize: {v}");

    // A body that omits relay_only (older joiner) → false.
    let legacy: RegisterRequest = serde_json::from_value(serde_json::json!({
        "wg_public_key": b64,
        "display_name": "legacy",
        "tags": [],
    }))
    .expect("legacy register body must parse");
    assert!(!legacy.relay_only);

    let hb = HeartbeatRequest {
        peer_id: Uuid::nil(),
        wg_listen_port: Some(51820),
        hosted_app_ulas: vec![],
        software_version: None,
        mesh_version: None,
        relay_only: true,
        peer_paths: vec![],
    };
    let hv = serde_json::to_value(&hb).unwrap();
    assert_eq!(hv["relay_only"], true);
    let legacy_hb: HeartbeatRequest = serde_json::from_value(serde_json::json!({
        "peer_id": "00000000-0000-0000-0000-000000000000",
    }))
    .expect("legacy heartbeat body must parse");
    assert!(!legacy_hb.relay_only);
    // Back-compat: a heartbeat with no `peer_paths` key parses to an empty
    // edge set (connectivity visibility — old joiner / old coordinator).
    assert!(legacy_hb.peer_paths.is_empty());
}

#[tokio::test]
async fn remote_to_info_parses_full_record() {
    let (b64, raw) = sample_pubkey_b64();
    let remote = RemotePeer {
        peer_id: Uuid::nil(),
        wg_public_key: b64,
        ula: "fd5a:1f00:1::1".into(),
        listen_endpoint: Some("127.0.0.1:51820".into()),
        display_name: "alice".into(),
        tags: vec!["dev".into()],
        hosted_app_ulas: vec![],
        software_version: None,
        mesh_version: None,
        joined_at_micros: 1_700_000_000_000_000,
    };
    let info = remote_to_info(&remote).await.unwrap();
    assert_eq!(info.peer_id, Uuid::nil());
    assert_eq!(info.wg_public_key, raw);
    assert_eq!(info.ula.to_string(), "fd5a:1f00:1::1");
    assert_eq!(info.listen_endpoint.unwrap().to_string(), "127.0.0.1:51820");
    assert_eq!(info.display_name, "alice");
    assert_eq!(info.tags, vec!["dev".to_string()]);
}

/// `remote_to_info` parses well-formed hosted app-ULAs into typed
/// addresses (per-app-ULA routing). A peer hosting no apps yields an
/// empty vec.
#[tokio::test]
async fn remote_to_info_parses_hosted_app_ulas() {
    let (b64, _) = sample_pubkey_b64();
    let remote = RemotePeer {
        peer_id: Uuid::nil(),
        wg_public_key: b64,
        ula: "fd5a:1f00:1::1".into(),
        listen_endpoint: None,
        display_name: "supervisor".into(),
        tags: vec![],
        hosted_app_ulas: vec![
            "fd5a:1f02:dead:beef:cafe:0:0:1".into(),
            "fd5a:1f02:dead:beef:cafe:0:0:2".into(),
        ],
        software_version: None,
        mesh_version: None,
        joined_at_micros: 0,
    };
    let info = remote_to_info(&remote).await.unwrap();
    assert_eq!(
        info.hosted_app_ulas,
        vec![
            "fd5a:1f02:dead:beef:cafe:0:0:1"
                .parse::<Ipv6Addr>()
                .unwrap(),
            "fd5a:1f02:dead:beef:cafe:0:0:2"
                .parse::<Ipv6Addr>()
                .unwrap(),
        ]
    );
}

/// A malformed hosted app-ULA literal is SKIPPED (logged), not fatal —
/// the peer's session must survive one bad app-ULA. Good ones in the
/// same record still parse.
#[tokio::test]
async fn remote_to_info_skips_malformed_hosted_app_ula() {
    let (b64, _) = sample_pubkey_b64();
    let remote = RemotePeer {
        peer_id: Uuid::nil(),
        wg_public_key: b64,
        ula: "fd5a:1f00:1::1".into(),
        listen_endpoint: None,
        display_name: "supervisor".into(),
        tags: vec![],
        hosted_app_ulas: vec![
            "not-an-ipv6".into(),
            "fd5a:1f02:dead:beef:cafe:0:0:9".into(),
        ],
        software_version: None,
        mesh_version: None,
        joined_at_micros: 0,
    };
    let info = remote_to_info(&remote).await.unwrap();
    // The bad one is dropped; the good one survives.
    assert_eq!(
        info.hosted_app_ulas,
        vec![
            "fd5a:1f02:dead:beef:cafe:0:0:9"
                .parse::<Ipv6Addr>()
                .unwrap()
        ]
    );
}

/// A peer behind NAT registers with an empty `listen_endpoint`; we
/// must accept that as `None` rather than failing the roster
/// update.
#[tokio::test]
async fn remote_to_info_treats_empty_endpoint_as_none() {
    let (b64, _) = sample_pubkey_b64();
    let remote = RemotePeer {
        peer_id: Uuid::nil(),
        wg_public_key: b64,
        ula: "fd5a:1f00:1::2".into(),
        listen_endpoint: Some(String::new()),
        display_name: "bob".into(),
        tags: vec![],
        hosted_app_ulas: vec![],
        software_version: None,
        mesh_version: None,
        joined_at_micros: 0,
    };
    let info = remote_to_info(&remote).await.unwrap();
    assert!(info.listen_endpoint.is_none());
}

#[tokio::test]
async fn remote_to_info_rejects_bad_ula() {
    let (b64, _) = sample_pubkey_b64();
    let remote = RemotePeer {
        peer_id: Uuid::nil(),
        wg_public_key: b64,
        ula: "not-an-ipv6".into(),
        listen_endpoint: None,
        display_name: "x".into(),
        tags: vec![],
        hosted_app_ulas: vec![],
        software_version: None,
        mesh_version: None,
        joined_at_micros: 0,
    };
    let err = remote_to_info(&remote).await.unwrap_err();
    assert!(matches!(err, JoinerError::MalformedPeer(_)));
}

/// End-to-end happy path against a `wiremock` fake coordinator. We
/// assert the joiner sends the registration body in the correct
/// shape (POST + JSON + base64 pubkey) and parses the response.
#[tokio::test]
async fn register_round_trip_against_mock_coordinator() {
    let server = MockServer::start().await;
    let response_body = serde_json::json!({
        "peer_id": "01910f10-0000-7000-8000-000000000001",
        "ula": "fd5a:1f00:1::1",
        "peers": [
            {
                "peer_id": "01910f10-0000-7000-8000-000000000002",
                "wg_public_key": B64.encode([7u8; 32]),
                "ula": "fd5a:1f00:1::2",
                "listen_endpoint": "10.0.0.2:51820",
                "display_name": "peer-two",
                "tags": ["wasm-host"],
                "joined_at_micros": 1_700_000_000_000_000_i64
            }
        ]
    });
    Mock::given(method("POST"))
        .and(path("/v1/mesh/register"))
        .and(header("content-type", "application/json"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_json(response_body),
        )
        .expect(1)
        .mount(&server)
        .await;

    let client = CoordinatorClient::new(server.uri(), None, None, None, true).unwrap();
    let pubkey = [0xAAu8; 32];
    let resp = client
        .register(
            &pubkey,
            Some("127.0.0.1:51820".parse().unwrap()),
            Some(51820),
            "alice",
            &["dev-machine".to_owned()],
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            false,
        )
        .await
        .unwrap();
    assert_eq!(resp.ula, "fd5a:1f00:1::1");
    assert_eq!(resp.peers.len(), 1);
    assert_eq!(resp.peers[0].display_name, "peer-two");
}

/// When a join token is supplied, the register request must carry it
/// as an `Authorization: Bearer <token>` header (spec §8). The mock
/// only matches when that exact header is present, so a passing test
/// proves the header was sent.
#[tokio::test]
async fn register_sends_bearer_header_when_join_token_present() {
    let server = MockServer::start().await;
    let response_body = serde_json::json!({
        "peer_id": "01910f10-0000-7000-8000-000000000001",
        "ula": "fd5a:1f00:1::1",
        "peers": []
    });
    Mock::given(method("POST"))
        .and(path("/v1/mesh/register"))
        .and(header("authorization", "Bearer my-join-jwt"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_json(response_body),
        )
        .expect(1)
        .mount(&server)
        .await;

    let client = CoordinatorClient::new(server.uri(), None, None, None, true).unwrap();
    let resp = client
        .register(
            &[0xAAu8; 32],
            None,
            Some(51820),
            "alice",
            &[],
            Some("my-join-jwt"),
            None,
            None,
            None,
            None,
            None,
            None,
            false,
        )
        .await
        .expect("register with bearer should succeed");
    assert_eq!(resp.ula, "fd5a:1f00:1::1");
}

/// The register body must carry `wg_listen_port` (for reflexive
/// discovery) and, when no explicit advertise-endpoint is given, must
/// OMIT `listen_endpoint` — the joiner no longer auto-advertises a
/// loopback address; it lets the coordinator reflect. A body matcher
/// proves both on the wire.
#[tokio::test]
async fn register_sends_wg_port_and_omits_listen_endpoint() {
    use wiremock::matchers::body_partial_json;
    let server = MockServer::start().await;
    let response_body = serde_json::json!({
        "peer_id": "01910f10-0000-7000-8000-000000000001",
        "ula": "fd5a:1f00:1::1",
        "peers": []
    });
    Mock::given(method("POST"))
        .and(path("/v1/mesh/register"))
        // Requires wg_listen_port == 51820 in the JSON body.
        .and(body_partial_json(
            serde_json::json!({ "wg_listen_port": 51820 }),
        ))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_json(&response_body),
        )
        .expect(1)
        .mount(&server)
        .await;

    let client = CoordinatorClient::new(server.uri(), None, None, None, true).unwrap();
    // listen_endpoint = None → must be omitted from the body (serde
    // skip_serializing_if). The mock only matched on wg_listen_port, so
    // also assert the serialized body has no listen_endpoint key.
    let body = serde_json::to_value(RegisterRequest {
        wg_public_key: B64.encode([0xAAu8; 32]),
        listen_endpoint: None,
        wg_listen_port: Some(51820),
        display_name: "alice".into(),
        tags: vec![],
        hosted_app_ulas: vec![],
        requested_ula: None,
        kind: None,
        parent: None,
        app_uuid: None,
        software_version: None,
        mesh_version: None,
        relay_only: false,
    })
    .unwrap();
    assert!(
        body.get("listen_endpoint").is_none(),
        "listen_endpoint must be omitted when None: {body}"
    );
    assert_eq!(body["wg_listen_port"], 51820);

    client
        .register(
            &[0xAAu8; 32],
            None,
            Some(51820),
            "alice",
            &[],
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            false,
        )
        .await
        .expect("register should succeed and match the wg_listen_port body");
}

/// The register response must surface the coordinator-reflected
/// `observed_ip` + `observed_endpoint` (the reflexive endpoint other
/// peers will dial). Older coordinators omit them → `None`.
#[tokio::test]
async fn register_parses_observed_reflexive_fields() {
    let server = MockServer::start().await;
    let response_body = serde_json::json!({
        "peer_id": "01910f10-0000-7000-8000-000000000001",
        "ula": "fd5a:1f00:1::1",
        "peers": [],
        "observed_ip": "203.0.113.7",
        "observed_endpoint": "203.0.113.7:51820"
    });
    Mock::given(method("POST"))
        .and(path("/v1/mesh/register"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_json(response_body),
        )
        .mount(&server)
        .await;
    let client = CoordinatorClient::new(server.uri(), None, None, None, true).unwrap();
    let resp = client
        .register(
            &[0xAAu8; 32],
            None,
            Some(51820),
            "alice",
            &[],
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            false,
        )
        .await
        .expect("register");
    assert_eq!(resp.observed_ip.as_deref(), Some("203.0.113.7"));
    assert_eq!(resp.observed_endpoint.as_deref(), Some("203.0.113.7:51820"));
}

/// Back-compat: a response WITHOUT the observed fields parses cleanly
/// (they default to `None`) — older coordinators must still work.
#[tokio::test]
async fn register_tolerates_missing_observed_fields() {
    let server = MockServer::start().await;
    let response_body = serde_json::json!({
        "peer_id": "01910f10-0000-7000-8000-000000000001",
        "ula": "fd5a:1f00:1::1",
        "peers": []
    });
    Mock::given(method("POST"))
        .and(path("/v1/mesh/register"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_json(response_body),
        )
        .mount(&server)
        .await;
    let client = CoordinatorClient::new(server.uri(), None, None, None, true).unwrap();
    let resp = client
        .register(
            &[0xAAu8; 32],
            None,
            Some(51820),
            "alice",
            &[],
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            false,
        )
        .await
        .expect("register");
    assert!(resp.observed_ip.is_none());
    assert!(resp.observed_endpoint.is_none());
}

/// With no join token, the register request must NOT carry an
/// Authorization header — the dev/E1 escape hatch against a
/// non-validating coordinator. The mock requires the header to be
/// ABSENT (matches only when there's no auth), so a pass proves we
/// didn't send one.
#[tokio::test]
async fn register_omits_bearer_header_when_no_join_token() {
    use wiremock::matchers::header_exists;
    let server = MockServer::start().await;
    let response_body = serde_json::json!({
        "peer_id": "01910f10-0000-7000-8000-000000000001",
        "ula": "fd5a:1f00:1::1",
        "peers": []
    });
    // A mock that requires the Authorization header to exist; we then
    // assert it received ZERO calls, i.e. our tokenless request did
    // not match because it carried no auth header.
    Mock::given(method("POST"))
        .and(path("/v1/mesh/register"))
        .and(header_exists("authorization"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .expect(0)
        .mount(&server)
        .await;
    // Fallback mock with no header requirement so the call still gets
    // a valid response to parse.
    Mock::given(method("POST"))
        .and(path("/v1/mesh/register"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_json(response_body),
        )
        .mount(&server)
        .await;

    let client = CoordinatorClient::new(server.uri(), None, None, None, true).unwrap();
    client
        .register(
            &[0xAAu8; 32],
            None,
            Some(51820),
            "alice",
            &[],
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            false,
        )
        .await
        .expect("tokenless register should succeed");
    // The `.expect(0)` on the header-requiring mock is verified on
    // server drop — if our request had carried an auth header it would
    // have matched and tripped the expectation.
}

#[tokio::test]
async fn heartbeat_returns_roster_snapshot() {
    let server = MockServer::start().await;
    let response_body = serde_json::json!({ "peers": [] });
    Mock::given(method("POST"))
        .and(path("/v1/mesh/heartbeat"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_json(response_body),
        )
        .expect(1)
        .mount(&server)
        .await;
    let client = CoordinatorClient::new(server.uri(), None, None, None, true).unwrap();
    let resp = client
        .heartbeat(Uuid::nil(), Some(51820), &[], None, None, false, Vec::new())
        .await
        .unwrap();
    assert!(resp.peers.is_empty());
}

/// Per-app-ULA routing: when the joiner hosts app-ULAs, the heartbeat
/// body must carry them as `hosted_app_ulas`. A body matcher proves the
/// set is on the wire.
#[tokio::test]
async fn heartbeat_sends_hosted_app_ulas() {
    use wiremock::matchers::body_partial_json;
    let server = MockServer::start().await;
    let response_body = serde_json::json!({ "peers": [] });
    Mock::given(method("POST"))
        .and(path("/v1/mesh/heartbeat"))
        .and(body_partial_json(serde_json::json!({
            "hosted_app_ulas": ["fd5a:1f02:dead:beef:cafe:0:0:1"]
        })))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_json(response_body),
        )
        .expect(1)
        .mount(&server)
        .await;
    let client = CoordinatorClient::new(server.uri(), None, None, None, true).unwrap();
    client
        .heartbeat(
            Uuid::nil(),
            Some(51820),
            &["fd5a:1f02:dead:beef:cafe:0:0:1".to_owned()],
            None,
            None,
            false,
            Vec::new(),
        )
        .await
        .expect("heartbeat with hosted app-ULAs should match the body");
}

/// Back-compat: an EMPTY hosted set is omitted from the heartbeat body
/// (serde `skip_serializing_if`), so older coordinators see no new key.
#[tokio::test]
async fn heartbeat_omits_empty_hosted_app_ulas() {
    let body = serde_json::to_value(HeartbeatRequest {
        peer_id: Uuid::nil(),
        wg_listen_port: Some(51820),
        hosted_app_ulas: vec![],
        software_version: None,
        mesh_version: None,
        relay_only: false,
        peer_paths: vec![],
    })
    .unwrap();
    assert!(
        body.get("hosted_app_ulas").is_none(),
        "empty hosted_app_ulas must be omitted: {body}"
    );
    // An empty edge set is likewise omitted from the wire so older
    // coordinators see no new key (connectivity visibility back-compat).
    assert!(
        body.get("peer_paths").is_none(),
        "empty peer_paths must be omitted: {body}"
    );
}

#[tokio::test]
async fn deregister_accepts_204() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/mesh/deregister"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;
    let client = CoordinatorClient::new(server.uri(), None, None, None, true).unwrap();
    client.deregister(Uuid::nil()).await.unwrap();
}

#[tokio::test]
async fn deregister_surfaces_http_status_on_failure() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/mesh/deregister"))
        .respond_with(ResponseTemplate::new(500).set_body_string("kaboom"))
        .expect(1)
        .mount(&server)
        .await;
    let client = CoordinatorClient::new(server.uri(), None, None, None, true).unwrap();
    let err = client.deregister(Uuid::nil()).await.unwrap_err();
    match err {
        JoinerError::HttpStatus { status, body } => {
            assert_eq!(status, 500);
            assert!(body.contains("kaboom"), "body: {body}");
        }
        other => panic!("expected HttpStatus, got {other:?}"),
    }
}

/// A 200 with garbled JSON must surface as [`JoinerError::JsonCodec`]
/// — not silently swallowed — so the operator notices the
/// coordinator/joiner version mismatch.
#[tokio::test]
async fn register_surfaces_json_codec_error_on_garbage_body() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/mesh/register"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_string("not json at all"),
        )
        .expect(1)
        .mount(&server)
        .await;
    let client = CoordinatorClient::new(server.uri(), None, None, None, true).unwrap();
    let err = client
        .register(
            &[0u8; 32],
            None,
            Some(51820),
            "x",
            &[],
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            false,
        )
        .await
        .unwrap_err();
    assert!(matches!(err, JoinerError::JsonCodec(_)), "{err:?}");
}

/// When `requested_ula`, `kind`, `parent`, and `app_uuid` are set on the
/// register request, they must all appear in the JSON body sent to the
/// coordinator, and the coordinator-returned ULA (which mirrors the
/// requested one when honored) must be returned in the response.
#[tokio::test]
async fn register_sends_requested_ula_and_peer_metadata() {
    use wiremock::matchers::body_partial_json;
    let server = MockServer::start().await;
    let app_uuid_str = "01910f10-0000-7000-8000-000000000099";
    let sup_ula = "fd5a:1f00:1::1";
    let runner_ula = "fd5a:1f02:aabb::1";
    let response_body = serde_json::json!({
        "peer_id": "01910f10-0000-7000-8000-000000000002",
        // Coordinator honors the requested ULA and echoes it back.
        "ula": runner_ula,
        "peers": []
    });
    Mock::given(method("POST"))
        .and(path("/v1/mesh/register"))
        .and(body_partial_json(serde_json::json!({
            "requested_ula": runner_ula,
            "kind": "runner",
            "parent": sup_ula,
            "app_uuid": app_uuid_str,
        })))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_json(response_body),
        )
        .expect(1)
        .mount(&server)
        .await;

    let client = CoordinatorClient::new(server.uri(), None, None, None, true).unwrap();
    let resp = client
        .register(
            &[0xAAu8; 32],
            None,
            Some(51820),
            "runner-abc",
            &[],
            None,
            Some(runner_ula.to_owned()),
            Some("runner".to_owned()),
            Some(sup_ula.to_owned()),
            Some(app_uuid_str.to_owned()),
            None,
            None,
            false,
        )
        .await
        .expect("register with requested_ula + metadata should succeed");
    // The coordinator echoed back the requested ULA.
    assert_eq!(resp.ula, runner_ula);
}

/// SV-2: when the host supplies a `software_version`, the register body
/// carries it so the coordinator can store it.
#[tokio::test]
async fn register_sends_software_version_in_body() {
    use wiremock::matchers::body_partial_json;
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/mesh/register"))
        .and(body_partial_json(serde_json::json!({
            "software_version": "v1.4.0"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "peer_id": "01910f10-0000-7000-8000-000000000001",
            "ula": "fd5a:1f00:1::1",
            "peers": []
        })))
        .expect(1)
        .mount(&server)
        .await;
    let client = CoordinatorClient::new(server.uri(), None, None, None, true).unwrap();
    let pubkey = [0xAAu8; 32];
    client
        .register(
            &pubkey,
            None,
            Some(51820),
            "alice",
            &["dev-machine".to_owned()],
            None,
            None,
            None,
            None,
            None,
            Some("v1.4.0".to_owned()),
            None,
            false,
        )
        .await
        .expect("register with software_version should match the body");
}

/// Backward compat: existing callers that pass `None` for all four new
/// fields must NOT have `requested_ula` / `kind` / `parent` /
/// `app_uuid` in the body (omitted by `skip_serializing_if`). This
/// keeps the wire format unchanged for plain peer joiners.
#[test]
fn register_request_omits_optional_runner_fields_when_none() {
    let body = serde_json::to_value(RegisterRequest {
        wg_public_key: B64.encode([0xAAu8; 32]),
        listen_endpoint: None,
        wg_listen_port: Some(51820),
        display_name: "alice".into(),
        tags: vec![],
        hosted_app_ulas: vec![],
        requested_ula: None,
        kind: None,
        parent: None,
        app_uuid: None,
        software_version: None,
        mesh_version: None,
        relay_only: false,
    })
    .unwrap();
    assert!(
        body.get("requested_ula").is_none(),
        "requested_ula must be omitted when None: {body}"
    );
    assert!(
        body.get("kind").is_none(),
        "kind must be omitted when None: {body}"
    );
    assert!(
        body.get("parent").is_none(),
        "parent must be omitted when None: {body}"
    );
    assert!(
        body.get("app_uuid").is_none(),
        "app_uuid must be omitted when None: {body}"
    );
}

#[test]
fn base_url_trims_trailing_slash() {
    let c = CoordinatorClient::new("http://127.0.0.1:8888/", None, None, None, true).unwrap();
    assert_eq!(c.base_url(), "http://127.0.0.1:8888");
}

/// Insecure (dev) path must build successfully with all TLS args
/// at `None` — the cert paths are intentionally ignored so the
/// joiner can hit a plaintext coordinator without ceremony.
#[test]
fn new_insecure_skips_tls() {
    let c = CoordinatorClient::new("http://example.com".to_owned(), None, None, None, true);
    assert!(c.is_ok(), "expected ok, got {:?}", c.err());
}

/// Production path requires all three cert paths. Missing ANY one
/// of them surfaces as [`JoinerError::InvalidConfig`] BEFORE any
/// I/O — gives the operator a precise actionable error instead of
/// a vague "file not found" mid-handshake.
#[test]
fn new_secure_requires_all_three_paths() {
    let err = CoordinatorClient::new(
        "https://coordinator.mesh".to_owned(),
        None,
        None,
        None,
        false,
    )
    .unwrap_err();
    assert!(
        matches!(err, JoinerError::InvalidConfig(_)),
        "expected InvalidConfig, got {err:?}"
    );
}

/// Even with two of the three paths supplied, the validation must
/// still trip — guards against a copy-paste deploy script that
/// forgot to pass the CA bundle.
#[test]
fn new_secure_requires_ca_too() {
    let dir = tempfile::TempDir::new().unwrap();
    let cert = dir.path().join("c.pem");
    let key = dir.path().join("k.pem");
    // Files don't need to exist — validation runs before disk I/O.
    let err = CoordinatorClient::new(
        "https://coordinator.mesh".to_owned(),
        Some(cert.as_path()),
        Some(key.as_path()),
        None,
        false,
    )
    .unwrap_err();
    assert!(matches!(err, JoinerError::InvalidConfig(_)));
}

/// Happy path mTLS build: generate a self-signed cert on the fly,
/// reuse it as both client cert and CA, and confirm the client
/// builder succeeds. Doesn't actually open a connection — just
/// asserts the cert parse / loader pipeline is wired up right.
#[test]
fn new_secure_builds_client_with_valid_pems() {
    let dir = tempfile::TempDir::new().unwrap();
    let cert = rcgen::generate_simple_self_signed(vec!["mesh-joiner".to_owned()]).unwrap();
    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();

    let cert_path = dir.path().join("client.pem");
    let key_path = dir.path().join("client.key");
    let ca_path = dir.path().join("ca.pem");
    std::fs::write(&cert_path, &cert_pem).unwrap();
    std::fs::write(&key_path, &key_pem).unwrap();
    // Self-sign so we can reuse the cert as a trust anchor.
    std::fs::write(&ca_path, &cert_pem).unwrap();

    let client = CoordinatorClient::new(
        "https://coordinator.mesh".to_owned(),
        Some(cert_path.as_path()),
        Some(key_path.as_path()),
        Some(ca_path.as_path()),
        false,
    );
    assert!(client.is_ok(), "expected ok, got error: {:?}", client.err());
}
