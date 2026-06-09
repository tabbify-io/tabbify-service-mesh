//! Tests for HTTP API: SSE viewer filter + DTO back-compat.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use super::dto::{HeartbeatRequest, PeerPathDto, RegisterRequest};
use super::handlers::topology_handler;
use super::stream::ViewerFilter;
use crate::http::sse::PeerEvent;
use crate::publisher::EventPublisher;
use crate::roster::coordinator::Coordinator;
use crate::roster::events::HolePunchInitiate;
use async_trait::async_trait;
use axum::extract::State;
use base64::Engine as _;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

struct NoopPublisher;
#[async_trait]
impl EventPublisher for NoopPublisher {
    async fn publish(&self, _t: &str, _s: &str, _p: Vec<u8>) -> Result<(), String> {
        Ok(())
    }
}

fn test_coordinator() -> Coordinator {
    Coordinator::new(Arc::new(NoopPublisher), Duration::from_secs(60))
}

fn holepunch_for(initiator: Uuid, target: Uuid) -> PeerEvent {
    PeerEvent::HolePunch(HolePunchInitiate {
        initiator_peer_id: initiator.to_string(),
        target_peer_id: target.to_string(),
        target_external_endpoint: "203.0.113.9:51820".into(),
        timestamp_micros: 1,
    })
}

/// The per-viewer SSE filter forwards a hole-punch frame ONLY to the
/// peer named as its initiator — that peer is the one instructed to
/// fire UDP. A viewer named as initiator gets the frame; the same
/// viewer named only as a target (someone else's initiate) does not.
#[test]
fn viewer_filter_forwards_holepunch_only_to_initiator() {
    let viewer = Uuid::from_u128(1);
    let other = Uuid::from_u128(2);
    let mut filter = ViewerFilter {
        coordinator: test_coordinator(),
        viewer_id: viewer,
        viewer_tags: vec![],
        revealed: HashSet::new(),
    };
    // We are the initiator → forwarded.
    assert!(filter.apply(holepunch_for(viewer, other)).is_some());
    // We are only the target of someone else's initiate → dropped.
    assert!(filter.apply(holepunch_for(other, viewer)).is_none());
}

/// Back-compat: a register/heartbeat body from an older joiner that
/// omits `hosted_app_ulas` must still deserialize (serde default →
/// empty). A regression here would 400 every legacy joiner.
#[test]
fn requests_deserialize_without_hosted_app_ulas() {
    let reg: RegisterRequest = serde_json::from_value(serde_json::json!({
        "wg_public_key": "AAAA",
        "display_name": "legacy",
    }))
    .expect("legacy register body must parse");
    assert!(reg.hosted_app_ulas.is_empty());

    let hb: HeartbeatRequest = serde_json::from_value(serde_json::json!({
        "peer_id": "01910f10-0000-7000-8000-000000000001",
    }))
    .expect("legacy heartbeat body must parse");
    assert!(hb.hosted_app_ulas.is_empty());
}

/// And a NEW joiner's body carrying `hosted_app_ulas` round-trips the
/// set through deserialization.
#[test]
fn requests_carry_hosted_app_ulas_when_present() {
    let reg: RegisterRequest = serde_json::from_value(serde_json::json!({
        "wg_public_key": "AAAA",
        "display_name": "supervisor",
        "hosted_app_ulas": ["fd5a:1f02:dead:beef:cafe:0:0:1"],
    }))
    .expect("register body parses");
    assert_eq!(reg.hosted_app_ulas, vec!["fd5a:1f02:dead:beef:cafe:0:0:1"]);
}

/// Back-compat (SV-1): an older joiner that omits `software_version`
/// must still deserialize — the field defaults to `None`, never an
/// error. `None` = unknown, never a downgrade trigger.
#[test]
fn register_request_omitting_software_version_defaults_to_none() {
    let body = serde_json::json!({
        "wg_public_key": "AAAA",
        "display_name": "old-joiner",
        "tags": []
    });
    let req: super::dto::RegisterRequest =
        serde_json::from_value(body).expect("old register body must still parse");
    assert_eq!(req.software_version, None);
}

/// A `PeerInfo` roster entry emitted by an older coordinator omits the
/// field; the joiner / any consumer must read it back as `None`.
#[test]
fn peer_info_omitting_software_version_defaults_to_none() {
    let body = serde_json::json!({
        "peer_id": "01910f10-0000-7000-8000-000000000001",
        "wg_public_key": "AAAA",
        "ula": "fd5a:1f00:1::1",
        "display_name": "p",
        "tags": [],
        "joined_at_micros": 0
    });
    let info: super::dto::PeerInfo =
        serde_json::from_value(body).expect("old roster entry must still parse");
    assert_eq!(info.software_version, None);
}

/// Back-compat (Fix D): a register body from a joiner that predates the
/// `relay_only` field must still deserialize — the field defaults to
/// `false` (the peer participates in direct + hole-punch as before).
#[test]
fn register_request_omitting_relay_only_defaults_to_false() {
    let req: RegisterRequest = serde_json::from_value(serde_json::json!({
        "wg_public_key": "AAAA",
        "display_name": "legacy",
    }))
    .expect("legacy register body must parse");
    assert!(!req.relay_only);
}

/// A relay-only joiner's register body round-trips the flag as `true`.
#[test]
fn register_request_carries_relay_only_when_present() {
    let req: RegisterRequest = serde_json::from_value(serde_json::json!({
        "wg_public_key": "AAAA",
        "display_name": "node-in-netns",
        "relay_only": true,
    }))
    .expect("register body parses");
    assert!(req.relay_only);
}

/// Heartbeat re-asserts `relay_only`; older joiners omit it → `false`.
#[test]
fn heartbeat_request_relay_only_back_compat_and_present() {
    let legacy: HeartbeatRequest = serde_json::from_value(serde_json::json!({
        "peer_id": "01910f10-0000-7000-8000-000000000001",
    }))
    .expect("legacy heartbeat body must parse");
    assert!(!legacy.relay_only);

    let modern: HeartbeatRequest = serde_json::from_value(serde_json::json!({
        "peer_id": "01910f10-0000-7000-8000-000000000001",
        "relay_only": true,
    }))
    .expect("modern heartbeat body parses");
    assert!(modern.relay_only);
}

/// Heartbeat carries per-peer connectivity edges (connectivity visibility);
/// an older joiner omits `peer_paths` → empty (back-compat).
#[test]
fn heartbeat_request_peer_paths_back_compat_and_present() {
    let legacy: HeartbeatRequest = serde_json::from_value(serde_json::json!({
        "peer_id": "01910f10-0000-7000-8000-000000000001",
    }))
    .expect("legacy heartbeat body must parse");
    assert!(legacy.peer_paths.is_empty(), "no peer_paths → empty edges");

    let modern: HeartbeatRequest = serde_json::from_value(serde_json::json!({
        "peer_id": "01910f10-0000-7000-8000-000000000001",
        "peer_paths": [
            { "peer_id": "01910f10-0000-7000-8000-000000000002", "direct": true, "last_rx_age_ms": 7 },
            { "peer_id": "01910f10-0000-7000-8000-000000000003", "direct": false }
        ]
    }))
    .expect("modern heartbeat body parses");
    assert_eq!(modern.peer_paths.len(), 2);
    assert!(modern.peer_paths[0].direct);
    assert_eq!(modern.peer_paths[0].last_rx_age_ms, 7);
    assert!(!modern.peer_paths[1].direct);
    // `last_rx_age_ms` defaults when omitted.
    assert_eq!(modern.peer_paths[1].last_rx_age_ms, 0);
}

/// A `PeerInfo` roster entry from an older coordinator omits `relay_only`;
/// a consumer reads it back as `false` (visible + round-trips).
#[test]
fn peer_info_relay_only_back_compat_and_round_trips() {
    let legacy: super::dto::PeerInfo = serde_json::from_value(serde_json::json!({
        "peer_id": "01910f10-0000-7000-8000-000000000001",
        "wg_public_key": "AAAA",
        "ula": "fd5a:1f00:1::1",
        "display_name": "p",
        "tags": [],
        "joined_at_micros": 0
    }))
    .expect("old roster entry must still parse");
    assert!(!legacy.relay_only);

    let modern: super::dto::PeerInfo = serde_json::from_value(serde_json::json!({
        "peer_id": "01910f10-0000-7000-8000-000000000001",
        "wg_public_key": "AAAA",
        "ula": "fd5a:1f00:1::1",
        "display_name": "p",
        "tags": [],
        "joined_at_micros": 0,
        "relay_only": true
    }))
    .expect("modern roster entry parses");
    assert!(modern.relay_only);
}

/// A minimal register request for a plain machine peer (seed → pubkey).
fn machine_req(seed: u8, name: &str) -> RegisterRequest {
    RegisterRequest {
        wg_public_key: base64::engine::general_purpose::STANDARD.encode([seed; 32]),
        listen_endpoint: Some("127.0.0.1:51820".into()),
        wg_listen_port: Some(51820),
        display_name: name.into(),
        network: String::new(),
        tags: vec![],
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

/// `GET /v1/mesh/topology` (driven through [`topology_handler`]) returns
/// `200` with both registered machines and the single undirected edge
/// between them, marked `direct`.
#[tokio::test]
async fn topology_handler_returns_machines_and_edges() {
    let c = test_coordinator();
    let (a, _) = c.register(machine_req(1, "A")).await.expect("register A");
    let (b, _) = c.register(machine_req(2, "B")).await.expect("register B");

    // A reports a DIRECT path to B (one direction is enough for the
    // collapsed undirected edge to be direct).
    c.record_peer_paths(
        a.peer_id,
        &[PeerPathDto {
            peer_id: b.peer_id.to_string(),
            direct: true,
            last_rx_age_ms: 12,
        }],
    );

    let resp = topology_handler(State(c)).await;
    assert_eq!(resp.status(), 200, "topology must be 200");

    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("read body");
    // The response DTO is Serialize-only (it is a wire response, like
    // RosterResponse), so the test parses the JSON shape directly.
    let topo: serde_json::Value = serde_json::from_slice(&bytes).expect("parse topology body");

    let machines = topo["machines"].as_array().expect("machines array");
    let edges = topo["edges"].as_array().expect("edges array");
    assert_eq!(machines.len(), 2, "both machines present");
    assert_eq!(edges.len(), 1, "exactly one collapsed edge");
    assert_eq!(edges[0]["direct"], serde_json::json!(true), "A↔B is direct");
    assert_eq!(edges[0]["age_ms"], serde_json::json!(12));
}
