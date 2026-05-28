//! Tests for HTTP API: SSE viewer filter + DTO back-compat.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use super::dto::{HeartbeatRequest, RegisterRequest};
use super::stream::ViewerFilter;
use crate::http::sse::PeerEvent;
use crate::publisher::EventPublisher;
use crate::roster::coordinator::Coordinator;
use crate::roster::events::HolePunchInitiate;
use async_trait::async_trait;
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
