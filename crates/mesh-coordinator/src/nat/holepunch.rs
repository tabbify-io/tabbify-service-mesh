//! Stage 2 skeleton — UDP hole punch initiation events.
//!
//! When two peers each have a known `observed_external` socket addr
//! (recorded from prior heartbeats), the coordinator emits a pair of
//! `HolePunchInitiate` events on the `platform.mesh.peers` segment — one
//! per peer, with `initiator_peer_id` / `target_peer_id` swapped so
//! both sides know the other's external endpoint and can fire UDP packets
//! simultaneously.
//!
//! The real hole-punching state machine (timing, retries, NAT type
//! detection, fallback to relay) is **deferred to a cloud rollout with
//! real NAT topology**. This module only pins the protocol shape so
//! joiner subscribers don't churn when the real implementation lands.
//!
//! Gating logic: the coordinator tracks an in-memory `DashSet<(Uuid,
//! Uuid)>` of already-punched ordered pairs so a single pair is only
//! emitted once per coordinator lifetime. Pairs are keyed in canonical
//! (smaller, larger) form so heartbeats from either side hit the same
//! key. The set is reset on coordinator restart, which is fine — punch
//! events never need re-emitting after a restart (the joiners re-register
//! and re-pair).
//!
//! Spam mitigation: this is a skeleton, not a production policy. When
//! the real impl lands, gating should probably also age out entries so
//! a peer that became reachable directly can later fall back to hole
//! punching without a coordinator restart.
//!
//! Called from `coordinator.rs::heartbeat`: after stamping `peer A`'s
//! heartbeat with its newly observed external endpoint, iterate over
//! every other peer `B` that also has a non-empty external endpoint and
//! emit the pair if `(min(A,B), max(A,B))` isn't yet in the punched set.

use crate::http::sse::{PeerBroadcaster, PeerEvent};
use crate::publisher::{EventPublisher, publish_event};
use crate::roster::coordinator::PEER_SEGMENT;
use crate::roster::events::HolePunchInitiate;
use dashmap::DashSet;
use std::sync::Arc;
use tracing::debug;
use uuid::Uuid;

/// Pair tracking key. Stored in canonical (smaller, larger) form so
/// heartbeats from either side hit the same entry. Single source of
/// truth for "already emitted hole-punch for this pair".
pub type PunchPair = (Uuid, Uuid);

/// Build the canonical key for a pair. Order-independent.
#[must_use]
pub fn canonical_pair(a: Uuid, b: Uuid) -> PunchPair {
    if a <= b { (a, b) } else { (b, a) }
}

/// One peer's "punch-relevant" snapshot — what `try_emit_pair` needs
/// to decide whether to emit and what to write in the event payload.
#[derive(Debug, Clone)]
pub struct PunchPeer {
    /// Coordinator-assigned UUID.
    pub peer_id: Uuid,
    /// The reflexive `WireGuard` endpoint to dial for the punch (`ip:wg_port`)
    /// — the peer's `listen_endpoint`, NOT the raw heartbeat TCP source. A
    /// punch fired at the TCP source would miss the `WireGuard` UDP mapping.
    /// Empty string ≡ "not dialable yet", in which case we skip.
    pub dial_endpoint: String,
}

/// Tracks which `(peer_id, peer_id)` ordered pairs have already had
/// a `HolePunchInitiate` event emitted. Cheap to clone — wraps an `Arc`
/// internally via `DashSet`.
#[derive(Default, Clone)]
pub struct PunchTracker {
    punched: Arc<DashSet<PunchPair>>,
}

impl PunchTracker {
    /// Empty tracker.
    #[must_use]
    pub fn new() -> Self {
        Self {
            punched: Arc::new(DashSet::new()),
        }
    }

    /// Has this canonical pair already been emitted?
    #[must_use]
    pub fn contains(&self, pair: PunchPair) -> bool {
        self.punched.contains(&pair)
    }

    /// Mark this canonical pair as emitted. Returns `true` if the pair
    /// was newly inserted (caller wins the race), `false` otherwise.
    pub fn mark(&self, pair: PunchPair) -> bool {
        self.punched.insert(pair)
    }

    /// Forget the pair — used in tests / by future ageing-out logic.
    pub fn clear(&self, pair: PunchPair) -> bool {
        self.punched.remove(&pair).is_some()
    }

    /// Number of pairs already punched.
    #[must_use]
    pub fn len(&self) -> usize {
        self.punched.len()
    }

    /// Convenience predicate.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.punched.is_empty()
    }
}

/// Best-effort emit of the `HolePunchInitiate` pair for `(a, b)`.
///
/// Skips silently when either peer is missing an external endpoint or the
/// canonical pair has already been emitted. Returns `true` when both
/// events were published (regardless of publisher success — publish is
/// best-effort), `false` when no work was done.
pub async fn try_emit_pair(
    publisher: &dyn EventPublisher,
    broadcaster: &PeerBroadcaster,
    tracker: &PunchTracker,
    a: &PunchPeer,
    b: &PunchPeer,
    now_micros: i64,
) -> bool {
    if a.peer_id == b.peer_id {
        return false;
    }
    if a.dial_endpoint.is_empty() || b.dial_endpoint.is_empty() {
        return false;
    }
    let pair = canonical_pair(a.peer_id, b.peer_id);
    if !tracker.mark(pair) {
        return false;
    }
    debug!(
        a = %a.peer_id,
        b = %b.peer_id,
        ext_a = %a.dial_endpoint,
        ext_b = %b.dial_endpoint,
        "holepunch: emitting initiate pair (skeleton — no real punching yet)",
    );
    // Event 1: A is initiator, B is target. A sends first to B's external.
    let ev_a = HolePunchInitiate {
        initiator_peer_id: a.peer_id.to_string(),
        target_peer_id: b.peer_id.to_string(),
        target_external_endpoint: b.dial_endpoint.clone(),
        timestamp_micros: now_micros,
    };
    // Persist (audit/event-log) AND broadcast to live SSE subscribers —
    // the broadcast is what actually delivers the punch instruction to the
    // initiator's joiner; the per-viewer SSE filter routes it by initiator.
    publish_event(publisher, PEER_SEGMENT, &ev_a).await;
    broadcaster.broadcast(PeerEvent::HolePunch(ev_a));
    // Event 2: B is initiator, A is target. B sends first to A's external.
    let ev_b = HolePunchInitiate {
        initiator_peer_id: b.peer_id.to_string(),
        target_peer_id: a.peer_id.to_string(),
        target_external_endpoint: a.dial_endpoint.clone(),
        timestamp_micros: now_micros,
    };
    publish_event(publisher, PEER_SEGMENT, &ev_b).await;
    broadcaster.broadcast(PeerEvent::HolePunch(ev_b));
    true
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::publisher::EventPublisher;
    use async_trait::async_trait;
    use parking_lot::Mutex;
    use std::sync::Arc as StdArc;

    /// A single captured publish: `(event_type, segment, payload)`.
    type CapturedEvent = (String, String, Vec<u8>);

    /// Publisher that records every `(event_type, segment, payload)` for
    /// assertion. Cheap clone — wraps a `Mutex<Vec<...>>` in `Arc`.
    #[derive(Clone, Default)]
    struct CapturingPublisher {
        events: StdArc<Mutex<Vec<CapturedEvent>>>,
    }

    impl CapturingPublisher {
        fn new() -> Self {
            Self::default()
        }

        fn events(&self) -> Vec<CapturedEvent> {
            self.events.lock().clone()
        }
    }

    #[async_trait]
    impl EventPublisher for CapturingPublisher {
        async fn publish(
            &self,
            event_type: &str,
            segment: &str,
            payload: Vec<u8>,
        ) -> Result<(), String> {
            self.events
                .lock()
                .push((event_type.to_owned(), segment.to_owned(), payload));
            Ok(())
        }
    }

    fn peer(seed: u8, ext: &str) -> PunchPeer {
        PunchPeer {
            peer_id: Uuid::from_u128(u128::from(seed)),
            dial_endpoint: ext.into(),
        }
    }

    #[test]
    fn canonical_pair_is_order_independent() {
        let a = Uuid::from_u128(1);
        let b = Uuid::from_u128(2);
        assert_eq!(canonical_pair(a, b), canonical_pair(b, a));
        assert_eq!(canonical_pair(a, b), (a, b));
    }

    #[tokio::test]
    async fn try_emit_pair_publishes_two_events_with_swapped_endpoints() {
        let pub_ = CapturingPublisher::new();
        let tracker = PunchTracker::new();
        let a = peer(1, "203.0.113.1:34567");
        let b = peer(2, "198.51.100.42:51820");
        let emitted = try_emit_pair(&pub_, &PeerBroadcaster::new(), &tracker, &a, &b, 1_000).await;
        assert!(emitted, "expected pair to be emitted");
        let events = pub_.events();
        assert_eq!(events.len(), 2, "expected two HolePunchInitiate events");
        for (event_type, segment, _) in &events {
            assert_eq!(event_type, "holepunch_initiate");
            assert_eq!(segment, "platform.mesh.peers");
        }
        // Verify field values by decoding.
        let decoded: Vec<HolePunchInitiate> = events
            .iter()
            .map(|(_, _, bytes)| {
                serde_json::from_slice::<HolePunchInitiate>(bytes).expect("decode")
            })
            .collect();
        assert!(decoded.iter().all(|e| e.timestamp_micros == 1_000));
        // One event has A as initiator pointing at B's endpoint, the other swapped.
        let from_a = decoded
            .iter()
            .find(|e| e.initiator_peer_id == a.peer_id.to_string())
            .expect("event from A");
        assert_eq!(from_a.target_peer_id, b.peer_id.to_string());
        assert_eq!(from_a.target_external_endpoint, b.dial_endpoint);
        let from_b = decoded
            .iter()
            .find(|e| e.initiator_peer_id == b.peer_id.to_string())
            .expect("event from B");
        assert_eq!(from_b.target_peer_id, a.peer_id.to_string());
        assert_eq!(from_b.target_external_endpoint, a.dial_endpoint);
    }

    #[tokio::test]
    async fn try_emit_pair_skips_when_external_missing() {
        let pub_ = CapturingPublisher::new();
        let tracker = PunchTracker::new();
        let a = peer(1, "203.0.113.1:34567");
        let b = peer(2, ""); // no external known
        let emitted = try_emit_pair(&pub_, &PeerBroadcaster::new(), &tracker, &a, &b, 0).await;
        assert!(!emitted);
        assert!(pub_.events().is_empty(), "no events should fire");
        assert!(tracker.is_empty(), "tracker must stay empty");
    }

    #[tokio::test]
    async fn try_emit_pair_is_idempotent_per_canonical_pair() {
        let pub_ = CapturingPublisher::new();
        let tracker = PunchTracker::new();
        let a = peer(1, "203.0.113.1:34567");
        let b = peer(2, "198.51.100.42:51820");
        let first = try_emit_pair(&pub_, &PeerBroadcaster::new(), &tracker, &a, &b, 1).await;
        let second = try_emit_pair(&pub_, &PeerBroadcaster::new(), &tracker, &a, &b, 2).await;
        // Swap order — should still be deduped via canonical_pair.
        let third = try_emit_pair(&pub_, &PeerBroadcaster::new(), &tracker, &b, &a, 3).await;
        assert!(first);
        assert!(!second);
        assert!(!third);
        assert_eq!(pub_.events().len(), 2);
        assert_eq!(tracker.len(), 1);
    }

    #[tokio::test]
    async fn try_emit_pair_skips_self_pair() {
        let pub_ = CapturingPublisher::new();
        let tracker = PunchTracker::new();
        let a = peer(7, "203.0.113.1:34567");
        let emitted = try_emit_pair(&pub_, &PeerBroadcaster::new(), &tracker, &a, &a, 0).await;
        assert!(!emitted);
        assert!(pub_.events().is_empty());
    }

    #[test]
    fn tracker_clear_removes_known_pair() {
        let tracker = PunchTracker::new();
        let pair = (Uuid::from_u128(1), Uuid::from_u128(2));
        assert!(tracker.mark(pair));
        assert!(tracker.contains(pair));
        assert!(tracker.clear(pair));
        assert!(!tracker.contains(pair));
    }
}
