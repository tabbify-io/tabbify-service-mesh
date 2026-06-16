//! Stage 2 — UDP hole-punch initiation events (FUNCTIONAL; basic cone-NAT).
//!
//! When two peers each have a known `observed_external` socket addr
//! (recorded from prior heartbeats), the coordinator emits a pair of
//! `HolePunchInitiate` events on the `platform.mesh.peers` segment — one
//! per peer, with `initiator_peer_id` / `target_peer_id` swapped so
//! both sides know the other's external endpoint and can fire UDP packets
//! simultaneously. The joiner-side subscriber consumes these and actually
//! fires the synchronized bursts (see `mesh-joiner` `nat::holepunch`), so the
//! basic cone-NAT punch path is END-TO-END LIVE, not a skeleton.
//!
//! Deferred (advanced only): NAT-type detection, retry/backoff strategy for
//! symmetric NAT, and adaptive timing. The relay floor already provides the
//! fallback when a punch doesn't establish a direct path.
//!
//! Gating logic: the coordinator tracks an in-memory `DashMap<(Uuid,
//! Uuid), last_emit_micros>` of punched ordered pairs and RE-EMITS a pair
//! once its last emit is older than [`PUNCH_REEMIT_COOLDOWN_MICROS`].
//! Pairs are keyed in canonical (smaller, larger) form so heartbeats from
//! either side hit the same key.
//!
//! Why re-emit (not emit-once): a UDP hole punch is not guaranteed to
//! succeed on the first simultaneous attempt — NAT mappings expire, the
//! two sides' bursts must overlap, and a peer whose SSE stream was briefly
//! disconnected at emit time would otherwise miss its punch directive
//! FOREVER (the joiner fires a short handshake burst, not a sustained
//! retry). Emitting once per coordinator lifetime therefore orphans any
//! NAT'd peer whose first punch window misses — observed live when a peer
//! re-registered with a fresh identity after a coordinator/host replace:
//! the surviving peer kept the stale pairing and never re-punched. Re-
//! emitting on a cooldown drives repeated bidirectional bursts until the
//! NATs align and the `WireGuard` session establishes. The cooldown bounds
//! the SSE traffic; the joiner no-ops a punch directive for a peer it is
//! already sessioned with, so re-emits to an established pair are cheap.
//!
//! Called from `coordinator.rs::heartbeat`: after stamping `peer A`'s
//! heartbeat with its newly observed external endpoint, iterate over
//! every other peer `B` that also has a non-empty external endpoint and
//! emit the pair if `(min(A,B), max(A,B))` isn't yet in the punched set.

use crate::http::sse::{PeerBroadcaster, PeerEvent};
use crate::publisher::{EventPublisher, publish_event};
use crate::roster::coordinator::PEER_SEGMENT;
use crate::roster::events::HolePunchInitiate;
use dashmap::DashMap;
use std::sync::Arc;
use tracing::debug;
use uuid::Uuid;

/// Re-emit cooldown for a hole-punch pair.
///
/// Once a pair's last emit is older than this, the next heartbeat re-emits the
/// bidirectional punch — repeated simultaneous bursts until the NATs align (see
/// module docs). Set a touch below the joiner heartbeat interval so a stuck
/// pair gets a fresh attempt roughly every heartbeat, while an established pair
/// costs at most one (no-op'd) directive per window.
pub const PUNCH_REEMIT_COOLDOWN_MICROS: i64 = 15_000_000; // 15s

/// TTL after which a punch pair is reaped as stale.
///
/// A live pair re-claims (refreshing `last_emit`) every
/// [`PUNCH_REEMIT_COOLDOWN_MICROS`] while either side keeps heartbeating, so a
/// pair only ages past this when a peer vanished WITHOUT a clean deregister
/// (the precise case — a graceful deregister calls [`PunchTracker::remove_peer`]
/// immediately). Set well above the cooldown so a merely-quiet-but-live pair is
/// never reaped. This bounds the tracker's growth over a long-running mesh.
pub const PUNCH_PAIR_TTL_MICROS: i64 = 300_000_000; // 5 min (≫ cooldown)

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

/// Last `HolePunchInitiate` emit time (unix micros) per canonical pair.
///
/// Tracks last-emit (not just presence) so a stuck pair is re-punched on a
/// cooldown rather than emitted once-and-forgotten. Cheap to clone — wraps an
/// `Arc` internally via `DashMap`.
#[derive(Default, Clone)]
pub struct PunchTracker {
    last_emit: Arc<DashMap<PunchPair, i64>>,
}

impl PunchTracker {
    /// Empty tracker.
    #[must_use]
    pub fn new() -> Self {
        Self {
            last_emit: Arc::new(DashMap::new()),
        }
    }

    /// Claim the right to emit a punch for this canonical pair at `now_micros`.
    ///
    /// Returns `true` (and records `now_micros` as the new last-emit) when the
    /// pair has never been emitted OR its last emit is at least
    /// [`PUNCH_REEMIT_COOLDOWN_MICROS`] ago — i.e. it's time to (re-)punch.
    /// Returns `false` within the cooldown window (deduped), so repeated
    /// heartbeats don't spam a freshly-emitted pair.
    pub fn claim(&self, pair: PunchPair, now_micros: i64) -> bool {
        use dashmap::mapref::entry::Entry;
        match self.last_emit.entry(pair) {
            Entry::Occupied(mut e) => {
                if now_micros - *e.get() >= PUNCH_REEMIT_COOLDOWN_MICROS {
                    *e.get_mut() = now_micros;
                    true
                } else {
                    false
                }
            }
            Entry::Vacant(e) => {
                e.insert(now_micros);
                true
            }
        }
    }

    /// Has this canonical pair ever been emitted?
    #[must_use]
    pub fn contains(&self, pair: PunchPair) -> bool {
        self.last_emit.contains_key(&pair)
    }

    /// Forget the pair — used in tests / by future eviction logic.
    pub fn clear(&self, pair: PunchPair) -> bool {
        self.last_emit.remove(&pair).is_some()
    }

    /// Remove every pair involving `peer_id`. Called when a peer deregisters or
    /// times out so its punch pairs are cleaned up immediately (the precise,
    /// non-TTL path). Returns the number of pairs removed.
    pub fn remove_peer(&self, peer_id: Uuid) -> usize {
        let before = self.last_emit.len();
        self.last_emit
            .retain(|&(a, b), _| a != peer_id && b != peer_id);
        before - self.last_emit.len()
    }

    /// Reap pairs whose last emit is older than `cutoff_micros` — a backstop for
    /// pairs whose peers vanished without a clean deregister. Returns the number
    /// removed. A live pair keeps a fresh `last_emit` (re-claims on the cooldown
    /// while either side heartbeats), so only genuinely stale pairs age out.
    pub fn reap_older_than(&self, cutoff_micros: i64) -> usize {
        let before = self.last_emit.len();
        self.last_emit.retain(|_, &mut last| last >= cutoff_micros);
        before - self.last_emit.len()
    }

    /// Number of pairs tracked.
    #[must_use]
    pub fn len(&self) -> usize {
        self.last_emit.len()
    }

    /// Convenience predicate.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.last_emit.is_empty()
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
    // (Re-)emit only when the pair is new or its last punch is older than the
    // cooldown — drives sustained bidirectional bursts until the session lands,
    // without spamming a freshly-punched pair on every heartbeat.
    if !tracker.claim(pair, now_micros) {
        return false;
    }
    debug!(
        a = %a.peer_id,
        b = %b.peer_id,
        ext_a = %a.dial_endpoint,
        ext_b = %b.dial_endpoint,
        "holepunch: emitting initiate pair (joiners will fire synchronized bursts)",
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
    async fn try_emit_pair_reemits_after_cooldown() {
        let pub_ = CapturingPublisher::new();
        let tracker = PunchTracker::new();
        let a = peer(1, "203.0.113.1:34567");
        let b = peer(2, "198.51.100.42:51820");
        // First punch at t=0.
        assert!(try_emit_pair(&pub_, &PeerBroadcaster::new(), &tracker, &a, &b, 0).await);
        // Still within the cooldown -> deduped (no re-punch yet).
        assert!(
            !try_emit_pair(
                &pub_,
                &PeerBroadcaster::new(),
                &tracker,
                &a,
                &b,
                PUNCH_REEMIT_COOLDOWN_MICROS - 1,
            )
            .await
        );
        // At the cooldown boundary -> re-emits the pair so a stuck punch retries.
        assert!(
            try_emit_pair(
                &pub_,
                &PeerBroadcaster::new(),
                &tracker,
                &a,
                &b,
                PUNCH_REEMIT_COOLDOWN_MICROS,
            )
            .await
        );
        // Two emits => four HolePunchInitiate events; still one tracked pair.
        assert_eq!(pub_.events().len(), 4);
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
        assert!(tracker.claim(pair, 0));
        assert!(tracker.contains(pair));
        assert!(tracker.clear(pair));
        assert!(!tracker.contains(pair));
    }

    #[test]
    fn remove_peer_drops_all_pairs_involving_it() {
        let tracker = PunchTracker::new();
        let a = Uuid::from_u128(1);
        let b = Uuid::from_u128(2);
        let c = Uuid::from_u128(3);
        tracker.claim(canonical_pair(a, b), 0);
        tracker.claim(canonical_pair(a, c), 0);
        tracker.claim(canonical_pair(b, c), 0);
        assert_eq!(tracker.len(), 3);
        // Removing `a` drops (a,b) and (a,c) but keeps (b,c).
        assert_eq!(tracker.remove_peer(a), 2);
        assert_eq!(tracker.len(), 1);
        assert!(tracker.contains(canonical_pair(b, c)));
        assert!(!tracker.contains(canonical_pair(a, b)));
    }

    #[test]
    fn reap_older_than_removes_only_stale_pairs() {
        let tracker = PunchTracker::new();
        let fresh = canonical_pair(Uuid::from_u128(1), Uuid::from_u128(2));
        let stale = canonical_pair(Uuid::from_u128(3), Uuid::from_u128(4));
        tracker.claim(stale, 1_000); // old last_emit
        tracker.claim(fresh, 10_000); // recent last_emit
        // Cutoff between the two — only `stale` is older than it.
        assert_eq!(tracker.reap_older_than(5_000), 1);
        assert!(tracker.contains(fresh), "fresh pair survives");
        assert!(!tracker.contains(stale), "stale pair reaped");
    }

    #[test]
    fn claim_dedupes_within_cooldown_then_allows_after() {
        let tracker = PunchTracker::new();
        let pair = (Uuid::from_u128(1), Uuid::from_u128(2));
        assert!(tracker.claim(pair, 1_000), "first claim wins");
        assert!(!tracker.claim(pair, 1_000), "same instant -> deduped");
        assert!(
            !tracker.claim(pair, 1_000 + PUNCH_REEMIT_COOLDOWN_MICROS - 1),
            "just under cooldown -> deduped"
        );
        assert!(
            tracker.claim(pair, 1_000 + PUNCH_REEMIT_COOLDOWN_MICROS),
            "cooldown elapsed -> re-claim"
        );
    }
}
