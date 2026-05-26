//! SSE peer-stream plumbing.
//!
//! Tracks one tokio broadcast channel of `PeerEvent`s; SSE handlers
//! subscribe to it and translate each event into a `data:` frame. The
//! channel is bounded — slow consumers see `Lagged` and drop those frames
//! rather than blocking the coordinator.

use crate::http::api::PeerInfo;
use crate::roster::events::HolePunchInitiate;
use serde::Serialize;
use tokio::sync::broadcast;

/// Capacity of the broadcast channel — small enough to spot lag in logs,
/// large enough that a slow subscriber doesn't lose updates from a single
/// burst of registrations.
pub const PEER_BROADCAST_CAPACITY: usize = 256;

/// One mutation to the peer roster, broadcast to every SSE subscriber.
///
/// The broadcast channel is shared across all subscribers, so per-viewer
/// ACL filtering happens in the per-subscriber stream adapter rather than
/// at broadcast time (see [`crate::http::api`]). For that filtering to
/// work on removals too, [`PeerEvent::Removed`] carries the departed
/// peer's `tags` — the viewer should only see a remove frame for a peer it
/// was previously allowed to see.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PeerEvent {
    /// A peer was added to the roster.
    Added(PeerInfo),
    /// A peer was updated in place (heartbeat, idempotent re-register).
    Updated(PeerInfo),
    /// A peer was removed from the roster.
    Removed {
        /// The departed peer's id.
        peer_id: String,
        /// The departed peer's tags — used for per-viewer ACL filtering of
        /// the remove frame. Not serialised onto the wire (the public
        /// `peer_removed` payload stays `{ "peer_id": ... }`).
        #[serde(skip)]
        tags: Vec<String>,
    },
    /// Stage 2 — a coordinator-driven hole-punch instruction. Unlike the
    /// roster events this is addressed to a single peer (the initiator):
    /// the per-viewer SSE filter forwards it only to the peer whose id
    /// matches `initiator_peer_id`, so each side is told to fire UDP at
    /// the other's external endpoint. Carried on the same broadcast
    /// channel + stream as roster frames rather than a sibling endpoint.
    HolePunch(HolePunchInitiate),
}

impl PeerEvent {
    /// The SSE `event:` field name, matching the public API contract.
    #[must_use]
    pub const fn event_name(&self) -> &'static str {
        match self {
            Self::Added(_) => "peer_added",
            Self::Updated(_) => "peer_updated",
            Self::Removed { .. } => "peer_removed",
            Self::HolePunch(_) => "holepunch_initiate",
        }
    }

    /// The initiator peer id of a [`PeerEvent::HolePunch`] (the peer that
    /// should fire UDP first), or `None` for roster events. The per-viewer
    /// SSE filter routes a hole-punch frame to exactly this peer.
    #[must_use]
    pub fn holepunch_initiator(&self) -> Option<&str> {
        match self {
            Self::HolePunch(hp) => Some(hp.initiator_peer_id.as_str()),
            _ => None,
        }
    }

    /// The tags of the peer this event concerns — used by the SSE filter
    /// to decide whether a given viewer may receive this frame.
    #[must_use]
    pub fn peer_tags(&self) -> &[String] {
        match self {
            Self::Added(p) | Self::Updated(p) => &p.tags,
            Self::Removed { tags, .. } => tags,
            // HolePunch is routed by initiator id, not tags.
            Self::HolePunch(_) => &[],
        }
    }

    /// Serialise the payload that goes after the SSE `data:` prefix.
    ///
    /// # Errors
    /// Returns `serde_json::Error` only if `PeerInfo` serialisation
    /// fails, which would indicate a programming bug (all fields are
    /// `String`s or `Vec<String>`).
    pub fn data_payload(&self) -> Result<String, serde_json::Error> {
        match self {
            Self::Added(p) | Self::Updated(p) => serde_json::to_string(p),
            Self::Removed { peer_id, .. } => serde_json::to_string(&serde_json::json!({
                "peer_id": peer_id,
            })),
            Self::HolePunch(hp) => serde_json::to_string(hp),
        }
    }
}

/// Shared broadcast sender — cheap to clone.
///
/// New subscribers receive only events emitted *after* they subscribe;
/// the SSE handler bootstraps each new connection with the current
/// roster snapshot to bridge that gap.
#[derive(Clone)]
pub struct PeerBroadcaster {
    tx: broadcast::Sender<PeerEvent>,
}

impl PeerBroadcaster {
    /// Build a new broadcaster with the default capacity.
    #[must_use]
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(PEER_BROADCAST_CAPACITY);
        Self { tx }
    }

    /// Broadcast an event. Returns silently when no SSE subscribers are
    /// connected — that's the normal idle state.
    pub fn broadcast(&self, event: PeerEvent) {
        let _ = self.tx.send(event);
    }

    /// Open a fresh subscription.
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<PeerEvent> {
        self.tx.subscribe()
    }
}

impl Default for PeerBroadcaster {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::roster::events::HolePunchInitiate;

    fn sample_holepunch() -> HolePunchInitiate {
        HolePunchInitiate {
            initiator_peer_id: "aaaaaaaa-0000-7000-8000-000000000001".into(),
            target_peer_id: "bbbbbbbb-0000-7000-8000-000000000002".into(),
            target_external_endpoint: "203.0.113.1:51820".into(),
            timestamp_micros: 99,
        }
    }

    /// A `HolePunch` event must surface on the wire as `holepunch_initiate`
    /// with a JSON body that round-trips back to the original event — that
    /// is the contract the joiner's SSE consumer parses against.
    #[test]
    fn holepunch_event_name_and_payload_round_trip() {
        let hp = sample_holepunch();
        let ev = PeerEvent::HolePunch(hp.clone());
        assert_eq!(ev.event_name(), "holepunch_initiate");
        let payload = ev.data_payload().expect("payload serialises");
        let decoded: HolePunchInitiate =
            serde_json::from_str(&payload).expect("payload round-trips");
        assert_eq!(decoded, hp);
    }

    /// The per-viewer SSE filter routes a hole-punch event to its initiator
    /// only, so `PeerEvent` must expose the initiator id for `HolePunch` and
    /// `None` for roster events (which are tag-filtered instead).
    #[test]
    fn holepunch_initiator_exposed_for_filtering() {
        let hp = sample_holepunch();
        let ev = PeerEvent::HolePunch(hp.clone());
        assert_eq!(
            ev.holepunch_initiator(),
            Some(hp.initiator_peer_id.as_str())
        );

        let removed = PeerEvent::Removed {
            peer_id: "x".into(),
            tags: vec![],
        };
        assert_eq!(removed.holepunch_initiator(), None);
    }
}
