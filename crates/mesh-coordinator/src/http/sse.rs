//! SSE peer-stream plumbing.
//!
//! Tracks one tokio broadcast channel of `PeerEvent`s; SSE handlers
//! subscribe to it and translate each event into a `data:` frame. The
//! channel is bounded — slow consumers see `Lagged` and drop those frames
//! rather than blocking the coordinator.

use crate::http::api::PeerInfo;
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
}

impl PeerEvent {
    /// The SSE `event:` field name, matching the public API contract.
    #[must_use]
    pub const fn event_name(&self) -> &'static str {
        match self {
            Self::Added(_) => "peer_added",
            Self::Updated(_) => "peer_updated",
            Self::Removed { .. } => "peer_removed",
        }
    }

    /// The tags of the peer this event concerns — used by the SSE filter
    /// to decide whether a given viewer may receive this frame.
    #[must_use]
    pub fn peer_tags(&self) -> &[String] {
        match self {
            Self::Added(p) | Self::Updated(p) => &p.tags,
            Self::Removed { tags, .. } => tags,
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
