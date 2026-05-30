//! Mesh-native peer-lifecycle event types.
//!
//! These are the coordinator's own event/DTO types for the peer roster
//! state machine. They were previously sourced from `tabbify-events`
//! (Protobuf) when the coordinator wrote peer lifecycle into the substrate
//! event log. The standalone mesh owns these as plain Rust structs with
//! `serde` for any wire / persistence framing — no Protobuf, no external
//! schema dependency.
//!
//! Segment: `platform.mesh.peers`.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Canonical wire string for a mesh event, used as the `event_type` label
/// passed to an [`crate::publisher::EventPublisher`].
pub trait MeshEvent {
    /// The canonical event-type identifier.
    fn event_type() -> &'static str;
}

/// A peer joined the overlay mesh. Emitted by the coordinator when a
/// joiner's `POST /v1/mesh/register` succeeds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerJoined {
    /// Coordinator-assigned UUID v7 (string form).
    pub peer_id: String,
    /// 32-byte X25519 public key.
    pub wg_public_key: Vec<u8>,
    /// Assigned IPv6 ULA (textual).
    pub ula: String,
    /// Peer's reported listen address (may be empty if behind NAT).
    pub listen_endpoint: String,
    /// Human-readable peer name.
    pub display_name: String,
    /// Network the peer belongs to (selects its ULA block, spec §6). Empty
    /// is the default/unnamed network.
    #[serde(default)]
    pub network: String,
    /// Role hints: `["dev-machine", "wasm-host", ...]`.
    pub tags: Vec<String>,
    /// App-ULAs (IPv6 literals, `fd5a:1f02:...`) this peer hosts at
    /// register time. The coordinator stays app-agnostic — these are
    /// opaque `/128`s the peer declares it serves, advertised to all
    /// viewers exactly like [`Self::ula`] so other peers learn to route
    /// to it (per-app-ULA routing). `#[serde(default)]` keeps replay /
    /// older events back-compatible.
    #[serde(default)]
    pub hosted_app_ulas: Vec<String>,
    /// Joined-at, wall-clock micros.
    pub joined_at_micros: i64,
    /// Peer role: `"peer"` or `"runner"`. `#[serde(default)]` keeps
    /// replay of older events back-compatible (defaults to `"peer"`).
    #[serde(default = "default_kind")]
    pub kind: String,
    /// ULA of the supervisor that owns this runner. `None` for plain peers.
    /// `#[serde(default)]` keeps older events back-compatible.
    #[serde(default)]
    pub parent: Option<String>,
    /// UUID of the app this runner serves. `None` for plain peers.
    /// `#[serde(default)]` keeps older events back-compatible.
    #[serde(default)]
    pub app_uuid: Option<String>,
    /// Software version the registrant reported (e.g. `"v1.4.0"`).
    /// `#[serde(default)]` keeps replay / older events back-compatible.
    #[serde(default)]
    pub software_version: Option<String>,
}

fn default_kind() -> String {
    "peer".to_owned()
}

impl MeshEvent for PeerJoined {
    fn event_type() -> &'static str {
        "peer_joined"
    }
}

/// Periodic keepalive. The coordinator stamps `observed_external` from the
/// source address of the HTTP request — joiners use this for hole-punch
/// coordination in Stage 2.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerHeartbeat {
    /// Peer id originally returned by `register`.
    pub peer_id: String,
    /// Socket addr the coordinator saw on the heartbeat request.
    pub observed_external: String,
    /// The peer's CURRENT full set of hosted app-ULAs (IPv6 literals,
    /// `fd5a:1f02:...`). A supervisor re-sends its entire hosted set on
    /// every heartbeat; the coordinator REPLACES the peer's stored set
    /// with this one (per-app-ULA routing). `#[serde(default)]` keeps
    /// replay / older heartbeats back-compatible.
    #[serde(default)]
    pub hosted_app_ulas: Vec<String>,
    /// Software version reported on this heartbeat. `None` (older / omitting
    /// peer) means "no change" — the apply layer leaves the stored value
    /// untouched. `#[serde(default)]` keeps replay back-compatible.
    #[serde(default)]
    pub software_version: Option<String>,
    /// Heartbeat wall-clock micros.
    pub at_micros: i64,
}

impl MeshEvent for PeerHeartbeat {
    fn event_type() -> &'static str {
        "peer_heartbeat"
    }
}

/// A peer left the overlay (graceful deregister OR heartbeat timeout).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerLeft {
    /// Peer id that left.
    pub peer_id: String,
    /// Reason string (e.g. `"client_deregister"`, `"heartbeat_timeout"`).
    pub reason: String,
    /// Left-at wall-clock micros.
    pub left_at_micros: i64,
}

impl MeshEvent for PeerLeft {
    fn event_type() -> &'static str {
        "peer_left"
    }
}

/// Stage 2 — coordinator-driven UDP hole punch initiation.
///
/// When the coordinator observes that two peers each have a known
/// `observed_external` socket addr (from prior heartbeats), it emits a
/// pair of these (one per peer, with initiator/target swapped) so the
/// joiners can simultaneously fire UDP packets at each other's external
/// endpoint and punch a hole through their NATs. The actual hole-punching
/// state machine (timing / retries / NAT-type detection) is deferred to a
/// real-NAT cloud rollout; this type pins the protocol shape now so joiner
/// subscribers don't churn when the real impl lands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct HolePunchInitiate {
    /// Peer that should send first.
    pub initiator_peer_id: String,
    /// Peer to dial.
    pub target_peer_id: String,
    /// External endpoint to dial, e.g. `"203.0.113.42:34567"`.
    pub target_external_endpoint: String,
    /// Emission wall-clock micros.
    pub timestamp_micros: i64,
}

impl MeshEvent for HolePunchInitiate {
    fn event_type() -> &'static str {
        "holepunch_initiate"
    }
}
