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
    /// Joined-at, wall-clock micros.
    pub joined_at_micros: i64,
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
