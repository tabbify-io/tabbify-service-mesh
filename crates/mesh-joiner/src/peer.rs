//! Public + wire shapes for peers in the overlay mesh.
//!
//! [`PeerInfo`] is the API-level type returned to callers of
//! [`crate::Joiner::peers`]. [`RemotePeer`] is the wire shape the
//! coordinator returns over HTTP / SSE. They look identical except for
//! the binary-vs-base64 representation of the public key and the
//! string-vs-typed representation of `ula` / `listen_endpoint`.

use serde::{Deserialize, Serialize};
use std::net::{Ipv6Addr, SocketAddr};
use uuid::Uuid;

/// Public information about a peer participating in the mesh. Returned
/// by [`crate::Joiner::peers`] and surfaced in roster-change callbacks.
///
/// All fields are post-validation: [`Self::wg_public_key`] is exactly
/// 32 bytes, [`Self::ula`] is guaranteed to parse as IPv6, and
/// [`Self::listen_endpoint`] is `None` precisely when the peer is
/// passive (behind NAT, no known external endpoint).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerInfo {
    /// Coordinator-assigned UUID v7. Stable across roster updates.
    pub peer_id: Uuid,
    /// Raw 32-byte X25519 public key.
    pub wg_public_key: [u8; 32],
    /// IPv6 ULA assigned to this peer.
    pub ula: Ipv6Addr,
    /// Reported `WireGuard` listen endpoint. `None` means the peer is
    /// passive — we register their `Tunn` session but don't try to
    /// send handshake initiations; they'll initiate to us instead.
    pub listen_endpoint: Option<SocketAddr>,
    /// Human-readable display name.
    pub display_name: String,
    /// Role tags ("dev-machine", "wasm-host", ...).
    pub tags: Vec<String>,
    /// App-ULAs (`fd5a:1f02:...`) this peer currently hosts, parsed from
    /// the roster. The roster consumer installs an app-route for each
    /// (per-app-ULA routing) so traffic to `[app_ula]` reaches this peer.
    /// Empty for a peer that hosts no apps (the common case).
    #[serde(default)]
    pub hosted_app_ulas: Vec<Ipv6Addr>,
    /// Software version this peer reports running (e.g. `"v1.4.0"`),
    /// parsed straight through from the coordinator roster. `None` =
    /// unknown (older coordinator omitting the field).
    pub software_version: Option<String>,
    /// Mesh-joiner version this peer reports running (its own crate version,
    /// independent of `software_version`). `None` = unknown.
    pub mesh_version: Option<String>,
    /// Coordinator-stamped microseconds-since-epoch.
    pub joined_at_micros: i64,
}

/// Wire shape for a peer as the coordinator emits it. Strings are
/// validated into typed fields by [`crate::coordinator::client::remote_to_info`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemotePeer {
    /// Coordinator-assigned UUID v7.
    pub peer_id: Uuid,
    /// Base64-encoded 32-byte X25519 public key.
    pub wg_public_key: String,
    /// Textual IPv6 ULA.
    pub ula: String,
    /// Textual `host:port` listen endpoint, or empty / absent when the
    /// peer is passive.
    pub listen_endpoint: Option<String>,
    /// Human-readable display name.
    pub display_name: String,
    /// Role tags.
    pub tags: Vec<String>,
    /// App-ULAs (IPv6 literals, `fd5a:1f02:...`) this peer currently
    /// hosts, as advertised by the coordinator. Parsed into typed
    /// addresses by [`crate::coordinator::client::remote_to_info`].
    /// `#[serde(default)]` keeps older coordinators (which omit it)
    /// working — the peer is then treated as hosting no apps.
    #[serde(default)]
    pub hosted_app_ulas: Vec<String>,
    /// Software version the coordinator advertises for this peer. `None`
    /// from an older coordinator that omits it. `#[serde(default)]` keeps
    /// the wire format back-compatible.
    #[serde(default)]
    pub software_version: Option<String>,
    /// Mesh-joiner version the coordinator advertises for this peer (the peer's
    /// own crate version). `#[serde(default)]` keeps the wire format
    /// back-compatible with coordinators that omit it.
    #[serde(default)]
    pub mesh_version: Option<String>,
    /// Microseconds-since-epoch as stamped by the coordinator.
    pub joined_at_micros: i64,
}

/// SSE event types the coordinator emits on `/v1/mesh/peers/stream`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerEventKind {
    /// New peer registered.
    Added,
    /// Existing peer's metadata changed (e.g. endpoint shifted because
    /// the joiner's external IP rolled over).
    Updated,
    /// Peer deregistered or timed out.
    Removed,
    /// Stage 2 — a coordinator-driven instruction to fire UDP at a peer's
    /// external endpoint and punch a NAT hole. Not a roster mutation; the
    /// SSE consumer forwards it to the hole-punch task instead of touching
    /// the session table.
    HolePunch,
}

impl PeerEventKind {
    /// Parse the SSE `event:` field name.
    #[must_use]
    pub fn from_event_name(s: &str) -> Option<Self> {
        match s {
            "peer_added" => Some(Self::Added),
            "peer_updated" => Some(Self::Updated),
            "peer_removed" => Some(Self::Removed),
            "holepunch_initiate" => Some(Self::HolePunch),
            _ => None,
        }
    }
}

/// Payload of a `peer_removed` SSE event. The coordinator may omit
/// every other field — only the id is needed to drop routing state.
#[derive(Debug, Clone, Deserialize)]
pub struct PeerRemovedPayload {
    /// The departing peer's id.
    pub peer_id: Uuid,
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn parses_known_event_names() {
        assert_eq!(
            PeerEventKind::from_event_name("peer_added"),
            Some(PeerEventKind::Added)
        );
        assert_eq!(
            PeerEventKind::from_event_name("peer_updated"),
            Some(PeerEventKind::Updated)
        );
        assert_eq!(
            PeerEventKind::from_event_name("peer_removed"),
            Some(PeerEventKind::Removed)
        );
    }

    #[test]
    fn ignores_unknown_event_names() {
        assert!(PeerEventKind::from_event_name("heartbeat").is_none());
        assert!(PeerEventKind::from_event_name("").is_none());
    }

    /// The joiner must recognise the coordinator's Stage 2 hole-punch
    /// frame so the SSE consumer can route it to the punch task. The
    /// event name must match the coordinator's `HolePunchInitiate`
    /// `event_type` (`holepunch_initiate`) exactly.
    #[test]
    fn parses_holepunch_event_name() {
        assert_eq!(
            PeerEventKind::from_event_name("holepunch_initiate"),
            Some(PeerEventKind::HolePunch)
        );
    }

    /// Back-compat (SV-1): a roster entry from an older coordinator omits
    /// `software_version`; `RemotePeer` must deserialize it as `None`,
    /// never error. `None` = unknown.
    #[test]
    fn remote_peer_omitting_software_version_defaults_to_none() {
        let body = serde_json::json!({
            "peer_id": "01910f10-0000-7000-8000-000000000001",
            "wg_public_key": "AAAA",
            "ula": "fd5a:1f00:1::1",
            "display_name": "p",
            "tags": [],
            "joined_at_micros": 0
        });
        let r: RemotePeer =
            serde_json::from_value(body).expect("old roster entry must still parse");
        assert_eq!(r.software_version, None);
    }
}
