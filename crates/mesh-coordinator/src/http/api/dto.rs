//! Wire-shape DTOs for every `/v1/mesh/...` endpoint plus the SSE
//! `peers/stream` query. Lives separately from the handlers so other
//! modules (e.g. roster/identity / openapi.rs) can import the DTOs
//! without dragging in axum routing machinery.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// JSON shape returned to clients for every peer. Mirrors the proto
/// `PeerJoined` payload, except `wg_public_key` is base64-encoded.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PeerInfo {
    /// Coordinator-assigned UUID v7 (string form).
    pub peer_id: String,
    /// 32-byte X25519 public key, base64-encoded (standard alphabet).
    pub wg_public_key: String,
    /// Assigned IPv6 ULA, textual form.
    pub ula: String,
    /// Joiner-reported listen socket (`host:port`).
    pub listen_endpoint: Option<String>,
    /// Human-readable peer name.
    pub display_name: String,
    /// Network this peer belongs to — selects its ULA block (a tag/claim
    /// per spec §6). Empty string is the default/unnamed network.
    #[serde(default)]
    pub network: String,
    /// Role hint labels.
    pub tags: Vec<String>,
    /// App-ULAs (IPv6 literals, `fd5a:1f02:...`) this peer currently
    /// hosts. Advertised to every viewer exactly like [`Self::ula`] so a
    /// consuming peer learns to route app-bound traffic to this host
    /// (per-app-ULA routing). `#[serde(default)]` keeps the wire format
    /// back-compatible with peers/coordinators that omit it.
    #[serde(default)]
    pub hosted_app_ulas: Vec<String>,
    /// Joined-at wall-clock micros.
    pub joined_at_micros: i64,
    /// Peer role. `"peer"` for a normal supervisor/joiner; `"runner"` for
    /// a per-app runner process that joins as its own mesh peer.
    /// Defaults to `"peer"` for backward compatibility — existing joiners
    /// that omit this field are treated as plain peers.
    #[serde(default = "default_kind")]
    pub kind: String,
    /// ULA of the supervisor that owns this runner. `None` for a plain
    /// peer. Set by runner peers so `tabbify-node` can build the
    /// supervisor → runners topology tree.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    /// UUID of the app this runner serves. `None` for a plain peer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_uuid: Option<String>,
}

pub(super) fn default_kind() -> String {
    "peer".to_owned()
}

/// Body of `POST /v1/mesh/register`.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct RegisterRequest {
    /// 32-byte X25519 public key, base64-encoded.
    pub wg_public_key: String,
    /// Optional `WireGuard` listen socket — empty for NAT-bound peers.
    #[serde(default)]
    pub listen_endpoint: Option<String>,
    /// UDP port the joiner's `WireGuard` socket is bound to. Sent so the
    /// coordinator can synthesize the peer's reflexive endpoint as
    /// `<observed-public-ip>:<wg_listen_port>` for cone-NAT traversal
    /// (the HTTP source port is a TCP port, unrelated to the WG UDP port).
    /// `#[serde(default)]` keeps the wire format back-compatible: an older
    /// joiner that omits it falls back to its self-reported endpoint.
    #[serde(default)]
    pub wg_listen_port: Option<u16>,
    /// Human-readable nickname.
    pub display_name: String,
    /// Network to join — selects the peer's ULA block (spec §6). Empty
    /// (the default) lands the peer in the default/unnamed network.
    ///
    /// Pre-E4 this is joiner-supplied (trust-on-assert); E4 will overwrite
    /// it with the validated join-token claim. See
    /// [`crate::roster::identity`].
    #[serde(default)]
    pub network: String,
    /// Role hints. Pre-E4 joiner-supplied; E4 replaces with JWT claims.
    #[serde(default)]
    pub tags: Vec<String>,
    /// App-ULAs (IPv6 literals, `fd5a:1f02:...`) the registrant already
    /// hosts at register time. Stored as the peer's initial hosted set
    /// and advertised to other viewers (per-app-ULA routing).
    /// `#[serde(default)]` keeps older joiners (which omit it) working.
    #[serde(default)]
    pub hosted_app_ulas: Vec<String>,
    /// Peer role. `"peer"` (default) for a normal joiner/supervisor;
    /// `"runner"` for a per-app runner. `#[serde(default)]` keeps
    /// existing joiners that omit it working — they default to `"peer"`.
    #[serde(default = "default_kind")]
    pub kind: String,
    /// ULA of the supervisor that owns this runner. Omitted (→ `None`)
    /// for plain peers. `#[serde(default)]` for backward compatibility.
    #[serde(default)]
    pub parent: Option<String>,
    /// UUID of the app this runner serves. Omitted (→ `None`) for plain
    /// peers. `#[serde(default)]` for backward compatibility.
    #[serde(default)]
    pub app_uuid: Option<String>,
    /// Explicit IPv6 ULA the peer wants to be assigned (e.g.
    /// `"fd5a:1f02:aaaa::1"`). When present, well-formed, and unclaimed (or
    /// claimed by THIS same peer — re-join / sticky identity), the
    /// coordinator assigns it verbatim. When absent the coordinator falls
    /// back to the standard idx-based derivation. A different peer holding
    /// the same ULA causes the register to be rejected with
    /// [`crate::roster::coordinator::CoordinatorError::UlaConflict`].
    /// `#[serde(default)]` keeps older joiners (which omit this field) working.
    #[serde(default)]
    pub requested_ula: Option<String>,
}

/// Body of `POST /v1/mesh/register` response.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct RegisterResponse {
    /// Coordinator-assigned UUID v7.
    pub peer_id: String,
    /// Assigned IPv6 ULA, textual form.
    pub ula: String,
    /// Snapshot of the full roster, including the newly-registered peer.
    pub peers: Vec<PeerInfo>,
    /// The peer's own observed external IP (the source IP the coordinator
    /// saw the register request arrive from — its NAT's public IP). `None`
    /// when the source addr was unavailable (tests without connect-info).
    /// The joiner can log this and/or compare it against its self-detected
    /// address to know whether it is behind NAT.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_ip: Option<String>,
    /// The reflexive endpoint the coordinator stored for this peer (what
    /// other peers will dial), i.e. `<observed-ip>:<wg_listen_port>` when
    /// behind NAT, or the self-reported endpoint when already public.
    /// `None` for a fully-passive peer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_endpoint: Option<String>,
}

/// Body of `POST /v1/mesh/heartbeat`.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct HeartbeatRequest {
    /// Peer id originally returned by `register`.
    pub peer_id: String,
    /// UDP port the joiner's `WireGuard` socket is bound to — same role as
    /// on [`RegisterRequest`]. Re-sent on every heartbeat so the
    /// coordinator can refresh the reflexive endpoint if the peer's
    /// observed public IP changes (e.g. NAT rebind / roaming).
    /// `#[serde(default)]` for back-compat with older joiners.
    #[serde(default)]
    pub wg_listen_port: Option<u16>,
    /// The supervisor's CURRENT full set of hosted app-ULAs (IPv6
    /// literals, `fd5a:1f02:...`), re-sent on every heartbeat. The
    /// coordinator REPLACES the peer's stored set with this one and, if
    /// it changed, re-broadcasts the peer so viewers re-learn the routes
    /// (per-app-ULA routing). `#[serde(default)]` keeps older joiners
    /// (which omit it) working — they are simply treated as hosting no
    /// apps.
    #[serde(default)]
    pub hosted_app_ulas: Vec<String>,
}

/// Body of `POST /v1/mesh/heartbeat` response.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct HeartbeatResponse {
    /// Snapshot of the current roster.
    pub peers: Vec<PeerInfo>,
    /// The peer's own observed external IP on this heartbeat. Same
    /// semantics as [`RegisterResponse::observed_ip`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_ip: Option<String>,
    /// The reflexive endpoint currently stored for this peer. Same
    /// semantics as [`RegisterResponse::observed_endpoint`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_endpoint: Option<String>,
}

/// Body of `POST /v1/mesh/deregister`.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct DeregisterRequest {
    /// Peer id to remove.
    pub peer_id: String,
}

/// Body of `GET /v1/mesh/peers` response.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct RosterResponse {
    /// All currently-registered peers, ordered by peer index.
    pub peers: Vec<PeerInfo>,
}

/// JSON error envelope. Kept dead simple — there's no public-facing
/// error code taxonomy yet.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ApiError {
    /// Human-readable error description.
    pub error: String,
}

/// Query parameters for `GET /v1/mesh/peers/stream`.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct StreamQuery {
    /// The subscribing peer's id. When present, the stream is ACL-filtered
    /// to the peers that viewer is policy-permitted to see (and converges
    /// correctly on policy changes — see `ViewerFilter`). When absent,
    /// the stream is unfiltered (admin/debug clients). A joiner passes its
    /// own `peer_id` here so it only ever learns allowed peers.
    #[serde(default)]
    pub peer_id: Option<String>,
}
