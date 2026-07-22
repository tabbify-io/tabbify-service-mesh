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
    /// Reported software version of the binary this peer is running
    /// (e.g. `"v1.4.0"`). `None` = unknown — set by the host (supervisor)
    /// once it learns its own version; a coordinator/joiner that omits it
    /// (older build) deserializes to `None`. `None` is NEVER a downgrade
    /// trigger (self-update health gate, spec P0). `#[serde(default)]`
    /// keeps the wire format back-compatible.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub software_version: Option<String>,
    /// Mesh-joiner version this peer reports running (its own crate version,
    /// independent of `software_version`). `None` = unknown. Omitted from the
    /// wire when `None` to stay back-compatible.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mesh_version: Option<String>,
    /// Whether this peer declared itself **relay-only** — it has NO reachable
    /// direct endpoint (e.g. it runs in a container netns with no inbound mesh
    /// port). A relay-only peer is advertised with `listen_endpoint = None`
    /// and is NEVER a hole-punch target. `#[serde(default)]` keeps the wire
    /// format back-compatible with coordinators/peers that predate the field
    /// (→ `false`, the directly-reachable default).
    #[serde(default)]
    pub relay_only: bool,
    /// LIVE connectivity of this peer (the admin direct/relay pill) — distinct
    /// from the `relay_only` policy flag above.
    ///
    /// By DEFAULT (no `?vantage`) this is a PER-MACHINE self-view: `Some("direct")`
    /// when THIS peer reported at least one direct (p2p) path of its own on its
    /// last heartbeat, `Some("relay")` when it reported edges but all relayed,
    /// and `None` when it reported no edges (a just-joined or older joiner →
    /// "unknown"). The self-view is what lets the pill show "Direct" for peers
    /// holding a p2p path in a topology where the serving node is relay-only.
    ///
    /// When the roster is fetched with `?vantage=<peer-id>`, this falls back to
    /// the single-vantage view instead: the live path to this peer AS SEEN BY
    /// the vantage peer (`Some("direct")` / `Some("relay")` / `None` when the
    /// vantage reported no edge to this peer).
    ///
    /// `relay_only` explains *why* a path is relay by design; this shows the
    /// *actual current route*. `#[serde(default)]` keeps the wire
    /// back-compatible (older coordinators omit it → `None`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connectivity: Option<String>,
    /// Age in ms of the connectivity observation that produced
    /// [`Self::connectivity`] — the value behind the admin pill's "last data
    /// Ns ago" tooltip (2026-06-07 visibility design). For the self-view
    /// default this is the FRESHEST (min) age across the peer's own reported
    /// edges; for an explicit `?vantage` it is that single edge's age. `None`
    /// when `connectivity` is `None` (no edge → nothing to age), and also for
    /// the `"dead"` black-hole state (a wedged data plane has no live edge to
    /// age). `#[serde(default, skip_serializing_if = ...)]` keeps the wire
    /// back-compatible (older coordinators omit it → `None`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connectivity_age_ms: Option<u64>,
}

pub(super) fn default_kind() -> String {
    "peer".to_owned()
}

/// serde default for [`HeartbeatRequest::dataplane_healthy`]: `true`. Fail-open
/// — an absent field means a legacy joiner that can't report, and it must be
/// assumed healthy, never a black hole (so a new coordinator never paints a
/// false "dead" pill for an older peer).
pub(super) const fn default_dataplane_healthy() -> bool {
    true
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
    /// [`crate::roster::coordinator::CoordinatorError::UlaConflict`]; a
    /// host-slot address outside the peer's own (authenticated) network
    /// block is rejected with
    /// [`crate::roster::coordinator::CoordinatorError::UlaNetworkMismatch`]
    /// (both 409, so the joiner's sticky-then-free fallback recovers).
    /// `#[serde(default)]` keeps older joiners (which omit this field) working.
    #[serde(default)]
    pub requested_ula: Option<String>,
    /// Software version the registrant is running (e.g. `"v1.4.0"`).
    /// Host-supplied; `#[serde(default)]` → `None` for older joiners.
    #[serde(default)]
    pub software_version: Option<String>,
    /// Mesh-joiner version the registrant is running (self-reported crate
    /// version). `#[serde(default)]` → `None` for older joiners.
    #[serde(default)]
    pub mesh_version: Option<String>,
    /// The registrant declares it is **relay-only**: no reachable direct
    /// endpoint (e.g. a container netns with no inbound mesh port). When
    /// `true`, the coordinator (a) advertises NO direct listen endpoint for
    /// this peer (no reflexive synthesis) and (b) suppresses every hole-punch
    /// directive for any pair involving it, so a relay-only ↔ NAT'd handshake
    /// stays single-sided and completes over the relay instead of thrashing on
    /// simultaneous inits. `#[serde(default)]` → `false` for older joiners.
    #[serde(default)]
    pub relay_only: bool,
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

/// One reported connectivity edge in a heartbeat (connectivity
/// visibility).
///
/// Mirrors the joiner's `PeerPath`: THIS reporter's live data path to peer
/// `peer_id` is direct (p2p) when `direct == true`, else via the DERP relay
/// floor. `last_rx_age_ms` is how stale that observation is. The coordinator
/// stores these per reporter and stamps `PeerInfo.connectivity` from a
/// requested vantage. `#[serde(default)]` on the carrier
/// ([`HeartbeatRequest::peer_paths`]) keeps an older joiner (no edges)
/// interoperable.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct PeerPathDto {
    /// The peer whose live path this reporter is describing (string UUID).
    pub peer_id: String,
    /// `true` = reporter's current data path to that peer is direct (p2p);
    /// `false` = relay.
    pub direct: bool,
    /// Milliseconds since the reporter last received a valid datagram from
    /// that peer.
    #[serde(default)]
    pub last_rx_age_ms: u64,
    /// Whether the reporter's LATEST inbound `WireGuard` handshake-class frame
    /// from that peer arrived over its direct UDP socket (`Some(true)`) or via
    /// the relay (`Some(false)`). `None` = no handshake-class frame observed
    /// yet, or an older joiner that does not report the field
    /// (`#[serde(default)]` keeps it interoperable). Canary observability.
    #[serde(default)]
    pub last_handshake_direct: Option<bool>,
    /// Milliseconds since that latest handshake-class frame; `None` exactly
    /// when `last_handshake_direct` is `None`.
    #[serde(default)]
    pub last_handshake_age_ms: Option<u64>,
    /// The reporter's lifetime count of valid inbound handshake-class frames
    /// from that peer — the between-heartbeats delta is the pair's
    /// re-handshake RATE (thrash signature). `0` from older joiners.
    #[serde(default)]
    pub handshake_rx_total: u64,
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
    /// Software version the peer is currently running. Re-sent every
    /// heartbeat so the control plane sees `actual` version drift toward
    /// `desired` (spec P0 OBSERVE). `#[serde(default)]` → `None` for older
    /// joiners; `None` leaves the stored value untouched.
    #[serde(default)]
    pub software_version: Option<String>,
    /// Mesh-joiner version re-sent every heartbeat (self-reported). `None`
    /// leaves the stored value untouched. `#[serde(default)]` → `None` for
    /// older joiners.
    #[serde(default)]
    pub mesh_version: Option<String>,
    /// Re-asserted relay-only flag (same semantics as on
    /// [`RegisterRequest`]). Re-sent every heartbeat so a peer that flips
    /// reachability is reflected without a full re-register.
    /// `#[serde(default)]` → `false` for older joiners.
    #[serde(default)]
    pub relay_only: bool,
    /// This reporter's live per-peer data paths (connectivity visibility).
    /// One [`PeerPathDto`] per session: direct (p2p) vs relay + staleness.
    /// The coordinator REPLACES the reporter's stored edges with this set on
    /// every heartbeat, so it tracks exactly what the reporter sees right
    /// now (same wholesale-replace semantics as `hosted_app_ulas`). The
    /// edges live with the reporter's roster entry and age out with its
    /// presence — no separate TTL. `#[serde(default)]` → empty for older
    /// joiners, which the coordinator reads as "no edges → unknown".
    #[serde(default)]
    pub peer_paths: Vec<PeerPathDto>,
    /// Reporter's own WG data-plane health (Track K / black-hole pill, Track V).
    /// `false` = this node is sending but receiving zero decap frames (a wedged
    /// WG return path — the MSI black hole); the coordinator stamps its self-view
    /// `connectivity` as `"dead"`, overriding any now-stale edges. `#[serde(default
    /// = "default_dataplane_healthy")]` → `true` for older joiners (fail-open: a
    /// node that cannot report is assumed healthy, so a transient gap never paints
    /// a false "dead").
    #[serde(default = "default_dataplane_healthy")]
    pub dataplane_healthy: bool,
    /// Track C: command ids the node executed since its last heartbeat. The
    /// coordinator removes each from the peer's pending queue (ack) so the
    /// at-least-once carrier never re-delivers an already-run verb.
    /// `#[serde(default)]` → empty for older joiners.
    #[serde(default)]
    pub executed_command_ids: Vec<String>,
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
    /// Track C remote-restart: signed commands the super-admin queued for this
    /// peer, drained on this heartbeat. The node verifies each end-to-end,
    /// executes it, and acks via `executed_command_ids` next tick.
    /// `#[serde(default)]` + `skip_serializing_if` → omitted from the wire when
    /// empty, so the common no-command heartbeat is unchanged.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pending_commands: Vec<crate::roster::coordinator::command_queue::NodeCommandDto>,
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

/// Body of `GET /v1/mesh/topology` response: the **machine graph**.
///
/// A read-only projection of the roster, EXCLUDING app-runners (a runner
/// is a peer whose ULA is inside `fd5a:1f02::/32` or that carries the
/// `"runner"` tag). The directed per-reporter [`PeerInfo::connectivity`]
/// edges are collapsed into undirected machine↔machine pairs (see
/// [`TopologyEdge`]). The node + frontend mirror this shape byte-for-byte.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct TopologyResponse {
    /// Roster peers that are machines (runners excluded), ordered by the
    /// coordinator's peer index for deterministic output.
    pub machines: Vec<TopologyMachine>,
    /// Undirected machine↔machine edges, ordered by `(from, to)` UUID
    /// string for deterministic output. Each unordered pair appears once.
    pub edges: Vec<TopologyEdge>,
}

/// One machine node in the [`TopologyResponse`] graph. A trimmed
/// [`PeerInfo`] carrying only the display-facing fields the topology view
/// needs.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct TopologyMachine {
    /// Coordinator-assigned UUID v7 (string form).
    pub peer_id: String,
    /// Human-readable peer name (the peer's `display_name`).
    pub name: String,
    /// Assigned IPv6 ULA, textual form.
    pub ula: String,
    /// Role hint labels.
    pub tags: Vec<String>,
    /// Whether this peer declared itself relay-only (no reachable direct
    /// endpoint). Same flag as [`PeerInfo::relay_only`].
    pub relay_only: bool,
    /// Reported software version this peer is running (e.g. `"1.4.35"`).
    /// `None` = unknown. Unlike [`PeerInfo::software_version`] (which OMITS
    /// the key when `None` via `skip_serializing_if`), this field is ALWAYS
    /// present in the wire JSON and serializes as `null` when unknown — the
    /// topology contract requires it to be nullable/always-present so the
    /// node + frontend can rely on the key existing.
    pub software_version: Option<String>,
    /// Reported mesh-joiner version this peer is running (e.g. `"1.4.36"`).
    /// `None` = unknown. Always present in the wire JSON (serializes as `null`
    /// when unknown), like `software_version` above, so the node + frontend can
    /// rely on the key existing.
    pub mesh_version: Option<String>,
    /// Self-view live connectivity (`"direct"` / `"relay"` / `"dead"` / `None`)
    /// so the topology graph can paint a wedged machine 🔴 — the same value as
    /// the default [`PeerInfo::connectivity`] stamp (Track V). Always present
    /// (serializes `null` when unknown) like `software_version`, so the node +
    /// frontend can rely on the key existing.
    pub connectivity: Option<String>,
}

/// One undirected edge in the [`TopologyResponse`] graph.
///
/// Collapsed from the directed per-reporter paths: for an unordered
/// machine pair `{A, B}` where at least one direction reported a path,
/// `direct = A→B.direct OR B→A.direct` and `age_ms = min` of the reported
/// ages. `from < to` by UUID string so the pair appears exactly once.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct TopologyEdge {
    /// The lexicographically-smaller endpoint UUID (string form).
    pub from: String,
    /// The lexicographically-larger endpoint UUID (string form).
    pub to: String,
    /// `true` when EITHER direction reported a direct (p2p) path.
    pub direct: bool,
    /// Minimum `last_rx_age_ms` across the reported directions of the pair.
    pub age_ms: u64,
    /// Whether the FRESHEST reported handshake-class frame on this pair rode
    /// a direct endpoint (`true`) or the relay (`false`). Always present in
    /// the wire JSON (`null` = neither direction has observed a handshake
    /// yet, or both run older joiners) — same nullable/always-present
    /// contract as `TopologyMachine::software_version`.
    pub last_handshake_direct: Option<bool>,
    /// Age in ms of that freshest handshake observation; `null` exactly when
    /// `last_handshake_direct` is `null`.
    pub last_handshake_age_ms: Option<u64>,
    /// Sum of both directions' lifetime handshake-class frame counts — the
    /// between-polls delta is the pair's re-handshake RATE (the thrash
    /// signature a direct-rollout canary aborts on). `0` = no observations.
    pub handshake_rx_total: u64,
}

/// JSON error envelope. Kept dead simple — there's no public-facing
/// error code taxonomy yet.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ApiError {
    /// Human-readable error description.
    pub error: String,
}

/// Query parameters for `GET /v1/mesh/peers`.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct RosterQuery {
    /// Optional vantage peer id (connectivity visibility) — an OVERRIDE for the
    /// default per-machine self-view. When present, each returned
    /// `PeerInfo.connectivity` is stamped from THIS vantage peer's reported live
    /// path to that machine: `"direct"` (p2p), `"relay"`, or `null` (the vantage
    /// reported no edge → unknown). When ABSENT (the default the admin uses),
    /// each peer is stamped from its OWN reported paths — a per-machine self-view
    /// ("does machine M hold any direct path of its own?"), which is meaningful
    /// even when the serving node is relay-only.
    #[serde(default)]
    pub vantage: Option<String>,
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
