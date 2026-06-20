//! HTTP client wrapper around the `mesh-coordinator` REST surface.
//!
//! The coordinator exposes four endpoints; we model each one with a
//! dedicated method so the joiner doesn't have to remember URL paths or
//! deal with `serde_json::Value` shapes. SSE consumption lives in
//! [`crate::coordinator::peer_sync`] — this module is request/response
//! only.
//!
//! # Wire contract (mirrored from the dispatch spec)
//!
//! | Method | Path                       | Body                                  | Returns                |
//! |--------|----------------------------|---------------------------------------|------------------------|
//! | POST   | `/v1/mesh/register`        | [`RegisterRequest`]                   | [`RegisterResponse`]   |
//! | POST   | `/v1/mesh/heartbeat`       | [`HeartbeatRequest`]                  | [`HeartbeatResponse`]  |
//! | POST   | `/v1/mesh/deregister`      | [`DeregisterRequest`]                 | `204 No Content`       |
//! | GET    | `/v1/mesh/peers/stream`    | —                                     | SSE — see `peer_sync`  |
//!
//! All bodies are JSON. The `wg_public_key` field is base64 (standard
//! padded). ULAs and listen endpoints are textual.
//!
//! Layout:
//!
//! - This file — wire DTOs + the [`CoordinatorClient`] struct + its
//!   four HTTP methods.
//! - [`mod@decode`] — base64 / `RemotePeer` decoders, response-drain
//!   helpers. Re-exports [`decode_pubkey`] and [`remote_to_info`].
//! - [`mod@tls`] — mTLS [`reqwest::ClientBuilder`] construction.

mod decode;
#[cfg(test)]
mod tests;
mod tls;

pub use decode::{decode_pubkey, remote_to_info};

use crate::coordinator::command::NodeCommand;
use crate::error::{JoinerError, Result};
use crate::peer::RemotePeer;
use base64::engine::{Engine as _, general_purpose::STANDARD as B64};
use decode::{ensure_success, take_body_excerpt};
use serde::{Deserialize, Serialize};
use std::path::Path;
use uuid::Uuid;

/// Body of `POST /v1/mesh/register`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterRequest {
    /// 32-byte X25519 public key, base64-encoded.
    pub wg_public_key: String,
    /// Locally-known UDP listen address, if any. With reflexive endpoint
    /// discovery this is usually `None` — the joiner lets the coordinator
    /// derive the reachable endpoint from the observed source IP + the
    /// `wg_listen_port` below. Set only when the operator passed an
    /// explicit `--advertise-endpoint` override.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen_endpoint: Option<String>,
    /// UDP port our `WireGuard` socket is bound to. Sent so the coordinator
    /// can synthesize our reflexive endpoint (`<observed-ip>:<port>`) for
    /// cone-NAT traversal without a manual `--advertise-endpoint`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wg_listen_port: Option<u16>,
    /// Human-readable display name.
    pub display_name: String,
    /// Role tags ("dev-machine", "wasm-host", ...).
    pub tags: Vec<String>,
    /// App-ULAs (IPv6 literals, `fd5a:1f02:...`) this node hosts at
    /// register time. Usually empty — apps are typically hosted after
    /// join via [`crate::Joiner::host_app_ula`], which advertises them on
    /// the next heartbeat. Omitted from the wire when empty for a tidy
    /// body (per-app-ULA routing).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hosted_app_ulas: Vec<String>,
    /// Explicit IPv6 ULA the peer wants to be assigned (e.g.
    /// `"fd5a:1f02:aabb::1"`). When `Some`, the coordinator attempts to
    /// honor it; when `None` (default) the coordinator derives the ULA
    /// from the peer index. Omitted from the wire when `None` for back-compat
    /// with coordinators that predate Task 0.2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_ula: Option<String>,
    /// Peer role. `Some("runner")` for a per-app runner; `None` (default)
    /// for a plain supervisor/joiner — omitted from the wire so older
    /// coordinators are unaffected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// ULA of the supervisor that owns this runner. `None` for plain peers.
    /// Omitted from the wire when `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    /// UUID of the app this runner serves. `None` for plain peers.
    /// Omitted from the wire when `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_uuid: Option<String>,
    /// Software version of the binary the host is running (e.g. `"v1.4.0"`).
    /// Host-supplied; omitted from the wire when `None` so older
    /// coordinators are unaffected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub software_version: Option<String>,
    /// Mesh-joiner's own compile-time version, self-reported so the control
    /// plane can track the mesh-stack version per peer. Omitted from the wire
    /// when `None` for backward compat with older coordinators.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mesh_version: Option<String>,
    /// Declare this peer **relay-only** — it has no reachable direct endpoint
    /// (e.g. a container netns with no inbound mesh port). When `true` the
    /// coordinator advertises no direct endpoint for us and never emits a
    /// hole-punch directive for a pair involving us, so a relay-only ↔ NAT'd
    /// `WireGuard` handshake stays single-sided and completes over the relay.
    /// Always serialized (a plain `bool`) so a coordinator reads our intent
    /// explicitly; `#[serde(default)]` only matters on the read side.
    #[serde(default)]
    pub relay_only: bool,
}

/// Body of `POST /v1/mesh/register`'s response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterResponse {
    /// UUID v7 assigned by the coordinator.
    pub peer_id: Uuid,
    /// IPv6 ULA assigned to this joiner.
    pub ula: String,
    /// Initial roster (excluding the joiner itself).
    pub peers: Vec<RemotePeer>,
    /// Our own observed external IP, as the coordinator saw the register
    /// request arrive (our NAT's public IP). `None` from an older
    /// coordinator that doesn't reflect it. Informational — lets the
    /// joiner log whether it is behind NAT.
    #[serde(default)]
    pub observed_ip: Option<String>,
    /// The reflexive endpoint the coordinator stored for us (what other
    /// peers will dial). `None` from an older coordinator.
    #[serde(default)]
    pub observed_endpoint: Option<String>,
}

/// One reported edge in the connectivity-visibility feature.
///
/// THIS joiner's live data path to peer `peer_id` is currently `direct`
/// (p2p) or — when `false` — via the DERP relay floor. `last_rx_age_ms` is
/// how long ago a valid inbound UDP datagram last arrived from that peer
/// (drives the staleness/"last data Ns ago" surface). Reported per peer on
/// every heartbeat; the coordinator aggregates these into per-reporter edges
/// and stamps each roster `PeerInfo.connectivity` from a requested vantage.
///
/// Mirrored exactly by the coordinator's `PeerPathDto`. Backward compatible:
/// the `HeartbeatRequest.peer_paths` carrier is `#[serde(default)]`, so an
/// older coordinator simply ignores it and an older joiner sends none.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerPath {
    /// The peer whose live path we are reporting.
    pub peer_id: Uuid,
    /// `true` = our current data path to that peer is direct (p2p);
    /// `false` = relay.
    pub direct: bool,
    /// Milliseconds since the last valid inbound datagram from that peer.
    /// Clamped to non-negative.
    pub last_rx_age_ms: u64,
}

/// Body of `POST /v1/mesh/heartbeat`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatRequest {
    /// The peer id this joiner was assigned at registration time.
    pub peer_id: Uuid,
    /// Our `WireGuard` UDP listen port — re-sent on every heartbeat so the
    /// coordinator can refresh our reflexive endpoint if our observed
    /// public IP changes (NAT rebind / roaming).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wg_listen_port: Option<u16>,
    /// Our CURRENT full set of hosted app-ULAs (IPv6 literals), re-sent on
    /// every heartbeat. The coordinator replaces our stored set with this
    /// one (per-app-ULA routing). Omitted from the wire when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hosted_app_ulas: Vec<String>,
    /// Software version re-sent every heartbeat so the control plane can
    /// observe `actual` version (spec P0). Omitted from the wire when `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub software_version: Option<String>,
    /// Mesh-joiner version re-sent every heartbeat (self-reported). Omitted from
    /// the wire when `None` for backward compat.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mesh_version: Option<String>,
    /// Re-assert our relay-only flag on every heartbeat (same semantics as on
    /// [`RegisterRequest`]) so a coordinator that lost + rebuilt our entry, or
    /// a peer that flips reachability, stays consistent without a full
    /// re-register. `#[serde(default)]` matters on the read side.
    #[serde(default)]
    pub relay_only: bool,
    /// Per-peer live path edges from THIS reporter (connectivity
    /// visibility). One [`PeerPath`] per session: is our current data path
    /// to that peer direct (p2p) or relay, and how stale. The coordinator
    /// stores these per reporter and stamps `PeerInfo.connectivity` from a
    /// requested vantage. `#[serde(default)]` so an older joiner (no
    /// `peer_paths`) and an older coordinator (ignores it) both interop —
    /// the coordinator treats absence as "no edges → unknown".
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub peer_paths: Vec<PeerPath>,
    /// Track K keystone: this reporter's live WG data-plane health
    /// (`Joiner::dataplane_healthy`). `false` ⇒ this node is a black hole
    /// (control-plane heartbeat alive, WG decap-RX dead). The coordinator
    /// surfaces it for the visibility pill (Track V) and the OTA data-plane
    /// gate reads its own local value (Track D). `#[serde(default = "..")]` to
    /// `true` so an older joiner (no field) and an older coordinator (ignores
    /// it) interop — absence is read as "healthy", never as a black hole, so a
    /// new coordinator never evicts a legacy peer for a missing field.
    #[serde(default = "default_dataplane_healthy")]
    pub dataplane_healthy: bool,
    /// Track C: command ids this node executed since the last heartbeat. The
    /// coordinator removes them from the pending queue (ack). Omitted when
    /// empty for a tidy body; `#[serde(default)]` so an older coordinator
    /// simply ignores it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub executed_command_ids: Vec<String>,
}

/// serde default for [`HeartbeatRequest::dataplane_healthy`]: `true`
/// (fail-open — an absent field means a legacy reporter that can't report, and
/// it must be assumed healthy, never a black hole).
const fn default_dataplane_healthy() -> bool {
    true
}

/// Body of the heartbeat response. The coordinator returns the current
/// roster so the joiner can self-heal if the SSE stream missed an event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatResponse {
    /// Current full roster (excluding this peer).
    pub peers: Vec<RemotePeer>,
    /// Our own observed external IP on this heartbeat. `None` from an
    /// older coordinator.
    #[serde(default)]
    pub observed_ip: Option<String>,
    /// The reflexive endpoint currently stored for us. `None` from an
    /// older coordinator.
    #[serde(default)]
    pub observed_endpoint: Option<String>,
    /// Track C remote-restart: signed commands the super-admin queued for this
    /// node, drained on this heartbeat. Verified + executed in `tick_once`,
    /// then acked via `executed_command_ids` next tick. `#[serde(default)]` →
    /// empty from an older coordinator that omits the field.
    #[serde(default)]
    pub pending_commands: Vec<NodeCommand>,
}

/// Body of `POST /v1/mesh/deregister`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeregisterRequest {
    /// Our peer id.
    pub peer_id: Uuid,
}

/// HTTP client wrapper. Cheap to clone — shares a single
/// `reqwest::Client` internally.
#[derive(Debug, Clone)]
pub struct CoordinatorClient {
    http: reqwest::Client,
    base_url: String,
}

impl CoordinatorClient {
    /// Build a client targeting `base_url` (e.g.
    /// `https://127.0.0.1:8888`). Trailing slashes are tolerated.
    ///
    /// When `insecure == true` (dev/smoke-test path) the three TLS
    /// path arguments are ignored and a plain `reqwest::Client` is
    /// built — talks to a coordinator launched with
    /// `--insecure-no-mtls`.
    ///
    /// When `insecure == false` (production path) all three TLS paths
    /// must be provided:
    ///
    /// * `tls_cert` — PEM-encoded client cert signed by the mesh CA.
    /// * `tls_key` — PEM-encoded private key matching the cert.
    /// * `tls_ca` — PEM-encoded CA bundle the joiner trusts when
    ///   validating the coordinator's server cert.
    ///
    /// The CA bundle is the ONLY root trusted for this client; we do
    /// not fall back to the system trust store because the mesh CA is
    /// private and nothing public should ever vouch for the coordinator.
    ///
    /// # Errors
    ///
    /// * [`JoinerError::InvalidConfig`] when `insecure == false` and
    ///   any of the three TLS paths is missing.
    /// * [`JoinerError::TunSetup`] is *not* used here — TLS file read
    ///   / parse errors surface as [`JoinerError::HttpTransport`]
    ///   carrying the underlying message.
    /// * [`JoinerError::HttpTransport`] for any reqwest builder
    ///   failure or PEM read/parse failure.
    pub fn new(
        base_url: impl Into<String>,
        tls_cert: Option<&Path>,
        tls_key: Option<&Path>,
        tls_ca: Option<&Path>,
        insecure: bool,
    ) -> Result<Self> {
        let trimmed = base_url.into().trim_end_matches('/').to_owned();

        let builder = if insecure {
            reqwest::Client::builder()
        } else {
            // mTLS branch: validate the trio before touching disk so
            // the operator gets a precise error instead of a generic
            // "file not found" if they forgot a flag.
            let (Some(cert_path), Some(key_path), Some(ca_path)) = (tls_cert, tls_key, tls_ca)
            else {
                return Err(JoinerError::InvalidConfig(
                    "mTLS requires all three paths: --tls-cert, --tls-key, --tls-ca \
                     (or use --insecure-no-mtls for dev)"
                        .to_owned(),
                ));
            };
            tls::build_mtls_client_builder(cert_path, key_path, ca_path)?
        };

        let http = builder
            .build()
            .map_err(|e| JoinerError::HttpTransport(e.to_string()))?;

        Ok(Self {
            http,
            base_url: trimmed,
        })
    }

    /// Expose the configured base URL — used by `peer_sync` to build
    /// the SSE GET request without re-parsing the joiner config.
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Borrow the inner `reqwest::Client` so the SSE consumer can share
    /// the connection pool.
    #[must_use]
    pub const fn http(&self) -> &reqwest::Client {
        &self.http
    }

    /// `POST /v1/mesh/register` — exchange `(pubkey, endpoint, name,
    /// tags)` for `(peer_id, ula, roster)`.
    ///
    /// `listen_endpoint` is a free-form `host:port` string forwarded to
    /// the coordinator verbatim — it is the address OTHER peers must
    /// dial to reach us. We do not resolve it locally because the local
    /// resolver may not know the name we want others to use (e.g. a Mac
    /// peer advertising `host.lima.internal:51820` to a Lima
    /// counterpart; Mac itself can't resolve that name). DNS happens at
    /// the consuming peer in `remote_to_info`.
    ///
    /// `join_token` is the node-join JWT issued by the auth service. When
    /// `Some`, it is sent as `Authorization: Bearer <token>` — the
    /// coordinator validates it and takes the node's authoritative
    /// `network` + `tags` from the token claims (spec §8). When `None`
    /// (dev/E1 escape hatch against a coordinator with no `AUTH_URL`) no
    /// auth header is sent and the coordinator trusts `tags` verbatim. The
    /// `tags` we send are advisory either way — a validating coordinator
    /// ignores them in favor of the claims.
    ///
    /// `requested_ula` — explicit IPv6 ULA to request from the coordinator
    /// (Task 0.2). `None` = coordinator-derived. `kind` / `parent` /
    /// `app_uuid` — runner peer metadata (Task 0.1/0.3). All `None` for
    /// plain peers — omitted from the wire for backward compat.
    ///
    /// `software_version` — version of the binary the host is running
    /// (e.g. `"v1.4.0"`). Host-supplied; `None` for an older host —
    /// omitted from the wire (spec P0).
    ///
    /// `relay_only` — `true` when this peer has no reachable direct endpoint
    /// (e.g. a container netns with no inbound mesh port). The coordinator
    /// then advertises no direct endpoint for us and never makes us a
    /// hole-punch target, so a relay-only ↔ NAT'd handshake completes over
    /// the relay without simultaneous-init thrash. `false` for a normal peer.
    #[allow(clippy::too_many_arguments)]
    pub async fn register(
        &self,
        wg_public_key: &[u8; 32],
        listen_endpoint: Option<String>,
        wg_listen_port: Option<u16>,
        display_name: &str,
        tags: &[String],
        join_token: Option<&str>,
        requested_ula: Option<String>,
        kind: Option<String>,
        parent: Option<String>,
        app_uuid: Option<String>,
        software_version: Option<String>,
        mesh_version: Option<String>,
        relay_only: bool,
    ) -> Result<RegisterResponse> {
        let body = RegisterRequest {
            wg_public_key: B64.encode(wg_public_key),
            listen_endpoint,
            wg_listen_port,
            display_name: display_name.to_owned(),
            tags: tags.to_vec(),
            // Initial register hosts no apps — they are hosted after join
            // via `Joiner::host_app_ula` and advertised on the next
            // heartbeat (per-app-ULA routing). The field exists on the wire
            // for forward-compat + symmetry with heartbeat.
            hosted_app_ulas: Vec::new(),
            requested_ula,
            kind,
            parent,
            app_uuid,
            software_version,
            mesh_version,
            relay_only,
        };
        let url = format!("{}/v1/mesh/register", self.base_url);
        let mut builder = self.http.post(&url).json(&body);
        // Attach the join token as a Bearer credential when present. Use
        // reqwest's `bearer_auth` so the `Authorization: Bearer <token>`
        // header is formatted exactly as the coordinator's extractor
        // expects.
        if let Some(token) = join_token.map(str::trim).filter(|t| !t.is_empty()) {
            builder = builder.bearer_auth(token);
        }
        let resp = builder
            .send()
            .await
            .map_err(|e| JoinerError::HttpTransport(e.to_string()))?;
        ensure_success(&url, resp).await
    }

    /// `POST /v1/mesh/heartbeat` — keepalive that also refreshes the
    /// caller's view of the roster.
    ///
    /// `wg_listen_port` is our `WireGuard` UDP port, re-sent so the
    /// coordinator can refresh our reflexive endpoint on an observed-IP
    /// change.
    ///
    /// `software_version` is the version of the binary the host is running,
    /// re-sent every heartbeat so the control plane can observe `actual`
    /// version drift (spec P0). `None` (host-supplied) is omitted from the
    /// wire and leaves the coordinator's stored value untouched.
    ///
    /// `peer_paths` is THIS reporter's per-peer live path snapshot
    /// (connectivity visibility): for each session, is our data path to that
    /// peer direct or relay, and how stale. Empty when there are no sessions
    /// (omitted from the wire) — the coordinator then keeps no edges for us.
    /// `executed_command_ids` are the Track-C command ids this node ran since
    /// the previous heartbeat — the coordinator clears them from the pending
    /// queue (ack). Empty (the common case) is omitted from the wire.
    #[allow(clippy::too_many_arguments)]
    pub async fn heartbeat(
        &self,
        peer_id: Uuid,
        wg_listen_port: Option<u16>,
        hosted_app_ulas: &[String],
        software_version: Option<String>,
        mesh_version: Option<String>,
        relay_only: bool,
        peer_paths: Vec<PeerPath>,
        dataplane_healthy: bool,
        executed_command_ids: &[String],
    ) -> Result<HeartbeatResponse> {
        let url = format!("{}/v1/mesh/heartbeat", self.base_url);
        let body = HeartbeatRequest {
            peer_id,
            wg_listen_port,
            hosted_app_ulas: hosted_app_ulas.to_vec(),
            software_version,
            mesh_version,
            relay_only,
            peer_paths,
            dataplane_healthy,
            executed_command_ids: executed_command_ids.to_vec(),
        };
        let resp = self
            .http
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| JoinerError::HttpTransport(e.to_string()))?;
        ensure_success(&url, resp).await
    }

    /// `POST /v1/mesh/deregister` — best-effort graceful exit.
    ///
    /// The coordinator responds with 204 on success. Some
    /// implementations also accept 200 — we tolerate both, anything
    /// else surfaces as [`JoinerError::HttpStatus`].
    pub async fn deregister(&self, peer_id: Uuid) -> Result<()> {
        let url = format!("{}/v1/mesh/deregister", self.base_url);
        let body = DeregisterRequest { peer_id };
        let resp = self
            .http
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| JoinerError::HttpTransport(e.to_string()))?;
        let status = resp.status();
        if status.is_success() {
            return Ok(());
        }
        Err(JoinerError::HttpStatus {
            status: status.as_u16(),
            body: take_body_excerpt(resp).await,
        })
    }
}
