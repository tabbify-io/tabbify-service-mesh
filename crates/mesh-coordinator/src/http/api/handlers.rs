//! Request-handlers for the four non-streaming mesh endpoints
//! (register / heartbeat / deregister / peers). The SSE stream lives in
//! [`super::stream`].

use super::dto::{
    ApiError, DeregisterRequest, HeartbeatRequest, HeartbeatResponse, RegisterRequest,
    RegisterResponse, RosterQuery, RosterResponse,
};
use crate::roster::coordinator::{Coordinator, CoordinatorError};
use axum::{
    Json,
    extract::{ConnectInfo, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use std::net::SocketAddr;
use std::str::FromStr;
use tracing::warn;
use uuid::Uuid;

/// Convert coordinator errors into `(status, body)` pairs for axum.
pub fn coord_err_to_response(err: &CoordinatorError) -> Response {
    let status = match err {
        CoordinatorError::UnknownPeer(_) => StatusCode::NOT_FOUND,
        CoordinatorError::Allocation(_) => StatusCode::SERVICE_UNAVAILABLE,
        CoordinatorError::InvalidPeerId(_)
        | CoordinatorError::InvalidPubkey(_)
        | CoordinatorError::PubkeyDecode(_) => StatusCode::BAD_REQUEST,
        // A failed join-token validation (missing / invalid / revoked /
        // wrong-kind / validator unreachable) rejects the register.
        CoordinatorError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
        // A different peer already holds the requested ULA.
        CoordinatorError::UlaConflict(_) => StatusCode::CONFLICT,
    };
    (
        status,
        Json(ApiError {
            error: err.to_string(),
        }),
    )
        .into_response()
}

/// Extract the bearer token from an `Authorization: Bearer <token>` header.
/// Returns `None` when the header is absent, non-UTF-8, or not a `Bearer`
/// scheme — the coordinator then treats the join token as missing (which
/// is a 401 when a validator is configured).
fn bearer_token(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|t| t.trim().to_owned())
}

/// Register a peer with the coordinator.
///
/// The joiner submits its `WireGuard` public key + intended display name
/// and gets back a coordinator-assigned `peer_id` + IPv6 ULA plus an
/// ACL-filtered snapshot of currently-visible peers. When the coordinator
/// is configured with an `AUTH_URL` (production), every request MUST
/// present a valid `Authorization: Bearer <join-token>`; the joiner's
/// `network` + `tags` are then taken from the validated claims
/// (authoritative). In dev (no `AUTH_URL`) the Bearer header is ignored.
#[utoipa::path(
    post,
    path = "/v1/mesh/register",
    tag = "mesh",
    request_body = RegisterRequest,
    responses(
        (status = 200, description = "Registered; returns peer_id, ULA, observed endpoint, and filtered roster", body = RegisterResponse),
        (status = 400, description = "Malformed wg_public_key or peer_id", body = ApiError),
        (status = 401, description = "Missing / invalid / revoked join-token (when AUTH_URL configured)", body = ApiError),
        (status = 409, description = "Requested ULA is held by a different peer", body = ApiError),
        (status = 503, description = "ULA allocation exhausted", body = ApiError),
    ),
    security(("bearer" = []))
)]
#[tracing::instrument(
    skip_all,
    fields(
        display_name = %req.display_name,
        network = %req.network,
        kind = %req.kind,
    ),
)]
pub async fn register_handler(
    State(coordinator): State<Coordinator>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<RegisterRequest>,
) -> Response {
    // Forward the joiner's `Authorization: Bearer <join-token>` to the
    // coordinator. When a validator is configured the token is required +
    // validated, and the node's network/tags come from the claims
    // (authoritative); when not, it is ignored (dev/E1 escape hatch).
    let bearer = bearer_token(&headers);
    // The source socket addr is the peer's NAT public IP (+ an unrelated
    // TCP port). The coordinator pairs the IP with the request's reported
    // `wg_listen_port` to synthesize a reflexive endpoint for cone-NAT
    // traversal. `None` in tests driving the router without the
    // make-service wrapper — reflection is then skipped.
    let observed = connect_info.as_ref().map(|c| c.0);
    match coordinator
        .register_authenticated(req, bearer.as_deref(), observed)
        .await
    {
        Ok((entry, _outcome)) => {
            // ACL enforcement (spec §5.3): the registrant only learns the
            // peers its tags are policy-permitted to reach. Isolation
            // between user-networks falls out of this — a denied peer never
            // enters the roster the joiner builds sessions from.
            let body = RegisterResponse {
                peer_id: entry.peer_id.to_string(),
                ula: entry.ula.to_string(),
                peers: coordinator.visible_peers(entry.peer_id, &entry.tags),
                // Echo the peer its own observed external IP + the
                // reflexive endpoint we stored (what others will dial).
                observed_ip: observed.map(|o| o.ip().to_string()),
                observed_endpoint: entry.listen_endpoint.clone(),
            };
            (StatusCode::OK, Json(body)).into_response()
        }
        Err(e) => {
            warn!(error = %e, "register failed");
            coord_err_to_response(&e)
        }
    }
}

/// Keepalive — refresh the peer's last-seen timestamp + reflexive endpoint.
///
/// The supervisor re-sends its CURRENT set of hosted app-ULAs on every
/// heartbeat; the coordinator REPLACES the stored set and re-broadcasts
/// when it changes (per-app-ULA routing). A peer that misses heartbeats
/// for longer than `--heartbeat-timeout-secs` is swept by the timeout
/// task. Auth: transport-level mTLS only — no application bearer.
#[utoipa::path(
    post,
    path = "/v1/mesh/heartbeat",
    tag = "mesh",
    request_body = HeartbeatRequest,
    responses(
        (status = 200, description = "Roster snapshot + the peer's observed endpoint", body = HeartbeatResponse),
        (status = 400, description = "Malformed peer_id", body = ApiError),
        (status = 404, description = "peer_id not registered", body = ApiError),
    ),
)]
#[tracing::instrument(
    skip_all,
    fields(peer_id = %req.peer_id),
)]
pub async fn heartbeat_handler(
    State(coordinator): State<Coordinator>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    Json(req): Json<HeartbeatRequest>,
) -> Response {
    let peer_id = match Uuid::from_str(&req.peer_id) {
        Ok(id) => id,
        Err(e) => return coord_err_to_response(&CoordinatorError::InvalidPeerId(e.to_string())),
    };
    // ConnectInfo is `None` in tests that drive the router via `Router::call`
    // without the make-service wrapper. Recording an empty string in that
    // case keeps the publish path lossless for production while not
    // forcing test plumbing to fake a SocketAddr.
    let observed_addr = connect_info.as_ref().map(|c| c.0);
    let observed = observed_addr.map(|a| a.to_string()).unwrap_or_default();
    // Capture the reported connectivity edges before `req` is consumed by
    // the heartbeat call below — they are stored separately (connectivity
    // visibility), not threaded through the heartbeat event.
    let peer_paths = req.peer_paths;
    match coordinator
        .heartbeat(
            peer_id,
            observed,
            req.wg_listen_port,
            req.hosted_app_ulas,
            req.software_version,
            req.relay_only,
        )
        .await
    {
        Ok(entry) => {
            // Replace this reporter's stored edges from the heartbeat. Done
            // only on a successful heartbeat (the entry exists), mirroring the
            // wholesale-replace the heartbeat does for hosted_app_ulas.
            coordinator.record_peer_paths(entry.peer_id, &peer_paths);
            // Filter the self-heal roster the same way as register: a peer
            // only re-learns the peers it is policy-permitted to reach.
            let body = HeartbeatResponse {
                peers: coordinator.visible_peers(entry.peer_id, &entry.tags),
                // Echo the peer its own observed external IP + the
                // (possibly refreshed) reflexive endpoint we now store.
                observed_ip: observed_addr.map(|a| a.ip().to_string()),
                observed_endpoint: entry.listen_endpoint.clone(),
            };
            (StatusCode::OK, Json(body)).into_response()
        }
        Err(e) => coord_err_to_response(&e),
    }
}

/// Gracefully remove a peer from the roster. Idempotent — removing an
/// already-absent peer still returns `204`. Auth: transport-level mTLS
/// only — no application bearer.
#[utoipa::path(
    post,
    path = "/v1/mesh/deregister",
    tag = "mesh",
    request_body = DeregisterRequest,
    responses(
        (status = 204, description = "Peer removed (idempotent)"),
        (status = 400, description = "Malformed peer_id", body = ApiError),
    ),
)]
#[tracing::instrument(
    skip_all,
    fields(peer_id = %req.peer_id),
)]
pub async fn deregister_handler(
    State(coordinator): State<Coordinator>,
    Json(req): Json<DeregisterRequest>,
) -> Response {
    let peer_id = match Uuid::from_str(&req.peer_id) {
        Ok(id) => id,
        Err(e) => return coord_err_to_response(&CoordinatorError::InvalidPeerId(e.to_string())),
    };
    // Idempotent: removing a missing peer is still 204.
    let _ = coordinator.deregister(peer_id, "client_deregister").await;
    StatusCode::NO_CONTENT.into_response()
}

/// Roster snapshot — UNFILTERED, ordered by peer index. Intended for
/// admin / debug / observability tooling; joiners use the per-viewer
/// ACL-filtered stream at `/v1/mesh/peers/stream` instead. Auth:
/// transport-level mTLS only — no application bearer.
///
/// Each peer's live `connectivity` (`"direct"` / `"relay"` / omitted) is, by
/// default, a PER-MACHINE self-view stamped from that peer's OWN last-reported
/// paths (connectivity visibility) — "does machine M hold any direct path of
/// its own?". Optional `?vantage=<peer-id>` overrides this with the legacy
/// single-vantage view (M's connectivity AS SEEN BY the vantage peer). A
/// malformed `vantage` is ignored (degrades to the default self-view).
#[utoipa::path(
    get,
    path = "/v1/mesh/peers",
    tag = "mesh",
    params(
        ("vantage" = Option<String>, Query, description = "Override the default per-machine self-view: stamp each peer's connectivity from THIS peer's reported live paths"),
    ),
    responses(
        (status = 200, description = "Full roster snapshot (admin / debug view)", body = RosterResponse),
    ),
)]
#[tracing::instrument(skip_all)]
pub async fn peers_handler(
    State(coordinator): State<Coordinator>,
    Query(query): Query<RosterQuery>,
) -> Response {
    // A malformed vantage UUID degrades to "no vantage" (the default
    // per-machine self-view) rather than 400 — the field is purely advisory
    // (connectivity stamping).
    let vantage = query.vantage.as_deref().and_then(|v| Uuid::from_str(v).ok());
    Json(RosterResponse {
        peers: coordinator.snapshot_with_vantage(vantage),
    })
    .into_response()
}
