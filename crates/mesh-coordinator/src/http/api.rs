//! HTTP API: JSON request/response types + axum router + handlers.
//!
//! All endpoints live under `/v1/mesh/...`. JSON is the wire format —
//! `wg_public_key` is base64-encoded for human readability + curl-ability.

use crate::http::policy_api::{PolicyApiState, get_policy_handler, put_policy_handler};
use crate::http::sse::PeerEvent;
use crate::roster::coordinator::{Coordinator, CoordinatorError};
use axum::{
    Json, Router,
    extract::{ConnectInfo, Query, State},
    http::StatusCode,
    response::{
        IntoResponse, Response,
        sse::{Event as SseFrame, KeepAlive, Sse},
    },
    routing::{get, post},
};
use futures::stream::{Stream, StreamExt};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;
use tokio_stream::wrappers::{BroadcastStream, errors::BroadcastStreamRecvError};
use tracing::warn;
use uuid::Uuid;

/// JSON shape returned to clients for every peer. Mirrors the proto
/// `PeerJoined` payload, except `wg_public_key` is base64-encoded.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    /// Joined-at wall-clock micros.
    pub joined_at_micros: i64,
}

/// Body of `POST /v1/mesh/register`.
#[derive(Debug, Clone, Deserialize)]
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
}

/// Body of `POST /v1/mesh/register` response.
#[derive(Debug, Clone, Serialize)]
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
#[derive(Debug, Clone, Deserialize)]
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
}

/// Body of `POST /v1/mesh/heartbeat` response.
#[derive(Debug, Clone, Serialize)]
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
#[derive(Debug, Clone, Deserialize)]
pub struct DeregisterRequest {
    /// Peer id to remove.
    pub peer_id: String,
}

/// Body of `GET /v1/mesh/peers` response.
#[derive(Debug, Clone, Serialize)]
pub struct RosterResponse {
    /// All currently-registered peers, ordered by peer index.
    pub peers: Vec<PeerInfo>,
}

/// JSON error envelope. Kept dead simple — there's no public-facing
/// error code taxonomy yet.
#[derive(Debug, Clone, Serialize)]
struct ApiError {
    error: String,
}

/// Convert coordinator errors into `(status, body)` pairs for axum.
fn coord_err_to_response(err: &CoordinatorError) -> Response {
    let status = match err {
        CoordinatorError::UnknownPeer(_) => StatusCode::NOT_FOUND,
        CoordinatorError::Allocation(_) => StatusCode::SERVICE_UNAVAILABLE,
        CoordinatorError::InvalidPeerId(_)
        | CoordinatorError::InvalidPubkey(_)
        | CoordinatorError::PubkeyDecode(_) => StatusCode::BAD_REQUEST,
        // A failed join-token validation (missing / invalid / revoked /
        // wrong-kind / validator unreachable) rejects the register.
        CoordinatorError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
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

/// Build the full HTTP router with the admin policy API disabled.
///
/// Convenience wrapper over [`build_router_with_admin`] for callers
/// (tests, dev) that don't need runtime policy edits — no
/// `MESH_ADMIN_TOKEN`, so `GET/PUT /v1/policy` reject every call. Pass the
/// result to `axum::serve(listener, router)` or
/// `router.into_make_service_with_connect_info::<SocketAddr>()` so the
/// heartbeat handler can stamp the observed external addr.
pub fn build_router(coordinator: Coordinator) -> Router {
    build_router_with_admin(coordinator, None)
}

/// Build the full HTTP router, optionally enabling the admin policy API.
///
/// When `admin_token` is `Some`, `GET/PUT /v1/policy` are served and gated
/// behind `Authorization: Bearer <token>`. When `None`, those endpoints
/// still exist but reject every call with `401` (fail-closed — a
/// coordinator with no admin token can't be reconfigured over the wire).
///
/// The peer endpoints (`/v1/mesh/...`) and the policy endpoints carry
/// different axum state types, so they are built as two sub-routers and
/// merged.
pub fn build_router_with_admin(coordinator: Coordinator, admin_token: Option<String>) -> Router {
    let peer_routes = Router::new()
        .route("/v1/mesh/register", post(register_handler))
        .route("/v1/mesh/heartbeat", post(heartbeat_handler))
        .route("/v1/mesh/deregister", post(deregister_handler))
        .route("/v1/mesh/peers", get(peers_handler))
        .route("/v1/mesh/peers/stream", get(stream_handler))
        .with_state(coordinator.clone());

    let policy_state = PolicyApiState {
        coordinator,
        admin_token,
    };
    let policy_routes = Router::new()
        .route(
            "/v1/policy",
            get(get_policy_handler).put(put_policy_handler),
        )
        .with_state(policy_state);

    peer_routes.merge(policy_routes)
}

async fn register_handler(
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

async fn heartbeat_handler(
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
    let observed = observed_addr
        .map(|a| a.to_string())
        .unwrap_or_default();
    match coordinator
        .heartbeat(peer_id, observed, req.wg_listen_port)
        .await
    {
        Ok(entry) => {
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

async fn deregister_handler(
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

async fn peers_handler(State(coordinator): State<Coordinator>) -> Response {
    Json(RosterResponse {
        peers: coordinator.snapshot(),
    })
    .into_response()
}

/// Query parameters for `GET /v1/mesh/peers/stream`.
#[derive(Debug, Clone, Deserialize)]
pub struct StreamQuery {
    /// The subscribing peer's id. When present, the stream is ACL-filtered
    /// to the peers that viewer is policy-permitted to see (and converges
    /// correctly on policy changes — see [`ViewerFilter`]). When absent,
    /// the stream is unfiltered (admin/debug clients). A joiner passes its
    /// own `peer_id` here so it only ever learns allowed peers.
    #[serde(default)]
    pub peer_id: Option<String>,
}

async fn stream_handler(
    State(coordinator): State<Coordinator>,
    Query(query): Query<StreamQuery>,
) -> Sse<impl Stream<Item = Result<SseFrame, Infallible>>> {
    // Bootstrap the subscriber with the current roster, THEN attach to
    // the live broadcast. The subscribe-then-snapshot ordering would
    // race — between subscribe and snapshot a peer could leave and the
    // remove frame would arrive before the bootstrap "added" frame.
    let receiver = coordinator.broadcaster().subscribe();

    // Resolve the viewer's identity. An unknown / absent peer_id yields a
    // `None` filter (unfiltered stream — backward-compatible admin view).
    // A known peer_id installs an ACL filter keyed on that viewer's tags.
    let viewer = query
        .peer_id
        .as_deref()
        .and_then(|s| Uuid::from_str(s).ok())
        .and_then(|id| coordinator.peer_tags(id).map(|tags| (id, tags)));

    let snapshot = coordinator.snapshot();
    let stream = peer_event_stream(coordinator, viewer, snapshot, receiver);
    Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
}

/// Per-viewer ACL filter for the SSE stream.
///
/// The broadcast channel is shared across all subscribers, so filtering is
/// per-subscriber here rather than at broadcast time. The filter is
/// **stateful**: it remembers which peer ids it has currently revealed to
/// this viewer. That statefulness is what makes policy changes converge —
/// when a `PUT /v1/policy` re-broadcasts every peer as `Updated`
/// ([`Coordinator::resync_all_peers`]), this filter re-evaluates each peer
/// and synthesises the right frame:
///
/// - newly visible (not previously revealed) → `peer_added`
/// - still visible (already revealed)        → `peer_updated`
/// - newly hidden (was revealed)             → synthetic `peer_removed`
/// - still hidden                            → dropped
///
/// Visibility is evaluated against the *current* policy on every frame, so
/// the filter needs the coordinator handle and the viewer's tags.
struct ViewerFilter {
    coordinator: Coordinator,
    viewer_id: Uuid,
    viewer_tags: Vec<String>,
    /// Peer ids currently revealed to this viewer.
    revealed: HashSet<String>,
}

impl ViewerFilter {
    /// Apply the filter to one broadcast event, returning the SSE frame the
    /// viewer should receive (or `None` to drop it).
    fn apply(&mut self, event: PeerEvent) -> Option<SseFrame> {
        match event {
            PeerEvent::Added(info) | PeerEvent::Updated(info) => {
                // Never reveal the viewer to itself.
                if info.peer_id == self.viewer_id.to_string() {
                    return None;
                }
                let visible = self
                    .coordinator
                    .viewer_can_see(&self.viewer_tags, &info.tags);
                if visible {
                    // Added if first time we reveal this peer, else Updated.
                    let frame = if self.revealed.insert(info.peer_id.clone()) {
                        to_sse_frame(&PeerEvent::Added(info))
                    } else {
                        to_sse_frame(&PeerEvent::Updated(info))
                    };
                    Some(frame)
                } else if self.revealed.remove(&info.peer_id) {
                    // Was visible, now denied → synthetic removal.
                    Some(to_sse_frame(&PeerEvent::Removed {
                        peer_id: info.peer_id,
                        tags: info.tags,
                    }))
                } else {
                    None
                }
            }
            PeerEvent::Removed { peer_id, tags } => {
                // Only forward a removal for a peer the viewer had been
                // shown (and was allowed to see).
                if self.revealed.remove(&peer_id) {
                    Some(to_sse_frame(&PeerEvent::Removed { peer_id, tags }))
                } else {
                    None
                }
            }
            // A hole-punch instruction goes only to the peer told to fire
            // (its initiator). Routed by id, not tags — and never gated by
            // `revealed`, since a punch can be needed before either peer
            // has appeared in the other's roster view.
            PeerEvent::HolePunch(ref hp) => {
                if hp.initiator_peer_id == self.viewer_id.to_string() {
                    Some(to_sse_frame(&event))
                } else {
                    None
                }
            }
        }
    }
}

/// Translate the broadcast channel into SSE frames, optionally ACL-filtered
/// for a specific viewer. Lagged subscribers see their dropped frames
/// counted (via a warn log) and the stream continues — that matches the
/// contract "drop oldest if slow consumer".
fn peer_event_stream(
    coordinator: Coordinator,
    viewer: Option<(Uuid, Vec<String>)>,
    bootstrap: Vec<PeerInfo>,
    receiver: tokio::sync::broadcast::Receiver<PeerEvent>,
) -> impl Stream<Item = Result<SseFrame, Infallible>> {
    // Seed the per-viewer filter (if any) from the bootstrap snapshot so
    // the initial `peer_added` burst is itself ACL-filtered and the
    // `revealed` set is primed for later convergence.
    let mut filter = viewer.map(|(viewer_id, viewer_tags)| ViewerFilter {
        coordinator,
        viewer_id,
        viewer_tags,
        revealed: HashSet::new(),
    });

    let initial_frames: Vec<SseFrame> = bootstrap
        .into_iter()
        .filter_map(|p| match filter.as_mut() {
            Some(f) => f.apply(PeerEvent::Added(p)),
            None => Some(to_sse_frame(&PeerEvent::Added(p))),
        })
        .collect();
    let initial = futures::stream::iter(
        initial_frames
            .into_iter()
            .map(Ok::<SseFrame, Infallible>),
    );

    let live = BroadcastStream::new(receiver).filter_map(move |next| {
        // `filter` is moved into the closure; updated in place per frame.
        let frame = match next {
            Ok(event) => match filter.as_mut() {
                Some(f) => f.apply(event),
                None => Some(to_sse_frame(&event)),
            },
            Err(BroadcastStreamRecvError::Lagged(n)) => {
                warn!(dropped = n, "SSE subscriber lagged, dropping frames");
                None
            }
        };
        async move { frame.map(Ok::<SseFrame, Infallible>) }
    });
    initial.chain(live)
}

/// Build an SSE frame for a single peer event. Falls back to a generic
/// error frame if the payload fails to serialise — that path should be
/// unreachable, but a single bad event must never poison the stream.
fn to_sse_frame(event: &PeerEvent) -> SseFrame {
    match event.data_payload() {
        Ok(json) => SseFrame::default().event(event.event_name()).data(json),
        Err(e) => {
            warn!(error = %e, "failed to serialise peer event");
            SseFrame::default().event("error").data("serialisation failed")
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::publisher::EventPublisher;
    use crate::roster::events::HolePunchInitiate;
    use async_trait::async_trait;
    use std::sync::Arc;

    struct NoopPublisher;
    #[async_trait]
    impl EventPublisher for NoopPublisher {
        async fn publish(&self, _t: &str, _s: &str, _p: Vec<u8>) -> Result<(), String> {
            Ok(())
        }
    }

    fn test_coordinator() -> Coordinator {
        Coordinator::new(Arc::new(NoopPublisher), Duration::from_secs(60))
    }

    fn holepunch_for(initiator: Uuid, target: Uuid) -> PeerEvent {
        PeerEvent::HolePunch(HolePunchInitiate {
            initiator_peer_id: initiator.to_string(),
            target_peer_id: target.to_string(),
            target_external_endpoint: "203.0.113.9:51820".into(),
            timestamp_micros: 1,
        })
    }

    /// The per-viewer SSE filter forwards a hole-punch frame ONLY to the
    /// peer named as its initiator — that peer is the one instructed to
    /// fire UDP. A viewer named as initiator gets the frame; the same
    /// viewer named only as a target (someone else's initiate) does not.
    #[test]
    fn viewer_filter_forwards_holepunch_only_to_initiator() {
        let viewer = Uuid::from_u128(1);
        let other = Uuid::from_u128(2);
        let mut filter = ViewerFilter {
            coordinator: test_coordinator(),
            viewer_id: viewer,
            viewer_tags: vec![],
            revealed: HashSet::new(),
        };
        // We are the initiator → forwarded.
        assert!(filter.apply(holepunch_for(viewer, other)).is_some());
        // We are only the target of someone else's initiate → dropped.
        assert!(filter.apply(holepunch_for(other, viewer)).is_none());
    }
}

