//! HTTP API: JSON request/response types + axum router + handlers.
//!
//! All endpoints live under `/v1/mesh/...`. JSON is the wire format —
//! `wg_public_key` is base64-encoded for human readability + curl-ability.
//!
//! Layout:
//!
//! - [`mod@dto`] — wire-shape DTOs (`PeerInfo`, `RegisterRequest`,
//!   `RegisterResponse`, `HeartbeatRequest`, `HeartbeatResponse`,
//!   `DeregisterRequest`, `RosterResponse`, `StreamQuery`, `ApiError`).
//! - [`mod@handlers`] — the four non-streaming request handlers.
//! - [`mod@stream`] — the SSE stream handler + per-viewer ACL filter.
//! - This file — router builders + `pub(crate)` re-exports.

mod dto;
pub(crate) mod handlers;
pub(crate) mod stream;

#[cfg(test)]
mod tests;

pub use dto::{
    DeregisterRequest, HeartbeatRequest, HeartbeatResponse, PeerInfo, RegisterRequest,
    RegisterResponse, RosterResponse, StreamQuery,
};
pub(crate) use dto::ApiError;
pub(crate) use handlers::{deregister_handler, heartbeat_handler, peers_handler, register_handler};
pub(crate) use stream::stream_handler;

use crate::http::policy_api::{PolicyApiState, get_policy_handler, put_policy_handler};
use crate::roster::coordinator::Coordinator;
use axum::{
    Router,
    routing::{get, post},
};

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

    peer_routes
        .merge(policy_routes)
        // Swagger UI at `/swagger-ui` + the raw spec at `/openapi.json`.
        // Unauthenticated, so operators can browse the contract before
        // they hold a join token / admin token.
        .merge(crate::openapi::swagger_routes())
}
