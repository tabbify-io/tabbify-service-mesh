//! Admin HTTP API for Track-C signed remote commands.
//!
//! | Method | Path                                | Auth                      | Purpose                     |
//! |--------|-------------------------------------|---------------------------|-----------------------------|
//! | `POST` | `/v1/mesh/peers/{peer_id}/commands` | `Bearer MESH_ADMIN_TOKEN` | Enqueue a signed command.   |
//! | `GET`  | `/v1/mesh/peers/{peer_id}/commands` | `Bearer MESH_ADMIN_TOKEN` | List pending `command_id`s. |
//!
//! Same fail-closed `check_admin` as the policy API: a missing/unset token →
//! `401`. The coordinator is a DUMB RELAY — it never verifies the body's
//! Ed25519 signature; the node verifies the super-admin key end-to-end.

use crate::http::admin_auth::{check_admin_bearer, err};
use crate::roster::coordinator::Coordinator;
use crate::roster::coordinator::command_queue::NodeCommandDto;
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Serialize;
use std::str::FromStr;
use uuid::Uuid;

/// State for the command admin handlers: coordinator + the admin token.
#[derive(Clone)]
pub struct CommandApiState {
    /// The coordinator owning the per-peer command queue.
    pub coordinator: Coordinator,
    /// Expected admin bearer token. `None` disables the endpoints (401).
    pub admin_token: Option<String>,
}

/// `GET` response: the pending `command_id`s for the peer.
#[derive(Debug, Serialize)]
struct PendingResponse {
    pending: Vec<String>,
}

/// Fail-closed bearer check — the shared rule, same as every admin surface.
fn check_admin(state: &CommandApiState, headers: &HeaderMap) -> Option<Response> {
    check_admin_bearer(state.admin_token.as_deref(), headers, "command")
}

/// Parse the path `peer_id`, mapping a malformed UUID to a `400` response.
/// Returns the parsed id, or `Err(response)` — the caller short-circuits with
/// it. (`Err` carries the boxed response so the `Result` stays small.)
fn parse_peer(raw: &str) -> Result<Uuid, Box<Response>> {
    Uuid::from_str(raw).map_err(|e| {
        Box::new(err(
            StatusCode::BAD_REQUEST,
            format!("invalid peer id: {e}"),
        ))
    })
}

/// Enqueue a signed command for the target peer (admin-gated). The coordinator
/// relays it verbatim — no signature check here.
pub async fn post_command_handler(
    State(state): State<CommandApiState>,
    Path(peer_id): Path<String>,
    headers: HeaderMap,
    Json(command): Json<NodeCommandDto>,
) -> Response {
    if let Some(resp) = check_admin(&state, &headers) {
        return resp;
    }
    let peer = match parse_peer(&peer_id) {
        Ok(p) => p,
        Err(r) => return *r,
    };
    state.coordinator.enqueue_command(peer, command);
    StatusCode::ACCEPTED.into_response()
}

/// List pending `command_id`s for the target peer (admin-gated).
pub async fn get_commands_handler(
    State(state): State<CommandApiState>,
    Path(peer_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Some(resp) = check_admin(&state, &headers) {
        return resp;
    }
    let peer = match parse_peer(&peer_id) {
        Ok(p) => p,
        Err(r) => return *r,
    };
    Json(PendingResponse {
        pending: state.coordinator.pending_command_ids(peer),
    })
    .into_response()
}
