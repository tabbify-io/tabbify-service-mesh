//! Admin HTTP API for the Track A-a per-pair `direct` flag.
//!
//! | Method | Path                              | Auth                      | Purpose                          |
//! |--------|-----------------------------------|---------------------------|----------------------------------|
//! | `POST` | `/v1/mesh/pairs/{a}/{b}/direct`   | `Bearer MESH_ADMIN_TOKEN` | Set/clear the pair's direct flag.|
//!
//! Same fail-closed `check_admin` as the policy + command APIs: a missing/unset
//! token → `401`. The flag DEFAULTS OFF for every pair (relay is the floor) and
//! is set ONLY here; toggling it off instantly returns the pair to relay on the
//! next heartbeat (the instant rollback lever). A coordinator restart drops the
//! whole store → every pair returns to relay (the SAFE direction).

use crate::http::api::ApiError;
use crate::roster::coordinator::Coordinator;
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use std::str::FromStr;
use uuid::Uuid;

/// State for the direct-flag admin handler: coordinator + the admin token.
#[derive(Clone)]
pub struct DirectApiState {
    /// The coordinator owning the per-pair direct-flag store.
    pub coordinator: Coordinator,
    /// Expected admin bearer token. `None` disables the endpoint (401).
    pub admin_token: Option<String>,
}

/// `POST` body: whether the pair should be direct (`true`) or relay (`false`).
#[derive(Debug, Deserialize)]
pub struct DirectBody {
    /// `true` flags the pair for direct WG; `false` clears it (relay floor).
    pub direct: bool,
}

fn err(status: StatusCode, message: impl Into<String>) -> Response {
    (
        status,
        Json(ApiError {
            error: message.into(),
        }),
    )
        .into_response()
}

/// Fail-closed bearer check — identical semantics to the policy + command APIs.
fn check_admin(state: &DirectApiState, headers: &HeaderMap) -> Option<Response> {
    let Some(expected) = state.admin_token.as_deref() else {
        return Some(err(
            StatusCode::UNAUTHORIZED,
            "direct-flag admin API disabled (MESH_ADMIN_TOKEN unset)",
        ));
    };
    let presented = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    match presented {
        Some(tok) if tok == expected => None,
        _ => Some(err(
            StatusCode::UNAUTHORIZED,
            "invalid or missing admin token",
        )),
    }
}

/// Parse one path UUID, mapping a malformed value to a `400` response.
fn parse_uuid(raw: &str) -> Result<Uuid, Box<Response>> {
    Uuid::from_str(raw)
        .map_err(|e| Box::new(err(StatusCode::BAD_REQUEST, format!("invalid peer id: {e}"))))
}

/// Set (or clear) the per-pair direct flag (admin-gated, Track A-a).
///
/// `{"direct": true}` flags the (canonical) pair so the coordinator MAY
/// synthesize a reflexive endpoint + emit a punch for it even when a peer is
/// `relay_only` — the one deliberate, observable relaxation of the 2026-06-07
/// contract. `{"direct": false}` clears it; the pair returns to the relay floor
/// on the next heartbeat. Returns `204 No Content` on success.
pub async fn post_direct_handler(
    State(state): State<DirectApiState>,
    Path((a, b)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<DirectBody>,
) -> Response {
    if let Some(resp) = check_admin(&state, &headers) {
        return resp;
    }
    let a = match parse_uuid(&a) {
        Ok(p) => p,
        Err(r) => return *r,
    };
    let b = match parse_uuid(&b) {
        Ok(p) => p,
        Err(r) => return *r,
    };
    state
        .coordinator
        .direct_pair_flags()
        .set_direct(a, b, body.direct);
    StatusCode::NO_CONTENT.into_response()
}
