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

use crate::http::admin_auth::{check_admin_bearer, err};
use crate::roster::coordinator::Coordinator;
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
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

/// `POST` body — two INDEPENDENT, optional per-pair overrides (R5 dual-field).
/// Back-compat: an existing `{"direct": true|false}` body still works verbatim.
#[derive(Debug, Deserialize)]
pub struct DirectBody {
    /// Per-pair "force-attempt-direct" override: `true` makes the pair attempt
    /// direct even while the GLOBAL proactive gate is OFF (the Stage-2 single-
    /// pair canary lever); `false` clears it. Absent ⇒ leave it unchanged.
    #[serde(default)]
    pub direct: Option<bool>,
    /// HARD relay pin: `true` pins the pair to the relay (wins over the gate AND
    /// over `direct`); `false` clears the pin. Absent ⇒ leave it unchanged.
    #[serde(default)]
    pub pin_to_relay: Option<bool>,
}

/// Fail-closed bearer check — identical semantics to the policy + command APIs.
fn check_admin(state: &DirectApiState, headers: &HeaderMap) -> Option<Response> {
    check_admin_bearer(state.admin_token.as_deref(), headers, "direct-flag")
}

/// Parse one path UUID, mapping a malformed value to a `400` response.
fn parse_uuid(raw: &str) -> Result<Uuid, Box<Response>> {
    Uuid::from_str(raw).map_err(|e| {
        Box::new(err(
            StatusCode::BAD_REQUEST,
            format!("invalid peer id: {e}"),
        ))
    })
}

/// Set (or clear) the per-pair direct overrides (admin-gated).
///
/// `{"direct": true}` forces the (canonical) pair to attempt direct even while
/// the global proactive gate is OFF; `{"pin_to_relay": true}` HARD-pins the pair
/// to the relay (wins over the gate and over `direct`). Either field may be sent
/// (both optional); `false` clears that override; absent leaves it unchanged.
/// Returns `204 No Content` on success. NOTE: a self-declared `relay_only` peer
/// is never dialed regardless of `direct` (R6) — the per-pair `direct` override
/// only relaxes the GLOBAL gate for a NON-pinned pair.
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
    let flags = state.coordinator.direct_pair_flags();
    if let Some(direct) = body.direct {
        flags.set_direct(a, b, direct);
    }
    if let Some(pin) = body.pin_to_relay {
        flags.set_pinned_to_relay(a, b, pin);
    }
    StatusCode::NO_CONTENT.into_response()
}
