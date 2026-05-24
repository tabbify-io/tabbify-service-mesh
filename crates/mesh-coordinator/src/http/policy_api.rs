//! Admin HTTP API for the ACL policy (spec §7).
//!
//! | Method | Path         | Auth                      | Purpose                         |
//! |--------|--------------|---------------------------|---------------------------------|
//! | `GET`  | `/v1/policy` | `Bearer MESH_ADMIN_TOKEN` | Fetch current policy + `ETag`.  |
//! | `PUT`  | `/v1/policy` | `Bearer MESH_ADMIN_TOKEN` | Replace policy; `If-Match` req. |
//!
//! - **Auth:** a missing/incorrect bearer token → `401`. The expected
//!   token is read once from `MESH_ADMIN_TOKEN` at router-build time and
//!   carried in [`PolicyApiState`]. When unset, the admin endpoints are
//!   *disabled* (every call → `401`) so a coordinator without an admin
//!   token can't be reconfigured over the wire.
//! - **Concurrency:** `GET` returns the current `ETag`; `PUT` requires a
//!   matching `If-Match`, returning `412 Precondition Failed` on a stale
//!   tag (lost-update protection).
//! - **Convergence:** a successful `PUT` re-filters every connected node's
//!   roster view and pushes the resulting add/update/remove frames over
//!   the existing `peers/stream` SSE — nodes converge without
//!   re-registering. See [`Coordinator::resync_all_peers`].

use crate::policy::{Policy, PolicyReplaceError};
use crate::roster::coordinator::Coordinator;
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Serialize;

/// State carried by the policy admin handlers: the coordinator (for the
/// store + roster resync) plus the configured admin token.
#[derive(Clone)]
pub struct PolicyApiState {
    /// The coordinator owning the live policy store + roster.
    pub coordinator: Coordinator,
    /// Expected admin bearer token. `None` disables the admin endpoints
    /// (all calls 401) — fail-closed when no token is configured.
    pub admin_token: Option<String>,
}

/// JSON body of `GET /v1/policy` — the policy plus its current version tag
/// (the same value also lands in the `ETag` response header).
#[derive(Debug, Serialize)]
struct PolicyResponse {
    /// Current policy document.
    policy: Policy,
    /// Current version tag (mirrors the `ETag` header).
    etag: String,
}

/// JSON error envelope, matching the peer API's shape.
#[derive(Debug, Serialize)]
struct ApiError {
    error: String,
}

fn err(status: StatusCode, message: impl Into<String>) -> Response {
    (status, Json(ApiError { error: message.into() })).into_response()
}

/// Verify the `Authorization: Bearer <token>` header against the configured
/// admin token. Returns `None` on match, or `Some(401 response)` to reject.
///
/// (Returns `Option` rather than `Result` so the rejection — a large
/// `Response` — isn't carried in an `Err` variant, which would bloat every
/// caller's `Result`.)
///
/// Fail-closed: if no admin token is configured, every request is rejected.
fn check_admin(state: &PolicyApiState, headers: &HeaderMap) -> Option<Response> {
    let Some(expected) = state.admin_token.as_deref() else {
        return Some(err(
            StatusCode::UNAUTHORIZED,
            "policy admin API disabled (MESH_ADMIN_TOKEN unset)",
        ));
    };
    let presented = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    match presented {
        Some(tok) if tok == expected => None,
        _ => Some(err(StatusCode::UNAUTHORIZED, "invalid or missing admin token")),
    }
}

/// `GET /v1/policy` — fetch the current policy + `ETag` (admin-gated).
pub async fn get_policy_handler(
    State(state): State<PolicyApiState>,
    headers: HeaderMap,
) -> Response {
    if let Some(resp) = check_admin(&state, &headers) {
        return resp;
    }
    let snap = state.coordinator.policy().snapshot();
    let body = PolicyResponse {
        policy: snap.policy,
        etag: snap.etag.clone(),
    };
    ([(header::ETAG, snap.etag)], Json(body)).into_response()
}

/// `PUT /v1/policy` — replace the policy (admin-gated, `If-Match` required).
///
/// - `401` — bad/missing admin token.
/// - `428 Precondition Required` — missing `If-Match` header.
/// - `412 Precondition Failed` — `If-Match` `ETag` is stale.
/// - `200` — replaced; body carries the new policy + `ETag`, and the roster
///   is re-filtered + pushed over SSE.
pub async fn put_policy_handler(
    State(state): State<PolicyApiState>,
    headers: HeaderMap,
    Json(new_policy): Json<Policy>,
) -> Response {
    if let Some(resp) = check_admin(&state, &headers) {
        return resp;
    }
    let Some(if_match) = headers
        .get(header::IF_MATCH)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
    else {
        return err(
            StatusCode::PRECONDITION_REQUIRED,
            "If-Match header required for policy replace (optimistic concurrency)",
        );
    };

    match state.coordinator.policy().replace(&if_match, new_policy) {
        Ok(snap) => {
            // Policy changed → re-filter every connected node's view and
            // push the deltas over the existing SSE stream so nodes
            // converge their sessions without re-registering.
            state.coordinator.resync_all_peers();
            let body = PolicyResponse {
                policy: snap.policy,
                etag: snap.etag.clone(),
            };
            ([(header::ETAG, snap.etag)], Json(body)).into_response()
        }
        Err(PolicyReplaceError::EtagMismatch { current, .. }) => (
            StatusCode::PRECONDITION_FAILED,
            [(header::ETAG, current.clone())],
            Json(ApiError {
                error: format!("etag mismatch; current is {current}"),
            }),
        )
            .into_response(),
    }
}
