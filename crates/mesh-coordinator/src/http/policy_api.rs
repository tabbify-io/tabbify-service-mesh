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

use crate::http::admin_auth::{check_admin_bearer, err};
use crate::http::api::ApiError;
use crate::policy::{Policy, PolicyReplaceError};
use crate::roster::coordinator::Coordinator;
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Serialize;
use utoipa::ToSchema;

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
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct PolicyResponse {
    /// Current policy document.
    pub policy: Policy,
    /// Current version tag (mirrors the `ETag` header).
    pub etag: String,
}

/// Verify the admin bearer for this API. Delegates to the shared
/// [`check_admin_bearer`] so every admin surface enforces one rule.
fn check_admin(state: &PolicyApiState, headers: &HeaderMap) -> Option<Response> {
    check_admin_bearer(state.admin_token.as_deref(), headers, "policy")
}

/// Fetch the current ACL policy + its `ETag` (admin-gated).
///
/// Returns the live policy snapshot, with the version tag mirrored as
/// both the JSON `etag` field and the `ETag` response header. The
/// returned `ETag` is required as `If-Match` on any subsequent `PUT`
/// (optimistic concurrency).
#[utoipa::path(
    get,
    path = "/v1/policy",
    tag = "policy",
    responses(
        (status = 200, description = "Current policy + ETag (mirrored in the ETag response header)", body = PolicyResponse),
        (status = 401, description = "Missing / invalid admin token (or admin API disabled)", body = ApiError),
    ),
    security(("bearer" = []))
)]
#[tracing::instrument(skip_all)]
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

/// Replace the ACL policy (admin-gated, `If-Match` required).
///
/// Requires both `Authorization: Bearer <MESH_ADMIN_TOKEN>` and the
/// current `ETag` echoed in `If-Match` for optimistic concurrency. On
/// success the roster is re-filtered and the deltas pushed over the
/// existing `/v1/mesh/peers/stream` SSE — connected nodes converge
/// without re-registering.
#[utoipa::path(
    put,
    path = "/v1/policy",
    tag = "policy",
    request_body = Policy,
    responses(
        (status = 200, description = "Replaced; body carries the new policy + ETag (also in header)", body = PolicyResponse),
        (status = 401, description = "Missing / invalid admin token (or admin API disabled)", body = ApiError),
        (status = 412, description = "If-Match ETag stale; current ETag returned in header", body = ApiError),
        (status = 422, description = "Policy rejected by validation (e.g. a cross-tenant tag:net-* source)", body = ApiError),
        (status = 428, description = "Missing If-Match header", body = ApiError),
    ),
    security(("bearer" = []))
)]
#[tracing::instrument(skip_all)]
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
        Err(e @ PolicyReplaceError::Invalid(_)) => {
            // The payload would break tenant isolation (e.g. a tag:net-*
            // source). Reject it as a client error; nothing was installed.
            err(StatusCode::UNPROCESSABLE_ENTITY, e.to_string())
        }
    }
}
