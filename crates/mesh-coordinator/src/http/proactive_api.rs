//! Admin HTTP API for the fleet-wide `proactive` direct gate (runtime toggle).
//!
//! | Method | Path                 | Auth                      | Purpose                              |
//! |--------|----------------------|---------------------------|--------------------------------------|
//! | `POST` | `/v1/mesh/proactive` | `Bearer MESH_ADMIN_TOKEN` | Arm/disarm the global proactive gate.|
//! | `GET`  | `/v1/mesh/proactive` | `Bearer MESH_ADMIN_TOKEN` | Read the current gate state.         |
//!
//! `proactive` is the fleet-wide gate: when ON, every NON-`relay_only` pair is
//! allowed to ATTEMPT direct (still governed by the per-pair flags and always
//! backed by the relay floor). It was previously settable ONLY at startup
//! (`--proactive` / `TABBIFY_MESH_PROACTIVE`). The coordinator runs in a managed
//! account with no operator shell, so a startup-only gate is unreachable; this
//! endpoint exposes the SAME `AtomicBool` as a runtime knob, flippable over the
//! admin API with no restart — the instant, reversible Stage-4 fleet lever
//! (mirrors the per-pair `direct_api`).
//!
//! The relay floor is UNCHANGED regardless: proactive only relaxes the gate for
//! a direct ATTEMPT — a `relay_only` peer is never dialed (R6), and a failed
//! punch always degrades back to relay. A coordinator restart resets the gate to
//! its `--proactive` startup default (the SAFE direction when that default is
//! off), exactly like the per-pair flag store.

use crate::http::admin_auth::check_admin_bearer;
use crate::roster::coordinator::Coordinator;
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

/// State for the proactive-gate admin handler: coordinator + the admin token.
#[derive(Clone)]
pub struct ProactiveApiState {
    /// The coordinator owning the `proactive` atomic.
    pub coordinator: Coordinator,
    /// Expected admin bearer token. `None` disables the endpoint (401).
    pub admin_token: Option<String>,
}

/// `POST` body — arm or disarm the fleet-wide proactive gate.
#[derive(Debug, Deserialize)]
pub struct ProactiveBody {
    /// `true` arms the gate (non-relay-only pairs may attempt direct); `false`
    /// disarms it (every non-flagged pair returns to relay on the next
    /// heartbeat).
    pub on: bool,
}

/// `GET` response — the current gate state.
#[derive(Debug, Serialize)]
pub struct ProactiveState {
    /// Whether the fleet-wide proactive gate is currently armed.
    pub on: bool,
}

/// Fail-closed bearer check — identical semantics to the direct + policy APIs.
fn check_admin(state: &ProactiveApiState, headers: &HeaderMap) -> Option<Response> {
    check_admin_bearer(state.admin_token.as_deref(), headers, "proactive")
}

/// Read the current fleet-wide proactive gate state (admin-gated).
pub async fn get_proactive_handler(
    State(state): State<ProactiveApiState>,
    headers: HeaderMap,
) -> Response {
    if let Some(resp) = check_admin(&state, &headers) {
        return resp;
    }
    Json(ProactiveState {
        on: state.coordinator.proactive_on(),
    })
    .into_response()
}

/// Arm/disarm the fleet-wide proactive gate at runtime (admin-gated).
///
/// `{"on": true}` arms it; `{"on": false}` disarms it. Returns `204 No Content`.
/// The relay floor is untouched: proactive only relaxes the gate for a direct
/// ATTEMPT — a `relay_only` peer is never dialed and a failed punch degrades to
/// relay.
pub async fn post_proactive_handler(
    State(state): State<ProactiveApiState>,
    headers: HeaderMap,
    Json(body): Json<ProactiveBody>,
) -> Response {
    if let Some(resp) = check_admin(&state, &headers) {
        return resp;
    }
    state.coordinator.set_proactive(body.on);
    StatusCode::NO_CONTENT.into_response()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::publisher::EventPublisher;
    use async_trait::async_trait;
    use axum::http::{HeaderValue, header};
    use std::sync::Arc;
    use std::time::Duration;

    struct NoopPublisher;
    #[async_trait]
    impl EventPublisher for NoopPublisher {
        async fn publish(&self, _t: &str, _s: &str, _p: Vec<u8>) -> Result<(), String> {
            Ok(())
        }
    }

    fn state_with(token: Option<&str>) -> (ProactiveApiState, Coordinator) {
        let coordinator = Coordinator::new(Arc::new(NoopPublisher), Duration::from_secs(60));
        let state = ProactiveApiState {
            coordinator: coordinator.clone(),
            admin_token: token.map(str::to_string),
        };
        (state, coordinator)
    }

    fn bearer(tok: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {tok}")).unwrap(),
        );
        h
    }

    /// The happy path: a valid admin token arms the gate, and a second call
    /// disarms it — the runtime fleet lever, both directions, no restart.
    #[tokio::test]
    async fn post_arms_then_disarms_the_gate() {
        let (state, coord) = state_with(Some("secret"));
        assert!(!coord.proactive_on(), "gate starts off (startup default)");

        let resp = post_proactive_handler(
            State(state.clone()),
            bearer("secret"),
            Json(ProactiveBody { on: true }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        assert!(coord.proactive_on(), "armed after {{\"on\":true}}");

        let resp = post_proactive_handler(
            State(state),
            bearer("secret"),
            Json(ProactiveBody { on: false }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        assert!(!coord.proactive_on(), "disarmed after {{\"on\":false}}");
    }

    /// Fail-closed: a wrong token is rejected with 401 and the gate is NOT
    /// touched (a bad request can never flip the fleet).
    #[tokio::test]
    async fn wrong_token_is_rejected_and_gate_untouched() {
        let (state, coord) = state_with(Some("secret"));
        let resp = post_proactive_handler(
            State(state),
            bearer("nope"),
            Json(ProactiveBody { on: true }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(
            !coord.proactive_on(),
            "gate untouched by a rejected request"
        );
    }

    /// An unset admin token disables the endpoint entirely (401) — a
    /// coordinator with no admin token can't be reconfigured over the wire.
    #[tokio::test]
    async fn unset_token_disables_endpoint() {
        let (state, coord) = state_with(None);
        let resp = post_proactive_handler(
            State(state),
            bearer("anything"),
            Json(ProactiveBody { on: true }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(!coord.proactive_on());
    }

    /// `GET` reflects the live state and is itself admin-gated.
    #[tokio::test]
    async fn get_reports_state_and_is_admin_gated() {
        let (state, coord) = state_with(Some("secret"));
        coord.set_proactive(true);

        let ok = get_proactive_handler(State(state.clone()), bearer("secret")).await;
        assert_eq!(ok.status(), StatusCode::OK);

        let denied = get_proactive_handler(State(state), bearer("wrong")).await;
        assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
    }
}
