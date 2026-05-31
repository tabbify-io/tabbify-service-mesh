//! `utoipa` `OpenAPI` document + Swagger UI mount.
//!
//! Aggregates every coordinator HTTP handler into a single `OpenAPI` 3
//! document served at `GET /openapi.json`, with Swagger UI at
//! `/swagger-ui`. Both are unauthenticated so operators can browse the
//! contract before they hold any tokens; the documented endpoints
//! themselves still enforce their own auth (transport-level mTLS for the
//! peer endpoints, application-level `Bearer` join-token on
//! `POST /v1/mesh/register` when `AUTH_URL` is configured, and
//! `Bearer MESH_ADMIN_TOKEN` on the policy admin endpoints).

use axum::Router;
use utoipa::OpenApi;
use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa_swagger_ui::SwaggerUi;

use crate::http::api::{
    ApiError, DeregisterRequest, HeartbeatRequest, HeartbeatResponse, PeerInfo, RegisterRequest,
    RegisterResponse, RosterResponse, StreamQuery,
};
use crate::http::policy_api::PolicyResponse;
use crate::http::sse::PeerEvent;
use crate::policy::{AclRule, Policy};
use crate::roster::events::HolePunchInitiate;

/// Aggregated `OpenAPI` 3 document for the mesh coordinator API.
///
/// `paths(...)` enumerates every public HTTP handler decorated with a
/// `#[utoipa::path]` macro; `components.schemas(...)` lists every DTO
/// referenced by those paths (and the SSE per-event payload — the
/// streaming body itself can't be a single `OpenAPI` body type, so the
/// per-event [`PeerEvent`] schema documents what a subscriber decodes
/// from each `data:` frame).
#[derive(OpenApi)]
#[openapi(
    info(
        title = "tabbify-mesh-coordinator",
        version = "0.1.0",
        description = "Mesh control plane. Joiners register over HTTP, get a stable \
                       peer-id + IPv6 ULA, exchange WireGuard public keys, then run \
                       data-plane traffic peer-to-peer. The HTTP surface covers \
                       peer registration, heartbeats, the unfiltered roster snapshot, \
                       the per-viewer ACL-filtered SSE stream of peer-lifecycle + \
                       hole-punch events, and the admin ACL policy API."
    ),
    paths(
        crate::http::api::handlers::register_handler,
        crate::http::api::handlers::heartbeat_handler,
        crate::http::api::handlers::deregister_handler,
        crate::http::api::handlers::peers_handler,
        crate::http::api::stream::stream_handler,
        crate::http::relay::relay_ws_handler,
        crate::http::policy_api::get_policy_handler,
        crate::http::policy_api::put_policy_handler,
    ),
    components(schemas(
        // Peer lifecycle DTOs.
        PeerInfo,
        RegisterRequest, RegisterResponse,
        HeartbeatRequest, HeartbeatResponse,
        DeregisterRequest,
        RosterResponse,
        StreamQuery,
        // SSE per-event payload (the streaming body itself isn't a
        // single OpenAPI body type; this documents what a subscriber
        // decodes from each `data:` frame).
        PeerEvent,
        HolePunchInitiate,
        // Policy admin DTOs.
        Policy, AclRule,
        PolicyResponse,
        // Shared error envelope.
        ApiError,
    )),
    modifiers(&BearerSecurity),
    tags(
        (name = "mesh", description = "Peer registration, heartbeats, roster, and the SSE peer-event stream."),
        (name = "policy", description = "Admin-gated ACL policy fetch / replace with optimistic concurrency (ETag / If-Match)."),
    )
)]
pub struct ApiDoc;

/// Registers the `bearer` security scheme referenced by the
/// authenticated paths' `security(("bearer" = []))`.
///
/// Two distinct populations of bearer tokens travel under this single
/// scheme name:
/// - `POST /v1/mesh/register` carries an end-user join token, validated
///   against the configured auth service (`AUTH_URL`, spec §8).
/// - `GET/PUT /v1/policy` carries the operator's `MESH_ADMIN_TOKEN`.
///
/// `OpenAPI` 3.0 has no native way to model two different bearer audiences
/// under one scheme, so the description spells out the dual usage; the
/// per-path docstrings disambiguate at the endpoint level.
struct BearerSecurity;

impl utoipa::Modify for BearerSecurity {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "bearer",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .description(Some(
                            "Bearer token. On `POST /v1/mesh/register` this is the \
                             end-user join token validated via AUTH_URL (spec §8); \
                             on `GET/PUT /v1/policy` it is the operator's \
                             MESH_ADMIN_TOKEN.",
                        ))
                        .build(),
                ),
            );
        }
    }
}

/// Router serving the Swagger UI (`/swagger-ui`) + the raw spec
/// (`/openapi.json`). Designed to be merged into the coordinator router
/// without imposing a state type on the docs endpoints themselves.
pub fn swagger_routes() -> Router {
    SwaggerUi::new("/swagger-ui")
        .url("/openapi.json", ApiDoc::openapi())
        .into()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    /// The `OpenAPI` document builds and enumerates every coordinator route.
    /// A regression here is the first sign a new handler was added to the
    /// router but not the `OpenAPI` `paths(...)` list.
    #[test]
    fn openapi_doc_enumerates_every_route() {
        let doc = ApiDoc::openapi();
        let mut paths: Vec<&str> = doc.paths.paths.keys().map(String::as_str).collect();
        paths.sort_unstable();
        assert_eq!(
            paths,
            vec![
                "/v1/mesh/deregister",
                "/v1/mesh/heartbeat",
                "/v1/mesh/peers",
                "/v1/mesh/peers/stream",
                "/v1/mesh/register",
                "/v1/mesh/relay",
                "/v1/policy",
            ],
        );
    }

    /// The `bearer` security scheme is registered and the paths that
    /// require it (register, policy GET/PUT) declare it.
    #[test]
    fn bearer_scheme_registered_on_authenticated_paths() {
        let doc = ApiDoc::openapi();
        let components = doc.components.as_ref().expect("components present");
        assert!(
            components.security_schemes.contains_key("bearer"),
            "bearer security scheme must be registered",
        );

        // `POST /v1/mesh/register` requires bearer.
        let register = doc
            .paths
            .paths
            .get("/v1/mesh/register")
            .and_then(|item| item.post.as_ref())
            .expect("POST /v1/mesh/register present");
        assert!(
            register
                .security
                .as_ref()
                .is_some_and(|s| !s.is_empty()),
            "POST /v1/mesh/register must declare bearer security",
        );

        // `/v1/policy` GET + PUT both require bearer.
        let policy_item = doc
            .paths
            .paths
            .get("/v1/policy")
            .expect("/v1/policy present");
        let policy_get = policy_item.get.as_ref().expect("GET /v1/policy present");
        let policy_put = policy_item.put.as_ref().expect("PUT /v1/policy present");
        assert!(
            policy_get
                .security
                .as_ref()
                .is_some_and(|s| !s.is_empty()),
            "GET /v1/policy must declare bearer security",
        );
        assert!(
            policy_put
                .security
                .as_ref()
                .is_some_and(|s| !s.is_empty()),
            "PUT /v1/policy must declare bearer security",
        );
    }

    /// The SSE endpoint advertises `text/event-stream` so clients (and
    /// generated SDKs) treat it as a streaming response, not a one-shot
    /// JSON body.
    #[test]
    fn sse_endpoint_declares_event_stream_content_type() {
        let doc = ApiDoc::openapi();
        let op = doc
            .paths
            .paths
            .get("/v1/mesh/peers/stream")
            .and_then(|item| item.get.as_ref())
            .expect("GET /v1/mesh/peers/stream present");
        let ok = op
            .responses
            .responses
            .get("200")
            .and_then(|r| match r {
                utoipa::openapi::RefOr::T(resp) => Some(resp),
                utoipa::openapi::RefOr::Ref(_) => None,
            })
            .expect("200 response present");
        assert!(
            ok.content.contains_key("text/event-stream"),
            "SSE response must declare content_type=text/event-stream",
        );
    }
}
