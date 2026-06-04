//! End-to-end smoke test: the coordinator's HTTP router serves the
//! `OpenAPI` 3 document at `/openapi.json` and the Swagger UI at
//! `/swagger-ui`.
//!
//! A regression here is the first sign the new docs router was lost while
//! refactoring `build_router_with_admin` — the rest of the wire contract
//! is exercised by `http_smoke.rs` and `jwt_register.rs`.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use serde_json::Value;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tabbify_mesh_coordinator::{
    AclRule, Coordinator, NoopPublisher, Policy, PolicyStore, build_router,
};

fn permissive_policy() -> Policy {
    Policy::new(vec![AclRule::accept(&["*"], &["*"])])
}

async fn spawn_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let coord = Coordinator::with_policy(
        Arc::new(NoopPublisher),
        Duration::from_secs(60),
        PolicyStore::new(permissive_policy()),
    );
    let router = build_router(coord);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let handle = tokio::spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .expect("serve");
    });
    (addr, handle)
}

/// `GET /openapi.json` returns a valid `OpenAPI` 3 document that includes
/// every documented coordinator route.
#[tokio::test]
async fn openapi_json_is_served_and_lists_every_route() {
    let (addr, _server) = spawn_server().await;
    let url = format!("http://{addr}/openapi.json");
    let resp = reqwest::get(&url).await.expect("openapi.json GET");
    assert_eq!(resp.status(), 200, "openapi.json must be served");
    let body: Value = resp.json().await.expect("openapi.json is JSON");

    // OpenAPI 3 marker.
    assert!(
        body.get("openapi")
            .and_then(Value::as_str)
            .is_some_and(|v| v.starts_with("3.")),
        "expected `openapi: 3.x`, got {:?}",
        body.get("openapi"),
    );

    // Every route from the coordinator router shows up in `paths`.
    let paths = body
        .get("paths")
        .and_then(Value::as_object)
        .expect("`paths` object present");
    for expected in [
        "/v1/mesh/register",
        "/v1/mesh/heartbeat",
        "/v1/mesh/deregister",
        "/v1/mesh/peers",
        "/v1/mesh/peers/stream",
        "/v1/policy",
    ] {
        assert!(
            paths.contains_key(expected),
            "openapi paths missing {expected}; present: {:?}",
            paths.keys().collect::<Vec<_>>(),
        );
    }

    // The SSE endpoint declares `text/event-stream` so generated SDKs
    // treat it as a streaming response.
    let sse_content = body["paths"]["/v1/mesh/peers/stream"]["get"]["responses"]["200"]["content"]
        .as_object()
        .expect("SSE 200 has content");
    assert!(
        sse_content.contains_key("text/event-stream"),
        "SSE 200 must advertise text/event-stream; got {:?}",
        sse_content.keys().collect::<Vec<_>>(),
    );
}

/// `GET /swagger-ui` (with trailing slash) serves the Swagger UI HTML so
/// operators can browse the API contract from a browser.
#[tokio::test]
async fn swagger_ui_is_served() {
    let (addr, _server) = spawn_server().await;
    // The SwaggerUi mount handles both `/swagger-ui` and
    // `/swagger-ui/index.html`. Hit the index directly so we don't depend
    // on redirect handling (which differs between reqwest versions and
    // between axum's tree vs flat-routing internals).
    let url = format!("http://{addr}/swagger-ui/index.html");
    let resp = reqwest::get(&url).await.expect("swagger-ui GET");
    assert_eq!(resp.status(), 200, "swagger-ui index must be served");
    let ctype = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    assert!(
        ctype.starts_with("text/html"),
        "swagger-ui index must be HTML; got content-type={ctype:?}",
    );
    let body = resp.text().await.expect("swagger-ui body");
    assert!(
        body.to_lowercase().contains("swagger"),
        "swagger-ui index must reference Swagger; first bytes: {:?}",
        &body.chars().take(200).collect::<String>(),
    );
}

/// `POST /v1/mesh/register` declares the `bearer` security scheme — a
/// regression here means the `OpenAPI` auth annotation was lost while
/// refactoring the handler.
#[tokio::test]
async fn register_declares_bearer_security_in_spec() {
    let (addr, _server) = spawn_server().await;
    let url = format!("http://{addr}/openapi.json");
    let body: Value = reqwest::get(&url)
        .await
        .expect("openapi GET")
        .json()
        .await
        .expect("openapi JSON");
    let security = &body["paths"]["/v1/mesh/register"]["post"]["security"];
    let array = security
        .as_array()
        .expect("POST /v1/mesh/register must declare a `security` array");
    assert!(
        !array.is_empty(),
        "POST /v1/mesh/register `security` must not be empty",
    );
    assert!(
        array
            .iter()
            .any(|entry| entry.as_object().is_some_and(|m| m.contains_key("bearer"))),
        "POST /v1/mesh/register must include the `bearer` scheme; got {array:?}",
    );

    // And the scheme itself is declared under `components.securitySchemes`.
    let schemes = &body["components"]["securitySchemes"];
    assert!(
        schemes["bearer"].is_object(),
        "components.securitySchemes.bearer must be declared; got {schemes:?}",
    );
}
