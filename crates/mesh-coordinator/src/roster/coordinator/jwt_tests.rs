//! JWT join-token validation (spec §8 / E4).
//!
//! These exercise `register_authenticated` against a fake auth service
//! (wiremock). The central guarantee: when a validator is configured a
//! node's effective network + tags equal exactly what the validator
//! returns — spoofed `RegisterRequest` values are ignored — and an
//! invalid / missing / revoked token rejects the register. The escape
//! hatch (no validator) preserves the legacy request-trusting behavior.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use super::*;
use crate::auth::AuthValidator;
use crate::http::api::RegisterRequest;
use crate::policy::{AclRule, Policy, PolicyStore};
use crate::publisher::NoopPublisher;
use base64::Engine as _;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn pubkey(seed: u8) -> String {
    base64::engine::general_purpose::STANDARD.encode([seed; 32])
}

/// A register request that self-asserts a (potentially spoofed)
/// network + tag set. Whether those survive depends entirely on
/// whether a validator is wired.
fn req_with(seed: u8, network: &str, tags: &[&str]) -> RegisterRequest {
    RegisterRequest {
        wg_public_key: pubkey(seed),
        listen_endpoint: Some("127.0.0.1:51820".into()),
        wg_listen_port: Some(51820),
        display_name: "node".into(),
        network: network.into(),
        tags: tags.iter().map(|s| (*s).to_owned()).collect(),
        hosted_app_ulas: vec![],
        kind: "peer".into(),
        parent: None,
        app_uuid: None,
        requested_ula: None,
    }
}

/// Permissive policy so visibility filtering doesn't get in the way —
/// these tests are about identity stamping, not roster filtering.
fn permissive() -> PolicyStore {
    PolicyStore::new(Policy::new(vec![AclRule::accept(&["*"], &["*"])]))
}

fn coordinator_with_validator(validator: AuthValidator) -> Coordinator {
    Coordinator::with_policy_and_validator(
        Arc::new(NoopPublisher),
        Duration::from_secs(60),
        permissive(),
        Some(validator),
    )
}

/// Mount a `/v1/validate` mock returning the given JSON body.
async fn mock_validate(server: &MockServer, body: serde_json::Value) {
    Mock::given(method("POST"))
        .and(path("/v1/validate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(server)
        .await;
}

/// Valid token → admit, and the node's network + tags come from the
/// CLAIMS, not the request.
#[tokio::test]
async fn valid_token_admits_with_claims_network_and_tags() {
    let server = MockServer::start().await;
    mock_validate(
        &server,
        serde_json::json!({
            "valid": true,
            "subject": "node-alice",
            "network": "alice",
            "tags": ["tag:user-alice"],
            "kind": "join",
            "exp": 1_900_000_000_i64,
        }),
    )
    .await;
    let c = coordinator_with_validator(AuthValidator::new(server.uri()).unwrap());

    // Request asserts a DIFFERENT network/tags than the claims.
    let req = req_with(1, "request-network", &["tag:request-supplied"]);
    let (entry, outcome) = c
        .register_authenticated(req, Some("good-token"), None)
        .await
        .expect("admit");
    assert_eq!(outcome, RegisterOutcome::Created);
    assert_eq!(entry.network, "alice", "network must come from claims");
    assert_eq!(
        entry.tags,
        vec!["tag:user-alice".to_owned()],
        "tags must come from claims"
    );
}

/// The headline spoofing test: a node sends `tag:admin` + a foreign
/// network in its request, but the validator says it's a plain alice
/// node. The roster entry must reflect ONLY the claims.
#[tokio::test]
async fn spoofed_request_tags_are_ignored_in_favor_of_claims() {
    let server = MockServer::start().await;
    mock_validate(
        &server,
        serde_json::json!({
            "valid": true,
            "subject": "node-alice",
            "network": "alice",
            "tags": ["tag:user-alice"],
            "kind": "join",
            "exp": 1_900_000_000_i64,
        }),
    )
    .await;
    let c = coordinator_with_validator(AuthValidator::new(server.uri()).unwrap());

    // Malicious request: claim bob's network + an admin tag.
    let spoof = req_with(2, "bob", &["tag:user-bob", "tag:admin"]);
    let (entry, _) = c
        .register_authenticated(spoof, Some("good-token"), None)
        .await
        .expect("admit");
    assert_eq!(entry.network, "alice");
    assert_eq!(entry.tags, vec!["tag:user-alice".to_owned()]);
    assert!(
        !entry.tags.iter().any(|t| t == "tag:admin"),
        "spoofed admin tag must not appear"
    );
    // The ULA must be allocated in the CLAIMS network's block, not the
    // spoofed one — derive the expected slot from the claims network.
    let claims_slot = crate::roster::allocator::network_slot("alice");
    assert_eq!(
        entry.ula.segments()[2],
        claims_slot,
        "ULA block must be derived from the claims network"
    );
}

/// `valid: false` (expired / revoked / tampered) → Unauthorized.
#[tokio::test]
async fn invalid_or_revoked_token_is_rejected() {
    let server = MockServer::start().await;
    mock_validate(
        &server,
        serde_json::json!({
            "valid": false,
            "subject": "",
            "network": "",
            "tags": [],
            "kind": "join",
            "exp": 0,
        }),
    )
    .await;
    let c = coordinator_with_validator(AuthValidator::new(server.uri()).unwrap());

    let err = c
        .register_authenticated(req_with(3, "alice", &[]), Some("revoked-token"), None)
        .await
        .expect_err("must reject");
    assert!(matches!(err, CoordinatorError::Unauthorized(_)), "{err:?}");
    // Rejected join leaves zero roster state behind.
    assert_eq!(c.snapshot().len(), 0);
}

/// A validator is configured but no token is presented → Unauthorized,
/// before any roster mutation.
#[tokio::test]
async fn missing_token_is_rejected_when_validator_configured() {
    let server = MockServer::start().await;
    // No mock needed — we should never reach the auth service.
    let c = coordinator_with_validator(AuthValidator::new(server.uri()).unwrap());

    let err = c
        .register_authenticated(req_with(4, "alice", &[]), None, None)
        .await
        .expect_err("must reject");
    assert!(matches!(err, CoordinatorError::Unauthorized(_)), "{err:?}");
    assert_eq!(c.snapshot().len(), 0);
}

/// Auth service unreachable → fail closed (Unauthorized), never admit.
#[tokio::test]
async fn auth_service_unreachable_fails_closed() {
    // Port 1 refuses; nothing is listening.
    let c = coordinator_with_validator(AuthValidator::new("http://127.0.0.1:1").unwrap());
    let err = c
        .register_authenticated(req_with(5, "alice", &[]), Some("token"), None)
        .await
        .expect_err("must fail closed");
    assert!(matches!(err, CoordinatorError::Unauthorized(_)), "{err:?}");
    assert_eq!(c.snapshot().len(), 0);
}

/// Escape hatch: no validator → the request-supplied network + tags are
/// trusted (legacy dev/E1 behavior), token ignored.
#[tokio::test]
async fn escape_hatch_without_validator_trusts_request() {
    let c = Coordinator::with_policy_and_validator(
        Arc::new(NoopPublisher),
        Duration::from_secs(60),
        permissive(),
        None,
    );
    let (entry, _) = c
        .register_authenticated(req_with(6, "alice", &["tag:user-alice"]), None, None)
        .await
        .expect("admit (escape hatch)");
    assert_eq!(entry.network, "alice");
    assert_eq!(entry.tags, vec!["tag:user-alice".to_owned()]);
}

/// Re-register with the same pubkey must also stamp tags from claims —
/// a re-register can't be used to swap in spoofed tags either.
#[tokio::test]
async fn re_register_restamps_tags_from_claims() {
    let server = MockServer::start().await;
    mock_validate(
        &server,
        serde_json::json!({
            "valid": true,
            "subject": "node-alice",
            "network": "alice",
            "tags": ["tag:user-alice"],
            "kind": "join",
            "exp": 1_900_000_000_i64,
        }),
    )
    .await;
    let c = coordinator_with_validator(AuthValidator::new(server.uri()).unwrap());

    let (first, o1) = c
        .register_authenticated(req_with(7, "x", &["tag:request"]), Some("token"), None)
        .await
        .expect("first");
    assert_eq!(o1, RegisterOutcome::Created);
    // Second register, same pubkey, tries to assert admin again.
    let (second, o2) = c
        .register_authenticated(req_with(7, "x", &["tag:admin"]), Some("token"), None)
        .await
        .expect("re-register");
    assert_eq!(o2, RegisterOutcome::Existed);
    assert_eq!(first.peer_id, second.peer_id);
    assert_eq!(
        second.tags,
        vec!["tag:user-alice".to_owned()],
        "re-register tags must still come from claims"
    );
}
