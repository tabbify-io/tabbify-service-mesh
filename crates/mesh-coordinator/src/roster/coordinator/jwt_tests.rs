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
use std::sync::atomic::{AtomicUsize, Ordering};
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
        software_version: None,
        mesh_version: None,
        relay_only: false,
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

struct FirstPublishGate {
    calls: AtomicUsize,
    entered: Arc<tokio::sync::Barrier>,
    release: Arc<tokio::sync::Barrier>,
}

#[async_trait::async_trait]
impl crate::publisher::EventPublisher for FirstPublishGate {
    async fn publish(
        &self,
        _event_type: &str,
        _segment: &str,
        _payload: Vec<u8>,
    ) -> Result<(), String> {
        if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
            self.entered.wait().await;
            self.release.wait().await;
        }
        Ok(())
    }
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

async fn fixed_ula_claims(server: &MockServer, allowed: &[&str], network: &str) {
    mock_validate(
        server,
        serde_json::json!({
            "valid": true,
            "subject": "store-service",
            "network": network,
            "tags": [],
            "requested_ulas": allowed,
            "kind": "join",
            "exp": 1_900_000_000_i64,
        }),
    )
    .await;
}

#[tokio::test]
async fn exact_signed_capability_allows_only_its_fixed_ula_and_binds_network() {
    let server = MockServer::start().await;
    fixed_ula_claims(&server, &["fd5a:1f00:fffe::1"], "store-system").await;
    let c = coordinator_with_validator(AuthValidator::new(server.uri()).unwrap());
    let mut req = req_with(21, "spoofed-other-network", &["infra", "forge"]);
    req.requested_ula = Some("fd5a:1f00:fffe:0:0:0:0:1".into());

    let (entry, _) = c
        .register_authenticated(req, Some("token-for-store-system"), None)
        .await
        .expect("exact capability admits");
    assert_eq!(entry.ula.to_string(), "fd5a:1f00:fffe::1");
    assert_eq!(
        entry.network, "store-system",
        "token network is authoritative"
    );
}

#[tokio::test]
async fn concurrent_exact_capability_registers_cannot_both_reserve_fixed_ula() {
    let server = MockServer::start().await;
    fixed_ula_claims(&server, &["fd5a:1f00:fffe::1"], "store-system").await;
    let publish_entered = Arc::new(tokio::sync::Barrier::new(2));
    let publish_release = Arc::new(tokio::sync::Barrier::new(2));
    let publisher = Arc::new(FirstPublishGate {
        calls: AtomicUsize::new(0),
        entered: publish_entered.clone(),
        release: publish_release.clone(),
    });
    let coordinator = Coordinator::with_policy_and_validator(
        publisher,
        Duration::from_secs(60),
        permissive(),
        Some(AuthValidator::new(server.uri()).unwrap()),
    );
    let barrier = Arc::new(tokio::sync::Barrier::new(3));

    let register = |seed, token: &'static str| {
        let coordinator = coordinator.clone();
        let barrier = barrier.clone();
        tokio::spawn(async move {
            let mut request = req_with(seed, "spoofed-network", &[]);
            request.requested_ula = Some("fd5a:1f00:fffe::1".into());
            barrier.wait().await;
            coordinator
                .register_authenticated(request, Some(token), None)
                .await
        })
    };
    let first = register(31, "first-token");
    let second = register(32, "second-token");
    barrier.wait().await;
    publish_entered.wait().await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(
        !first.is_finished() && !second.is_finished(),
        "the second register crossed publish/apply while the first reservation was pending"
    );
    publish_release.wait().await;
    let outcomes = [first.await.unwrap(), second.await.unwrap()];

    assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|result| matches!(result, Err(CoordinatorError::UlaConflict(_))))
            .count(),
        1
    );
    assert_eq!(coordinator.snapshot().len(), 1);
}

#[tokio::test]
async fn capability_for_fixed_ula_one_rejects_fixed_ula_two() {
    let server = MockServer::start().await;
    fixed_ula_claims(&server, &["fd5a:1f00:fffe::1"], "store-system").await;
    let c = coordinator_with_validator(AuthValidator::new(server.uri()).unwrap());
    let mut req = req_with(22, "store-system", &[]);
    req.requested_ula = Some("fd5a:1f00:fffe::2".into());

    let error = c
        .register_authenticated(req, Some("token-for-one"), None)
        .await
        .expect_err("capability must be exact");
    assert!(matches!(error, CoordinatorError::Unauthorized(_)));
}

#[tokio::test]
async fn self_advertised_infra_or_forge_tags_never_authorize_fixed_ula() {
    let server = MockServer::start().await;
    fixed_ula_claims(&server, &[], "store-system").await;
    let c = coordinator_with_validator(AuthValidator::new(server.uri()).unwrap());
    let mut req = req_with(23, "store-system", &["infra", "forge"]);
    req.requested_ula = Some("fd5a:1f00:fffe::1".into());

    let error = c
        .register_authenticated(req, Some("no-capability"), None)
        .await
        .expect_err("self tags must not grant fixed ULA");
    assert!(matches!(error, CoordinatorError::Unauthorized(_)));
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

/// Authenticated network RE-HOME: a same-pubkey re-register whose validated
/// claims name a DIFFERENT network moves the peer — its `network`, `ula` (into
/// the new network's slot), and `tags` are all reconciled to the new claims.
/// This is the dedik system→tenant retag: one wireguard identity, a fresh join
/// token bound to a new network. A subsequent same-network re-register is then
/// STABLE (no ULA thrash back to the old sticky address the joiner keeps
/// re-requesting).
#[tokio::test]
async fn re_register_rehomes_peer_to_new_network_from_claims() {
    use wiremock::matchers::body_string_contains;

    let server = MockServer::start().await;
    // Two token-keyed validate responses on the same auth endpoint so the two
    // registers resolve to DIFFERENT networks deterministically.
    Mock::given(method("POST"))
        .and(path("/v1/validate"))
        .and(body_string_contains("tok-alpha"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "valid": true,
            "subject": "dedik",
            "network": "alpha",
            "tags": ["tag:net-alpha"],
            "kind": "join",
            "exp": 1_900_000_000_i64,
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/validate"))
        .and(body_string_contains("tok-beta"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "valid": true,
            "subject": "dedik",
            "network": "beta",
            "tags": ["tag:net-beta", "tag:deploy-beta"],
            "kind": "join",
            "exp": 1_900_000_000_i64,
        })))
        .mount(&server)
        .await;
    let c = coordinator_with_validator(AuthValidator::new(server.uri()).unwrap());

    // First join: network alpha. The request self-asserts junk that the claims
    // override; `requested_ula` stays None so it lands on an idx-based ULA in
    // alpha's slot.
    let (first, o1) = c
        .register_authenticated(
            req_with(11, "junk", &["tag:spoof"]),
            Some("tok-alpha"),
            None,
        )
        .await
        .expect("first join");
    assert_eq!(o1, RegisterOutcome::Created);
    assert_eq!(first.network, "alpha");
    assert_eq!(first.tags, vec!["tag:net-alpha".to_owned()]);

    // Re-tag: SAME pubkey (seed 11), a beta-network token. The peer is re-homed.
    // Its request STILL carries the alpha sticky ULA — proving the re-home
    // ignores `requested_ula` and allocates fresh in beta's slot.
    let mut retagged = req_with(11, "junk", &["tag:spoof"]);
    retagged.requested_ula = Some(first.ula.to_string());
    let (second, o2) = c
        .register_authenticated(retagged, Some("tok-beta"), None)
        .await
        .expect("re-home");
    assert_eq!(
        o2,
        RegisterOutcome::Existed,
        "same pubkey → still a re-register"
    );
    assert_eq!(
        first.peer_id, second.peer_id,
        "identity (peer_id) is preserved"
    );
    assert_eq!(
        second.network, "beta",
        "network reconciled to the new claims"
    );
    assert_eq!(
        second.tags,
        vec!["tag:net-beta".to_owned(), "tag:deploy-beta".to_owned()],
        "tags replaced wholesale — the alpha tag is dropped",
    );
    assert_ne!(
        first.ula, second.ula,
        "a re-home allocates a fresh ULA in the new network's slot",
    );
    assert_ne!(
        first.ula.segments()[2],
        second.ula.segments()[2],
        "the ULA moved into a different network slot",
    );

    // Stability: a third same-pubkey re-register on the SAME (beta) network must
    // NOT move the ULA again — even though the joiner keeps re-requesting its old
    // alpha sticky address. This is what stops a post-retag restart from thrashing.
    let mut again = req_with(11, "junk", &["tag:spoof"]);
    again.requested_ula = Some(first.ula.to_string());
    let (third, o3) = c
        .register_authenticated(again, Some("tok-beta"), None)
        .await
        .expect("steady re-register");
    assert_eq!(o3, RegisterOutcome::Existed);
    assert_eq!(third.network, "beta");
    assert_eq!(
        third.ula, second.ula,
        "same-network re-register is ULA-stable"
    );
}
