//! Roster-state-machine tests for [`Coordinator`].
//!
//! Covers register / heartbeat / deregister, the Stage 2 hole-punch
//! pairing wiring, reflexive endpoint reflection, per-app-ULA routing,
//! per-app-runner peer metadata, and the `requested_ula` honour path.
//! JWT join-token auth lives in the sibling [`super::jwt_tests`] module.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use super::*;
use crate::http::api::RegisterRequest;
use crate::http::sse::PeerEvent;
use crate::publisher::NoopPublisher;
use base64::Engine as _;
use std::net::SocketAddr;

fn pubkey(seed: u8) -> String {
    let bytes = [seed; 32];
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn coordinator() -> Coordinator {
    Coordinator::new(Arc::new(NoopPublisher), Duration::from_secs(60))
}

fn req(seed: u8, name: &str) -> RegisterRequest {
    RegisterRequest {
        wg_public_key: pubkey(seed),
        listen_endpoint: Some("127.0.0.1:51820".into()),
        wg_listen_port: Some(51820),
        display_name: name.into(),
        network: String::new(),
        tags: vec!["dev-machine".into()],
        hosted_app_ulas: vec![],
        kind: "peer".into(),
        parent: None,
        app_uuid: None,
        requested_ula: None,
        software_version: None,
    }
}

#[tokio::test]
async fn register_assigns_sequential_ulas() {
    let c = coordinator();
    let (p1, o1) = c.register(req(1, "alice")).await.expect("register 1");
    let (p2, o2) = c.register(req(2, "bob")).await.expect("register 2");
    assert_eq!(o1, RegisterOutcome::Created);
    assert_eq!(o2, RegisterOutcome::Created);
    assert_eq!(p1.peer_index, 1);
    assert_eq!(p2.peer_index, 2);
    assert_ne!(p1.peer_id, p2.peer_id);
    assert_ne!(p1.ula, p2.ula);
}

#[tokio::test]
async fn re_register_same_pubkey_is_idempotent() {
    let c = coordinator();
    let (first, o1) = c.register(req(7, "alice")).await.expect("first");
    let (second, o2) = c
        .register(RegisterRequest {
            display_name: "alice-renamed".into(),
            ..req(7, "ignored")
        })
        .await
        .expect("re-register");
    assert_eq!(o1, RegisterOutcome::Created);
    assert_eq!(o2, RegisterOutcome::Existed);
    assert_eq!(first.peer_id, second.peer_id);
    assert_eq!(first.ula, second.ula);
    assert_eq!(second.display_name, "alice-renamed");
    // Only one ULA index issued, despite two register calls.
    assert_eq!(c.snapshot().len(), 1);
}

#[tokio::test]
async fn heartbeat_updates_only_known_peers() {
    let c = coordinator();
    let (entry, _) = c.register(req(3, "carol")).await.expect("register");
    let updated = c
        .heartbeat(
            entry.peer_id,
            "203.0.113.1:51820".into(),
            Some(51820),
            vec![],
            None,
        )
        .await
        .expect("heartbeat");
    assert_eq!(updated.peer_id, entry.peer_id);

    let bogus = Uuid::now_v7();
    let err = c
        .heartbeat(bogus, "ignored".into(), None, vec![], None)
        .await
        .expect_err("unknown peer");
    assert!(matches!(err, CoordinatorError::UnknownPeer(_)));
}

#[tokio::test]
async fn deregister_is_idempotent() {
    let c = coordinator();
    let (entry, _) = c.register(req(4, "dave")).await.expect("register");
    assert!(c.deregister(entry.peer_id, "test").await);
    // Second call returns false, no panic, no double-publish.
    assert!(!c.deregister(entry.peer_id, "test").await);
    // After deregister the by_pubkey index is also clear, so the
    // same pubkey can register fresh and earn a new peer_id.
    let (replacement, outcome) = c
        .register(req(4, "dave-prime"))
        .await
        .expect("register again");
    assert_ne!(replacement.peer_id, entry.peer_id);
    assert_eq!(outcome, RegisterOutcome::Created);
}

#[tokio::test]
async fn snapshot_is_ordered_by_peer_index() {
    let c = coordinator();
    let _ = c.register(req(10, "p10")).await.expect("ok");
    let _ = c.register(req(11, "p11")).await.expect("ok");
    let _ = c.register(req(12, "p12")).await.expect("ok");
    let snap = c.snapshot();
    let names: Vec<_> = snap.iter().map(|p| p.display_name.clone()).collect();
    assert_eq!(names, vec!["p10".to_string(), "p11".into(), "p12".into()]);
}

#[tokio::test]
async fn invalid_pubkey_length_is_rejected() {
    let c = coordinator();
    let too_short = base64::engine::general_purpose::STANDARD.encode([0u8; 16]);
    let err = c
        .register(RegisterRequest {
            wg_public_key: too_short,
            listen_endpoint: None,
            wg_listen_port: None,
            display_name: "short".into(),
            network: String::new(),
            tags: vec![],
            hosted_app_ulas: vec![],
            kind: "peer".into(),
            parent: None,
            app_uuid: None,
            requested_ula: None,
            software_version: None,
        })
        .await
        .expect_err("invalid pubkey");
    assert!(matches!(err, CoordinatorError::InvalidPubkey(16)));
}

#[tokio::test]
async fn stale_peers_returns_only_timed_out_entries() {
    let c = Coordinator::new(Arc::new(NoopPublisher), Duration::from_millis(50));
    let (a, _) = c.register(req(20, "a")).await.expect("ok");
    let _ = c.register(req(21, "b")).await.expect("ok");
    // Backdate `a` past the timeout.
    {
        let mut e = c.inner.roster.get_mut(&a.peer_id).expect("entry");
        e.last_heartbeat = Instant::now()
            .checked_sub(Duration::from_millis(500))
            .expect("instant arithmetic");
    }
    let stale = c.stale_peers(Instant::now());
    assert_eq!(stale, vec![a.peer_id]);
}

// -----------------------------------------------------------------
// Stage 2 skeleton — hole punch initiation tests.
//
// These verify the coordinator's heartbeat hook calls the holepunch
// emit logic at the right times. Detailed semantics of the emit
// function itself are covered in `crate::nat::holepunch::tests` —
// here we focus on the wiring: «does heartbeat actually trigger it
// when both peers have external addrs, and stay quiet otherwise».
// -----------------------------------------------------------------

use crate::publisher::EventPublisher;
use crate::roster::events::HolePunchInitiate;
use async_trait::async_trait;
use parking_lot::Mutex;
use std::sync::Arc as StdArc;

/// A single captured publish: `(event_type, segment, payload)`.
type CapturedEvent = (String, String, Vec<u8>);

/// Test-only publisher that records every `(event_type, segment,
/// payload)` tuple so assertions can inspect what the coordinator
/// emitted. Cheap to clone — wraps a `Mutex<Vec<...>>` in `Arc`.
#[derive(Clone, Default)]
struct CapturingPublisher {
    events: StdArc<Mutex<Vec<CapturedEvent>>>,
}

impl CapturingPublisher {
    fn new() -> Self {
        Self::default()
    }

    fn events(&self) -> Vec<CapturedEvent> {
        self.events.lock().clone()
    }

    fn count_by_type(&self, ty: &str) -> usize {
        self.events
            .lock()
            .iter()
            .filter(|(event_type, _, _)| event_type == ty)
            .count()
    }
}

#[async_trait]
impl EventPublisher for CapturingPublisher {
    async fn publish(
        &self,
        event_type: &str,
        segment: &str,
        payload: Vec<u8>,
    ) -> Result<(), String> {
        self.events
            .lock()
            .push((event_type.to_owned(), segment.to_owned(), payload));
        Ok(())
    }
}

fn coordinator_with(publisher: StdArc<CapturingPublisher>) -> Coordinator {
    Coordinator::new(publisher, Duration::from_secs(60))
}

#[tokio::test]
async fn heartbeat_emits_holepunch_pair_when_both_peers_have_external() {
    let pub_ = StdArc::new(CapturingPublisher::new());
    let c = coordinator_with(pub_.clone());
    let (alice, _) = c.register(req(40, "alice")).await.expect("a");
    let (bob, _) = c.register(req(41, "bob")).await.expect("b");

    // First heartbeats — neither peer has been seen yet, so each
    // populates its own observed_external. After the first heartbeat
    // from each, both peers have non-empty external addrs.
    c.heartbeat(
        alice.peer_id,
        "203.0.113.10:11111".into(),
        Some(51820),
        vec![],
        None,
    )
    .await
    .expect("a hb1");
    // Only alice has external so far — no holepunch event yet.
    assert_eq!(
        pub_.count_by_type("holepunch_initiate"),
        0,
        "should not emit until both peers have observed_external"
    );

    c.heartbeat(
        bob.peer_id,
        "198.51.100.20:22222".into(),
        Some(51820),
        vec![],
        None,
    )
    .await
    .expect("b hb1");

    // Now both have external addrs → exactly one pair = 2 events.
    let punch_events = pub_.count_by_type("holepunch_initiate");
    assert_eq!(
        punch_events, 2,
        "expected exactly 2 HolePunchInitiate events (one per peer)"
    );

    // Decode and verify field values.
    let events: Vec<HolePunchInitiate> = pub_
        .events()
        .into_iter()
        .filter(|(t, _, _)| t == "holepunch_initiate")
        .map(|(_, _, bytes)| serde_json::from_slice::<HolePunchInitiate>(&bytes).expect("decode"))
        .collect();
    let from_alice = events
        .iter()
        .find(|e| e.initiator_peer_id == alice.peer_id.to_string())
        .expect("event from alice");
    assert_eq!(from_alice.target_peer_id, bob.peer_id.to_string());
    // Target is bob's REFLEXIVE WG endpoint (observed-ip:wg-port), not the
    // raw heartbeat TCP source (:22222).
    assert_eq!(from_alice.target_external_endpoint, "198.51.100.20:51820");
    let from_bob = events
        .iter()
        .find(|e| e.initiator_peer_id == bob.peer_id.to_string())
        .expect("event from bob");
    assert_eq!(from_bob.target_peer_id, alice.peer_id.to_string());
    assert_eq!(from_bob.target_external_endpoint, "203.0.113.10:51820");

    // Sanity: the tracker should know about this pair now.
    assert_eq!(c.punch_tracker().len(), 1);

    // Another heartbeat from alice should NOT re-emit (dedup).
    c.heartbeat(
        alice.peer_id,
        "203.0.113.10:11111".into(),
        Some(51820),
        vec![],
        None,
    )
    .await
    .expect("a hb2");
    assert_eq!(
        pub_.count_by_type("holepunch_initiate"),
        2,
        "dedup must prevent re-emit on subsequent heartbeats"
    );
}

/// The hole-punch pair must reach live SSE subscribers over the
/// broadcast channel — not just the event-log publisher. Without this
/// the joiner (which consumes the SSE stream) never learns to punch.
#[tokio::test]
async fn heartbeat_broadcasts_holepunch_pair_to_sse_subscribers() {
    let pub_ = StdArc::new(CapturingPublisher::new());
    let c = coordinator_with(pub_.clone());
    let (alice, _) = c.register(req(70, "alice")).await.expect("a");
    let (bob, _) = c.register(req(71, "bob")).await.expect("b");

    // Subscribe AFTER register so the channel only carries the
    // heartbeat-time frames we care about.
    let mut rx = c.broadcaster().subscribe();
    c.heartbeat(
        alice.peer_id,
        "203.0.113.70:11111".into(),
        Some(51820),
        vec![],
        None,
    )
    .await
    .expect("a hb");
    c.heartbeat(
        bob.peer_id,
        "198.51.100.71:22222".into(),
        Some(51820),
        vec![],
        None,
    )
    .await
    .expect("b hb");

    // Drain the channel and keep only the hole-punch frames.
    let mut punches = Vec::new();
    while let Ok(ev) = rx.try_recv() {
        if let PeerEvent::HolePunch(hp) = ev {
            punches.push(hp);
        }
    }
    assert_eq!(
        punches.len(),
        2,
        "expected the hole-punch pair on the broadcast channel"
    );
    // Each event points the initiator at the OTHER peer's REFLEXIVE WG
    // endpoint (observed-ip:wg-port), not the raw heartbeat TCP source.
    assert!(
        punches
            .iter()
            .any(|p| p.target_external_endpoint == "203.0.113.70:51820")
    );
    assert!(
        punches
            .iter()
            .any(|p| p.target_external_endpoint == "198.51.100.71:51820")
    );
}

#[tokio::test]
async fn heartbeat_does_not_emit_when_one_peer_lacks_external() {
    let pub_ = StdArc::new(CapturingPublisher::new());
    let c = coordinator_with(pub_.clone());
    let (alice, _) = c.register(req(50, "alice")).await.expect("a");
    let (_bob, _) = c.register(req(51, "bob")).await.expect("b");

    // Alice heartbeats with a known external — bob never heartbeats,
    // so its observed_external stays empty.
    c.heartbeat(alice.peer_id, "203.0.113.30:33333".into(), None, vec![], None)
        .await
        .expect("a hb");

    assert_eq!(
        pub_.count_by_type("holepunch_initiate"),
        0,
        "must not emit when target peer's external is unknown"
    );
    assert!(c.punch_tracker().is_empty());
}

#[tokio::test]
async fn heartbeat_with_empty_external_skips_emit() {
    let pub_ = StdArc::new(CapturingPublisher::new());
    let c = coordinator_with(pub_.clone());
    let (alice, _) = c.register(req(60, "alice")).await.expect("a");
    let (bob, _) = c.register(req(61, "bob")).await.expect("b");

    // Alice gets an external on heartbeat 1.
    c.heartbeat(alice.peer_id, "203.0.113.50:44444".into(), None, vec![], None)
        .await
        .expect("a hb");

    // Bob heartbeats but ConnectInfo wasn't captured — empty string.
    // This mirrors the test-router path that drives via Router::call
    // without the make_service wrapper.
    c.heartbeat(bob.peer_id, String::new(), None, vec![], None)
        .await
        .expect("b hb empty external");

    assert_eq!(
        pub_.count_by_type("holepunch_initiate"),
        0,
        "empty observed_external must not trigger an emit"
    );
}

// -----------------------------------------------------------------
// Stage 2 — reflexive endpoint reflection (the NAT-traversal path).
//
// These drive `register_authenticated` / `heartbeat` with a synthetic
// PUBLIC observed `SocketAddr` (what the HTTP handler reads off
// `ConnectInfo` in production) and assert the coordinator STORES the
// reflexive `<observed-public-ip>:<wg-port>` endpoint, not the
// joiner's loopback self-report. The pure decision table is covered in
// `crate::nat::reflexive::tests`; this is the roster-integration wiring.
// -----------------------------------------------------------------

/// A joiner behind NAT self-reports `127.0.0.1:<port>` but the
/// coordinator observes a PUBLIC source IP. The stored
/// `listen_endpoint` must be the reflexive `<public-ip>:<wg-port>`.
#[tokio::test]
async fn register_stores_reflexive_endpoint_for_natted_peer() {
    let c = coordinator();
    // req() self-reports 127.0.0.1:51820 with wg_listen_port 51820.
    let observed: SocketAddr = "203.0.113.7:34812".parse().expect("addr");
    let (entry, outcome) = c
        .register_authenticated(req(1, "natted"), None, Some(observed))
        .await
        .expect("register");
    assert_eq!(outcome, RegisterOutcome::Created);
    // Reflexive: observed public IP + REPORTED wg port (51820), NOT the
    // HTTP source port 34812 and NOT the loopback self-report.
    assert_eq!(entry.listen_endpoint.as_deref(), Some("203.0.113.7:51820"));
    // The observed external (full sockaddr) is seeded for hole-punch.
    assert_eq!(entry.observed_external, "203.0.113.7:34812");
    // And the stored roster entry agrees.
    let stored = c.snapshot();
    assert_eq!(
        stored[0].listen_endpoint.as_deref(),
        Some("203.0.113.7:51820")
    );
}

/// An explicit `--advertise-endpoint` pointing at a PUBLIC address must
/// survive — reflexive discovery must not clobber an operator override.
#[tokio::test]
async fn register_preserves_public_self_report_over_reflexive() {
    let c = coordinator();
    let req = RegisterRequest {
        wg_public_key: pubkey(2),
        listen_endpoint: Some("198.51.100.50:51820".into()), // explicit public advert
        wg_listen_port: Some(51820),
        display_name: "advertised".into(),
        network: String::new(),
        tags: vec!["dev-machine".into()],
        hosted_app_ulas: vec![],
        kind: "peer".into(),
        parent: None,
        app_uuid: None,
        requested_ula: None,
        software_version: None,
    };
    let observed: SocketAddr = "203.0.113.7:34812".parse().expect("addr");
    let (entry, _) = c
        .register_authenticated(req, None, Some(observed))
        .await
        .expect("register");
    assert_eq!(
        entry.listen_endpoint.as_deref(),
        Some("198.51.100.50:51820"),
        "explicit public advertise-endpoint must win over reflexive"
    );
}

/// Same-host smoke test: coordinator observes a loopback / private
/// source (it's on the same machine), so there's nothing public to
/// advertise — the loopback self-report is kept verbatim. This is the
/// back-compat path that keeps local two-peer runs working.
#[tokio::test]
async fn register_keeps_loopback_when_observed_is_private() {
    let c = coordinator();
    let observed: SocketAddr = "127.0.0.1:55001".parse().expect("addr");
    let (entry, _) = c
        .register_authenticated(req(3, "local"), None, Some(observed))
        .await
        .expect("register");
    assert_eq!(entry.listen_endpoint.as_deref(), Some("127.0.0.1:51820"));
}

/// A heartbeat from a NEW public IP (NAT rebind / roaming) rolls the
/// stored reflexive endpoint over to the new IP, keeping the WG port.
#[tokio::test]
async fn heartbeat_rolls_reflexive_endpoint_over_on_ip_change() {
    let c = coordinator();
    let observed1: SocketAddr = "203.0.113.7:34812".parse().expect("addr");
    let (entry, _) = c
        .register_authenticated(req(4, "roamer"), None, Some(observed1))
        .await
        .expect("register");
    assert_eq!(entry.listen_endpoint.as_deref(), Some("203.0.113.7:51820"));

    // Heartbeat arrives from a different public IP — same WG port.
    let updated = c
        .heartbeat(
            entry.peer_id,
            "198.51.100.99:60000".into(),
            Some(51820),
            vec![],
            None,
        )
        .await
        .expect("heartbeat");
    assert_eq!(
        updated.listen_endpoint.as_deref(),
        Some("198.51.100.99:51820"),
        "reflexive endpoint must follow the peer's new public IP"
    );
}

/// A heartbeat must NOT clobber an explicit public advertise-endpoint:
/// the peer's stored public endpoint is fed back as the self-report and
/// preserved.
#[tokio::test]
async fn heartbeat_preserves_public_advertised_endpoint() {
    let c = coordinator();
    let req = RegisterRequest {
        wg_public_key: pubkey(5),
        listen_endpoint: Some("198.51.100.50:51820".into()),
        wg_listen_port: Some(51820),
        display_name: "advertised".into(),
        network: String::new(),
        tags: vec![],
        hosted_app_ulas: vec![],
        kind: "peer".into(),
        parent: None,
        app_uuid: None,
        requested_ula: None,
        software_version: None,
    };
    let observed: SocketAddr = "203.0.113.7:34812".parse().expect("addr");
    let (entry, _) = c
        .register_authenticated(req, None, Some(observed))
        .await
        .expect("register");
    // Heartbeat from a public IP that differs from the advertised one.
    let updated = c
        .heartbeat(
            entry.peer_id,
            "203.0.113.7:34900".into(),
            Some(51820),
            vec![],
            None,
        )
        .await
        .expect("heartbeat");
    assert_eq!(
        updated.listen_endpoint.as_deref(),
        Some("198.51.100.50:51820"),
        "explicit public advert must survive heartbeats"
    );
}

/// A peer whose stored endpoint is a non-reflexive LOOPBACK fallback
/// (e.g. registered before connect-info was available) must still be
/// able to roll over to a reflexive public endpoint on a heartbeat
/// that reveals a public source IP — loopback is a fallback, not a
/// sticky operator advertisement.
#[tokio::test]
async fn heartbeat_promotes_loopback_fallback_to_reflexive() {
    let c = coordinator();
    // Register with NO observed addr → loopback self-report kept,
    // endpoint_is_reflexive == false.
    let (entry, _) = c.register(req(8, "late")).await.expect("register");
    assert_eq!(entry.listen_endpoint.as_deref(), Some("127.0.0.1:51820"));
    assert!(!entry.endpoint_is_reflexive);
    // Heartbeat from a public IP → must promote to reflexive.
    let updated = c
        .heartbeat(
            entry.peer_id,
            "203.0.113.7:34812".into(),
            Some(51820),
            vec![],
            None,
        )
        .await
        .expect("heartbeat");
    assert_eq!(
        updated.listen_endpoint.as_deref(),
        Some("203.0.113.7:51820")
    );
    assert!(updated.endpoint_is_reflexive);
}

/// Re-register from behind NAT must refresh (not regress) the reflexive
/// endpoint: the idempotent re-register path stores the reflexive
/// endpoint, not the loopback self-report.
#[tokio::test]
async fn re_register_refreshes_reflexive_endpoint() {
    let c = coordinator();
    // First register with NO observed (e.g. early bring-up) → loopback.
    let (first, _) = c.register(req(6, "peer")).await.expect("first");
    assert_eq!(first.listen_endpoint.as_deref(), Some("127.0.0.1:51820"));
    // Re-register (same pubkey) WITH a public observed addr → reflexive.
    let observed: SocketAddr = "203.0.113.7:34812".parse().expect("addr");
    let (second, outcome) = c
        .register_authenticated(req(6, "peer"), None, Some(observed))
        .await
        .expect("re-register");
    assert_eq!(outcome, RegisterOutcome::Existed);
    assert_eq!(first.peer_id, second.peer_id);
    assert_eq!(second.listen_endpoint.as_deref(), Some("203.0.113.7:51820"));
}

// -----------------------------------------------------------------
// Per-app-ULA routing — the coordinator carries opaque hosted
// app-ULA /128s through register + heartbeat and advertises them to
// viewers exactly like the peer's own ULA. The coordinator stays
// app-agnostic: it never derives or validates an app-ULA, it just
// relays the set the peer declares. These tests pin the control-plane
// contract the joiner's app-route layer (Component 2) consumes.
// -----------------------------------------------------------------

/// A request that also declares a set of hosted app-ULAs.
fn req_hosting(seed: u8, name: &str, hosted: &[&str]) -> RegisterRequest {
    RegisterRequest {
        hosted_app_ulas: hosted.iter().map(|s| (*s).to_owned()).collect(),
        ..req(seed, name)
    }
}

/// Register must STORE the declared hosted app-ULAs and surface them
/// on the roster entry + the wire `PeerInfo` (snapshot), with the same
/// visibility as the peer's own ULA.
#[tokio::test]
async fn register_stores_and_advertises_hosted_app_ulas() {
    let c = coordinator();
    let app_a = "fd5a:1f02:dead:beef:cafe:0:0:1";
    let app_b = "fd5a:1f02:dead:beef:cafe:0:0:2";
    let (entry, outcome) = c
        .register(req_hosting(1, "supervisor", &[app_a, app_b]))
        .await
        .expect("register");
    assert_eq!(outcome, RegisterOutcome::Created);
    assert_eq!(
        entry.hosted_app_ulas,
        vec![app_a.to_owned(), app_b.to_owned()]
    );
    // The wire-facing snapshot carries them too (advertised to viewers).
    let snap = c.snapshot();
    assert_eq!(snap.len(), 1);
    assert_eq!(
        snap[0].hosted_app_ulas,
        vec![app_a.to_owned(), app_b.to_owned()]
    );
}

/// A heartbeat REPLACES the stored hosted set wholesale: a supervisor
/// re-sends its full hosted set each tick, so an added app appears and
/// a removed app disappears purely from the replace.
#[tokio::test]
async fn heartbeat_replaces_hosted_app_ula_set() {
    let c = coordinator();
    let app_a = "fd5a:1f02:dead:beef:cafe:0:0:1";
    let app_b = "fd5a:1f02:dead:beef:cafe:0:0:2";
    let (entry, _) = c
        .register(req_hosting(2, "supervisor", &[app_a]))
        .await
        .expect("register");
    assert_eq!(entry.hosted_app_ulas, vec![app_a.to_owned()]);

    // Heartbeat now advertises a DIFFERENT set: drop app_a, add app_b.
    let updated = c
        .heartbeat(
            entry.peer_id,
            "203.0.113.1:51820".into(),
            Some(51820),
            vec![app_b.to_owned()],
            None,
        )
        .await
        .expect("heartbeat");
    assert_eq!(
        updated.hosted_app_ulas,
        vec![app_b.to_owned()],
        "heartbeat must replace the stored hosted set wholesale"
    );

    // An empty heartbeat set clears everything (supervisor stopped all).
    let cleared = c
        .heartbeat(
            entry.peer_id,
            "203.0.113.1:51820".into(),
            Some(51820),
            vec![],
            None,
        )
        .await
        .expect("heartbeat clear");
    assert!(cleared.hosted_app_ulas.is_empty());
}

/// A heartbeat that CHANGES the hosted set must reach SSE subscribers
/// as an `Updated` frame carrying the new set — that is how a viewer
/// re-learns which apps a supervisor hosts (per-app-ULA routing).
#[tokio::test]
async fn heartbeat_broadcasts_updated_with_new_hosted_set() {
    let c = coordinator();
    let app_a = "fd5a:1f02:dead:beef:cafe:0:0:1";
    let (entry, _) = c.register(req(3, "supervisor")).await.expect("register");

    // Subscribe AFTER register so we only see heartbeat-time frames.
    let mut rx = c.broadcaster().subscribe();
    c.heartbeat(
        entry.peer_id,
        "203.0.113.1:51820".into(),
        Some(51820),
        vec![app_a.to_owned()],
        None,
    )
    .await
    .expect("heartbeat");

    // Drain the channel; find an Updated frame for this peer carrying
    // the new hosted set.
    let mut saw_hosted = false;
    while let Ok(ev) = rx.try_recv() {
        if let PeerEvent::Updated(info) = ev {
            if info.peer_id == entry.peer_id.to_string()
                && info.hosted_app_ulas == vec![app_a.to_owned()]
            {
                saw_hosted = true;
            }
        }
    }
    assert!(
        saw_hosted,
        "a changed hosted set must be broadcast as Updated with the new set"
    );
}

/// Re-register also refreshes the hosted set from the request, mirroring
/// the heartbeat replace semantics (so a restart that re-declares its
/// apps converges).
#[tokio::test]
async fn re_register_refreshes_hosted_app_ula_set() {
    let c = coordinator();
    let app_a = "fd5a:1f02:dead:beef:cafe:0:0:1";
    let app_b = "fd5a:1f02:dead:beef:cafe:0:0:2";
    let (first, o1) = c
        .register(req_hosting(4, "supervisor", &[app_a]))
        .await
        .expect("first");
    assert_eq!(o1, RegisterOutcome::Created);
    // Re-register (same pubkey/seed) with a different hosted set.
    let (second, o2) = c
        .register(req_hosting(4, "supervisor", &[app_b]))
        .await
        .expect("re-register");
    assert_eq!(o2, RegisterOutcome::Existed);
    assert_eq!(first.peer_id, second.peer_id);
    assert_eq!(second.hosted_app_ulas, vec![app_b.to_owned()]);
}

/// An older joiner that omits `hosted_app_ulas` (serde default) is
/// treated as hosting no apps — the field defaults to empty and never
/// errors. This guards the back-compat contract.
#[tokio::test]
async fn register_defaults_hosted_app_ulas_to_empty() {
    let c = coordinator();
    let (entry, _) = c.register(req(5, "legacy")).await.expect("register");
    assert!(entry.hosted_app_ulas.is_empty());
}

// -----------------------------------------------------------------
// Per-app-runner peer metadata (kind / parent / app_uuid).
//
// A runner peer joins with kind="runner", parent=<supervisor ULA>,
// app_uuid=<uuid>. A plain supervisor peer joins without those fields
// and gets the defaults. Both round-trip through the roster snapshot
// (GET /v1/mesh/peers → PeerInfo). This is Task 0.1 of the per-app-
// runner architecture refactor.
// -----------------------------------------------------------------

fn req_runner(seed: u8, name: &str, parent: &str, app_uuid: &str) -> RegisterRequest {
    RegisterRequest {
        kind: "runner".into(),
        parent: Some(parent.into()),
        app_uuid: Some(app_uuid.into()),
        ..req(seed, name)
    }
}

/// A peer registered with kind="runner", parent, and `app_uuid` must
/// appear in the roster snapshot with those exact values.
#[tokio::test]
async fn runner_peer_metadata_round_trips_through_roster() {
    let c = coordinator();
    let parent_ula = "fd5a:1f00:0:1::1";
    let app_id = "01910f10-0000-7000-8000-000000000001";
    let (entry, outcome) = c
        .register(req_runner(80, "runner-1", parent_ula, app_id))
        .await
        .expect("register");
    assert_eq!(outcome, RegisterOutcome::Created);
    // PeerEntry carries the fields.
    assert_eq!(entry.kind, "runner");
    assert_eq!(entry.parent.as_deref(), Some(parent_ula));
    assert_eq!(entry.app_uuid.as_deref(), Some(app_id));
    // PeerInfo (the wire/roster snapshot) must carry them too.
    let snap = c.snapshot();
    assert_eq!(snap.len(), 1);
    assert_eq!(snap[0].kind, "runner");
    assert_eq!(snap[0].parent.as_deref(), Some(parent_ula));
    assert_eq!(snap[0].app_uuid.as_deref(), Some(app_id));
}

/// A plain peer (no `kind/parent/app_uuid` in request) defaults to
/// kind="peer" and absent `parent/app_uuid` in the roster.
#[tokio::test]
async fn plain_peer_defaults_to_kind_peer_with_no_parent_or_app_uuid() {
    let c = coordinator();
    let (entry, _) = c.register(req(81, "plain")).await.expect("register");
    assert_eq!(entry.kind, "peer");
    assert!(entry.parent.is_none());
    assert!(entry.app_uuid.is_none());
    // Wire snapshot agrees.
    let snap = c.snapshot();
    assert_eq!(snap[0].kind, "peer");
    assert!(snap[0].parent.is_none());
    assert!(snap[0].app_uuid.is_none());
}

// -----------------------------------------------------------------
// Task 0.2 — requested_ula: peers can request a specific ULA instead
// of the idx-derived one. The coordinator honours it if it is
// well-formed AND unclaimed (or claimed by the SAME peer on re-join).
// A DIFFERENT peer trying to claim an already-held ULA is rejected.
// -----------------------------------------------------------------

fn req_with_requested_ula(seed: u8, name: &str, requested_ula: &str) -> RegisterRequest {
    RegisterRequest {
        requested_ula: Some(requested_ula.into()),
        ..req(seed, name)
    }
}

/// A peer that supplies a valid, unclaimed `requested_ula` receives
/// exactly that address — not an idx-derived one.
#[tokio::test]
async fn register_honours_requested_ula_when_unclaimed() {
    let c = coordinator();
    let want = "fd5a:1f02:aaaa::1";
    let (entry, outcome) = c
        .register(req_with_requested_ula(90, "runner-a", want))
        .await
        .expect("register");
    assert_eq!(outcome, RegisterOutcome::Created);
    assert_eq!(
        entry.ula.to_string(),
        want,
        "assigned ULA must be exactly the requested one"
    );
    // The snapshot must also reflect it.
    let snap = c.snapshot();
    assert_eq!(snap.len(), 1);
    assert_eq!(snap[0].ula, want);
}

/// A second, DIFFERENT peer requesting the same ULA that a prior peer
/// already holds must be rejected with a clear conflict error.
#[tokio::test]
async fn register_rejects_requested_ula_claimed_by_different_peer() {
    let c = coordinator();
    let want = "fd5a:1f02:bbbb::1";
    // Peer A claims it first.
    c.register(req_with_requested_ula(91, "peer-a", want))
        .await
        .expect("peer-a register");
    // Peer B (different pubkey / identity) tries the same ULA.
    let err = c
        .register(req_with_requested_ula(92, "peer-b", want))
        .await
        .expect_err("peer-b must be rejected");
    assert!(
        matches!(err, CoordinatorError::UlaConflict(_)),
        "expected UlaConflict, got {err:?}"
    );
    // Only one peer in the roster.
    assert_eq!(c.snapshot().len(), 1);
}

/// The SAME peer re-registering with its own previously-assigned ULA
/// (sticky identity on restart) must succeed — outcome Existed, same
/// `peer_id`, same ULA.
#[tokio::test]
async fn register_allows_same_peer_to_reclaim_its_own_ula() {
    let c = coordinator();
    let want = "fd5a:1f02:cccc::1";
    let (first, o1) = c
        .register(req_with_requested_ula(93, "runner-c", want))
        .await
        .expect("first register");
    assert_eq!(o1, RegisterOutcome::Created);
    assert_eq!(first.ula.to_string(), want);

    // Same pubkey (seed 93) re-registers, requesting the same ULA.
    let (second, o2) = c
        .register(req_with_requested_ula(93, "runner-c-restart", want))
        .await
        .expect("re-register");
    assert_eq!(o2, RegisterOutcome::Existed);
    assert_eq!(first.peer_id, second.peer_id, "peer_id must be stable");
    assert_eq!(
        second.ula.to_string(),
        want,
        "re-registered peer keeps its ULA"
    );
}

/// When no `requested_ula` is supplied, the coordinator falls back to
/// the original idx-based assignment (regression guard).
#[tokio::test]
async fn register_fallback_to_idx_when_no_requested_ula() {
    let c = coordinator();
    let (p1, _) = c.register(req(94, "plain-a")).await.expect("ok");
    let (p2, _) = c.register(req(95, "plain-b")).await.expect("ok");
    // Both get idx-derived addresses (sequential within the default network).
    assert_ne!(p1.ula, p2.ula);
    assert_eq!(p1.peer_index, 1);
    assert_eq!(p2.peer_index, 2);
}

/// SV-1: a register carrying `software_version` stores it on the entry,
/// surfaces it in the snapshot, and broadcasts it on `peer_added`.
/// A subsequent heartbeat with a new value updates the stored version
/// and re-broadcasts it on `peer_updated`. `None` on heartbeat leaves
/// the stored value untouched (never a downgrade).
#[tokio::test]
async fn software_version_is_stored_and_broadcast() {
    let c = coordinator();
    let mut rx = c.broadcaster().subscribe();

    let mut r = req(200, "versioned");
    r.software_version = Some("v1.4.0".to_owned());
    let (entry, _) = c.register(r).await.expect("register");
    assert_eq!(entry.software_version.as_deref(), Some("v1.4.0"));
    assert_eq!(
        c.snapshot()[0].software_version.as_deref(),
        Some("v1.4.0"),
        "snapshot must carry the version"
    );
    match rx.try_recv().expect("peer_added broadcast") {
        PeerEvent::Added(info) => {
            assert_eq!(info.software_version.as_deref(), Some("v1.4.0"));
        }
        other => panic!("expected Added, got {other:?}"),
    }

    // Heartbeat reports a newer version → stored value updates + rebroadcast.
    let after = c
        .heartbeat(
            entry.peer_id,
            String::new(),
            Some(51820),
            vec![],
            Some("v1.5.0".to_owned()),
        )
        .await
        .expect("heartbeat");
    assert_eq!(after.software_version.as_deref(), Some("v1.5.0"));
    match rx.try_recv().expect("peer_updated broadcast") {
        PeerEvent::Updated(info) => {
            assert_eq!(info.software_version.as_deref(), Some("v1.5.0"));
        }
        other => panic!("expected Updated, got {other:?}"),
    }

    // A heartbeat that omits the version (None) must NOT wipe it.
    let kept = c
        .heartbeat(entry.peer_id, String::new(), Some(51820), vec![], None)
        .await
        .expect("heartbeat none");
    assert_eq!(
        kept.software_version.as_deref(),
        Some("v1.5.0"),
        "None on heartbeat must not clear the stored version"
    );
}
