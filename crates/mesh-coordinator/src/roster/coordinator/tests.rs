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
        relay_only: false,
    }
}

/// A passive registration: NO self-reported `listen_endpoint`. This is what
/// a real NAT-bound joiner sends — it omits `listen_endpoint` entirely and
/// relies on the coordinator to synthesize a reflexive endpoint from the
/// observed public source IP + the reported `wg_listen_port` (see
/// `mesh-joiner::joiner`, which only sends a `listen_endpoint` when the
/// operator passes an explicit `--advertise-endpoint`). Tests that exercise
/// the reflexive-discovery / hole-punch path MUST use this, not `req()` —
/// a self-reported address (even loopback) is now treated as an explicit
/// operator advertise and is honored verbatim + sticky.
fn passive_req(seed: u8, name: &str) -> RegisterRequest {
    RegisterRequest {
        listen_endpoint: None,
        ..req(seed, name)
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
            false,
        )
        .await
        .expect("heartbeat");
    assert_eq!(updated.peer_id, entry.peer_id);

    let bogus = Uuid::now_v7();
    let err = c
        .heartbeat(bogus, "ignored".into(), None, vec![], None, false)
        .await
        .expect_err("unknown peer");
    assert!(matches!(err, CoordinatorError::UnknownPeer(_)));
}

#[tokio::test]
async fn record_peer_paths_replaces_reporter_edges() {
    use crate::http::api::PeerPathDto;
    let c = coordinator();
    let (reporter, _) = c.register(req(20, "reporter")).await.expect("register R");
    let (target, _) = c.register(req(21, "target")).await.expect("register P");

    // No edges reported yet → unknown.
    assert_eq!(c.edge(reporter.peer_id, target.peer_id), None);

    // Reporter reports a DIRECT edge to the target.
    c.record_peer_paths(
        reporter.peer_id,
        &[PeerPathDto {
            peer_id: target.peer_id.to_string(),
            direct: true,
            last_rx_age_ms: 42,
        }],
    );
    assert_eq!(
        c.edge(reporter.peer_id, target.peer_id),
        Some((true, 42)),
        "stored edge reflects the reported direct path + age"
    );

    // A later heartbeat with an EMPTY set replaces (clears) the edges —
    // wholesale-replace, same as hosted_app_ulas.
    c.record_peer_paths(reporter.peer_id, &[]);
    assert_eq!(
        c.edge(reporter.peer_id, target.peer_id),
        None,
        "wholesale replace clears a dropped edge"
    );

    // Recording for an unknown reporter is a no-op (no panic).
    c.record_peer_paths(
        Uuid::now_v7(),
        &[PeerPathDto {
            peer_id: target.peer_id.to_string(),
            direct: false,
            last_rx_age_ms: 0,
        }],
    );
}

#[tokio::test]
async fn self_connectivity_is_per_machine_self_view() {
    use crate::http::api::PeerPathDto;
    let c = coordinator();
    // M_direct reports at least one direct edge → "direct".
    let (m_direct, _) = c.register(req(40, "Mdirect")).await.expect("register Md");
    // M_relay reports only relay edges → "relay".
    let (m_relay, _) = c.register(req(41, "Mrelay")).await.expect("register Mr");
    // M_none reports nothing → None (unknown).
    let (m_none, _) = c.register(req(42, "Mnone")).await.expect("register Mn");
    // A peer to point edges at; its own edges are irrelevant to the others.
    let (target, _) = c.register(req(43, "target")).await.expect("register T");

    c.record_peer_paths(
        m_direct.peer_id,
        &[
            PeerPathDto {
                peer_id: target.peer_id.to_string(),
                direct: false,
                last_rx_age_ms: 100,
            },
            PeerPathDto {
                // A single direct edge anywhere flips the self-view to "direct".
                peer_id: m_relay.peer_id.to_string(),
                direct: true,
                last_rx_age_ms: 3,
            },
        ],
    );
    c.record_peer_paths(
        m_relay.peer_id,
        &[PeerPathDto {
            peer_id: target.peer_id.to_string(),
            direct: false,
            last_rx_age_ms: 250,
        }],
    );
    // m_none reports no edges at all.

    assert_eq!(
        c.self_connectivity(m_direct.peer_id).as_deref(),
        Some("direct"),
        "a peer with any direct edge sees itself as direct"
    );
    assert_eq!(
        c.self_connectivity(m_relay.peer_id).as_deref(),
        Some("relay"),
        "a peer with only relay edges sees itself as relay"
    );
    assert_eq!(
        c.self_connectivity(m_none.peer_id),
        None,
        "a peer that reported no edges is unknown"
    );
    assert_eq!(
        c.self_connectivity(Uuid::now_v7()),
        None,
        "an unknown peer is unknown"
    );
}

#[tokio::test]
async fn snapshot_stamps_connectivity_from_each_peers_own_paths() {
    use crate::http::api::PeerPathDto;
    let c = coordinator();
    // A reports a direct edge → A's own pill is "direct".
    let (a, _) = c.register(req(30, "A")).await.expect("register A");
    // B reports only a relay edge → B's own pill is "relay".
    let (b, _) = c.register(req(31, "B")).await.expect("register B");
    // C reports nothing → C's pill is unknown (None).
    let (cc, _) = c.register(req(32, "C")).await.expect("register C");

    c.record_peer_paths(
        a.peer_id,
        &[PeerPathDto {
            peer_id: b.peer_id.to_string(),
            direct: true,
            last_rx_age_ms: 5,
        }],
    );
    c.record_peer_paths(
        b.peer_id,
        &[PeerPathDto {
            peer_id: a.peer_id.to_string(),
            direct: false,
            last_rx_age_ms: 200,
        }],
    );

    // Default snapshot (no vantage) now stamps each peer from its OWN paths.
    let snap = c.snapshot();
    let conn = |id: Uuid| {
        snap.iter()
            .find(|p| p.peer_id == id.to_string())
            .and_then(|p| p.connectivity.clone())
    };
    assert_eq!(
        conn(a.peer_id).as_deref(),
        Some("direct"),
        "A reported a direct edge → A's pill is direct"
    );
    assert_eq!(
        conn(b.peer_id).as_deref(),
        Some("relay"),
        "B reported only relay → B's pill is relay"
    );
    assert_eq!(conn(cc.peer_id), None, "C reported nothing → unknown");
}

#[tokio::test]
async fn snapshot_with_vantage_overrides_with_single_vantage_view() {
    use crate::http::api::PeerPathDto;
    let c = coordinator();
    let (reporter, _) = c.register(req(33, "R")).await.expect("register R");
    let (direct_m, _) = c.register(req(34, "Mdirect")).await.expect("register Md");
    let (relay_m, _) = c.register(req(35, "Mrelay")).await.expect("register Mr");
    let (no_edge_m, _) = c.register(req(36, "Munknown")).await.expect("register Mu");

    // R reports a direct path to Md, a relayed path to Mr, nothing for Mu.
    c.record_peer_paths(
        reporter.peer_id,
        &[
            PeerPathDto {
                peer_id: direct_m.peer_id.to_string(),
                direct: true,
                last_rx_age_ms: 5,
            },
            PeerPathDto {
                peer_id: relay_m.peer_id.to_string(),
                direct: false,
                last_rx_age_ms: 200,
            },
        ],
    );

    // With an explicit vantage = R, the API keeps the legacy single-vantage
    // view: connectivity = edge(R, M). Md→"direct", Mr→"relay", Mu→None.
    let stamped = c.snapshot_with_vantage(Some(reporter.peer_id));
    let conn = |id: Uuid| {
        stamped
            .iter()
            .find(|p| p.peer_id == id.to_string())
            .and_then(|p| p.connectivity.clone())
    };
    assert_eq!(conn(direct_m.peer_id).as_deref(), Some("direct"));
    assert_eq!(conn(relay_m.peer_id).as_deref(), Some("relay"));
    assert_eq!(conn(no_edge_m.peer_id), None, "no edge from vantage → unknown");
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
            relay_only: false,
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
    // Passive registrations (no self-report) so the stored endpoint is
    // synthesized reflexively from the heartbeat source — the real NAT-peer
    // path the hole-punch logic targets.
    let (alice, _) = c.register(passive_req(40, "alice")).await.expect("a");
    let (bob, _) = c.register(passive_req(41, "bob")).await.expect("b");

    // First heartbeats — neither peer has been seen yet, so each
    // populates its own observed_external. After the first heartbeat
    // from each, both peers have non-empty external addrs.
    c.heartbeat(
        alice.peer_id,
        "203.0.113.10:11111".into(),
        Some(51820),
        vec![],
        None,
        false,
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
        false,
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
        false,
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
    // Passive registrations (no self-report) so each peer's stored endpoint
    // is the reflexive value synthesized from its heartbeat source IP.
    let (alice, _) = c.register(passive_req(70, "alice")).await.expect("a");
    let (bob, _) = c.register(passive_req(71, "bob")).await.expect("b");

    // Subscribe AFTER register so the channel only carries the
    // heartbeat-time frames we care about.
    let mut rx = c.broadcaster().subscribe();
    c.heartbeat(
        alice.peer_id,
        "203.0.113.70:11111".into(),
        Some(51820),
        vec![],
        None,
        false,
    )
    .await
    .expect("a hb");
    c.heartbeat(
        bob.peer_id,
        "198.51.100.71:22222".into(),
        Some(51820),
        vec![],
        None,
        false,
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
    c.heartbeat(
        alice.peer_id,
        "203.0.113.30:33333".into(),
        None,
        vec![],
        None,
        false,
    )
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
    c.heartbeat(
        alice.peer_id,
        "203.0.113.50:44444".into(),
        None,
        vec![],
        None,
        false,
    )
    .await
    .expect("a hb");

    // Bob heartbeats but ConnectInfo wasn't captured — empty string.
    // This mirrors the test-router path that drives via Router::call
    // without the make_service wrapper.
    c.heartbeat(bob.peer_id, String::new(), None, vec![], None, false)
        .await
        .expect("b hb empty external");

    assert_eq!(
        pub_.count_by_type("holepunch_initiate"),
        0,
        "empty observed_external must not trigger an emit"
    );
}

// -----------------------------------------------------------------
// Fix D — relay-only peers are never punch targets.
//
// A relay-only peer (one declaring it has no reachable direct endpoint)
// must NEVER be paired for a hole punch — punching at its black-hole
// endpoint in parallel with the relay is the simultaneous-init thrash this
// fix removes. Because the pairing builds each pair from BOTH ends, a punch
// is suppressed when EITHER peer is relay-only; two normal peers still pair.
// -----------------------------------------------------------------

/// `relay_only = true` builds NO `PunchPeer`, so a heartbeat that would
/// otherwise pair two dialable peers emits nothing when either is relay-only
/// — and the non-relay-only baseline still emits, proving it's the flag (not
/// some other gate) doing the suppression.
#[tokio::test]
async fn heartbeat_suppresses_holepunch_when_either_peer_relay_only() {
    let pub_ = StdArc::new(CapturingPublisher::new());
    let c = coordinator_with(pub_.clone());
    let (alice, _) = c.register(req(80, "alice")).await.expect("a");
    let (bob, _) = c.register(req(81, "bob")).await.expect("b");

    // Mark bob relay-only AFTER register. Give bob a (non-empty) endpoint so
    // the ONLY reason the pair is skipped is the relay_only guard, not a
    // missing dial target — isolating the new behaviour from endpoint
    // suppression (covered separately in `nat::reflexive` tests).
    {
        let mut e = c.inner.roster.get_mut(&bob.peer_id).expect("bob entry");
        e.relay_only = true;
        e.listen_endpoint = Some("198.51.100.81:51820".into());
    }

    // Both peers heartbeat with public observed addrs — alice is fully
    // dialable, bob would be too if it weren't relay-only.
    c.heartbeat(
        alice.peer_id,
        "203.0.113.80:11111".into(),
        Some(51820),
        vec![],
        None,
        false,
    )
    .await
    .expect("a hb");
    c.heartbeat(
        bob.peer_id,
        "198.51.100.81:22222".into(),
        Some(51820),
        vec![],
        None,
        true,
    )
    .await
    .expect("b hb");

    assert_eq!(
        pub_.count_by_type("holepunch_initiate"),
        0,
        "no punch directive may be emitted for a pair involving a relay-only peer"
    );
    assert!(
        c.punch_tracker().is_empty(),
        "relay-only suppression must not even claim a punch pair"
    );
}

/// Baseline: the SAME scenario with bob NOT relay-only DOES emit the pair.
/// Guards against a false pass (e.g. a missing endpoint silently suppressing
/// the punch regardless of the flag).
#[tokio::test]
async fn heartbeat_emits_holepunch_for_two_non_relay_only_peers() {
    let pub_ = StdArc::new(CapturingPublisher::new());
    let c = coordinator_with(pub_.clone());
    let (alice, _) = c.register(req(82, "alice")).await.expect("a");
    let (bob, _) = c.register(req(83, "bob")).await.expect("b");
    // Give bob a dialable endpoint, but leave relay_only = false (the
    // register default).
    {
        let mut e = c.inner.roster.get_mut(&bob.peer_id).expect("bob entry");
        e.listen_endpoint = Some("198.51.100.83:51820".into());
    }

    c.heartbeat(
        alice.peer_id,
        "203.0.113.82:11111".into(),
        Some(51820),
        vec![],
        None,
        false,
    )
    .await
    .expect("a hb");
    c.heartbeat(
        bob.peer_id,
        "198.51.100.83:22222".into(),
        Some(51820),
        vec![],
        None,
        false,
    )
    .await
    .expect("b hb");

    assert_eq!(
        pub_.count_by_type("holepunch_initiate"),
        2,
        "two directly-reachable, non-relay-only peers must still pair (2 events)"
    );
}

/// A relay-only peer registered through the full `register_authenticated`
/// path (with a public observed source) gets `listen_endpoint = None` — the
/// coordinator advertises NO direct dial target for it. Verifies the
/// reflexive-suppression wiring end-to-end, not just the pure resolver.
#[tokio::test]
async fn relay_only_register_advertises_no_listen_endpoint() {
    let c = coordinator();
    let observed: SocketAddr = "203.0.113.90:34812".parse().expect("addr");
    let (entry, _) = c
        .register_authenticated(
            RegisterRequest {
                relay_only: true,
                // Even a self-reported public endpoint must be suppressed.
                listen_endpoint: Some("203.0.113.90:51820".into()),
                ..req(90, "relay-only-node")
            },
            None,
            Some(observed),
        )
        .await
        .expect("register relay-only");
    assert_eq!(
        entry.listen_endpoint, None,
        "a relay-only peer must advertise no direct listen endpoint"
    );
    assert!(
        entry.relay_only,
        "relay_only flag must round-trip onto the entry"
    );
    assert!(!entry.endpoint_is_reflexive, "no endpoint → not reflexive");
}

// -----------------------------------------------------------------
// Stage 2 — reflexive endpoint reflection (the NAT-traversal path).
//
// These drive `register_authenticated` / `heartbeat` with a synthetic
// PUBLIC observed `SocketAddr` (what the HTTP handler reads off
// `ConnectInfo` in production) and assert the coordinator STORES the
// reflexive `<observed-public-ip>:<wg-port>` endpoint for a PASSIVE peer
// (one that sent NO self-report — the real NAT-peer path). The pure
// decision table is covered in `crate::nat::reflexive::tests`; this is the
// roster-integration wiring.
// -----------------------------------------------------------------

/// A passive joiner behind NAT sends NO `listen_endpoint`, but the
/// coordinator observes a PUBLIC source IP. The stored `listen_endpoint`
/// must be the reflexive `<public-ip>:<wg-port>`.
#[tokio::test]
async fn register_stores_reflexive_endpoint_for_natted_peer() {
    let c = coordinator();
    // passive_req() sends no self-report; wg_listen_port is 51820.
    let observed: SocketAddr = "203.0.113.7:34812".parse().expect("addr");
    let (entry, outcome) = c
        .register_authenticated(passive_req(1, "natted"), None, Some(observed))
        .await
        .expect("register");
    assert_eq!(outcome, RegisterOutcome::Created);
    // Reflexive: observed public IP + REPORTED wg port (51820), NOT the
    // HTTP source port 34812.
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
        relay_only: false,
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

/// Same-host smoke test: a peer explicitly advertises a loopback endpoint
/// (`req()` self-reports `127.0.0.1:51820`) and the coordinator observes a
/// loopback source. The explicit self-report is honored verbatim — this is
/// the local two-peer back-compat path. (An explicit self-report is now
/// authoritative regardless of being private; a passive peer with a private
/// observed IP would instead stay endpoint-less — see
/// `crate::nat::reflexive::tests::private_observed_ip_no_self_report_stays_passive`.)
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
    // Passive peer: its endpoint is reflexive, hence eligible to roam.
    let (entry, _) = c
        .register_authenticated(passive_req(4, "roamer"), None, Some(observed1))
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
            false,
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
        relay_only: false,
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
            false,
        )
        .await
        .expect("heartbeat");
    assert_eq!(
        updated.listen_endpoint.as_deref(),
        Some("198.51.100.50:51820"),
        "explicit public advert must survive heartbeats"
    );
}

/// A PASSIVE peer (no self-report) that registered before its public
/// source was observed has NO stored endpoint yet; its first heartbeat
/// from a public source IP must synthesize the reflexive endpoint. This is
/// the real NAT-peer bring-up path — a peer with no explicit advertise
/// relies entirely on reflexive discovery.
#[tokio::test]
async fn heartbeat_synthesizes_reflexive_for_passive_peer() {
    let c = coordinator();
    // Passive register with NO observed addr → no endpoint stored yet,
    // endpoint_is_reflexive == false.
    let (entry, _) = c.register(passive_req(8, "late")).await.expect("register");
    assert_eq!(entry.listen_endpoint.as_deref(), None);
    assert!(!entry.endpoint_is_reflexive);
    // Heartbeat from a public IP → must synthesize the reflexive endpoint.
    let updated = c
        .heartbeat(
            entry.peer_id,
            "203.0.113.7:34812".into(),
            Some(51820),
            vec![],
            None,
            false,
        )
        .await
        .expect("heartbeat");
    assert_eq!(
        updated.listen_endpoint.as_deref(),
        Some("203.0.113.7:51820")
    );
    assert!(updated.endpoint_is_reflexive);
}

/// Re-register of a PASSIVE peer from behind NAT must refresh (not regress)
/// the reflexive endpoint: the idempotent re-register path, once it sees a
/// public observed addr, stores the reflexive endpoint.
#[tokio::test]
async fn re_register_refreshes_reflexive_endpoint() {
    let c = coordinator();
    // First passive register with NO observed (e.g. early bring-up) → no
    // endpoint stored yet.
    let (first, _) = c.register(passive_req(6, "peer")).await.expect("first");
    assert_eq!(first.listen_endpoint.as_deref(), None);
    // Re-register (same pubkey) WITH a public observed addr → reflexive.
    let observed: SocketAddr = "203.0.113.7:34812".parse().expect("addr");
    let (second, outcome) = c
        .register_authenticated(passive_req(6, "peer"), None, Some(observed))
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
            false,
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
            false,
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
        false,
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

/// Raw 32-byte pubkey for a register seed — the bytes `pubkey(seed)`
/// base64-encodes. Lets a test register a relay connection under the SAME
/// key a peer registered with, so it can assert the connection is torn
/// down when that peer is evicted.
fn pubkey_bytes(seed: u8) -> Vec<u8> {
    vec![seed; 32]
}

/// Backdate a peer's `last_heartbeat` past the coordinator's
/// `heartbeat_timeout` so the staleness-gated adopt-on-stale path treats it
/// as a dead holder.
fn make_stale(c: &Coordinator, peer_id: Uuid) {
    let timeout = c.heartbeat_timeout();
    let mut e = c.inner.roster.get_mut(&peer_id).expect("entry");
    e.last_heartbeat = Instant::now()
        .checked_sub(timeout + Duration::from_secs(1))
        .expect("instant arithmetic");
}

/// FIX B — adopt-on-stale: a node redeploy churns its pubkey, so a FRESH
/// pubkey B requests the sticky ULA that a STALE peer A (pubkey A,
/// `last_heartbeat` older than the timeout) still pins. The coordinator must
/// EVICT the stale holder (drop its roster entry, `by_pubkey`, AND relay conn,
/// broadcast `Removed(old)`) and GRANT the ULA to B (`Added(new)`), NOT 409.
/// Without this the churned node fails to join until A times out, while peers
/// loop on a stale `WireGuard` session.
#[tokio::test]
async fn register_evicts_stale_holder_and_adopts_requested_ula() {
    let c = coordinator();
    let want = "fd5a:1f02:dead::1";

    // Peer A claims the sticky ULA, then goes stale.
    let (a, _) = c
        .register(req_with_requested_ula(40, "stale-peer", want))
        .await
        .expect("peer-a register");
    let pubkey_a = pubkey_bytes(40);
    // Register a live relay connection under A's pubkey — eviction must
    // tear it down (proves `apply_peer_left` -> `relay.drop_pubkey(A)`).
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    c.relay().register(pubkey_a.clone(), tx);
    assert!(
        c.relay().forward(&pubkey_a, vec![1, 2, 3]),
        "relay conn for A is live before eviction"
    );
    make_stale(&c, a.peer_id);

    // Subscribe AFTER setup so the channel carries only the eviction +
    // grant frames.
    let mut rx = c.broadcaster().subscribe();

    // Fresh pubkey B requests the SAME ULA → adopt-on-stale, NOT 409.
    let (b, outcome) = c
        .register(req_with_requested_ula(41, "fresh-peer", want))
        .await
        .expect("fresh peer must adopt the stale ULA, not 409");
    assert_eq!(outcome, RegisterOutcome::Created);
    assert_eq!(b.ula.to_string(), want, "B is granted the requested ULA");
    assert_ne!(b.peer_id, a.peer_id, "B is a new peer record");

    // The stale holder A is gone from the roster + by_pubkey; only B holds X.
    assert_eq!(c.snapshot().len(), 1, "only the fresh peer remains");
    assert_eq!(c.snapshot()[0].ula, want);
    assert!(
        !c.is_registered_pubkey(&pubkey_a),
        "stale A's pubkey must be evicted from by_pubkey"
    );
    // A's relay connection was dropped by the eviction.
    assert!(
        !c.relay().forward(&pubkey_a, vec![4, 5, 6]),
        "stale A's relay conn must be torn down on eviction"
    );

    // The broadcast carries Removed(A) BEFORE Added(B).
    let mut removed_old = false;
    let mut added_new = false;
    let mut removed_before_added = false;
    while let Ok(ev) = rx.try_recv() {
        match ev {
            PeerEvent::Removed { peer_id, .. } if peer_id == a.peer_id.to_string() => {
                removed_old = true;
            }
            PeerEvent::Added(info) if info.peer_id == b.peer_id.to_string() => {
                added_new = true;
                // Removed must have been observed first.
                if removed_old {
                    removed_before_added = true;
                }
            }
            _ => {}
        }
    }
    assert!(removed_old, "Removed(old) must be broadcast");
    assert!(added_new, "Added(new) must be broadcast");
    assert!(
        removed_before_added,
        "Removed(old) must be broadcast BEFORE Added(new)"
    );
}

/// FIX B is staleness-gated: a CURRENT-heartbeat holder must NOT be evicted.
/// A fresh/hostile peer requesting a ULA a genuinely LIVE different peer holds
/// still gets a `409` — critical under `--insecure-no-mtls` where a register
/// is unauthenticated and must never be able to kick a live peer off its ULA.
#[tokio::test]
async fn register_keeps_409_when_holder_heartbeat_is_current() {
    let c = coordinator();
    let want = "fd5a:1f02:beef::1";

    // Peer A claims the ULA and is freshly registered (current heartbeat).
    let (a, _) = c
        .register(req_with_requested_ula(42, "live-peer", want))
        .await
        .expect("peer-a register");

    // Fresh pubkey B requests the SAME ULA while A is still live → 409.
    let err = c
        .register(req_with_requested_ula(43, "intruder", want))
        .await
        .expect_err("a live holder must not be kicked off its ULA");
    assert!(
        matches!(err, CoordinatorError::UlaConflict(_)),
        "expected UlaConflict for a current-heartbeat holder, got {err:?}"
    );
    // A is untouched: still the sole holder of the ULA.
    assert_eq!(c.snapshot().len(), 1);
    assert_eq!(c.snapshot()[0].peer_id, a.peer_id.to_string());
    assert_eq!(c.snapshot()[0].ula, want);
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
            false,
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
        .heartbeat(
            entry.peer_id,
            String::new(),
            Some(51820),
            vec![],
            None,
            false,
        )
        .await
        .expect("heartbeat none");
    assert_eq!(
        kept.software_version.as_deref(),
        Some("v1.5.0"),
        "None on heartbeat must not clear the stored version"
    );
}

// ── Durable roster (coordinator-restart resilience) ─────────────────────────
// A coordinator backed by a FileRosterStore must, after a "restart" (a fresh
// Coordinator over the SAME store dir + `restore()`), bring every peer back at
// the SAME ULA, repopulate `by_pubkey` so a sticky re-register is idempotent
// (no 409), and resume the allocator past the restored indices (no reshuffle).

use crate::roster::store::FileRosterStore;

fn coordinator_with_store(dir: &std::path::Path) -> Coordinator {
    Coordinator::with_policy_validator_store(
        Arc::new(NoopPublisher),
        Duration::from_secs(60),
        PolicyStore::empty(),
        None,
        Arc::new(FileRosterStore::new(dir)),
    )
}

#[tokio::test]
async fn restore_brings_peers_back_at_the_same_ula() {
    let dir = tempfile::tempdir().expect("tempdir");
    // First coordinator lifetime: register two peers, persist on each.
    let (alice_id, alice_ula, bob_ula);
    {
        let c1 = coordinator_with_store(dir.path());
        let (a, _) = c1.register(req(1, "alice")).await.expect("reg alice");
        let (b, _) = c1.register(req(2, "bob")).await.expect("reg bob");
        alice_id = a.peer_id;
        alice_ula = a.ula;
        bob_ula = b.ula;
    }
    // "Restart": fresh coordinator over the same store dir.
    let c2 = coordinator_with_store(dir.path());
    c2.restore().await;
    let snap = c2.snapshot();
    assert_eq!(snap.len(), 2, "both peers restored");
    // Same peer_id + ULA survive the restart (no reshuffle).
    let alice = snap
        .iter()
        .find(|p| p.peer_id == alice_id.to_string())
        .expect("alice restored");
    assert_eq!(alice.ula, alice_ula.to_string());
    assert!(snap.iter().any(|p| p.ula == bob_ula.to_string()));
}

#[tokio::test]
async fn sticky_reregister_after_restore_is_idempotent_no_409() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (orig_id, orig_ula);
    {
        let c1 = coordinator_with_store(dir.path());
        let (p, _) = c1.register(req(7, "registry")).await.expect("reg");
        orig_id = p.peer_id;
        orig_ula = p.ula;
    }
    let c2 = coordinator_with_store(dir.path());
    c2.restore().await;
    // Same pubkey re-registers → idempotent: same peer_id + ULA, NO UlaConflict.
    let (again, outcome) = c2
        .register(req(7, "registry"))
        .await
        .expect("sticky re-register must NOT 409 after restore");
    assert_eq!(outcome, RegisterOutcome::Existed);
    assert_eq!(again.peer_id, orig_id, "same peer_id after restart");
    assert_eq!(again.ula, orig_ula, "same ULA after restart");
}

#[tokio::test]
async fn different_peer_claiming_a_restored_ula_gets_409() {
    let dir = tempfile::tempdir().expect("tempdir");
    let claimed_ula;
    {
        let c1 = coordinator_with_store(dir.path());
        let (p, _) = c1.register(req(1, "holder")).await.expect("reg");
        claimed_ula = p.ula.to_string();
    }
    let c2 = coordinator_with_store(dir.path());
    c2.restore().await;
    // A DIFFERENT peer (seed 2) requesting the restored peer's ULA must be
    // rejected — proving restore put the holder back into the conflict scan.
    let mut intruder = req(2, "intruder");
    intruder.requested_ula = Some(claimed_ula.clone());
    let err = c2
        .register(intruder)
        .await
        .expect_err("claiming a restored ULA must conflict");
    assert!(
        matches!(err, CoordinatorError::UlaConflict(u) if u == claimed_ula),
        "expected UlaConflict for the restored ULA",
    );
}

#[tokio::test]
async fn allocator_resumes_past_restored_indices() {
    let dir = tempfile::tempdir().expect("tempdir");
    {
        let c1 = coordinator_with_store(dir.path());
        // Two peers in the default network → indices 1 and 2.
        c1.register(req(1, "a")).await.expect("a");
        c1.register(req(2, "b")).await.expect("b");
    }
    let c2 = coordinator_with_store(dir.path());
    c2.restore().await;
    // A brand-new peer must get index 3, not collide at 1 (allocator resumed).
    let (fresh, outcome) = c2.register(req(9, "fresh")).await.expect("fresh");
    assert_eq!(outcome, RegisterOutcome::Created);
    assert_eq!(fresh.peer_index, 3, "allocator continued past restored 1,2");
}

#[tokio::test]
async fn deregister_persists_so_peer_is_not_resurrected() {
    let dir = tempfile::tempdir().expect("tempdir");
    let gone_id;
    {
        let c1 = coordinator_with_store(dir.path());
        let (p, _) = c1.register(req(1, "ephemeral")).await.expect("reg");
        gone_id = p.peer_id;
        assert!(c1.deregister(gone_id, "client_deregister").await);
    }
    let c2 = coordinator_with_store(dir.path());
    c2.restore().await;
    assert!(
        c2.snapshot().is_empty(),
        "a deregistered peer must not be resurrected on restart",
    );
}

#[tokio::test]
async fn restored_peer_is_not_immediately_stale() {
    let dir = tempfile::tempdir().expect("tempdir");
    {
        let c1 = coordinator_with_store(dir.path());
        c1.register(req(1, "p")).await.expect("reg");
    }
    let c2 = coordinator_with_store(dir.path());
    c2.restore().await;
    // restore() stamps a fresh last_heartbeat → no peer is stale right now.
    assert!(
        c2.stale_peers(std::time::Instant::now()).is_empty(),
        "restored peers get a full heartbeat-timeout grace, not instant eviction",
    );
}

// -----------------------------------------------------------------
// Topology: the machine graph. `topology()` projects the roster into
// `{ machines, edges }`, EXCLUDING app-runners (ULA in `fd5a:1f02::/32`
// OR tag `"runner"`) and collapsing the directed `paths` into undirected
// machine↔machine pairs.
// -----------------------------------------------------------------

#[tokio::test]
async fn topology_collapses_edges_and_filters_runners() {
    use crate::http::api::PeerPathDto;

    let c = coordinator();
    // Three machine peers (plain `fd5a:1f00:...` ULAs).
    let (a, _) = c
        .register(RegisterRequest {
            tags: vec!["supervisor".into(), "firecracker".into()],
            software_version: Some("1.4.35".into()),
            relay_only: false,
            ..req(60, "A")
        })
        .await
        .expect("register A");
    let (b, _) = c.register(req(61, "B")).await.expect("register B");
    let (cc, _) = c.register(req(62, "C")).await.expect("register C");
    // A runner peer — detected by its `fd5a:1f02::/32` ULA.
    let (runner, _) = c
        .register(req_with_requested_ula(63, "runner-1", "fd5a:1f02:aaaa::1"))
        .await
        .expect("register runner");

    // Directed paths: A→B direct, B→A relay, A→C relay, runner→A direct.
    c.record_peer_paths(
        a.peer_id,
        &[
            PeerPathDto {
                peer_id: b.peer_id.to_string(),
                direct: true,
                last_rx_age_ms: 50,
            },
            PeerPathDto {
                peer_id: cc.peer_id.to_string(),
                direct: false,
                last_rx_age_ms: 900,
            },
        ],
    );
    c.record_peer_paths(
        b.peer_id,
        &[PeerPathDto {
            peer_id: a.peer_id.to_string(),
            direct: false,
            last_rx_age_ms: 30,
        }],
    );
    c.record_peer_paths(
        runner.peer_id,
        &[PeerPathDto {
            peer_id: a.peer_id.to_string(),
            direct: true,
            last_rx_age_ms: 10,
        }],
    );

    let topo = c.topology();

    // Machines = {A, B, C}; runner excluded.
    let machine_ids: std::collections::HashSet<String> =
        topo.machines.iter().map(|m| m.peer_id.clone()).collect();
    assert_eq!(machine_ids.len(), 3, "exactly three machines (runner excluded)");
    assert!(machine_ids.contains(&a.peer_id.to_string()));
    assert!(machine_ids.contains(&b.peer_id.to_string()));
    assert!(machine_ids.contains(&cc.peer_id.to_string()));
    assert!(
        !machine_ids.contains(&runner.peer_id.to_string()),
        "the runner must not appear as a machine"
    );

    // The machine carrying the metadata round-trips tags / relay_only /
    // software_version the same way `to_info()` does.
    let machine_a = topo
        .machines
        .iter()
        .find(|m| m.peer_id == a.peer_id.to_string())
        .expect("machine A present");
    assert_eq!(machine_a.name, "A");
    assert_eq!(machine_a.ula, a.ula.to_string());
    assert_eq!(machine_a.tags, vec!["supervisor", "firecracker"]);
    assert!(!machine_a.relay_only);
    assert_eq!(machine_a.software_version.as_deref(), Some("1.4.35"));

    // NO edge touches the runner.
    for e in &topo.edges {
        assert_ne!(e.from, runner.peer_id.to_string());
        assert_ne!(e.to, runner.peer_id.to_string());
    }

    // Helper: find the undirected edge for an unordered machine pair.
    let find_edge = |x: &Uuid, y: &Uuid| {
        let (lo, hi) = if x.to_string() < y.to_string() {
            (x.to_string(), y.to_string())
        } else {
            (y.to_string(), x.to_string())
        };
        topo.edges
            .iter()
            .find(|e| e.from == lo && e.to == hi)
            .cloned()
    };

    // Edge {A,B}: A→B direct OR B→A relay → direct; age = min(50, 30) = 30.
    let ab = find_edge(&a.peer_id, &b.peer_id).expect("edge A-B present");
    assert!(ab.direct, "A↔B is direct (one direction reported direct)");
    assert_eq!(ab.age_ms, 30, "age_ms is the min of reported ages");
    // It appears EXACTLY once.
    let ab_count = topo
        .edges
        .iter()
        .filter(|e| {
            (e.from == a.peer_id.to_string() && e.to == b.peer_id.to_string())
                || (e.from == b.peer_id.to_string() && e.to == a.peer_id.to_string())
        })
        .count();
    assert_eq!(ab_count, 1, "the {{A,B}} pair appears exactly once");

    // Edge {A,C}: only A→C relay → relay; age = 900.
    let ac = find_edge(&a.peer_id, &cc.peer_id).expect("edge A-C present");
    assert!(!ac.direct, "A↔C is relay (no direction reported direct)");
    assert_eq!(ac.age_ms, 900);

    // No spurious B↔C edge (neither reported a path to the other).
    assert!(find_edge(&b.peer_id, &cc.peer_id).is_none());
}

/// Defense-in-depth: a runner that does NOT have a `fd5a:1f02::/32` ULA
/// must still be excluded from the machine graph when it is identified as a
/// runner by `kind == "runner"` and/or the `"runner"` tag. Exercises the
/// branch of `is_machine` that the ULA-based test above does not.
#[tokio::test]
async fn topology_excludes_runner_by_kind_and_tag_without_1f02_ula() {
    use crate::http::api::PeerPathDto;

    let c = coordinator();
    // A plain machine.
    let (a, _) = c.register(req(70, "A")).await.expect("register A");
    // A runner identified ONLY by `kind == "runner"` — NO `"runner"` tag and
    // a PLAIN (`fd5a:1f00:...`) idx-derived ULA — so neither the ULA branch
    // nor the tag branch of `is_machine` catches it; only the kind branch.
    let (kind_runner, _) = c
        .register(RegisterRequest {
            kind: "runner".into(),
            tags: vec!["dev-machine".into()],
            parent: Some("fd5a:1f00:0:1::1".into()),
            app_uuid: Some("01910f10-0000-7000-8000-000000000001".into()),
            ..req(71, "runner-kind-only")
        })
        .await
        .expect("register kind-only runner");
    // A runner identified ONLY by the `"runner"` tag — kind="peer", plain ULA.
    let (tag_runner, _) = c
        .register(RegisterRequest {
            tags: vec!["runner".into()],
            ..req(72, "runner-tag-only")
        })
        .await
        .expect("register tag-only runner");

    // Sanity: neither runner got a 1f02 ULA, so the ULA branch can't be the
    // thing excluding them — kind / tag must.
    assert_ne!(
        kind_runner.ula.segments()[1],
        0x1f02,
        "kind-only runner must use a NON-1f02 ULA to exercise the kind branch"
    );
    assert_ne!(
        tag_runner.ula.segments()[1],
        0x1f02,
        "tag-only runner must use a NON-1f02 ULA to exercise the tag branch"
    );

    // Edges in both directions so a missed exclusion would surface as an edge.
    c.record_peer_paths(
        a.peer_id,
        &[
            PeerPathDto {
                peer_id: kind_runner.peer_id.to_string(),
                direct: true,
                last_rx_age_ms: 5,
            },
            PeerPathDto {
                peer_id: tag_runner.peer_id.to_string(),
                direct: true,
                last_rx_age_ms: 5,
            },
        ],
    );
    c.record_peer_paths(
        kind_runner.peer_id,
        &[PeerPathDto {
            peer_id: a.peer_id.to_string(),
            direct: true,
            last_rx_age_ms: 5,
        }],
    );
    c.record_peer_paths(
        tag_runner.peer_id,
        &[PeerPathDto {
            peer_id: a.peer_id.to_string(),
            direct: true,
            last_rx_age_ms: 5,
        }],
    );

    let topo = c.topology();

    // Only the plain machine appears; both runners are filtered out.
    let machine_ids: std::collections::HashSet<String> =
        topo.machines.iter().map(|m| m.peer_id.clone()).collect();
    assert_eq!(machine_ids.len(), 1, "only the plain machine is a machine");
    assert!(machine_ids.contains(&a.peer_id.to_string()));
    assert!(
        !machine_ids.contains(&kind_runner.peer_id.to_string()),
        "a kind=runner peer must be excluded even without a 1f02 ULA or tag"
    );
    assert!(
        !machine_ids.contains(&tag_runner.peer_id.to_string()),
        "a tag=runner peer must be excluded even without a 1f02 ULA"
    );

    // And NO edge touches either runner (neither is a machine).
    for e in &topo.edges {
        assert_ne!(e.from, kind_runner.peer_id.to_string());
        assert_ne!(e.to, kind_runner.peer_id.to_string());
        assert_ne!(e.from, tag_runner.peer_id.to_string());
        assert_ne!(e.to, tag_runner.peer_id.to_string());
    }
    assert!(topo.edges.is_empty(), "the only edges were runner↔machine");
}
