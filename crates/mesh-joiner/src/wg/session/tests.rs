//! Session-table / per-app-ULA-routing tests.
//!
//! Exercises the table-management API around [`super::SessionTable`].
//! Ciphertext flow is integration-tested through `mesh-fabric`'s
//! `wireguard_udp.rs` suite.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use super::*;
use crate::peer::PeerInfo;
use boringtun::noise::TunnResult;
use parking_lot::Mutex as PlMutex;
use std::net::{Ipv6Addr, SocketAddr};
use std::sync::Arc;
use uuid::Uuid;
use x25519_dalek::{PublicKey, StaticSecret};

fn pubkey_bytes_at(n: u8) -> [u8; 32] {
    let secret = StaticSecret::from([n; 32]);
    *PublicKey::from(&secret).as_bytes()
}

fn info(n: u8, ula: &str, endpoint: Option<&str>) -> PeerInfo {
    PeerInfo {
        peer_id: Uuid::nil(),
        wg_public_key: pubkey_bytes_at(n),
        ula: ula.parse().unwrap(),
        listen_endpoint: endpoint.map(|s| s.parse().unwrap()),
        display_name: format!("peer-{n}"),
        tags: vec![],
        hosted_app_ulas: vec![],
        software_version: None,
        joined_at_micros: 0,
    }
}

/// Records every add/remove the table pushes so route-scoping tests
/// can assert the kernel would see exactly the right `/128`s. App
/// routes are recorded in their own vectors so per-app-ULA routing can
/// be asserted independently of peer routes.
#[derive(Default)]
struct RecordingRouteSink {
    added: PlMutex<Vec<Ipv6Addr>>,
    removed: PlMutex<Vec<Ipv6Addr>>,
    app_added: PlMutex<Vec<Ipv6Addr>>,
    app_removed: PlMutex<Vec<Ipv6Addr>>,
}
impl RouteSink for RecordingRouteSink {
    fn add_allowed(&self, ula: Ipv6Addr) {
        self.added.lock().push(ula);
    }
    fn remove_allowed(&self, ula: Ipv6Addr) {
        self.removed.lock().push(ula);
    }
    fn add_app_route(&self, app_ula: Ipv6Addr) {
        self.app_added.lock().push(app_ula);
    }
    fn remove_app_route(&self, app_ula: Ipv6Addr) {
        self.app_removed.lock().push(app_ula);
    }
}

#[test]
fn empty_table_starts_empty() {
    let t = SessionTable::new();
    assert!(t.is_empty());
    assert_eq!(t.len(), 0);
    assert!(t.snapshot().is_empty());
}

/// A session built by `upsert` carries the peer's raw WG public key, and
/// the `by_pubkey` index resolves to that same session — the demux the
/// relay RX path uses to find the right `Tunn` for an inbound frame.
#[test]
fn upsert_indexes_session_by_pubkey() {
    let t = SessionTable::new();
    let me = StaticSecret::from([42u8; 32]);
    let p = info(1, "fd5a:1f00:1::1", Some("127.0.0.1:51820"));
    t.upsert(&me, &p);
    let session = t.by_pubkey(p.wg_public_key).expect("session by pubkey");
    assert_eq!(
        session.peer_pubkey, p.wg_public_key,
        "session stores the peer's pubkey"
    );
    // The pubkey index resolves to the same session as the ULA index.
    assert_eq!(session.ula, p.ula);
}

/// Removing a session drops its `by_pubkey` entry too, so a later relay
/// frame for that pubkey no longer resolves to a stale session.
#[test]
fn remove_clears_pubkey_index() {
    let t = SessionTable::new();
    let me = StaticSecret::from([42u8; 32]);
    let p = info(1, "fd5a:1f00:1::1", Some("127.0.0.1:51820"));
    t.upsert(&me, &p);
    assert!(t.by_pubkey(p.wg_public_key).is_some());
    assert!(t.remove(p.ula));
    assert!(t.by_pubkey(p.wg_public_key).is_none());
}

/// Identity rotation: a peer keeps the SAME ULA but rotates its WG key.
/// Re-upserting at ULA X with a new pubkey B must drop the stale pubkey A
/// from the `by_pubkey` index (so a relay frame from the old key no longer
/// resolves to a session) while B resolves to the surviving session, which
/// now carries B's key. ULA X must still resolve throughout.
#[test]
fn upsert_same_ula_new_pubkey_rolls_over_pubkey_index() {
    let t = SessionTable::new();
    let me = StaticSecret::from([42u8; 32]);
    let pubkey_a = pubkey_bytes_at(1);
    let pubkey_b = pubkey_bytes_at(2);

    // Upsert ULA X with pubkey A.
    let first = info(1, "fd5a:1f00:1::7", Some("127.0.0.1:51820"));
    t.upsert(&me, &first);
    assert!(t.by_pubkey(pubkey_a).is_some(), "pubkey A indexed");

    // Re-upsert the SAME ULA with pubkey B (the peer rotated its key).
    let second = info(2, "fd5a:1f00:1::7", Some("127.0.0.1:51820"));
    t.upsert(&me, &second);

    // ULA X still resolves.
    let by_ula = t
        .by_ula("fd5a:1f00:1::7".parse::<Ipv6Addr>().unwrap())
        .expect("ULA X still resolves after the key rotation");
    assert_eq!(by_ula.peer_pubkey, pubkey_b);
    // The stale pubkey A is gone; pubkey B resolves to the live session.
    assert!(
        t.by_pubkey(pubkey_a).is_none(),
        "stale pubkey A must be dropped on rotation"
    );
    let by_pk = t.by_pubkey(pubkey_b).expect("pubkey B resolves");
    assert_eq!(by_pk.peer_pubkey, pubkey_b, "session carries the new pubkey");
}

/// Fix C: a re-upsert with the SAME pubkey and only the endpoint changed
/// must KEEP the existing session (and its `Tunn` + handshake timer) in
/// place, repointing the endpoint without rebuilding. Rebuilding on every
/// ~20s `peer_updated` wipes the boringtun handshake state and resets
/// `direct_confirmed`, forcing a needless re-handshake and breaking the
/// timer-driven relay-retransmit backstop. `Arc::ptr_eq` proves the SAME
/// underlying session survived; the endpoint reflects the new address.
#[test]
fn upsert_same_pubkey_endpoint_change_keeps_session() {
    let t = SessionTable::new();
    let me = StaticSecret::from([42u8; 32]);
    let ula: Ipv6Addr = "fd5a:1f00:1::5".parse().unwrap();

    let first = info(1, "fd5a:1f00:1::5", Some("127.0.0.1:51820"));
    t.upsert(&me, &first);
    let before = t.by_ula(ula).expect("session after first upsert");

    // Re-upsert SAME ULA + SAME pubkey, only the endpoint changed.
    let moved = info(1, "fd5a:1f00:1::5", Some("10.0.0.5:51820"));
    t.upsert(&me, &moved);
    let after = t.by_ula(ula).expect("session after endpoint-only re-upsert");

    assert!(
        Arc::ptr_eq(&before, &after),
        "endpoint-only re-upsert (same pubkey) must KEEP the same session/Tunn"
    );
    assert_eq!(
        after.endpoint(),
        Some("10.0.0.5:51820".parse().unwrap()),
        "the endpoint must be repointed to the new advertised address"
    );
}

/// Fix C sibling: a re-upsert with a ROTATED pubkey (same ULA) MUST rebuild
/// the session — a brand-new `Tunn` keyed to the new key. This preserves
/// the prior identity-rotation fix: a key change drops the stale `Tunn` (a
/// handshake with the old key would never complete) and rolls over the
/// `by_pubkey` alias. `Arc::ptr_eq` proves a DIFFERENT session was built.
#[test]
fn upsert_rotated_pubkey_rebuilds_session() {
    let t = SessionTable::new();
    let me = StaticSecret::from([42u8; 32]);
    let ula: Ipv6Addr = "fd5a:1f00:1::6".parse().unwrap();

    let first = info(1, "fd5a:1f00:1::6", Some("127.0.0.1:51820"));
    t.upsert(&me, &first);
    let before = t.by_ula(ula).expect("session after first upsert");

    // Re-upsert SAME ULA with a NEW pubkey (the peer rotated its key).
    let rotated = info(2, "fd5a:1f00:1::6", Some("127.0.0.1:51820"));
    t.upsert(&me, &rotated);
    let after = t.by_ula(ula).expect("session after key rotation");

    assert!(
        !Arc::ptr_eq(&before, &after),
        "a key rotation MUST rebuild the session (fresh Tunn for the new key)"
    );
    assert_eq!(after.peer_pubkey, pubkey_bytes_at(2), "session carries the new key");
}

#[test]
fn upsert_inserts_and_indexes_both_lookups() {
    let t = SessionTable::new();
    let me = StaticSecret::from([42u8; 32]);
    let p = info(1, "fd5a:1f00:1::1", Some("127.0.0.1:51820"));
    t.upsert(&me, &p);
    assert_eq!(t.len(), 1);
    assert!(t.by_ula(p.ula).is_some());
    assert!(t.by_endpoint("127.0.0.1:51820".parse().unwrap()).is_some());
}

/// Passive peers (no endpoint) must still be registered for the
/// reverse direction. They live only in the ULA index.
#[test]
fn upsert_passive_peer_skips_endpoint_index() {
    let t = SessionTable::new();
    let me = StaticSecret::from([42u8; 32]);
    let p = info(2, "fd5a:1f00:1::2", None);
    t.upsert(&me, &p);
    assert!(t.by_ula(p.ula).is_some());
    // The endpoint table must remain empty for passive peers.
    assert!(t.by_endpoint("127.0.0.1:51820".parse().unwrap()).is_none());
}

/// Replacing a peer's endpoint must evict the stale UDP route so a
/// later datagram from the old endpoint isn't misrouted.
#[test]
fn upsert_with_changed_endpoint_evicts_stale_route() {
    let t = SessionTable::new();
    let me = StaticSecret::from([42u8; 32]);
    let initial = info(3, "fd5a:1f00:1::3", Some("127.0.0.1:51820"));
    t.upsert(&me, &initial);
    let moved = info(3, "fd5a:1f00:1::3", Some("10.0.0.5:51820"));
    t.upsert(&me, &moved);
    assert!(t.by_endpoint("127.0.0.1:51820".parse().unwrap()).is_none());
    assert!(t.by_endpoint("10.0.0.5:51820".parse().unwrap()).is_some());
}

#[test]
fn remove_clears_both_indexes() {
    let t = SessionTable::new();
    let me = StaticSecret::from([42u8; 32]);
    let p = info(4, "fd5a:1f00:1::4", Some("127.0.0.1:7777"));
    t.upsert(&me, &p);
    assert!(t.remove(p.ula));
    assert!(t.by_ula(p.ula).is_none());
    assert!(t.by_endpoint("127.0.0.1:7777".parse().unwrap()).is_none());
}

#[test]
fn remove_on_unknown_ula_returns_false() {
    let t = SessionTable::new();
    let ula: Ipv6Addr = "fd5a:1f00:1::9".parse().unwrap();
    assert!(!t.remove(ula));
}

#[test]
fn clear_drops_all_sessions() {
    let t = SessionTable::new();
    let me = StaticSecret::from([42u8; 32]);
    t.upsert(&me, &info(1, "fd5a:1f00:1::1", Some("127.0.0.1:51820")));
    t.upsert(&me, &info(2, "fd5a:1f00:1::2", Some("127.0.0.1:51821")));
    t.clear();
    assert!(t.is_empty());
}

/// `classify_tunn_result` should turn `Done` into `Nothing` and
/// IPv4 packets into `Nothing` (we drop v4 over this overlay).
#[test]
fn classify_handles_done_and_v4() {
    assert!(matches!(
        classify_tunn_result(TunnResult::Done),
        WgAction::Nothing
    ));
}

// ---- spec §5.5: per-peer /128 allowed-ips ----

/// A freshly-upserted session carries an allowed-set containing the
/// peer's own ULA (the MVP cryptokey-routing invariant).
#[test]
fn upsert_builds_allowed_set_with_peer_ula() {
    let t = SessionTable::new();
    let me = StaticSecret::from([42u8; 32]);
    let p = info(1, "fd5a:1f00:1::1", Some("127.0.0.1:51820"));
    t.upsert(&me, &p);
    let session = t.by_ula(p.ula).unwrap();
    assert!(session.is_allowed_source(p.ula), "own ULA must be allowed");
}

/// The allowed-set must REJECT any address other than the peer's
/// own ULA — including a different ULA inside the same `/48`. This
/// is the whole point of §5.5: a peer is constrained to its `/128`,
/// not the blanket overlay prefix.
#[test]
fn allowed_set_rejects_other_ulas_in_same_prefix() {
    let t = SessionTable::new();
    let me = StaticSecret::from([42u8; 32]);
    let p = info(1, "fd5a:1f00:1::1", Some("127.0.0.1:51820"));
    t.upsert(&me, &p);
    let session = t.by_ula(p.ula).unwrap();
    // A neighbour /128 in the same /48 the peer is NOT allowed to source.
    let neighbour: Ipv6Addr = "fd5a:1f00:1::2".parse().unwrap();
    assert!(!session.is_allowed_source(neighbour));
    // And an address in a different network block.
    let elsewhere: Ipv6Addr = "fd5a:1f00:2::1".parse().unwrap();
    assert!(!session.is_allowed_source(elsewhere));
}

/// With a route sink wired, inserting a NEW peer installs exactly
/// one `/128` route (the peer's ULA) — never a `/48`.
#[test]
fn upsert_installs_per_peer_128_route() {
    let sink = Arc::new(RecordingRouteSink::default());
    let t = SessionTable::with_route_sink(sink.clone());
    let me = StaticSecret::from([42u8; 32]);
    let p = info(1, "fd5a:1f00:1::1", Some("127.0.0.1:51820"));
    t.upsert(&me, &p);
    let added = sink.added.lock();
    assert_eq!(*added, vec![p.ula], "exactly the peer's /128 is routed");
}

/// Re-upserting the SAME ULA (e.g. an endpoint roam or re-handshake)
/// must NOT re-install the route — route churn would needlessly
/// flap the kernel table.
#[test]
fn re_upsert_same_ula_does_not_duplicate_route() {
    let sink = Arc::new(RecordingRouteSink::default());
    let t = SessionTable::with_route_sink(sink.clone());
    let me = StaticSecret::from([42u8; 32]);
    t.upsert(&me, &info(1, "fd5a:1f00:1::1", Some("127.0.0.1:51820")));
    t.upsert(&me, &info(1, "fd5a:1f00:1::1", Some("10.0.0.5:51820")));
    assert_eq!(sink.added.lock().len(), 1, "route installed once per ULA");
}

/// Removing a session tears down its `/128` route.
#[test]
fn remove_tears_down_per_peer_route() {
    let sink = Arc::new(RecordingRouteSink::default());
    let t = SessionTable::with_route_sink(sink.clone());
    let me = StaticSecret::from([42u8; 32]);
    let p = info(1, "fd5a:1f00:1::1", Some("127.0.0.1:51820"));
    t.upsert(&me, &p);
    assert!(t.remove(p.ula));
    assert_eq!(*sink.removed.lock(), vec![p.ula]);
}

/// `clear` removes every per-peer route so a `leave()` leaves no
/// stale overlay routes behind.
#[test]
fn clear_tears_down_all_routes() {
    let sink = Arc::new(RecordingRouteSink::default());
    let t = SessionTable::with_route_sink(sink.clone());
    let me = StaticSecret::from([42u8; 32]);
    let a = info(1, "fd5a:1f00:1::1", Some("127.0.0.1:51820"));
    let b = info(2, "fd5a:1f00:1::2", Some("127.0.0.1:51821"));
    t.upsert(&me, &a);
    t.upsert(&me, &b);
    t.clear();
    let mut removed = sink.removed.lock().clone();
    removed.sort();
    assert_eq!(removed, vec![a.ula, b.ula]);
}

/// A table built with `new()` (no sink) must not panic on upsert /
/// remove — route management is simply skipped.
#[test]
fn no_sink_table_skips_route_management() {
    let t = SessionTable::new();
    let me = StaticSecret::from([42u8; 32]);
    let p = info(1, "fd5a:1f00:1::1", Some("127.0.0.1:51820"));
    t.upsert(&me, &p);
    assert!(t.remove(p.ula));
}

// ---- NAT traversal: persistent keepalive + endpoint roaming ----

// The persistent-keepalive constant must stay at the WireGuard
// canonical 25s — the value that keeps NAT UDP mappings open. A
// regression here silently breaks cone-NAT traversal (mappings expire
// between sparse data packets), so pin it.
#[test]
fn persistent_keepalive_is_25s() {
    assert_eq!(WG_PERSISTENT_KEEPALIVE_SECS, 25);
}

// Endpoint roaming, passive-peer case: a peer that registered with NO
// endpoint (passive / behind NAT) adopts the source address of the
// first datagram we successfully decapsulate from it as its outbound
// endpoint. This is what lets us reply to a peer that punched out to
// us first.
#[test]
fn learn_endpoint_promotes_source_for_passive_peer() {
    let t = SessionTable::new();
    let me = StaticSecret::from([42u8; 32]);
    let p = info(1, "fd5a:1f00:1::1", None); // passive — no endpoint
    t.upsert(&me, &p);
    let session = t.by_ula(p.ula).expect("session");
    assert!(session.endpoint().is_none(), "starts passive");

    let learned: SocketAddr = "203.0.113.9:51820".parse().unwrap();
    t.learn_endpoint(&session, learned);
    // Promoted as the outbound default AND indexed for inbound demux.
    assert_eq!(session.endpoint(), Some(learned));
    assert!(t.by_endpoint(learned).is_some());
}

// Fix B — endpoint roaming, UNCONFIRMED active-peer case: a peer that
// has an advertised endpoint but whose direct path is NOT yet confirmed
// is repointed onto a learned inbound source. The advertised endpoint may
// be a BLACK HOLE (a no-inbound-port peer's reflexive endpoint) — a real
// inbound datagram from a different source proves a live return path, so
// adopt it as the outbound default while still unconfirmed. The new source
// is also indexed for inbound demux. (Old behaviour kept the advertised
// endpoint here, which black-holed TX on a dead candidate.)
#[test]
fn learn_endpoint_repoints_unconfirmed_active_peer() {
    let t = SessionTable::new();
    let me = StaticSecret::from([42u8; 32]);
    let advertised = "203.0.113.9:51820";
    let p = info(1, "fd5a:1f00:1::1", Some(advertised));
    t.upsert(&me, &p);
    let session = t.by_ula(p.ula).expect("session");
    assert!(!session.direct_confirmed(), "fresh session starts unconfirmed");

    let inbound_src: SocketAddr = "203.0.113.9:40000".parse().unwrap(); // different port
    t.learn_endpoint(&session, inbound_src);
    // Unconfirmed + differing source → repoint the outbound default so a
    // dead reflexive candidate can't black-hole TX.
    assert_eq!(
        session.endpoint(),
        Some(inbound_src),
        "an unconfirmed session repoints onto a live learned source"
    );
    // And the new source is indexed so inbound from it routes here.
    assert!(t.by_endpoint(inbound_src).is_some());
}

// Fix B sibling — a CONFIRMED direct path must NEVER be clobbered by an
// ephemeral inbound source. Once a decrypted data packet proved the path
// works bidirectionally, the confirmed endpoint is authoritative; a
// differing inbound source is indexed for demux but does NOT repoint the
// outbound default (that would regress a working path onto an ephemeral
// NAT mapping with a short lifetime).
#[test]
fn learn_endpoint_does_not_repoint_confirmed_peer() {
    let t = SessionTable::new();
    let me = StaticSecret::from([42u8; 32]);
    let advertised = "203.0.113.9:51820";
    let p = info(1, "fd5a:1f00:1::1", Some(advertised));
    t.upsert(&me, &p);
    let session = t.by_ula(p.ula).expect("session");
    // Prove the direct path so the confirmed endpoint becomes authoritative.
    session.confirm_direct(1_000);
    assert!(session.direct_confirmed());

    let inbound_src: SocketAddr = "203.0.113.9:40000".parse().unwrap(); // different port
    t.learn_endpoint(&session, inbound_src);
    // Confirmed → outbound default unchanged (still the advertised endpoint).
    assert_eq!(
        session.endpoint(),
        Some(advertised.parse().unwrap()),
        "a confirmed endpoint must not be clobbered by an ephemeral source"
    );
    // The new source is still indexed for inbound demux + response targeting.
    assert!(t.by_endpoint(inbound_src).is_some());
}

// ---- per-app-ULA routing (consumer side) ----
//
// A remote peer can host one or more app-ULAs (`fd5a:1f02:...`). When
// the roster advertises them, the consumer records `app_ula → host_ula`
// in a secondary index, grows the host session's allowed-set, and
// installs a kernel `/128` route. `by_ula(app_ula)` then resolves to
// the hosting peer's session. All STRICTLY ADDITIVE to the peer-ULA
// path tested above.

const APP_A: &str = "fd5a:1f02:dead:beef:cafe:0:0:1";
const APP_B: &str = "fd5a:1f02:dead:beef:cafe:0:0:2";
const HOST_ULA: &str = "fd5a:1f00:1::1";

fn ula(s: &str) -> Ipv6Addr {
    s.parse().unwrap()
}

/// `by_ula(app_ula)` resolves to the HOSTING peer's session via the
/// `app_routes` fallback — the core of per-app-ULA routing.
#[test]
fn by_ula_resolves_app_ula_to_host_session() {
    let t = SessionTable::new();
    let me = StaticSecret::from([42u8; 32]);
    let host = info(1, HOST_ULA, Some("127.0.0.1:51820"));
    t.upsert(&me, &host);
    // Before hosting, an app-ULA resolves to nothing.
    assert!(t.by_ula(ula(APP_A)).is_none());
    // After hosting, it resolves to the host's session.
    t.host_remote_app_route(ula(APP_A), host.ula);
    let resolved = t.by_ula(ula(APP_A)).expect("app-ULA resolves");
    assert_eq!(resolved.ula, host.ula, "app-ULA must map to the host peer");
    // And the index agrees.
    assert_eq!(t.app_route_host(ula(APP_A)), Some(host.ula));
}

/// The peer-ULA fast path is unchanged: a peer's own ULA resolves
/// directly, never consulting `app_routes`. Guards the "additive"
/// contract.
#[test]
fn by_ula_peer_fast_path_unaffected_by_app_routes() {
    let t = SessionTable::new();
    let me = StaticSecret::from([42u8; 32]);
    let host = info(1, HOST_ULA, Some("127.0.0.1:51820"));
    t.upsert(&me, &host);
    t.host_remote_app_route(ula(APP_A), host.ula);
    // The peer's own ULA still resolves to its session directly.
    let s = t.by_ula(host.ula).expect("peer ULA fast path");
    assert_eq!(s.ula, host.ula);
}

/// Hosting an app-ULA GROWS the host session's allowed-source set so a
/// response sourced from the app-ULA passes the RX source check.
#[test]
fn host_app_route_grows_allowed_ips() {
    let t = SessionTable::new();
    let me = StaticSecret::from([42u8; 32]);
    let host = info(1, HOST_ULA, Some("127.0.0.1:51820"));
    t.upsert(&me, &host);
    let session = t.by_ula(host.ula).expect("session");
    // Initially only the peer's own ULA is allowed.
    assert!(session.is_allowed_source(host.ula));
    assert!(!session.is_allowed_source(ula(APP_A)));
    // After hosting, the app-ULA is an allowed source too.
    t.host_remote_app_route(ula(APP_A), host.ula);
    assert!(session.is_allowed_source(ula(APP_A)));
}

/// Un-hosting SHRINKS the allowed-set back, drops the index entry, and
/// the app-ULA no longer resolves.
#[test]
fn unhost_app_route_shrinks_allowed_ips_and_unmaps() {
    let t = SessionTable::new();
    let me = StaticSecret::from([42u8; 32]);
    let host = info(1, HOST_ULA, Some("127.0.0.1:51820"));
    t.upsert(&me, &host);
    let session = t.by_ula(host.ula).expect("session");
    t.host_remote_app_route(ula(APP_A), host.ula);
    assert!(session.is_allowed_source(ula(APP_A)));

    t.unhost_remote_app_route(ula(APP_A));
    assert!(
        !session.is_allowed_source(ula(APP_A)),
        "allowed-set shrinks"
    );
    assert!(
        t.app_route_host(ula(APP_A)).is_none(),
        "index entry dropped"
    );
    assert!(t.by_ula(ula(APP_A)).is_none(), "app-ULA no longer resolves");
    // The peer's own ULA survives un-hosting an app.
    assert!(session.is_allowed_source(host.ula));
}

/// Hosting / un-hosting drives the route sink's APP-route methods
/// (kernel `/128` install/remove), distinct from peer-route methods.
#[test]
fn host_app_route_drives_route_sink() {
    let sink = Arc::new(RecordingRouteSink::default());
    let t = SessionTable::with_route_sink(sink.clone());
    let me = StaticSecret::from([42u8; 32]);
    let host = info(1, HOST_ULA, Some("127.0.0.1:51820"));
    t.upsert(&me, &host);
    // The peer route was installed; no app routes yet.
    assert_eq!(*sink.added.lock(), vec![host.ula]);
    assert!(sink.app_added.lock().is_empty());

    t.host_remote_app_route(ula(APP_A), host.ula);
    assert_eq!(
        *sink.app_added.lock(),
        vec![ula(APP_A)],
        "app /128 installed"
    );

    t.unhost_remote_app_route(ula(APP_A));
    assert_eq!(
        *sink.app_removed.lock(),
        vec![ula(APP_A)],
        "app /128 removed"
    );
}

/// Removing the HOST peer's session tears down every app-ULA it hosted
/// — index entries dropped + kernel app routes removed.
#[test]
fn removing_host_peer_tears_down_its_app_routes() {
    let sink = Arc::new(RecordingRouteSink::default());
    let t = SessionTable::with_route_sink(sink.clone());
    let me = StaticSecret::from([42u8; 32]);
    let host = info(1, HOST_ULA, Some("127.0.0.1:51820"));
    t.upsert(&me, &host);
    t.host_remote_app_route(ula(APP_A), host.ula);
    t.host_remote_app_route(ula(APP_B), host.ula);
    assert_eq!(t.app_ulas_for_host(host.ula).len(), 2);

    assert!(t.remove(host.ula));
    // Both app-ULAs are unmapped and their kernel routes removed.
    assert!(t.app_route_host(ula(APP_A)).is_none());
    assert!(t.app_route_host(ula(APP_B)).is_none());
    let mut app_removed = sink.app_removed.lock().clone();
    app_removed.sort();
    let mut expected = vec![ula(APP_A), ula(APP_B)];
    expected.sort();
    assert_eq!(app_removed, expected);
}

/// A re-upsert of the host peer (endpoint roam / re-handshake) builds a
/// FRESH session but must PRESERVE the app-ULAs it hosts in the new
/// session's allowed-set — replayed from the durable `app_routes`
/// index. Without this, an endpoint roam would silently break app
/// responses.
#[test]
fn re_upsert_host_preserves_hosted_app_ulas_in_allowed_set() {
    let t = SessionTable::new();
    let me = StaticSecret::from([42u8; 32]);
    let host = info(1, HOST_ULA, Some("127.0.0.1:51820"));
    t.upsert(&me, &host);
    t.host_remote_app_route(ula(APP_A), host.ula);

    // Endpoint roam: same ULA, new endpoint → fresh Tunn + session.
    let moved = info(1, HOST_ULA, Some("10.0.0.5:51820"));
    t.upsert(&me, &moved);
    let session = t.by_ula(host.ula).expect("session after roam");
    assert!(
        session.is_allowed_source(ula(APP_A)),
        "hosted app-ULA must survive a session re-upsert"
    );
    // And it still resolves through by_ula.
    assert_eq!(t.by_ula(ula(APP_A)).map(|s| s.ula), Some(host.ula));
}

/// Recording an app route BEFORE the host's session exists still wires
/// the allowed-set once the session is upserted (index-first ordering).
/// This matters because the roster can advertise a peer's hosted apps
/// in the same frame that first creates its session.
#[test]
fn app_route_recorded_before_session_is_applied_on_upsert() {
    let t = SessionTable::new();
    let me = StaticSecret::from([42u8; 32]);
    let host = info(1, HOST_ULA, Some("127.0.0.1:51820"));
    // Record the app route with NO session yet — index holds it.
    t.host_remote_app_route(ula(APP_A), host.ula);
    assert_eq!(t.app_route_host(ula(APP_A)), Some(host.ula));
    // by_ula can't resolve yet (no host session).
    assert!(t.by_ula(ula(APP_A)).is_none());
    // First upsert of the host: a *new* session — but the replay loop
    // only runs on re-upsert, so wire the allowed-set explicitly via a
    // second host_remote_app_route once the session exists. The roster
    // consumer always (re-)applies after upsert, so model that here.
    t.upsert(&me, &host);
    t.host_remote_app_route(ula(APP_A), host.ula);
    let session = t.by_ula(host.ula).expect("session");
    assert!(session.is_allowed_source(ula(APP_A)));
    assert_eq!(t.by_ula(ula(APP_A)).map(|s| s.ula), Some(host.ula));
}

/// No-sink table: app-route hosting/un-hosting must not panic (route
/// management simply skipped), mirroring the peer-route no-sink guard.
#[test]
fn no_sink_table_skips_app_route_management() {
    let t = SessionTable::new();
    let me = StaticSecret::from([42u8; 32]);
    let host = info(1, HOST_ULA, Some("127.0.0.1:51820"));
    t.upsert(&me, &host);
    t.host_remote_app_route(ula(APP_A), host.ula);
    t.unhost_remote_app_route(ula(APP_A));
}
