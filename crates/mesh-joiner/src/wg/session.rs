// Same intentional pattern as `mesh-fabric::wireguard`: we acquire the
// tunnel mutex, copy the bytes out, drop the mutex *before* the await.
// Clippy's `significant_drop_tightening` lint flags this as drop-earlier
// noise — the lock is already block-scoped, which is the point.
#![allow(clippy::significant_drop_tightening)]

//! Per-peer `boringtun::noise::Tunn` lifecycle.
//!
//! The joiner owns one [`SessionTable`] keyed by the peer's ULA. Each
//! [`PeerSession`] wraps a single `Tunn` plus the metadata needed to
//! route ciphertext to the right UDP endpoint.
//!
//! # Why a shared table instead of one task per peer?
//!
//! Spawning N tasks for N peers gives us N socket clones to manage and
//! makes the inbound path messy (which task owns the UDP recv loop?).
//! Instead we follow the [`tabbify_mesh_fabric::wireguard::WireGuardFabric`]
//! pattern: one socket, one receive loop, one timer loop, all peers
//! multiplexed by source endpoint on RX and by ULA on TX. The
//! receive/timer loops live in [`crate::joiner`] because they need
//! handles to both this table and the TUN device.
//!
//! Tests in this module exercise the table-management API; the actual
//! ciphertext flow is integration-tested through `mesh-fabric`'s
//! existing `wireguard_udp.rs` suite, which exercises the same
//! boringtun calls we make here.

use crate::peer::PeerInfo;
use boringtun::noise::{Tunn, TunnResult};
use dashmap::DashMap;
use rand_core::{OsRng, RngCore};
use std::collections::HashSet;
use std::net::{Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::sync::Mutex;
use x25519_dalek::{PublicKey, StaticSecret};

/// `WireGuard` persistent-keepalive interval (seconds), applied to EVERY
/// peer session.
///
/// Crucial for `NAT` traversal: a keepalive every 25s keeps the `NAT`'s
/// UDP mapping for our `WireGuard` socket open even when no data flows, so
/// the reflexive endpoint other peers dial stays valid and `boringtun`'s
/// endpoint roaming has live traffic to latch onto. 25s is the canonical
/// `WireGuard` default and matches `mesh-fabric::wireguard`.
pub const WG_PERSISTENT_KEEPALIVE_SECS: u16 = 25;

/// Sink that mirrors a peer's allowed `/128`s into the kernel routing
/// table (spec §5.5 — per-peer allowed-ips, TX direction).
///
/// The [`SessionTable`] holds an optional implementor and calls it on
/// every session insert / removal so the set of `/128`s routed at the
/// host TUN device tracks exactly the set of peers we currently have a
/// session with — never the blanket `/48`. The real implementor
/// (`crate::platform::TunRouteSink`) shells out to `ip` / `route`; unit
/// tests use a recording fake (or `None` to skip routing entirely).
///
/// Object-safe so the table can store it behind `Arc<dyn RouteSink>`
/// without leaking a concrete platform type into the data plane.
pub trait RouteSink: Send + Sync {
    /// Install a host route for `ula/128` via the overlay TUN device.
    /// Called when a session for `ula` is first inserted. Idempotent on
    /// the implementor's side (re-adding an existing route is a no-op).
    fn add_allowed(&self, ula: Ipv6Addr);
    /// Remove the host route for `ula/128`. Called when the session is
    /// removed. Idempotent (removing an absent route is a no-op).
    fn remove_allowed(&self, ula: Ipv6Addr);
}

/// One peer's encryption state + routing metadata.
pub struct PeerSession {
    /// The peer's coordinator-assigned id. Useful for tracing.
    pub peer_id: uuid::Uuid,
    /// IPv6 ULA assigned to this peer.
    pub ula: Ipv6Addr,
    /// The set of `/128` source addresses this peer is permitted to use
    /// (spec §5.5 — cryptokey-routing invariant). Built from the
    /// coordinator's roster at [`SessionTable::upsert`] time: at minimum
    /// the peer's own ULA, plus any extra `/128`s policy permits it to
    /// represent (carried on [`PeerInfo`] in a later phase). The RX path
    /// drops any inner IPv6 packet whose SOURCE address is not in this
    /// set — boringtun does not enforce allowed-ips for us.
    pub allowed_ips: HashSet<Ipv6Addr>,
    /// UDP endpoint to send ciphertext to. `None` means we don't yet
    /// know how to reach this peer — either they registered passively
    /// (no advertised endpoint) OR we haven't learned their actual
    /// source address yet. The endpoint gets LEARNED + updated in
    /// `SessionTable::learn_endpoint` when we successfully decapsulate
    /// a packet from a new source address (`WireGuard`'s roaming
    /// behaviour — peer's NAT mapping changes, we follow).
    pub endpoint: parking_lot::RwLock<Option<SocketAddr>>,
    /// Boringtun session state. Wrapped in a tokio Mutex so async
    /// send + receive halves can serialise access without holding a
    /// guard across socket I/O.
    pub tunn: Mutex<Tunn>,
}

impl PeerSession {
    /// Snapshot the current endpoint. Hot path; uses an `RwLock` read
    /// guard which is contention-free against other readers.
    pub fn endpoint(&self) -> Option<SocketAddr> {
        *self.endpoint.read()
    }

    /// `true` iff `source` is one of the `/128`s this peer is allowed to
    /// use. The RX path calls this on every decapsulated inner packet to
    /// enforce `WireGuard`'s cryptokey-routing invariant (spec §5.5).
    #[must_use]
    pub fn is_allowed_source(&self, source: Ipv6Addr) -> bool {
        self.allowed_ips.contains(&source)
    }
}

/// Derive the allowed `/128` set for a peer from its roster record.
///
/// MVP: exactly the peer's own ULA. The signature takes the whole
/// [`PeerInfo`] so a later phase can fold in extra policy-permitted
/// `/128`s (e.g. a shared-service address a peer is allowed to source)
/// without churning callers.
fn allowed_ips_for(info: &PeerInfo) -> HashSet<Ipv6Addr> {
    let mut set = HashSet::with_capacity(1);
    set.insert(info.ula);
    set
}

impl std::fmt::Debug for PeerSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerSession")
            .field("peer_id", &self.peer_id)
            .field("ula", &self.ula)
            .field("allowed_ips", &self.allowed_ips)
            .field("endpoint", &self.endpoint())
            .field("tunn", &"<Tunn>")
            .finish()
    }
}

/// Shared registry of active per-peer sessions. Cheap to clone.
#[derive(Clone, Default)]
pub struct SessionTable {
    /// Lookup by ULA — used by the TUN-read path to find the session
    /// for a given destination address.
    by_ula: Arc<DashMap<Ipv6Addr, Arc<PeerSession>>>,
    /// Lookup by source UDP endpoint — used by the UDP-recv path to
    /// route an inbound ciphertext datagram to the right `Tunn`.
    by_endpoint: Arc<DashMap<SocketAddr, Arc<PeerSession>>>,
    /// Optional sink that mirrors per-peer `/128`s into the kernel
    /// routing table (spec §5.5, TX scoping). `None` (the default) skips
    /// route management entirely — used by unit tests and by callers
    /// that manage routes out of band.
    route_sink: Option<Arc<dyn RouteSink>>,
}

impl std::fmt::Debug for SessionTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionTable")
            .field("by_ula", &self.by_ula)
            .field("by_endpoint", &self.by_endpoint)
            .field("route_sink", &self.route_sink.as_ref().map(|_| "<RouteSink>"))
            .finish()
    }
}

impl SessionTable {
    /// Construct an empty table with no route sink — routes are not
    /// mirrored to the kernel. Used by tests and callers that manage
    /// routing themselves.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct an empty table wired to `route_sink`. Every session
    /// insert / removal installs / removes the corresponding `/128`
    /// host route (spec §5.5 — TX route scoping replaces the blanket
    /// `/48`). The joiner uses this; tests use [`Self::new`].
    #[must_use]
    pub fn with_route_sink(route_sink: Arc<dyn RouteSink>) -> Self {
        Self {
            route_sink: Some(route_sink),
            ..Self::default()
        }
    }

    /// Number of registered sessions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_ula.len()
    }

    /// `true` if no sessions are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_ula.is_empty()
    }

    /// All known peer ULAs (for snapshots / diagnostics).
    pub fn ulas(&self) -> Vec<Ipv6Addr> {
        self.by_ula.iter().map(|kv| *kv.key()).collect()
    }

    /// Look up a session by ULA — used by the TUN→UDP path.
    #[must_use]
    pub fn by_ula(&self, ula: Ipv6Addr) -> Option<Arc<PeerSession>> {
        self.by_ula.get(&ula).map(|kv| kv.value().clone())
    }

    /// Record `source` as a fast-path lookup alias for `session`. Used
    /// when the UDP recv loop successfully decapsulates a packet from
    /// an unexpected source addr — common in NAT / port-forward
    /// topologies where the peer's source port differs from its
    /// advertised endpoint.
    ///
    /// IMPORTANT: this does NOT overwrite the session's primary
    /// `endpoint`. The primary endpoint is the peer's *advertised*
    /// reachable address — the one the coordinator stored — and is
    /// stable for new outbound traffic. The ephemeral source addr seen
    /// on inbound is good only for keeping the existing conntrack
    /// flow alive (e.g. our response to an incoming handshake). New
    /// Mac-initiated traffic must still target the advertised port
    /// because the NAT mapping for the ephemeral source has limited
    /// lifetime. The exception: peers that registered passively (no
    /// advertised endpoint) — for those we promote the learned source
    /// to be authoritative since it's the only address we have.
    pub fn learn_endpoint(&self, session: &Arc<PeerSession>, source: SocketAddr) {
        // Always index the source for inbound demux + response targeting.
        self.by_endpoint.insert(source, session.clone());
        // Only adopt as the outbound default when we don't have a
        // stable advertised endpoint already.
        let mut guard = session.endpoint.write();
        if guard.is_none() {
            *guard = Some(source);
        }
    }

    /// Look up a session by the source UDP endpoint we saw a datagram
    /// arrive from — used by the UDP→TUN path.
    #[must_use]
    pub fn by_endpoint(&self, endpoint: SocketAddr) -> Option<Arc<PeerSession>> {
        self.by_endpoint
            .get(&endpoint)
            .map(|kv| kv.value().clone())
    }

    /// Iterate all sessions — needed for the timer loop which has to
    /// poke every `Tunn::update_timers` periodically.
    pub fn snapshot(&self) -> Vec<Arc<PeerSession>> {
        self.by_ula.iter().map(|kv| kv.value().clone()).collect()
    }

    /// Insert or replace a peer's session.
    ///
    /// Building a fresh `Tunn` on every insert is correct (replacing an
    /// existing session means the peer rotated its key or the
    /// coordinator re-issued its endpoint), even though it means we
    /// re-handshake. Stage 2 may keep the session warm across endpoint
    /// changes; that requires API knowledge boringtun 0.7 does not
    /// stably expose.
    pub fn upsert(&self, our_private: &StaticSecret, info: &PeerInfo) {
        // Drop the old endpoint binding before installing the new one
        // so a stale (endpoint -> session) pointer never lingers when a
        // peer changes address. `is_new` tracks whether this ULA had no
        // prior session — only then do we install a fresh `/128` route
        // (re-handshakes for an already-routed ULA must not churn the
        // kernel routing table).
        let prior = self.by_ula.get(&info.ula).map(|kv| kv.value().clone());
        let is_new = prior.is_none();
        if let Some(old) = prior {
            if let Some(addr) = old.endpoint() {
                self.by_endpoint.remove(&addr);
            }
        }

        let mut idx_bytes = [0u8; 4];
        OsRng.fill_bytes(&mut idx_bytes);
        let index = u32::from_le_bytes(idx_bytes);

        let peer_pubkey = PublicKey::from(info.wg_public_key);
        let tunn = Tunn::new(
            our_private.clone(),
            peer_pubkey,
            None,                                 // no preshared key in MVP
            Some(WG_PERSISTENT_KEEPALIVE_SECS),   // keep NAT mapping open
            index,
            None,                                 // default rate limiter
        );

        let session = Arc::new(PeerSession {
            peer_id: info.peer_id,
            ula: info.ula,
            allowed_ips: allowed_ips_for(info),
            endpoint: parking_lot::RwLock::new(info.listen_endpoint),
            tunn: Mutex::new(tunn),
        });
        self.by_ula.insert(info.ula, session.clone());
        if let Some(addr) = info.listen_endpoint {
            self.by_endpoint.insert(addr, session);
        }
        // TX route scoping: install a per-peer `/128` host route only on
        // first insert (spec §5.5). The blanket `/48` route is gone.
        if is_new {
            if let Some(sink) = &self.route_sink {
                sink.add_allowed(info.ula);
            }
        }
    }

    /// Drop a peer's session by ULA. Returns `true` if anything was
    /// removed (useful for tests).
    pub fn remove(&self, ula: Ipv6Addr) -> bool {
        let Some((_, session)) = self.by_ula.remove(&ula) else {
            return false;
        };
        if let Some(addr) = session.endpoint() {
            self.by_endpoint.remove(&addr);
        }
        // Tear down the peer's `/128` route now that no session can use it.
        if let Some(sink) = &self.route_sink {
            sink.remove_allowed(ula);
        }
        true
    }

    /// Drop every session — used during [`crate::Joiner::leave`]. Tears
    /// down every per-peer `/128` route before clearing the indexes so
    /// the kernel routing table doesn't retain stale overlay routes.
    pub fn clear(&self) {
        if let Some(sink) = &self.route_sink {
            for ula in self.ulas() {
                sink.remove_allowed(ula);
            }
        }
        self.by_ula.clear();
        self.by_endpoint.clear();
    }
}

/// Outcome of a single `Tunn` operation translated into an owned form
/// so the caller can drop the tunnel lock before awaiting socket I/O.
/// Mirrors the pattern in `mesh-fabric::wireguard`.
#[derive(Debug)]
pub enum WgAction {
    /// Send the contained bytes over UDP to the peer's endpoint.
    SendToPeer(Vec<u8>),
    /// Deliver the contained decrypted IPv6 packet to the TUN device.
    DeliverToTun(Vec<u8>),
    /// boringtun handled the datagram internally; nothing further to do.
    Nothing,
    /// boringtun reported an error — caller should log and continue.
    Error(String),
}

/// Translate boringtun's `TunnResult` into an owned, lock-free form.
/// `WriteToTunnelV4` collapses to `Nothing` because our overlay is
/// IPv6-only.
#[must_use]
pub fn classify_tunn_result(res: TunnResult<'_>) -> WgAction {
    match res {
        TunnResult::Err(e) => WgAction::Error(format!("{e:?}")),
        TunnResult::WriteToNetwork(bytes) => WgAction::SendToPeer(bytes.to_vec()),
        TunnResult::WriteToTunnelV6(bytes, _) => WgAction::DeliverToTun(bytes.to_vec()),
        // boringtun's `Done` plus any v4-tunnel write (we're v6-only)
        // collapse to "nothing for us to forward".
        TunnResult::Done | TunnResult::WriteToTunnelV4(_, _) => WgAction::Nothing,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use parking_lot::Mutex as PlMutex;
    use uuid::Uuid;

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
            joined_at_micros: 0,
        }
    }

    /// Records every add/remove the table pushes so route-scoping tests
    /// can assert the kernel would see exactly the right `/128`s.
    #[derive(Default)]
    struct RecordingRouteSink {
        added: PlMutex<Vec<Ipv6Addr>>,
        removed: PlMutex<Vec<Ipv6Addr>>,
    }
    impl RouteSink for RecordingRouteSink {
        fn add_allowed(&self, ula: Ipv6Addr) {
            self.added.lock().push(ula);
        }
        fn remove_allowed(&self, ula: Ipv6Addr) {
            self.removed.lock().push(ula);
        }
    }

    #[test]
    fn empty_table_starts_empty() {
        let t = SessionTable::new();
        assert!(t.is_empty());
        assert_eq!(t.len(), 0);
        assert!(t.snapshot().is_empty());
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

    // Endpoint roaming, active-peer case: a peer that already has a stable
    // advertised endpoint (e.g. its reflexive endpoint from the
    // coordinator) keeps that endpoint as the OUTBOUND default even after
    // we observe inbound from a different source port — but the new source
    // IS indexed for inbound demux + response targeting. This matches
    // WireGuard semantics: new outbound traffic uses the advertised
    // endpoint, while the ephemeral inbound source keeps the existing flow
    // alive.
    #[test]
    fn learn_endpoint_indexes_but_keeps_advertised_default_for_active_peer() {
        let t = SessionTable::new();
        let me = StaticSecret::from([42u8; 32]);
        let advertised = "203.0.113.9:51820";
        let p = info(1, "fd5a:1f00:1::1", Some(advertised));
        t.upsert(&me, &p);
        let session = t.by_ula(p.ula).expect("session");

        let inbound_src: SocketAddr = "203.0.113.9:40000".parse().unwrap(); // different port
        t.learn_endpoint(&session, inbound_src);
        // Outbound default unchanged (still the advertised endpoint).
        assert_eq!(
            session.endpoint(),
            Some(advertised.parse().unwrap()),
            "advertised endpoint must remain the outbound default"
        );
        // But the new source is indexed so inbound from it routes here.
        assert!(t.by_endpoint(inbound_src).is_some());
    }
}
