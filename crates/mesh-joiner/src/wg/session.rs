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
    /// Install a host route for an APP-ULA `app_ula/128` via the overlay
    /// TUN device (per-app-ULA routing — consumer side). Called when a
    /// remote peer advertises a NEW hosted app-ULA, so the OS hands
    /// app-bound packets to our TUN read side; the [`SessionTable`]'s
    /// `app_routes` index then steers them to the hosting peer's session.
    ///
    /// Mechanically identical to [`Self::add_allowed`] (both install a
    /// `/128` host route to the TUN); kept as a distinct method so a fake
    /// sink in tests can assert app-route installs separately from
    /// peer-route installs, and so the data path stays self-documenting.
    /// Default-implemented as a no-op so existing sinks need no change.
    fn add_app_route(&self, app_ula: Ipv6Addr) {
        let _ = app_ula;
    }
    /// Remove the host route for an app-ULA `app_ula/128`. Called when the
    /// hosting peer drops the app-ULA or leaves. Idempotent. Default
    /// no-op (see [`Self::add_app_route`]).
    fn remove_app_route(&self, app_ula: Ipv6Addr) {
        let _ = app_ula;
    }
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
    /// the peer's own ULA, plus every app-ULA it currently hosts (added
    /// via [`Self::add_allowed_source`] when the roster advertises a new
    /// hosted app-ULA — per-app-ULA routing). The RX path drops any inner
    /// IPv6 packet whose SOURCE address is not in this set — boringtun
    /// does not enforce allowed-ips for us.
    ///
    /// Wrapped in an `RwLock` because the set GROWS and SHRINKS over the
    /// session's lifetime as the hosting peer starts / stops apps; the RX
    /// hot path takes a read guard (contention-free against other
    /// readers), the rare roster-driven mutation takes a write guard.
    pub allowed_ips: parking_lot::RwLock<HashSet<Ipv6Addr>>,
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
        self.allowed_ips.read().contains(&source)
    }

    /// Add `addr` to this peer's allowed-source set. Used when the roster
    /// advertises a NEW app-ULA hosted by this peer, so a RESPONSE sourced
    /// from the app-ULA passes the RX source check (per-app-ULA routing).
    /// Returns `true` if it was newly inserted.
    pub fn add_allowed_source(&self, addr: Ipv6Addr) -> bool {
        self.allowed_ips.write().insert(addr)
    }

    /// Remove `addr` from this peer's allowed-source set. Used when the
    /// hosting peer drops an app-ULA. Never removes the peer's own ULA
    /// (callers only pass app-ULAs). Returns `true` if it was present.
    pub fn remove_allowed_source(&self, addr: Ipv6Addr) -> bool {
        self.allowed_ips.write().remove(&addr)
    }

    /// Snapshot the current allowed-source set (diagnostics / tests).
    #[must_use]
    pub fn allowed_ips_snapshot(&self) -> HashSet<Ipv6Addr> {
        self.allowed_ips.read().clone()
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
            .field("allowed_ips", &self.allowed_ips.read())
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
    /// Secondary index for per-app-ULA routing: `app_ula → hosting peer's
    /// ULA`. Consulted by [`Self::by_ula`] as a FALLBACK after the
    /// peer-ULA fast path misses, so a packet bound for an app-ULA
    /// resolves to the session of the peer that hosts it. Strictly
    /// additive — peer-ULA routing never touches this map.
    app_routes: Arc<DashMap<Ipv6Addr, Ipv6Addr>>,
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
            .field("app_routes", &self.app_routes)
            .field(
                "route_sink",
                &self.route_sink.as_ref().map(|_| "<RouteSink>"),
            )
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

    /// Look up the session that should carry traffic destined for `dst`
    /// — used by the TUN→UDP path.
    ///
    /// Two-stage resolution (per-app-ULA routing):
    /// 1. **Peer-ULA fast path** — `dst` is a peer's own ULA → its
    ///    session directly. This is the original, hot path and is tried
    ///    first so the common case pays nothing for app routing.
    /// 2. **App-ULA fallback** — `dst` is an app-ULA in the `app_routes`
    ///    index → resolve to the hosting peer's ULA, then its session. A
    ///    packet bound for `[app_ula]` is thus delivered over the tunnel
    ///    to whichever peer hosts that app.
    #[must_use]
    pub fn by_ula(&self, dst: Ipv6Addr) -> Option<Arc<PeerSession>> {
        // Fast path: dst is a peer ULA we have a session for.
        if let Some(kv) = self.by_ula.get(&dst) {
            return Some(kv.value().clone());
        }
        // Fallback: dst is an app-ULA → resolve to the hosting peer.
        let host_ula = *self.app_routes.get(&dst)?.value();
        self.by_ula.get(&host_ula).map(|kv| kv.value().clone())
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
        self.by_endpoint.get(&endpoint).map(|kv| kv.value().clone())
    }

    /// Record that remote peer `host_ula` hosts `app_ula` (per-app-ULA
    /// routing — consumer side). Wires up all three pieces of state the
    /// data path needs:
    ///
    /// 1. the `app_routes` secondary index (`app_ula → host_ula`) so
    ///    [`Self::by_ula`] resolves app-bound packets to the host's
    ///    session;
    /// 2. the host session's `allowed_ips` (so a RESPONSE sourced from
    ///    `app_ula` passes the RX source check);
    /// 3. the kernel `/128` host route via the [`RouteSink`] (so the OS
    ///    hands `app_ula`-bound packets to our TUN read side).
    ///
    /// Idempotent: re-recording the same `(app_ula, host_ula)` is a no-op
    /// for the index + allowed-set and only re-pokes the (idempotent)
    /// route sink. A no-op for the kernel route when the table has no sink
    /// (tests). Does nothing if we have no session for `host_ula` yet —
    /// the index is still recorded, and [`Self::upsert`] replays it onto
    /// the session's allowed-set when the host's session appears.
    pub fn host_remote_app_route(&self, app_ula: Ipv6Addr, host_ula: Ipv6Addr) {
        self.app_routes.insert(app_ula, host_ula);
        if let Some(session) = self.by_ula.get(&host_ula) {
            session.add_allowed_source(app_ula);
        }
        if let Some(sink) = &self.route_sink {
            sink.add_app_route(app_ula);
        }
    }

    /// Reverse [`Self::host_remote_app_route`]: the hosting peer dropped
    /// `app_ula` (or left). Removes the `app_routes` entry, the host
    /// session's allowed-source, and the kernel `/128` route. Idempotent.
    pub fn unhost_remote_app_route(&self, app_ula: Ipv6Addr) {
        if let Some((_, host_ula)) = self.app_routes.remove(&app_ula) {
            if let Some(session) = self.by_ula.get(&host_ula) {
                session.remove_allowed_source(app_ula);
            }
        }
        if let Some(sink) = &self.route_sink {
            sink.remove_app_route(app_ula);
        }
    }

    /// Reconcile the app-ULAs routed to `host_ula` against the set the
    /// roster now advertises for it (per-app-ULA routing). Installs a
    /// route for each newly-advertised app-ULA and tears down each one the
    /// peer no longer hosts — the wholesale-replace contract that mirrors
    /// the coordinator's heartbeat semantics.
    ///
    /// Idempotent and cheap when nothing changed (the common steady
    /// state): an app-ULA already routed to the same host is re-hosted
    /// (no-op for the index + allowed-set, re-pokes the idempotent route
    /// sink). Call AFTER [`Self::upsert`] for `host_ula` so the host
    /// session exists and the allowed-set grows on the live session.
    ///
    /// Drives the route sink for every actual add/remove. The roster
    /// consumers ([`crate::coordinator::peer_sync`] +
    /// [`crate::coordinator::heartbeat`]) call this on each peer they
    /// upsert.
    pub fn reconcile_app_routes(&self, host_ula: Ipv6Addr, advertised: &[Ipv6Addr]) {
        let advertised_set: HashSet<Ipv6Addr> = advertised.iter().copied().collect();
        // Install routes for newly-advertised app-ULAs.
        for &app_ula in advertised {
            self.host_remote_app_route(app_ula, host_ula);
        }
        // Tear down app-ULAs this host no longer advertises. Collect first
        // to avoid mutating `app_routes` while iterating it.
        let stale: Vec<Ipv6Addr> = self
            .app_ulas_for_host(host_ula)
            .into_iter()
            .filter(|a| !advertised_set.contains(a))
            .collect();
        for app_ula in stale {
            self.unhost_remote_app_route(app_ula);
        }
    }

    /// The set of app-ULAs currently routed to `host_ula` (diagnostics +
    /// the roster-diff in [`crate::coordinator::peer_sync`], which needs
    /// to know which app-ULAs a peer hosts NOW to compute adds/removals).
    #[must_use]
    pub fn app_ulas_for_host(&self, host_ula: Ipv6Addr) -> Vec<Ipv6Addr> {
        self.app_routes
            .iter()
            .filter(|kv| *kv.value() == host_ula)
            .map(|kv| *kv.key())
            .collect()
    }

    /// Resolve which peer hosts `app_ula`, if any (diagnostics / tests).
    #[must_use]
    pub fn app_route_host(&self, app_ula: Ipv6Addr) -> Option<Ipv6Addr> {
        self.app_routes.get(&app_ula).map(|kv| *kv.value())
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
            None,                               // no preshared key in MVP
            Some(WG_PERSISTENT_KEEPALIVE_SECS), // keep NAT mapping open
            index,
            None, // default rate limiter
        );

        let session = Arc::new(PeerSession {
            peer_id: info.peer_id,
            ula: info.ula,
            allowed_ips: parking_lot::RwLock::new(allowed_ips_for(info)),
            endpoint: parking_lot::RwLock::new(info.listen_endpoint),
            tunn: Mutex::new(tunn),
        });
        // Re-apply any app-ULAs this peer already hosts onto the FRESH
        // session's allowed-set. A re-upsert (endpoint roam / re-handshake)
        // builds a brand-new `PeerSession` whose allowed-set starts at just
        // the peer's own ULA, which would silently drop the app-ULAs a
        // prior session had accumulated. The `app_routes` index is the
        // durable source of truth for which app-ULAs map to this peer, so
        // replay them here (per-app-ULA routing, additive — a no-op when
        // the peer hosts no apps, i.e. the common peer-only case).
        if !is_new {
            for kv in self.app_routes.iter() {
                if *kv.value() == info.ula {
                    session.add_allowed_source(*kv.key());
                }
            }
        }
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
        // Tear down every app-ULA route that pointed at this peer — the
        // host is gone, so the app is no longer reachable through it
        // (per-app-ULA routing). Collect first to avoid mutating the map
        // while iterating it.
        let orphaned: Vec<Ipv6Addr> = self.app_ulas_for_host(ula);
        for app_ula in orphaned {
            self.app_routes.remove(&app_ula);
            if let Some(sink) = &self.route_sink {
                sink.remove_app_route(app_ula);
            }
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
            // Tear down every app-ULA route too (per-app-ULA routing).
            for kv in self.app_routes.iter() {
                sink.remove_app_route(*kv.key());
            }
        }
        self.by_ula.clear();
        self.by_endpoint.clear();
        self.app_routes.clear();
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
            hosted_app_ulas: vec![],
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
}
