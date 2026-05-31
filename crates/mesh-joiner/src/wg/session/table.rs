//! Shared registry of all live per-peer [`PeerSession`]s plus
//! per-app-ULA secondary routing.
//!
//! Maintains three indexes:
//!
//! * `by_ula: DashMap<Ipv6Addr, Arc<PeerSession>>` — the TX fast path
//!   (TUN-read side: peer ULA → session).
//! * `by_endpoint: DashMap<SocketAddr, Arc<PeerSession>>` — the RX
//!   demux (UDP-recv side: source addr → session).
//! * `app_routes: DashMap<Ipv6Addr, Ipv6Addr>` — secondary, additive:
//!   `app_ula → hosting peer ula`. Consulted as a fallback in
//!   [`SessionTable::by_ula`].

use super::WG_PERSISTENT_KEEPALIVE_SECS;
use super::peer_session::{PeerSession, allowed_ips_for};
use super::route_sink::RouteSink;
use crate::peer::PeerInfo;
use boringtun::noise::Tunn;
use dashmap::DashMap;
use rand_core::{OsRng, RngCore};
use std::collections::HashSet;
use std::net::{Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::sync::Mutex;
use x25519_dalek::{PublicKey, StaticSecret};

/// Shared registry of active per-peer sessions. Cheap to clone.
#[derive(Clone, Default)]
pub struct SessionTable {
    /// Lookup by ULA — used by the TUN-read path to find the session
    /// for a given destination address.
    by_ula: Arc<DashMap<Ipv6Addr, Arc<PeerSession>>>,
    /// Lookup by source UDP endpoint — used by the UDP-recv path to
    /// route an inbound ciphertext datagram to the right `Tunn`.
    by_endpoint: Arc<DashMap<SocketAddr, Arc<PeerSession>>>,
    /// Lookup by the peer's raw WG public key — used by the relay RX path
    /// to demux an inbound relay frame (keyed by source pubkey) to the
    /// right session. Populated on every [`Self::upsert`] and dropped on
    /// [`Self::remove`] / [`Self::clear`].
    by_pubkey: Arc<DashMap<[u8; 32], Arc<PeerSession>>>,
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
            .field("by_pubkey", &self.by_pubkey.len())
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

    /// Look up a session by its peer's raw WG public key (relay RX demux).
    /// The relay read-loop receives a frame whose 32-byte prefix is the
    /// SOURCE pubkey and resolves it here to find the `Tunn` to feed.
    #[must_use]
    pub fn by_pubkey(&self, pubkey: [u8; 32]) -> Option<Arc<PeerSession>> {
        self.by_pubkey.get(&pubkey).map(|kv| kv.value().clone())
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
            // Drop the prior pubkey index entry when the peer rotated its
            // key (same ULA, new pubkey) so a stale pubkey → session
            // pointer never lingers. A re-upsert with the same key is
            // re-inserted below, so this is safe either way.
            if old.peer_pubkey != info.wg_public_key {
                self.by_pubkey.remove(&old.peer_pubkey);
            }
        }

        let mut idx_bytes = [0u8; 4];
        OsRng.fill_bytes(&mut idx_bytes);
        let index = u32::from_le_bytes(idx_bytes);

        // The x25519 `PublicKey` boringtun needs; distinct from the raw
        // `[u8; 32]` we store on the session for relay demux below.
        let tunn_pubkey = PublicKey::from(info.wg_public_key);
        let tunn = Tunn::new(
            our_private.clone(),
            tunn_pubkey,
            None,                               // no preshared key in MVP
            Some(WG_PERSISTENT_KEEPALIVE_SECS), // keep NAT mapping open
            index,
            None, // default rate limiter
        );

        let session = Arc::new(PeerSession {
            peer_id: info.peer_id,
            ula: info.ula,
            peer_pubkey: info.wg_public_key,
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
        self.by_pubkey.insert(info.wg_public_key, session.clone());
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
        self.by_pubkey.remove(&session.peer_pubkey);
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
        self.by_pubkey.clear();
        self.app_routes.clear();
    }
}
