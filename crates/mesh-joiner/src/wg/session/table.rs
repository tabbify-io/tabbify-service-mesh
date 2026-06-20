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
use crate::relay::RelayHandle;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use boringtun::noise::Tunn;
use dashmap::DashMap;
use rand_core::{OsRng, RngCore};
use std::collections::HashSet;
use std::net::{Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
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
    /// Optional relay handle (Stage-3 connectivity floor). When `Some`,
    /// the WG TX seams forward a packet through the relay instead of
    /// silently dropping it when no direct endpoint is known. `None` (the
    /// default) preserves the pre-relay drop behaviour — used by tests and
    /// by a joiner started with `--no-relay`.
    relay: Option<RelayHandle>,
    /// Unix-micros of the LAST successful WG decap from ANY peer over ANY
    /// path — direct UDP **or** relay (the keystone, spec §2/§5 Track K). A
    /// black-hole node (control-plane heartbeat alive, WG decap-RX zero) has a
    /// stale value here while everything else stays green; that is the only
    /// signal that distinguishes "alive" from "data-plane dead". Refreshed in
    /// `process_inbound_datagram` for BOTH paths — fixing the `via_direct=false`
    /// relay blind spot (`relay/client.rs:391`) where relayed RX never touched
    /// any liveness clock. `Arc<AtomicI64>` so every cheap-clone of the table
    /// (udp/relay/timer loops) refreshes the SAME process-global value. `0` =
    /// "never decapsulated a frame".
    last_inbound_data_frame_ts: Arc<AtomicI64>,
    /// Unix-micros of the LAST `send_wire` attempt to ANY peer. Pairs with
    /// `last_inbound_data_frame_ts` to gate `dataplane_healthy`: a node that
    /// has NOT tried to send since the last sample is idle and must never be
    /// judged a black hole (no TX ⇒ no expectation of RX). `0` = "never sent".
    last_send_attempt_ts: Arc<AtomicI64>,
}

/// Monotonic relaxed store: set `clock` to `now` only if `now` is later than
/// the current value, so an out-of-order stamp from a concurrent loop never
/// rewinds a liveness clock. Relaxed throughout — the clocks gate a
/// seconds-scale staleness check, so losing one update under a race is inert.
fn store_max(clock: &AtomicI64, now: i64) {
    let mut cur = clock.load(Ordering::Relaxed);
    while now > cur {
        match clock.compare_exchange_weak(cur, now, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(observed) => cur = observed,
        }
    }
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
            .field("relay", &self.relay.as_ref().map(|_| "<RelayHandle>"))
            .field(
                "last_inbound_data_frame_ts",
                &self.last_inbound_data_frame_ts.load(Ordering::Relaxed),
            )
            .field(
                "last_send_attempt_ts",
                &self.last_send_attempt_ts.load(Ordering::Relaxed),
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

    /// Construct an empty table wired to `route_sink` AND an optional
    /// relay handle (Stage-3 connectivity floor). When `relay` is `Some`,
    /// the WG TX seams forward a packet through the relay instead of
    /// dropping it when no direct endpoint is known. The joiner passes
    /// `Some` when relay is enabled; `with_route_sink` (relay `None`) and
    /// `new` stay the no-relay paths.
    #[must_use]
    pub fn with_route_sink_and_relay(
        route_sink: Arc<dyn RouteSink>,
        relay: Option<RelayHandle>,
    ) -> Self {
        Self {
            route_sink: Some(route_sink),
            relay,
            ..Self::default()
        }
    }

    /// Borrow the relay handle, if this table was built with one. The WG
    /// TX/timer loops call this to relay a packet when no direct endpoint
    /// is known.
    #[must_use]
    pub const fn relay(&self) -> Option<&RelayHandle> {
        self.relay.as_ref()
    }

    /// Refresh the data-plane liveness clock: stamp `now_micros` as the time
    /// of the last successful inbound WG decap, MONOTONICALLY (an out-of-order
    /// stamp from a concurrent loop never rewinds it). Called from the WG RX
    /// seam for BOTH direct UDP and relay decap (Track K keystone) — a relayed
    /// frame must NOT confirm a DIRECT path (that stays `via_direct`-gated on
    /// the session) but DOES prove the data plane is alive, so it refreshes
    /// THIS table-global clock. A relaxed CAS-free max is fine: the worst race
    /// loses one stamp of granularity, which is inert against the seconds-scale
    /// staleness threshold.
    pub fn note_inbound_data_frame(&self, now_micros: i64) {
        store_max(&self.last_inbound_data_frame_ts, now_micros);
    }

    /// Stamp `now_micros` as the time of the last `send_wire` attempt
    /// (monotonic, same rationale as `note_inbound_data_frame`). Gates the
    /// idle-is-healthy rule in `dataplane_healthy`.
    pub fn note_send_attempt(&self, now_micros: i64) {
        store_max(&self.last_send_attempt_ts, now_micros);
    }

    /// Unix-micros of the last successful inbound WG decap (any path). `0`
    /// means none yet. Read by `dataplane_healthy` and the diagnostics
    /// surface.
    #[must_use]
    pub fn last_inbound_data_frame_ts(&self) -> i64 {
        self.last_inbound_data_frame_ts.load(Ordering::Relaxed)
    }

    /// Unix-micros of the last `send_wire` attempt. `0` means none yet.
    #[must_use]
    pub fn last_send_attempt_ts(&self) -> i64 {
        self.last_send_attempt_ts.load(Ordering::Relaxed)
    }

    /// Track K data-plane liveness decision (pure; `now`/`threshold` injected
    /// for testability). Returns `true` (healthy) unless this node is
    /// DEMONSTRABLY a black hole:
    ///
    /// * **No peers** ⇒ healthy (nothing to be dead toward).
    /// * **Idle** (we have NOT sent since the last inbound frame, i.e.
    ///   `last_send_attempt_ts <= last_inbound_data_frame_ts`) ⇒ healthy. A
    ///   quiet node that isn't transmitting has no reason to expect RX, so it
    ///   must never be judged dead — fail-open (spec §7) so Track B's watchdog
    ///   never thrashes an idle worker.
    /// * **Sending but RX stale** (we sent after the last inbound AND that
    ///   inbound is older than `threshold_micros`) ⇒ UNHEALTHY. This is the
    ///   MSI black-hole signature: frames go out (`send_wire`), zero return
    ///   decap.
    ///
    /// Read-only: never mutates any state. A relaxed read of each clock is
    /// fine — a one-tick-stale value at worst shifts the verdict by one sample.
    #[must_use]
    pub fn dataplane_healthy(&self, now_micros: i64, threshold_micros: i64) -> bool {
        // No peers → nothing to be a black hole toward.
        if self.is_empty() {
            return true;
        }
        let last_rx = self.last_inbound_data_frame_ts();
        let last_send = self.last_send_attempt_ts();
        // Idle: no send since the last inbound (or never sent) → healthy.
        if last_send <= last_rx {
            return true;
        }
        // Sending: healthy iff the last inbound is within the freshness window.
        now_micros.saturating_sub(last_rx) < threshold_micros
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
    /// IMPORTANT: a CONFIRMED-direct endpoint is never clobbered. Once a
    /// decrypted data packet proved the path works bidirectionally, the
    /// confirmed endpoint is authoritative and an ephemeral inbound source
    /// (good only for keeping a transient NAT mapping alive) must not
    /// regress it.
    ///
    /// While the session is UNCONFIRMED, however, the "advertised"
    /// endpoint the coordinator stored is only a CANDIDATE — and for a
    /// no-inbound-port peer (a container netns, a symmetric-NAT peer whose
    /// reflexive endpoint we can't actually reach) it may be a BLACK HOLE.
    /// A real inbound datagram from a different source proves a live return
    /// path exists, so we adopt that source as the outbound default. This
    /// lets a relayed inbound repoint an unconfirmed session off a
    /// hole-punch-written dead endpoint if a genuine direct path appears.
    ///
    /// Adoption rule: take the learned source as the outbound default when
    /// the endpoint is unset, OR when the session is unconfirmed AND the
    /// source differs from the current candidate. Passive peers (no
    /// advertised endpoint) are the `is_none()` case.
    pub fn learn_endpoint(&self, session: &Arc<PeerSession>, source: SocketAddr) {
        // Always index the source for inbound demux + response targeting.
        self.by_endpoint.insert(source, session.clone());
        // Adopt as the outbound default when (a) we have no endpoint yet,
        // or (b) the path is unconfirmed and this is a NEW source — never
        // clobber a confirmed-direct endpoint with an ephemeral source.
        let mut guard = session.endpoint.write();
        if guard.is_none() || (!session.direct_confirmed() && *guard != Some(source)) {
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
    /// 3. an `add_app_route` poke at the [`RouteSink`]. NOTE: the
    ///    production `TunRouteSink` currently inherits the trait's NO-OP
    ///    default for app routes — no kernel `/128` is installed yet, so
    ///    consumer-side reachability of an app-ULA relies on the hosting
    ///    runner's own peer ULA *being* the app-ULA (the fly-model case,
    ///    covered by `add_allowed`). A future `TunRouteSink` override
    ///    must honor its source scope (route into the scoped table).
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
    /// A FRESH `Tunn` is built only when there is no prior session for this
    /// ULA, OR when the peer ROTATED its WG key (same ULA, new pubkey — the
    /// old `Tunn` is keyed to a dead identity and could never complete a
    /// handshake). On an endpoint- / metadata-only change with the SAME
    /// pubkey the existing session is KEPT IN PLACE — its `Tunn` (and the
    /// boringtun handshake/rekey timer) survives so a needless re-handshake
    /// isn't forced on every ~20s `peer_updated`, and the timer-driven
    /// relay-retransmit backstop stays reliable. Endpoint roaming is
    /// handled out of band (`send_wire`'s `endpoint()` read +
    /// [`Self::learn_endpoint`] + `downgrade_direct_if_stale`), so keeping
    /// the `Tunn` across an endpoint-only change is correct.
    pub fn upsert(&self, our_private: &StaticSecret, info: &PeerInfo) {
        let prior = self.by_ula.get(&info.ula).map(|kv| kv.value().clone());
        // SAME-pubkey re-upsert (endpoint / metadata only): keep the live
        // session + Tunn, repointing the endpoint indexes in place.
        if let Some(old) = &prior {
            if old.peer_pubkey == info.wg_public_key {
                self.update_in_place(old, info);
                return;
            }
        }

        // From here on we BUILD a fresh session: either the first insert
        // for this ULA (`is_new`) or a key rotation (drop the stale state).
        let is_new = prior.is_none();
        if let Some(old) = prior {
            // Key rotation (same ULA, new pubkey). Drop the stale endpoint
            // binding and the stale pubkey alias so no dead pointer lingers.
            if let Some(addr) = old.endpoint() {
                self.by_endpoint.remove(&addr);
            }
            // Identity rotation: surface the key change so a relay-frame
            // drop "no session for source pubkey" can be correlated with
            // the peer that just re-keyed (observability — no behaviour
            // change; the index roll-over already happens below).
            tracing::info!(
                event = "peer_rekey",
                peer_id = %info.peer_id,
                ula = %info.ula,
                old_pubkey = %B64URL.encode(old.peer_pubkey),
                new_pubkey = %B64URL.encode(info.wg_public_key),
                "session: peer rotated its WG key — rolling over the pubkey index"
            );
            self.by_pubkey.remove(&old.peer_pubkey);
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
            // A fresh session always starts UNCONFIRMED — even a re-upsert
            // (endpoint roam / re-handshake) must re-prove the direct path
            // before TX leaves the relay floor. The advertised endpoint is
            // only a candidate until a decrypted data packet confirms it.
            direct_confirmed: AtomicBool::new(false),
            last_direct_rx_micros: AtomicI64::new(0),
            last_probe_micros: AtomicI64::new(0),
            tunn: Mutex::new(tunn),
        });
        // Re-apply any app-ULAs this peer already hosts onto the FRESH
        // session's allowed-set. A key ROTATION (`!is_new`) builds a
        // brand-new `PeerSession` whose allowed-set starts at just the
        // peer's own ULA, which would silently drop the app-ULAs the prior
        // session had accumulated. The `app_routes` index is the durable
        // source of truth for which app-ULAs map to this peer, so replay
        // them here (per-app-ULA routing, additive — a no-op when the peer
        // hosts no apps, i.e. the common peer-only case).
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

    /// Update an EXISTING session whose pubkey is unchanged (endpoint /
    /// metadata-only re-upsert) WITHOUT rebuilding it. Keeps the live
    /// `Tunn` — and so the boringtun handshake/rekey timer — intact, while
    /// repointing the routing indexes to the freshly-advertised endpoint:
    ///
    /// 1. Evict the stale `by_endpoint` alias and install the new one so an
    ///    inbound datagram from the new endpoint still demuxes here.
    /// 2. Repoint the session's outbound `endpoint` to the advertised
    ///    address (or `None` if the peer went passive). The advertised
    ///    endpoint is authoritative roster state; `learn_endpoint` /
    ///    `downgrade_direct_if_stale` continue to handle live roaming.
    /// 3. Reconcile the allowed-set against the durable `app_routes` index
    ///    so a newly-hosted app-ULA is permitted as a source. Strictly
    ///    additive — the peer's own ULA is already present from the
    ///    original insert.
    ///
    /// The per-peer `/128` route is left untouched (it was installed on the
    /// first insert and the ULA hasn't changed).
    fn update_in_place(&self, session: &Arc<PeerSession>, info: &PeerInfo) {
        // (1) Repoint the by_endpoint index: drop the old alias, add the new.
        let old_endpoint = session.endpoint();
        if old_endpoint != info.listen_endpoint {
            if let Some(addr) = old_endpoint {
                self.by_endpoint.remove(&addr);
            }
        }
        if let Some(addr) = info.listen_endpoint {
            self.by_endpoint.insert(addr, session.clone());
        }
        // (2) Repoint the outbound endpoint to the advertised address.
        *session.endpoint.write() = info.listen_endpoint;
        // (3) Reconcile hosted app-ULAs onto the (preserved) allowed-set.
        for kv in self.app_routes.iter() {
            if *kv.value() == info.ula {
                session.add_allowed_source(*kv.key());
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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod liveness_tests {
    use super::*;

    /// THRESHOLD used by the table-level tests (mirrors the joiner's
    /// `DATAPLANE_RX_SILENCE_THRESHOLD_MICROS`): 90s of RX silence.
    const TH: i64 = 90_000_000;

    /// A fresh table has never seen an inbound data frame nor a send attempt:
    /// both clocks start at `0` (the "never" sentinel).
    #[test]
    fn liveness_clocks_default_to_zero() {
        let t = SessionTable::new();
        assert_eq!(t.last_inbound_data_frame_ts(), 0, "no inbound yet");
        assert_eq!(t.last_send_attempt_ts(), 0, "no send yet");
    }

    /// `note_inbound_data_frame` advances the inbound clock to the stamped
    /// time; a LATER stamp moves it forward; an EARLIER stamp never regresses
    /// it (monotonic — out-of-order decap on two loops must not rewind the
    /// freshness signal).
    #[test]
    fn note_inbound_data_frame_is_monotonic() {
        let t = SessionTable::new();
        t.note_inbound_data_frame(1_000);
        assert_eq!(t.last_inbound_data_frame_ts(), 1_000);
        t.note_inbound_data_frame(5_000);
        assert_eq!(t.last_inbound_data_frame_ts(), 5_000, "advances forward");
        t.note_inbound_data_frame(2_000);
        assert_eq!(
            t.last_inbound_data_frame_ts(),
            5_000,
            "an earlier stamp must not rewind the clock"
        );
    }

    /// `note_send_attempt` advances the send clock the same monotonic way.
    #[test]
    fn note_send_attempt_is_monotonic() {
        let t = SessionTable::new();
        t.note_send_attempt(3_000);
        assert_eq!(t.last_send_attempt_ts(), 3_000);
        t.note_send_attempt(1_000);
        assert_eq!(t.last_send_attempt_ts(), 3_000, "no rewind");
    }

    /// The clocks are SHARED across clones (the cheap-clone `SessionTable`
    /// hands the SAME `Arc<AtomicI64>` to every loop): a stamp on one clone is
    /// visible through another. This is what makes a single process-global
    /// signal possible across the udp/relay/timer loops.
    #[test]
    fn liveness_clocks_shared_across_clones() {
        let t = SessionTable::new();
        let cloned = t.clone();
        cloned.note_inbound_data_frame(9_000);
        assert_eq!(
            t.last_inbound_data_frame_ts(),
            9_000,
            "a stamp on a clone is visible through the original"
        );
    }

    /// Build a table with one peer session so `len() >= 1`.
    fn table_with_one_peer() -> SessionTable {
        let me = StaticSecret::from([9u8; 32]);
        let info = crate::peer::PeerInfo {
            peer_id: uuid::Uuid::nil(),
            wg_public_key: *PublicKey::from(&StaticSecret::from([3u8; 32])).as_bytes(),
            ula: "fd5a:1f00:1::1".parse().unwrap(),
            listen_endpoint: Some("127.0.0.1:51820".parse().unwrap()),
            display_name: "peer".into(),
            tags: vec![],
            hosted_app_ulas: vec![],
            software_version: None,
            mesh_version: None,
            joined_at_micros: 0,
        };
        let t = SessionTable::new();
        t.upsert(&me, &info);
        t
    }

    /// A node with NO peers is always healthy — there is nothing to be a black
    /// hole toward (fail-open).
    #[test]
    fn dataplane_healthy_when_no_peers() {
        let t = SessionTable::new();
        // Even with a stale (or zero) RX clock and a recent send, no peers ⇒ healthy.
        t.note_send_attempt(1_000_000_000);
        assert!(t.dataplane_healthy(1_000_000_000 + TH * 2, TH));
    }

    /// A node with peers that has NOT sent since the last inbound sample is
    /// IDLE — healthy regardless of RX age (no TX ⇒ no RX expectation).
    #[test]
    fn dataplane_healthy_when_idle_no_send_since_rx() {
        let t = table_with_one_peer();
        // Last inbound at t=10s; NO send after it. Now is far past threshold.
        t.note_inbound_data_frame(10_000_000);
        // send clock <= inbound clock ⇒ idle.
        assert!(
            t.dataplane_healthy(10_000_000 + TH * 5, TH),
            "an idle node (no send since last RX) is never a black hole"
        );
    }

    /// THE black-hole case: peers present, WE SENT after the last inbound, and
    /// the inbound clock is older than THRESHOLD ⇒ UNHEALTHY (data-plane dead).
    #[test]
    fn dataplane_unhealthy_when_sending_but_rx_stale() {
        let t = table_with_one_peer();
        t.note_inbound_data_frame(10_000_000); // last RX at 10s
        t.note_send_attempt(20_000_000); // we sent at 20s (after RX)
        // Now = 10s + threshold + 1µs ⇒ RX age exceeds threshold while sending.
        assert!(
            !t.dataplane_healthy(10_000_000 + TH + 1, TH),
            "sending peers with stale RX is a black hole"
        );
    }

    /// Sending AND fresh RX ⇒ healthy (the steady state).
    #[test]
    fn dataplane_healthy_when_sending_and_rx_fresh() {
        let t = table_with_one_peer();
        t.note_inbound_data_frame(100_000_000);
        t.note_send_attempt(100_000_000);
        assert!(t.dataplane_healthy(100_000_000 + TH / 2, TH));
    }
}
