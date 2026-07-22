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
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, Ordering};
use tokio::sync::Mutex;
use tokio::sync::mpsc::UnboundedSender;
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
    /// Unix-micros of the LAST active IDLE LIVENESS PROBE the timer loop fired.
    /// Rate-limits that probe to a FIXED cadence — at most one DATA probe per
    /// [`IDLE_PROBE_AFTER_MICROS`] — so an idle node emits ONE probe per tick
    /// window instead of a 200ms busy-loop. The probe's job under the
    /// `DeliverToTun`-only reboot gate is to keep ELICITING the peer's RX at a
    /// cadence well under the 90s silence threshold: because EVERY node runs
    /// this probe, each node RECEIVES the peer's probe (a real `DeliverToTun` that
    /// refreshes THIS node's reboot clock) every ≤ `IDLE_PROBE_AFTER_MICROS`,
    /// phase-independently, so a healthy-but-idle tunnel stays GREEN while a
    /// genuinely dead one still ages out. `0` = "never probed". `Arc<AtomicI64>`
    /// like the other clocks so the rate-limit is process-global across the
    /// cheap-clone table. NOTE: unlike the old escalating back-off, the cadence
    /// is FIXED and INDEPENDENT of send-state — a truly-dead peer being probed
    /// every window is cheap and correct (it still reads UNHEALTHY because no
    /// `DeliverToTun` returns), while a healthy pair must NEVER stop probing (a
    /// dropped probe must self-heal on the very next window — no latch).
    last_idle_probe_ts: Arc<AtomicI64>,
    /// Optional sender to the convergence-kick queue (eager-relay-convergence).
    /// When `Some` (the joiner wires it via [`Self::with_convergence_tx`]), a
    /// genuinely-NEW, non-ephemeral session is enqueued on [`Self::upsert`] so a
    /// background `convergence_loop` fires ONE relay-floored handshake kick —
    /// converging a passive/far peer without waiting on the ~25s persistent-
    /// keepalive bootstrap. `None` (the default) keeps the pre-convergence
    /// behaviour (tests, `--no-relay`). Cheap-clone like `relay`.
    convergence_tx: Option<UnboundedSender<Arc<PeerSession>>>,
}

/// FIXED cadence of the active idle liveness probe.
///
/// A node whose reboot RX clock has aged past this window emits ONE real
/// inner-v6 DATA probe, then again every `IDLE_PROBE_AFTER_MICROS` for as long
/// as it stays idle.
///
/// Set to `DATAPLANE_RX_SILENCE_THRESHOLD_MICROS / 4` (22.5s for the 90s
/// threshold). This is the load-bearing margin under the `DeliverToTun`-only reboot
/// gate: the probe elicits NO reply (its inner packet is next-header 59, No-Next-
/// Header — the peer's TUN drops it), so a node cannot refresh its OWN reboot RX
/// clock; refresh comes ONLY from the PEER independently probing. Because EVERY
/// node probes every ≤ this window, each node RECEIVES the peer's DATA probe
/// (a real `DeliverToTun` that refreshes its reboot clock) every ≤ this window,
/// phase-independently — with an anti-phase transient bounded by 2× this window
/// (45s) which still sits comfortably under the 90s silence threshold (~2× worst-
/// case, ~4× steady-state margin). At the OLD 45s (= threshold/2) the anti-phase
/// peer-to-peer RX-refresh interval reached 2×45s = 90s + relay RTT — the 90s
/// threshold with ZERO margin, so a perfectly healthy idle pair drifted into a
/// spurious FLEET-WIDE reboot every ~90s. Kept above the ~20s keepalive cadence
/// only incidentally; correctness now rests on the < threshold-with-margin bound,
/// not on out-racing keepalives.
pub const IDLE_PROBE_AFTER_MICROS: i64 = crate::joiner::DATAPLANE_RX_SILENCE_THRESHOLD_MICROS / 4;

/// Shared overflow-safe exponential back-off: `min(base << streak, cap)`.
///
/// Computed by iterative doubling so a large `streak` saturates at `cap` instead
/// of overflowing (`i64::checked_shl` guards only the shift COUNT, not the
/// resulting VALUE — a wide shift silently yields garbage, so it is unsuitable
/// here). Returns `cap` the instant the doubled value reaches or exceeds it.
/// Used by the expired-`Tunn` re-arm (task #14) loop-guard.
#[must_use]
pub const fn escalating_backoff(streak: u32, base_micros: i64, cap_micros: i64) -> i64 {
    let mut window = base_micros;
    let mut i = 0u32;
    while i < streak {
        // Double; saturate to cap on the first step that reaches/overflows it.
        match window.checked_mul(2) {
            Some(doubled) if doubled < cap_micros => window = doubled,
            _ => return cap_micros,
        }
        i += 1;
    }
    if window < cap_micros { window } else { cap_micros }
}

/// Pure trigger for the active idle liveness probe.
///
/// Returns `true` when there is a peer to probe AND the reboot RX clock has aged
/// past `after_micros`, so the node must emit ONE real DATA probe to keep
/// ELICITING the peer's RX:
///
/// * **No peers** ⇒ `false` (nothing to probe toward — mirrors the
///   `dataplane_healthy` no-peers fail-open).
/// * **Genuinely fresh RX** (`now - last_rx < after_micros`) ⇒ `false`. The
///   data plane is demonstrably alive within this window; no probe needed.
/// * **RX aged past the window** (`now - last_rx >= after_micros`) ⇒ `true`,
///   REGARDLESS of send-state. This is deliberately INDEPENDENT of
///   `last_send_attempt_ts`: the old `last_send <= last_rx` gate made a node
///   STOP probing the instant it emitted a probe (which advances the send clock),
///   so a single dropped-in-both-directions window LATCHED both ends — neither
///   re-probed, RX froze, both aged out to a spurious reboot with no self-heal.
///   A FIXED cadence that ignores send-state cannot latch: a healthy pair keeps
///   refreshing each other every window; a dead peer is re-probed every window
///   yet still reads UNHEALTHY (no `DeliverToTun` returns) so the reboot still
///   fires on a real outage.
///
/// Pure (`now` / clocks / threshold injected) and read-only, mirroring
/// [`SessionTable::dataplane_healthy`]; the rate limit lives in
/// [`SessionTable::should_emit_idle_probe`].
#[must_use]
pub const fn idle_probe_due(
    now_micros: i64,
    last_rx_micros: i64,
    has_peers: bool,
    after_micros: i64,
) -> bool {
    if !has_peers {
        return false;
    }
    // Probe once the RX clock has aged past the window — send-state is
    // intentionally IRRELEVANT (fixed cadence, no latch).
    now_micros.saturating_sub(last_rx_micros) >= after_micros
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
                "convergence_tx",
                &self.convergence_tx.as_ref().map(|_| "<convergence_tx>"),
            )
            .field(
                "last_inbound_data_frame_ts",
                &self.last_inbound_data_frame_ts.load(Ordering::Relaxed),
            )
            .field(
                "last_send_attempt_ts",
                &self.last_send_attempt_ts.load(Ordering::Relaxed),
            )
            .field(
                "last_idle_probe_ts",
                &self.last_idle_probe_ts.load(Ordering::Relaxed),
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

    /// Wire the eager-relay-convergence kick queue onto an existing table: a
    /// genuinely-new, non-ephemeral [`Self::upsert`] enqueues its session onto
    /// `tx`, drained by the joiner's `convergence_loop`. Composes with the other
    /// builders (`with_route_sink_and_relay(...).with_convergence_tx(tx)`).
    #[must_use]
    pub fn with_convergence_tx(mut self, tx: UnboundedSender<Arc<PeerSession>>) -> Self {
        self.convergence_tx = Some(tx);
        self
    }

    /// Enqueue an EXISTING peer session (looked up by ULA) for ONE relay-floored
    /// convergence kick — the joiner's response to a relay-rendezvous `RelayWake`
    /// naming this `source_ula` as a cold peer trying to reach us. Reuses the
    /// eager-convergence machinery: `convergence_loop` drains it and fires
    /// `kick_convergence_handshake` (`encapsulate(&[])` → a handshake-init on a
    /// cold `Tunn`, a harmless keepalive on an established one), ALWAYS relay-
    /// floored (I2). No-op when the peer is unknown or no convergence channel is
    /// wired (`--no-relay` / tests). Idempotence is enforced coordinator-side
    /// (the per-dst wake cooldown), so this needs no rate-limit of its own.
    pub fn request_convergence_kick(&self, ula: Ipv6Addr) {
        if let Some(tx) = &self.convergence_tx
            && let Some(session) = self.by_ula.get(&ula).map(|kv| kv.value().clone())
        {
            let _ = tx.send(session);
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

    /// Unix-micros of the last active idle liveness probe (B-fix-1). `0` =
    /// none yet. Diagnostics / tests.
    #[must_use]
    pub fn last_idle_probe_ts(&self) -> i64 {
        self.last_idle_probe_ts.load(Ordering::Relaxed)
    }

    /// Decide whether the timer loop should fire ONE active idle liveness probe
    /// THIS tick, CLAIMING the rate-limit slot when it returns `true`.
    ///
    /// Two gates compose:
    /// 1. [`idle_probe_due`] — the pure trigger (peers present, RX aged past
    ///    `after_micros`), INDEPENDENT of send-state (no latch — CRIT-2 fix).
    /// 2. A per-table FIXED-cadence limiter: at most one probe per
    ///    `after_micros`. An idle node emits ONE DATA probe per window and keeps
    ///    doing so at that fixed cadence for as long as it stays idle — the
    ///    probe must keep ELICITING the peer's RX (each end refreshes the OTHER's
    ///    reboot clock), so the cadence must NOT escalate away from the < 90s
    ///    threshold. A truly-dead peer probed every window is cheap and stays
    ///    UNHEALTHY (no `DeliverToTun` returns); a healthy pair NEVER stops probing
    ///    so a dropped probe self-heals on the very next window. The first ever
    ///    probe fires immediately (clock starts at `0` ⇒ the window has elapsed).
    ///    The slot is claimed by stamping `last_idle_probe_ts` (relaxed, same
    ///    rationale as the other liveness clocks — a racing double-read at worst
    ///    emits one extra DATA probe, which WG anti-replay / the relay floor make
    ///    harmless).
    ///
    /// Read-then-claim is intentional: the caller emits the probe only when this
    /// returns `true`, so claiming here keeps the side effect bounded to one
    /// frame per `after_micros` regardless of the 200ms timer cadence.
    pub fn should_emit_idle_probe(&self, now_micros: i64, after_micros: i64) -> bool {
        if !idle_probe_due(
            now_micros,
            self.last_inbound_data_frame_ts(),
            !self.is_empty(),
            after_micros,
        ) {
            return false;
        }
        // Fixed-cadence rate-limit: claim the slot iff a full `after_micros`
        // window has elapsed since the last probe — one DATA probe per window,
        // never a 200ms busy-loop, never an escalating back-off.
        let last = self.last_idle_probe_ts.load(Ordering::Relaxed);
        if now_micros.saturating_sub(last) >= after_micros {
            self.last_idle_probe_ts.store(now_micros, Ordering::Relaxed);
            true
        } else {
            false
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
    /// Adoption rule (classic `WireGuard` roaming): a source that just
    /// AUTHENTICATED (the caller only invokes this after a successful
    /// decapsulate under this peer's `Tunn`; boringtun's anti-replay +
    /// handshake-timestamp checks make a replayed datagram fail decap) is
    /// the address the peer VERIFIABLY transmits from right now — adopt it
    /// as the outbound default whenever it differs, CONFIRMED OR NOT, and
    /// mark the endpoint LEARNED (provenance for [`Self::update_in_place`]).
    ///
    /// This deliberately supersedes the old "a confirmed endpoint is
    /// authoritative, never repoint it" rule: that guard was one leg of the
    /// symmetric-NAT wedge (the MSI black hole). A symmetric-NAT peer's
    /// roster-advertised reflexive endpoint is a per-destination BLACK HOLE
    /// toward us; the only address that ever works is the one its packets
    /// actually arrive from. If the outbound endpoint has been regressed onto
    /// the dead candidate (roster churn, NAT rebind), refusing to re-adopt the
    /// live authenticated source wedges TX into the black hole forever —
    /// while kernel `WireGuard` simply roams to the latest authenticated
    /// source, exactly as we do now.
    pub fn learn_endpoint(&self, session: &Arc<PeerSession>, source: SocketAddr) {
        // Always index the source for inbound demux + response targeting.
        self.by_endpoint.insert(source, session.clone());
        // Adopt any NEW authenticated source as the outbound default and
        // record its provenance (a learned address outranks the roster
        // candidate in `update_in_place`).
        let mut guard = session.endpoint.write();
        if *guard != Some(source) {
            *guard = Some(source);
            session.endpoint_learned.store(true, Ordering::Relaxed);
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

    /// Pick ONE live peer to carry the active idle liveness probe (B-fix-1).
    /// PREFERS a relay-anchored peer (one whose direct path is NOT confirmed —
    /// the coordinator-relay is the floor for it, so the probe rides the relay
    /// the black hole is suspected on) and falls back to any peer; ties broken
    /// by the lowest ULA so the choice is STABLE across ticks (avoids
    /// scattering probes). `None` only when the table is empty (the caller has
    /// already gated on peers-present, so this is essentially infallible there).
    #[must_use]
    pub fn idle_probe_target(&self) -> Option<Arc<PeerSession>> {
        let mut relay_anchored: Option<Arc<PeerSession>> = None;
        let mut any: Option<Arc<PeerSession>> = None;
        for kv in self.by_ula.iter() {
            let session = kv.value();
            let better = |cur: &Option<Arc<PeerSession>>| {
                cur.as_ref().is_none_or(|c| session.ula < c.ula)
            };
            if !session.direct_confirmed() && better(&relay_anchored) {
                relay_anchored = Some(session.clone());
            }
            if better(&any) {
                any = Some(session.clone());
            }
        }
        relay_anchored.or(any)
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
        // ROUTE SELF-HEAL: (re)install the peer's /128 on EVERY upsert, not just
        // first-insert. `reconcile_roster` upserts each roster peer every
        // heartbeat, so making the install UNCONDITIONAL means a route stripped
        // by a churn race — e.g. a stale `peer_removed` for a ULA that was
        // re-assigned to a fresh peer during an MSI IP-flip re-register — is
        // repaired within one heartbeat tick instead of staying routeless
        // forever. `add_allowed` → `add_peer_route` is idempotent ("File exists"
        // tolerated), so re-installing an already-present /128 is a cheap no-op.
        if let Some(sink) = &self.route_sink {
            sink.add_allowed(info.ula);
        }
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
            // Roster-sourced candidate, not a learned address (provenance
            // starts at "advertised" until an authenticated inbound source
            // is adopted by `learn_endpoint`).
            endpoint_learned: AtomicBool::new(false),
            // A fresh session always starts UNCONFIRMED — even a re-upsert
            // (endpoint roam / re-handshake) must re-prove the direct path
            // before TX leaves the relay floor. The advertised endpoint is
            // only a candidate until a decrypted data packet confirms it.
            direct_confirmed: AtomicBool::new(false),
            last_direct_rx_micros: AtomicI64::new(0),
            last_direct_data_tx_micros: AtomicI64::new(0),
            last_direct_data_rx_micros: AtomicI64::new(0),
            last_probe_micros: AtomicI64::new(0),
            // A freshly-upserted peer starts un-penalised (A-c hysteresis).
            failed_handshake_count: AtomicU32::new(0),
            direct_suppressed_until: AtomicI64::new(0),
            // Never re-armed yet — the first detected `Tunn` expiry re-arms
            // at once (FIX 3). Streak starts un-escalated (task #14 loop-guard).
            last_rearm_micros: AtomicI64::new(0),
            rearm_streak: AtomicU32::new(0),
            // Eager convergence eligibility: a long-lived host/infra peer
            // (`fd5a:1f00:…`) re-arms its expired Tunn on the brisk 5 s base; an
            // ephemeral runner-FC (`fd5a:1f02:…`) keeps the 90 s default.
            eager_convergence: AtomicBool::new(!crate::peer::is_ephemeral_peer(info.ula)),
            // Handshake observability starts empty: no handshake-class frame
            // seen yet on this (fresh or key-rotated) session.
            last_handshake_rx_micros: AtomicI64::new(0),
            last_handshake_rx_direct: AtomicBool::new(false),
            handshake_rx_count: std::sync::atomic::AtomicU64::new(0),
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
        // Eager-relay-convergence: a genuinely-NEW, non-ephemeral peer is
        // enqueued for ONE relay-floored handshake kick so a passive/far peer
        // converges without waiting on the ~25s persistent-keepalive bootstrap.
        // A same-pubkey re-upsert returned early via `update_in_place`, so it
        // never reaches here (I11 — no per-heartbeat micro-storm); ephemeral
        // runner-FCs stay lazy. Enqueue BEFORE the `by_endpoint` move below.
        if is_new
            && !crate::peer::is_ephemeral_peer(info.ula)
            && let Some(tx) = &self.convergence_tx
        {
            let _ = tx.send(session.clone());
        }
        if let Some(addr) = info.listen_endpoint {
            self.by_endpoint.insert(addr, session);
        }
        // TX route scoping: the per-peer `/128` host route (spec §5.5, the
        // blanket `/48` is gone) is installed UNCONDITIONALLY at the top of
        // `upsert` now, so a stripped route self-heals on the next reconcile —
        // no `is_new` gate here.
    }

    /// Update an EXISTING session whose pubkey is unchanged (endpoint /
    /// metadata-only re-upsert) WITHOUT rebuilding it. Keeps the live
    /// `Tunn` — and so the boringtun handshake/rekey timer — intact, while
    /// reconciling the routing indexes against the fresh roster record:
    ///
    /// 1. Endpoint handling. The roster's advertised endpoint is a
    ///    CANDIDATE, never authority: it must NOT overwrite a LEARNED
    ///    endpoint (an address the peer's authenticated datagrams actually
    ///    arrive from — [`Self::learn_endpoint`]). For a symmetric-NAT peer
    ///    the advertised reflexive address (observed by the coordinator's
    ///    vantage) is a per-destination BLACK HOLE toward us, and this
    ///    method runs on EVERY `peer_updated` + every ~20s heartbeat
    ///    reconcile — the old unconditional repoint regressed a proven
    ///    learned path onto the black hole within one tick of every direct
    ///    convergence, permanently (the MSI wedge). So:
    ///    * endpoint LEARNED → keep it and its demux alias; still index the
    ///      advertised candidate so inbound from it demuxes here.
    ///    * endpoint not learned (roster-sourced or unset) → repoint to the
    ///      freshly-advertised address exactly as before (roster roaming for
    ///      well-behaved peers), evicting the stale alias.
    /// 2. Reconcile the allowed-set against the durable `app_routes` index
    ///    so a newly-hosted app-ULA is permitted as a source. Strictly
    ///    additive — the peer's own ULA is already present from the
    ///    original insert.
    ///
    /// The per-peer `/128` route is left untouched (it was installed on the
    /// first insert and the ULA hasn't changed).
    fn update_in_place(&self, session: &Arc<PeerSession>, info: &PeerInfo) {
        // (1) Endpoint: learned addresses outrank the roster candidate.
        if session.endpoint_learned() {
            // Keep the learned outbound endpoint + its alias; additionally
            // index the advertised candidate for inbound demux.
            if let Some(addr) = info.listen_endpoint {
                self.by_endpoint.insert(addr, session.clone());
            }
        } else {
            // Roster-sourced endpoint → follow the roster (drop the old
            // alias, add the new, repoint the outbound default).
            let old_endpoint = session.endpoint();
            if old_endpoint != info.listen_endpoint {
                if let Some(addr) = old_endpoint {
                    self.by_endpoint.remove(&addr);
                }
            }
            if let Some(addr) = info.listen_endpoint {
                self.by_endpoint.insert(addr, session.clone());
            }
            *session.endpoint.write() = info.listen_endpoint;
        }
        // (2) Reconcile hosted app-ULAs onto the (preserved) allowed-set.
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

    /// Force a fresh WG handshake on EVERY live session (Track C `ResetWg`).
    ///
    /// Re-arms each peer's `Tunn` ([`PeerSession::reset_handshake`]) so the next
    /// outbound frame re-initiates the handshake — clears half-open / stale
    /// sessions WITHOUT a process restart. Endpoints, allowed-source sets, the
    /// routing indexes, and the relay floor are ALL preserved: a relay-only peer
    /// simply re-handshakes over the relay (spec §7 — no verb may flip a peer to
    /// direct). `our_private` is this node's own X25519 secret (the same key the
    /// sessions were built with). Snapshots the session set first so a
    /// concurrent reconcile mutation never deadlocks against the per-`Tunn`
    /// async lock.
    pub async fn force_rehandshake_all(&self, our_private: &StaticSecret) {
        let sessions: Vec<Arc<PeerSession>> =
            self.by_ula.iter().map(|kv| kv.value().clone()).collect();
        for session in sessions {
            session.reset_handshake(our_private).await;
            tracing::info!(
                peer_id = %session.peer_id,
                ula = %session.ula,
                "ResetWg: re-armed WG handshake (relay floor preserved)"
            );
        }
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

    /// Build a `PeerInfo` keyed by a single-byte pubkey seed `pk`.
    fn mk_info(ula: &str, pk: u8, endpoint: Option<&str>) -> crate::peer::PeerInfo {
        crate::peer::PeerInfo {
            peer_id: uuid::Uuid::nil(),
            wg_public_key: *PublicKey::from(&StaticSecret::from([pk; 32])).as_bytes(),
            ula: ula.parse().unwrap(),
            listen_endpoint: endpoint.map(|e| e.parse().unwrap()),
            display_name: "peer".into(),
            tags: vec![],
            hosted_app_ulas: vec![],
            software_version: None,
            mesh_version: None,
            joined_at_micros: 0,
        }
    }

    /// Eager-relay-convergence: a genuinely-NEW, non-ephemeral peer is enqueued
    /// onto the convergence channel so `convergence_loop` can fire its kick.
    #[test]
    fn eager_upsert_enqueues_new_session() {
        let me = StaticSecret::from([9u8; 32]);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let t = SessionTable::new().with_convergence_tx(tx);
        let info = mk_info("fd5a:1f00:1::1", 1, Some("127.0.0.1:51820"));
        t.upsert(&me, &info);
        let got = rx
            .try_recv()
            .expect("a new non-ephemeral peer is enqueued for the convergence kick");
        assert_eq!(got.ula, info.ula);
    }

    /// Relay-rendezvous: `request_convergence_kick` enqueues an EXISTING session
    /// (looked up by ULA) for a relay-floored kick — the joiner's response to a
    /// `RelayWake` naming that source. An unknown ULA is a safe no-op.
    #[test]
    fn request_convergence_kick_enqueues_known_peer_and_noops_unknown() {
        let me = StaticSecret::from([9u8; 32]);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let t = SessionTable::new().with_convergence_tx(tx);
        let info = mk_info("fd5a:1f00:1::1", 1, Some("127.0.0.1:51820"));
        t.upsert(&me, &info);
        let _ = rx.try_recv(); // drain the eager upsert enqueue
        // A wake naming this peer's ULA enqueues it for the kick-back.
        t.request_convergence_kick(info.ula);
        let got = rx
            .try_recv()
            .expect("a known peer is enqueued for the rendezvous kick");
        assert_eq!(got.ula, info.ula);
        // An unknown ULA is a safe no-op (no panic, no enqueue).
        t.request_convergence_kick("fd5a:1f00:9::9".parse().unwrap());
        assert!(rx.try_recv().is_err(), "unknown peer ⇒ no enqueue");
    }

    /// Invariant I11: a same-pubkey re-upsert (the ~20s `peer_updated` path)
    /// hits `update_in_place` and must NEVER re-enqueue — else every heartbeat
    /// would re-mint a handshake (a self-inflicted micro-storm).
    #[test]
    fn inplace_reupsert_does_not_enqueue() {
        let me = StaticSecret::from([9u8; 32]);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let t = SessionTable::new().with_convergence_tx(tx);
        let info = mk_info("fd5a:1f00:1::1", 1, Some("127.0.0.1:51820"));
        t.upsert(&me, &info); // is_new ⇒ enqueue
        let _ = rx.try_recv(); // drain the first
        t.upsert(&me, &info); // SAME pubkey ⇒ update_in_place, NO enqueue
        assert!(
            rx.try_recv().is_err(),
            "a same-pubkey re-upsert must not re-enqueue (I11)"
        );
    }

    /// Ephemeral runner-FCs (`fd5a:1f02:…`) stay on the LAZY path — numerous and
    /// short-lived, they get no eager kick.
    #[test]
    fn ephemeral_upsert_does_not_enqueue() {
        let me = StaticSecret::from([9u8; 32]);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let t = SessionTable::new().with_convergence_tx(tx);
        let info = mk_info("fd5a:1f02:abcd::1", 7, Some("127.0.0.1:51820"));
        t.upsert(&me, &info);
        assert!(
            rx.try_recv().is_err(),
            "an ephemeral runner-FC stays lazy — no eager convergence kick"
        );
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

    // ---- active idle liveness probe: FIXED-cadence trigger ----

    /// Probe-after window for the pure-trigger tests (mirrors
    /// [`IDLE_PROBE_AFTER_MICROS`] = threshold/4 = 22.5s).
    const AFTER: i64 = IDLE_PROBE_AFTER_MICROS;

    /// The load-bearing MARGIN invariant (CRIT-1): the anti-phase peer-to-peer
    /// RX-refresh interval is bounded by 2×AFTER (each node probes every AFTER,
    /// so each RECEIVES the peer's probe every ≤AFTER, worst-case transient
    /// 2×AFTER). That bound MUST stay strictly under the 90s silence threshold —
    /// with margin — or a perfectly healthy idle pair spuriously reboots. At the
    /// old AFTER=45s (threshold/2) the bound was exactly the threshold (ZERO
    /// margin). threshold/4 gives ~4× steady / ~2× worst-case headroom.
    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn idle_probe_cadence_has_margin_under_threshold() {
        assert!(
            2 * AFTER < TH,
            "anti-phase RX-refresh bound 2×AFTER={} must stay under threshold {TH} (margin)",
            2 * AFTER
        );
        assert!(
            AFTER <= TH / 4,
            "cadence AFTER={AFTER} must be ≤ threshold/4 for ≥4× steady-state margin"
        );
    }

    /// THE trigger case: peers present and the RX clock aged PAST the window ⇒
    /// `idle_probe_due` true. This is the 2026-06-21 blind spot — a trickle of
    /// relay control frames kept RX < threshold while no DATA round-tripped, so
    /// the node read healthy forever; the probe elicits real DATA to expose it.
    #[test]
    fn idle_probe_due_when_rx_aged() {
        assert!(idle_probe_due(
            10_000_000 + AFTER + 1,
            10_000_000, // last_rx
            true,       // peers present
            AFTER,
        ));
    }

    /// CRIT-2: the trigger is INDEPENDENT of send-state. A probe advances the
    /// node's own DATA-send clock, but the node MUST keep probing at the fixed
    /// cadence anyway — otherwise a single window where both ends drop each
    /// other's probe latches both (`last_send` > `last_rx`) and neither re-probes,
    /// freezing RX into a spurious reboot. The old `last_send <= last_rx` gate is
    /// gone: due depends ONLY on RX age.
    #[test]
    fn idle_probe_due_even_when_already_sending() {
        // last_send way after last_rx (a probe just went out) — still due, so the
        // node re-probes and cannot latch.
        assert!(
            idle_probe_due(10_000_000 + AFTER + 1, 10_000_000, true, AFTER),
            "RX aged past the window ⇒ due regardless of send-state (no latch)"
        );
    }

    /// RX returns FRESH (`now - last_rx < after`) ⇒ NO probe. The data plane is
    /// demonstrably alive within this window (the "+RX-returns ⇒ no probe"
    /// direction — probing stops once real RX resumes).
    #[test]
    fn idle_probe_not_due_when_rx_fresh() {
        assert!(!idle_probe_due(
            10_000_000 + AFTER / 2, // RX age < after ⇒ fresh
            10_000_000,
            true,
            AFTER,
        ));
    }

    /// Boundary: RX age one micro under the window ⇒ not due; exactly at the
    /// window ⇒ due. Pins the cadence threshold exact.
    #[test]
    fn idle_probe_boundary_is_exact() {
        assert!(
            !idle_probe_due(10_000_000 + AFTER - 1, 10_000_000, true, AFTER),
            "one micro under the window is still fresh ⇒ no probe"
        );
        assert!(
            idle_probe_due(10_000_000 + AFTER, 10_000_000, true, AFTER),
            "exactly at the window the probe is due"
        );
    }

    /// No peers ⇒ NO probe — mirrors the `dataplane_healthy` no-peers fail-open
    /// (nothing to probe toward).
    #[test]
    fn idle_probe_not_due_without_peers() {
        assert!(!idle_probe_due(
            10_000_000 + AFTER * 5,
            10_000_000,
            false, // no peers
            AFTER,
        ));
    }

    /// The table gate composes the trigger with a FIXED-cadence limiter: an idle
    /// table emits the FIRST probe as soon as the window is reached (clock starts
    /// at 0 ⇒ elapsed), SUPPRESSES a second within the SAME window, then ALLOWS
    /// one again exactly one AFTER later — a steady one-probe-per-window pulse,
    /// never a busy-loop, never an escalating back-off.
    #[test]
    fn should_emit_idle_probe_is_rate_limited() {
        let t = table_with_one_peer();
        t.note_inbound_data_frame(10_000_000);
        let base = 10_000_000 + AFTER; // first moment the probe is due
        assert!(
            t.should_emit_idle_probe(base, AFTER),
            "first probe fires once the window is reached"
        );
        // Within the SAME window (half an AFTER later) ⇒ suppressed.
        assert!(
            !t.should_emit_idle_probe(base + AFTER / 2, AFTER),
            "a second probe within the fixed window is suppressed (no busy-loop)"
        );
        // Exactly one AFTER later ⇒ fires again (FIXED cadence, not escalating).
        assert!(
            t.should_emit_idle_probe(base + AFTER, AFTER),
            "a probe fires again exactly one window later — fixed cadence"
        );
        // And again, still at the same fixed spacing — it never doubles away.
        assert!(
            t.should_emit_idle_probe(base + 2 * AFTER, AFTER),
            "the cadence stays fixed at AFTER — never escalates"
        );
    }

    /// Fresh RX STOPS the probe until RX ages again — no back-off state to carry:
    /// a fresh-RX tick is simply not-due, and once RX ages past the window the
    /// next probe is due at the same cadence.
    #[test]
    fn real_rx_stops_probe_until_aged_again() {
        let t = table_with_one_peer();
        t.note_inbound_data_frame(10_000_000);
        // Fire once the window is reached.
        assert!(t.should_emit_idle_probe(10_000_000 + AFTER, AFTER));
        // A real inbound refreshes RX ⇒ the very next tick is not-due (fresh).
        let rx2 = 10_000_000 + AFTER + 5_000_000;
        t.note_inbound_data_frame(rx2);
        assert!(
            !t.should_emit_idle_probe(rx2 + AFTER / 2, AFTER),
            "fresh RX ⇒ not due (probing pauses while data flows)"
        );
        // RX ages past the window again ⇒ due once more at the fixed cadence.
        assert!(
            t.should_emit_idle_probe(rx2 + AFTER, AFTER),
            "once RX ages past the window the probe is due again"
        );
    }

    /// The gate claims the rate-limit slot ONLY when it actually emits: a
    /// not-due call (fresh RX) must NOT stamp `last_idle_probe_ts`, so a later
    /// genuinely-due tick still fires immediately.
    #[test]
    fn should_emit_idle_probe_does_not_claim_when_not_due() {
        let t = table_with_one_peer();
        t.note_inbound_data_frame(10_000_000);
        assert!(!t.should_emit_idle_probe(10_000_000 + AFTER / 2, AFTER));
        assert_eq!(t.last_idle_probe_ts(), 0, "a not-due call must not stamp");
        assert!(t.should_emit_idle_probe(10_000_000 + AFTER, AFTER));
    }

    /// END-TO-END liveness chain: an idle node whose probe went out (send clock
    /// advanced) with NO RX back past the threshold reads UNHEALTHY, and once
    /// real RX returns it is healthy again.
    #[test]
    fn probe_then_no_rx_makes_dataplane_unhealthy() {
        let t = table_with_one_peer();
        t.note_inbound_data_frame(10_000_000); // last RX at 10s
        let now = 10_000_000 + TH + 1; // past the 90s RX-silence threshold
        // BEFORE the probe: idle ⇒ fail-open ⇒ judged HEALTHY despite stale RX.
        assert!(
            t.dataplane_healthy(now, TH),
            "the fail-open idle rule masks the black hole before any probe"
        );
        // The probe fires and stamps the send clock.
        assert!(t.should_emit_idle_probe(now, AFTER));
        t.note_send_attempt(now); // the probe's send_wire would do this
        // AFTER the probe: sending + stale RX ⇒ UNHEALTHY (black hole exposed).
        assert!(
            !t.dataplane_healthy(now, TH),
            "with the send clock advanced past a stale RX, the verdict flips unhealthy"
        );
        // RX RETURNS: a real inbound refreshes the clock ⇒ healthy again.
        t.note_inbound_data_frame(now);
        assert!(
            t.dataplane_healthy(now, TH),
            "once real RX resumes the node is healthy again"
        );
    }

    // ---- coupled two-node dynamics (real elapsed-time simulation) ----

    /// Decide + emit `node`'s idle probe for the FIXED cadence, advancing the
    /// EMITTER's own DATA-send clock on a fire (as `send_wire` stamps it for a
    /// real DATA frame). Returns whether it fired. DELIVERY to the peer (a
    /// `DeliverToTun` that refreshes the PEER's reboot clock — a probe never
    /// refreshes the emitter's OWN RX, it elicits no reply) is applied SEPARATELY
    /// by the caller so two INDEPENDENT nodes decide on the SAME start-of-tick
    /// state: a probe must not instantaneously suppress the peer's own tick
    /// (frames cross with real latency, not mid-tick).
    fn probe_emit(node: &SessionTable, now: i64) -> bool {
        if node.should_emit_idle_probe(now, AFTER) {
            node.note_send_attempt(now); // real DATA ⇒ advances own send clock
            true
        } else {
            false
        }
    }

    /// CRIT-1 REGRESSION — ANTI-PHASE HEALTHY PAIR. Two idle established peers
    /// (one peer each) whose probe phases are offset by up to AFTER. Driven over
    /// REAL elapsed time across >3 threshold windows, refreshing each other via
    /// the fixed-cadence probe: BOTH must stay `dataplane_healthy` the WHOLE
    /// time. At the old AFTER=45s (threshold/2) the anti-phase RX-refresh
    /// interval reaches the 90s threshold with ZERO margin and the pair drifts
    /// into a spurious fleet-wide reboot; at threshold/4 it never does.
    #[test]
    fn idle_pair_stays_healthy_across_windows_anti_phase() {
        let a = table_with_one_peer();
        let b = table_with_one_peer();
        let base: i64 = 10_000_000_000; // 10_000s — larger than any offset
        // Seed both reboot clocks (as the timer baseline seed would); B is offset
        // by half a window so the two probe phases are ANTI-phase.
        a.note_inbound_data_frame(base);
        b.note_inbound_data_frame(base - AFTER / 2);

        let step = 1_000_000; // 1s granularity
        let end = base + 3 * TH + 2 * AFTER; // > 3 threshold windows
        let mut now = base;
        while now <= end {
            // Both nodes decide on the SAME start-of-tick state (independent
            // timers), THEN their probes cross — a fired probe refreshes the
            // OTHER node's reboot clock.
            let a_fired = probe_emit(&a, now);
            let b_fired = probe_emit(&b, now);
            if a_fired {
                b.note_inbound_data_frame(now);
            }
            if b_fired {
                a.note_inbound_data_frame(now);
            }
            assert!(
                a.dataplane_healthy(now, TH),
                "A: idle-but-healthy pair must stay GREEN the whole time (t={now})"
            );
            assert!(
                b.dataplane_healthy(now, TH),
                "B: idle-but-healthy pair must stay GREEN the whole time (t={now})"
            );
            now += step;
        }
    }

    /// CRIT-2 REGRESSION — SINGLE-ROUND BIDIRECTIONAL LOSS RECOVERS. Both idle
    /// peers probe in the same window but BOTH probes are dropped (no delivery),
    /// so each has `last_send > last_rx`. The OLD `last_send <= last_rx` gate
    /// would latch both here (neither re-probes ⇒ RX frozen ⇒ spurious reboot).
    /// The fixed cadence CANNOT latch: on the very NEXT window both re-probe, the
    /// re-probes are delivered, RX refreshes, and both read HEALTHY.
    #[test]
    fn bidirectional_probe_loss_recovers_no_latch() {
        let a = table_with_one_peer();
        let b = table_with_one_peer();
        let base: i64 = 10_000_000_000;
        a.note_inbound_data_frame(base);
        b.note_inbound_data_frame(base);

        // Window 1: both due, both probe, BOTH probes LOST (no delivery).
        let t1 = base + AFTER;
        assert!(probe_emit(&a, t1), "A probes in window 1");
        assert!(probe_emit(&b, t1), "B probes in window 1");
        // Both now have last_send > last_rx — the exact latch condition.
        assert!(a.last_send_attempt_ts() > a.last_inbound_data_frame_ts());
        assert!(b.last_send_attempt_ts() > b.last_inbound_data_frame_ts());

        // Window 2: NO latch — both re-probe despite having just sent. Decide on
        // the same start-of-tick state, then the re-probes cross (delivered).
        let t2 = base + 2 * AFTER;
        let a_fired = probe_emit(&a, t2);
        let b_fired = probe_emit(&b, t2);
        assert!(a_fired, "A must re-probe next window (no send-state latch — CRIT-2 fix)");
        assert!(b_fired, "B must re-probe next window (no send-state latch — CRIT-2 fix)");
        // The delivered re-probes refreshed each other's RX ⇒ both healthy again.
        a.note_inbound_data_frame(t2); // B's re-probe lands on A
        b.note_inbound_data_frame(t2); // A's re-probe lands on B
        assert!(a.dataplane_healthy(t2, TH), "A recovers after one lost round");
        assert!(b.dataplane_healthy(t2, TH), "B recovers after one lost round");
    }

    /// DEAD PEER STILL UNHEALTHY. An established peer that stops delivering DATA:
    /// probes keep going out at the fixed cadence (advancing the send clock) but
    /// NONE come back (deliver=false forever). Past the threshold the node reads
    /// UNHEALTHY so the guarded reboot still fires on a real outage — and the
    /// probe keeps firing every window (a dead peer is cheap to re-probe).
    #[test]
    fn dead_peer_ages_out_to_unhealthy() {
        let node = table_with_one_peer();
        let base: i64 = 10_000_000_000;
        node.note_inbound_data_frame(base);

        let step = 1_000_000;
        let mut now = base + AFTER;
        let mut probes = 0;
        // Run past the threshold. The dead peer NEVER delivers DATA back.
        while now <= base + TH + 2 * AFTER {
            if probe_emit(&node, now) {
                probes += 1;
            }
            now += step;
        }
        assert!(probes >= 3, "a dead peer is re-probed every window (fixed cadence)");
        assert!(
            !node.dataplane_healthy(base + TH + 1, TH),
            "no DATA came back past the threshold ⇒ UNHEALTHY (reboot must fire)"
        );
    }

    /// `idle_probe_target` prefers a RELAY-ANCHORED peer (direct NOT confirmed)
    /// and breaks ties by the lowest ULA so the choice is stable across ticks.
    #[test]
    fn idle_probe_target_prefers_relay_anchored_lowest_ula() {
        let me = StaticSecret::from([9u8; 32]);
        let mk = |ula: &str, pk: u8| crate::peer::PeerInfo {
            peer_id: uuid::Uuid::nil(),
            wg_public_key: *PublicKey::from(&StaticSecret::from([pk; 32])).as_bytes(),
            ula: ula.parse().unwrap(),
            listen_endpoint: Some("127.0.0.1:51820".parse().unwrap()),
            display_name: "peer".into(),
            tags: vec![],
            hosted_app_ulas: vec![],
            software_version: None,
            mesh_version: None,
            joined_at_micros: 0,
        };
        let t = SessionTable::new();
        t.upsert(&me, &mk("fd5a:1f00:1::3", 3));
        t.upsert(&me, &mk("fd5a:1f00:1::1", 4));
        t.upsert(&me, &mk("fd5a:1f00:1::2", 5));
        // All unconfirmed (relay-anchored) ⇒ lowest ULA wins.
        let target = t.idle_probe_target().expect("a target exists");
        let lowest: Ipv6Addr = "fd5a:1f00:1::1".parse().unwrap();
        assert_eq!(target.ula, lowest);
        // Confirm the lowest-ULA peer's direct path: it is no longer
        // relay-anchored, so the next-lowest UNCONFIRMED peer is preferred.
        target.confirm_direct(1);
        let next = t.idle_probe_target().expect("a target still exists");
        let second: Ipv6Addr = "fd5a:1f00:1::2".parse().unwrap();
        assert_eq!(
            next.ula, second,
            "a confirmed-direct peer is skipped in favour of a relay-anchored one"
        );
    }

    /// An empty table has no probe target (the caller gates on peers-present,
    /// but the picker is defensively `None`).
    #[test]
    fn idle_probe_target_none_when_empty() {
        assert!(SessionTable::new().idle_probe_target().is_none());
    }
}
