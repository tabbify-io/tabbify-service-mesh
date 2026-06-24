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
    /// Unix-micros of the LAST active IDLE LIVENESS PROBE the timer loop fired
    /// (B-fix-1). Rate-limits that probe so an ambiguously-idle node emits ONE
    /// keepalive-sized frame per (escalating) interval (advancing
    /// `last_send_attempt_ts`) instead of a busy-loop. The probe's ONLY job is to
    /// break the fail-open idle rule in `dataplane_healthy`: once it advances the
    /// send clock past the RX clock, the UNCHANGED black-hole verdict can detect
    /// a node whose data plane is wedged (no real RX in the 90s window) — the
    /// 2026-06-21 MSI signature where a trickle of relay control frames masked a
    /// black hole. `0` = "never probed". `Arc<AtomicI64>` like the other clocks
    /// so the rate-limit is process-global across the cheap-clone table.
    last_idle_probe_ts: Arc<AtomicI64>,
    /// Count of consecutive idle liveness probes emitted WITHOUT a real inbound
    /// frame arriving since (B-fix-1 ESCALATING back-off — task #13). The probe
    /// interval grows `min(BASE << streak, CAP)` so a chronically black-holed
    /// peer (MSI's flaky WAN) is probed ever LESS often — a bounded retry
    /// schedule, NOT a fixed-interval hammer. Reset to `0` the instant a real
    /// inbound data frame lands ([`Self::note_inbound_data_frame`]): the moment
    /// the path recovers, probing returns to the responsive BASE cadence.
    /// `Arc<AtomicU32>` so the streak is process-global across the cheap-clone
    /// table, like the liveness clocks.
    idle_probe_streak: Arc<AtomicU32>,
    /// Optional sender to the convergence-kick queue (eager-relay-convergence).
    /// When `Some` (the joiner wires it via [`Self::with_convergence_tx`]), a
    /// genuinely-NEW, non-ephemeral session is enqueued on [`Self::upsert`] so a
    /// background `convergence_loop` fires ONE relay-floored handshake kick —
    /// converging a passive/far peer without waiting on the ~25s persistent-
    /// keepalive bootstrap. `None` (the default) keeps the pre-convergence
    /// behaviour (tests, `--no-relay`). Cheap-clone like `relay`.
    convergence_tx: Option<UnboundedSender<Arc<PeerSession>>>,
}

/// How long a node may be AMBIGUOUSLY IDLE before the active idle liveness
/// probe starts firing (B-fix-1).
///
/// "Ambiguously idle" = peers present, no send since the last inbound, RX clock
/// not fresh. 45s sits BELOW the 90s `DATAPLANE_RX_SILENCE_THRESHOLD_MICROS` so
/// the probe has time to advance the send clock and let a genuine black hole
/// age the RX clock out within one 90s window. Above the ~20s heartbeat /
/// keepalive cadence so a normally quiet-but-live node (keepalives still
/// round-tripping) never trips it.
pub const IDLE_PROBE_AFTER_MICROS: i64 = 45_000_000;

/// BASE spacing between consecutive active idle liveness probes (B-fix-1,
/// escalating back-off — task #13).
///
/// The FIRST probe after the path goes silent fires at this cadence (30s):
/// frequent enough that the send clock stays ahead of the RX clock across the
/// 90s freshness window, so `dataplane_healthy` reliably flips unhealthy on a
/// genuine black hole within the first window. Each subsequent un-answered probe
/// doubles the wait ([`SessionTable::idle_probe_interval`]) up to
/// [`IDLE_PROBE_INTERVAL_CAP_MICROS`] — a chronically dead peer is NOT hammered
/// at a fixed 30s rate.
pub const IDLE_PROBE_INTERVAL_BASE_MICROS: i64 = 30_000_000;

/// CAP on the escalating idle-probe interval (B-fix-1 — task #13).
///
/// The doubling back-off saturates here (10 min) so a permanently black-holed
/// peer still gets an occasional liveness probe (the path may recover) without
/// ever returning to a tight loop. Once a real inbound frame lands the streak
/// resets and the cadence drops straight back to
/// [`IDLE_PROBE_INTERVAL_BASE_MICROS`].
pub const IDLE_PROBE_INTERVAL_CAP_MICROS: i64 = 600_000_000;

/// The escalating idle-probe interval for a consecutive-failure `streak`
/// (B-fix-1 — task #13).
///
/// `min(BASE << streak, CAP)`: `streak == 0` (the first probe, or right after a
/// real RX reset the counter) yields BASE; each subsequent un-answered probe
/// doubles the wait up to CAP. Overflow-safe, pure + `const`; delegates to the
/// shared [`escalating_backoff`].
#[must_use]
pub const fn idle_probe_interval(streak: u32, base_micros: i64, cap_micros: i64) -> i64 {
    escalating_backoff(streak, base_micros, cap_micros)
}

/// Shared overflow-safe exponential back-off: `min(base << streak, cap)`.
///
/// Computed by iterative doubling so a large `streak` saturates at `cap` instead
/// of overflowing (`i64::checked_shl` guards only the shift COUNT, not the
/// resulting VALUE — a wide shift silently yields garbage, so it is unsuitable
/// here). Returns `cap` the instant the doubled value reaches or exceeds it.
/// Used by both the idle-probe (task #13) and the expired-`Tunn` re-arm (task
/// #14) loop-guards.
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

/// Pure trigger for the active idle liveness probe (B-fix-1). Returns `true`
/// when the node is AMBIGUOUSLY IDLE and should emit ONE keepalive frame to
/// keep the data-plane liveness signal honest:
///
/// * **No peers** ⇒ `false` (nothing to probe toward — mirrors the
///   `dataplane_healthy` no-peers fail-open).
/// * **Genuinely fresh RX** (`now - last_rx < after_micros`) ⇒ `false`. The
///   data plane is demonstrably alive; no probe needed.
/// * **Already sending after the last RX** (`last_send > last_rx`) ⇒ `false`.
///   The node is NOT idle — `dataplane_healthy` already owns this case (it can
///   see the stale RX while sending and flip unhealthy on its own).
/// * **Ambiguously idle** (peers present AND `last_send <= last_rx` AND
///   `now - last_rx >= after_micros`) ⇒ `true`. This is the exact fail-open
///   blind spot: idle (so judged healthy) yet RX is no longer fresh. Emit a
///   probe so the send clock advances and the black-hole verdict can act.
///
/// Pure (`now` / clocks / threshold injected) and read-only, mirroring
/// [`SessionTable::dataplane_healthy`]; the rate limit lives in
/// [`SessionTable::should_emit_idle_probe`].
#[must_use]
pub const fn idle_probe_due(
    now_micros: i64,
    last_rx_micros: i64,
    last_send_micros: i64,
    has_peers: bool,
    after_micros: i64,
) -> bool {
    if !has_peers {
        return false;
    }
    // Not idle: a send already followed the last inbound — `dataplane_healthy`
    // owns this case, no probe needed.
    if last_send_micros > last_rx_micros {
        return false;
    }
    // Idle: probe only once the RX clock has aged past the ambiguity window.
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
            .field(
                "idle_probe_streak",
                &self.idle_probe_streak.load(Ordering::Relaxed),
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
        // A real inbound frame means the path is alive again — collapse the
        // escalating idle-probe back-off so probing returns to BASE cadence the
        // instant the black hole clears (B-fix-1 — task #13). Relaxed: a racing
        // probe at worst reads a one-step-stale streak, which only shifts the
        // next interval by one doubling — inert against the seconds-scale gate.
        self.idle_probe_streak.store(0, Ordering::Relaxed);
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

    /// Snapshot the consecutive un-answered idle-probe streak (B-fix-1 —
    /// diagnostics + tests). Reset to `0` the instant a real inbound frame lands.
    #[must_use]
    pub fn idle_probe_streak(&self) -> u32 {
        self.idle_probe_streak.load(Ordering::Relaxed)
    }

    /// Decide whether the timer loop should fire ONE active idle liveness probe
    /// THIS tick (B-fix-1), CLAIMING the rate-limit slot when it returns `true`.
    ///
    /// Two gates compose:
    /// 1. [`idle_probe_due`] — the pure ambiguous-idle trigger (peers present,
    ///    idle, RX aged past `after_micros`).
    /// 2. A per-table ESCALATING interval limiter (task #13): at most one probe
    ///    per window, and the window GROWS with the consecutive un-answered
    ///    streak — `min(base << streak, cap)` ([`idle_probe_interval`]). An
    ///    ambiguously-idle node emits ONE keepalive at BASE cadence, then ever
    ///    less often if no RX returns, so a chronically dead peer is never
    ///    hammered at a fixed rate. The first ever probe fires immediately (clock
    ///    starts at `0`, streak `0` ⇒ BASE window already elapsed); each emit
    ///    bumps the streak so the NEXT window doubles. The slot is claimed by
    ///    stamping `last_idle_probe_ts` + incrementing `idle_probe_streak`
    ///    (relaxed, same rationale as the other liveness clocks — a racing
    ///    double-read at worst emits one extra keepalive / mis-steps the back-off
    ///    by one doubling, which WG anti-replay / the relay floor make harmless).
    ///    [`Self::note_inbound_data_frame`] resets the streak to `0` on real RX.
    ///
    /// Read-then-claim is intentional: the caller emits the probe only when this
    /// returns `true`, so claiming here keeps the side effect bounded to one
    /// frame per (escalating) interval regardless of the 200ms timer cadence.
    pub fn should_emit_idle_probe(
        &self,
        now_micros: i64,
        after_micros: i64,
        base_interval_micros: i64,
        cap_interval_micros: i64,
    ) -> bool {
        if !idle_probe_due(
            now_micros,
            self.last_inbound_data_frame_ts(),
            self.last_send_attempt_ts(),
            !self.is_empty(),
            after_micros,
        ) {
            return false;
        }
        // Escalating rate-limit: the required spacing grows with the un-answered
        // streak, so claim the slot iff that (doubling, capped) window elapsed.
        let streak = self.idle_probe_streak.load(Ordering::Relaxed);
        let interval = idle_probe_interval(streak, base_interval_micros, cap_interval_micros);
        let last = self.last_idle_probe_ts.load(Ordering::Relaxed);
        if now_micros.saturating_sub(last) >= interval {
            self.last_idle_probe_ts.store(now_micros, Ordering::Relaxed);
            // Bump the streak so the NEXT un-answered window doubles. Saturating
            // so a pathological run can never wrap (the interval is capped
            // anyway). A real inbound frame resets this to 0.
            let next = streak.saturating_add(1);
            self.idle_probe_streak.store(next, Ordering::Relaxed);
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

    // ---- B-fix-1: active idle liveness probe trigger ----

    /// Probe-after threshold for the pure-trigger tests (45s, mirrors
    /// [`IDLE_PROBE_AFTER_MICROS`]).
    const AFTER: i64 = IDLE_PROBE_AFTER_MICROS;

    /// BASE / CAP idle-probe intervals for the escalating-back-off tests (task
    /// #13). Mirror the production constants.
    const BASE: i64 = IDLE_PROBE_INTERVAL_BASE_MICROS;
    const CAP: i64 = IDLE_PROBE_INTERVAL_CAP_MICROS;

    /// THE ambiguous-idle case the probe exists for: peers present, NO send
    /// since the last inbound (idle ⇒ `dataplane_healthy` would fail-OPEN), and
    /// the RX clock aged PAST the probe-after window. `idle_probe_due` ⇒ true.
    /// This is the exact 2026-06-21 blind spot — a trickle of relay frames kept
    /// RX < 90s while no data round-tripped, so the node read healthy forever.
    #[test]
    fn idle_probe_due_when_ambiguously_idle_and_rx_aged() {
        // last_rx at 10s, no later send (last_send <= last_rx), now well past
        // the 45s ambiguity window.
        assert!(idle_probe_due(
            10_000_000 + AFTER + 1,
            10_000_000, // last_rx
            10_000_000, // last_send == last_rx ⇒ idle
            true,       // peers present
            AFTER,
        ));
    }

    /// RX returns FRESH (`now - last_rx < after`) ⇒ NO probe. The data plane is
    /// demonstrably alive, so the idle probe must not fire — this is the
    /// "+RX-returns ⇒ healthy" direction (the probe stops once real RX resumes).
    #[test]
    fn idle_probe_not_due_when_rx_fresh() {
        assert!(!idle_probe_due(
            10_000_000 + AFTER / 2, // RX age < after ⇒ fresh
            10_000_000,
            10_000_000,
            true,
            AFTER,
        ));
    }

    /// Genuinely-fresh RX at the very edge (RX age just under the window) ⇒ no
    /// probe; the same clocks one tick later (RX age == window) ⇒ probe due.
    /// Pins the boundary so the 45s threshold is exact.
    #[test]
    fn idle_probe_boundary_is_exact() {
        assert!(
            !idle_probe_due(10_000_000 + AFTER - 1, 10_000_000, 10_000_000, true, AFTER),
            "one micro under the window is still fresh ⇒ no probe"
        );
        assert!(
            idle_probe_due(10_000_000 + AFTER, 10_000_000, 10_000_000, true, AFTER),
            "exactly at the window the probe is due"
        );
    }

    /// NOT idle — a send already followed the last inbound (`last_send >
    /// last_rx`) ⇒ NO probe. `dataplane_healthy` already owns this case (it can
    /// see the stale RX while sending and flip unhealthy itself), so the probe
    /// must not double up.
    #[test]
    fn idle_probe_not_due_when_already_sending() {
        assert!(!idle_probe_due(
            10_000_000 + AFTER * 5,
            10_000_000, // last_rx
            20_000_000, // last_send AFTER rx ⇒ not idle
            true,
            AFTER,
        ));
    }

    /// No peers ⇒ NO probe — mirrors the `dataplane_healthy` no-peers fail-open
    /// (nothing to probe toward).
    #[test]
    fn idle_probe_not_due_without_peers() {
        assert!(!idle_probe_due(
            10_000_000 + AFTER * 5,
            10_000_000,
            10_000_000,
            false, // no peers
            AFTER,
        ));
    }

    // ---- task #13: escalating idle-probe interval (pure) ----

    /// `idle_probe_interval` doubles per streak step and saturates at CAP:
    /// streak 0 ⇒ BASE, 1 ⇒ 2·BASE, 2 ⇒ 4·BASE, … then clamps to CAP and never
    /// exceeds it — the bounded-retry schedule that replaces the fixed pulse.
    #[test]
    fn idle_probe_interval_doubles_then_caps() {
        assert_eq!(idle_probe_interval(0, BASE, CAP), BASE, "streak 0 ⇒ BASE");
        assert_eq!(idle_probe_interval(1, BASE, CAP), 2 * BASE, "streak 1 ⇒ 2·BASE");
        assert_eq!(idle_probe_interval(2, BASE, CAP), 4 * BASE, "streak 2 ⇒ 4·BASE");
        // Climb until the doubling would exceed CAP, then stay clamped.
        let mut prev = 0;
        for streak in 0..64u32 {
            let w = idle_probe_interval(streak, BASE, CAP);
            assert!(w >= BASE, "never below BASE");
            assert!(w <= CAP, "back-off {w} must never exceed CAP {CAP}");
            assert!(w >= prev, "monotonic non-decreasing across the streak");
            prev = w;
        }
        assert_eq!(
            idle_probe_interval(u32::MAX, BASE, CAP),
            CAP,
            "a pathological streak saturates at CAP, never overflows"
        );
    }

    /// The end-to-end table gate composes the trigger with the per-table
    /// ESCALATING interval limiter (task #13): an ambiguously-idle table emits
    /// the FIRST probe immediately (clock starts at 0, streak 0 ⇒ BASE window
    /// already elapsed), then SUPPRESSES a second probe within the (now DOUBLED)
    /// window, then ALLOWS one again only past the LARGER window — one keepalive
    /// per escalating window, never a busy-loop.
    #[test]
    fn should_emit_idle_probe_is_rate_limited() {
        let t = table_with_one_peer();
        // Drive into ambiguous-idle: an inbound at 10s, no later send.
        t.note_inbound_data_frame(10_000_000);
        let base = 10_000_000 + AFTER; // first moment the probe is due
        assert!(
            t.should_emit_idle_probe(base, AFTER, BASE, CAP),
            "first probe fires once the ambiguity window is reached"
        );
        assert_eq!(t.idle_probe_streak(), 1, "first emit bumps the streak to 1");
        // After the first emit the streak is 1 ⇒ the next required window is
        // 2·BASE. A probe at base + BASE (one BASE later) is therefore STILL
        // suppressed — proving the back-off escalated, not a fixed BASE pulse.
        assert!(
            !t.should_emit_idle_probe(base + BASE, AFTER, BASE, CAP),
            "a second probe one BASE later is suppressed — the window doubled"
        );
        // Past the doubled window (2·BASE) the next probe fires.
        assert!(
            t.should_emit_idle_probe(base + 2 * BASE, AFTER, BASE, CAP),
            "a probe fires again once the DOUBLED interval has elapsed"
        );
        assert_eq!(t.idle_probe_streak(), 2, "second emit bumps the streak to 2");
    }

    /// A real inbound frame COLLAPSES the escalating back-off (task #13): after
    /// several un-answered probes the streak is high (long window), but the
    /// instant `note_inbound_data_frame` lands the streak resets to 0 so probing
    /// returns to the responsive BASE cadence — the moment the black hole clears.
    #[test]
    fn real_rx_resets_idle_probe_backoff() {
        let t = table_with_one_peer();
        t.note_inbound_data_frame(10_000_000);
        let mut now = 10_000_000 + AFTER;
        // Emit three escalating probes (no RX between them): streak climbs.
        assert!(t.should_emit_idle_probe(now, AFTER, BASE, CAP)); // streak 0→1
        now += 2 * BASE;
        assert!(t.should_emit_idle_probe(now, AFTER, BASE, CAP)); // streak 1→2
        now += 4 * BASE;
        assert!(t.should_emit_idle_probe(now, AFTER, BASE, CAP)); // streak 2→3
        assert_eq!(t.idle_probe_streak(), 3, "three un-answered probes");
        // RX returns: the streak collapses to 0.
        t.note_inbound_data_frame(now);
        assert_eq!(t.idle_probe_streak(), 0, "real RX resets the back-off");
        // The path goes silent again; the very next due probe fires at BASE
        // cadence (not the long pre-reset window), proving recovery is snappy.
        let due = now + AFTER; // RX aged past the ambiguity window again
        assert!(
            t.should_emit_idle_probe(due, AFTER, BASE, CAP),
            "after a reset the next probe is due at BASE cadence again"
        );
    }

    /// The gate claims the rate-limit slot ONLY when it actually emits: a
    /// not-due call (fresh RX) must NOT stamp `last_idle_probe_ts`, so a later
    /// genuinely-due tick still fires immediately. Guards against a fresh-RX
    /// tick silently consuming the interval.
    #[test]
    fn should_emit_idle_probe_does_not_claim_when_not_due() {
        let t = table_with_one_peer();
        t.note_inbound_data_frame(10_000_000);
        // Fresh RX ⇒ not due ⇒ must not claim the slot.
        assert!(!t.should_emit_idle_probe(10_000_000 + AFTER / 2, AFTER, BASE, CAP));
        assert_eq!(t.last_idle_probe_ts(), 0, "a not-due call must not stamp");
        assert_eq!(t.idle_probe_streak(), 0, "a not-due call must not bump the streak");
        // Now genuinely due → fires immediately (slot was never consumed).
        assert!(t.should_emit_idle_probe(10_000_000 + AFTER, AFTER, BASE, CAP));
    }

    /// END-TO-END liveness chain (the whole point of B-fix-1): an
    /// ambiguously-idle node reads HEALTHY under `dataplane_healthy` (the
    /// fail-open blind spot). After the probe stamps the send clock, the
    /// UNCHANGED verdict flips UNHEALTHY because RX is still stale — and once
    /// real RX returns it is healthy again.
    #[test]
    fn probe_then_no_rx_makes_dataplane_unhealthy() {
        let t = table_with_one_peer();
        t.note_inbound_data_frame(10_000_000); // last RX at 10s, no send after
        let now = 10_000_000 + TH + 1; // past the 90s RX-silence threshold
        // BEFORE the probe: idle ⇒ fail-open ⇒ judged HEALTHY despite stale RX.
        assert!(
            t.dataplane_healthy(now, TH),
            "the fail-open idle rule masks the black hole before any probe"
        );
        // The probe fires (ambiguous-idle) and stamps the send clock.
        assert!(t.should_emit_idle_probe(now, AFTER, BASE, CAP));
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
