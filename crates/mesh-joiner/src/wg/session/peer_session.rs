//! Per-peer `boringtun::noise::Tunn` plus the routing metadata the data
//! plane needs.
//!
//! One [`PeerSession`] = one `Tunn` + an allowed-`/128` source set + the
//! UDP endpoint to dial. The registry that tracks all live sessions
//! lives in [`super::table`].

use crate::peer::PeerInfo;
use boringtun::noise::Tunn;
use std::collections::HashSet;
use std::net::{Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, Ordering};
use tokio::sync::Mutex;

/// How long a confirmed-direct path may go without a VALID inbound UDP
/// datagram before we downgrade it back to the relay floor.
///
/// 35 s is deliberately comfortably above `WireGuard`'s 25 s persistent
/// keepalive (`WG_PERSISTENT_KEEPALIVE_SECS`): a live-but-idle direct path
/// keeps refreshing `last_direct_rx_micros` via those keepalives, so it
/// never false-downgrades. Once the path actually dies (NAT rebind / SG
/// change) no keepalives arrive, the timestamp ages past this TTL, and the
/// next `downgrade_direct_if_stale` falls the session back to the relay.
pub const DIRECT_PATH_TTL_MICROS: i64 = 35_000_000;

/// How long a confirmed-direct path may carry ACTIVE non-keepalive TX with
/// ZERO direct inbound DATA before it is declared a TX black hole.
///
/// Fires [`PeerSession::downgrade_direct_if_tx_blackholed`] — the
/// DIRECTION-AWARE sibling of [`DIRECT_PATH_TTL_MICROS`]: the
/// staleness TTL measures only RX (any valid inbound datagram refreshes it),
/// so a peer whose OUTBOUND path to us stays alive keeps a confirmed session
/// "fresh" forever even when OUR outbound direct path to it is dead — the
/// asymmetric wedge (the MSI symmetric-NAT incident: their keepalives arrive,
/// our frames vanish, the relay is never engaged). This TTL closes it: if we
/// are actively transmitting on the confirmed path (a non-keepalive send
/// within the window) yet no direct inbound DATA (`DeliverToTun`,
/// `via_direct`) has arrived within the same window, the direct path has not
/// proven our TX direction — fall back to the relay floor and let the
/// governed probe re-confirm.
///
/// 20 s is several WG retransmit cycles (5 s) and far above any WAN RTT, so
/// an active healthy flow (whose return DATA arrives within milliseconds)
/// never trips it; it stays below the 25 s keepalive/idle-probe cadences so
/// a genuinely wedged path falls back before boringtun's 90 s handshake
/// expiry compounds the outage.
pub const DIRECT_TX_BLACKHOLE_TTL_MICROS: i64 = 20_000_000;

/// Base back-off window after the FIRST failed direct handshake (A-c).
///
/// Each consecutive failure roughly doubles the window (capped at
/// `DIRECT_BACKOFF_CAP_MICROS`), so a black-hole candidate is re-probed
/// exponentially less often instead of every probe interval forever. 2 s is a
/// few WG retransmit cycles — enough that a transient stall recovers without a
/// long penalty, short enough to retry a flapping path soon.
pub const DIRECT_BACKOFF_BASE_MICROS: i64 = 2_000_000;

/// Cap on the exponential direct-handshake back-off (A-c).
///
/// A permanently unreachable candidate (symmetric NAT / black hole) is
/// re-probed at most once per cap interval — the durable replacement for the
/// `relay_only` sledgehammer. 5 min keeps the SPOF-relief probe rare while
/// still periodically re-checking in case the NAT mapping changes.
pub const DIRECT_BACKOFF_CAP_MICROS: i64 = 300_000_000;

/// BASE spacing between automatic expired-`Tunn` RE-ARMS (FIX 3 + task #14
/// loop-guard).
///
/// boringtun gives up on a handshake after `REKEY_ATTEMPT_TIME` (90 s of
/// retransmitting the init every `REKEY_TIMEOUT`=5 s with no response): it calls
/// `set_expired()` and from then on EVERY `update_timers` returns
/// `ConnectionExpired` forever — it never emits another init on its own. A fresh
/// relay-only ⇄ relay-only peer (the lifeline `fc22:6::1`) whose first 90 s
/// window lapses without a completed relayed handshake is then permanently
/// wedged. The timer loop detects the expired `Tunn` and re-arms it (a fresh
/// handshake-init over the relay floor). The FIRST re-arm is gated at this
/// BASE cadence (~one fresh WG attempt-window after the last); each consecutive
/// STILL-FAILING re-arm doubles the wait ([`PeerSession::should_rearm_expired`])
/// up to [`EXPIRED_REARM_BACKOFF_CAP_MICROS`] — the loop-guard that stops a
/// chronically-dead peer (MSI's flaky WAN) from re-handshaking at a fixed 90 s
/// rate forever. Matches `REKEY_ATTEMPT_TIME`.
pub const EXPIRED_REARM_BACKOFF_MICROS: i64 = 90_000_000;

/// CAP on the escalating expired-`Tunn` re-arm back-off (task #14 loop-guard).
///
/// A permanently-wedged session (chronic WAN black hole) re-arms at most once
/// per cap interval (10 min) instead of every 90 s — a BOUNDED-retry schedule
/// that still periodically re-attempts a relayed bootstrap (the path may
/// recover) without churning a re-handshake every attempt-window. The streak
/// resets the instant a valid inbound datagram proves the path is alive
/// ([`PeerSession::note_direct_rx`]), so a transient wedge drops straight back
/// to the responsive BASE cadence.
pub const EXPIRED_REARM_BACKOFF_CAP_MICROS: i64 = 600_000_000;

/// BRISK re-arm base for an EAGER (host/infra) peer that has not yet converged.
///
/// At `= REKEY_TIMEOUT` (5 s) it is the FLOOR that avoids double-minting an init
/// inside one boringtun REKEY window: boringtun retransmits its own init every
/// 5 s, so a faster re-arm would race it (WG dedups and the relay carries both,
/// but 5 s keeps it clean). An eager peer thus re-arms at 5 s → 10 s → … →
/// [`EXPIRED_REARM_BACKOFF_CAP_MICROS`], converging a lossy WAN far faster than
/// the 90 s default, while the streak still backs a chronically-dead peer off.
pub const CONVERGENCE_REARM_BACKOFF_MICROS: i64 = 5_000_000;

/// The escalating expired-`Tunn` re-arm interval for a consecutive-failure
/// `streak` (task #14 loop-guard).
///
/// `min(BASE << streak, CAP)`: `streak == 0` (the first re-arm, or right after a
/// real RX reset the counter) yields BASE; each subsequent still-failing re-arm
/// doubles the wait up to CAP. Overflow-safe, pure + `const`; delegates to the
/// shared [`super::table::escalating_backoff`].
#[must_use]
pub const fn rearm_interval(streak: u32, base_micros: i64, cap_micros: i64) -> i64 {
    super::table::escalating_backoff(streak, base_micros, cap_micros)
}

/// One peer's encryption state + routing metadata.
pub struct PeerSession {
    /// The peer's coordinator-assigned id. Useful for tracing.
    pub peer_id: uuid::Uuid,
    /// IPv6 ULA assigned to this peer.
    pub ula: Ipv6Addr,
    /// The peer's raw 32-byte X25519 `WireGuard` public key. Captured at
    /// [`super::SessionTable::upsert`] time so the relay RX path can demux
    /// an inbound frame (keyed by source pubkey) to the right session.
    pub peer_pubkey: [u8; 32],
    /// The set of `/128` source addresses this peer is permitted to use
    /// (spec §5.5 — cryptokey-routing invariant). Built from the
    /// coordinator's roster at [`super::SessionTable::upsert`] time: at minimum
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
    /// `true` when the CURRENT `endpoint` was LEARNED from an authenticated
    /// inbound datagram ([`super::SessionTable::learn_endpoint`] adoption) rather
    /// than copied from the roster's advertised candidate. Provenance matters:
    /// a LEARNED endpoint is the address the peer's packets ACTUALLY arrive
    /// from (its live per-us NAT mapping), while the roster candidate is only
    /// the coordinator-observed reflexive address — for a symmetric-NAT peer
    /// (per-destination mappings) the candidate is a BLACK HOLE toward us. A
    /// roster re-upsert must therefore never overwrite a learned endpoint
    /// (`SessionTable::update_in_place`); the flag is cleared when the path is
    /// downgraded (stale RX / TX black hole), re-opening the roster repoint.
    pub endpoint_learned: AtomicBool,
    /// `true` once a CONFIRMED-working direct path to this peer exists —
    /// i.e. a decrypted DATA packet (`boringtun`'s `DeliverToTun`) has
    /// arrived over UDP, proving the direct path works BIDIRECTIONALLY (the
    /// sender only emits data after ITS handshake completed, which required
    /// our response to reach it). Until then `endpoint` is only a
    /// CANDIDATE and the TX path uses the relay floor. A lone handshake
    /// init/response must NEVER set this — it can arrive directly even when
    /// the return path is blocked, which would falsely upgrade.
    pub direct_confirmed: AtomicBool,
    /// Unix-micros of the last VALID inbound UDP datagram from this peer
    /// (any valid `WireGuard` packet, incl. keepalives). Drives the
    /// staleness downgrade: a confirmed path that stops receiving for
    /// longer than `DIRECT_PATH_TTL_MICROS` is downgraded back to the
    /// relay. `0` means "never seen a valid direct datagram".
    pub last_direct_rx_micros: AtomicI64,
    /// Unix-micros of the last NON-KEEPALIVE frame sent over the CONFIRMED
    /// direct path (data or handshake — anything that creates an RX
    /// expectation, the same rule as the table-global `note_send_attempt`).
    /// Pairs with `last_direct_data_rx_micros` to drive the TX-black-hole
    /// downgrade ([`Self::downgrade_direct_if_tx_blackholed`]). `0` = never.
    pub last_direct_data_tx_micros: AtomicI64,
    /// Unix-micros of the last inner DATA packet delivered from this peer over
    /// the DIRECT path (`DeliverToTun` with `via_direct` — the only proof the
    /// direct path works BIDIRECTIONALLY). Stamped by [`Self::confirm_direct`],
    /// which is invoked on exactly that event. `0` = never.
    pub last_direct_data_rx_micros: AtomicI64,
    /// Unix-micros of the last UNCONFIRMED direct PROBE we sent at this
    /// peer's candidate endpoint (see `send_wire`). Rate-limits the probe so
    /// a black-hole candidate (a reflexive endpoint that never works) costs
    /// ~1 packet per probe-interval instead of a full-rate duplicate stream,
    /// while still letting one probe win the race on a genuinely reachable
    /// path. `0` = never probed, so the first send probes immediately.
    pub last_probe_micros: AtomicI64,
    /// Count of consecutive FAILED direct handshakes to this peer's candidate
    /// endpoint (A-c hysteresis). Drives the exponential back-off window in
    /// `direct_suppressed_until`. Reset to 0 on ANY valid inbound datagram
    /// (`note_direct_rx`) — a live candidate is never penalised. A relaxed
    /// counter is fine: an off-by-one in a racing double-increment only
    /// nudges the back-off by one step.
    pub failed_handshake_count: AtomicU32,
    /// Unix-micros until which the unconfirmed direct PROBE is SUPPRESSED for
    /// this peer (A-c hysteresis). Set by `note_handshake_failure` to
    /// `now + min(BASE << (failures-1), CAP)`. `0` = never failed → not
    /// suppressed. The probe gate in `send_wire` skips probing while
    /// `now < direct_suppressed_until`, converting the 1/s forever-probe into
    /// bounded, exponentially-spaced attempts. Cleared on a valid inbound rx.
    pub direct_suppressed_until: AtomicI64,
    /// Unix-micros of the last automatic EXPIRED-`Tunn` re-arm (FIX 3). The
    /// timer loop re-arms a `Tunn` boringtun gave up on (`set_expired` after
    /// `REKEY_ATTEMPT_TIME`) so a wedged relay-only ⇄ relay-only session can
    /// bootstrap; this clock rate-limits the re-arm to one per
    /// the ESCALATING `EXPIRED_REARM_BACKOFF_MICROS` window (task #14 loop-guard,
    /// see `rearm_streak`) so a genuinely-unreachable peer retries at an ever
    /// SLOWER WG cadence instead of every 200 ms tick. `0` = never re-armed →
    /// the first detected expiry re-arms at once.
    pub last_rearm_micros: AtomicI64,
    /// Count of consecutive automatic expired-`Tunn` re-arms WITHOUT a valid
    /// inbound datagram arriving since (task #14 loop-guard). Drives the
    /// escalating re-arm back-off in [`Self::should_rearm_expired`]:
    /// `min(BASE << streak, CAP)`, so a chronically black-holed peer re-arms
    /// ever less often — a bounded retry schedule, NOT a fixed 90 s loop. Reset
    /// to `0` on ANY valid inbound datagram ([`Self::note_direct_rx`]): the
    /// instant the relayed handshake completes (RX resumes), re-arming returns
    /// to the responsive BASE cadence. Relaxed like the other counters — an
    /// off-by-one in a racing increment only nudges the back-off by one step.
    pub rearm_streak: AtomicU32,
    /// `true` when this is a long-lived host/infra peer eligible for EAGER
    /// convergence (set at upsert from `!is_ephemeral_peer`). An eager peer that
    /// has not yet converged re-arms its expired `Tunn` on the BRISK
    /// [`CONVERGENCE_REARM_BACKOFF_MICROS`] (5 s) base instead of the 90 s
    /// default — so a far/lossy/passive peer bootstraps quickly once its first
    /// cold-handshake window lapses, while ephemeral runner-FCs keep the slow
    /// default. Relaxed like the other flags; a stale read shifts ONE re-arm
    /// window at worst.
    pub eager_convergence: AtomicBool,
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

    /// `true` iff a confirmed-working direct path exists. The TX hot path
    /// reads this on every send to decide direct-vs-relay; a relaxed load
    /// is fine because the worst case of a stale read is one extra packet
    /// over the wrong path.
    pub fn direct_confirmed(&self) -> bool {
        self.direct_confirmed.load(Ordering::Relaxed)
    }

    /// `true` when this peer is eligible for eager convergence (a long-lived
    /// host/infra peer, set at upsert). Drives the BRISK expired-`Tunn` re-arm
    /// base (`CONVERGENCE_REARM_BACKOFF_MICROS`) instead of the 90 s default.
    pub fn eager_convergence(&self) -> bool {
        self.eager_convergence.load(Ordering::Relaxed)
    }

    /// Live path snapshot for diagnostics / heartbeat reporting:
    /// `(direct_confirmed, age_micros)` where `age_micros = now_micros -
    /// last_direct_rx_micros`. The connectivity-visibility feature reports
    /// this per peer so the coordinator can stamp a "direct vs relay" path
    /// from a requested vantage. A relaxed load is fine — a one-tick-stale
    /// read only ages out a path slightly later. The age is signed and may
    /// be negative for a clock skew between the confirm and this read;
    /// callers clamp it to a non-negative wire value.
    pub fn path_status(&self, now_micros: i64) -> (bool, i64) {
        let direct = self.direct_confirmed.load(Ordering::Relaxed);
        let age = now_micros - self.last_direct_rx_micros.load(Ordering::Relaxed);
        (direct, age)
    }

    /// Refresh the last-valid-RX timestamp. Called on ANY valid inbound UDP
    /// datagram (incl. `WireGuard` keepalives), so a confirmed-but-idle
    /// direct path keeps its staleness clock fresh and never
    /// false-downgrades. Does NOT confirm the path — only
    /// `confirm_direct` does.
    pub fn note_direct_rx(&self, now_micros: i64) {
        self.last_direct_rx_micros
            .store(now_micros, Ordering::Relaxed);
        // A valid inbound datagram proves this candidate is alive → drop any
        // accumulated handshake-failure penalty so it is probed freely again,
        // AND collapse the escalating expired-Tunn re-arm back-off (task #14
        // loop-guard) so a recovered session re-arms at BASE cadence again.
        self.clear_handshake_backoff();
        self.rearm_streak.store(0, Ordering::Relaxed);
    }

    /// THE upgrade signal: a decrypted DATA packet arrived over UDP,
    /// proving the direct path works bidirectionally. Mark the path
    /// confirmed AND refresh the staleness clock. Called ONLY from the
    /// `DeliverToTun` path on a direct (non-relayed) datagram.
    pub fn confirm_direct(&self, now_micros: i64) {
        self.direct_confirmed.store(true, Ordering::Relaxed);
        self.last_direct_rx_micros
            .store(now_micros, Ordering::Relaxed);
        // The confirming event IS a direct inbound DATA delivery — stamp the
        // direction-aware clock the TX-black-hole downgrade compares against.
        self.last_direct_data_rx_micros
            .store(now_micros, Ordering::Relaxed);
    }

    /// `true` when the current `endpoint` was LEARNED from an authenticated
    /// inbound datagram rather than copied from the roster (see the field doc).
    /// Read by `SessionTable::update_in_place` to keep the roster's advertised
    /// candidate from clobbering a live learned address.
    #[must_use]
    pub fn endpoint_learned(&self) -> bool {
        self.endpoint_learned.load(Ordering::Relaxed)
    }

    /// Stamp a NON-KEEPALIVE send over the CONFIRMED direct path (data or
    /// handshake — anything that creates an RX expectation; bare keepalives are
    /// excluded by the caller, mirroring the table-global `note_send_attempt`
    /// rule). Feeds [`Self::downgrade_direct_if_tx_blackholed`].
    pub fn note_direct_tx(&self, now_micros: i64) {
        self.last_direct_data_tx_micros
            .store(now_micros, Ordering::Relaxed);
    }

    /// Direction-aware downgrade (the asymmetric-wedge backstop): a CONFIRMED
    /// direct path that is ACTIVELY transmitting (a non-keepalive send within
    /// `ttl_micros`) yet has received ZERO direct inbound DATA within the same
    /// window is a TX black hole — our frames vanish even though the peer's
    /// own outbound path to us may still be refreshing the RX-staleness clock
    /// (keepalives / handshakes keep `downgrade_direct_if_stale` from ever
    /// firing). Fall back to the relay floor and let the governed probe
    /// re-confirm. Returns `true` when it downgraded.
    ///
    /// Guards, in order:
    /// * not confirmed → `false` (the relay floor already carries TX);
    /// * never sent (`last_direct_data_tx == 0`) → `false`;
    /// * NOT actively sending (last non-keepalive TX older than the window) →
    ///   `false` — an idle pair has no RX expectation and must never flap;
    /// * direct DATA arrived within the window → `false` — the path is proven.
    ///
    /// An actual downgrade counts as a handshake failure (the same
    /// anti-oscillation rule as the stale downgrade) and clears
    /// `endpoint_learned` so the next roster upsert may repoint the candidate.
    pub fn downgrade_direct_if_tx_blackholed(&self, now_micros: i64, ttl_micros: i64) -> bool {
        if !self.direct_confirmed.load(Ordering::Relaxed) {
            return false;
        }
        let last_tx = self.last_direct_data_tx_micros.load(Ordering::Relaxed);
        if last_tx == 0 {
            return false;
        }
        let actively_sending = now_micros.saturating_sub(last_tx) <= ttl_micros;
        let rx_silent = now_micros.saturating_sub(
            self.last_direct_data_rx_micros.load(Ordering::Relaxed),
        ) > ttl_micros;
        if actively_sending && rx_silent {
            self.direct_confirmed.store(false, Ordering::Relaxed);
            self.endpoint_learned.store(false, Ordering::Relaxed);
            // Anti-oscillation: same rule as the stale downgrade — the failed
            // candidate serves out a back-off window before being re-probed.
            self.note_handshake_failure(now_micros);
            return true;
        }
        false
    }

    /// Rate-limit gate for the unconfirmed direct PROBE in `send_wire`:
    /// returns `true` at most once per `interval_micros`, stamping the clock
    /// when it does. A relaxed load/store is fine — a racing double-read at
    /// worst emits one extra probe, which is harmless (the probe is the same
    /// encapsulated frame the relay also carries; WG anti-replay dedups). The
    /// first call (clock = `0`) always probes, so a freshly reachable path
    /// confirms without waiting a full interval.
    pub fn should_probe_direct(&self, now_micros: i64, interval_micros: i64) -> bool {
        let last = self.last_probe_micros.load(Ordering::Relaxed);
        if now_micros.saturating_sub(last) >= interval_micros {
            self.last_probe_micros.store(now_micros, Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    /// Snapshot the consecutive failed-handshake count (diagnostics + tests).
    #[must_use]
    pub fn failed_handshake_count(&self) -> u32 {
        self.failed_handshake_count.load(Ordering::Relaxed)
    }

    /// Snapshot the suppression deadline (diagnostics + tests).
    #[must_use]
    pub fn direct_suppressed_until_micros(&self) -> i64 {
        self.direct_suppressed_until.load(Ordering::Relaxed)
    }

    /// `true` iff the unconfirmed direct probe is currently SUPPRESSED for this
    /// peer — i.e. `now_micros` is before the back-off deadline a prior
    /// failure set. The probe gate consults this so a black-hole candidate is
    /// re-probed only on the exponential schedule, not every interval.
    #[must_use]
    pub fn direct_suppressed(&self, now_micros: i64) -> bool {
        now_micros < self.direct_suppressed_until.load(Ordering::Relaxed)
    }

    /// Record one FAILED direct handshake: bump the consecutive-failure count
    /// and open an exponential-capped back-off window. The window is
    /// `min(BASE << (failures-1), CAP)` so the first failure backs off `BASE`,
    /// the second `2·BASE`, … saturating at `CAP`. A relaxed load/store pair is
    /// fine — a racing double-call at worst advances the schedule one step.
    pub fn note_handshake_failure(&self, now_micros: i64) {
        let failures = self.failed_handshake_count.fetch_add(1, Ordering::Relaxed) + 1;
        // Saturating shift: clamp the exponent so the `<<` can't overflow, then
        // clamp the product to the cap. `failures - 1` is the step (1st failure
        // ⇒ exponent 0 ⇒ BASE).
        let exp = (failures - 1).min(30); // BASE << 30 already ≫ CAP
        // `checked_shl` returns None on an out-of-range shift; we clamp `exp`
        // to 30 (BASE << 30 ≈ 2^51, well within i64 and already ≫ CAP), so the
        // shift never overflows and the `.min(CAP)` below caps the window.
        let window = DIRECT_BACKOFF_BASE_MICROS
            .checked_shl(exp)
            .unwrap_or(DIRECT_BACKOFF_CAP_MICROS)
            .min(DIRECT_BACKOFF_CAP_MICROS);
        self.direct_suppressed_until
            .store(now_micros.saturating_add(window), Ordering::Relaxed);
    }

    /// Clear the back-off: reset the failure count to 0 and lift any
    /// suppression window. Called when the candidate proves itself alive (a
    /// valid inbound datagram). Folded into `note_direct_rx` below.
    pub fn clear_handshake_backoff(&self) {
        self.failed_handshake_count.store(0, Ordering::Relaxed);
        self.direct_suppressed_until.store(0, Ordering::Relaxed);
    }

    /// Snapshot the consecutive un-answered expired-`Tunn` re-arm streak (task
    /// #14 loop-guard — diagnostics + tests). Reset to `0` on a valid inbound rx.
    #[must_use]
    pub fn rearm_streak(&self) -> u32 {
        self.rearm_streak.load(Ordering::Relaxed)
    }

    /// Rate-limit gate for the automatic expired-`Tunn` RE-ARM (FIX 3 + task #14
    /// loop-guard): returns `true` at most once per ESCALATING back-off window,
    /// stamping the clock + bumping the streak when it does. The timer loop calls
    /// this only after it has already observed `Tunn::is_expired()`, so a `true`
    /// means "this expired session is due for a fresh handshake-init now".
    ///
    /// The first call (clock = `0`, streak = `0`) re-arms immediately so a
    /// just-wedged session bootstraps without waiting a full back-off. Each
    /// consecutive STILL-FAILING re-arm doubles the required wait —
    /// `min(base << streak, cap)` ([`rearm_interval`]) — so a chronically
    /// unreachable peer (MSI's flaky WAN) re-arms ever LESS often instead of
    /// re-handshaking at a fixed 90 s rate forever (THE loop-guard). A valid
    /// inbound datagram resets the streak ([`Self::note_direct_rx`]) so a
    /// transient wedge recovers at BASE cadence. A relaxed load/store is fine — a
    /// racing double-read at worst fires one extra init (boringtun's own
    /// retransmit would emit it anyway) or mis-steps the back-off by one
    /// doubling.
    pub fn should_rearm_expired(&self, now_micros: i64, base_micros: i64, cap_micros: i64) -> bool {
        let streak = self.rearm_streak.load(Ordering::Relaxed);
        let backoff = rearm_interval(streak, base_micros, cap_micros);
        let last = self.last_rearm_micros.load(Ordering::Relaxed);
        if now_micros.saturating_sub(last) >= backoff {
            self.last_rearm_micros.store(now_micros, Ordering::Relaxed);
            // Bump the streak so the NEXT still-failing window doubles; a valid
            // inbound rx resets it to 0. Saturating so a pathological run never
            // wraps (the window is capped regardless).
            self.rearm_streak
                .store(streak.saturating_add(1), Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    /// Downgrade a confirmed path back to the relay floor if it has gone
    /// silent for longer than `ttl_micros` (NAT rebind / path death). A
    /// no-op when the path is already unconfirmed or still fresh. Called
    /// from the timer loop on every tick.
    pub fn downgrade_direct_if_stale(&self, now_micros: i64, ttl_micros: i64) {
        if self.direct_confirmed.load(Ordering::Relaxed)
            && now_micros - self.last_direct_rx_micros.load(Ordering::Relaxed) > ttl_micros
        {
            self.direct_confirmed.store(false, Ordering::Relaxed);
            // The learned endpoint went silent past the TTL — its NAT mapping
            // is presumed dead, so surrender provenance: the next roster
            // upsert may repoint the advertised candidate, and a live inbound
            // source will re-learn.
            self.endpoint_learned.store(false, Ordering::Relaxed);
            // Anti-oscillation: a path that confirmed then went silent is now
            // suspect. Count the downgrade as a handshake failure so the next
            // `send_wire` does NOT immediately re-probe and re-flap — the
            // candidate must serve out a back-off window first. A path that is
            // genuinely back (return frames resume) clears this on the next
            // valid `note_direct_rx`. Only the ACTUAL confirmed→relay
            // transition penalises; a no-op downgrade leaves the count alone.
            self.note_handshake_failure(now_micros);
        }
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

    /// Force a fresh WG handshake on THIS session (Track C `ResetWg`).
    ///
    /// Re-arms the boringtun `Tunn` in place via [`Tunn::set_static_private`],
    /// which CLEARS every established noise session and resets the handshake
    /// state so the next outbound frame re-initiates the handshake — clearing a
    /// half-open / stale session WITHOUT a process restart. The peer pubkey,
    /// endpoint, allowed-source set, and the `direct_confirmed` flag are all
    /// untouched, so the relay floor and any confirmed-direct path are
    /// preserved exactly (a relay-only peer simply re-handshakes over the
    /// relay). `our_private` is this node's own X25519 secret — the same key
    /// the session was built with at `upsert` time.
    pub async fn reset_handshake(&self, our_private: &x25519_dalek::StaticSecret) {
        let our_public = x25519_dalek::PublicKey::from(our_private);
        let mut tunn = self.tunn.lock().await;
        // `None` rate-limiter → boringtun keeps the existing default limiter
        // semantics (rate-limited like a fresh `Tunn::new` with `None`).
        tunn.set_static_private(our_private.clone(), our_public, None);
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
pub(super) fn allowed_ips_for(info: &PeerInfo) -> HashSet<Ipv6Addr> {
    let mut set = HashSet::with_capacity(1);
    set.insert(info.ula);
    set
}

impl std::fmt::Debug for PeerSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerSession")
            .field("peer_id", &self.peer_id)
            .field("ula", &self.ula)
            .field("peer_pubkey", &"<pubkey>")
            .field("allowed_ips", &self.allowed_ips.read())
            .field("endpoint", &self.endpoint())
            .field("endpoint_learned", &self.endpoint_learned())
            .field("direct_confirmed", &self.direct_confirmed())
            .field("eager_convergence", &self.eager_convergence())
            .field(
                "last_direct_rx_micros",
                &self.last_direct_rx_micros.load(Ordering::Relaxed),
            )
            .field(
                "last_direct_data_tx_micros",
                &self.last_direct_data_tx_micros.load(Ordering::Relaxed),
            )
            .field(
                "last_direct_data_rx_micros",
                &self.last_direct_data_rx_micros.load(Ordering::Relaxed),
            )
            .field(
                "last_probe_micros",
                &self.last_probe_micros.load(Ordering::Relaxed),
            )
            .field(
                "failed_handshake_count",
                &self.failed_handshake_count.load(Ordering::Relaxed),
            )
            .field(
                "direct_suppressed_until",
                &self.direct_suppressed_until.load(Ordering::Relaxed),
            )
            .field(
                "last_rearm_micros",
                &self.last_rearm_micros.load(Ordering::Relaxed),
            )
            .field("rearm_streak", &self.rearm_streak.load(Ordering::Relaxed))
            .field("tunn", &"<Tunn>")
            .finish()
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use boringtun::noise::Tunn;
    use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU32};
    use x25519_dalek::{PublicKey, StaticSecret};

    /// Build a bare `PeerSession` (no endpoint, empty allowed-set) for
    /// exercising the direct-path confirmation state machine in isolation.
    fn bare_session() -> PeerSession {
        PeerSession {
            peer_id: uuid::Uuid::nil(),
            ula: "fd5a:1f00:1::1".parse().unwrap(),
            peer_pubkey: [0u8; 32],
            allowed_ips: parking_lot::RwLock::new(HashSet::new()),
            endpoint: parking_lot::RwLock::new(None),
            endpoint_learned: AtomicBool::new(false),
            direct_confirmed: AtomicBool::new(false),
            last_direct_rx_micros: AtomicI64::new(0),
            last_direct_data_tx_micros: AtomicI64::new(0),
            last_direct_data_rx_micros: AtomicI64::new(0),
            last_probe_micros: AtomicI64::new(0),
            failed_handshake_count: AtomicU32::new(0),
            direct_suppressed_until: AtomicI64::new(0),
            last_rearm_micros: AtomicI64::new(0),
            rearm_streak: AtomicU32::new(0),
            eager_convergence: AtomicBool::new(false),
            tunn: Mutex::new(Tunn::new(
                StaticSecret::from([1u8; 32]),
                PublicKey::from(&StaticSecret::from([2u8; 32])),
                None,
                None,
                7,
                None,
            )),
        }
    }

    /// A fresh session starts UNCONFIRMED — the relay is the floor until a
    /// direct data packet proves the path works both ways.
    #[test]
    fn direct_confirmed_defaults_false() {
        let s = bare_session();
        assert!(!s.direct_confirmed());
    }

    /// `confirm_direct` is the upgrade signal: it flips the bool true.
    #[test]
    fn confirm_direct_sets_confirmed() {
        let s = bare_session();
        s.confirm_direct(1_000);
        assert!(s.direct_confirmed());
    }

    /// `note_direct_rx` alone (a keepalive / handshake over UDP) refreshes
    /// staleness but must NOT confirm — only real data confirms.
    #[test]
    fn note_direct_rx_does_not_confirm() {
        let s = bare_session();
        s.note_direct_rx(1_000);
        assert!(!s.direct_confirmed());
    }

    /// `should_probe_direct` is the per-session rate-limit for the
    /// unconfirmed direct probe: the first call (clock = 0) probes, a second
    /// call within the interval is suppressed, and a call past the interval
    /// probes again — so a black-hole candidate is dialed at most once per
    /// interval instead of on every packet.
    #[test]
    fn should_probe_direct_rate_limits() {
        let s = bare_session();
        let interval = 1_000_000; // 1s
        assert!(
            s.should_probe_direct(5_000_000, interval),
            "first probe fires (clock starts at 0)"
        );
        assert!(
            !s.should_probe_direct(5_000_001, interval),
            "a second probe 1µs later is suppressed"
        );
        assert!(
            !s.should_probe_direct(5_999_999, interval),
            "still suppressed just under the interval"
        );
        assert!(
            s.should_probe_direct(6_000_000, interval),
            "probes again once a full interval has elapsed"
        );
    }

    /// `downgrade_direct_if_stale` resets a confirmed path AFTER the TTL
    /// elapses (NAT rebind / path death), but NOT before — a live path
    /// whose RX timestamp is fresh stays confirmed.
    #[test]
    fn downgrade_only_after_ttl() {
        let s = bare_session();
        s.confirm_direct(1_000); // last_direct_rx = 1_000
        // Not stale yet: within the TTL window.
        s.downgrade_direct_if_stale(1_000 + DIRECT_PATH_TTL_MICROS, DIRECT_PATH_TTL_MICROS);
        assert!(s.direct_confirmed(), "must stay confirmed within the TTL");
        // Stale: past the TTL window → fall back to relay.
        s.downgrade_direct_if_stale(1_000 + DIRECT_PATH_TTL_MICROS + 1, DIRECT_PATH_TTL_MICROS);
        assert!(
            !s.direct_confirmed(),
            "must downgrade once the TTL is exceeded"
        );
    }

    /// `path_status` reports the live `(direct_confirmed, age_micros)` pair
    /// the heartbeat surfaces to the coordinator: after a confirm at `t0`,
    /// `path_status(t0 + 5)` is `(true, 5)`; an unconfirmed session reports
    /// `direct = false`.
    #[test]
    fn path_status_reports_confirmed_and_age() {
        let s = bare_session();
        // Unconfirmed: direct is false (age is whatever — `0` baseline here).
        let (direct, _age) = s.path_status(1_000);
        assert!(!direct, "fresh session must report not-direct");
        // Confirm at t0, then read at t0 + 5 micros.
        s.confirm_direct(1_000);
        let (direct, age) = s.path_status(1_005);
        assert!(direct, "confirmed session must report direct");
        assert_eq!(age, 5, "age = now - last_direct_rx_micros");
    }

    /// A-c hysteresis: a fresh session is NOT suppressed and has a zero
    /// failure count. After `note_handshake_failure` the count climbs and a
    /// back-off window opens; `note_direct_rx` (any valid inbound) RESETS the
    /// failure count + clears suppression (the candidate proved itself alive).
    #[test]
    fn handshake_backoff_climbs_and_resets_on_rx() {
        let s = bare_session();
        assert!(!s.direct_suppressed(1_000), "fresh session is not suppressed");
        assert_eq!(s.failed_handshake_count(), 0);

        // First failure at t=1_000 opens a back-off window of BASE micros.
        s.note_handshake_failure(1_000);
        assert_eq!(s.failed_handshake_count(), 1);
        assert!(
            s.direct_suppressed(1_000),
            "immediately after a failure the candidate is suppressed"
        );
        assert!(
            !s.direct_suppressed(1_000 + DIRECT_BACKOFF_BASE_MICROS),
            "suppression lifts once the back-off window elapses"
        );

        // A valid inbound datagram resets the counter and clears suppression —
        // the candidate is alive again, so we stop penalising it.
        s.note_direct_rx(2_000);
        assert_eq!(s.failed_handshake_count(), 0, "rx resets the failure count");
        assert!(!s.direct_suppressed(2_000), "rx clears the suppression window");
    }

    /// The back-off is EXPONENTIAL and CAPPED: each consecutive failure roughly
    /// doubles the window (base, 2·base, 4·base, …) until it saturates at
    /// `DIRECT_BACKOFF_CAP_MICROS`, so a permanent black-hole candidate is
    /// probed at most once per cap interval — never the old 1/s forever.
    #[test]
    fn handshake_backoff_is_exponential_and_capped() {
        let s = bare_session();
        // Drive many failures; the window must never exceed the cap.
        let mut last_window = 0i64;
        for n in 1..=20 {
            let t = i64::from(n) * 1_000_000;
            s.note_handshake_failure(t);
            // The window currently in force = direct_suppressed_until - t.
            let window = s.direct_suppressed_until_micros() - t;
            assert!(
                window <= DIRECT_BACKOFF_CAP_MICROS,
                "back-off window {window} must never exceed the cap {DIRECT_BACKOFF_CAP_MICROS}"
            );
            // Monotonic non-decreasing until the cap.
            if last_window < DIRECT_BACKOFF_CAP_MICROS {
                assert!(window >= last_window, "back-off must not shrink before the cap");
            }
            last_window = window;
        }
        assert_eq!(
            last_window, DIRECT_BACKOFF_CAP_MICROS,
            "after enough failures the window saturates exactly at the cap"
        );
    }

    /// A-c anti-oscillation: when a confirmed path is downgraded for staleness,
    /// it must enter the back-off so the next send does NOT immediately
    /// re-probe and re-flap. A downgrade therefore opens a suppression window.
    #[test]
    fn stale_downgrade_opens_backoff_to_stop_oscillation() {
        let s = bare_session();
        s.confirm_direct(0);
        // Path goes silent past the TTL → downgrade.
        s.downgrade_direct_if_stale(DIRECT_PATH_TTL_MICROS + 1, DIRECT_PATH_TTL_MICROS);
        assert!(!s.direct_confirmed(), "stale path downgrades to relay");
        assert!(
            s.direct_suppressed(DIRECT_PATH_TTL_MICROS + 1),
            "a downgrade must open a back-off window (anti-oscillation)"
        );
        assert!(
            s.failed_handshake_count() >= 1,
            "a downgrade counts as a handshake failure for the back-off curve"
        );
    }

    /// A downgrade that does NOTHING (path not stale / not confirmed) must NOT
    /// open a back-off — only an actual confirmed→relay transition penalises.
    #[test]
    fn noop_downgrade_does_not_open_backoff() {
        let s = bare_session();
        // Not confirmed → downgrade is a no-op → no penalty.
        s.downgrade_direct_if_stale(1_000_000, DIRECT_PATH_TTL_MICROS);
        assert!(!s.direct_suppressed(1_000_000));
        assert_eq!(s.failed_handshake_count(), 0);

        // Confirmed + fresh → within TTL → no-op → no penalty.
        s.confirm_direct(1_000_000);
        s.downgrade_direct_if_stale(1_000_000 + 1, DIRECT_PATH_TTL_MICROS);
        assert!(s.direct_confirmed());
        assert_eq!(s.failed_handshake_count(), 0, "a no-op downgrade must not penalise");
    }

    /// FIX 3 re-arm gate: `should_rearm_expired` fires the FIRST time (clock = 0
    /// ⇒ a just-wedged session re-arms immediately), is suppressed for a full
    /// BASE window afterwards (so the 200 ms timer tick can NOT tight-loop the
    /// re-arm), and fires again once that WG attempt-window cadence elapses — so
    /// a genuinely-unreachable expired peer retries at WG speed, not every tick.
    #[test]
    fn should_rearm_expired_rate_limits() {
        let s = bare_session();
        let base_w = EXPIRED_REARM_BACKOFF_MICROS;
        let cap_w = EXPIRED_REARM_BACKOFF_CAP_MICROS;
        // Use a realistic wall-clock baseline (≫ backoff) so the first call —
        // with `last_rearm_micros == 0` — always satisfies `now - 0 >= backoff`,
        // matching the live `now_micros()` magnitude the timer loop feeds in.
        let base = 1_700_000_000_000_000;
        assert!(
            s.should_rearm_expired(base, base_w, cap_w),
            "first re-arm fires immediately (clock starts at 0)"
        );
        assert_eq!(s.rearm_streak(), 1, "first re-arm bumps the streak");
        assert!(
            !s.should_rearm_expired(base + 1, base_w, cap_w),
            "a re-arm 1µs later is suppressed (no tight-loop)"
        );
        // The streak is now 1 ⇒ the next window is 2·BASE. A re-arm exactly one
        // BASE later is therefore STILL suppressed — proving the loop-guard
        // back-off escalated, not a fixed-cadence retry.
        assert!(
            !s.should_rearm_expired(base + base_w, base_w, cap_w),
            "one BASE later is still suppressed — the re-arm window doubled (loop-guard)"
        );
        assert!(
            s.should_rearm_expired(base + 2 * base_w, base_w, cap_w),
            "re-arms again once the DOUBLED window has elapsed"
        );
        assert_eq!(s.rearm_streak(), 2, "second re-arm bumps the streak again");
    }

    /// THE loop-guard contract (task #14): the expired-`Tunn` re-arm window
    /// climbs `min(BASE << streak, CAP)` and never exceeds CAP — so a chronically
    /// black-holed peer (MSI WAN) re-handshakes ever LESS often, not at a fixed
    /// 90 s rate forever. A valid inbound rx (`note_direct_rx`) collapses the
    /// streak so a recovered/transient wedge drops straight back to BASE cadence.
    #[test]
    fn rearm_backoff_escalates_caps_and_resets_on_rx() {
        let base_w = EXPIRED_REARM_BACKOFF_MICROS;
        let cap_w = EXPIRED_REARM_BACKOFF_CAP_MICROS;
        // Pure interval: doubles per step, clamps at CAP, monotonic, no overflow.
        assert_eq!(rearm_interval(0, base_w, cap_w), base_w, "streak 0 ⇒ BASE");
        assert_eq!(rearm_interval(1, base_w, cap_w), 2 * base_w, "streak 1 ⇒ 2·BASE");
        let mut prev = 0;
        for streak in 0..64u32 {
            let w = rearm_interval(streak, base_w, cap_w);
            assert!(w >= base_w, "never below BASE");
            assert!(w <= cap_w, "re-arm window {w} must never exceed CAP {cap_w}");
            assert!(w >= prev, "monotonic non-decreasing");
            prev = w;
        }
        assert_eq!(
            rearm_interval(u32::MAX, base_w, cap_w),
            cap_w,
            "a pathological streak saturates at CAP, never overflows"
        );
        // Live: drive the streak up, then a real rx collapses it to BASE cadence.
        let s = bare_session();
        let mut now = 1_700_000_000_000_000;
        assert!(s.should_rearm_expired(now, base_w, cap_w)); // streak 0→1
        now += 2 * base_w;
        assert!(s.should_rearm_expired(now, base_w, cap_w)); // streak 1→2
        now += 4 * base_w;
        assert!(s.should_rearm_expired(now, base_w, cap_w)); // streak 2→3
        assert_eq!(s.rearm_streak(), 3, "three un-answered re-arms");
        // RX returns: the streak collapses.
        s.note_direct_rx(now);
        assert_eq!(s.rearm_streak(), 0, "a valid inbound rx resets the re-arm back-off");
        // The next re-arm is due at BASE cadence again (one BASE after the last).
        assert!(
            s.should_rearm_expired(now + base_w, base_w, cap_w),
            "after a reset the next re-arm is due at BASE cadence"
        );
    }

    /// The asymmetric-wedge backstop (`downgrade_direct_if_tx_blackholed`):
    /// a CONFIRMED path that keeps TRANSMITTING while receiving ZERO direct
    /// inbound DATA within the window must downgrade — even though the
    /// RX-staleness clock stays fresh (the peer's keepalives keep arriving,
    /// so `downgrade_direct_if_stale` never fires). This is the MSI
    /// signature: their outbound path to us is alive, ours to them is dead.
    #[test]
    fn tx_blackhole_downgrade_fires_when_sending_without_direct_data_rx() {
        let s = bare_session();
        let ttl = DIRECT_TX_BLACKHOLE_TTL_MICROS;
        // Confirm at t0 — stamps both the staleness AND the direct-DATA-RX clocks.
        s.confirm_direct(1_000_000);
        // The peer's keepalives keep the STALENESS clock fresh (the wedge!):
        let now = 1_000_000 + ttl + 5_000_000;
        s.note_direct_rx(now);
        // We are actively sending on the confirmed path…
        s.note_direct_tx(now);
        // …but no direct inbound DATA arrived within the window.
        assert!(
            s.downgrade_direct_if_tx_blackholed(now, ttl),
            "active TX + silent direct-DATA RX past the TTL must downgrade"
        );
        assert!(!s.direct_confirmed(), "the path fell back to the relay floor");
        assert!(
            s.direct_suppressed(now),
            "a TX-black-hole downgrade opens a back-off (anti-oscillation)"
        );
        assert!(
            !s.endpoint_learned(),
            "the downgrade surrenders endpoint provenance so the roster may repoint"
        );
    }

    /// The TX-black-hole downgrade must be IDLE-SAFE: with no recent
    /// non-keepalive TX there is no RX expectation, so a quiet confirmed pair
    /// (arbitrarily old data clocks) never flaps to the relay.
    #[test]
    fn tx_blackhole_downgrade_is_idle_safe() {
        let s = bare_session();
        let ttl = DIRECT_TX_BLACKHOLE_TTL_MICROS;
        s.confirm_direct(1_000_000);
        // Never sent at all → no downgrade, no matter how old the RX clock.
        assert!(!s.downgrade_direct_if_tx_blackholed(1_000_000 + 100 * ttl, ttl));
        assert!(s.direct_confirmed());
        // A flow that FINISHED long ago (last TX outside the window) is idle
        // too — the unanswered final frame of a completed exchange must not
        // downgrade a healthy path hours later.
        s.note_direct_tx(2_000_000);
        assert!(!s.downgrade_direct_if_tx_blackholed(2_000_000 + ttl + 1, ttl));
        assert!(s.direct_confirmed(), "stale TX (idle) never downgrades");
    }

    /// Fresh direct inbound DATA within the window proves the path — an
    /// active healthy flow (request out, response data back) never trips the
    /// TX-black-hole downgrade.
    #[test]
    fn tx_blackhole_downgrade_spares_active_healthy_flow() {
        let s = bare_session();
        let ttl = DIRECT_TX_BLACKHOLE_TTL_MICROS;
        let now = 10_000_000;
        s.note_direct_tx(now - 1_000); // sending…
        s.confirm_direct(now - 500); // …and direct DATA came back (stamps RX)
        assert!(
            !s.downgrade_direct_if_tx_blackholed(now, ttl),
            "fresh direct DATA RX within the window keeps the path confirmed"
        );
        assert!(s.direct_confirmed());
    }

    /// A keepalive refresh (`note_direct_rx`) keeps a confirmed-but-idle
    /// path alive: with periodic refreshes inside the TTL it never
    /// false-downgrades.
    #[test]
    fn keepalive_refresh_prevents_false_downgrade() {
        let s = bare_session();
        s.confirm_direct(0);
        // A WG keepalive lands well within the TTL, refreshing the clock.
        s.note_direct_rx(DIRECT_PATH_TTL_MICROS - 1);
        // "Now" is past the original confirm + TTL, but the refresh moved
        // the window forward, so the path is still live.
        s.downgrade_direct_if_stale(DIRECT_PATH_TTL_MICROS + 10, DIRECT_PATH_TTL_MICROS);
        assert!(
            s.direct_confirmed(),
            "keepalive refresh prevents a false downgrade"
        );
    }
}
