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

/// Minimum spacing between automatic expired-`Tunn` RE-ARMS (FIX 3).
///
/// boringtun gives up on a handshake after `REKEY_ATTEMPT_TIME` (90 s of
/// retransmitting the init every `REKEY_TIMEOUT`=5 s with no response): it calls
/// `set_expired()` and from then on EVERY `update_timers` returns
/// `ConnectionExpired` forever — it never emits another init on its own. A fresh
/// relay-only ⇄ relay-only peer (the lifeline `fc22:6::1`) whose first 90 s
/// window lapses without a completed relayed handshake is then permanently
/// wedged. The timer loop detects the expired `Tunn` and re-arms it (a fresh
/// handshake-init over the relay floor); this gates the re-arm so a genuinely
/// unreachable peer retries at WG cadence (~one fresh 90 s attempt-window after
/// the last), NOT in a tight 200 ms-tick loop. Matches `REKEY_ATTEMPT_TIME`.
pub const EXPIRED_REARM_BACKOFF_MICROS: i64 = 90_000_000;

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
    /// `EXPIRED_REARM_BACKOFF_MICROS` (WG attempt-window cadence) so a
    /// genuinely-unreachable peer retries at WG speed instead of every 200 ms
    /// tick. `0` = never re-armed → the first detected expiry re-arms at once.
    pub last_rearm_micros: AtomicI64,
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
        // accumulated handshake-failure penalty so it is probed freely again.
        self.clear_handshake_backoff();
    }

    /// THE upgrade signal: a decrypted DATA packet arrived over UDP,
    /// proving the direct path works bidirectionally. Mark the path
    /// confirmed AND refresh the staleness clock. Called ONLY from the
    /// `DeliverToTun` path on a direct (non-relayed) datagram.
    pub fn confirm_direct(&self, now_micros: i64) {
        self.direct_confirmed.store(true, Ordering::Relaxed);
        self.last_direct_rx_micros
            .store(now_micros, Ordering::Relaxed);
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

    /// Rate-limit gate for the automatic expired-`Tunn` RE-ARM (FIX 3):
    /// returns `true` at most once per `backoff_micros`, stamping the clock when
    /// it does. The timer loop calls this only after it has already observed
    /// `Tunn::is_expired()`, so a `true` means "this expired session is due for
    /// a fresh handshake-init now". The first call (clock = `0`) re-arms
    /// immediately so a just-wedged session bootstraps without waiting a full
    /// back-off; subsequent re-arms are spaced at WG attempt-window cadence so a
    /// genuinely-unreachable peer is not re-armed every 200 ms tick. A relaxed
    /// load/store is fine — a racing double-read at worst fires one extra init,
    /// which boringtun's own retransmit logic would emit anyway.
    pub fn should_rearm_expired(&self, now_micros: i64, backoff_micros: i64) -> bool {
        let last = self.last_rearm_micros.load(Ordering::Relaxed);
        if now_micros.saturating_sub(last) >= backoff_micros {
            self.last_rearm_micros.store(now_micros, Ordering::Relaxed);
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
            .field("direct_confirmed", &self.direct_confirmed())
            .field(
                "last_direct_rx_micros",
                &self.last_direct_rx_micros.load(Ordering::Relaxed),
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
            direct_confirmed: AtomicBool::new(false),
            last_direct_rx_micros: AtomicI64::new(0),
            last_probe_micros: AtomicI64::new(0),
            failed_handshake_count: AtomicU32::new(0),
            direct_suppressed_until: AtomicI64::new(0),
            last_rearm_micros: AtomicI64::new(0),
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
    /// `EXPIRED_REARM_BACKOFF_MICROS` window afterwards (so the 200 ms timer
    /// tick can NOT tight-loop the re-arm), and fires again once that WG
    /// attempt-window cadence elapses — so a genuinely-unreachable expired peer
    /// retries at WG speed, not every tick.
    #[test]
    fn should_rearm_expired_rate_limits() {
        let s = bare_session();
        let backoff = EXPIRED_REARM_BACKOFF_MICROS;
        // Use a realistic wall-clock baseline (≫ backoff) so the first call —
        // with `last_rearm_micros == 0` — always satisfies `now - 0 >= backoff`,
        // matching the live `now_micros()` magnitude the timer loop feeds in.
        let base = 1_700_000_000_000_000;
        assert!(
            s.should_rearm_expired(base, backoff),
            "first re-arm fires immediately (clock starts at 0)"
        );
        assert!(
            !s.should_rearm_expired(base + 1, backoff),
            "a re-arm 1µs later is suppressed (no tight-loop)"
        );
        assert!(
            !s.should_rearm_expired(base + backoff - 1, backoff),
            "still suppressed just under the back-off window"
        );
        assert!(
            s.should_rearm_expired(base + backoff, backoff),
            "re-arms again once a full WG attempt-window has elapsed"
        );
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
