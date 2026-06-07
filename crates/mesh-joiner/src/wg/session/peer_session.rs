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
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
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

    /// Downgrade a confirmed path back to the relay floor if it has gone
    /// silent for longer than `ttl_micros` (NAT rebind / path death). A
    /// no-op when the path is already unconfirmed or still fresh. Called
    /// from the timer loop on every tick.
    pub fn downgrade_direct_if_stale(&self, now_micros: i64, ttl_micros: i64) {
        if self.direct_confirmed.load(Ordering::Relaxed)
            && now_micros - self.last_direct_rx_micros.load(Ordering::Relaxed) > ttl_micros
        {
            self.direct_confirmed.store(false, Ordering::Relaxed);
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
            .field("tunn", &"<Tunn>")
            .finish()
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use boringtun::noise::Tunn;
    use std::sync::atomic::{AtomicBool, AtomicI64};
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
