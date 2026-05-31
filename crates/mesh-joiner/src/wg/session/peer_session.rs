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
use tokio::sync::Mutex;

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
            .field("tunn", &"<Tunn>")
            .finish()
    }
}
