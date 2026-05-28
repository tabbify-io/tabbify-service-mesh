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
//! Layout:
//!
//! - [`mod@route_sink`] — [`RouteSink`] trait: kernel-route mirror.
//! - [`mod@peer_session`] — [`PeerSession`] (one peer's `Tunn` + metadata).
//! - [`mod@table`] — [`SessionTable`] (registry + per-app-ULA routing).
//! - This file — [`WgAction`] + [`classify_tunn_result`] + the
//!   keepalive constant.
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

mod peer_session;
mod route_sink;
mod table;

#[cfg(test)]
mod tests;

pub use peer_session::PeerSession;
pub use route_sink::RouteSink;
pub use table::SessionTable;

use boringtun::noise::TunnResult;

/// `WireGuard` persistent-keepalive interval (seconds), applied to EVERY
/// peer session.
///
/// Crucial for `NAT` traversal: a keepalive every 25s keeps the `NAT`'s
/// UDP mapping for our `WireGuard` socket open even when no data flows, so
/// the reflexive endpoint other peers dial stays valid and `boringtun`'s
/// endpoint roaming has live traffic to latch onto. 25s is the canonical
/// `WireGuard` default and matches `mesh-fabric::wireguard`.
pub const WG_PERSISTENT_KEEPALIVE_SECS: u16 = 25;

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
