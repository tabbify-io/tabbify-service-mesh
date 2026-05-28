// Intentional pattern: we acquire the tunnel mutex, copy out the
// outbound bytes, and drop the mutex *before* awaiting socket I/O.
// Clippy's `significant_drop_tightening` lint flags this as "drop
// earlier" — but the whole point is that the lock is already held
// in the smallest possible scope (block-scoped binding).
#![allow(clippy::significant_drop_tightening)]

//! Userspace-`WireGuard` [`MeshFabric`] implementation backed by
//! Cloudflare's [`boringtun`] state machine.
//!
//! # Architecture
//!
//! Each `WireGuardFabric` owns one UDP socket bound to a configurable
//! address (typically `0.0.0.0:51820`). Outbound frames are wrapped in a
//! synthetic IPv6 header so boringtun's data-plane invariants hold
//! (`Tunn::encapsulate` expects valid IP datagrams; the response from
//! `decapsulate` is validated as IP), then encrypted via the per-peer
//! [`boringtun::noise::Tunn`] session and sent over UDP. The receiving
//! end reverses the process: decapsulate, strip the IPv6 header,
//! dispatch by destination ULA.
//!
//! The IPv6-wrapper is invisible to callers — the public surface matches
//! [`crate::loopback::LoopbackFabric`] exactly, so a substrate
//! supervisor that already drives the loopback fabric can switch to
//! `WireGuard` by swapping the constructor.
//!
//! # Two operating modes
//!
//! * **Pure UDP** — no kernel TUN device involved. Two
//!   `WireGuardFabric` instances exchange handshake packets and
//!   encrypted data frames over loopback UDP. Used by the unit tests
//!   in `tests/wireguard_udp.rs`.
//! * **TUN-integrated** — decapsulated packets are written to a
//!   kernel TUN device (`utun*` on macOS, `/dev/net/tun` on Linux)
//!   and packets read from the device are encapsulated and sent over
//!   UDP. Requires root / `CAP_NET_ADMIN`. The OS-specific kernel
//!   plumbing lives behind the cross-platform [`crate::tun`]
//!   abstraction — `WireGuardFabric` itself is OS-agnostic. Covered
//!   by the `#[ignore]` integration test `tests/wireguard_tun.rs`.
//!
//! Layout:
//!
//! - [`mod@keys`] — `WireGuardKeypair`, `generate_keypair`, peer spec.
//! - [`mod@ipv6`] — synthetic IPv6 framing (private).
//! - [`mod@transport`] — send path + per-peer handshake driver +
//!   `MeshFabric` / `MeshFabricMutators` impls.
//! - [`mod@loops`] — background UDP receive + timer tasks (private).
//! - This file — types + [`WireGuardFabric::bind`] + accessors.

mod ipv6;
mod keys;
mod loops;
mod transport;

#[cfg(test)]
mod tests;

pub use keys::{WireGuardKeypair, WireGuardPeerSpec, generate_keypair};

use crate::trait_def::{AppMessage, FabricError};
use boringtun::noise::Tunn;
use dashmap::DashMap;
use std::net::{Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, mpsc};
use x25519_dalek::{PublicKey, StaticSecret};

/// Maximum app payload we'll wrap. The IPv6 length field is 16 bits,
/// so the absolute hard limit is `u16::MAX`. We also reserve enough
/// headroom for boringtun's 32-byte data overhead.
pub const MAX_APP_PAYLOAD: usize = (u16::MAX as usize) - 64;

/// Userspace-WireGuard [`crate::MeshFabric`]. Cheap to clone — handles share
/// state via an internal `Arc`.
#[derive(Clone)]
pub struct WireGuardFabric {
    pub(super) inner: Arc<Inner>,
}

pub(super) struct Inner {
    pub(super) local_node_id: String,
    pub(super) local_addr: SocketAddr,
    /// Local private key — kept here for re-establishing sessions on
    /// peer changes.
    pub(super) static_private: StaticSecret,
    /// Outbound UDP socket. The receive loop reads from a clone owned
    /// by the spawned task.
    pub(super) socket: Arc<UdpSocket>,
    /// Local endpoint table: ULA -> mpsc sender that delivers inbound
    /// messages to the application.
    pub(super) endpoints: DashMap<Ipv6Addr, EndpointEntry>,
    /// Routes to remote ULAs: ULA -> `node_id`.
    pub(super) remote_routes: DashMap<Ipv6Addr, String>,
    /// Per-peer encryption state. Wrapped in a tokio Mutex so the
    /// async send + receive halves can serialise access without
    /// holding a guard across UDP I/O.
    pub(super) peers: DashMap<String, Arc<PeerState>>,
}

pub(super) struct PeerState {
    pub(super) endpoint: SocketAddr,
    /// Retained for debugging / future rekey flows even though the
    /// data-plane reads it only via the encapsulated `Tunn`.
    #[allow(dead_code)]
    pub(super) public_key: PublicKey,
    pub(super) tunn: Mutex<Tunn>,
}

pub(super) struct EndpointEntry {
    #[allow(dead_code)]
    pub(super) id: String,
    pub(super) tx: mpsc::UnboundedSender<(Ipv6Addr, AppMessage)>,
}

impl WireGuardFabric {
    /// Bind a fabric instance to `local_addr` (typically
    /// `0.0.0.0:51820` or `127.0.0.1:0` for tests). Spawns a background
    /// tokio task that reads inbound UDP datagrams and dispatches them
    /// to local endpoints.
    ///
    /// `local_node_id` is the stable identifier this fabric uses when
    /// announcing itself to peers.
    pub async fn bind(
        local_addr: SocketAddr,
        local_node_id: String,
        static_private: StaticSecret,
    ) -> Result<Self, FabricError> {
        let socket = UdpSocket::bind(local_addr)
            .await
            .map_err(|e| FabricError::Transport(format!("udp bind {local_addr}: {e}")))?;
        let bound_addr = socket
            .local_addr()
            .map_err(|e| FabricError::Transport(format!("udp local_addr: {e}")))?;
        let socket = Arc::new(socket);

        let inner = Arc::new(Inner {
            local_node_id: local_node_id.clone(),
            local_addr: bound_addr,
            static_private,
            socket: Arc::clone(&socket),
            endpoints: DashMap::new(),
            remote_routes: DashMap::new(),
            peers: DashMap::new(),
        });

        tokio::spawn(loops::receive_loop(socket, Arc::clone(&inner)));
        tokio::spawn(loops::timer_loop(Arc::clone(&inner)));

        tracing::info!(
            node_id = %local_node_id,
            addr = %bound_addr,
            "WireGuardFabric bound"
        );

        Ok(Self { inner })
    }

    /// The actual bound UDP socket address (useful when `bind` was
    /// called with port `0`).
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.inner.local_addr
    }

    /// The stable identifier this fabric uses when announcing itself.
    #[must_use]
    pub fn local_node_id(&self) -> &str {
        &self.inner.local_node_id
    }
}

// -----------------------------------------------------------------------------
// Re-exports for downstream crates that need to type peer specs / load
// private keys without depending on x25519-dalek directly.
// -----------------------------------------------------------------------------

/// Re-export of [`PublicKey`] for downstream crates that want to type
/// peer specs without depending on x25519-dalek directly.
pub use x25519_dalek::PublicKey as PeerPublicKey;
/// Re-export of [`StaticSecret`] for downstream crates that need to
/// load private keys from disk and pass them to [`WireGuardFabric::bind`].
pub use x25519_dalek::StaticSecret as PeerStaticSecret;
