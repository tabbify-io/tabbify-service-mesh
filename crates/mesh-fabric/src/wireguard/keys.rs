//! `WireGuard` keypair generation + peer-spec DTO.

use rand_core::{OsRng, RngCore};
use std::net::SocketAddr;
use x25519_dalek::{PublicKey, StaticSecret};

/// X25519 keypair returned by [`generate_keypair`] and consumed by
/// [`super::WireGuardFabric::bind`].
#[derive(Clone)]
pub struct WireGuardKeypair {
    /// The X25519 secret. Treat as cryptographically sensitive — never
    /// log, never emit in events.
    pub private: StaticSecret,
    /// The X25519 public key. Safe to publish via the
    /// `node_pubkey_announced` substrate event.
    pub public: PublicKey,
}

impl std::fmt::Debug for WireGuardKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use std::fmt::Write as _;
        let mut pub_hex = String::with_capacity(64);
        for b in self.public.as_bytes() {
            write!(pub_hex, "{b:02x}").map_err(|_| std::fmt::Error)?;
        }
        f.debug_struct("WireGuardKeypair")
            .field("private", &"<redacted>")
            .field("public", &pub_hex)
            .finish()
    }
}

/// Generate a fresh X25519 keypair suitable for `WireGuard`. Pulls
/// entropy from the OS RNG.
#[must_use]
pub fn generate_keypair() -> WireGuardKeypair {
    let mut secret_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut secret_bytes);
    let private = StaticSecret::from(secret_bytes);
    let public = PublicKey::from(&private);
    WireGuardKeypair { private, public }
}

/// Specification of a remote `WireGuard` peer.
#[derive(Debug, Clone)]
pub struct WireGuardPeerSpec {
    /// Stable identifier of the peer (matches `local_node_id` on the
    /// remote `WireGuardFabric`).
    pub node_id: String,
    /// UDP endpoint where the peer is listening.
    pub endpoint: SocketAddr,
    /// The peer's X25519 public key — typically learned via a
    /// `node_pubkey_announced` substrate event.
    pub public_key: PublicKey,
}
