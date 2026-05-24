//! X25519 keypair generation for `WireGuard`.
//!
//! Mirrors [`tabbify_mesh_fabric::generate_keypair`] but kept local so
//! the joiner can evolve key persistence independently (e.g. load from
//! disk in a follow-up stage) without churning the fabric crate.
//!
//! # Storage policy
//!
//! The private key lives in process memory for the lifetime of the
//! [`crate::Joiner`] only. There is **no disk persistence in MVP** —
//! each restart generates a fresh keypair, which means the coordinator
//! treats the restarted process as a brand-new peer (new `peer_id`,
//! fresh ULA). Persistence is tracked separately.

use rand_core::{OsRng, RngCore};
use x25519_dalek::{PublicKey, StaticSecret};

/// X25519 keypair used to bring up `WireGuard` tunnels.
#[derive(Clone)]
pub struct WgKeypair {
    /// Cryptographically sensitive — never log, never publish.
    pub private: StaticSecret,
    /// Safe to publish. Sent to the coordinator on registration.
    pub public: PublicKey,
}

impl std::fmt::Debug for WgKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use std::fmt::Write as _;
        let mut pub_hex = String::with_capacity(64);
        for b in self.public.as_bytes() {
            // Hex-format with leading zero — `Display` for the
            // 32-byte public key is a stable identifier we use in
            // tracing.
            let _ = write!(pub_hex, "{b:02x}");
        }
        f.debug_struct("WgKeypair")
            .field("private", &"<redacted>")
            .field("public", &pub_hex)
            .finish()
    }
}

/// Generate a fresh X25519 keypair via the OS RNG.
///
/// Two consecutive calls always return distinct keys — this is the
/// contract the joiner relies on when the process restarts and wants a
/// new peer identity.
#[must_use]
pub fn generate() -> WgKeypair {
    let mut secret_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut secret_bytes);
    let private = StaticSecret::from(secret_bytes);
    let public = PublicKey::from(&private);
    WgKeypair { private, public }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    /// Sanity: public keys are 32 bytes (X25519 invariant) and the
    /// secret never produces an all-zero public key (would mean the OS
    /// RNG is broken).
    #[test]
    fn generates_32_byte_non_zero_public_key() {
        let kp = generate();
        assert_eq!(kp.public.as_bytes().len(), 32);
        assert!(
            kp.public.as_bytes().iter().any(|&b| b != 0),
            "public key was all zero — OS RNG returned bad entropy?"
        );
    }

    /// Two successive calls must yield distinct keypairs. If this ever
    /// fires, either the RNG is deterministic (catastrophic) or
    /// `StaticSecret` is caching something it shouldn't.
    #[test]
    fn successive_calls_are_distinct() {
        let a = generate();
        let b = generate();
        assert_ne!(a.public.as_bytes(), b.public.as_bytes());
    }

    /// The `Debug` impl must not leak the private key — we redact it
    /// to a fixed string. Checking the textual format directly is the
    /// only way to guarantee future refactors don't accidentally enable
    /// the derived `Debug`.
    #[test]
    fn debug_redacts_private_key() {
        let kp = generate();
        let s = format!("{kp:?}");
        assert!(s.contains("<redacted>"));
        // The public hex should still be present for diagnostics.
        let first_byte_hex = format!("{:02x}", kp.public.as_bytes()[0]);
        assert!(s.contains(&first_byte_hex), "missing public hex: {s}");
    }
}
