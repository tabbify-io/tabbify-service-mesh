#![cfg_attr(not(test), warn(missing_docs))]

//! Tabbify mesh fabric — pluggable transport for app-to-app messaging.
//!
//! See `substrate/docs/superpowers/specs/2026-05-16-wasm-http-apps-architecture-design.md`
//! §2.5 (ULA scheme) and §7 (`MeshFabric` trait).

pub mod in_process;
pub mod loopback;
pub mod trait_def;
pub mod ula;

#[cfg(feature = "wireguard")]
pub mod wireguard;

/// Cross-platform TUN device abstraction.
///
/// Used by [`wireguard::WireGuardFabric`] to plumb decrypted IPv6
/// frames in and out of the host kernel. See [`tun`] for the per-OS
/// contract; the macOS and Linux backends each live in their own
/// submodule gated by `#[cfg(target_os = ...)]`.
#[cfg(feature = "wireguard")]
pub mod tun;

pub use loopback::{LoopbackFabric, LoopbackPeerSpec};
pub use trait_def::{
    AppMessage, FabricError, InboundRx, MeshFabric, MeshFabricMutators, RoutingSnapshot,
};
pub use ula::{Ula, UlaPrefix};

#[cfg(feature = "wireguard")]
pub use wireguard::{
    generate_keypair, PeerPublicKey, PeerStaticSecret, WireGuardFabric, WireGuardKeypair,
    WireGuardPeerSpec,
};
