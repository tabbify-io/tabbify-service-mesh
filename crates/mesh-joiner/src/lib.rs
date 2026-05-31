#![cfg_attr(not(test), warn(missing_docs))]

//! `tabbify-mesh-joiner` — joiner-side library for the overlay mesh
//! network.
//!
//! A "joiner" is a process that wants to participate as a peer in the
//! overlay mesh: it registers with the coordinator, gets an IPv6 ULA,
//! opens a TUN device, and establishes `WireGuard` tunnels to all other
//! peers. The orchestration lives in [`joiner::Joiner`] — most callers
//! only need the public re-exports below.
//!
//! # Quick start
//!
//! ```ignore
//! use std::time::Duration;
//! use tabbify_mesh_joiner::{JoinConfig, Joiner};
//!
//! # async fn _doc() -> anyhow::Result<()> {
//! let joiner = Joiner::join(JoinConfig {
//!     coordinator_url: "http://127.0.0.1:8888".into(),
//!     display_name: "alice-laptop".into(),
//!     tags: vec!["dev-machine".into()],
//!     ..JoinConfig::default()
//! }).await?;
//!
//! println!("our ULA: {}", joiner.my_ula());
//! for peer in joiner.peers() {
//!     println!("peer {} = {}", peer.display_name, peer.ula);
//! }
//!
//! joiner.leave().await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Privileges
//!
//! The joiner shells out to `ifconfig`/`route` (macOS) or `ip` (Linux)
//! to configure the TUN device with our ULA + add the overlay route.
//! Both call paths require **root / `sudo`** (macOS) or `CAP_NET_ADMIN`
//! (Linux). Sudo-less operation is Stage 2 work.
//!
//! # Internal layout
//!
//! Crate-root modules carry the caller-facing surface; the rest is grouped
//! by domain:
//!
//! * [`config`] — caller-facing [`JoinConfig`] + defaults.
//! * [`error`] — typed errors.
//! * [`joiner`] — top-level orchestrator.
//! * [`peer`] — public [`PeerInfo`] type + wire shapes.
//! * [`coordinator`] — coordinator-facing control plane: HTTP client,
//!   heartbeat reconciliation, and the SSE peer-stream consumer.
//! * [`wg`] — `WireGuard` data plane: per-peer `Tunn` sessions, the
//!   UDP / TUN / timer byte-pump loops, and X25519 keypair plumbing.
//! * [`platform`] — per-OS shell-outs to wire the TUN device into the
//!   kernel routing table.
//! * [`nat`] — Stage 2 hole-punch subscriber stub.
//! * [`relay`] — Stage 3 DERP-style relay client: forwards
//!   already-encrypted WG datagrams through the coordinator when no
//!   direct path is known.

// Crate-root modules: caller-facing config / error / public types and the
// orchestrator that ties the domains together.
pub mod config;
pub mod coordinator;
pub mod error;
pub mod joiner;
pub mod nat;
pub mod peer;
pub mod relay;
pub mod platform;
pub mod wg;

// `anyhow::Result` is the documented return type of `Joiner::join` and
// `Joiner::leave`. Re-export so callers don't need a direct `anyhow`
// dependency.
pub use anyhow::Result;

pub use config::JoinConfig;
pub use error::{JoinerError, Result as JoinerResult};
pub use joiner::Joiner;
pub use peer::PeerInfo;

/// Re-export of the unified logging initialiser so a host application that
/// embeds the joiner (the supervisor / node) calls the SAME
/// `init_logging` the coordinator binary and the `tabbify-mesh` CLI use —
/// one JSON shape, one `RUST_LOG` default (`info`), one flat `service`
/// field across the whole fleet. See [`tabbify_mesh_log::init_logging`].
///
/// ```ignore
/// tabbify_mesh_joiner::init_logging("tabbify-supervisor");
/// ```
pub use tabbify_mesh_log::init_logging;
