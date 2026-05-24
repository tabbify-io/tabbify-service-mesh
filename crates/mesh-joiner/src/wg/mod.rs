//! `WireGuard` data plane.
//!
//! The userspace boringtun machinery that carries overlay traffic:
//!
//! * [`session`] — per-peer `boringtun::noise::Tunn` registry
//!   ([`session::SessionTable`]) keyed by ULA + source endpoint.
//! * [`loops`] — UDP / TUN / timer background loops that pump bytes
//!   between the kernel TUN device and the WG tunnels.
//! * [`keypair`] — X25519 keypair generation.
//! * [`persistent_keypair`] — load-or-generate keypair persistence so the
//!   joiner keeps a stable identity across restarts.

pub mod keypair;
pub mod loops;
pub mod persistent_keypair;
pub mod session;
