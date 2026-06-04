//! DERP-style relay client (Stage 3 connectivity floor).
//!
//! When two mesh peers can't reach each other directly (NAT timing,
//! symmetric NAT, firewalled port) the joiner forwards its
//! already-WG-encrypted datagrams through the coordinator's relay
//! endpoint, keyed by destination pubkey. Direct + hole-punch keep
//! running in parallel; when a punch succeeds traffic upgrades back to
//! the direct path. The relay never sees plaintext — frames carry
//! opaque WG transport packets.
//!
//! Layout:
//!
//! - [`mod@frame`] — the wire codec (byte-identical to the coordinator's
//!   independent copy).
//! - [`mod@client`] — the [`RelayHandle`] used by the WG TX seams plus
//!   the persistent WebSocket task.

pub(crate) mod client;
pub mod frame;

pub use client::RelayHandle;
pub use frame::{decode_relay_frame, encode_relay_frame};
