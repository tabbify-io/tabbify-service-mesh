//! DERP-style relay: the coordinator forwards opaque (already-encrypted)
//! `WireGuard` frames between mesh peers by destination pubkey, the
//! connectivity floor when direct + hole-punch fail.
//!
//! [`frame`] is the wire codec (identical bytes in the joiner crate);
//! [`registry`] is the ephemeral pubkey → live-WS connection table the HTTP
//! relay handler registers and forwards through.

pub mod frame;
pub mod registry;

pub use frame::{decode_relay_frame, encode_relay_frame};
pub use registry::RelayRegistry;
