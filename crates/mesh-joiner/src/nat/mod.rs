//! NAT traversal — Stage 2 UDP hole-punch subscriber.
//!
//! Holds the joiner-side hole-punch subscriber stub ([`holepunch`]). The
//! real implementation (firing UDP packets at a peer's external endpoint)
//! is deferred until the SSE wire mechanism for `HolePunchInitiate` events
//! is decided; this pins the import path + protocol shape now.

pub mod holepunch;
