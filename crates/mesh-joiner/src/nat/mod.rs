//! NAT traversal — Stage 2 UDP hole-punch subscriber.
//!
//! Holds the joiner-side hole-punch subscriber ([`holepunch`]), which IS wired
//! and functional: the SSE consumer (`coordinator::peer_sync`) forwards
//! `HolePunchInitiate` events to it and it fires synchronized UDP bursts at the
//! target's reflexive endpoint. Advanced symmetric-NAT handling (type
//! detection, retry strategy) is the only deferred part.

pub mod holepunch;
pub mod stun;
