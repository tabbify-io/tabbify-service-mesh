//! NAT traversal — Stage 2 reflexive-endpoint discovery + hole-punch
//! coordination.
//!
//! Holds:
//! * [`reflexive`] — pure decision logic that turns a peer's
//!   coordinator-observed source address + its self-reported endpoint
//!   into the endpoint other peers should dial. This is the active
//!   Stage-2 cone-NAT endpoint-discovery path.
//! * [`holepunch`] — the FUNCTIONAL coordinator-side hole-punch initiation (basic cone-NAT).
//!   The real hole-punching state machine (for symmetric NAT) is deferred
//!   to a cloud rollout with real NAT topology; this pins the protocol
//!   shape now.

pub mod direct_flags;
pub mod holepunch;
pub mod reflexive;
