//! NAT traversal — Stage 2 UDP hole-punch coordination.
//!
//! Holds the coordinator-side hole-punch initiation skeleton
//! ([`holepunch`]). The real hole-punching state machine is deferred to a
//! cloud rollout with real NAT topology; this pins the protocol shape now.

pub mod holepunch;
