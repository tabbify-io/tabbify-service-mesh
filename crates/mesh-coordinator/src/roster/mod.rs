//! Roster domain — the coordinator's peer state machine + supporting types.
//!
//! Groups the in-memory roster + register/heartbeat/deregister state
//! machine ([`coordinator`]), the event `apply_*` seam ([`apply`]), the
//! sequential ULA allocator ([`allocator`]), the peer-lifecycle event
//! shapes ([`events`]), the durable roster snapshot store ([`store`]), and
//! the heartbeat-timeout sweeper ([`timeout`]).

pub mod allocator;
pub mod apply;
pub mod coordinator;
pub mod events;
pub mod filter;
pub mod identity;
pub mod store;
pub mod timeout;
