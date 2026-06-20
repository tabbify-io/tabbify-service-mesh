//! Coordinator-facing control plane.
//!
//! Everything the joiner uses to talk to the `mesh-coordinator` REST +
//! SSE surface and keep its local roster in sync:
//!
//! * [`client`] — typed HTTP wrapper around the four coordinator
//!   endpoints (register / heartbeat / deregister + the SSE base URL).
//! * [`heartbeat`] — periodic keepalive + roster reconciliation task.
//! * [`peer_sync`] — SSE consumer for `/v1/mesh/peers/stream`.

pub mod client;
pub mod command;
pub mod heartbeat;
pub mod peer_sync;
