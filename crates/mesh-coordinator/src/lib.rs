//! mesh-coordinator — control plane for the overlay mesh.
//!
//! Joiners register over HTTP, get a stable peer-id + ULA, exchange
//! `WireGuard` public keys via this service, then carry data plane
//! traffic peer-to-peer. See [`events`] for the peer-lifecycle event
//! shapes.

// Domain-grouped modules. `publisher` stays at the crate root because it
// is a cross-cutting sink trait used by both the roster state machine and
// the NAT hole-punch path. `policy` holds the tag-based ACL allow-graph +
// its runtime store; the roster filter consumes it. `auth` holds the
// join-token validation client (spec §8) that makes the JWT claims
// authoritative for a node's network + tags.
pub mod auth;
pub mod http;
pub mod nat;
pub mod openapi;
pub mod policy;
pub mod publisher;
pub mod relay;
pub mod roster;

// Re-export the timeout sweeper at the crate root so `main.rs` keeps using
// `tabbify_mesh_coordinator::timeout::spawn` without caring that the module
// physically lives under `roster/`.
pub use roster::timeout;

pub use auth::{AuthValidator, ValidatedClaims, ValidationError};
pub use http::api::{PeerInfo, build_router, build_router_with_admin};
pub use http::mtls::{MtlsServerConfig, build_server_config};
pub use http::policy_api::PolicyApiState;
pub use http::sse::PeerEvent;
pub use nat::holepunch::{PunchPair, PunchPeer, PunchTracker, canonical_pair, try_emit_pair};
pub use policy::{AclRule, Policy, PolicyReplaceError, PolicySnapshot, PolicyStore};
pub use publisher::{EventPublisher, NoopPublisher};
pub use relay::RelayRegistry;
pub use roster::allocator::{DEFAULT_NETWORK_SLOT, ULA_PREFIX_LITERAL, UlaAllocator, network_slot};
pub use roster::coordinator::{Coordinator, CoordinatorError, PeerEntry};
pub use roster::events::{HolePunchInitiate, MeshEvent, PeerHeartbeat, PeerJoined, PeerLeft};
pub use roster::identity::{NodeIdentity, stamp_identity};
pub use roster::store::{FileRosterStore, NoopRosterStore, RosterStore, SharedRosterStore};
