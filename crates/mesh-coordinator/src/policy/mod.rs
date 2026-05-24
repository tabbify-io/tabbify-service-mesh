//! ACL policy domain — tag-based allow-graph + its runtime store.
//!
//! [`model`] holds the [`Policy`] / [`AclRule`] types and the
//! default-deny, symmetric [`Policy::can_see`] evaluator (OQ-7: symmetric
//! visibility now, asymmetric deferred). [`store`] wraps a live policy
//! behind an `RwLock` with `ETag` optimistic concurrency for the
//! `GET`/`PUT` `/v1/policy` admin API.
//!
//! The mesh's whole worldview is "peers ↔ peers + tags/ACL" — this module
//! is the ACL half. The coordinator filters every node's view of the
//! roster through [`Policy::can_see`] so a node only ever learns the
//! peers it is allowed to reach; the joiner then builds `WireGuard`
//! sessions solely from that filtered roster, making isolation a
//! *consequence* of filtering rather than a separate enforcement step.

pub mod model;
pub mod store;

pub use model::{AclRule, Policy};
pub use store::{PolicyReplaceError, PolicySnapshot, PolicyStore};
