//! HTTP surface for the coordinator control plane.
//!
//! Groups the JSON request/response types + axum router ([`api`]), the
//! SSE peer-stream plumbing ([`sse`]), the admin policy API ([`policy_api`],
//! `/v1/policy`), and the mTLS server config ([`mtls`]). Peer endpoints
//! live under `/v1/mesh/...`; the ACL admin endpoints under `/v1/policy`.
//!
//! Every admin-gated surface shares the single bearer check in
//! [`admin_auth`] — one definition of "is this caller an admin".

pub(crate) mod admin_auth;
pub mod api;
pub mod command_api;
pub mod direct_api;
pub mod mtls;
pub mod policy_api;
pub mod proactive_api;
pub(crate) mod relay;
pub mod sse;
