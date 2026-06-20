//! HTTP surface for the coordinator control plane.
//!
//! Groups the JSON request/response types + axum router ([`api`]), the
//! SSE peer-stream plumbing ([`sse`]), the admin policy API ([`policy_api`],
//! `/v1/policy`), and the mTLS server config ([`mtls`]). Peer endpoints
//! live under `/v1/mesh/...`; the ACL admin endpoints under `/v1/policy`.

pub mod api;
pub mod command_api;
pub mod direct_api;
pub mod mtls;
pub mod policy_api;
pub(crate) mod relay;
pub mod sse;
