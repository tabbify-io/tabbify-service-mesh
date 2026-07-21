//! Single source of truth for the join/mint contract shared by
//! `tabbify-service-auth` (mints join tokens), `tabbify-service-node`
//! (requests them) and `tabbify-service-mesh` (grants mesh addresses).
//!
//! Every item here used to exist as two or three hand-mirrored copies guarded
//! only by a "MUST stay in lockstep" comment; each copy that drifted became a
//! production incident (app-name charset, legacy registry ULA, silent
//! `JoinRequest` divergence). Services vendor this crate
//! (`vendor/tabbify-join-contract`) so every rule exists exactly once.

mod container;
mod join_request;
mod ula;

pub use container::{
    is_container_name_char, validate_container_name, ContainerNameError, CONTAINER_KINDS,
    CONTAINER_NAME_MAX_LEN,
};
pub use join_request::JoinRequest;
pub use ula::{is_fixed_infra_ula, is_legacy_infra_ula, HOST_ULA_SLOT, INFRA_ULA_IDX};
