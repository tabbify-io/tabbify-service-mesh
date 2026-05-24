//! Joiner API facade.
//!
//! Thin re-export of the real `tabbify-mesh-joiner` crate. Lives in its
//! own module so the CLI never imports the joiner crate directly; if we
//! ever need to mock the joiner for CLI-level tests, the seam is here.

pub use tabbify_mesh_joiner::{JoinConfig, Joiner, JoinerError, PeerInfo, Result};
