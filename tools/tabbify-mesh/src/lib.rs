//! `tabbify-mesh` — library face of the `tabbify-mesh` binary.
//!
//! Exposes submodules so that unit tests (status-file round-trips,
//! relative-time formatting) can exercise pure helpers without spinning
//! up the full CLI.
#![cfg_attr(not(test), warn(missing_docs))]

pub mod cli;
pub mod commands;
pub mod joiner_api;
pub mod status_file;
pub mod time_format;
