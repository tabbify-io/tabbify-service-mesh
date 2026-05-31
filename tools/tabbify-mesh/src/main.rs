//! `tabbify-mesh` binary entry point.

use anyhow::Result;
use clap::Parser;

use tabbify_mesh::cli::{Cli, Cmd};
use tabbify_mesh::commands;

#[tokio::main]
async fn main() -> Result<()> {
    // Single fleet-wide logging init: JSON + `info` default + a flat
    // `service` field. This replaces the old inline `warn`-default,
    // non-JSON subscriber so this CLI's logs match the coordinator's and
    // the host apps' shape in Loki. Re-exported from `tabbify-mesh-joiner`.
    tabbify_mesh_joiner::init_logging("tabbify-mesh");

    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Join(args) => commands::join::run(*args).await,
        Cmd::Status => commands::status::run().await,
        Cmd::Peers(args) => commands::peers::run(args).await,
        Cmd::Leave(args) => commands::leave::run(args).await,
    }
}
