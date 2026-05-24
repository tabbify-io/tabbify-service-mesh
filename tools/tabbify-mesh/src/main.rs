//! `tabbify-mesh` binary entry point.

use anyhow::Result;
use clap::Parser;
use tracing_subscriber::EnvFilter;

use tabbify_mesh::cli::{Cli, Cmd};
use tabbify_mesh::commands;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .init();

    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Join(args) => commands::join::run(args).await,
        Cmd::Status => commands::status::run().await,
        Cmd::Peers(args) => commands::peers::run(args).await,
        Cmd::Leave(args) => commands::leave::run(args).await,
    }
}
