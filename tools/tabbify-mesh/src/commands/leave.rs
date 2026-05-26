//! `tabbify-mesh leave` — deregister from the coordinator without
//! requiring a running daemon.

use anyhow::{Context, Result};
use uuid::Uuid;

use crate::cli::{DEFAULT_COORDINATOR_URL, LeaveArgs};
use crate::status_file;

const LEAVE_ENDPOINT: &str = "/v1/mesh/deregister";

/// Run the `leave` subcommand.
///
/// Resolution order for `peer_id` and `coordinator_url`:
///   1. explicit CLI flag,
///   2. value from the local status file,
///   3. (for coordinator only) `TABBIFY_MESH_COORDINATOR` env var or
///      `DEFAULT_COORDINATOR_URL`.
///
/// # Errors
/// Returns an error if no `peer_id` can be resolved or the coordinator
/// rejects the deregister request.
pub async fn run(args: LeaveArgs) -> Result<()> {
    let snapshot = status_file::read().ok();

    let peer_id: Uuid = match args
        .peer_id
        .or_else(|| snapshot.as_ref().map(|s| s.peer_id))
    {
        Some(id) => id,
        None => {
            anyhow::bail!(
                "no peer_id: pass --peer-id <UUID> or start a `join` daemon to populate the local status file"
            );
        }
    };

    let coordinator = args
        .coordinator
        .or_else(|| snapshot.as_ref().map(|s| s.coordinator_url.clone()))
        .unwrap_or_else(|| DEFAULT_COORDINATOR_URL.to_string());

    let url = format!("{}{LEAVE_ENDPOINT}", coordinator.trim_end_matches('/'));

    println!("leaving peer_id={peer_id} via {coordinator}");

    let resp = reqwest::Client::new()
        .post(&url)
        .json(&serde_json::json!({ "peer_id": peer_id }))
        .send()
        .await
        .with_context(|| format!("POST {url}"))?;

    if !resp.status().is_success() {
        anyhow::bail!("coordinator returned HTTP {} for {url}", resp.status());
    }

    // Clean up the local status file — best effort.
    if let Err(e) = status_file::remove() {
        tracing::warn!(error = %e, "remove status file failed");
    }

    println!("left.");
    Ok(())
}
