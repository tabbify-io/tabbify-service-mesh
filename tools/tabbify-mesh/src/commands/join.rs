//! `tabbify-mesh join` — long-running daemon that joins the overlay
//! mesh, periodically refreshes the local status file, and gracefully
//! deregisters on Ctrl-C.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::Utc;
use tokio::sync::Mutex;

use crate::cli::JoinArgs;
use crate::joiner_api::{JoinConfig, Joiner};
use crate::status_file::{self, StatusSnapshot};

/// Interval at which the daemon refreshes `~/.tabbify-mesh/status.json`.
const STATUS_REFRESH_INTERVAL: Duration = Duration::from_secs(5);

/// Run the `join` subcommand.
///
/// # Errors
/// Returns an error if the coordinator handshake fails or if the status
/// file cannot be written during startup.
pub async fn run(args: JoinArgs) -> Result<()> {
    let JoinArgs {
        coordinator,
        name,
        tags,
        join_token,
        listen_port,
        tun_name,
        heartbeat_interval,
        advertise_endpoint,
        tls_cert,
        tls_key,
        tls_ca,
        insecure_no_mtls,
    } = args;

    println!("joining... coordinator={coordinator}");

    let config = JoinConfig {
        coordinator_url: coordinator.clone(),
        display_name: name.clone(),
        tags: tags.clone(),
        join_token,
        listen_port,
        tun_name,
        heartbeat_interval: Duration::from_secs(heartbeat_interval),
        advertise_endpoint,
        // CLI doesn't expose `--keypair-path` yet — fall back to the
        // joiner's `$HOME/.tabbify-mesh/keypair` default so smoke tests
        // and ad-hoc runs persist a stable identity across restarts.
        keypair_path: None,
        tls_cert,
        tls_key,
        tls_ca,
        insecure_no_mtls,
    };

    let joiner = Joiner::join(config)
        .await
        .with_context(|| format!("join failed (coordinator={coordinator})"))?;

    let my_peer_id = joiner.my_peer_id();
    let my_ula = joiner.my_ula();
    let initial_peers = joiner.peers();

    println!("peer_id={my_peer_id}");
    println!("ula={my_ula}");
    println!("peers={} (initial snapshot)", initial_peers.len());
    println!("running. Ctrl-C to leave.");

    // Write the first status snapshot immediately so that `status` /
    // `peers` see a fresh file from the start. NON-FATAL: when multiple
    // peers run on the same host (smoke tests), they race on the shared
    // `~/.tabbify-mesh/status.json` path — one wins, others lose. The
    // daemon must keep running regardless; only the most-recently-written
    // peer ends up in the status file.
    if let Err(e) = status_file::write(&snapshot_from(&joiner, &coordinator, &name, &tags)) {
        tracing::warn!(error = %e, "initial status file write failed (ok if multiple peers share HOME)");
    }

    let joiner = Arc::new(Mutex::new(Some(joiner)));

    // Background refresh loop. Exits cleanly when the joiner handle is
    // taken (during shutdown) or on a write failure (which we log and
    // continue from).
    let refresh_handle = {
        let joiner = Arc::clone(&joiner);
        let coordinator = coordinator.clone();
        let name = name.clone();
        let tags = tags.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(STATUS_REFRESH_INTERVAL);
            // First tick fires immediately — skip it since we just wrote.
            ticker.tick().await;
            loop {
                ticker.tick().await;
                let snapshot = snapshot_under_lock(&joiner, &coordinator, &name, &tags).await;
                let Some(snapshot) = snapshot else { break };
                if let Err(e) = status_file::write(&snapshot) {
                    tracing::warn!(error = %e, "status file refresh failed");
                }
            }
        })
    };

    // Wait for Ctrl-C.
    if let Err(e) = tokio::signal::ctrl_c().await {
        tracing::warn!(error = %e, "ctrl_c listener failed");
    }

    println!("leaving...");

    // Take the joiner out of the shared cell so the refresh loop exits.
    let owned = {
        let mut guard = joiner.lock().await;
        guard.take()
    };
    refresh_handle.abort();
    let _ = refresh_handle.await;

    if let Some(joiner) = owned {
        if let Err(e) = joiner.leave().await {
            tracing::warn!(error = %e, "leave failed");
        }
    }

    if let Err(e) = status_file::remove() {
        tracing::warn!(error = %e, "remove status file failed");
    }

    Ok(())
}

fn snapshot_from(
    joiner: &Joiner,
    coordinator_url: &str,
    display_name: &str,
    tags: &[String],
) -> StatusSnapshot {
    let peers = joiner.peers();
    StatusSnapshot {
        peer_id: joiner.my_peer_id(),
        ula: joiner.my_ula(),
        coordinator_url: coordinator_url.to_string(),
        display_name: display_name.to_string(),
        tags: tags.to_vec(),
        peer_count: peers.len(),
        last_heartbeat_at: Utc::now(),
        pid: std::process::id(),
    }
}

/// Acquire the shared joiner lock long enough to extract the live peer
/// roster and identity, then release the lock before building the
/// snapshot. Returns `None` if the joiner has already been taken for
/// shutdown.
async fn snapshot_under_lock(
    joiner: &Arc<Mutex<Option<Joiner>>>,
    coordinator_url: &str,
    display_name: &str,
    tags: &[String],
) -> Option<StatusSnapshot> {
    let mut guard = joiner.lock().await;
    let inner = guard.as_mut()?;
    let peer_id = inner.my_peer_id();
    let ula = inner.my_ula();
    let peers = inner.peers();
    drop(guard);

    Some(StatusSnapshot {
        peer_id,
        ula,
        coordinator_url: coordinator_url.to_string(),
        display_name: display_name.to_string(),
        tags: tags.to_vec(),
        peer_count: peers.len(),
        last_heartbeat_at: Utc::now(),
        pid: std::process::id(),
    })
}
