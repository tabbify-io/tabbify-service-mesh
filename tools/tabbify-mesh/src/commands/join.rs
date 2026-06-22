//! `tabbify-mesh join` — long-running daemon that joins the overlay
//! mesh, periodically refreshes the local status file, and gracefully
//! deregisters on Ctrl-C.

use std::net::Ipv6Addr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::cli::JoinArgs;
use crate::joiner_api::{JoinConfig, Joiner};
use crate::status_file::{self, StatusSnapshot};

/// One-shot identity record written ONCE on a successful join when
/// `--status-file <PATH>` is set (the supervisor's lifeline systemd unit
/// points it at `<dataDir>/data/lifeline-status.json`).
///
/// Its sole purpose: after a supervisord crash wedges the in-process joiner,
/// an operator reads this file to learn the standalone lifeline's node-id and
/// addresses a Track-C signed restart command to it. Distinct from the
/// running-daemon [`StatusSnapshot`] in `~/.tabbify-mesh/status.json`: this is
/// the lifeline's STABLE address-of-record, not a live roster snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LifelineStatus {
    /// Coordinator-assigned peer id of this lifeline joiner (the Track-C target).
    pub peer_id: Uuid,
    /// This lifeline's mesh ULA.
    pub ula: Ipv6Addr,
    /// Display name advertised by this lifeline joiner.
    pub name: String,
}

/// Atomically write `status` to `path` as pretty JSON (tmp file in the same
/// dir, then rename — mirrors [`status_file::write_to`]). Creates parent dirs.
///
/// # Errors
/// Returns an error if the parent dir cannot be created, the record cannot be
/// serialized, or either the temp write or the rename fails.
fn write_lifeline_status(path: &Path, status: &LifelineStatus) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create lifeline-status dir {}", parent.display()))?;
    }
    let json = serde_json::to_string_pretty(status).context("serialize lifeline status")?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, json).with_context(|| format!("write {}", tmp.display()))?;
    std::fs::rename(&tmp, path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

/// Interval at which the daemon refreshes `~/.tabbify-mesh/status.json`.
const STATUS_REFRESH_INTERVAL: Duration = Duration::from_secs(5);

/// Default data dir for the standalone joiner's sidecars (reboot-guard, …)
/// when `--identity-path` is unset: `~/.tabbify-mesh`, falling back to the
/// current dir if `$HOME` is unavailable (a sidecar there is harmless).
fn default_data_dir() -> std::path::PathBuf {
    status_file::status_dir().unwrap_or_else(|_| std::path::PathBuf::from("."))
}

/// Map the parsed [`JoinArgs`] onto a [`JoinConfig`]. `super_admin_pubkey` is
/// NOT a config field (the sink + gate are SEPARATE `join_with_commands` args),
/// so it is consumed by the caller, not here.
fn build_join_config(args: JoinArgs) -> JoinConfig {
    JoinConfig {
        coordinator_url: args.coordinator,
        display_name: args.name,
        tags: args.tags,
        join_token: args.join_token,
        listen_port: args.listen_port,
        tun_name: args.tun_name,
        heartbeat_interval: Duration::from_secs(args.heartbeat_interval),
        advertise_endpoint: args.advertise_endpoint,
        // CLI doesn't expose `--keypair-path` yet — fall back to the
        // joiner's `$HOME/.tabbify-mesh/keypair` default so smoke tests
        // and ad-hoc runs persist a stable identity across restarts.
        keypair_path: None,
        // `--identity-path` (sticky keypair + ULA in one JSON). When set it
        // takes PRECEDENCE over the keypair-only default: the joiner's
        // `resolve_identity` uses the identity file and re-requests the same
        // mesh ULA across restarts (the lifeline-joiner sticky-address path).
        identity_path: args.identity_path,
        tls_cert: args.tls_cert,
        tls_key: args.tls_key,
        tls_ca: args.tls_ca,
        insecure_no_mtls: args.insecure_no_mtls,
        // Relay is on by default (the connectivity floor); `--no-relay`
        // opts out. `relay_urls` is the ORDERED HA-relay failover list
        // (repeated `--relay-url` / comma `TABBIFY_MESH_RELAY_URL`); empty
        // derives the single relay from the coordinator URL. The legacy
        // single `relay_url` field is unused from the CLI now — the list
        // supersedes it.
        relay_enabled: !args.no_relay,
        relay_url: None,
        relay_urls: args.relay_url,
        // Relay-only: this peer has no reachable direct endpoint, so the
        // coordinator must suppress its direct endpoint + hole-punch
        // directives. Off by default (a normal directly-reachable peer).
        relay_only: args.relay_only,
        // Host-integration toggles (multi-joiner-per-netns routing +
        // tailscaled-style firewall trust). Off by default.
        source_scoped_routes: args.source_scoped_routes,
        manage_firewall: args.manage_firewall,
        // Track A-a: optional STUN server for a symmetric-NAT-correct WG
        // mapping. Unset (default) keeps coordinator-reflexive advertise.
        stun_server: args.mesh_stun_server,
        // Runner-specific fields are not exposed via CLI — plain join is
        // always a plain peer. Per-app-runner processes set these
        // programmatically via JoinConfig directly.
        ..JoinConfig::default()
    }
}

/// Lifeline-distinct executed-nonce sidecar path (FIX 7). Lives in the SAME
/// `sink_data_dir` as the reboot-guard, but under a `lifeline-`-prefixed name so
/// it never collides with the supervisor in-process joiner's
/// `mesh-command-nonces.json` (both default to the identity dir). Factored out
/// so the lifeline-vs-supervisor distinctness is a directly testable contract.
fn lifeline_command_nonce_path(sink_data_dir: &std::path::Path) -> std::path::PathBuf {
    sink_data_dir.join("lifeline-command-nonces.json")
}

/// Join the mesh, wiring the Track-C signed-command gate + host sink IFF a
/// non-empty super-admin pubkey is given.
///
/// `super_admin_pubkey` set (and valid 64-char hex) ⇒ this standalone joiner is
/// a signed-remote-command TARGET (the lifeline recovery lever). Empty / unset
/// ⇒ plain join, remote commands fail-closed. `sink_data_dir` hosts the
/// reboot-guard sidecar. Factored out of [`run`] to keep it under the line cap.
async fn join_with_optional_sink(
    config: JoinConfig,
    coordinator: &str,
    super_admin_pubkey: Option<&str>,
    sink_data_dir: &std::path::Path,
) -> Result<Joiner> {
    match super_admin_pubkey.filter(|hex| !hex.trim().is_empty()) {
        Some(pubkey_hex) => {
            let pubkey = crate::host_sink::parse_super_admin_pubkey(Some(pubkey_hex))
                .with_context(|| "invalid --super-admin-pubkey (expected 64-char hex)")?;
            let sink = crate::host_sink::build_sink(pubkey_hex, sink_data_dir)
                .with_context(|| "invalid --super-admin-pubkey (expected 64-char hex)")?;
            println!("Track C: super-admin pubkey configured — signed remote commands ENABLED");
            // FIX 7: the standalone LIFELINE joiner MUST use a nonce file
            // DISTINCT from the supervisor's in-process joiner. Passing `None`
            // here would derive the same `<dataDir>/mesh-command-nonces.json` the
            // in-process joiner uses (they share `identity_path`'s parent dir),
            // so the two replay-guards would clobber each other's executed-nonce
            // ledger. Pin a lifeline-specific path in the SAME sink data dir.
            let nonce_path = lifeline_command_nonce_path(sink_data_dir);
            Joiner::join_with_commands(config, Some(pubkey), Some(nonce_path), Some(sink))
                .await
                .with_context(|| format!("join failed (coordinator={coordinator})"))
        }
        None => Joiner::join(config)
            .await
            .with_context(|| format!("join failed (coordinator={coordinator})")),
    }
}

/// Run the `join` subcommand.
///
/// # Errors
/// Returns an error if the coordinator handshake fails or if the status
/// file cannot be written during startup.
pub async fn run(args: JoinArgs) -> Result<()> {
    // Identity tied to coordinator / name / tags for the status snapshots, plus
    // the standalone Track-C sink inputs — built in a dedicated helper so `run`
    // stays under the clippy line cap.
    let coordinator = args.coordinator.clone();
    let name = args.name.clone();
    let tags = args.tags.clone();
    let super_admin_pubkey = args.super_admin_pubkey.clone();
    // Lifeline identity record (Track-C address-of-record). Captured before
    // `build_join_config` consumes `args`; written ONCE after a successful join.
    let status_file = args.status_file.clone();
    // Track C (standalone lifeline sink): the reboot-guard sidecar lives next to
    // the identity file (the lifeline's data dir) when one is set, else in the
    // default `~/.tabbify-mesh` dir.
    let sink_data_dir = args
        .identity_path
        .as_ref()
        .and_then(|p| p.parent())
        .map_or_else(default_data_dir, std::path::Path::to_path_buf);

    println!("joining... coordinator={coordinator}");

    let config = build_join_config(args);

    // When a super-admin pubkey is configured AND parses, run the joiner with
    // the Track-C gate (verifies every command against the key) wired to the
    // host command sink. Otherwise plain join — remote commands fail-closed.
    let joiner =
        join_with_optional_sink(config, &coordinator, super_admin_pubkey.as_deref(), &sink_data_dir)
            .await?;

    let my_peer_id = joiner.my_peer_id();
    let my_ula = joiner.my_ula();
    let initial_peers = joiner.peers();

    println!("peer_id={my_peer_id}");
    println!("ula={my_ula}");
    println!("peers={} (initial snapshot)", initial_peers.len());
    println!("running. Ctrl-C to leave.");

    // Track C: on a SUCCESSFUL join, record this lifeline's identity so an
    // operator can address a signed restart command to its node-id after a
    // supervisord crash. FATAL if it fails — the supervisor's lifeline unit
    // depends on this file existing, so a silent write failure would leave the
    // recovery lever unaddressable.
    if let Some(path) = status_file.as_deref() {
        let status = LifelineStatus {
            peer_id: my_peer_id,
            ula: my_ula,
            name: name.clone(),
        };
        write_lifeline_status(path, &status)
            .with_context(|| format!("write lifeline status file {}", path.display()))?;
        println!("lifeline status written: {}", path.display());
    }

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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn sample_status() -> LifelineStatus {
        LifelineStatus {
            peer_id: Uuid::from_u128(0x0123_4567_89AB_CDEF_0123_4567_89AB_CDEF),
            ula: Ipv6Addr::from_str("fd5a:1f00:2:3::1").expect("parse ULA"),
            name: "lifeline".to_string(),
        }
    }

    /// `--status-file` write produces a JSON file whose round-trip equals the
    /// source record (the post-join lifeline write contract, tested via the
    /// helper directly with a known `peer_id` / `ula` / `name`).
    #[test]
    fn write_lifeline_status_round_trips() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Nested path proves parent dirs are created (the systemd unit points
        // at `<dataDir>/data/lifeline-status.json`).
        let path = dir.path().join("data").join("lifeline-status.json");
        let status = sample_status();

        write_lifeline_status(&path, &status).expect("write_lifeline_status");

        let bytes = std::fs::read(&path).expect("read back");
        let loaded: LifelineStatus = serde_json::from_slice(&bytes).expect("parse");
        assert_eq!(loaded, status);
    }

    /// The persisted JSON carries exactly the operator-facing fields with their
    /// expected values — `peer_id`, `ula`, `name`.
    #[test]
    fn write_lifeline_status_json_has_expected_fields() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("lifeline-status.json");
        write_lifeline_status(&path, &sample_status()).expect("write");

        let raw = std::fs::read_to_string(&path).expect("read raw");
        for needle in ["peer_id", "ula", "name"] {
            assert!(raw.contains(needle), "missing field {needle} in {raw}");
        }
        // The joiner peer id + ULA + display name land verbatim (Uuid serializes
        // hyphenated; Ipv6Addr in its canonical compressed form).
        assert!(
            raw.contains("01234567-89ab-cdef-0123-456789abcdef"),
            "peer_id uuid must be serialized: {raw}"
        );
        assert!(raw.contains("fd5a:1f00:2:3::1"), "ula must be serialized: {raw}");
        assert!(raw.contains("lifeline"), "name must be serialized: {raw}");
    }

    /// FIX 7: the standalone lifeline joiner derives a nonce path ending in
    /// `lifeline-command-nonces.json` inside its sink data dir — DISTINCT from
    /// the supervisor in-process joiner's `mesh-command-nonces.json` (which the
    /// `None` arm of `join_with_commands` would otherwise derive in the same
    /// dir), so the two replay-guards never clobber each other.
    #[test]
    fn lifeline_command_nonce_path_is_distinct() {
        let dir = std::path::Path::new("/opt/tabbify/data");
        let path = lifeline_command_nonce_path(dir);
        assert!(
            path.ends_with("lifeline-command-nonces.json"),
            "lifeline nonce path must end in lifeline-command-nonces.json, got {}",
            path.display()
        );
        // It lives in the given sink data dir...
        assert_eq!(path.parent(), Some(dir));
        // ...and is NOT the supervisor in-process joiner's nonce file.
        assert_ne!(path, dir.join("mesh-command-nonces.json"));
    }

    /// A second write overwrites the file atomically (operator always reads the
    /// latest identity).
    #[test]
    fn write_lifeline_status_overwrites() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("lifeline-status.json");

        let mut status = sample_status();
        write_lifeline_status(&path, &status).expect("first write");

        status.name = "lifeline-renamed".to_string();
        write_lifeline_status(&path, &status).expect("second write");

        let bytes = std::fs::read(&path).expect("read back");
        let loaded: LifelineStatus = serde_json::from_slice(&bytes).expect("parse");
        assert_eq!(loaded.name, "lifeline-renamed");
    }
}
