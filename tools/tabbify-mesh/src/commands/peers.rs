//! `tabbify-mesh peers` — list peers known to the coordinator.

use anyhow::{Context, Result};
use chrono::{DateTime, TimeZone, Utc};

use crate::cli::PeersArgs;
use crate::joiner_api::PeerInfo;
use crate::status_file;
use crate::time_format;

/// Default coordinator endpoint that returns the live peer table.
/// Mirrors the mesh-coordinator HTTP contract.
const PEERS_ENDPOINT: &str = "/v1/mesh/peers";

#[derive(Debug, serde::Deserialize)]
struct PeersResponse {
    peers: Vec<PeerInfo>,
}

/// Run the `peers` subcommand.
///
/// # Errors
/// Returns an error if the coordinator request fails or its response
/// cannot be deserialized.
pub async fn run(args: PeersArgs) -> Result<()> {
    let url = format!(
        "{}{}",
        args.coordinator.trim_end_matches('/'),
        PEERS_ENDPOINT
    );
    let resp = reqwest::get(&url)
        .await
        .with_context(|| format!("GET {url}"))?;
    if !resp.status().is_success() {
        anyhow::bail!("coordinator returned HTTP {} for {url}", resp.status());
    }
    let body: PeersResponse = resp
        .json()
        .await
        .with_context(|| format!("decode peers response from {url}"))?;

    // Best-effort: identify our own row using the local status file (if
    // a daemon is running). Absence is non-fatal.
    let self_peer_id = status_file::read().ok().map(|s| s.peer_id);

    print_peers(&body.peers, self_peer_id, Utc::now());
    Ok(())
}

fn print_peers(
    peers: &[PeerInfo],
    self_peer_id: Option<uuid::Uuid>,
    now: DateTime<Utc>,
) {
    println!(
        "{:<20} {:<26} {:<22} {:<22} {:<12}",
        "NAME", "ULA", "ENDPOINT", "TAGS", "LAST_SEEN"
    );
    if peers.is_empty() {
        println!("(no peers)");
        return;
    }
    for peer in peers {
        let endpoint = peer
            .listen_endpoint
            .map_or_else(|| "-".to_string(), |e| e.to_string());
        let tags = if peer.tags.is_empty() {
            "-".to_string()
        } else {
            peer.tags.join(",")
        };
        let last_seen = if Some(peer.peer_id) == self_peer_id {
            "self".to_string()
        } else {
            joined_at_relative(peer.joined_at_micros, now)
        };
        println!(
            "{:<20} {:<26} {:<22} {:<22} {:<12}",
            truncate(&peer.display_name, 20),
            peer.ula.to_string(),
            endpoint,
            truncate(&tags, 22),
            last_seen,
        );
    }
}

fn joined_at_relative(micros: i64, now: DateTime<Utc>) -> String {
    Utc.timestamp_micros(micros).single().map_or_else(
        || "?".to_string(),
        |then| time_format::relative(then, now),
    )
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_short_string_unchanged() {
        assert_eq!(truncate("hello", 10), "hello");
    }

    #[test]
    fn truncate_long_string_gets_ellipsis() {
        let out = truncate("abcdefghijklmnop", 5);
        assert_eq!(out.chars().count(), 5);
        assert!(out.ends_with('…'));
    }
}
