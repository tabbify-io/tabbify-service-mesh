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
    peers: Vec<PeerRow>,
}

/// A `GET /v1/mesh/peers` row: the joiner [`PeerInfo`] PLUS the coordinator's
/// connectivity-pill fields (`connectivity` = direct/relay/dead,
/// `connectivity_age_ms`). Flattened so every existing field keeps working
/// while the CONN column reads the V-pill. Both connectivity fields default to
/// `None` (an older coordinator omits them — back-compatible).
#[derive(Debug, serde::Deserialize)]
struct PeerRow {
    #[serde(flatten)]
    info: PeerInfo,
    #[serde(default)]
    connectivity: Option<String>,
    #[serde(default)]
    connectivity_age_ms: Option<u64>,
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

fn print_peers(peers: &[PeerRow], self_peer_id: Option<uuid::Uuid>, now: DateTime<Utc>) {
    println!(
        "{:<20} {:<26} {:<22} {:<14} {:<18} {:<12}",
        "NAME", "ULA", "ENDPOINT", "CONN", "TAGS", "LAST_SEEN"
    );
    if peers.is_empty() {
        println!("(no peers)");
        return;
    }
    for row in peers {
        let peer = &row.info;
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
        let conn = conn_cell(row.connectivity.as_deref(), row.connectivity_age_ms);
        println!(
            "{:<20} {:<26} {:<22} {:<14} {:<18} {:<12}",
            truncate(&peer.display_name, 20),
            peer.ula.to_string(),
            endpoint,
            conn,
            truncate(&tags, 18),
            last_seen,
        );
    }
}

/// Render the CONN cell — the live connectivity V-pill (`direct`/`relay`/`dead`)
/// plus the age of the observation. `-` when the coordinator reported no
/// connectivity (older coordinator, or no live edge). During a rollout an
/// operator reads this column to confirm a pair went `direct` (or that a NAT
/// peer cleanly stays `relay`).
fn conn_cell(connectivity: Option<&str>, age_ms: Option<u64>) -> String {
    connectivity.map_or_else(
        || "-".to_string(),
        |state| {
            age_ms.map_or_else(
                || state.to_string(),
                |ms| format!("{state} {}", fmt_age_ms(ms)),
            )
        },
    )
}

/// Compact age formatter for the CONN cell: `820ms`, `3.4s`, `2m`. Integer math
/// only (no float cast) so the value is exact and clippy-clean.
fn fmt_age_ms(ms: u64) -> String {
    if ms < 1_000 {
        format!("{ms}ms")
    } else if ms < 60_000 {
        // One decimal of a second, computed without a lossy `u64 as f64`.
        format!("{}.{}s", ms / 1_000, (ms % 1_000) / 100)
    } else {
        format!("{}m", ms / 60_000)
    }
}

fn joined_at_relative(micros: i64, now: DateTime<Utc>) -> String {
    Utc.timestamp_micros(micros)
        .single()
        .map_or_else(|| "?".to_string(), |then| time_format::relative(then, now))
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
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
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

    #[test]
    fn conn_cell_renders_state_and_age() {
        assert_eq!(conn_cell(Some("direct"), Some(820)), "direct 820ms");
        assert_eq!(conn_cell(Some("relay"), Some(3_400)), "relay 3.4s");
        assert_eq!(conn_cell(Some("relay"), Some(120_000)), "relay 2m");
        // A wedged "dead" peer has no live edge to age (age None).
        assert_eq!(conn_cell(Some("dead"), None), "dead");
        // Older coordinator omits connectivity entirely.
        assert_eq!(conn_cell(None, None), "-");
    }

    /// The CONN column reads the coordinator's V-pill fields from the peers
    /// response even though the base `PeerInfo` (joiner) doesn't carry them —
    /// `#[serde(flatten)]` + the two extra optional fields capture both.
    #[test]
    fn peer_row_deserializes_flattened_connectivity() {
        let json = serde_json::json!({
            "peer_id": "00000000-0000-0000-0000-000000000000",
            "wg_public_key": vec![0u8; 32],
            "ula": "fd5a:1f00:0:2::1",
            "display_name": "serving",
            "tags": ["tag:system"],
            "joined_at_micros": 0,
            "connectivity": "direct",
            "connectivity_age_ms": 420
        });
        let row: PeerRow = serde_json::from_value(json).expect("deserialize PeerRow");
        assert_eq!(row.connectivity.as_deref(), Some("direct"));
        assert_eq!(row.connectivity_age_ms, Some(420));
        assert_eq!(row.info.display_name, "serving");
    }
}
