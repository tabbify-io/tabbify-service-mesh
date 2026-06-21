//! Standalone host [`CommandSink`] for the lifeline joiner (Track C).
//!
//! When `tabbify-mesh join --super-admin-pubkey <hex>` runs as a long-lived
//! lifeline daemon on a worker box, an accepted signed command must turn into a
//! HOST process effect the in-mesh joiner cannot perform on itself:
//!
//! * `RestartJoiner` → `systemctl restart tabbify-supervisor` (the cleanest
//!   "rebuild the joiner" on a host daemon — a fresh process re-reads
//!   `TABBIFY_MESH_RELAY_ONLY` from the unit env, preserving the relay floor).
//! * `RebootHost` → a GUARDED `systemctl reboot`, capped at ≤3/hour by a
//!   persisted [`RebootGuard`] so a wedged box cannot reboot-loop into a brick.
//!
//! This is the standalone-tool twin of the supervisor's
//! `mesh_command::{sink,reboot_guard}`: the lifeline joiner runs OUT of process
//! from the supervisor, so it needs its OWN sink rather than borrowing the
//! supervisor's. The exec + loop-guard are intentionally identical in behaviour.

use std::fs;
use std::io;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tabbify_mesh_joiner::coordinator::command_exec::CommandSink;

/// Max reboots permitted within [`WINDOW_SECS`] before the guard parks.
pub const MAX_PER_WINDOW: usize = 3;
/// Rolling window length (1 hour).
pub const WINDOW_SECS: u64 = 3600;

/// The systemd unit a `RestartJoiner` verb restarts — the supervisor on the
/// host (restarting the supervisor cycles its in-process joiner too).
pub const SUPERVISOR_UNIT: &str = "tabbify-supervisor";

/// Persisted reboot history (unix-seconds timestamps).
#[derive(Debug, Default, Serialize, Deserialize)]
struct RebootHistory {
    reboots: Vec<u64>,
}

/// File-backed reboot loop-guard (≤[`MAX_PER_WINDOW`] reboots / [`WINDOW_SECS`]).
pub struct RebootGuard {
    path: PathBuf,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl RebootGuard {
    /// Build a guard backed by `path` (created on first record).
    #[must_use]
    pub const fn new(path: PathBuf) -> Self {
        Self { path }
    }

    fn load(&self) -> RebootHistory {
        fs::read_to_string(&self.path).map_or_else(
            |_| RebootHistory::default(),
            |json| serde_json::from_str(&json).unwrap_or_default(),
        )
    }

    fn save(&self, h: &RebootHistory) -> io::Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let json =
            serde_json::to_string(h).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        fs::write(&self.path, json)
    }

    /// Try to consume a reboot slot at `now` (unix-seconds). Returns `true`
    /// (and records the reboot) when under the limit within the window; `false`
    /// (parked) otherwise. Prunes timestamps older than the window every call.
    pub fn try_reboot(&self, now: u64) -> bool {
        let mut h = self.load();
        let cutoff = now.saturating_sub(WINDOW_SECS);
        h.reboots.retain(|&t| t >= cutoff);
        if h.reboots.len() >= MAX_PER_WINDOW {
            tracing::error!(
                count = h.reboots.len(),
                "reboot loop-guard PARKED — {MAX_PER_WINDOW} reboots within the window, refusing further reboots"
            );
            // Persist the pruned history even on a park so the window keeps moving.
            let _ = self.save(&h);
            return false;
        }
        h.reboots.push(now);
        if let Err(e) = self.save(&h) {
            tracing::warn!(error = %e, "reboot guard persist failed");
        }
        true
    }

    /// Convenience over `try_reboot(now_unix())`.
    pub fn try_reboot_now(&self) -> bool {
        self.try_reboot(now_unix())
    }
}

/// Path of the reboot-history sidecar under `data_dir`.
#[must_use]
pub fn reboot_history_path(data_dir: &std::path::Path) -> PathBuf {
    data_dir.join("reboot-guard.json")
}

/// Standalone host command sink for the lifeline joiner.
pub struct HostCommandSink {
    reboot_guard: RebootGuard,
    /// The systemd unit to restart for `RestartJoiner`.
    unit: String,
}

impl HostCommandSink {
    /// Build a sink with the reboot-history sidecar under `data_dir`, restarting
    /// `unit` on `RestartJoiner`.
    #[must_use]
    pub fn new(data_dir: &std::path::Path, unit: impl Into<String>) -> Self {
        Self {
            reboot_guard: RebootGuard::new(reboot_history_path(data_dir)),
            unit: unit.into(),
        }
    }
}

impl CommandSink for HostCommandSink {
    fn restart_joiner(&self) {
        tracing::warn!(unit = %self.unit, "Track C: RestartJoiner → systemctl restart");
        let _ = Command::new("systemctl")
            .arg("restart")
            .arg(&self.unit)
            .status();
    }

    fn reboot_host(&self) {
        if !self.reboot_guard.try_reboot_now() {
            tracing::error!("Track C: RebootHost refused by loop-guard (parked for a human)");
            return;
        }
        tracing::warn!("Track C: RebootHost → systemctl reboot (guard slot consumed)");
        let _ = Command::new("systemctl").arg("reboot").status();
    }
}

/// Parse a 32-byte Ed25519 super-admin pubkey from optional 64-char hex.
///
/// `None` on absent / empty / malformed / wrong-length input — the caller then
/// leaves remote commands fail-closed (a wedged pubkey can never become an open
/// door).
#[must_use]
pub fn parse_super_admin_pubkey(hex_opt: Option<&str>) -> Option<[u8; 32]> {
    let trimmed = hex_opt?.trim();
    if trimmed.is_empty() {
        return None;
    }
    let raw = hex::decode(trimmed).ok()?;
    raw.as_slice().try_into().ok()
}

/// Build the standalone host command sink from a super-admin pubkey hex.
///
/// The seam Phase-1.A.2 wires through.
///
/// Returns `Some(sink)` ONLY when `pubkey` is a valid 64-char hex Ed25519 key
/// (so the in-mesh joiner has a real Track-C restart target), and `None` for an
/// empty/malformed pubkey (remote commands stay fail-closed). `data_dir` hosts
/// the reboot-guard sidecar.
#[must_use]
pub fn build_sink(pubkey: &str, data_dir: &std::path::Path) -> Option<Arc<dyn CommandSink>> {
    parse_super_admin_pubkey(Some(pubkey))?;
    Some(Arc::new(HostCommandSink::new(data_dir, SUPERVISOR_UNIT)))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// A valid 64-char hex pubkey → `build_sink` returns `Some` (a real Track-C
    /// restart target); an empty string → `None` (fail-closed).
    #[test]
    fn build_sink_some_for_valid_hex_none_for_empty() {
        let dir = TempDir::new().unwrap();
        let valid = "aa".repeat(32); // 64 hex chars = 32 bytes.
        assert!(
            build_sink(&valid, dir.path()).is_some(),
            "valid hex pubkey must build a sink"
        );
        assert!(
            build_sink("", dir.path()).is_none(),
            "empty pubkey must NOT build a sink (fail-closed)"
        );
        assert!(
            build_sink("not-hex", dir.path()).is_none(),
            "malformed pubkey must NOT build a sink"
        );
        assert!(
            build_sink(&"aa".repeat(16), dir.path()).is_none(),
            "wrong-length pubkey (16 bytes) must NOT build a sink"
        );
    }

    /// `parse_super_admin_pubkey` round-trips a valid key and rejects the bad
    /// shapes (absent / empty / short / non-hex).
    #[test]
    fn parse_pubkey_accepts_valid_rejects_bad() {
        let hex = "bb".repeat(32);
        assert_eq!(parse_super_admin_pubkey(Some(&hex)), Some([0xbb; 32]));
        assert!(parse_super_admin_pubkey(None).is_none());
        assert!(parse_super_admin_pubkey(Some("")).is_none());
        assert!(parse_super_admin_pubkey(Some("  ")).is_none());
        assert!(parse_super_admin_pubkey(Some("abcd")).is_none());
        assert!(parse_super_admin_pubkey(Some(&"zz".repeat(32))).is_none());
    }

    /// The reboot guard allows up to the limit then parks — the same loop-guard
    /// behaviour the supervisor's sink relies on.
    #[test]
    fn reboot_guard_parks_after_limit() {
        let dir = TempDir::new().unwrap();
        let guard = RebootGuard::new(reboot_history_path(dir.path()));
        let t = 42;
        for _ in 0..MAX_PER_WINDOW {
            assert!(guard.try_reboot(t), "within-limit reboot must be allowed");
        }
        assert!(
            !guard.try_reboot(t),
            "the {MAX_PER_WINDOW}+1-th reboot must be parked"
        );
    }
}
