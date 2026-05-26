//! On-disk status snapshot written by the `join` daemon and read by
//! `status` / `leave`.
//!
//! Layout: `~/.tabbify-mesh/status.json`. The file is overwritten every
//! few seconds while the daemon is alive and removed cleanly on `leave`.

use std::net::Ipv6Addr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const STATUS_DIR_NAME: &str = ".tabbify-mesh";
const STATUS_FILE_NAME: &str = "status.json";

/// Snapshot persisted by the `join` daemon.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StatusSnapshot {
    /// Stable peer identifier assigned by the coordinator.
    pub peer_id: Uuid,
    /// Tenant-scoped ULA bound to the local TUN device.
    pub ula: Ipv6Addr,
    /// Coordinator the daemon is attached to.
    pub coordinator_url: String,
    /// Display name advertised to other peers.
    pub display_name: String,
    /// Free-form tags advertised to other peers.
    pub tags: Vec<String>,
    /// Number of peers currently known to the daemon, self included.
    pub peer_count: usize,
    /// Wall-clock of the last successful heartbeat.
    pub last_heartbeat_at: DateTime<Utc>,
    /// PID of the running `join` daemon.
    pub pid: u32,
}

/// Resolves `~/.tabbify-mesh/`.
///
/// # Errors
/// Returns an error if `$HOME` is unset or empty.
pub fn status_dir() -> Result<PathBuf> {
    let home = std::env::var("HOME").context("HOME environment variable is not set")?;
    if home.is_empty() {
        anyhow::bail!("HOME environment variable is empty");
    }
    Ok(PathBuf::from(home).join(STATUS_DIR_NAME))
}

/// Full path to the status file under [`status_dir`].
///
/// # Errors
/// Propagates [`status_dir`] failures.
pub fn status_path() -> Result<PathBuf> {
    Ok(status_dir()?.join(STATUS_FILE_NAME))
}

/// Atomically write `snapshot` to `path`. Creates parent dirs as needed.
///
/// # Errors
/// Returns an error if the parent directory cannot be created, if the
/// snapshot cannot be serialized, or if either the temp write or rename
/// fail.
pub fn write_to(path: &Path, snapshot: &StatusSnapshot) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create status dir {}", parent.display()))?;
    }
    let json = serde_json::to_string_pretty(snapshot).context("serialize status snapshot")?;
    // Atomic write: temp file in the same dir, then rename.
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, json).with_context(|| format!("write {}", tmp.display()))?;
    std::fs::rename(&tmp, path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

/// Write the snapshot to the default location (`~/.tabbify-mesh/status.json`).
///
/// # Errors
/// Propagates [`status_path`] and [`write_to`] failures.
pub fn write(snapshot: &StatusSnapshot) -> Result<()> {
    write_to(&status_path()?, snapshot)
}

/// Read a snapshot from `path`.
///
/// # Errors
/// Returns an error if the file is missing, unreadable, or malformed.
pub fn read_from(path: &Path) -> Result<StatusSnapshot> {
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))
}

/// Read the snapshot from the default location.
///
/// # Errors
/// Propagates [`status_path`] and [`read_from`] failures.
pub fn read() -> Result<StatusSnapshot> {
    read_from(&status_path()?)
}

/// Delete the status file if it exists. Idempotent.
///
/// # Errors
/// Returns an error if the path resolves but the unlink fails for any
/// reason other than `NotFound`.
pub fn remove() -> Result<()> {
    let path = status_path()?;
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("remove {}", path.display())),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;
    use std::str::FromStr;

    fn sample_snapshot() -> StatusSnapshot {
        StatusSnapshot {
            peer_id: Uuid::from_u128(0x0123_4567_89AB_CDEF_0123_4567_89AB_CDEF),
            ula: Ipv6Addr::from_str("fd5a:1f00:1:1::1").expect("parse ULA"),
            coordinator_url: "http://127.0.0.1:8888".to_string(),
            display_name: "leo-mac".to_string(),
            tags: vec!["dev-machine".to_string(), "wasm-host".to_string()],
            peer_count: 3,
            last_heartbeat_at: DateTime::from_timestamp(1_700_000_000, 0).expect("valid timestamp"),
            pid: 12_345,
        }
    }

    #[test]
    fn round_trip_via_tempfile() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("nested").join("status.json");
        let snap = sample_snapshot();

        write_to(&path, &snap).expect("write_to");
        let loaded = read_from(&path).expect("read_from");
        assert_eq!(loaded, snap);
    }

    #[test]
    fn read_missing_file_errors() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("missing.json");
        let err = read_from(&path).expect_err("expected error on missing file");
        assert!(format!("{err:#}").contains("missing.json"));
    }

    #[test]
    fn write_overwrites_existing_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("status.json");

        let mut snap = sample_snapshot();
        write_to(&path, &snap).expect("first write");

        snap.peer_count = 99;
        write_to(&path, &snap).expect("second write");

        let loaded = read_from(&path).expect("read_from");
        assert_eq!(loaded.peer_count, 99);
    }

    #[test]
    fn json_payload_has_expected_fields() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("status.json");
        write_to(&path, &sample_snapshot()).expect("write");

        let raw = std::fs::read_to_string(&path).expect("read raw");
        for needle in [
            "peer_id",
            "ula",
            "coordinator_url",
            "display_name",
            "tags",
            "peer_count",
            "last_heartbeat_at",
            "pid",
        ] {
            assert!(raw.contains(needle), "missing field {needle} in {raw}");
        }
    }
}
