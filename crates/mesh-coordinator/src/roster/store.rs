//! Durable roster snapshot store.
//!
//! The coordinator's roster is otherwise in-memory only: a restart (container
//! redeploy OR box replace) loses the peer set, resets the sequential ULA
//! allocator, and a peer that re-registers with a sticky `requested_ula` then
//! collides with a freshly-allocated index → `409 UlaConflict`, crash-looping
//! the joiner. See the production-readiness audit.
//!
//! This store persists the current peer set as a list of [`PeerJoined`] events
//! (each fully describes a peer) and reloads it on startup. Replaying those
//! through [`crate::roster::coordinator::Coordinator::apply_peer_joined`] —
//! the same pure apply seam a live register uses — restores the exact
//! `peer_id ↔ ULA ↔ wg_public_key` mapping AND bumps the allocator past every
//! restored index, so a coordinator restart no longer reshuffles ULAs and a
//! sticky re-register lands on the idempotent `by_pubkey` path (same address).
//!
//! The snapshot is a *compacted* event log: one entry per LIVE peer, rewritten
//! on each membership change. No heartbeat noise, bounded size, fast replay.

use crate::roster::events::PeerJoined;
use async_trait::async_trait;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{info, warn};

/// Durable sink for the coordinator's peer set.
///
/// Object-safe so the backend is pluggable (file today; an S3 backend that
/// also survives box-replace can be added behind the same trait without
/// touching the state machine).
#[async_trait]
pub trait RosterStore: Send + Sync {
    /// Load the persisted peer set. Returns empty on first boot or on ANY read
    /// error — a corrupt/unreadable snapshot must never crash startup; the
    /// mesh self-heals as joiners re-register.
    async fn load(&self) -> Vec<PeerJoined>;

    /// Persist the current peer set, replacing any prior snapshot. Best-effort:
    /// implementations log failures rather than propagating, since the caller
    /// has already committed the in-memory change.
    async fn save(&self, peers: &[PeerJoined]);
}

/// Type-erased handle the `Coordinator` holds.
pub type SharedRosterStore = Arc<dyn RosterStore>;

/// Default store — persists nothing, loads nothing.
///
/// Used by tests and the in-memory/dev configuration (no `--state-dir`): a
/// restart self-heals as joiners re-register within one heartbeat interval.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopRosterStore;

#[async_trait]
impl RosterStore for NoopRosterStore {
    async fn load(&self) -> Vec<PeerJoined> {
        Vec::new()
    }
    async fn save(&self, _peers: &[PeerJoined]) {}
}

/// File-backed store — writes the snapshot as a JSON array to
/// `<dir>/roster.json` via a temp file + atomic rename.
///
/// The temp-then-rename means a crash mid-write can never leave a partially
/// written (corrupt) snapshot. Back the directory with a docker volume on the
/// control box and the snapshot survives the common coordinator restart
/// (container recreate / image redeploy via SSM).
#[derive(Debug, Clone)]
pub struct FileRosterStore {
    /// Final snapshot path (`<dir>/roster.json`).
    path: PathBuf,
    /// Temp path written first, then atomically renamed onto `path`
    /// (`<dir>/roster.tmp` — a sibling in the same directory so `rename` is
    /// atomic within one filesystem).
    tmp: PathBuf,
}

impl FileRosterStore {
    /// Build a store rooted at `dir`. The snapshot lives at `<dir>/roster.json`.
    #[must_use]
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        let dir = dir.into();
        Self {
            path: dir.join("roster.json"),
            tmp: dir.join("roster.tmp"),
        }
    }
}

#[async_trait]
impl RosterStore for FileRosterStore {
    async fn load(&self) -> Vec<PeerJoined> {
        match tokio::fs::read(&self.path).await {
            Ok(bytes) => match serde_json::from_slice::<Vec<PeerJoined>>(&bytes) {
                Ok(peers) => {
                    info!(
                        count = peers.len(),
                        path = %self.path.display(),
                        "loaded durable roster snapshot",
                    );
                    peers
                }
                Err(e) => {
                    warn!(
                        error = %e,
                        path = %self.path.display(),
                        "roster snapshot parse failed — starting with empty roster",
                    );
                    Vec::new()
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                info!(path = %self.path.display(), "no roster snapshot yet — fresh start");
                Vec::new()
            }
            Err(e) => {
                warn!(
                    error = %e,
                    path = %self.path.display(),
                    "roster snapshot read failed — starting with empty roster",
                );
                Vec::new()
            }
        }
    }

    async fn save(&self, peers: &[PeerJoined]) {
        let buf = match serde_json::to_vec(peers) {
            Ok(b) => b,
            Err(e) => {
                warn!(error = %e, "roster snapshot serialize failed — keeping prior snapshot");
                return;
            }
        };
        // Ensure the parent directory exists (first save on a fresh volume).
        if let Some(parent) = self.path.parent() {
            if let Err(e) = tokio::fs::create_dir_all(parent).await {
                warn!(error = %e, dir = %parent.display(), "roster snapshot dir create failed");
                return;
            }
        }
        if let Err(e) = tokio::fs::write(&self.tmp, &buf).await {
            warn!(error = %e, path = %self.tmp.display(), "roster snapshot temp write failed");
            return;
        }
        // Atomic rename onto the real path — readers see either the old or the
        // new snapshot, never a torn write.
        if let Err(e) = tokio::fs::rename(&self.tmp, &self.path).await {
            warn!(error = %e, path = %self.path.display(), "roster snapshot rename failed");
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn sample_peer(idx: u8, name: &str) -> PeerJoined {
        PeerJoined {
            peer_id: uuid::Uuid::now_v7().to_string(),
            wg_public_key: vec![idx; 32],
            ula: format!("fd5a:1f00:0:{idx}::1"),
            listen_endpoint: "203.0.113.5:51820".into(),
            display_name: name.into(),
            network: String::new(),
            tags: vec!["supervisor".into()],
            hosted_app_ulas: vec![],
            joined_at_micros: 1,
            kind: "peer".into(),
            parent: None,
            app_uuid: None,
            software_version: Some("v1.0.0".into()),
            relay_only: false,
        }
    }

    #[tokio::test]
    async fn noop_store_loads_empty_and_save_is_a_noop() {
        let store = NoopRosterStore;
        store.save(&[sample_peer(1, "a")]).await;
        assert!(store.load().await.is_empty());
    }

    #[tokio::test]
    async fn file_store_round_trips_the_snapshot() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = FileRosterStore::new(dir.path());
        let peers = vec![sample_peer(1, "node"), sample_peer(7, "supervisor")];
        store.save(&peers).await;
        let loaded = store.load().await;
        assert_eq!(loaded, peers, "snapshot must round-trip exactly");
    }

    #[tokio::test]
    async fn file_store_load_is_empty_when_no_snapshot_exists() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = FileRosterStore::new(dir.path());
        assert!(
            store.load().await.is_empty(),
            "a missing snapshot loads as empty, not an error",
        );
    }

    #[tokio::test]
    async fn file_store_save_replaces_prior_snapshot() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = FileRosterStore::new(dir.path());
        store.save(&[sample_peer(1, "first")]).await;
        store
            .save(&[sample_peer(2, "second"), sample_peer(3, "third")])
            .await;
        let loaded = store.load().await;
        assert_eq!(loaded.len(), 2, "save replaces, never appends");
        assert_eq!(loaded[0].display_name, "second");
    }

    #[tokio::test]
    async fn file_store_load_is_empty_on_corrupt_snapshot() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = FileRosterStore::new(dir.path());
        tokio::fs::write(dir.path().join("roster.json"), b"{ not valid json")
            .await
            .expect("write corrupt");
        assert!(
            store.load().await.is_empty(),
            "a corrupt snapshot must never crash startup — load empty + self-heal",
        );
    }
}
