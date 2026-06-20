//! Replay-guard + verify gate for incoming signed commands (Track C).
//!
//! `NonceStore` persists every EXECUTED nonce to a JSON sidecar so a replayed
//! command is refused across a process restart (same durable-sidecar pattern as
//! the supervisor dev-session record #63). `CommandGate` bundles the configured
//! super-admin pubkey with the store and decides one command's fate:
//! reject unsigned/tampered/expired/replayed, accept a fresh valid one.

use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::coordinator::command::{CommandVerifyError, NodeCommand};

/// Durable set of executed nonces, JSON-persisted to one file.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct NonceStore {
    nonces: HashSet<String>,
    #[serde(skip)]
    path: Option<PathBuf>,
}

impl NonceStore {
    /// Load the store from `path` (or an empty in-memory store if absent).
    #[must_use]
    pub fn load(path: &Path) -> Self {
        let mut store = fs::read_to_string(path).map_or_else(
            |_| Self::default(),
            |json| serde_json::from_str(&json).unwrap_or_default(),
        );
        store.path = Some(path.to_path_buf());
        store
    }

    /// Whether `nonce` has already been executed.
    #[must_use]
    pub fn contains(&self, nonce: &str) -> bool {
        self.nonces.contains(nonce)
    }

    /// Record `nonce` as executed and best-effort persist. Logs (does not fail)
    /// on a write error — a missed persist only risks one re-exec on restart,
    /// which the verbs are designed to tolerate (idempotent restart/reset).
    pub fn record(&mut self, nonce: String) {
        self.nonces.insert(nonce);
        if let Some(p) = &self.path {
            if let Err(e) = self.persist(p) {
                tracing::warn!(error = %e, "nonce store persist failed");
            }
        }
    }

    fn persist(&self, path: &Path) -> io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let json =
            serde_json::to_string(self).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        fs::write(path, json)
    }
}

/// Verdict for one incoming command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandVerdict {
    /// Fresh, valid, unseen — execute it.
    Accept,
    /// Already executed (replay) — skip but ACK so the queue clears.
    Replay,
    /// Failed verify / expired — reject (and ACK so a forged command can't wedge
    /// the queue forever).
    Reject(CommandVerifyError),
}

/// The configured super-admin pubkey + the persisted nonce store.
pub struct CommandGate {
    /// Super-admin Ed25519 pubkey (32 raw bytes). `None` disables remote
    /// commands entirely (fail-closed: every command is rejected).
    super_admin_pubkey: Option<[u8; 32]>,
    nonces: NonceStore,
}

impl CommandGate {
    /// Build a gate from an optional 32-byte pubkey + a nonce-store path.
    #[must_use]
    pub fn new(super_admin_pubkey: Option<[u8; 32]>, nonce_path: &Path) -> Self {
        Self {
            super_admin_pubkey,
            nonces: NonceStore::load(nonce_path),
        }
    }

    /// Decide a command's fate WITHOUT mutating the store (the caller records on
    /// successful execution via [`Self::mark_executed`]).
    #[must_use]
    pub fn evaluate(&self, cmd: &NodeCommand, now_micros: i64) -> CommandVerdict {
        let Some(pk) = self.super_admin_pubkey else {
            return CommandVerdict::Reject(CommandVerifyError::BadSignature);
        };
        if let Err(e) = cmd.verify(&pk) {
            return CommandVerdict::Reject(e);
        }
        if let Err(e) = cmd.check_fresh(now_micros) {
            return CommandVerdict::Reject(e);
        }
        if self.nonces.contains(&cmd.nonce) {
            return CommandVerdict::Replay;
        }
        CommandVerdict::Accept
    }

    /// Persist `nonce` as executed (call AFTER a verb runs).
    pub fn mark_executed(&mut self, nonce: String) {
        self.nonces.record(nonce);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::coordinator::command::CommandVerb;
    use ed25519_dalek::SigningKey;
    use tempfile::TempDir;
    use uuid::Uuid;

    fn cmd(sk: &SigningKey, nonce: &str, expiry: i64) -> NodeCommand {
        NodeCommand::new(
            Uuid::now_v7(),
            CommandVerb::RestartJoiner,
            "01910f10-0000-7000-8000-0000000000aa".to_owned(),
            nonce.to_owned(),
            1,
            expiry,
        )
        .signed_by(sk)
    }

    #[test]
    fn accept_then_replay_after_record() {
        let dir = TempDir::new().unwrap();
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let mut gate =
            CommandGate::new(Some(sk.verifying_key().to_bytes()), &dir.path().join("nonces.json"));
        let c = cmd(&sk, "n1", i64::MAX);
        assert_eq!(gate.evaluate(&c, 10), CommandVerdict::Accept);
        gate.mark_executed(c.nonce.clone());
        assert_eq!(gate.evaluate(&c, 10), CommandVerdict::Replay);
    }

    #[test]
    fn replay_survives_reload() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("nonces.json");
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let c = cmd(&sk, "n-persist", i64::MAX);
        {
            let mut g = CommandGate::new(Some(sk.verifying_key().to_bytes()), &path);
            assert_eq!(g.evaluate(&c, 10), CommandVerdict::Accept);
            g.mark_executed(c.nonce.clone());
        }
        // Fresh gate from disk → the nonce is still known (replay).
        let g2 = CommandGate::new(Some(sk.verifying_key().to_bytes()), &path);
        assert_eq!(g2.evaluate(&c, 10), CommandVerdict::Replay);
    }

    #[test]
    fn wrong_key_and_no_key_reject() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("n.json");
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let c = cmd(&sk, "n2", i64::MAX);
        // No configured pubkey → reject (fail-closed).
        let g = CommandGate::new(None, &path);
        assert!(matches!(g.evaluate(&c, 10), CommandVerdict::Reject(_)));
        // Wrong pubkey → reject.
        let other = SigningKey::from_bytes(&[8u8; 32]);
        let g2 = CommandGate::new(Some(other.verifying_key().to_bytes()), &path);
        assert!(matches!(
            g2.evaluate(&c, 10),
            CommandVerdict::Reject(CommandVerifyError::BadSignature)
        ));
    }
}
