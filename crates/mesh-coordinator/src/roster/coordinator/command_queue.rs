//! Per-`PeerEntry` signed-command relay queue (Track C remote-restart).
//!
//! The coordinator is a DUMB RELAY: it queues a fully-signed [`NodeCommandDto`]
//! against the target peer and drains it into the next heartbeat response. It
//! NEVER inspects the signature — the node verifies the super-admin key
//! end-to-end, so a compromised coordinator cannot forge a command.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::roster::coordinator::Coordinator;

/// Relay mirror of the joiner's `NodeCommand`. Carried verbatim — the
/// coordinator treats `verb` / `signature` as opaque pass-through.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct NodeCommandDto {
    /// Idempotency key (UUID v7 string).
    pub command_id: String,
    /// Opaque verb string (`restart_joiner` / `reset_wg` / `reboot_host`).
    pub verb: String,
    /// Target peer id (string UUID).
    pub peer_id: String,
    /// Anti-replay nonce.
    pub nonce: String,
    /// Issued-at, unix micros.
    pub issued_at: i64,
    /// Expiry, unix micros.
    pub expiry: i64,
    /// Ed25519 signature (hex) — opaque to the coordinator.
    #[serde(default)]
    pub signature: String,
}

impl Coordinator {
    /// Queue a fully-signed command for `peer_id` (admin issuer side). No-op
    /// when the peer is not (or no longer) in the roster. The coordinator does
    /// NOT verify the signature — it is a relay.
    pub fn enqueue_command(&self, peer_id: Uuid, command: NodeCommandDto) {
        if let Some(mut entry) = self.inner.roster.get_mut(&peer_id) {
            entry.pending_commands.push(command);
        }
    }

    /// Drain (take) every pending command for `peer_id`, leaving the queue
    /// empty. Returns `[]` for an unknown peer. Called by the heartbeat path to
    /// stuff `HeartbeatResponse.pending_commands`.
    #[must_use]
    pub fn drain_commands(&self, peer_id: Uuid) -> Vec<NodeCommandDto> {
        self.inner
            .roster
            .get_mut(&peer_id)
            .map(|mut e| std::mem::take(&mut e.pending_commands))
            .unwrap_or_default()
    }

    /// Remove any pending command whose `command_id` is in `acked` (the node
    /// reported it executed). Idempotent. Guards the at-least-once carrier
    /// against re-delivering an already-run verb when the drain and the ack
    /// race across ticks.
    pub fn ack_commands(&self, peer_id: Uuid, acked: &[String]) {
        if acked.is_empty() {
            return;
        }
        if let Some(mut entry) = self.inner.roster.get_mut(&peer_id) {
            entry
                .pending_commands
                .retain(|c| !acked.contains(&c.command_id));
        }
    }

    /// Read-only snapshot of pending `command_id`s for `peer_id` (the `GET`
    /// status endpoint). `[]` for an unknown peer / empty queue.
    #[must_use]
    pub fn pending_command_ids(&self, peer_id: Uuid) -> Vec<String> {
        self.inner
            .roster
            .get(&peer_id)
            .map(|e| {
                e.pending_commands
                    .iter()
                    .map(|c| c.command_id.clone())
                    .collect()
            })
            .unwrap_or_default()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::publisher::NoopPublisher;
    use crate::roster::coordinator::Coordinator;
    use crate::roster::events::PeerJoined;
    use std::sync::Arc;
    use std::time::Duration;

    fn cmd(id: &str, verb: &str, peer: Uuid) -> NodeCommandDto {
        NodeCommandDto {
            command_id: id.to_owned(),
            verb: verb.to_owned(),
            peer_id: peer.to_string(),
            nonce: format!("nonce-{id}"),
            issued_at: 1,
            expiry: i64::MAX,
            signature: "deadbeef".to_owned(),
        }
    }

    /// Register one minimal peer through the real apply seam + return its id
    /// (`register_for_test` does not exist in this crate; `apply_peer_joined`
    /// is the canonical roster-insert path the rest of the tests use).
    fn register_one(coord: &Coordinator) -> Uuid {
        let peer = Uuid::now_v7();
        let joined = PeerJoined {
            peer_id: peer.to_string(),
            wg_public_key: vec![1u8; 32],
            ula: "fd5a:1f00:1:5::1".into(),
            listen_endpoint: String::new(),
            display_name: "node-1".into(),
            network: "n1".into(),
            tags: vec![],
            hosted_app_ulas: vec![],
            joined_at_micros: 1,
            kind: "peer".into(),
            parent: None,
            app_uuid: None,
            software_version: None,
            mesh_version: None,
            relay_only: false,
        };
        coord.apply_peer_joined(&joined).expect("register test peer");
        peer
    }

    /// Enqueue then drain returns the queued commands once; a second drain is
    /// empty (the heartbeat carries each command exactly once per tick).
    #[test]
    fn enqueue_then_drain_returns_once() {
        let coord = Coordinator::new(Arc::new(NoopPublisher), Duration::from_secs(30));
        let peer = register_one(&coord);
        coord.enqueue_command(peer, cmd("c1", "restart_joiner", peer));
        coord.enqueue_command(peer, cmd("c2", "reset_wg", peer));

        let drained = coord.drain_commands(peer);
        assert_eq!(drained.len(), 2);
        assert_eq!(drained[0].command_id, "c1");
        // Drained → the queue is now empty.
        assert!(coord.drain_commands(peer).is_empty());
    }

    /// Enqueuing for an unknown peer is a silent no-op (the peer may have
    /// deregistered between the admin POST and the queue write).
    #[test]
    fn enqueue_unknown_peer_is_noop() {
        let coord = Coordinator::new(Arc::new(NoopPublisher), Duration::from_secs(30));
        let ghost = Uuid::now_v7();
        coord.enqueue_command(ghost, cmd("c1", "restart_joiner", ghost));
        assert!(coord.drain_commands(ghost).is_empty());
    }

    /// Acking a `command_id` removes it from the pending set so a re-drain (the
    /// at-least-once heartbeat carrier) does not re-deliver an executed verb.
    #[test]
    fn ack_removes_pending_command() {
        let coord = Coordinator::new(Arc::new(NoopPublisher), Duration::from_secs(30));
        let peer = register_one(&coord);
        coord.enqueue_command(peer, cmd("c1", "reset_wg", peer));
        // Ack BEFORE drain (the node acks the PREVIOUS tick's command).
        coord.ack_commands(peer, &["c1".to_owned()]);
        assert!(coord.drain_commands(peer).is_empty());
    }

    /// [`Coordinator::pending_command_ids`] reflects the queue without draining
    /// it.
    #[test]
    fn pending_command_ids_is_non_draining() {
        let coord = Coordinator::new(Arc::new(NoopPublisher), Duration::from_secs(30));
        let peer = register_one(&coord);
        coord.enqueue_command(peer, cmd("c1", "restart_joiner", peer));
        assert_eq!(coord.pending_command_ids(peer), vec!["c1".to_owned()]);
        // Still there — a status read must not drain.
        assert_eq!(coord.pending_command_ids(peer), vec!["c1".to_owned()]);
        assert_eq!(coord.drain_commands(peer).len(), 1);
    }
}
