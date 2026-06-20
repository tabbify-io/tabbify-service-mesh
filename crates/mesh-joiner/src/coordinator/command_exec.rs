//! Execute the signed commands a heartbeat response carried (Track C).
//!
//! `tick_once` calls [`process_commands`] after the roster reconcile. Each
//! command is verified + freshness-checked + replay-checked by the
//! [`crate::coordinator::command_gate::CommandGate`]; an accepted verb is
//! dispatched to the host's [`CommandSink`] (process-level effects:
//! `RestartJoiner` / `RebootHost`) or handled in-joiner (`ResetWg`). Every
//! executed / rejected / replayed `command_id` is acked so the coordinator
//! clears its queue (fail-forward — a forged command can never wedge the queue).
//!
//! INVARIANT: the sink's restart MUST re-join with `relay_only` UNCHANGED — it
//! rides `TABBIFY_MESH_RELAY_ONLY` in the unit env, so a process restart
//! preserves it automatically. `ResetWg` never touches the relay floor or
//! endpoints (see [`crate::wg::session::SessionTable::force_rehandshake_all`]).

use x25519_dalek::StaticSecret;

use crate::coordinator::command::{CommandVerb, NodeCommand};
use crate::coordinator::command_gate::{CommandGate, CommandVerdict};
use crate::wg::session::SessionTable;

/// Host-side process-level effects the joiner cannot perform on itself.
/// The supervisor implements this over its `Arc<Joiner>` + reboot loop-guard.
pub trait CommandSink: Send + Sync {
    /// Drop + rebuild the in-process joiner (fresh register, fresh Tunns, fresh
    /// relay-WS). MUST re-join with `relay_only` preserved.
    fn restart_joiner(&self);
    /// `systemctl reboot`, behind the host's reboot loop-guard (≤3/hour).
    fn reboot_host(&self);
}

/// A no-op [`CommandSink`] for a host that does not configure remote commands.
///
/// Combined with a fail-closed [`CommandGate`] (no super-admin pubkey ⇒ every
/// command rejected), a host without remote-command wiring simply never acts.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopCommandSink;

impl CommandSink for NoopCommandSink {
    fn restart_joiner(&self) {
        tracing::warn!("Track C: RestartJoiner ignored — no command sink configured");
    }
    fn reboot_host(&self) {
        tracing::warn!("Track C: RebootHost ignored — no command sink configured");
    }
}

/// Evaluate + execute every command from a heartbeat response.
///
/// Returns the `command_id`s to ack next tick (accepted, replayed, AND
/// rejected — anything we will not re-run). `relay_only` is the node's current
/// relay-only setting; no verb path may flip it (spec §7), and a restart
/// re-reads it from the unit env. `our_private` is this node's X25519 secret
/// (needed to re-arm sessions for `ResetWg`).
pub async fn process_commands(
    commands: &[NodeCommand],
    gate: &mut CommandGate,
    sink: &dyn CommandSink,
    sessions: &SessionTable,
    our_private: &StaticSecret,
    relay_only: bool,
    now_micros: i64,
) -> Vec<String> {
    let mut acks = Vec::with_capacity(commands.len());
    for cmd in commands {
        let id = cmd.command_id.to_string();
        match gate.evaluate(cmd, now_micros) {
            CommandVerdict::Accept => {
                execute_verb(cmd.verb, sink, sessions, our_private, relay_only).await;
                gate.mark_executed(cmd.nonce.clone());
                tracing::info!(command_id = %id, verb = ?cmd.verb, "executed remote command");
                acks.push(id);
            }
            CommandVerdict::Replay => {
                tracing::debug!(
                    command_id = %id,
                    "remote command already executed (replay) — acking"
                );
                acks.push(id);
            }
            CommandVerdict::Reject(e) => {
                tracing::warn!(
                    command_id = %id,
                    error = %e,
                    "rejected remote command — acking to clear queue"
                );
                acks.push(id);
            }
        }
    }
    acks
}

/// Dispatch a verified verb. The relay floor MUST survive every verb (spec §7):
/// a `RestartJoiner` re-reads `TABBIFY_MESH_RELAY_ONLY` from the unit env, and
/// `ResetWg` never touches endpoints or the relay handle. `relay_only` is the
/// node's current setting, carried for clarity/logging — no path flips it.
async fn execute_verb(
    verb: CommandVerb,
    sink: &dyn CommandSink,
    sessions: &SessionTable,
    our_private: &StaticSecret,
    relay_only: bool,
) {
    match verb {
        CommandVerb::RestartJoiner => {
            tracing::warn!(relay_only, "Track C: dispatching RestartJoiner to host sink");
            sink.restart_joiner();
        }
        CommandVerb::RebootHost => {
            tracing::warn!(relay_only, "Track C: dispatching RebootHost to host sink");
            sink.reboot_host();
        }
        CommandVerb::ResetWg => {
            // In-joiner: re-arm every session. Preserves endpoints + the relay
            // floor (a relay-only peer re-handshakes over the relay).
            sessions.force_rehandshake_all(our_private).await;
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::coordinator::command::CommandVerb;
    use crate::coordinator::command_gate::CommandGate;
    use ed25519_dalek::SigningKey;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tempfile::TempDir;
    use uuid::Uuid;
    use x25519_dalek::StaticSecret;

    #[derive(Default)]
    struct RecordingSink {
        restarts: AtomicUsize,
        reboots: AtomicUsize,
    }
    impl CommandSink for RecordingSink {
        fn restart_joiner(&self) {
            self.restarts.fetch_add(1, Ordering::SeqCst);
        }
        fn reboot_host(&self) {
            self.reboots.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn our_secret() -> StaticSecret {
        StaticSecret::from([5u8; 32])
    }

    fn signed(sk: &SigningKey, verb: CommandVerb, nonce: &str) -> NodeCommand {
        NodeCommand::new(
            Uuid::now_v7(),
            verb,
            "01910f10-0000-7000-8000-0000000000aa".to_owned(),
            nonce.to_owned(),
            1,
            i64::MAX,
        )
        .signed_by(sk)
    }

    /// A valid `RestartJoiner` is executed once and acked; replaying it acks
    /// without re-running the sink.
    #[tokio::test]
    async fn restart_executes_once_then_replay_acks_only() {
        let dir = TempDir::new().unwrap();
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let mut gate =
            CommandGate::new(Some(sk.verifying_key().to_bytes()), &dir.path().join("n.json"));
        let sink = Arc::new(RecordingSink::default());
        let sessions = SessionTable::new();
        let secret = our_secret();
        let c = signed(&sk, CommandVerb::RestartJoiner, "n1");

        let acks = process_commands(
            std::slice::from_ref(&c),
            &mut gate,
            sink.as_ref(),
            &sessions,
            &secret,
            true,
            10,
        )
        .await;
        assert_eq!(acks.len(), 1);
        assert_eq!(sink.restarts.load(Ordering::SeqCst), 1);

        // Replay: acked again, sink NOT called a second time.
        let acks2 =
            process_commands(&[c], &mut gate, sink.as_ref(), &sessions, &secret, true, 10).await;
        assert_eq!(acks2.len(), 1);
        assert_eq!(sink.restarts.load(Ordering::SeqCst), 1);
    }

    /// A forged (wrong-key) command is rejected but STILL acked so it cannot
    /// wedge the queue, and the sink is never called.
    #[tokio::test]
    async fn forged_command_rejected_but_acked() {
        let dir = TempDir::new().unwrap();
        let real = SigningKey::from_bytes(&[7u8; 32]);
        let attacker = SigningKey::from_bytes(&[9u8; 32]);
        let mut gate =
            CommandGate::new(Some(real.verifying_key().to_bytes()), &dir.path().join("n.json"));
        let sink = Arc::new(RecordingSink::default());
        let sessions = SessionTable::new();
        let secret = our_secret();
        let forged = signed(&attacker, CommandVerb::RebootHost, "evil");

        let acks =
            process_commands(&[forged], &mut gate, sink.as_ref(), &sessions, &secret, true, 10)
                .await;
        assert_eq!(acks.len(), 1, "forged command is acked to clear the queue");
        assert_eq!(
            sink.reboots.load(Ordering::SeqCst),
            0,
            "forged reboot never runs"
        );
    }

    /// A valid `ResetWg` is handled in-joiner (no sink call) and acked. With an
    /// empty session table it is a safe no-op — the point is the verb path runs
    /// without touching the sink.
    #[tokio::test]
    async fn reset_wg_handled_in_joiner_and_acked() {
        let dir = TempDir::new().unwrap();
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let mut gate =
            CommandGate::new(Some(sk.verifying_key().to_bytes()), &dir.path().join("n.json"));
        let sink = Arc::new(RecordingSink::default());
        let sessions = SessionTable::new();
        let secret = our_secret();
        let c = signed(&sk, CommandVerb::ResetWg, "n-reset");

        let acks =
            process_commands(&[c], &mut gate, sink.as_ref(), &sessions, &secret, true, 10).await;
        assert_eq!(acks.len(), 1);
        assert_eq!(sink.restarts.load(Ordering::SeqCst), 0);
        assert_eq!(sink.reboots.load(Ordering::SeqCst), 0);
    }
}
