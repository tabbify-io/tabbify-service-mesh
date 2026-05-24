//! Stage 2 skeleton — UDP hole punch subscriber stub.
//!
//! The real implementation will:
//!
//! 1. Subscribe to `HolePunchInitiate` events from the coordinator (on
//!    segment `platform.mesh.peers`). The current SSE endpoint
//!    (`/v1/mesh/peers/stream`) only carries roster-shape `peer_added`
//!    / `peer_updated` / `peer_removed` frames — Stage 2 will need
//!    either an extension of that stream to carry hole-punch events
//!    or a sibling endpoint (`/v1/mesh/holepunch/stream`) carrying
//!    them.
//! 2. For each event where `initiator_peer_id` matches our peer id,
//!    fire a sequence of UDP packets at `target_external_endpoint` on
//!    our existing WG socket, then mark the session as "punched" so
//!    `wg_session::upsert` skips its normal handshake-initiation logic.
//! 3. For each event where `target_peer_id` matches our peer id, expect
//!    inbound packets from the initiator's endpoint and accept them.
//! 4. Handle timing (the simultaneous-fire is the whole point) via a
//!    delayed dispatch keyed off `timestamp_micros`.
//!
//! For now this module is a **stub** that runs a tokio task respecting
//! shutdown, logs that it's running, and exits cleanly. The
//! [`handle_holepunch_initiate`] entry point is exported separately so
//! the eventual SSE consumer can call it once the wire mechanism is
//! decided — gives downstream code the right import path now without
//! requiring SSE-extension work today.

use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::sync::watch;
use tracing::{debug, info};
use uuid::Uuid;

/// Coordinator-driven UDP hole punch initiation (Stage 2).
///
/// Mirrors the coordinator's event of the same name: emitted as a pair
/// (one per peer, initiator/target swapped) when both peers have a known
/// external endpoint. Defined locally so the joiner carries no dependency
/// on the coordinator crate; the SSE wire mechanism that delivers these
/// is not yet wired (see the module docs).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HolePunchInitiate {
    /// Peer that should send first.
    pub initiator_peer_id: String,
    /// Peer to dial.
    pub target_peer_id: String,
    /// External endpoint to dial, e.g. `"203.0.113.42:34567"`.
    pub target_external_endpoint: String,
    /// Emission wall-clock micros.
    pub timestamp_micros: i64,
}

/// Run the hole-punch subscriber task until `shutdown` flips to `true`.
///
/// Currently a placeholder: parks on a long-sleep loop so it joins the
/// rest of the joiner's background tasks with the same shutdown semantics.
/// When the SSE mechanism for `HolePunchInitiate` events lands, replace
/// the body with a stream consumer that calls
/// [`handle_holepunch_initiate`] for each parsed event.
pub async fn run(my_peer_id: Uuid, mut shutdown: watch::Receiver<bool>) {
    info!(
        peer_id = %my_peer_id,
        "holepunch: subscriber started (Stage 2 skeleton — real impl deferred)",
    );
    loop {
        // Long idle interval — this loop is here purely so the parent
        // can `join` it on graceful shutdown. We don't poll anything;
        // when the real subscriber lands it'll select! on stream + shutdown.
        tokio::select! {
            biased;
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    debug!("holepunch: shutdown signalled, exiting");
                    return;
                }
            }
            () = tokio::time::sleep(Duration::from_secs(30)) => {
                debug!(peer_id = %my_peer_id, "holepunch: stub still alive (no-op tick)");
            }
        }
    }
}

/// Stub handler for one decoded `HolePunchInitiate` event.
///
/// The real implementation will fire UDP packets here; for now we just log
/// that we received an initiate request, with enough detail (peer ids +
/// target endpoint) to verify the protocol shape end-to-end in tests.
/// Returns `true` when the event was intended for us (one of the peer
/// ids matched), `false` otherwise. Lets callers tally "events skipped"
/// for diagnostics without adding observability hooks to this stub.
pub fn handle_holepunch_initiate(
    my_peer_id: Uuid,
    event: &HolePunchInitiate,
) -> bool {
    let me = my_peer_id.to_string();
    if event.initiator_peer_id == me {
        info!(
            initiator = %event.initiator_peer_id,
            target = %event.target_peer_id,
            target_endpoint = %event.target_external_endpoint,
            timestamp_micros = event.timestamp_micros,
            "holepunch_initiate received (initiator role) — real impl deferred (Stage 2)",
        );
        true
    } else if event.target_peer_id == me {
        info!(
            initiator = %event.initiator_peer_id,
            target = %event.target_peer_id,
            timestamp_micros = event.timestamp_micros,
            "holepunch_initiate received (target role) — real impl deferred (Stage 2)",
        );
        true
    } else {
        debug!(
            initiator = %event.initiator_peer_id,
            target = %event.target_peer_id,
            "holepunch_initiate received for other peers — ignoring",
        );
        false
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn ev(initiator: Uuid, target: Uuid, endpoint: &str) -> HolePunchInitiate {
        HolePunchInitiate {
            initiator_peer_id: initiator.to_string(),
            target_peer_id: target.to_string(),
            target_external_endpoint: endpoint.into(),
            timestamp_micros: 42,
        }
    }

    #[test]
    fn handle_recognises_initiator_role() {
        let me = Uuid::from_u128(1);
        let other = Uuid::from_u128(2);
        assert!(handle_holepunch_initiate(
            me,
            &ev(me, other, "203.0.113.1:1234"),
        ));
    }

    #[test]
    fn handle_recognises_target_role() {
        let me = Uuid::from_u128(1);
        let other = Uuid::from_u128(2);
        assert!(handle_holepunch_initiate(
            me,
            &ev(other, me, "198.51.100.1:1234"),
        ));
    }

    #[test]
    fn handle_ignores_other_peers() {
        let me = Uuid::from_u128(1);
        let a = Uuid::from_u128(2);
        let b = Uuid::from_u128(3);
        assert!(!handle_holepunch_initiate(
            me,
            &ev(a, b, "203.0.113.1:1234"),
        ));
    }

    #[tokio::test]
    async fn run_exits_on_shutdown() {
        let (tx, rx) = watch::channel(false);
        let me = Uuid::from_u128(7);
        let handle = tokio::spawn(async move {
            run(me, rx).await;
        });
        tx.send(true).expect("shutdown send");
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("task exited within timeout")
            .expect("task ran to completion");
    }
}
