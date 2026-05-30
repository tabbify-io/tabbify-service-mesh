//! Periodic heartbeat task.
//!
//! Spawned by [`crate::joiner::Joiner::join`] once registration
//! succeeds. The task:
//!
//! 1. Sleeps for `interval`.
//! 2. Calls [`crate::coordinator::client::CoordinatorClient::heartbeat`].
//! 3. Reconciles the returned roster against the local session table —
//!    insertions cover sessions that we missed via SSE, deletions cover
//!    peers the coordinator timed out. This is the "self-heal" path
//!    that lets the joiner stay correct even if the SSE stream is
//!    flaky.
//! 4. Loops.
//!
//! Cancellation comes through a `tokio_util::sync::CancellationToken`
//! style channel — we use a plain `tokio::sync::watch` to avoid pulling
//! `tokio-util` just for one token.

use crate::coordinator::client::{CoordinatorClient, remote_to_info};
use crate::wg::session::SessionTable;
use dashmap::DashMap;
use std::collections::HashSet;
use std::net::Ipv6Addr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use uuid::Uuid;
use x25519_dalek::StaticSecret;

/// Snapshot the locally-hosted app-ULA set into the wire form
/// (`Vec<String>` of IPv6 literals) the heartbeat advertises. Sorted for
/// deterministic ordering (stable change-detection on the coordinator).
fn hosted_app_ula_strings(hosted: &DashMap<Ipv6Addr, ()>) -> Vec<String> {
    let mut v: Vec<String> = hosted.iter().map(|kv| kv.key().to_string()).collect();
    v.sort();
    v
}

/// Inputs to the heartbeat loop. Bundled into one struct so [`run`]
/// stays under the clippy argument-count cap without an `allow` — same
/// pattern as the joiner's `SpawnContext`.
pub struct HeartbeatTask {
    /// Coordinator HTTP client.
    pub client: Arc<CoordinatorClient>,
    /// Shared session table (reconciled against each heartbeat roster).
    pub sessions: SessionTable,
    /// Our X25519 private key — needed to (re)build peer sessions on
    /// reconcile.
    pub our_private: StaticSecret,
    /// Our coordinator-assigned peer id.
    pub peer_id: Uuid,
    /// Our `WireGuard` UDP listen port — re-sent for reflexive refresh.
    pub wg_listen_port: u16,
    /// App-ULAs this node hosts — advertised on every heartbeat
    /// (per-app-ULA routing). Shared with [`crate::Joiner`].
    pub hosted_app_ulas: Arc<DashMap<Ipv6Addr, ()>>,
    /// Software version advertised on every heartbeat (spec P0 OBSERVE).
    /// Host-supplied; `None` = unknown.
    pub software_version: Option<String>,
    /// Heartbeat interval.
    pub interval: Duration,
    /// Cancellation signal.
    pub shutdown: watch::Receiver<bool>,
}

/// Run the heartbeat loop until `shutdown` flips to `true`.
///
/// Designed to be spawned with `tokio::spawn(run(task))` — does not
/// return until cancelled.
pub async fn run(task: HeartbeatTask) {
    let HeartbeatTask {
        client,
        sessions,
        our_private,
        peer_id,
        wg_listen_port,
        hosted_app_ulas,
        software_version,
        interval,
        mut shutdown,
    } = task;
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Skip the immediate first tick — the initial roster was already
    // installed from the register response.
    ticker.tick().await;

    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    tracing::debug!(
                        peer_id = %peer_id,
                        "heartbeat: shutdown signalled, exiting"
                    );
                    return;
                }
            }
            _ = ticker.tick() => {
                tick_once(
                    &client,
                    &sessions,
                    &our_private,
                    peer_id,
                    wg_listen_port,
                    &hosted_app_ulas,
                    software_version.clone(),
                )
                .await;
            }
        }
    }
}

/// One heartbeat round-trip + roster reconciliation. Pulled out so unit
/// tests can drive it without waiting on a real ticker.
///
/// `wg_listen_port` is re-sent so the coordinator can refresh our
/// reflexive endpoint if our observed public IP changed.
///
/// `software_version` is re-sent so the control plane observes the host's
/// `actual` version (spec P0). `None` = unknown — the coordinator leaves
/// its stored value untouched.
pub async fn tick_once(
    client: &CoordinatorClient,
    sessions: &SessionTable,
    our_private: &StaticSecret,
    peer_id: Uuid,
    wg_listen_port: u16,
    hosted_app_ulas: &DashMap<Ipv6Addr, ()>,
    software_version: Option<String>,
) {
    // Advertise our CURRENT hosted app-ULA set so the coordinator replaces
    // its stored set (per-app-ULA routing — supervisor side).
    let hosted = hosted_app_ula_strings(hosted_app_ulas);
    match client
        .heartbeat(peer_id, Some(wg_listen_port), &hosted, software_version)
        .await
    {
        Ok(resp) => reconcile_roster(sessions, our_private, &resp.peers).await,
        Err(e) => {
            tracing::warn!(
                peer_id = %peer_id,
                error = %e,
                "heartbeat failed — will retry on next tick"
            );
        }
    }
}

/// Compute the (insert, delete) deltas between the local session table
/// and the coordinator's roster, then apply them.
///
/// Peers with malformed records are logged and skipped — the joiner
/// keeps running on its last-good view rather than dropping every
/// session over one bad peer.
async fn reconcile_roster(
    sessions: &SessionTable,
    our_private: &StaticSecret,
    remote: &[crate::peer::RemotePeer],
) {
    let mut remote_ulas: HashSet<std::net::Ipv6Addr> = HashSet::new();
    for r in remote {
        match remote_to_info(r).await {
            Ok(info) => {
                remote_ulas.insert(info.ula);
                // upsert is a no-op for unchanged endpoints (well — it
                // re-handshakes; we accept that cost for simplicity in
                // MVP). Future work: skip when (peer_id, endpoint,
                // pubkey) match.
                sessions.upsert(our_private, &info);
                // Per-app-ULA routing self-heal: reconcile the peer's
                // advertised app-ULAs even if the SSE stream missed a
                // frame. Same wholesale-replace semantics as peer_sync.
                sessions.reconcile_app_routes(info.ula, &info.hosted_app_ulas);
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "heartbeat: skipping malformed peer record"
                );
            }
        }
    }
    // Anyone in the local table but absent from the coordinator's
    // roster has been timed out or deregistered behind our back.
    for ula in sessions.ulas() {
        if !remote_ulas.contains(&ula) {
            tracing::debug!(%ula, "heartbeat: pruning timed-out peer");
            sessions.remove(ula);
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::peer::{PeerInfo, RemotePeer};
    use base64::engine::{Engine as _, general_purpose::STANDARD as B64};
    use std::net::Ipv6Addr;
    use x25519_dalek::PublicKey;

    fn pubkey_b64(n: u8) -> String {
        let secret = StaticSecret::from([n; 32]);
        let public = PublicKey::from(&secret);
        B64.encode(public.as_bytes())
    }

    fn remote(ula: &str, n: u8) -> RemotePeer {
        RemotePeer {
            peer_id: Uuid::nil(),
            wg_public_key: pubkey_b64(n),
            ula: ula.into(),
            listen_endpoint: Some("127.0.0.1:51820".into()),
            display_name: format!("peer-{n}"),
            tags: vec![],
            hosted_app_ulas: vec![],
            software_version: None,
            joined_at_micros: 0,
        }
    }

    fn local_info(ula: &str, n: u8) -> PeerInfo {
        let secret = StaticSecret::from([n; 32]);
        PeerInfo {
            peer_id: Uuid::nil(),
            wg_public_key: *PublicKey::from(&secret).as_bytes(),
            ula: ula.parse().unwrap(),
            // Distinct port per peer keeps the endpoint index unique
            // across the test population without burning real OS ports.
            listen_endpoint: Some(
                format!("127.0.0.1:{}", 30_000 + u16::from(n))
                    .parse()
                    .unwrap(),
            ),
            display_name: format!("peer-{n}"),
            tags: vec![],
            hosted_app_ulas: vec![],
            software_version: None,
            joined_at_micros: 0,
        }
    }

    /// `reconcile_roster` must add peers that the coordinator advertises
    /// but we don't have locally.
    #[tokio::test]
    async fn reconcile_adds_new_peers() {
        let sessions = SessionTable::new();
        let me = StaticSecret::from([0xAA; 32]);
        let remote = vec![remote("fd5a:1f00:1::1", 1), remote("fd5a:1f00:1::2", 2)];
        reconcile_roster(&sessions, &me, &remote).await;
        assert!(
            sessions
                .by_ula("fd5a:1f00:1::1".parse::<Ipv6Addr>().unwrap())
                .is_some()
        );
        assert!(
            sessions
                .by_ula("fd5a:1f00:1::2".parse::<Ipv6Addr>().unwrap())
                .is_some()
        );
        assert_eq!(sessions.len(), 2);
    }

    /// `reconcile_roster` must drop local peers that aren't in the
    /// coordinator's response — that's how timeouts get cleaned up.
    #[tokio::test]
    async fn reconcile_prunes_local_peers_absent_from_response() {
        let sessions = SessionTable::new();
        let me = StaticSecret::from([0xAA; 32]);
        sessions.upsert(&me, &local_info("fd5a:1f00:1::1", 1));
        sessions.upsert(&me, &local_info("fd5a:1f00:1::2", 2));
        // The coordinator only knows about ::1 now — ::2 should be
        // pruned.
        reconcile_roster(&sessions, &me, &[remote("fd5a:1f00:1::1", 1)]).await;
        assert!(
            sessions
                .by_ula("fd5a:1f00:1::1".parse::<Ipv6Addr>().unwrap())
                .is_some()
        );
        assert!(
            sessions
                .by_ula("fd5a:1f00:1::2".parse::<Ipv6Addr>().unwrap())
                .is_none()
        );
    }

    /// A malformed peer record should be skipped, not crash the
    /// reconciliation. Good peers in the same batch still apply.
    #[tokio::test]
    async fn reconcile_skips_malformed_records() {
        let sessions = SessionTable::new();
        let me = StaticSecret::from([0xAA; 32]);
        let mut bad = remote("oops-not-ipv6", 1);
        bad.ula = "not-an-ipv6".into();
        let good = remote("fd5a:1f00:1::5", 5);
        reconcile_roster(&sessions, &me, &[bad, good]).await;
        assert!(
            sessions
                .by_ula("fd5a:1f00:1::5".parse::<Ipv6Addr>().unwrap())
                .is_some()
        );
        assert_eq!(sessions.len(), 1);
    }
}
