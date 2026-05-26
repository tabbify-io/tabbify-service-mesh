//! Background sweep that deregisters peers with stale heartbeats.
//!
//! Runs on its own tokio task; cancelled by dropping the returned
//! `JoinHandle`. Sweep cadence is one quarter of the heartbeat timeout —
//! tight enough to drop dead peers promptly, loose enough not to thrash.

use crate::roster::coordinator::Coordinator;
use std::time::{Duration, Instant};
use tokio::task::JoinHandle;
use tracing::{debug, info};

/// Spawn the timeout sweeper. Returns the task handle so callers can
/// abort it on shutdown.
#[must_use]
pub fn spawn(coordinator: Coordinator) -> JoinHandle<()> {
    let timeout = coordinator.heartbeat_timeout();
    let interval = sweep_interval(timeout);
    tokio::spawn(async move {
        info!(
            heartbeat_timeout_secs = timeout.as_secs(),
            sweep_interval_secs = interval.as_secs(),
            "peer-timeout sweeper started",
        );
        let mut ticker = tokio::time::interval(interval);
        // First tick fires immediately; skip it so we don't sweep before
        // any peer has had a chance to register.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            sweep_once(&coordinator).await;
        }
    })
}

/// One sweep pass — kept public so unit tests can drive it deterministically.
pub async fn sweep_once(coordinator: &Coordinator) {
    let now = Instant::now();
    let stale = coordinator.stale_peers(now);
    if stale.is_empty() {
        debug!("no stale peers");
        return;
    }
    for peer_id in stale {
        let removed = coordinator.deregister(peer_id, "heartbeat_timeout").await;
        if removed {
            info!(peer_id = %peer_id, "peer dropped (heartbeat timeout)");
        }
    }
}

/// Sweep cadence — one quarter of the timeout, clamped to [1s, 60s] so
/// pathologically small or large timeouts still produce a sane interval.
#[must_use]
pub fn sweep_interval(timeout: Duration) -> Duration {
    let raw = timeout / 4;
    raw.clamp(Duration::from_secs(1), Duration::from_secs(60))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::http::api::RegisterRequest;
    use crate::publisher::NoopPublisher;
    use crate::roster::coordinator::Coordinator;
    use base64::Engine;
    use std::sync::Arc;

    fn pubkey(seed: u8) -> String {
        base64::engine::general_purpose::STANDARD.encode([seed; 32])
    }

    #[tokio::test]
    async fn sweep_removes_only_stale_peers() {
        let coord = Coordinator::new(Arc::new(NoopPublisher), Duration::from_millis(50));
        let (a, _) = coord
            .register(RegisterRequest {
                wg_public_key: pubkey(1),
                listen_endpoint: None,
                wg_listen_port: None,
                display_name: "stale".into(),
                network: String::new(),
                tags: vec![],
                hosted_app_ulas: vec![],
                kind: "peer".into(),
                parent: None,
                app_uuid: None,
                requested_ula: None,
            })
            .await
            .expect("ok");
        let (b, _) = coord
            .register(RegisterRequest {
                wg_public_key: pubkey(2),
                listen_endpoint: None,
                wg_listen_port: None,
                display_name: "fresh".into(),
                network: String::new(),
                tags: vec![],
                hosted_app_ulas: vec![],
                kind: "peer".into(),
                parent: None,
                app_uuid: None,
                requested_ula: None,
            })
            .await
            .expect("ok");

        // Make `a` look stale.
        tokio::time::sleep(Duration::from_millis(80)).await;
        // Refresh `b`'s heartbeat so it survives the sweep.
        coord
            .heartbeat(b.peer_id, String::new(), None, vec![])
            .await
            .expect("heartbeat");

        sweep_once(&coord).await;
        let snap = coord.snapshot();
        assert_eq!(snap.len(), 1, "stale peer should be dropped");
        assert_eq!(snap[0].peer_id, b.peer_id.to_string());
        // Confirm `a` is gone.
        assert!(snap.iter().all(|p| p.peer_id != a.peer_id.to_string()));
    }

    #[test]
    fn sweep_interval_is_clamped() {
        assert_eq!(
            sweep_interval(Duration::from_millis(100)),
            Duration::from_secs(1),
            "small timeout floors at 1s",
        );
        assert_eq!(
            sweep_interval(Duration::from_secs(60)),
            Duration::from_secs(15),
            "60s timeout sweeps every 15s",
        );
        assert_eq!(
            sweep_interval(Duration::from_secs(3600)),
            Duration::from_secs(60),
            "huge timeout caps at 60s",
        );
    }
}
