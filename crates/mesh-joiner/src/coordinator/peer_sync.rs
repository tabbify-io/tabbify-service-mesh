//! SSE consumer for `/v1/mesh/peers/stream`.
//!
//! The coordinator pushes three event types:
//!
//! * `peer_added`   — full [`crate::peer::RemotePeer`] JSON body.
//! * `peer_updated` — full [`crate::peer::RemotePeer`] JSON body.
//! * `peer_removed` — minimal `{ "peer_id": "..." }` body.
//!
//! For `peer_added` and `peer_updated` we upsert the local session
//! table (which transparently re-handshakes when the endpoint changes).
//! For `peer_removed` we tear down the session.
//!
//! On a stream disconnect we sleep with exponential backoff and
//! reconnect. The joiner's roster stays correct in the meantime because
//! [`crate::coordinator::heartbeat`] is doing its own periodic
//! reconciliation.

use crate::coordinator::client::{CoordinatorClient, remote_to_info};
use crate::nat::holepunch::HolePunchInitiate;
use crate::peer::{PeerEventKind, PeerRemovedPayload, RemotePeer};
use crate::wg::session::SessionTable;
use eventsource_stream::Eventsource;
use futures::StreamExt;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, watch};
use uuid::Uuid;
use x25519_dalek::StaticSecret;

/// Run the SSE consumer loop until `shutdown` flips to `true`.
///
/// `peer_id` is our own coordinator-assigned id; it is passed as the
/// `?peer_id=<id>` query parameter so the coordinator ACL-filters the
/// stream to exactly the peers we are policy-permitted to see (spec §5.3
/// / decision #3 of phase 5a). Without it the coordinator would emit the
/// unfiltered admin view.
///
/// Reconnect strategy: 1s → 2s → 5s → 10s, capped at 10s.
pub async fn run(
    client: Arc<CoordinatorClient>,
    sessions: SessionTable,
    our_private: StaticSecret,
    punch_tx: Option<mpsc::UnboundedSender<HolePunchInitiate>>,
    peer_id: Uuid,
    mut shutdown: watch::Receiver<bool>,
) {
    let backoff = [1u64, 2, 5, 10];
    let mut attempt: usize = 0;

    loop {
        if *shutdown.borrow() {
            return;
        }
        let stream_result = consume_once(
            &client,
            &sessions,
            &our_private,
            punch_tx.as_ref(),
            peer_id,
            &mut shutdown,
        )
        .await;
        match stream_result {
            StreamOutcome::ShutdownRequested => return,
            StreamOutcome::EndOfStream => {
                let delay = backoff[attempt.min(backoff.len() - 1)];
                tracing::warn!(
                    delay_secs = delay,
                    "peer-stream ended cleanly; reconnecting"
                );
                if sleep_or_shutdown(Duration::from_secs(delay), &mut shutdown).await {
                    return;
                }
                attempt = attempt.saturating_add(1);
            }
            StreamOutcome::Error(e) => {
                let delay = backoff[attempt.min(backoff.len() - 1)];
                tracing::warn!(
                    error = %e,
                    delay_secs = delay,
                    "peer-stream errored; reconnecting"
                );
                if sleep_or_shutdown(Duration::from_secs(delay), &mut shutdown).await {
                    return;
                }
                attempt = attempt.saturating_add(1);
            }
        }
    }
}

/// Outcome of a single SSE connection attempt — used so the loop above
/// can branch on whether a reconnect should happen.
#[derive(Debug)]
enum StreamOutcome {
    /// Shutdown was signalled mid-stream; exit immediately.
    ShutdownRequested,
    /// Stream closed without an error (coordinator restart, etc.).
    EndOfStream,
    /// Stream produced a transport-level error.
    Error(String),
}

/// Build the SSE subscription URL, carrying our `peer_id` as a query
/// parameter so the coordinator returns an ACL-filtered stream. Pulled
/// out so the query-param contract is unit-testable without a live
/// coordinator. The id is a UUID (hyphenated hex) → no escaping needed.
fn stream_url(base_url: &str, peer_id: Uuid) -> String {
    format!("{base_url}/v1/mesh/peers/stream?peer_id={peer_id}")
}

async fn consume_once(
    client: &CoordinatorClient,
    sessions: &SessionTable,
    our_private: &StaticSecret,
    punch_tx: Option<&mpsc::UnboundedSender<HolePunchInitiate>>,
    peer_id: Uuid,
    shutdown: &mut watch::Receiver<bool>,
) -> StreamOutcome {
    let url = stream_url(client.base_url(), peer_id);
    let resp = match client
        .http()
        .get(&url)
        .header("accept", "text/event-stream")
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => return StreamOutcome::Error(format!("connect: {e}")),
    };
    if !resp.status().is_success() {
        return StreamOutcome::Error(format!("status {}", resp.status()));
    }

    let mut stream = resp.bytes_stream().eventsource();

    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    return StreamOutcome::ShutdownRequested;
                }
            }
            next = stream.next() => {
                match next {
                    None => return StreamOutcome::EndOfStream,
                    Some(Err(e)) => return StreamOutcome::Error(e.to_string()),
                    Some(Ok(ev)) => {
                        let Some(kind) = PeerEventKind::from_event_name(&ev.event) else {
                            // SSE comment / heartbeat — ignore.
                            continue;
                        };
                        apply_event(sessions, our_private, punch_tx, kind, &ev.data).await;
                    }
                }
            }
        }
    }
}

/// Apply one parsed SSE event.
///
/// Roster events (`Added`/`Updated`/`Removed`) mutate the session table.
/// A `HolePunch` event is instead forwarded verbatim to the hole-punch
/// task over `punch_tx` (when wired) — the consumer does no session work
/// for it. `punch_tx` is `None` in tests and in any build that hasn't
/// wired the punch task.
pub async fn apply_event(
    sessions: &SessionTable,
    our_private: &StaticSecret,
    punch_tx: Option<&mpsc::UnboundedSender<HolePunchInitiate>>,
    kind: PeerEventKind,
    data: &str,
) {
    match kind {
        PeerEventKind::Added | PeerEventKind::Updated => {
            let remote: RemotePeer = match serde_json::from_str(data) {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(error = %e, body = %data, "peer-stream: failed to parse RemotePeer");
                    return;
                }
            };
            let info = match remote_to_info(&remote).await {
                Ok(i) => i,
                Err(e) => {
                    tracing::warn!(error = %e, "peer-stream: malformed peer record");
                    return;
                }
            };
            tracing::info!(
                peer_id = %info.peer_id,
                ula = %info.ula,
                ?kind,
                hosted_app_ulas = ?info.hosted_app_ulas,
                "peer-stream: applying upsert"
            );
            sessions.upsert(our_private, &info);
            // Per-app-ULA routing: after the peer's session exists,
            // reconcile the app-ULAs it advertises against what we
            // currently route to it (installs new app-routes, tears down
            // dropped ones). Additive — a no-op for peers hosting no apps.
            sessions.reconcile_app_routes(info.ula, &info.hosted_app_ulas);
        }
        PeerEventKind::Removed => {
            let payload: PeerRemovedPayload = match serde_json::from_str(data) {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!(error = %e, body = %data, "peer-stream: failed to parse PeerRemovedPayload");
                    return;
                }
            };
            // We have peer_id but the session table is keyed by ULA —
            // walk all sessions to find the match. With <100 peers this
            // is fine; if it ever becomes a bottleneck we add a
            // peer_id index to SessionTable.
            let candidates: Vec<_> = sessions
                .snapshot()
                .into_iter()
                .filter(|s| s.peer_id == payload.peer_id)
                .collect();
            for s in candidates {
                tracing::info!(peer_id = %s.peer_id, ula = %s.ula, "peer-stream: removing peer");
                sessions.remove(s.ula);
            }
        }
        PeerEventKind::HolePunch => {
            let Some(tx) = punch_tx else {
                // No punch task wired (tests / Stage-1-only build) — drop.
                return;
            };
            match serde_json::from_str::<HolePunchInitiate>(data) {
                Ok(ev) => {
                    tracing::info!(
                        initiator = %ev.initiator_peer_id,
                        target = %ev.target_peer_id,
                        target_endpoint = %ev.target_external_endpoint,
                        "peer-stream: forwarding hole-punch to punch task"
                    );
                    // Best-effort: if the punch task has gone away, drop it.
                    let _ = tx.send(ev);
                }
                Err(e) => {
                    tracing::warn!(error = %e, body = %data, "peer-stream: bad holepunch json");
                }
            }
        }
    }
    // `our_private` is used by the upsert paths above; explicitly
    // ignore the parameter on the `Removed` arm so clippy doesn't
    // complain about the dead use.
    let _ = our_private;
}

/// Sleep for `dur` unless `shutdown` fires first. Returns `true` if
/// shutdown was requested.
async fn sleep_or_shutdown(dur: Duration, shutdown: &mut watch::Receiver<bool>) -> bool {
    tokio::select! {
        () = tokio::time::sleep(dur) => false,
        _ = shutdown.changed() => *shutdown.borrow(),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::peer::RemotePeer;
    use base64::engine::{Engine as _, general_purpose::STANDARD as B64};
    use std::net::Ipv6Addr;
    use uuid::Uuid;
    use x25519_dalek::PublicKey;

    fn pubkey_b64(n: u8) -> String {
        let secret = StaticSecret::from([n; 32]);
        let public = PublicKey::from(&secret);
        B64.encode(public.as_bytes())
    }

    fn remote_json(ula: &str, n: u8) -> String {
        serde_json::to_string(&RemotePeer {
            peer_id: Uuid::parse_str("01910f10-0000-7000-8000-000000000001").unwrap(),
            wg_public_key: pubkey_b64(n),
            ula: ula.into(),
            listen_endpoint: Some("127.0.0.1:51820".into()),
            display_name: format!("peer-{n}"),
            tags: vec![],
            hosted_app_ulas: vec![],
            software_version: None,
            joined_at_micros: 0,
        })
        .unwrap()
    }

    #[tokio::test]
    async fn apply_added_inserts_session() {
        let sessions = SessionTable::new();
        let me = StaticSecret::from([0xAA; 32]);
        apply_event(
            &sessions,
            &me,
            None,
            PeerEventKind::Added,
            &remote_json("fd5a:1f00:1::1", 1),
        )
        .await;
        assert!(
            sessions
                .by_ula("fd5a:1f00:1::1".parse::<Ipv6Addr>().unwrap())
                .is_some()
        );
    }

    #[tokio::test]
    async fn apply_updated_overwrites_existing_session() {
        let sessions = SessionTable::new();
        let me = StaticSecret::from([0xAA; 32]);
        // Initial add.
        apply_event(
            &sessions,
            &me,
            None,
            PeerEventKind::Added,
            &remote_json("fd5a:1f00:1::1", 1),
        )
        .await;
        // Updated record — same ULA, different pubkey number — endpoint
        // index should be replaced cleanly.
        let mut updated: RemotePeer =
            serde_json::from_str(&remote_json("fd5a:1f00:1::1", 1)).unwrap();
        updated.listen_endpoint = Some("10.0.0.5:51820".into());
        apply_event(
            &sessions,
            &me,
            None,
            PeerEventKind::Updated,
            &serde_json::to_string(&updated).unwrap(),
        )
        .await;
        assert!(
            sessions
                .by_endpoint("127.0.0.1:51820".parse().unwrap())
                .is_none()
        );
        assert!(
            sessions
                .by_endpoint("10.0.0.5:51820".parse().unwrap())
                .is_some()
        );
    }

    #[tokio::test]
    async fn apply_removed_drops_matching_session() {
        let sessions = SessionTable::new();
        let me = StaticSecret::from([0xAA; 32]);
        let json = remote_json("fd5a:1f00:1::1", 1);
        let parsed: RemotePeer = serde_json::from_str(&json).unwrap();
        apply_event(&sessions, &me, None, PeerEventKind::Added, &json).await;
        assert_eq!(sessions.len(), 1);
        let removed_payload = serde_json::json!({ "peer_id": parsed.peer_id }).to_string();
        apply_event(
            &sessions,
            &me,
            None,
            PeerEventKind::Removed,
            &removed_payload,
        )
        .await;
        assert!(sessions.is_empty());
    }

    /// Malformed `peer_added` JSON must log + skip without panicking.
    #[tokio::test]
    async fn apply_event_swallows_bad_json() {
        let sessions = SessionTable::new();
        let me = StaticSecret::from([0xAA; 32]);
        apply_event(&sessions, &me, None, PeerEventKind::Added, "not json").await;
        assert!(sessions.is_empty());
    }

    /// A `holepunch_initiate` frame must be parsed and forwarded to the
    /// punch task's channel verbatim — the SSE consumer itself does no
    /// session work for it (that's the punch task's job).
    #[tokio::test]
    async fn apply_holepunch_forwards_to_channel() {
        let sessions = SessionTable::new();
        let me = StaticSecret::from([0xAA; 32]);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let body = serde_json::to_string(&crate::nat::holepunch::HolePunchInitiate {
            initiator_peer_id: "aaaaaaaa-0000-7000-8000-000000000001".into(),
            target_peer_id: "bbbbbbbb-0000-7000-8000-000000000002".into(),
            target_external_endpoint: "203.0.113.1:51820".into(),
            timestamp_micros: 7,
        })
        .unwrap();
        apply_event(&sessions, &me, Some(&tx), PeerEventKind::HolePunch, &body).await;
        let received = rx.try_recv().expect("event forwarded to punch task");
        assert_eq!(received.target_external_endpoint, "203.0.113.1:51820");
        assert_eq!(received.timestamp_micros, 7);
        // The session table is untouched by a hole-punch frame.
        assert!(sessions.is_empty());
    }

    /// Malformed hole-punch JSON must be swallowed (log + skip), not
    /// forwarded, and must never panic the consumer loop.
    #[tokio::test]
    async fn apply_holepunch_swallows_bad_json() {
        let sessions = SessionTable::new();
        let me = StaticSecret::from([0xAA; 32]);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        apply_event(
            &sessions,
            &me,
            Some(&tx),
            PeerEventKind::HolePunch,
            "not json",
        )
        .await;
        assert!(rx.try_recv().is_err(), "nothing forwarded on bad json");
    }

    /// Sanity: `PeerEventKind` ↔ event-name parsing round-trips for all
    /// three names.
    #[test]
    fn event_kind_names_round_trip() {
        for name in ["peer_added", "peer_updated", "peer_removed"] {
            assert!(PeerEventKind::from_event_name(name).is_some(), "{name}");
        }
    }

    /// spec §5.3 / 5a #3: the SSE subscription URL must carry our own
    /// `peer_id` so the coordinator returns an ACL-filtered stream. The
    /// query parameter name must be exactly `peer_id` (the coordinator's
    /// `StreamQuery` field) or filtering silently degrades to the
    /// unfiltered admin view.
    #[test]
    fn stream_url_includes_peer_id_query_param() {
        let id = Uuid::parse_str("01910f10-0000-7000-8000-000000000001").unwrap();
        let url = stream_url("http://127.0.0.1:8888", id);
        assert_eq!(
            url,
            "http://127.0.0.1:8888/v1/mesh/peers/stream?peer_id=01910f10-0000-7000-8000-000000000001"
        );
        // Belt-and-braces: the path and the exact param key are present.
        assert!(url.contains("/v1/mesh/peers/stream"));
        assert!(url.contains("?peer_id="));
        assert!(url.ends_with(&id.to_string()));
    }

    // ---- per-app-ULA routing: roster consumer install / remove ----
    //
    // These drive `apply_event` with roster frames that carry
    // `hosted_app_ulas` and assert the SESSION TABLE (with a recording
    // route sink) ends up with the right app-routes — adds on advertise,
    // removals on a shrunk set. A FAKE sink is used so the tests never
    // shell out to real `route` / `ifconfig`.

    use crate::wg::session::RouteSink;
    use parking_lot::Mutex as PlMutex;
    use std::sync::Arc;

    /// Recording route sink — captures app-route installs / removals so a
    /// roster-driven test can assert the kernel WOULD see the right /128s
    /// without shelling out.
    #[derive(Default)]
    struct RecordingSink {
        app_added: PlMutex<Vec<Ipv6Addr>>,
        app_removed: PlMutex<Vec<Ipv6Addr>>,
    }
    impl RouteSink for RecordingSink {
        fn add_allowed(&self, _ula: Ipv6Addr) {}
        fn remove_allowed(&self, _ula: Ipv6Addr) {}
        fn add_app_route(&self, app_ula: Ipv6Addr) {
            self.app_added.lock().push(app_ula);
        }
        fn remove_app_route(&self, app_ula: Ipv6Addr) {
            self.app_removed.lock().push(app_ula);
        }
    }

    /// A `RemotePeer` JSON body that ALSO advertises hosted app-ULAs.
    fn remote_json_hosting(ula: &str, n: u8, hosted: &[&str]) -> String {
        serde_json::to_string(&RemotePeer {
            peer_id: Uuid::parse_str("01910f10-0000-7000-8000-000000000001").unwrap(),
            wg_public_key: pubkey_b64(n),
            ula: ula.into(),
            listen_endpoint: Some("127.0.0.1:51820".into()),
            display_name: format!("peer-{n}"),
            tags: vec![],
            hosted_app_ulas: hosted.iter().map(|s| (*s).to_owned()).collect(),
            software_version: None,
            joined_at_micros: 0,
        })
        .unwrap()
    }

    const APP_X: &str = "fd5a:1f02:dead:beef:cafe:0:0:1";
    const APP_Y: &str = "fd5a:1f02:dead:beef:cafe:0:0:2";
    const HOST: &str = "fd5a:1f00:1::1";

    fn ula6(s: &str) -> Ipv6Addr {
        s.parse().unwrap()
    }

    /// A `peer_added` advertising hosted app-ULAs installs an app-route
    /// per app-ULA: the session table resolves each to the host, the
    /// host's allowed-set grows, and the route sink fires.
    #[tokio::test]
    async fn apply_added_with_hosted_app_ulas_installs_routes() {
        let sink = Arc::new(RecordingSink::default());
        let sessions = SessionTable::with_route_sink(sink.clone());
        let me = StaticSecret::from([0xAA; 32]);
        apply_event(
            &sessions,
            &me,
            None,
            PeerEventKind::Added,
            &remote_json_hosting(HOST, 1, &[APP_X, APP_Y]),
        )
        .await;
        // Both app-ULAs resolve to the host's session.
        assert_eq!(
            sessions.by_ula(ula6(APP_X)).map(|s| s.ula),
            Some(ula6(HOST))
        );
        assert_eq!(
            sessions.by_ula(ula6(APP_Y)).map(|s| s.ula),
            Some(ula6(HOST))
        );
        // The host session's allowed-set grew to include both.
        let host_session = sessions.by_ula(ula6(HOST)).expect("host session");
        assert!(host_session.is_allowed_source(ula6(APP_X)));
        assert!(host_session.is_allowed_source(ula6(APP_Y)));
        // The route sink installed both app /128s.
        let mut added = sink.app_added.lock().clone();
        added.sort();
        let mut expected = vec![ula6(APP_X), ula6(APP_Y)];
        expected.sort();
        assert_eq!(added, expected);
    }

    /// A `peer_updated` with a SHRUNK hosted set tears down the dropped
    /// app-ULA (reverse of install) while keeping the surviving one.
    #[tokio::test]
    async fn apply_updated_with_shrunk_hosted_set_removes_dropped_route() {
        let sink = Arc::new(RecordingSink::default());
        let sessions = SessionTable::with_route_sink(sink.clone());
        let me = StaticSecret::from([0xAA; 32]);
        // First advertise both X and Y.
        apply_event(
            &sessions,
            &me,
            None,
            PeerEventKind::Added,
            &remote_json_hosting(HOST, 1, &[APP_X, APP_Y]),
        )
        .await;
        // Now an update drops Y, keeps X.
        apply_event(
            &sessions,
            &me,
            None,
            PeerEventKind::Updated,
            &remote_json_hosting(HOST, 1, &[APP_X]),
        )
        .await;
        // X still routes; Y no longer does.
        assert_eq!(
            sessions.by_ula(ula6(APP_X)).map(|s| s.ula),
            Some(ula6(HOST))
        );
        assert!(sessions.by_ula(ula6(APP_Y)).is_none());
        // The dropped app /128 was removed from the kernel.
        assert_eq!(*sink.app_removed.lock(), vec![ula6(APP_Y)]);
        // And the host's allowed-set no longer accepts Y.
        let host_session = sessions.by_ula(ula6(HOST)).expect("host session");
        assert!(host_session.is_allowed_source(ula6(APP_X)));
        assert!(!host_session.is_allowed_source(ula6(APP_Y)));
    }

    /// `peer_removed` for the host tears down ALL its app-routes (the host
    /// is gone, so every app it served is unreachable through it).
    #[tokio::test]
    async fn apply_removed_host_tears_down_all_its_app_routes() {
        let sink = Arc::new(RecordingSink::default());
        let sessions = SessionTable::with_route_sink(sink.clone());
        let me = StaticSecret::from([0xAA; 32]);
        let added = remote_json_hosting(HOST, 1, &[APP_X, APP_Y]);
        let parsed: RemotePeer = serde_json::from_str(&added).unwrap();
        apply_event(&sessions, &me, None, PeerEventKind::Added, &added).await;
        assert_eq!(sessions.app_ulas_for_host(ula6(HOST)).len(), 2);

        let removed_payload = serde_json::json!({ "peer_id": parsed.peer_id }).to_string();
        apply_event(
            &sessions,
            &me,
            None,
            PeerEventKind::Removed,
            &removed_payload,
        )
        .await;
        // Host gone → neither app-ULA resolves.
        assert!(sessions.by_ula(ula6(APP_X)).is_none());
        assert!(sessions.by_ula(ula6(APP_Y)).is_none());
        let mut app_removed = sink.app_removed.lock().clone();
        app_removed.sort();
        let mut expected = vec![ula6(APP_X), ula6(APP_Y)];
        expected.sort();
        assert_eq!(app_removed, expected);
    }

    /// A peer-only `peer_added` (no hosted apps) installs ZERO app-routes
    /// — the additive contract: the app path is dormant for normal peers.
    #[tokio::test]
    async fn apply_added_without_hosted_apps_installs_no_app_routes() {
        let sink = Arc::new(RecordingSink::default());
        let sessions = SessionTable::with_route_sink(sink.clone());
        let me = StaticSecret::from([0xAA; 32]);
        apply_event(
            &sessions,
            &me,
            None,
            PeerEventKind::Added,
            &remote_json(HOST, 1),
        )
        .await;
        assert!(
            sink.app_added.lock().is_empty(),
            "no app routes for a plain peer"
        );
        assert_eq!(sessions.len(), 1);
    }
}
