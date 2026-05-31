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

use crate::coordinator::heartbeat::SharedPeerId;
use crate::wg::session::{PeerSession, SessionTable, WgAction, classify_tunn_result};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};
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

/// Buffer for a single handshake-initiation. A `WireGuard` handshake-init is
/// 148 bytes; 256 leaves margin without allocating a full MTU frame on
/// every burst packet.
const HANDSHAKE_BUF_LEN: usize = 256;

/// How many handshake-initiations to fire per punch, and the gap between
/// them. A short burst covers the race where our first packet reaches the
/// peer's NAT before it has punched back; once any pair crosses, the
/// session is up and boringtun's own rekey timer keeps it alive.
const PUNCH_BURST: usize = 5;
const PUNCH_INTERVAL: Duration = Duration::from_millis(300);

/// A resolved punch action: which peer session to drive, and the external
/// endpoint to fire handshake-initiations at.
#[derive(Debug, Clone)]
pub struct PunchPlan {
    /// The target peer's session (its `Tunn` + routing metadata).
    pub session: Arc<PeerSession>,
    /// The reflexive endpoint to dial.
    pub endpoint: SocketAddr,
}

/// Decide whether and where to punch for one `HolePunchInitiate`.
///
/// Returns `Some` only when ALL hold: we are the named initiator, the
/// target endpoint parses, and we already have a session for the target
/// peer (built from the roster). Otherwise `None` — we either aren't the
/// one to fire (we'll get our own initiator-side event from the swapped
/// pair) or have nothing to fire at yet.
#[must_use]
pub fn plan_punch(
    sessions: &SessionTable,
    my_peer_id: Uuid,
    event: &HolePunchInitiate,
) -> Option<PunchPlan> {
    if event.initiator_peer_id != my_peer_id.to_string() {
        return None;
    }
    let endpoint: SocketAddr = event.target_external_endpoint.parse().ok()?;
    let target_id = Uuid::parse_str(&event.target_peer_id).ok()?;
    let session = sessions
        .snapshot()
        .into_iter()
        .find(|s| s.peer_id == target_id)?;
    Some(PunchPlan { session, endpoint })
}

/// Force a fresh `WireGuard` handshake-initiation for `session` and return
/// the datagram to send. `force_resend = true` so a burst actually emits
/// repeated inits (boringtun would otherwise suppress one sent recently).
/// `None` if boringtun produced nothing to send.
async fn build_handshake_packet(session: &Arc<PeerSession>) -> Option<Vec<u8>> {
    let mut out = vec![0u8; HANDSHAKE_BUF_LEN];
    let mut tunn = session.tunn.lock().await;
    match classify_tunn_result(tunn.format_handshake_initiation(&mut out, true)) {
        WgAction::SendToPeer(bytes) => Some(bytes),
        _ => None,
    }
}

/// Execute a planned punch.
///
/// Repoints the session's outbound endpoint at the reflexive target, then
/// fires a short burst of handshake-initiations so our `NAT` mapping opens
/// and crosses with the peer's simultaneous burst.
pub async fn execute_punch(socket: &UdpSocket, plan: &PunchPlan, burst: usize, interval: Duration) {
    // Adopt the coordinator-provided reflexive endpoint as the outbound
    // default — it is authoritative (same source as an advertised endpoint).
    *plan.session.endpoint.write() = Some(plan.endpoint);
    for i in 0..burst {
        if let Some(bytes) = build_handshake_packet(&plan.session).await {
            if let Err(e) = socket.send_to(&bytes, plan.endpoint).await {
                tracing::warn!(error = %e, endpoint = %plan.endpoint, "holepunch: send failed");
            } else {
                // Re-peer observability: a WireGuard handshake-init just left
                // the wire toward the target's reflexive endpoint as part of
                // the NAT hole-punch burst. Same (peer_id, ula, endpoint,
                // event) shape as the roster + completion events so the punch
                // burst is traceable in Loki between the `holepunch_directive`
                // and a later `session_established`.
                tracing::info!(
                    peer_id = %plan.session.peer_id,
                    ula = %plan.session.ula,
                    endpoint = %plan.endpoint,
                    event = "handshake_init",
                    "holepunch: fired handshake-init"
                );
            }
        }
        if i + 1 < burst {
            tokio::time::sleep(interval).await;
        }
    }
}

/// Run the hole-punch task until `shutdown` flips or the punch channel
/// closes.
///
/// Consumes `HolePunchInitiate` events forwarded by the SSE consumer. For
/// each event where we are the initiator (and have a session for the
/// target), it fires a short burst of handshake-initiations at the
/// target's reflexive endpoint — opening our NAT mapping so the peer's
/// simultaneous burst crosses and the `WireGuard` session establishes. The
/// coordinator emits a swapped pair, so the other side punches back at us.
///
/// `my_peer_id` is the LIVE, shared peer id ([`SharedPeerId`]) — the SAME
/// handle the heartbeat + SSE tasks observe. A coordinator roster loss
/// (404 on heartbeat) makes the heartbeat task re-register and adopt a NEW
/// id, after which the coordinator keys hole-punch events to that new id.
/// We therefore read the current id from the shared handle on EVERY event
/// rather than capturing it once at spawn, so post-recovery punches keep
/// firing instead of silently filtering against a dead id. The guard is
/// read into a local `Uuid` and dropped before any `.await` so it is never
/// held across the punch I/O.
pub async fn run(
    my_peer_id: SharedPeerId,
    socket: Arc<UdpSocket>,
    sessions: SessionTable,
    mut punch_rx: mpsc::UnboundedReceiver<HolePunchInitiate>,
    mut shutdown: watch::Receiver<bool>,
) {
    // Read the id into a local first: holding the lock guard across the
    // tracing macro's await would make this future non-Send (the guard
    // isn't Sync) — same constraint the heartbeat task observes.
    let started_id = *my_peer_id.read().await;
    info!(peer_id = %started_id, "holepunch: subscriber started");
    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    debug!("holepunch: shutdown signalled, exiting");
                    return;
                }
            }
            maybe = punch_rx.recv() => {
                let Some(event) = maybe else {
                    debug!("holepunch: punch channel closed, exiting");
                    return;
                };
                // Read the LIVE id per event: a 404 re-register may have
                // swapped it since spawn. Clone the Uuid out and drop the
                // guard before any punch I/O (never hold the lock across an
                // .await).
                let current_id = *my_peer_id.read().await;
                match plan_punch(&sessions, current_id, &event) {
                    Some(plan) => {
                        info!(
                            target = %event.target_peer_id,
                            endpoint = %plan.endpoint,
                            "holepunch: punching",
                        );
                        execute_punch(&socket, &plan, PUNCH_BURST, PUNCH_INTERVAL).await;
                    }
                    None => {
                        debug!(
                            initiator = %event.initiator_peer_id,
                            target = %event.target_peer_id,
                            "holepunch: skip (not initiator / no session / bad endpoint)",
                        );
                    }
                }
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::coordinator::heartbeat::SharedPeerId;
    use crate::peer::PeerInfo;
    use crate::wg::session::SessionTable;
    use std::sync::Arc;
    use tokio::net::UdpSocket;
    use x25519_dalek::{PublicKey, StaticSecret};

    /// Build a session table holding exactly one peer session keyed by
    /// `peer_id`, so `plan_punch` has something to find.
    fn session_table_with(peer_id: Uuid, ula: &str, endpoint: Option<&str>) -> SessionTable {
        let t = SessionTable::new();
        let me = StaticSecret::from([7u8; 32]);
        let peer_pub = *PublicKey::from(&StaticSecret::from([9u8; 32])).as_bytes();
        let info = PeerInfo {
            peer_id,
            wg_public_key: peer_pub,
            ula: ula.parse().expect("ula"),
            listen_endpoint: endpoint.map(|s| s.parse().expect("endpoint")),
            display_name: "target".into(),
            tags: vec![],
            hosted_app_ulas: vec![],
            software_version: None,
            joined_at_micros: 0,
        };
        t.upsert(&me, &info);
        t
    }

    /// When we are the initiator and have a session for the target, the
    /// plan points at the event's external endpoint and that peer's session.
    #[test]
    fn plan_punch_targets_session_when_we_are_initiator() {
        let me = Uuid::from_u128(1);
        let target = Uuid::from_u128(2);
        let sessions = session_table_with(target, "fd5a:1f00:1::2", Some("198.51.100.2:51820"));
        let plan = plan_punch(&sessions, me, &ev(me, target, "203.0.113.2:40000")).expect("a plan");
        assert_eq!(plan.endpoint, "203.0.113.2:40000".parse().expect("addr"));
        assert_eq!(plan.session.peer_id, target);
    }

    /// We only fire when WE are the initiator. An event whose initiator is
    /// some other peer (we'd be the target) yields no plan — we'll get our
    /// own initiator-side event from the coordinator's swapped pair.
    #[test]
    fn plan_punch_skips_when_not_initiator() {
        let me = Uuid::from_u128(1);
        let other = Uuid::from_u128(2);
        let target = Uuid::from_u128(3);
        let sessions = session_table_with(target, "fd5a:1f00:1::3", None);
        assert!(plan_punch(&sessions, me, &ev(other, target, "203.0.113.3:1")).is_none());
    }

    /// No session for the named target → nothing to punch (roster hasn't
    /// caught up yet); skip rather than fabricate a session.
    #[test]
    fn plan_punch_skips_when_no_session_for_target() {
        let me = Uuid::from_u128(1);
        let target = Uuid::from_u128(2);
        let sessions = SessionTable::new();
        assert!(plan_punch(&sessions, me, &ev(me, target, "203.0.113.2:1")).is_none());
    }

    /// A malformed external endpoint string must be skipped, not panic.
    #[test]
    fn plan_punch_skips_on_unparseable_endpoint() {
        let me = Uuid::from_u128(1);
        let target = Uuid::from_u128(2);
        let sessions = session_table_with(target, "fd5a:1f00:1::2", None);
        assert!(plan_punch(&sessions, me, &ev(me, target, "not-an-addr")).is_none());
    }

    /// Executing a plan must (a) repoint the session's outbound endpoint
    /// at the reflexive target and (b) actually emit a `WireGuard`
    /// handshake-initiation datagram to that endpoint — that datagram is
    /// the "punch" that opens our NAT mapping.
    #[tokio::test]
    async fn execute_punch_sends_handshake_init_to_endpoint() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.expect("bind recv");
        let target_addr = receiver.local_addr().expect("recv addr");
        let sender = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("bind send"));

        let me = Uuid::from_u128(1);
        let target = Uuid::from_u128(2);
        let sessions = session_table_with(target, "fd5a:1f00:1::2", None);
        let plan =
            plan_punch(&sessions, me, &ev(me, target, &target_addr.to_string())).expect("a plan");

        execute_punch(&sender, &plan, 2, Duration::from_millis(1)).await;

        let mut buf = [0u8; 256];
        let (n, _from) = tokio::time::timeout(Duration::from_secs(1), receiver.recv_from(&mut buf))
            .await
            .expect("a datagram within timeout")
            .expect("recv ok");
        assert!(n >= 148, "WireGuard handshake-init is 148 bytes, got {n}");
        assert_eq!(
            buf[0], 1,
            "first byte is the WG handshake-init message type"
        );
        // The session now targets the reflexive endpoint for outbound.
        assert_eq!(plan.session.endpoint(), Some(target_addr));
    }

    fn ev(initiator: Uuid, target: Uuid, endpoint: &str) -> HolePunchInitiate {
        HolePunchInitiate {
            initiator_peer_id: initiator.to_string(),
            target_peer_id: target.to_string(),
            target_external_endpoint: endpoint.into(),
            timestamp_micros: 42,
        }
    }

    /// Wrap a fixed id in the shared handle the punch task now reads.
    fn shared(id: Uuid) -> SharedPeerId {
        Arc::new(tokio::sync::RwLock::new(id))
    }

    /// Regression for the 404-re-register hole-punch gap: after the shared
    /// peer id is swapped (as the heartbeat task does on a 404), the punch
    /// task must filter initiate events against the LIVE id, not the one it
    /// saw at spawn.
    ///
    /// Two phases, ordered so the swap is observably AFTER the task is
    /// running (no spawn-time read race):
    ///
    /// 1. With the OLD id live, an initiate keyed to OLD punches — proving
    ///    the task is up and reading the shared handle per event.
    /// 2. We then swap the shared handle to a NEW id (the 404 recovery) and
    ///    send an initiate keyed to the NEW id. It MUST punch too. Under the
    ///    old "capture a plain `Uuid` at spawn" behaviour the task would
    ///    still compare against OLD, skip (`initiator NEW != OLD`), and no
    ///    datagram would arrive — so phase 2 is the load-bearing assertion.
    #[tokio::test]
    async fn run_filters_on_live_peer_id_after_swap() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.expect("bind recv");
        let target_addr = receiver.local_addr().expect("recv addr");
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("bind send"));

        let old_id = Uuid::from_u128(1);
        let new_id = Uuid::from_u128(99);
        let target = Uuid::from_u128(2);
        let sessions = session_table_with(target, "fd5a:1f00:1::2", None);
        let live_id = shared(old_id);
        let (punch_tx, punch_rx) = tokio::sync::mpsc::unbounded_channel();
        let (_sd_tx, sd_rx) = watch::channel(false);

        let task = {
            let live_id = live_id.clone();
            let socket = socket.clone();
            tokio::spawn(async move {
                run(live_id, socket, sessions, punch_rx, sd_rx).await;
            })
        };

        // Phase 1: OLD id is live; an OLD-keyed initiate punches. Receiving
        // a datagram proves the task is running and has consumed the first
        // event, so the swap below is strictly ordered after spawn. A single
        // punch fires a BURST of `PUNCH_BURST` datagrams; we must DRAIN them
        // all before phase 2, otherwise phase 2's read could pick up a
        // leftover phase-1 packet and falsely "pass". The drain loop ends
        // when the burst is exhausted (a short per-packet timeout elapses).
        let mut buf = [0u8; 256];
        punch_tx
            .send(ev(old_id, target, &target_addr.to_string()))
            .expect("send initiate (old)");
        let (n1, _from) = tokio::time::timeout(Duration::from_secs(2), receiver.recv_from(&mut buf))
            .await
            .expect("phase-1 datagram (old id should punch)")
            .expect("recv ok");
        assert!(n1 >= 148, "expected a WG handshake-init, got {n1} bytes");
        // Drain the rest of the phase-1 burst so none can masquerade as a
        // phase-2 punch. PUNCH_INTERVAL is 300ms; 1s per packet is ample —
        // the loop ends when a read times out (burst exhausted).
        while let Ok(r) =
            tokio::time::timeout(Duration::from_secs(1), receiver.recv_from(&mut buf)).await
        {
            r.expect("recv ok");
        }

        // Phase 2: simulate the 404 re-register adopting a fresh peer id,
        // then send a NEW-keyed initiate. With the burst fully drained, the
        // ONLY way a datagram now arrives is the task re-reading the live id
        // and punching for the NEW-keyed event. A spawn-captured id would
        // compare NEW against OLD, skip, and this read would time out.
        *live_id.write().await = new_id;
        punch_tx
            .send(ev(new_id, target, &target_addr.to_string()))
            .expect("send initiate (new)");
        let (n2, _from) = tokio::time::timeout(Duration::from_secs(2), receiver.recv_from(&mut buf))
            .await
            .expect("phase-2 datagram (punch must use the live, swapped peer id)")
            .expect("recv ok");
        assert!(n2 >= 148, "expected a WG handshake-init, got {n2} bytes");
        assert_eq!(buf[0], 1, "first byte is the WG handshake-init type");

        // The task is mid-burst on phase 2 (PUNCH_BURST * PUNCH_INTERVAL),
        // so allow well over the burst duration for it to drain and exit.
        drop(punch_tx);
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("task exits when channel closes")
            .expect("task ran to completion");
    }

    #[tokio::test]
    async fn run_exits_on_shutdown() {
        let (tx, rx) = watch::channel(false);
        let (_punch_tx, punch_rx) = tokio::sync::mpsc::unbounded_channel();
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("bind"));
        let me = shared(Uuid::from_u128(7));
        let handle = tokio::spawn(async move {
            run(me, socket, SessionTable::new(), punch_rx, rx).await;
        });
        tx.send(true).expect("shutdown send");
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("task exited within timeout")
            .expect("task ran to completion");
    }

    /// An initiate event naming us as initiator drives a real punch: the
    /// task fires a handshake-init at the target's endpoint. A loopback
    /// receiver stands in for the target's reflexive endpoint.
    #[tokio::test]
    async fn run_punches_on_initiator_event() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.expect("bind recv");
        let target_addr = receiver.local_addr().expect("recv addr");
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("bind send"));

        let me = Uuid::from_u128(1);
        let target = Uuid::from_u128(2);
        let sessions = session_table_with(target, "fd5a:1f00:1::2", None);
        let (punch_tx, punch_rx) = tokio::sync::mpsc::unbounded_channel();
        let (_sd_tx, sd_rx) = watch::channel(false);

        let task = tokio::spawn(async move {
            run(shared(me), socket, sessions, punch_rx, sd_rx).await;
        });

        punch_tx
            .send(ev(me, target, &target_addr.to_string()))
            .expect("send initiate");

        let mut buf = [0u8; 256];
        let (n, _from) = tokio::time::timeout(Duration::from_secs(2), receiver.recv_from(&mut buf))
            .await
            .expect("a datagram within timeout")
            .expect("recv ok");
        assert!(n >= 148, "expected a WG handshake-init, got {n} bytes");
        assert_eq!(buf[0], 1, "first byte is the WG handshake-init type");

        // Closing the sender ends the run loop cleanly.
        drop(punch_tx);
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("task exits when channel closes")
            .expect("task ran to completion");
    }
}
