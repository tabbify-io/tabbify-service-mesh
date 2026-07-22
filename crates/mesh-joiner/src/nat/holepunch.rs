//! Stage 2 — joiner-side UDP hole-punch subscriber (FUNCTIONAL, not a stub).
//!
//! [`run`] is a live tokio task: the SSE consumer (`coordinator::peer_sync`)
//! decodes `HolePunchInitiate` frames off the coordinator's
//! `/v1/mesh/peers/stream` and forwards them on the `punch_rx` channel this
//! task drains. For each event where WE are the initiator (matched against the
//! LIVE `peer_id`, which a 404 re-register may have swapped):
//!
//! 1. [`plan_punch`] resolves the event to the target's session + reflexive
//!    endpoint (returns `None` for not-initiator / no-session / bad endpoint).
//! 2. [`execute_punch`] fires a synchronized burst of WG handshake-inits
//!    (`PUNCH_BURST` × `PUNCH_INTERVAL`) at that endpoint to open our NAT
//!    mapping, AND — while the path is still unconfirmed — relays the same
//!    handshake in parallel (so a no-inbound peer still converges). Once a real
//!    direct DATA packet arrives (`confirm_direct`), TX upgrades to the direct
//!    path and the parallel relay stops.
//!
//! The direct plane is gated by `relay_only`: a `relay_only` node (no usable
//! direct path) never probes/punches — that contract is what prevents the
//! 2026-06-07 double-sided-handshake-thrash outage. So this task only does
//! useful work for peers that genuinely have a reachable endpoint.

use crate::coordinator::heartbeat::SharedPeerId;
use crate::relay::RelayHandle;
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

/// Produce a `WireGuard` handshake-initiation for `session` to send, or `None`
/// if boringtun has nothing to emit right now.
///
/// `force_resend = FALSE` (deliberate — this was the relay-handshake bug):
/// with `true`, boringtun mints a BRAND-NEW initiation (fresh ephemeral, reset
/// handshake state) on EVERY call. The punch fires a burst (and re-fires per
/// coordinator directive), so `true` reset the in-flight handshake several
/// times a second. Over a DIRECT path (<1 ms RTT) the peer's response still
/// beat the next reset, so it completed; over the RELAY floor (~100-300 ms RTT)
/// the response for init #1 always arrived AFTER the runner had already reset to
/// init #2-5 → the response never matched the current handshake → boringtun
/// looped `REKEY_TIMEOUT` forever and NO relayed/NAT'd session ever reached
/// DATA (`DeliverToTun = 0`). With `false`, boringtun emits ONE init then
/// suppresses repeats within its retransmit window, and `update_timers` re-sends
/// at the proper `WireGuard` cadence (~5 s ≫ relay RTT) — so the response lands
/// against a stable handshake and the session completes over the relay.
async fn build_handshake_packet(session: &Arc<PeerSession>) -> Option<Vec<u8>> {
    let mut out = vec![0u8; HANDSHAKE_BUF_LEN];
    let mut tunn = session.tunn.lock().await;
    match classify_tunn_result(tunn.format_handshake_initiation(&mut out, false)) {
        WgAction::SendToPeer(bytes) => Some(bytes),
        _ => None,
    }
}

/// Execute a planned punch.
///
/// Fires a short burst of handshake-initiations so our `NAT` mapping opens
/// and crosses with the peer's simultaneous burst. The direct burst always
/// targets `plan.endpoint` (the reflexive candidate) to open OUR local NAT
/// mapping for a genuinely punchable peer.
///
/// Crucially this NEVER pins the session's outbound endpoint — confirmed or
/// not. For a no-inbound-port peer (a container netns, a symmetric-NAT peer
/// we can't reach) the coordinator-advertised reflexive endpoint is a BLACK
/// HOLE, and regressing the session onto it defeats `send_wire`'s relay
/// floor (unconfirmed) or wedges a CONFIRMED session's TX into the black
/// hole while the peer's own inbound keeps the path "fresh" (the MSI
/// symmetric-NAT wedge — the confirmed-only pin this used to do was the
/// same clobber as `update_in_place`'s roster repoint). Endpoint ownership
/// lives solely with `SessionTable::learn_endpoint` (authenticated source
/// adoption) and the roster candidate path; the punch's only job here is
/// firing datagrams to open OUR local NAT mapping, which needs no session
/// state at all.
///
/// While unconfirmed AND a `relay` is configured, each burst init is ALSO
/// queued on the relay floor (keyed by the peer's pubkey) — this is what
/// guarantees a black-hole peer receives the init so the handshake
/// completes. The relay double-fire stops the moment the direct path is
/// confirmed (`send_wire`'s confirmed-direct branch takes over), so steady
/// state never doubles handshake traffic. Tolerates `relay == None`
/// (no-relay / `--no-relay` builds): `try_relay` is best-effort and this
/// branch is simply skipped.
pub async fn execute_punch(
    socket: &UdpSocket,
    relay: Option<&RelayHandle>,
    plan: &PunchPlan,
    burst: usize,
    interval: Duration,
) {
    let confirmed = plan.session.direct_confirmed();
    // Deliberately NO endpoint pin here — see the fn doc. The directive's
    // reflexive candidate may be a black hole (symmetric NAT); only an
    // authenticated inbound source (`learn_endpoint`) may repoint a session.
    for i in 0..burst {
        if let Some(bytes) = build_handshake_packet(&plan.session).await {
            // (a) Direct: open OUR local NAT mapping toward the candidate.
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
            // (b) Relay floor: while unconfirmed, ALSO route the init through
            // the relay so a black-hole / no-inbound peer receives it and the
            // handshake can complete. Stop once confirmed — `send_wire` then
            // owns the (direct) path and a relay double-fire would be waste.
            if !confirmed {
                if let Some(relay) = relay {
                    relay.try_relay(plan.session.peer_pubkey, bytes.clone());
                }
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
                        execute_punch(&socket, sessions.relay(), &plan, PUNCH_BURST, PUNCH_INTERVAL).await;
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

    /// Insert one peer session into `t`, keyed by `peer_id` / `ula`, with a
    /// WG pubkey derived from `key_seed`. A DISTINCT `key_seed` yields a
    /// DISTINCT pubkey → a brand-new `Tunn` whose handshake hasn't been
    /// initiated yet, so its first `build_handshake_packet` emits a fresh
    /// init even under `force_resend = false`.
    fn upsert_target(
        t: &SessionTable,
        peer_id: Uuid,
        ula: &str,
        endpoint: Option<&str>,
        key_seed: u8,
    ) {
        let me = StaticSecret::from([7u8; 32]);
        let peer_pub = *PublicKey::from(&StaticSecret::from([key_seed; 32])).as_bytes();
        let info = PeerInfo {
            peer_id,
            wg_public_key: peer_pub,
            ula: ula.parse().expect("ula"),
            listen_endpoint: endpoint.map(|s| s.parse().expect("endpoint")),
            display_name: "target".into(),
            tags: vec![],
            hosted_app_ulas: vec![],
            software_version: None,
            mesh_version: None,
            joined_at_micros: 0,
        };
        t.upsert(&me, &info);
    }

    /// Build a session table holding exactly one peer session keyed by
    /// `peer_id`, so `plan_punch` has something to find.
    fn session_table_with(peer_id: Uuid, ula: &str, endpoint: Option<&str>) -> SessionTable {
        let t = SessionTable::new();
        upsert_target(&t, peer_id, ula, endpoint, 9);
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

    /// Executing a plan must actually emit a `WireGuard` handshake-init
    /// datagram DIRECT to the reflexive target — that datagram is the
    /// "punch" that opens our local NAT mapping for a genuinely punchable
    /// peer. (Fix A) For an UNCONFIRMED session the direct burst must NOT
    /// pin the session's outbound endpoint at the candidate: a no-inbound
    /// peer's reflexive endpoint is a black hole, and regressing the
    /// session onto it would defeat `send_wire`'s relay floor. The endpoint
    /// stays where it was (here: `None`, a passive target).
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
        assert!(
            !plan.session.direct_confirmed(),
            "fresh session is unconfirmed"
        );

        // No relay wired — proves the relay==None path still fires direct.
        execute_punch(&sender, None, &plan, 2, Duration::from_millis(1)).await;

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
        // The direct burst must NOT pin an unconfirmed session onto the
        // (possibly black-hole) candidate endpoint.
        assert_eq!(
            plan.session.endpoint(),
            None,
            "an unconfirmed punch must not regress the session's endpoint to the candidate"
        );
    }

    /// No-op route sink so a relay-carrying session table can be built in
    /// tests without shelling out to `route` / `ifconfig`.
    struct NoopSink;
    impl crate::wg::session::RouteSink for NoopSink {
        fn add_allowed(&self, _ula: std::net::Ipv6Addr) {}
        fn remove_allowed(&self, _ula: std::net::Ipv6Addr) {}
        fn add_app_route(&self, _app_ula: std::net::Ipv6Addr) {}
        fn remove_app_route(&self, _app_ula: std::net::Ipv6Addr) {}
    }

    /// Build a session table holding one peer session, wired to the given
    /// relay handle — mirrors `session_table_with` but carries a relay so
    /// `sessions.relay()` is `Some`. The session starts UNCONFIRMED.
    fn relay_table_with(
        peer_id: Uuid,
        ula: &str,
        endpoint: Option<&str>,
        relay: crate::relay::RelayHandle,
    ) -> SessionTable {
        let t = SessionTable::with_route_sink_and_relay(Arc::new(NoopSink), Some(relay));
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
            mesh_version: None,
            joined_at_micros: 0,
        };
        t.upsert(&me, &info);
        t
    }

    /// Fix A (PRIMARY): while a session is UNCONFIRMED, each punch burst
    /// packet must ALSO be queued on the relay floor — not just fired
    /// direct at the (possibly black-hole) reflexive endpoint. A
    /// no-inbound-port peer (a container netns) only ever receives the
    /// handshake-init via the relay, so without this the handshake never
    /// completes and the tunnel never forms. The relayed frame targets the
    /// session's `peer_pubkey`.
    #[tokio::test]
    async fn execute_punch_relays_init_while_unconfirmed() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.expect("bind recv");
        let target_addr = receiver.local_addr().expect("recv addr");
        let sender = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("bind send"));

        let me = Uuid::from_u128(1);
        let target = Uuid::from_u128(2);
        let (relay, mut relay_rx) = crate::relay::RelayHandle::new(false);
        // Endpoint advertised but unreachable (a black hole for a
        // no-inbound peer); the session is unconfirmed.
        let sessions = relay_table_with(
            target,
            "fd5a:1f00:1::2",
            Some(&target_addr.to_string()),
            relay,
        );
        let plan =
            plan_punch(&sessions, me, &ev(me, target, &target_addr.to_string())).expect("a plan");
        assert!(
            !plan.session.direct_confirmed(),
            "fresh session is unconfirmed"
        );
        let peer_pubkey = plan.session.peer_pubkey;

        execute_punch(
            &sender,
            sessions.relay(),
            &plan,
            2,
            Duration::from_millis(1),
        )
        .await;

        // (a) The direct datagram still went out (opens our NAT mapping).
        let mut buf = [0u8; 256];
        let (n, _from) = tokio::time::timeout(Duration::from_secs(1), receiver.recv_from(&mut buf))
            .await
            .expect("a direct datagram within timeout")
            .expect("recv ok");
        assert!(n >= 148, "WireGuard handshake-init is 148 bytes, got {n}");
        assert_eq!(buf[0], 1, "first byte is the WG handshake-init type");

        // (b) AND the init was queued on the relay floor for the peer pubkey.
        let relayed = tokio::time::timeout(Duration::from_secs(1), relay_rx.recv())
            .await
            .expect("the init must ALSO be relayed while unconfirmed")
            .expect("relay channel delivered the frame");
        assert_eq!(
            relayed.dst_pubkey, peer_pubkey,
            "the relayed init targets the target peer's pubkey"
        );
        assert!(
            !relayed.payload.is_empty(),
            "relayed payload is the WG handshake-init"
        );
    }

    /// Fix A sibling: once the direct path is CONFIRMED, the punch must NOT
    /// double-fire onto the relay — `send_wire`'s confirmed-direct branch
    /// has taken over, and relaying would needlessly double handshake
    /// traffic. The direct datagram still goes out (harmless NAT poke), but
    /// nothing is queued on the relay.
    #[tokio::test]
    async fn execute_punch_does_not_relay_when_confirmed() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.expect("bind recv");
        let target_addr = receiver.local_addr().expect("recv addr");
        let sender = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("bind send"));

        let me = Uuid::from_u128(1);
        let target = Uuid::from_u128(2);
        let (relay, mut relay_rx) = crate::relay::RelayHandle::new(false);
        let sessions = relay_table_with(
            target,
            "fd5a:1f00:1::2",
            Some(&target_addr.to_string()),
            relay,
        );
        let plan =
            plan_punch(&sessions, me, &ev(me, target, &target_addr.to_string())).expect("a plan");
        // Prove the direct path — the upgrade signal that stops relaying.
        plan.session.confirm_direct(1_000);
        assert!(plan.session.direct_confirmed());

        execute_punch(
            &sender,
            sessions.relay(),
            &plan,
            2,
            Duration::from_millis(1),
        )
        .await;

        // The direct datagram still goes out.
        let mut buf = [0u8; 256];
        let (n, _from) = tokio::time::timeout(Duration::from_secs(1), receiver.recv_from(&mut buf))
            .await
            .expect("a direct datagram within timeout")
            .expect("recv ok");
        assert!(n >= 148, "WireGuard handshake-init is 148 bytes, got {n}");

        // But NOTHING is relayed — a confirmed path doesn't double-fire.
        let relayed = tokio::time::timeout(Duration::from_millis(300), relay_rx.recv()).await;
        assert!(
            relayed.is_err(),
            "a confirmed session must not double-relay the punch init"
        );
    }

    /// The punch must NEVER repoint a session's outbound endpoint — confirmed
    /// or not. The old confirmed-only pin was the same clobber class as the
    /// roster repoint (the MSI symmetric-NAT wedge): the directive's reflexive
    /// candidate may be a per-destination black hole, and overwriting a
    /// proven learned endpoint with it wedges TX while the peer's inbound
    /// keeps the path "fresh". Endpoint ownership belongs to
    /// `learn_endpoint` (authenticated source adoption) alone.
    #[tokio::test]
    async fn execute_punch_never_repoints_a_confirmed_session() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.expect("bind recv");
        let candidate_addr = receiver.local_addr().expect("recv addr");
        let sender = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("bind send"));

        let me = Uuid::from_u128(1);
        let target = Uuid::from_u128(2);
        // The session's CURRENT endpoint is a proven learned address that
        // differs from the punch directive's reflexive candidate.
        let proven: std::net::SocketAddr = "127.0.0.1:40123".parse().expect("addr");
        let sessions = session_table_with(target, "fd5a:1f00:1::2", Some("127.0.0.1:40123"));
        let plan = plan_punch(&sessions, me, &ev(me, target, &candidate_addr.to_string()))
            .expect("a plan");
        plan.session.confirm_direct(1_000);
        assert!(plan.session.direct_confirmed());

        execute_punch(&sender, None, &plan, 1, Duration::from_millis(1)).await;

        // The burst still fired at the candidate (opens OUR NAT mapping)…
        let mut buf = [0u8; 256];
        let (n, _from) = tokio::time::timeout(Duration::from_secs(1), receiver.recv_from(&mut buf))
            .await
            .expect("a direct datagram within timeout")
            .expect("recv ok");
        assert!(n >= 148, "WireGuard handshake-init is 148 bytes, got {n}");

        // …but the session's outbound endpoint is untouched.
        assert_eq!(
            plan.session.endpoint(),
            Some(proven),
            "the punch must not clobber a confirmed session's endpoint with the directive candidate"
        );
    }

    /// Regression for the relay-handshake flood bug (the `force_resend =
    /// false` fix in `build_handshake_packet`). With the old `true`, every
    /// call minted a BRAND-NEW init (fresh ephemeral, reset handshake state),
    /// so a punch burst reset the in-flight handshake several times a second
    /// — over the relay floor (~100-300 ms RTT) the peer's response never
    /// matched the current handshake and boringtun looped `REKEY_TIMEOUT`
    /// forever. With `false`, boringtun emits ONE init then SUPPRESSES repeats
    /// within its retransmit window. This test drives `build_handshake_packet`
    /// twice in immediate succession on the SAME session: the first call must
    /// emit a real WG init (`Some`, ≥148 bytes, byte[0]==1), the second must
    /// be suppressed (`None`) — proving no repeated/reset inits are minted.
    #[tokio::test]
    async fn build_handshake_packet_suppresses_repeats_within_window() {
        let target = Uuid::from_u128(2);
        let sessions = session_table_with(target, "fd5a:1f00:1::2", None);
        let session = sessions
            .snapshot()
            .into_iter()
            .find(|s| s.peer_id == target)
            .expect("the target session");

        // First call: a fresh Tunn emits a real handshake-init.
        let first = build_handshake_packet(&session)
            .await
            .expect("the first call must emit a WG handshake-init");
        assert!(
            first.len() >= 148,
            "WireGuard handshake-init is 148 bytes, got {}",
            first.len()
        );
        assert_eq!(
            first[0], 1,
            "first byte is the WG handshake-init message type"
        );

        // Immediate second call on the SAME session: force_resend=false means
        // boringtun suppresses the repeat within its retransmit window, so no
        // new init is minted.
        let second = build_handshake_packet(&session).await;
        assert!(
            second.is_none(),
            "force_resend=false must suppress an immediate repeat init (no flood), got {} bytes",
            second.map_or(0, |b| b.len())
        );
    }

    /// A burst puts exactly ONE handshake-initiation on the wire, however large
    /// the burst is.
    ///
    /// The fast, always-run counterpart to the `#[ignore]`d expired-Tunn guard
    /// below: it costs no wall-clock, so it runs on every build. Flipping
    /// `build_handshake_packet`'s `force_resend` back to `true` makes this fail
    /// immediately with `burst` datagrams instead of one — that flag is what
    /// caused the 2026-06-07 relay outage (each fresh init reset the handshake
    /// the peer was still responding to, so no relayed session ever reached
    /// DATA), and nothing else in the suite catches a flip end-to-end.
    ///
    /// Note this also means the burst does NOT put `burst` datagrams on the wire
    /// for NAT-mapping purposes — suppression collapses it to one. That is the
    /// deliberate trade the `force_resend = false` fix made: a stable handshake
    /// beats a wider punch.
    #[tokio::test]
    async fn a_burst_puts_exactly_one_initiation_on_the_wire() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.expect("bind recv");
        let candidate_addr = receiver.local_addr().expect("recv addr");
        let sender = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("bind send"));

        let target = Uuid::from_u128(11);
        let sessions = session_table_with(target, "fd5a:1f00:1::b", None);
        let session = sessions
            .snapshot()
            .into_iter()
            .find(|s| s.peer_id == target)
            .expect("the target session");
        let plan = PunchPlan {
            session,
            endpoint: candidate_addr,
        };

        execute_punch(&sender, None, &plan, 5, Duration::from_millis(1)).await;

        // Drain everything the burst actually sent.
        let mut buf = vec![0u8; 2048];
        let mut sent_count = 0usize;
        while let Ok(Ok((len, _))) =
            tokio::time::timeout(Duration::from_millis(50), receiver.recv_from(&mut buf)).await
        {
            assert_eq!(
                buf[0], 1,
                "every datagram a punch sends is a WG handshake-init"
            );
            assert!(len >= 148, "WG handshake-init is 148 bytes, got {len}");
            sent_count += 1;
        }

        assert_eq!(
            sent_count, 1,
            "a burst of 5 must put exactly ONE initiation on the wire; {sent_count} means \
             repeats are no longer suppressed (force_resend=true?), which is the \
             2026-06-07 relay failure"
        );
    }

    /// Drive `session`'s `Tunn` to boringtun's permanent EXPIRED state (it gives
    /// up after `REKEY_ATTEMPT_TIME`). Costs real wall-clock — there is no global
    /// mock clock — so every test using it is `#[ignore]`d, matching
    /// `expired_session_is_rearmed_over_relay` in `wg::loops`.
    async fn drive_tunn_to_expired(session: &Arc<PeerSession>) {
        let mut scratch = vec![0u8; 65535];
        {
            let mut guard = session.tunn.lock().await;
            let _ = guard.encapsulate(&[], &mut scratch);
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(120);
        loop {
            {
                let mut guard = session.tunn.lock().await;
                if guard.is_expired() {
                    return;
                }
                let _ = guard.update_timers(&mut scratch);
            }
            assert!(
                std::time::Instant::now() < deadline,
                "Tunn failed to reach Expired within the attempt window"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// THE EXPIRED-TUNN SIBLING of
    /// `build_handshake_packet_suppresses_repeats_within_window`.
    ///
    /// The suspicion this pins: `force_resend = false` makes boringtun suppress
    /// repeats only while a handshake is IN PROGRESS, so a long-idle pair whose
    /// `Tunn` has EXPIRED might have no in-progress handshake to suppress
    /// against and mint a fresh initiation per burst iteration — which would
    /// reproduce the 2026-06-07 relay failure by a different door (over a
    /// ~100-300 ms relay RTT the response to init #1 lands after we already
    /// reset to #2-5, so it never matches and the session never reaches DATA).
    ///
    /// MEASURED: it does not. An expired `Tunn` mints exactly ONE initiation and
    /// leaves the expired state on that first call, after which boringtun's
    /// normal in-progress suppression applies to the rest of the burst. So this
    /// test PASSES against today's code and exists as a REGRESSION GUARD on that
    /// invariant, not as a reproduction. If anyone reintroduces `force_resend =
    /// true` — or boringtun changes what an expired `Tunn` does — this is what
    /// catches it on the expired path.
    #[tokio::test]
    #[ignore = "drives a real boringtun Tunn to 90s expiry (no global mock clock); run with --ignored"]
    async fn expired_tunn_burst_mints_at_most_one_initiation() {
        let target = Uuid::from_u128(9);
        let sessions = session_table_with(target, "fd5a:1f00:1::9", None);
        let session = sessions
            .snapshot()
            .into_iter()
            .find(|s| s.peer_id == target)
            .expect("the target session");

        drive_tunn_to_expired(&session).await;
        assert!(
            session.tunn.lock().await.is_expired(),
            "precondition: the Tunn must be EXPIRED"
        );

        // A burst's worth of calls, exactly as `execute_punch` makes them.
        let mut minted = 0usize;
        for _ in 0..BURST_FOR_TEST {
            if build_handshake_packet(&session).await.is_some() {
                minted += 1;
            }
        }

        assert!(
            minted <= 1,
            "an expired-Tunn burst must mint AT MOST ONE initiation (a fresh init \
             per iteration resets the handshake the peer is responding to); minted {minted}"
        );
    }

    /// The burst size the canary ran with, and what the test above simulates.
    const BURST_FOR_TEST: usize = 5;

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
    /// 1. With the OLD id live, an initiate keyed to OLD (targeting
    ///    `target1`) punches — proving the task is up and reading the shared
    ///    handle per event.
    /// 2. We then swap the shared handle to a NEW id (the 404 recovery) and
    ///    send an initiate keyed to the NEW id, targeting a DISTINCT session
    ///    (`target2`). It MUST punch too. Under the old "capture a plain
    ///    `Uuid` at spawn" behaviour the task would still compare against
    ///    OLD, skip (`initiator NEW != OLD`), and no datagram would arrive —
    ///    so phase 2 is the load-bearing assertion.
    ///
    /// Phase 2 deliberately targets a SECOND, distinct session (distinct WG
    /// pubkey → a fresh `Tunn`). With `build_handshake_packet`'s
    /// `force_resend = false`, re-punching the SAME session that already
    /// handshaked in phase 1 would be correctly SUPPRESSED (no new init), so
    /// re-using `target1` could not produce a phase-2 datagram. In
    /// production an id-swap (key rotation) likewise yields a new session, so
    /// a distinct target faithfully models the recovery path.
    #[tokio::test]
    async fn run_filters_on_live_peer_id_after_swap() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.expect("bind recv");
        let target_addr = receiver.local_addr().expect("recv addr");
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("bind send"));

        let old_id = Uuid::from_u128(1);
        let new_id = Uuid::from_u128(99);
        // Two DISTINCT target peers: distinct peer_id, distinct ULA, distinct
        // WG pubkey (key_seed) → two independent `Tunn`s. Phase 2 punches the
        // second so `force_resend = false` still emits a fresh init.
        let target1 = Uuid::from_u128(2);
        let target2 = Uuid::from_u128(3);
        let sessions = SessionTable::new();
        upsert_target(&sessions, target1, "fd5a:1f00:1::2", None, 9);
        upsert_target(&sessions, target2, "fd5a:1f00:1::3", None, 11);
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

        // Phase 1: OLD id is live; an OLD-keyed initiate (target1) punches.
        // Receiving a datagram proves the task is running and has consumed
        // the first event, so the swap below is strictly ordered after spawn.
        // Under `force_resend = false` a single punch emits ONE init (not the
        // full `PUNCH_BURST`): boringtun suppresses repeats within its
        // retransmit window. We still DRAIN defensively before phase 2 so no
        // stray phase-1 packet can masquerade as a phase-2 punch; with
        // force=false the drain loop simply finds nothing more and times out
        // quickly.
        let mut buf = [0u8; 256];
        punch_tx
            .send(ev(old_id, target1, &target_addr.to_string()))
            .expect("send initiate (old)");
        let (n1, _from) =
            tokio::time::timeout(Duration::from_secs(2), receiver.recv_from(&mut buf))
                .await
                .expect("phase-1 datagram (old id should punch)")
                .expect("recv ok");
        assert!(n1 >= 148, "expected a WG handshake-init, got {n1} bytes");
        // Drain any remainder of the phase-1 burst so none can masquerade as
        // a phase-2 punch. With force=false the burst emits a single init, so
        // this loop typically times out immediately on the first read.
        while let Ok(r) =
            tokio::time::timeout(Duration::from_secs(1), receiver.recv_from(&mut buf)).await
        {
            r.expect("recv ok");
        }

        // Phase 2: simulate the 404 re-register adopting a fresh peer id,
        // then send a NEW-keyed initiate targeting the DISTINCT `target2`
        // session (fresh Tunn → emits under force=false). With the burst
        // fully drained, the ONLY way a datagram now arrives is the task
        // re-reading the live id and punching for the NEW-keyed event. A
        // spawn-captured id would compare NEW against OLD, skip, and this
        // read would time out.
        *live_id.write().await = new_id;
        punch_tx
            .send(ev(new_id, target2, &target_addr.to_string()))
            .expect("send initiate (new)");
        let (n2, _from) =
            tokio::time::timeout(Duration::from_secs(2), receiver.recv_from(&mut buf))
                .await
                .expect("phase-2 datagram (punch must use the live, swapped peer id)")
                .expect("recv ok");
        assert!(n2 >= 148, "expected a WG handshake-init, got {n2} bytes");
        assert_eq!(buf[0], 1, "first byte is the WG handshake-init type");

        // The task may still be mid-burst on phase 2 (PUNCH_BURST *
        // PUNCH_INTERVAL), so allow well over the burst duration for it to
        // drain and exit.
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
