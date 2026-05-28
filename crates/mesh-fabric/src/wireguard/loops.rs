//! Background UDP / timer tasks for [`super::WireGuardFabric`].
//!
//! Spawned from [`super::WireGuardFabric::bind`]. The receive loop owns
//! the UDP read side and demuxes inbound datagrams by source endpoint;
//! the timer loop drives `boringtun::noise::Tunn::update_timers` for
//! every peer so handshakes + keepalives stay alive.

use super::ipv6::parse_ipv6_packet;
use super::{Inner, PeerState};
use boringtun::noise::TunnResult;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;

/// Maximum encapsulated datagram size we'll ever read from UDP.
///
/// 9001 bytes is the default jumbo MTU on EC2 / Linode networks plus
/// generous `WireGuard` overhead. Anything larger is almost certainly
/// garbage or an attack.
pub(super) const MAX_UDP_FRAME: usize = 9_001;

/// UDP receive loop — drains the socket and feeds bytes into the
/// matching peer's `Tunn` session.
pub(super) async fn receive_loop(socket: Arc<UdpSocket>, inner: Arc<Inner>) {
    let mut buf = vec![0u8; MAX_UDP_FRAME];
    loop {
        let (n, peer_addr) = match socket.recv_from(&mut buf).await {
            Ok(pair) => pair,
            Err(e) => {
                tracing::warn!(
                    node_id = %inner.local_node_id,
                    error = %e,
                    "udp recv failed"
                );
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };

        let datagram = &buf[..n];

        // Identify which peer this datagram belongs to. boringtun's
        // `parse_incoming_packet` carries the receiver session
        // index, but we don't have a global index -> peer map.
        // Instead, we route by source UDP endpoint — peers register
        // with a known endpoint, and incoming datagrams from that
        // endpoint feed that peer's tunnel.
        let Some(peer) = inner
            .peers
            .iter()
            .find(|kv| kv.value().endpoint == peer_addr)
            .map(|kv| kv.value().clone())
        else {
            tracing::trace!(
                node_id = %inner.local_node_id,
                %peer_addr,
                "dropping datagram from unknown UDP endpoint"
            );
            continue;
        };

        process_inbound(&inner, &peer, datagram).await;
    }
}

/// Classified outcome of a single `Tunn::decapsulate` call. We
/// translate the borrowed `TunnResult` into an owned form so we can
/// drop the tunnel lock + scratch borrow before awaiting socket I/O.
enum DecapAction {
    /// boringtun produced bytes to write back to the peer over UDP
    /// (handshake response, cookie reply, etc.).
    SendToPeer(Vec<u8>),
    /// boringtun decrypted an inbound IPv6 packet for the
    /// application.
    DeliverV6(Vec<u8>),
    /// boringtun handled the datagram internally — nothing to do.
    Nothing,
    /// Inbound v4 (we don't support).
    DropV4,
    /// boringtun reported an error.
    Error(String),
}

fn classify_decap_result(res: TunnResult<'_>) -> DecapAction {
    match res {
        TunnResult::Done => DecapAction::Nothing,
        TunnResult::Err(e) => DecapAction::Error(format!("{e:?}")),
        TunnResult::WriteToNetwork(bytes) => DecapAction::SendToPeer(bytes.to_vec()),
        TunnResult::WriteToTunnelV4(_, _) => DecapAction::DropV4,
        TunnResult::WriteToTunnelV6(bytes, _) => DecapAction::DeliverV6(bytes.to_vec()),
    }
}

/// Feed one inbound UDP datagram into `peer`'s tunnel, dispatch any
/// emitted application payloads to local endpoints, and forward any
/// response packets boringtun wants to send.
async fn process_inbound(inner: &Arc<Inner>, peer: &Arc<PeerState>, datagram: &[u8]) {
    // First call: decapsulate the actual UDP datagram.
    let first = {
        let mut scratch = vec![0u8; MAX_UDP_FRAME];
        let mut tunn = peer.tunn.lock().await;
        let res = tunn.decapsulate(None, datagram, &mut scratch);
        classify_decap_result(res)
    };
    apply_action(inner, peer, first).await;

    // boringtun documents that after `WriteToNetwork`, the caller
    // should repeatedly call `decapsulate` with an empty datagram
    // until `Done` is returned, in order to drain any queued packets
    // (handshake completion can release packets queued earlier).
    loop {
        let next = {
            let mut scratch = vec![0u8; MAX_UDP_FRAME];
            let mut tunn = peer.tunn.lock().await;
            let res = tunn.decapsulate(None, &[], &mut scratch);
            classify_decap_result(res)
        };
        if matches!(next, DecapAction::Nothing) {
            break;
        }
        apply_action(inner, peer, next).await;
    }
}

/// Apply a [`DecapAction`] — perform the actual UDP I/O or local
/// dispatch. No locks held across awaits.
async fn apply_action(inner: &Arc<Inner>, peer: &Arc<PeerState>, action: DecapAction) {
    match action {
        DecapAction::Nothing => {}
        DecapAction::Error(e) => {
            tracing::debug!(
                node_id = %inner.local_node_id,
                error = %e,
                "boringtun decapsulate error"
            );
        }
        DecapAction::SendToPeer(bytes) => {
            if let Err(e) = inner.socket.send_to(&bytes, peer.endpoint).await {
                tracing::debug!(
                    node_id = %inner.local_node_id,
                    error = %e,
                    "udp send (handshake response) failed"
                );
            }
        }
        DecapAction::DropV4 => {
            tracing::trace!(
                node_id = %inner.local_node_id,
                "received ipv4 packet — not supported by mesh-fabric, dropping"
            );
        }
        DecapAction::DeliverV6(bytes) => match parse_ipv6_packet(&bytes) {
            Ok((_src, dst_ula, payload)) => {
                if let Some(entry) = inner.endpoints.get(&dst_ula) {
                    if let Err(e) = entry.tx.send((dst_ula, payload)) {
                        tracing::trace!(
                            node_id = %inner.local_node_id,
                            %dst_ula,
                            error = %e,
                            "endpoint receiver dropped — frame discarded"
                        );
                    }
                } else {
                    tracing::trace!(
                        node_id = %inner.local_node_id,
                        %dst_ula,
                        "inbound frame for unknown local ULA — dropped"
                    );
                }
            }
            Err(e) => {
                tracing::debug!(
                    node_id = %inner.local_node_id,
                    ?e,
                    "ipv6 wrapper parse failed"
                );
            }
        },
    }
}

/// Periodically drive each peer's timer state. boringtun expects
/// `update_timers` to be called roughly every 250ms; this loop calls
/// it every 200ms. On `WriteToNetwork` we forward the bytes to the
/// peer (typically a re-handshake or keepalive).
pub(super) async fn timer_loop(inner: Arc<Inner>) {
    let mut interval = tokio::time::interval(Duration::from_millis(200));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        interval.tick().await;
        let peer_handles: Vec<(String, Arc<PeerState>)> = inner
            .peers
            .iter()
            .map(|kv| (kv.key().clone(), kv.value().clone()))
            .collect();
        for (_node_id, peer) in peer_handles {
            let outbound: Option<Vec<u8>> = {
                let mut scratch = vec![0u8; 256];
                let mut tunn = peer.tunn.lock().await;
                match tunn.update_timers(&mut scratch) {
                    TunnResult::WriteToNetwork(bytes) => Some(bytes.to_vec()),
                    _ => None,
                }
            };
            if let Some(bytes) = outbound {
                if let Err(e) = inner.socket.send_to(&bytes, peer.endpoint).await {
                    tracing::trace!(
                        node_id = %inner.local_node_id,
                        error = %e,
                        "timer-driven udp send failed"
                    );
                }
            }
        }
    }
}
