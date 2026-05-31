//! Send-path + per-peer handshake driver for [`super::WireGuardFabric`].
//!
//! Hosts `send_remote`, `kick_handshake`, `wait_until_handshake`,
//! peer-and-route mutators, plus the `MeshFabric` / `MeshFabricMutators`
//! trait impls. The receive side lives in [`super::loops`].

use super::ipv6::build_ipv6_packet;
use super::keys::WireGuardPeerSpec;
use super::{EndpointEntry, MAX_APP_PAYLOAD, WireGuardFabric};
use crate::loopback::LoopbackPeerSpec;
use crate::trait_def::{
    AppMessage, FabricError, InboundRx, MeshFabric, MeshFabricMutators, RoutingSnapshot,
};
use async_trait::async_trait;
use boringtun::noise::{Tunn, TunnResult};
use rand_core::{OsRng, RngCore};
use std::net::Ipv6Addr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, mpsc};

impl WireGuardFabric {
    /// Register a remote `WireGuard` peer. Replaces any existing entry
    /// for the same `node_id`.
    ///
    /// Returns the peer-handle for the caller to drive handshake
    /// timers manually if desired (most callers can ignore the return
    /// value — the background timer loop in [`Self::bind`] keeps
    /// handshakes alive).
    pub fn add_wireguard_peer(&self, peer: WireGuardPeerSpec) {
        // Each peer gets a unique 32-bit `index` for boringtun's
        // session bookkeeping. We derive it from the OS RNG.
        let mut idx_bytes = [0u8; 4];
        OsRng.fill_bytes(&mut idx_bytes);
        let index = u32::from_le_bytes(idx_bytes);

        let tunn = Tunn::new(
            self.inner.static_private.clone(),
            peer.public_key,
            None,     // no PSK
            Some(25), // 25s keepalive
            index,
            None, // default rate limiter
        );
        let state = Arc::new(super::PeerState {
            endpoint: peer.endpoint,
            public_key: peer.public_key,
            tunn: Mutex::new(tunn),
        });
        self.inner.peers.insert(peer.node_id, state);
    }

    /// Remove a peer and forget its session state.
    pub fn remove_wireguard_peer(&self, node_id: &str) {
        self.inner.peers.remove(node_id);
    }

    /// Add or replace a route: messages addressed to `ula` are
    /// forwarded to the peer identified by `node_id`.
    pub fn add_remote_route(&self, ula: Ipv6Addr, node_id: String) {
        self.inner.remote_routes.insert(ula, node_id);
    }

    /// Remove a remote route.
    pub fn remove_remote_route(&self, ula: Ipv6Addr) {
        self.inner.remote_routes.remove(&ula);
    }

    /// Wait until the named peer has a usable session — i.e. the
    /// initial `WireGuard` handshake has completed. Useful in tests
    /// where you want deterministic ordering between handshake and
    /// first data packet.
    ///
    /// Returns `Ok(())` once a session exists, or `Err` on timeout.
    pub async fn wait_until_handshake(
        &self,
        node_id: &str,
        timeout: Duration,
    ) -> Result<(), FabricError> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if let Some(peer) = self.inner.peers.get(node_id) {
                let established = {
                    let tunn = peer.tunn.lock().await;
                    tunn.time_since_last_handshake().is_some()
                };
                if established {
                    // Re-peer observability: the first authenticated packet
                    // has crossed — the session is live. Same (node_id,
                    // endpoint) fields as `handshake_init` so a Loki query
                    // can confirm the re-peer actually completed.
                    tracing::info!(
                        node_id = %node_id,
                        endpoint = %peer.endpoint,
                        event = "session_established",
                        "wireguard: handshake completed — session established"
                    );
                    return Ok(());
                }
            }
            if tokio::time::Instant::now() >= deadline {
                // Re-peer observability: the handshake never completed in
                // time. This is the line that pinpoints a stuck re-peer (the
                // ThinkPad sent inits but no authenticated packet came back).
                let endpoint = self
                    .inner
                    .peers
                    .get(node_id)
                    .map(|p| p.endpoint.to_string());
                tracing::warn!(
                    node_id = %node_id,
                    endpoint = ?endpoint,
                    event = "handshake_timeout",
                    timeout_ms = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX),
                    "wireguard: handshake did not complete within timeout"
                );
                return Err(FabricError::Transport(format!(
                    "handshake to {node_id} did not complete within {timeout:?}"
                )));
            }
            // Kick the handshake — `encapsulate` with empty payload
            // triggers a handshake init if none is in progress.
            self.kick_handshake(node_id).await.ok();
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// Force-send a handshake initiation to the named peer. Called
    /// internally by [`Self::wait_until_handshake`] and by the timer
    /// loop; rarely needed externally.
    async fn kick_handshake(&self, node_id: &str) -> Result<(), FabricError> {
        let peer = self
            .inner
            .peers
            .get(node_id)
            .ok_or_else(|| FabricError::Transport(format!("peer {node_id} not registered")))?
            .clone();
        let outbound: Option<Vec<u8>> = {
            let mut dst = vec![0u8; 256];
            let mut tunn = peer.tunn.lock().await;
            match tunn.format_handshake_initiation(&mut dst, false) {
                TunnResult::WriteToNetwork(bytes) => Some(bytes.to_vec()),
                TunnResult::Done => None,
                TunnResult::Err(e) => {
                    return Err(FabricError::Transport(format!(
                        "boringtun handshake error: {e:?}"
                    )));
                }
                other => {
                    return Err(FabricError::Transport(format!(
                        "unexpected boringtun handshake result: {other:?}"
                    )));
                }
            }
        };
        if let Some(bytes) = outbound {
            // Re-peer observability: a fresh WireGuard handshake-init is
            // going out to this peer's endpoint. `event="handshake_init"`
            // with the (node_id, endpoint) pair lets a Loki query see the
            // moment a re-peer attempt leaves the wire — paired with the
            // `session_established` / `handshake_timeout` events below it
            // tells you whether the handshake ever completed.
            tracing::info!(
                node_id = %node_id,
                endpoint = %peer.endpoint,
                event = "handshake_init",
                "wireguard: sending handshake-init to peer"
            );
            self.inner
                .socket
                .send_to(&bytes, peer.endpoint)
                .await
                .map_err(|e| FabricError::Transport(format!("kick handshake send: {e}")))?;
        }
        Ok(())
    }

    /// Encrypt + send `msg` to the peer identified by `node_id`.
    async fn send_remote(
        &self,
        node_id: &str,
        dst_ula: Ipv6Addr,
        msg: &[u8],
    ) -> Result<(), FabricError> {
        if msg.len() > MAX_APP_PAYLOAD {
            return Err(FabricError::Encoding(format!(
                "payload {} exceeds max {}",
                msg.len(),
                MAX_APP_PAYLOAD
            )));
        }

        let peer = self
            .inner
            .peers
            .get(node_id)
            .ok_or_else(|| FabricError::Transport(format!("peer {node_id} not registered")))?
            .clone();

        // Wrap the payload in a synthetic IPv6 packet so boringtun's
        // validation accepts it. The `src` is the unspecified address
        // (we don't currently expose a per-fabric "local ULA"), `dst`
        // is the application destination ULA.
        let framed = build_ipv6_packet(Ipv6Addr::UNSPECIFIED, dst_ula, msg)?;

        // First attempt: encapsulate. If no session yet, boringtun
        // queues the packet and emits a handshake initiation — we
        // forward that to the wire and let the receive loop handle
        // the response.
        let outbound: EncapAction = {
            let mut out = vec![0u8; framed.len() + 64];
            let mut tunn = peer.tunn.lock().await;
            let res = tunn.encapsulate(&framed, &mut out);
            match res {
                TunnResult::WriteToNetwork(bytes) => EncapAction::SendBytes(bytes.to_vec()),
                TunnResult::Done => EncapAction::Queued,
                TunnResult::Err(e) => EncapAction::Error(format!("{e:?}")),
                other => EncapAction::Error(format!("unexpected: {other:?}")),
            }
        };

        match outbound {
            EncapAction::SendBytes(bytes) => {
                self.inner
                    .socket
                    .send_to(&bytes, peer.endpoint)
                    .await
                    .map_err(|e| FabricError::Transport(format!("udp send: {e}")))?;
                Ok(())
            }
            EncapAction::Queued => Ok(()),
            EncapAction::Error(e) => Err(FabricError::Transport(format!(
                "boringtun encapsulate error: {e}"
            ))),
        }
    }
}

enum EncapAction {
    SendBytes(Vec<u8>),
    Queued,
    Error(String),
}

#[async_trait]
impl MeshFabric for WireGuardFabric {
    async fn send(&self, dst: Ipv6Addr, msg: AppMessage) -> Result<(), FabricError> {
        // Local endpoint? Deliver via mpsc, same shape as
        // InProcess/Loopback fabrics — no encryption needed.
        if let Some(entry) = self.inner.endpoints.get(&dst) {
            return entry
                .tx
                .send((dst, msg))
                .map_err(|e| FabricError::Transport(e.to_string()));
        }

        // Remote? Look up the routing table and forward.
        let node_id = self
            .inner
            .remote_routes
            .get(&dst)
            .map(|kv| kv.value().clone());
        if let Some(node_id) = node_id {
            return self.send_remote(&node_id, dst, &msg).await;
        }

        Err(FabricError::NoRoute(dst))
    }

    async fn register_local(
        &self,
        ula: Ipv6Addr,
        endpoint_id: String,
    ) -> Result<InboundRx, FabricError> {
        let (tx, rx) = mpsc::unbounded_channel();
        self.inner.endpoints.insert(
            ula,
            EndpointEntry {
                id: endpoint_id,
                tx,
            },
        );
        Ok(rx)
    }

    async fn unregister_local(&self, ula: Ipv6Addr) -> Result<(), FabricError> {
        self.inner.endpoints.remove(&ula);
        Ok(())
    }

    fn routing_snapshot(&self) -> RoutingSnapshot {
        let local_endpoints: Vec<_> = self
            .inner
            .endpoints
            .iter()
            .map(|kv| (*kv.key(), kv.value().id.clone()))
            .collect();
        let remote_routes: Vec<_> = self
            .inner
            .remote_routes
            .iter()
            .map(|kv| (*kv.key(), kv.value().clone()))
            .collect();
        RoutingSnapshot {
            local_endpoints,
            remote_routes,
        }
    }
}

/// Control-plane mutators — for symmetry with `LoopbackFabric` the
/// existing `MeshFabricMutators` trait carries `LoopbackPeerSpec`
/// values (peer endpoint only, no public key). A `WireGuardFabric`
/// needs the peer's public key too, so the mutator API as-is can't
/// fully register a `WireGuard` peer. The mutator implementation below
/// updates routes and drops sessions, but a WireGuard-aware
/// subscriber should call [`WireGuardFabric::add_wireguard_peer`] directly to
/// supply the public key.
///
/// This compromise keeps the trait stable across all three fabrics
/// while still letting the supervisor's existing
/// `mesh_routing_loop` drive route changes without an upcast.
impl MeshFabricMutators for WireGuardFabric {
    fn add_peer(&self, _peer: LoopbackPeerSpec) {
        // No-op — a `WireGuardFabric` needs a public key to bring up a
        // peer. Use [`WireGuardFabric::add_wireguard_peer`] instead.
        tracing::warn!(
            "WireGuardFabric::add_peer called via MeshFabricMutators — \
             use add_wireguard_peer to supply the public key"
        );
    }

    fn remove_peer(&self, node_id: &str) {
        self.inner.peers.remove(node_id);
    }

    fn add_remote_route(&self, ula: Ipv6Addr, node_id: String) {
        Self::add_remote_route(self, ula, node_id);
    }

    fn remove_remote_route(&self, ula: Ipv6Addr) {
        Self::remove_remote_route(self, ula);
    }
}
