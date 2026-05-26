// Intentional pattern: we acquire the tunnel mutex, copy out the
// outbound bytes, and drop the mutex *before* awaiting socket I/O.
// Clippy's `significant_drop_tightening` lint flags this as "drop
// earlier" — but the whole point is that the lock is already held
// in the smallest possible scope (block-scoped binding).
#![allow(clippy::significant_drop_tightening)]

//! Userspace-`WireGuard` [`MeshFabric`] implementation backed by
//! Cloudflare's [`boringtun`] state machine.
//!
//! # Architecture
//!
//! Each `WireGuardFabric` owns one UDP socket bound to a configurable
//! address (typically `0.0.0.0:51820`). Outbound frames are wrapped in a
//! synthetic IPv6 header so boringtun's data-plane invariants hold
//! (`Tunn::encapsulate` expects valid IP datagrams; the response from
//! `decapsulate` is validated as IP), then encrypted via the per-peer
//! [`boringtun::noise::Tunn`] session and sent over UDP. The receiving
//! end reverses the process: decapsulate, strip the IPv6 header,
//! dispatch by destination ULA.
//!
//! The IPv6-wrapper is invisible to callers — the public surface matches
//! [`crate::loopback::LoopbackFabric`] exactly, so a substrate
//! supervisor that already drives the loopback fabric can switch to
//! `WireGuard` by swapping the constructor.
//!
//! # Two operating modes
//!
//! * **Pure UDP** — no kernel TUN device involved. Two
//!   `WireGuardFabric` instances exchange handshake packets and
//!   encrypted data frames over loopback UDP. Used by the unit tests
//!   in `tests/wireguard_udp.rs`.
//! * **TUN-integrated** — decapsulated packets are written to a
//!   kernel TUN device (`utun*` on macOS, `/dev/net/tun` on Linux)
//!   and packets read from the device are encapsulated and sent over
//!   UDP. Requires root / `CAP_NET_ADMIN`. The OS-specific kernel
//!   plumbing lives behind the cross-platform [`crate::tun`]
//!   abstraction — `WireGuardFabric` itself is OS-agnostic. Covered
//!   by the `#[ignore]` integration test `tests/wireguard_tun.rs`.

use crate::loopback::LoopbackPeerSpec;
use crate::trait_def::{
    AppMessage, FabricError, InboundRx, MeshFabric, MeshFabricMutators, RoutingSnapshot,
};
use async_trait::async_trait;
use boringtun::noise::{Tunn, TunnResult};
use dashmap::DashMap;
use rand_core::{OsRng, RngCore};
use std::net::{Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, mpsc};
use x25519_dalek::{PublicKey, StaticSecret};

/// Maximum encapsulated datagram size we'll ever read from UDP.
///
/// 9001 bytes is the default jumbo MTU on EC2 / Linode networks plus
/// generous `WireGuard` overhead. Anything larger is almost certainly
/// garbage or an attack.
const MAX_UDP_FRAME: usize = 9_001;

/// Size of an IPv6 header — boringtun validates decapsulated packets
/// as IP, so we synthesise a minimal IPv6 header in front of every
/// application payload.
const IPV6_HEADER_LEN: usize = 40;

/// Maximum app payload we'll wrap. The IPv6 length field is 16 bits,
/// so the absolute hard limit is `u16::MAX`. We also reserve enough
/// headroom for boringtun's 32-byte data overhead.
pub const MAX_APP_PAYLOAD: usize = (u16::MAX as usize) - 64;

/// X25519 keypair returned by [`generate_keypair`] and consumed by
/// [`WireGuardFabric::bind`].
#[derive(Clone)]
pub struct WireGuardKeypair {
    /// The X25519 secret. Treat as cryptographically sensitive — never
    /// log, never emit in events.
    pub private: StaticSecret,
    /// The X25519 public key. Safe to publish via the
    /// `node_pubkey_announced` substrate event.
    pub public: PublicKey,
}

impl std::fmt::Debug for WireGuardKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use std::fmt::Write as _;
        let mut pub_hex = String::with_capacity(64);
        for b in self.public.as_bytes() {
            write!(pub_hex, "{b:02x}").map_err(|_| std::fmt::Error)?;
        }
        f.debug_struct("WireGuardKeypair")
            .field("private", &"<redacted>")
            .field("public", &pub_hex)
            .finish()
    }
}

/// Generate a fresh X25519 keypair suitable for `WireGuard`. Pulls
/// entropy from the OS RNG.
#[must_use]
pub fn generate_keypair() -> WireGuardKeypair {
    let mut secret_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut secret_bytes);
    let private = StaticSecret::from(secret_bytes);
    let public = PublicKey::from(&private);
    WireGuardKeypair { private, public }
}

/// Specification of a remote `WireGuard` peer.
#[derive(Debug, Clone)]
pub struct WireGuardPeerSpec {
    /// Stable identifier of the peer (matches `local_node_id` on the
    /// remote `WireGuardFabric`).
    pub node_id: String,
    /// UDP endpoint where the peer is listening.
    pub endpoint: SocketAddr,
    /// The peer's X25519 public key — typically learned via a
    /// `node_pubkey_announced` substrate event.
    pub public_key: PublicKey,
}

/// Userspace-WireGuard [`MeshFabric`]. Cheap to clone — handles share
/// state via an internal `Arc`.
#[derive(Clone)]
pub struct WireGuardFabric {
    inner: Arc<Inner>,
}

struct Inner {
    local_node_id: String,
    local_addr: SocketAddr,
    /// Local private key — kept here for re-establishing sessions on
    /// peer changes.
    static_private: StaticSecret,
    /// Outbound UDP socket. The receive loop reads from a clone owned
    /// by the spawned task.
    socket: Arc<UdpSocket>,
    /// Local endpoint table: ULA -> mpsc sender that delivers inbound
    /// messages to the application.
    endpoints: DashMap<Ipv6Addr, EndpointEntry>,
    /// Routes to remote ULAs: ULA -> `node_id`.
    remote_routes: DashMap<Ipv6Addr, String>,
    /// Per-peer encryption state. Wrapped in a tokio Mutex so the
    /// async send + receive halves can serialise access without
    /// holding a guard across UDP I/O.
    peers: DashMap<String, Arc<PeerState>>,
}

struct PeerState {
    endpoint: SocketAddr,
    /// Retained for debugging / future rekey flows even though the
    /// data-plane reads it only via the encapsulated `Tunn`.
    #[allow(dead_code)]
    public_key: PublicKey,
    tunn: Mutex<Tunn>,
}

struct EndpointEntry {
    #[allow(dead_code)]
    id: String,
    tx: mpsc::UnboundedSender<(Ipv6Addr, AppMessage)>,
}

impl WireGuardFabric {
    /// Bind a fabric instance to `local_addr` (typically
    /// `0.0.0.0:51820` or `127.0.0.1:0` for tests). Spawns a background
    /// tokio task that reads inbound UDP datagrams and dispatches them
    /// to local endpoints.
    ///
    /// `local_node_id` is the stable identifier this fabric uses when
    /// announcing itself to peers.
    pub async fn bind(
        local_addr: SocketAddr,
        local_node_id: String,
        static_private: StaticSecret,
    ) -> Result<Self, FabricError> {
        let socket = UdpSocket::bind(local_addr)
            .await
            .map_err(|e| FabricError::Transport(format!("udp bind {local_addr}: {e}")))?;
        let bound_addr = socket
            .local_addr()
            .map_err(|e| FabricError::Transport(format!("udp local_addr: {e}")))?;
        let socket = Arc::new(socket);

        let inner = Arc::new(Inner {
            local_node_id: local_node_id.clone(),
            local_addr: bound_addr,
            static_private,
            socket: Arc::clone(&socket),
            endpoints: DashMap::new(),
            remote_routes: DashMap::new(),
            peers: DashMap::new(),
        });

        tokio::spawn(receive_loop(socket, Arc::clone(&inner)));
        tokio::spawn(timer_loop(Arc::clone(&inner)));

        tracing::info!(
            node_id = %local_node_id,
            addr = %bound_addr,
            "WireGuardFabric bound"
        );

        Ok(Self { inner })
    }

    /// The actual bound UDP socket address (useful when `bind` was
    /// called with port `0`).
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.inner.local_addr
    }

    /// The stable identifier this fabric uses when announcing itself.
    #[must_use]
    pub fn local_node_id(&self) -> &str {
        &self.inner.local_node_id
    }

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
        let state = Arc::new(PeerState {
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
                let tunn = peer.tunn.lock().await;
                if tunn.time_since_last_handshake().is_some() {
                    return Ok(());
                }
            }
            if tokio::time::Instant::now() >= deadline {
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
/// subscriber should call [`Self::add_wireguard_peer`] directly to
/// supply the public key.
///
/// This compromise keeps the trait stable across all three fabrics
/// while still letting the supervisor's existing
/// `mesh_routing_loop` drive route changes without an upcast.
impl MeshFabricMutators for WireGuardFabric {
    fn add_peer(&self, _peer: LoopbackPeerSpec) {
        // No-op — a `WireGuardFabric` needs a public key to bring up a
        // peer. Use [`Self::add_wireguard_peer`] instead.
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

// -----------------------------------------------------------------------------
// IPv6 framing helpers
// -----------------------------------------------------------------------------

/// Build a minimal IPv6 packet wrapping `payload`. The resulting
/// bytes are accepted by boringtun's data-plane validation.
///
/// Layout (RFC 8200):
/// ```text
/// [0]      Version (4) | Traffic Class High (4)  = 0x60
/// [1]      Traffic Class Low (4) | Flow Label H (4)
/// [2-3]    Flow Label (low 16 bits)
/// [4-5]    Payload length (big-endian u16)
/// [6]      Next header (59 = no next header)
/// [7]      Hop limit
/// [8-23]   Source address
/// [24-39]  Destination address
/// [40..]   Payload
/// ```
fn build_ipv6_packet(src: Ipv6Addr, dst: Ipv6Addr, payload: &[u8]) -> Result<Vec<u8>, FabricError> {
    let payload_len: u16 = u16::try_from(payload.len())
        .map_err(|_| FabricError::Encoding(format!("payload {} > u16::MAX", payload.len())))?;
    let mut out = Vec::with_capacity(IPV6_HEADER_LEN + payload.len());
    // version = 6, TC = 0, FL = 0
    out.push(0x60);
    out.push(0x00);
    out.push(0x00);
    out.push(0x00);
    // payload length (big-endian)
    out.extend_from_slice(&payload_len.to_be_bytes());
    // next header = 59 (no next header — payload is opaque)
    out.push(59);
    // hop limit = 64
    out.push(64);
    out.extend_from_slice(&src.octets());
    out.extend_from_slice(&dst.octets());
    out.extend_from_slice(payload);
    Ok(out)
}

/// Strip the IPv6 header. Returns `(src, dst, payload)` on success.
fn parse_ipv6_packet(bytes: &[u8]) -> Result<(Ipv6Addr, Ipv6Addr, Vec<u8>), FabricError> {
    if bytes.len() < IPV6_HEADER_LEN {
        return Err(FabricError::Encoding(format!(
            "ipv6 packet too short: {}",
            bytes.len()
        )));
    }
    if bytes[0] >> 4 != 6 {
        return Err(FabricError::Encoding(format!(
            "not an ipv6 packet (version nibble = {})",
            bytes[0] >> 4
        )));
    }
    let payload_len = u16::from_be_bytes([bytes[4], bytes[5]]) as usize;
    if bytes.len() < IPV6_HEADER_LEN + payload_len {
        return Err(FabricError::Encoding(format!(
            "ipv6 length field {} exceeds available {} bytes",
            payload_len,
            bytes.len() - IPV6_HEADER_LEN
        )));
    }
    let mut src_bytes = [0u8; 16];
    let mut dst_bytes = [0u8; 16];
    src_bytes.copy_from_slice(&bytes[8..24]);
    dst_bytes.copy_from_slice(&bytes[24..40]);
    let src = Ipv6Addr::from(src_bytes);
    let dst = Ipv6Addr::from(dst_bytes);
    let payload = bytes[IPV6_HEADER_LEN..IPV6_HEADER_LEN + payload_len].to_vec();
    Ok((src, dst, payload))
}

// -----------------------------------------------------------------------------
// Background tasks
// -----------------------------------------------------------------------------

/// UDP receive loop — drains the socket and feeds bytes into the
/// matching peer's `Tunn` session.
async fn receive_loop(socket: Arc<UdpSocket>, inner: Arc<Inner>) {
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
async fn timer_loop(inner: Arc<Inner>) {
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

// -----------------------------------------------------------------------------
// Unsafe-code escape: we don't use `unsafe` in this module. The
// `unused_imports` warn is set workspace-wide; suppress the
// pub-export warning explicitly:
// -----------------------------------------------------------------------------

/// Re-export of [`PublicKey`] for downstream crates that want to type
/// peer specs without depending on x25519-dalek directly.
pub use x25519_dalek::PublicKey as PeerPublicKey;
/// Re-export of [`StaticSecret`] for downstream crates that need to
/// load private keys from disk and pass them to [`WireGuardFabric::bind`].
pub use x25519_dalek::StaticSecret as PeerStaticSecret;

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn ipv6_packet_roundtrip_preserves_payload() {
        let src: Ipv6Addr = "fd5a:1f00:0001::1".parse().unwrap();
        let dst: Ipv6Addr = "fd5a:1f00:0001::2".parse().unwrap();
        let payload = b"hello world";
        let packet = build_ipv6_packet(src, dst, payload).unwrap();
        let (parsed_src, parsed_dst, parsed_payload) = parse_ipv6_packet(&packet).unwrap();
        assert_eq!(parsed_src, src);
        assert_eq!(parsed_dst, dst);
        assert_eq!(parsed_payload, payload);
    }

    #[test]
    fn ipv6_packet_rejects_short_input() {
        let err = parse_ipv6_packet(&[0u8; 10]).unwrap_err();
        assert!(matches!(err, FabricError::Encoding(_)));
    }

    #[test]
    fn ipv6_packet_rejects_wrong_version() {
        let mut bytes = vec![0u8; IPV6_HEADER_LEN];
        bytes[0] = 0x40; // ipv4 nibble
        let err = parse_ipv6_packet(&bytes).unwrap_err();
        assert!(matches!(err, FabricError::Encoding(_)));
    }

    #[test]
    fn ipv6_packet_rejects_length_mismatch() {
        let mut packet =
            build_ipv6_packet(Ipv6Addr::UNSPECIFIED, Ipv6Addr::UNSPECIFIED, b"x").unwrap();
        // Truncate the payload byte.
        packet.truncate(IPV6_HEADER_LEN);
        let err = parse_ipv6_packet(&packet).unwrap_err();
        assert!(matches!(err, FabricError::Encoding(_)));
    }

    #[test]
    fn generate_keypair_produces_distinct_keys_each_call() {
        let kp1 = generate_keypair();
        let kp2 = generate_keypair();
        assert_ne!(kp1.public.as_bytes(), kp2.public.as_bytes());
    }
}
