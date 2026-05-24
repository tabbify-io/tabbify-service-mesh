//! TCP loopback [`MeshFabric`] — bridges app messages between processes on
//! the same host without `WireGuard`.
//!
//! Each `LoopbackFabric` instance binds a TCP listener on `127.0.0.1:<port>`
//! and maintains:
//!
//!   * a [`DashMap`] of locally-registered ULAs (mirrors
//!     [`crate::in_process::InProcessFabric`]),
//!   * a [`DashMap`] of remote routes — `ULA -> peer node_id`,
//!   * a [`DashMap`] of peer specs — `node_id -> SocketAddr`, and
//!   * a connection pool keyed by `node_id`. Connections are opened
//!     lazily on first send and re-opened on broken pipe.
//!
//! Frame format on the wire:
//!
//! ```text
//! [ 8 bytes  ] little-endian u64 — frame body length (header + payload)
//! [ 16 bytes ] destination ULA (raw IPv6 octets)
//! [ 16 bytes ] source ULA (raw IPv6 octets; senders fill best-effort)
//! [ N bytes  ] AppMessage payload
//! ```
//!
//! The header is 32 bytes; the body length field encodes header + payload.
//! Frames whose advertised length exceeds [`MAX_FRAME_BODY`] are rejected
//! to guard against runaway allocations.

use crate::trait_def::{
    AppMessage, FabricError, InboundRx, MeshFabric, MeshFabricMutators, RoutingSnapshot,
};
use async_trait::async_trait;
use dashmap::DashMap;
use std::net::{Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};

/// Maximum frame body length (header + payload), in bytes. Frames
/// advertising more than this are rejected and the connection is closed.
pub const MAX_FRAME_BODY: usize = 4 * 1024 * 1024;

/// Size of the frame header (dst ULA + src ULA, 16 bytes each).
const HEADER_LEN: usize = 32;

/// Specification of a peer node reachable from this fabric.
#[derive(Debug, Clone)]
pub struct LoopbackPeerSpec {
    /// Stable identifier of the remote node. Matches the `local_node_id`
    /// the peer used in [`LoopbackFabric::bind`].
    pub node_id: String,
    /// Loopback socket address the peer is listening on (e.g.
    /// `127.0.0.1:54123`).
    pub addr: SocketAddr,
}

/// TCP-loopback [`MeshFabric`]. Cheap to clone — handles share state via
/// an internal `Arc`.
#[derive(Clone)]
pub struct LoopbackFabric {
    inner: Arc<Inner>,
}

struct Inner {
    local_node_id: String,
    local_addr: SocketAddr,
    /// Local registrations: ULA -> endpoint entry.
    endpoints: DashMap<Ipv6Addr, EndpointEntry>,
    /// Routes to remote ULAs: ULA -> `node_id`.
    remote_routes: DashMap<Ipv6Addr, String>,
    /// Known peers: `node_id` -> socket address.
    peers: DashMap<String, SocketAddr>,
    /// Cached outbound TCP connections, keyed by `node_id`.
    connections: Mutex<std::collections::HashMap<String, Arc<Mutex<TcpStream>>>>,
}

struct EndpointEntry {
    id: String,
    tx: mpsc::UnboundedSender<(Ipv6Addr, AppMessage)>,
}

impl LoopbackFabric {
    /// Bind a fabric instance to `local_addr` (typically `127.0.0.1:0` to
    /// let the OS choose a port) with the stable identifier
    /// `local_node_id`. Spawns a background tokio task that accepts
    /// inbound TCP connections and dispatches frames to local endpoints.
    pub async fn bind(
        local_addr: SocketAddr,
        local_node_id: String,
    ) -> Result<Self, FabricError> {
        let listener = TcpListener::bind(local_addr)
            .await
            .map_err(|e| FabricError::Transport(format!("bind {local_addr}: {e}")))?;
        let bound_addr = listener
            .local_addr()
            .map_err(|e| FabricError::Transport(format!("local_addr: {e}")))?;

        let inner = Arc::new(Inner {
            local_node_id: local_node_id.clone(),
            local_addr: bound_addr,
            endpoints: DashMap::new(),
            remote_routes: DashMap::new(),
            peers: DashMap::new(),
            connections: Mutex::new(std::collections::HashMap::new()),
        });

        tokio::spawn(accept_loop(listener, Arc::clone(&inner)));

        tracing::info!(
            node_id = %local_node_id,
            addr = %bound_addr,
            "LoopbackFabric bound"
        );

        Ok(Self { inner })
    }

    /// Returns the actual bound socket address. Useful when `bind` was
    /// called with port `0` and the caller needs to advertise the
    /// OS-assigned port to peers.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.inner.local_addr
    }

    /// The stable identifier this fabric uses when announcing itself.
    #[must_use]
    pub fn local_node_id(&self) -> &str {
        &self.inner.local_node_id
    }

    /// Register or replace a peer's address.
    pub fn add_peer(&self, peer: LoopbackPeerSpec) {
        // Drop any cached connection — the peer may have moved.
        let node_id = peer.node_id.clone();
        let inner = Arc::clone(&self.inner);
        self.inner.peers.insert(peer.node_id, peer.addr);
        tokio::spawn(async move {
            inner.connections.lock().await.remove(&node_id);
        });
    }

    /// Remove a peer. Any cached connection is dropped.
    pub fn remove_peer(&self, node_id: &str) {
        self.inner.peers.remove(node_id);
        let node_id = node_id.to_owned();
        let inner = Arc::clone(&self.inner);
        tokio::spawn(async move {
            inner.connections.lock().await.remove(&node_id);
        });
    }

    /// Add or replace a route: messages addressed to `ula` are forwarded
    /// to the peer identified by `node_id`. The peer must have been
    /// registered via [`Self::add_peer`] before the next `send` to `ula`.
    pub fn add_remote_route(&self, ula: Ipv6Addr, node_id: String) {
        self.inner.remote_routes.insert(ula, node_id);
    }

    /// Remove a remote route.
    pub fn remove_remote_route(&self, ula: Ipv6Addr) {
        self.inner.remote_routes.remove(&ula);
    }

    async fn send_remote(
        &self,
        node_id: &str,
        dst: Ipv6Addr,
        msg: &[u8],
    ) -> Result<(), FabricError> {
        let addr = self
            .inner
            .peers
            .get(node_id)
            .map(|kv| *kv.value())
            .ok_or_else(|| {
                FabricError::Transport(format!("peer {node_id} has no registered address"))
            })?;

        let frame = encode_frame(dst, fallback_source_ula(), msg)?;

        // First attempt — use a cached connection if available, otherwise
        // open one.
        let conn = self.get_or_open_connection(node_id, addr).await?;
        match write_all(&conn, &frame).await {
            Ok(()) => Ok(()),
            Err(first_err) => {
                // Broken pipe / reset / closed — drop cache and retry once.
                self.drop_connection(node_id).await;
                tracing::debug!(
                    node_id, error = %first_err,
                    "loopback peer write failed; reopening connection"
                );
                let conn = self.get_or_open_connection(node_id, addr).await?;
                write_all(&conn, &frame)
                    .await
                    .map_err(|e| FabricError::Transport(format!("peer write: {e}")))
            }
        }
    }

    async fn get_or_open_connection(
        &self,
        node_id: &str,
        addr: SocketAddr,
    ) -> Result<Arc<Mutex<TcpStream>>, FabricError> {
        {
            let pool = self.inner.connections.lock().await;
            if let Some(existing) = pool.get(node_id) {
                return Ok(Arc::clone(existing));
            }
        }
        let stream = TcpStream::connect(addr).await.map_err(|e| {
            FabricError::Transport(format!("connect {node_id} ({addr}): {e}"))
        })?;
        if let Err(e) = stream.set_nodelay(true) {
            tracing::debug!(node_id, error = %e, "set_nodelay failed");
        }
        let arc = Arc::new(Mutex::new(stream));
        {
            let mut pool = self.inner.connections.lock().await;
            // Race: another caller may have inserted concurrently. Prefer
            // the existing entry to keep the pool single-owner per node.
            if let Some(existing) = pool.get(node_id) {
                return Ok(Arc::clone(existing));
            }
            pool.insert(node_id.to_owned(), Arc::clone(&arc));
        }
        Ok(arc)
    }

    async fn drop_connection(&self, node_id: &str) {
        self.inner.connections.lock().await.remove(node_id);
    }
}

#[async_trait]
impl MeshFabric for LoopbackFabric {
    async fn send(&self, dst: Ipv6Addr, msg: AppMessage) -> Result<(), FabricError> {
        // Local endpoint? Deliver via mpsc (same shape as InProcessFabric).
        if let Some(entry) = self.inner.endpoints.get(&dst) {
            return entry
                .tx
                .send((dst, msg))
                .map_err(|e| FabricError::Transport(e.to_string()));
        }

        // Remote? Look up the routing table and forward. The DashMap
        // guard is dropped before awaiting the I/O.
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
            .map(|kv| (*kv.key(), kv.id.clone()))
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

/// Control-plane API: delegates straight to the inherent mutator methods
/// so an external subscriber (typically the supervisor's
/// `mesh_routing_loop`) can drive the routing table through a single
/// trait object without depending on the concrete fabric type.
impl MeshFabricMutators for LoopbackFabric {
    fn add_peer(&self, peer: LoopbackPeerSpec) {
        Self::add_peer(self, peer);
    }

    fn remove_peer(&self, node_id: &str) {
        Self::remove_peer(self, node_id);
    }

    fn add_remote_route(&self, ula: Ipv6Addr, node_id: String) {
        Self::add_remote_route(self, ula, node_id);
    }

    fn remove_remote_route(&self, ula: Ipv6Addr) {
        Self::remove_remote_route(self, ula);
    }
}

/// Best-effort source ULA when the sender hasn't supplied one. The
/// in-process fabric reports `dst` as the "source" for symmetry; here we
/// follow the spec and emit the unspecified address. The downstream
/// receiver doesn't currently use the source field — it's reserved for
/// future use (P5 `WireGuard` fabric will populate it from the local ULA).
const fn fallback_source_ula() -> Ipv6Addr {
    Ipv6Addr::UNSPECIFIED
}

fn encode_frame(dst: Ipv6Addr, src: Ipv6Addr, payload: &[u8]) -> Result<Vec<u8>, FabricError> {
    let body_len = HEADER_LEN.checked_add(payload.len()).ok_or_else(|| {
        FabricError::Encoding(format!("payload too large: {}", payload.len()))
    })?;
    if body_len > MAX_FRAME_BODY {
        return Err(FabricError::Encoding(format!(
            "frame body {body_len} exceeds max {MAX_FRAME_BODY}"
        )));
    }
    let body_len_u64 = u64::try_from(body_len)
        .map_err(|e| FabricError::Encoding(format!("body_len conversion: {e}")))?;

    let mut out = Vec::with_capacity(8 + body_len);
    out.extend_from_slice(&body_len_u64.to_le_bytes());
    out.extend_from_slice(&dst.octets());
    out.extend_from_slice(&src.octets());
    out.extend_from_slice(payload);
    Ok(out)
}

async fn write_all(conn: &Arc<Mutex<TcpStream>>, bytes: &[u8]) -> std::io::Result<()> {
    let mut guard = conn.lock().await;
    guard.write_all(bytes).await?;
    guard.flush().await
}

async fn accept_loop(listener: TcpListener, inner: Arc<Inner>) {
    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                tracing::debug!(node_id = %inner.local_node_id, %peer_addr, "inbound conn");
                tokio::spawn(handle_connection(stream, Arc::clone(&inner)));
            }
            Err(e) => {
                tracing::warn!(node_id = %inner.local_node_id, error = %e, "accept failed");
                // Brief pause to avoid a tight error loop on repeated failures.
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        }
    }
}

async fn handle_connection(mut stream: TcpStream, inner: Arc<Inner>) {
    loop {
        match read_frame(&mut stream).await {
            Ok(Some((dst, _src, payload))) => {
                if let Some(entry) = inner.endpoints.get(&dst) {
                    if let Err(e) = entry.tx.send((dst, payload)) {
                        tracing::trace!(
                            node_id = %inner.local_node_id,
                            %dst, error = %e,
                            "local endpoint receiver dropped — frame dropped"
                        );
                    }
                } else {
                    tracing::trace!(
                        node_id = %inner.local_node_id,
                        %dst,
                        "inbound frame for unknown local ULA — dropped"
                    );
                }
            }
            Ok(None) => {
                tracing::trace!(node_id = %inner.local_node_id, "peer closed connection");
                return;
            }
            Err(e) => {
                tracing::debug!(
                    node_id = %inner.local_node_id,
                    error = %e,
                    "inbound frame decode failed; closing connection"
                );
                return;
            }
        }
    }
}

async fn read_frame(
    stream: &mut TcpStream,
) -> std::io::Result<Option<(Ipv6Addr, Ipv6Addr, AppMessage)>> {
    let mut len_buf = [0u8; 8];
    match stream.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let body_len = u64::from_le_bytes(len_buf);
    let body_len_usize = usize::try_from(body_len).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("body_len overflows usize: {e}"),
        )
    })?;
    if body_len_usize < HEADER_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("body_len {body_len_usize} < header {HEADER_LEN}"),
        ));
    }
    if body_len_usize > MAX_FRAME_BODY {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("body_len {body_len_usize} > max {MAX_FRAME_BODY}"),
        ));
    }

    let mut header = [0u8; HEADER_LEN];
    stream.read_exact(&mut header).await?;
    let mut dst_bytes = [0u8; 16];
    let mut src_bytes = [0u8; 16];
    dst_bytes.copy_from_slice(&header[..16]);
    src_bytes.copy_from_slice(&header[16..]);
    let dst = Ipv6Addr::from(dst_bytes);
    let src = Ipv6Addr::from(src_bytes);

    let payload_len = body_len_usize - HEADER_LEN;
    let mut payload = vec![0u8; payload_len];
    if payload_len > 0 {
        stream.read_exact(&mut payload).await?;
    }
    Ok(Some((dst, src, payload)))
}
