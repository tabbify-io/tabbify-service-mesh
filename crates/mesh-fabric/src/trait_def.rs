//! `MeshFabric` trait — the abstraction over how app messages are routed
//! between local endpoints and remote peers.

use crate::loopback::LoopbackPeerSpec;
use async_trait::async_trait;
use std::net::Ipv6Addr;
use thiserror::Error;
use tokio::sync::mpsc;

/// Opaque per-message payload (an HTTP frame, gRPC message, etc.).
pub type AppMessage = Vec<u8>;

/// Receiver returned by [`MeshFabric::register_local`] — the application
/// drains inbound messages from this channel.
pub type InboundRx = mpsc::UnboundedReceiver<(Ipv6Addr, AppMessage)>;

/// Errors returned by mesh fabric operations.
#[derive(Debug, Error)]
pub enum FabricError {
    /// No route is known to the destination ULA — the address is neither
    /// registered locally nor mapped to a remote peer.
    #[error("no route to {0}")]
    NoRoute(Ipv6Addr),

    /// The underlying transport failed (e.g., channel closed,
    /// connection refused, TCP error in `LoopbackFabric`).
    #[error("transport: {0}")]
    Transport(String),

    /// The frame failed to encode or decode (only used by network-backed
    /// fabrics).
    #[error("encoding: {0}")]
    Encoding(String),
}

/// Pluggable mesh fabric: knows how to deliver a message to a ULA.
///
/// Implementations:
///   * [`crate::in_process::InProcessFabric`] — tokio channels (tests).
///   * `LoopbackFabric` — TCP loopback between processes on one host (Phase 4).
///   * `WireGuardFabric` — boringtun + cross-platform TUN device
///     (Phase 5; see [`crate::tun`] for the `utun`/`/dev/net/tun`
///     abstraction).
#[async_trait]
pub trait MeshFabric: Send + Sync + 'static {
    /// Send `msg` to the endpoint registered at `dst`. Returns
    /// [`FabricError::NoRoute`] if `dst` is unknown.
    async fn send(&self, dst: Ipv6Addr, msg: AppMessage) -> Result<(), FabricError>;

    /// Register a local endpoint at `ula` with the given identifier.
    /// Returns an unbounded mpsc receiver that delivers inbound messages
    /// addressed to this endpoint.
    async fn register_local(
        &self,
        ula: Ipv6Addr,
        endpoint_id: String,
    ) -> Result<InboundRx, FabricError>;

    /// Remove the local registration. Subsequent `send`s to the address
    /// will return [`FabricError::NoRoute`].
    async fn unregister_local(&self, ula: Ipv6Addr) -> Result<(), FabricError>;

    /// Debugging snapshot of the routing table.
    fn routing_snapshot(&self) -> RoutingSnapshot;
}

/// Debug-friendly view of a fabric's current routing state.
#[derive(Debug, Clone, Default)]
pub struct RoutingSnapshot {
    /// Endpoints registered locally on this node: `(ula, endpoint_id)`.
    pub local_endpoints: Vec<(Ipv6Addr, String)>,

    /// Remote routes: `(ula, peer_identifier)`. Always empty for
    /// `InProcessFabric`.
    pub remote_routes: Vec<(Ipv6Addr, String)>,
}

/// Mutator API for fabrics whose routing table is populated externally
/// (typically by a substrate event subscriber).
///
/// [`MeshFabric`] itself only exposes the data-plane (send, register
/// local endpoints). The control-plane operations — "I learned about a
/// new peer", "this remote ULA now lives behind that peer" — are kept
/// here so the subscriber can drive them through a single trait object
/// without depending on a concrete fabric implementation.
///
/// Implementations:
///   * [`crate::loopback::LoopbackFabric`] — performs the underlying
///     [`DashMap`](dashmap::DashMap) updates and drops cached
///     connections on peer changes.
///   * [`crate::in_process::InProcessFabric`] — every method is a no-op
///     (the in-process fabric has no notion of peers).
pub trait MeshFabricMutators: Send + Sync + 'static {
    /// Register or replace a peer's address.
    fn add_peer(&self, peer: LoopbackPeerSpec);
    /// Forget a peer. Any cached connection is dropped.
    fn remove_peer(&self, node_id: &str);
    /// Add or replace a route: messages addressed to `ula` are forwarded
    /// to the peer identified by `node_id`.
    fn add_remote_route(&self, ula: Ipv6Addr, node_id: String);
    /// Remove a remote route.
    fn remove_remote_route(&self, ula: Ipv6Addr);
}
