//! Pure-Rust mesh fabric for unit tests. No syscalls, no sockets.
//!
//! Inbound delivery: each registered endpoint owns an unbounded mpsc
//! channel; [`MeshFabric::send`] looks up the channel by destination ULA
//! and forwards. The "source" address reported to the receiver is the
//! destination itself (there's no separate sender identity in
//! in-process mode — tests rarely need to distinguish).

use crate::loopback::LoopbackPeerSpec;
use crate::trait_def::{
    AppMessage, FabricError, InboundRx, MeshFabric, MeshFabricMutators, RoutingSnapshot,
};
use async_trait::async_trait;
use dashmap::DashMap;
use std::net::Ipv6Addr;
use std::sync::Arc;
use tokio::sync::mpsc;

/// In-process [`MeshFabric`] implementation. Cheap to clone.
#[derive(Clone)]
pub struct InProcessFabric {
    inner: Arc<Inner>,
}

struct Inner {
    endpoints: DashMap<Ipv6Addr, EndpointEntry>,
}

struct EndpointEntry {
    id: String,
    tx: mpsc::UnboundedSender<(Ipv6Addr, AppMessage)>,
}

impl InProcessFabric {
    /// Create an empty fabric.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Inner {
                endpoints: DashMap::new(),
            }),
        }
    }
}

impl Default for InProcessFabric {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl MeshFabric for InProcessFabric {
    async fn send(&self, dst: Ipv6Addr, msg: AppMessage) -> Result<(), FabricError> {
        let entry = self
            .inner
            .endpoints
            .get(&dst)
            .ok_or(FabricError::NoRoute(dst))?;
        entry
            .tx
            .send((dst, msg))
            .map_err(|e| FabricError::Transport(e.to_string()))
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
        RoutingSnapshot {
            local_endpoints,
            remote_routes: Vec::new(),
        }
    }
}

/// In-process fabric has no notion of remote peers — every mutator is a
/// no-op. Implementing the trait still lets callers wire the
/// `InProcessFabric` into APIs that expect [`MeshFabricMutators`] for
/// uniformity (e.g. the supervisor's mesh-routing subscriber).
impl MeshFabricMutators for InProcessFabric {
    fn add_peer(&self, _peer: LoopbackPeerSpec) {}

    fn remove_peer(&self, _node_id: &str) {}

    fn add_remote_route(&self, _ula: Ipv6Addr, _node_id: String) {}

    fn remove_remote_route(&self, _ula: Ipv6Addr) {}
}
