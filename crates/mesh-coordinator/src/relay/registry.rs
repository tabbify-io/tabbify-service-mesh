//! Ephemeral pubkey → live relay WS connection registry.

use dashmap::DashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::mpsc;

struct RelayConn {
    id: u64,
    tx: mpsc::UnboundedSender<Vec<u8>>,
}

/// Ephemeral pubkey → live-WS registry. Keyed by the RAW 32-byte X25519
/// pubkey, exactly like `Inner.by_pubkey`. Cheap to clone (Arc inside).
/// NOT event-sourced — a live socket can't be replayed.
#[derive(Clone, Default)]
pub struct RelayRegistry {
    conns: Arc<DashMap<Vec<u8>, RelayConn>>,
    next_id: Arc<AtomicU64>,
}

impl RelayRegistry {
    /// Empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a connection's sender under `pubkey` (last connection wins).
    /// Returns a unique id used for matched cleanup.
    pub fn register(&self, pubkey: Vec<u8>, tx: mpsc::UnboundedSender<Vec<u8>>) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.conns.insert(pubkey, RelayConn { id, tx });
        id
    }

    /// Forward a fully-encoded downlink frame to `pubkey`. Returns `true`
    /// when a live sender accepted it. Clones the sender out and drops the
    /// shard guard before sending (mpsc send is sync, but keep the pattern).
    #[must_use]
    pub fn forward(&self, pubkey: &[u8], frame: Vec<u8>) -> bool {
        let Some(tx) = self.conns.get(pubkey).map(|c| c.tx.clone()) else {
            return false;
        };
        tx.send(frame).is_ok()
    }

    /// Remove the entry only if it is still the connection with `id`
    /// (avoids racing a newer reconnect that replaced it).
    pub fn unregister(&self, pubkey: &[u8], id: u64) {
        self.conns.remove_if(pubkey, |_, c| c.id == id);
    }

    /// Remove any connection for `pubkey` (peer left the roster).
    pub fn drop_pubkey(&self, pubkey: &[u8]) {
        self.conns.remove(pubkey);
    }

    /// Number of live connections tracked.
    #[must_use]
    pub fn len(&self) -> usize {
        self.conns.len()
    }

    /// Convenience predicate.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.conns.is_empty()
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    #[test]
    fn register_returns_increasing_ids() {
        let reg = RelayRegistry::new();
        let (tx_a, _rx_a) = mpsc::unbounded_channel();
        let (tx_b, _rx_b) = mpsc::unbounded_channel();
        let id_a = reg.register(vec![1u8; 32], tx_a);
        let id_b = reg.register(vec![2u8; 32], tx_b);
        assert!(id_b > id_a, "ids must strictly increase");
    }

    #[test]
    fn forward_delivers_to_registered_pubkey() {
        let reg = RelayRegistry::new();
        let (tx, mut rx) = mpsc::unbounded_channel();
        reg.register(vec![9u8; 32], tx);
        assert!(reg.forward(&[9u8; 32], vec![1, 2, 3]));
        assert_eq!(rx.try_recv().expect("frame delivered"), vec![1, 2, 3]);
    }

    #[test]
    fn forward_to_unknown_pubkey_is_false() {
        let reg = RelayRegistry::new();
        assert!(!reg.forward(&[0u8; 32], vec![1, 2, 3]));
    }

    #[test]
    fn unregister_only_removes_matching_id() {
        let reg = RelayRegistry::new();
        let (tx_old, _rx_old) = mpsc::unbounded_channel();
        let old_id = reg.register(vec![5u8; 32], tx_old);
        // A newer connection replaces the entry under the same pubkey.
        let (tx_new, mut rx_new) = mpsc::unbounded_channel();
        let _new_id = reg.register(vec![5u8; 32], tx_new);
        // Unregistering the OLD id must be a no-op (the new conn still wins).
        reg.unregister(&[5u8; 32], old_id);
        assert!(reg.forward(&[5u8; 32], vec![7]));
        assert_eq!(rx_new.try_recv().expect("new conn still live"), vec![7]);
    }

    #[test]
    fn drop_pubkey_removes_unconditionally() {
        let reg = RelayRegistry::new();
        let (tx, _rx) = mpsc::unbounded_channel();
        reg.register(vec![3u8; 32], tx);
        assert_eq!(reg.len(), 1);
        reg.drop_pubkey(&[3u8; 32]);
        assert!(reg.is_empty());
        assert!(!reg.forward(&[3u8; 32], vec![1]));
    }
}
