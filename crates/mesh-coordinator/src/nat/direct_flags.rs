//! Per-pair `direct` flags (Track A-a) — the instant on/off lever for direct
//! `WireGuard` between a specific pair, including a NAT-ed peer (MSI/Frankfurt).
//!
//! The 2026-06-07 contract suppresses direct (reflexive + punch) whenever
//! EITHER peer is `relay_only`. Track A-a relaxes that suppression for ONE
//! explicitly-flagged pair: when `is_direct(a, b)` is true the coordinator MAY
//! synthesize a reflexive endpoint + emit a punch for that pair even though a
//! peer is `relay_only`. EVERYTHING ELSE stays on the relay floor.
//!
//! The flag DEFAULTS OFF for every pair (relay is the floor) and is set only
//! via the admin-gated API (`MESH_ADMIN_TOKEN`). It is the rollback lever:
//! toggling it off instantly returns the pair to relay on the next heartbeat.
//! A coordinator restart drops the whole store → every pair returns to relay,
//! which is the SAFE direction (a restart never silently leaves a pair direct).

use crate::nat::holepunch::{PunchPair, canonical_pair};
use dashmap::DashMap;
use std::sync::Arc;
use uuid::Uuid;

/// In-memory per-pair direct-enable flags. Cheap clone (`Arc<DashMap>`).
#[derive(Default, Clone)]
pub struct DirectPairFlags {
    direct: Arc<DashMap<PunchPair, bool>>,
}

impl DirectPairFlags {
    /// Empty store — every pair defaults to relay (the floor).
    #[must_use]
    pub fn new() -> Self {
        Self {
            direct: Arc::new(DashMap::new()),
        }
    }

    /// `true` iff the (canonical) pair is explicitly enabled for direct WG.
    #[must_use]
    pub fn is_direct(&self, a: Uuid, b: Uuid) -> bool {
        self.direct.get(&canonical_pair(a, b)).is_some_and(|v| *v)
    }

    /// Set (or clear) the direct flag for a pair. `false` clears the entry so
    /// the pair returns to the relay floor.
    pub fn set_direct(&self, a: Uuid, b: Uuid, on: bool) {
        let key = canonical_pair(a, b);
        if on {
            self.direct.insert(key, true);
        } else {
            self.direct.remove(&key);
        }
    }

    /// Drop every flag involving `peer_id` (called on deregister/timeout so a
    /// departed peer leaves no stale direct enable behind).
    pub fn remove_peer(&self, peer_id: Uuid) {
        self.direct
            .retain(|&(a, b), _| a != peer_id && b != peer_id);
    }

    /// Number of pairs flagged direct (diagnostics + tests).
    #[must_use]
    pub fn len(&self) -> usize {
        self.direct.len()
    }

    /// Convenience predicate.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.direct.is_empty()
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use uuid::Uuid;

    /// A pair defaults to NOT direct (relay floor). Setting it direct flips the
    /// lookup; clearing returns it to the floor. Order-independent (canonical).
    #[test]
    fn direct_flag_defaults_off_and_toggles() {
        let flags = DirectPairFlags::new();
        let a = Uuid::from_u128(1);
        let b = Uuid::from_u128(2);
        assert!(!flags.is_direct(a, b), "a pair defaults to relay (not direct)");
        flags.set_direct(a, b, true);
        assert!(flags.is_direct(a, b), "set_direct(true) enables direct for the pair");
        // Canonical key: order-independent.
        assert!(flags.is_direct(b, a), "the flag is order-independent");
        flags.set_direct(a, b, false);
        assert!(!flags.is_direct(a, b), "clearing returns the pair to the relay floor");
    }

    /// Removing a peer clears every pair flag involving it (so a departed peer
    /// can't leave a stale `direct` enabling a future identity reuse).
    #[test]
    fn remove_peer_clears_its_direct_flags() {
        let flags = DirectPairFlags::new();
        let a = Uuid::from_u128(1);
        let b = Uuid::from_u128(2);
        let c = Uuid::from_u128(3);
        flags.set_direct(a, b, true);
        flags.set_direct(b, c, true);
        flags.remove_peer(a);
        assert!(!flags.is_direct(a, b), "a's pairs are cleared");
        assert!(flags.is_direct(b, c), "unrelated pairs survive");
    }
}
