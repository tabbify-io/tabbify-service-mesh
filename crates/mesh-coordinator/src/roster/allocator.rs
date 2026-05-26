//! Multi-network ULA allocator for overlay peers.
//!
//! Layout (spec §6): `fd5a:1f<magic>:<network16>:<idx>::1`.
//!
//! - `fd5a:1f` — constant ULA prefix.
//! - `<magic>` — per-cluster magic byte (fixed at `0x00` here; the
//!   coordinator serves one cluster).
//! - `<network16>` — 16-bit block selector derived from the node's
//!   `network` value (a tag/claim, §6). Different networks land in
//!   disjoint blocks, so addresses never overlap across networks.
//! - `<idx>` — sequential peer index *within* a network, starting at 1.
//!
//! Each network gets its own independent `<idx>` counter, so two networks
//! can both have a peer at index 1 without address collision (the
//! `<network16>` hextet differs). The allocator is in-memory only —
//! coordinator restart resets every counter, matching the MVP "joiners
//! re-register on restart" contract.
//!
//! ## Network → `network16` mapping
//!
//! A `network` is a string (`"alice"`, `"tabbify-svc"`, ...). It is mapped
//! to a 16-bit block via [`network_slot`], an FNV-1a hash folded to 16
//! bits. The hash is **deterministic across builds** (unlike the std
//! `DefaultHasher`), so the same network name always selects the same
//! block — important because a network identifier must be stable across
//! coordinator restarts and deployments. The value `0` is reserved as the
//! "default / unnamed network" sentinel (empty network string maps there),
//! and any name that would hash to `0` is nudged to `1` so a named network
//! never silently shares the default block.

use dashmap::DashMap;
use std::net::Ipv6Addr;
use std::sync::atomic::{AtomicU16, Ordering};

/// Textual prefix shared by every ULA this allocator hands out.
///
/// Covers `fd5a:1f` plus the fixed `0x00` magic byte; the
/// `<network16>:<idx>` hextets follow. Useful for asserting layout in
/// tests without hardcoding the leading hextets again.
pub const ULA_PREFIX_LITERAL: &str = "fd5a:1f00:";

/// The `network16` block used for the default/unnamed network (empty
/// `network` string). Reserved so a named network never collides with it.
pub const DEFAULT_NETWORK_SLOT: u16 = 0;

/// Multi-network allocator state. Cheap to clone via the wrapping `Arc` in
/// the surrounding `Coordinator` (the `DashMap` is shared).
#[derive(Debug, Default)]
pub struct UlaAllocator {
    // network16 → next peer index within that network. AtomicU16 because
    // peer_index fits a u16 (≤65 535 peers per network is plenty) and the
    // atomic lets concurrent registers in the same network not collide.
    // The DashMap lets distinct networks have independent counters.
    per_network: DashMap<u16, AtomicU16>,
}

impl UlaAllocator {
    /// Fresh allocator with no networks yet seen.
    #[must_use]
    pub fn new() -> Self {
        Self {
            per_network: DashMap::new(),
        }
    }

    /// Reserve the next peer index within `network`'s block and the IPv6
    /// address it maps to.
    ///
    /// Returns `(peer_index, address)`. The index is per-network and
    /// starts at 1. Saturates at `u16::MAX` within a network — at that
    /// point allocation in that network refuses to hand out more.
    ///
    /// # Errors
    /// [`AllocError::Exhausted`] when the network's u16 index space is
    /// exhausted.
    pub fn allocate(&self, network: &str) -> Result<(u16, Ipv6Addr), AllocError> {
        let slot = network_slot(network);
        self.allocate_in_slot(slot)
    }

    /// Reserve the next index in an explicit `network16` slot. Lower-level
    /// entry-point used by replay (which already knows the slot from a
    /// stored ULA) and by [`Self::allocate`].
    ///
    /// # Errors
    /// [`AllocError::Exhausted`] when the slot's u16 index space is full.
    pub fn allocate_in_slot(&self, slot: u16) -> Result<(u16, Ipv6Addr), AllocError> {
        let counter = self
            .per_network
            .entry(slot)
            .or_insert_with(|| AtomicU16::new(0));
        // compare-exchange loop: refuse allocation past u16::MAX instead of
        // wrapping back to 0 (which would re-issue an existing ULA).
        loop {
            let current = counter.load(Ordering::Acquire);
            let Some(next) = current.checked_add(1) else {
                return Err(AllocError::Exhausted);
            };
            if counter
                .compare_exchange(current, next, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Ok((next, Self::address_for(slot, next)));
            }
        }
    }

    /// The IPv6 address for a `(network16, peer_index)` pair. Pure
    /// function — used when re-deriving an address from a stored slot+index
    /// without touching any counter.
    #[must_use]
    pub const fn address_for(slot: u16, peer_index: u16) -> Ipv6Addr {
        // fd5a:1f00:<slot>:<idx>::1 — magic byte fixed at 0x00.
        Ipv6Addr::new(0xfd5a, 0x1f00, slot, peer_index, 0, 0, 0, 1)
    }

    /// Number of indices already issued in `network`'s block. Inspection
    /// helper for tests + a future `/v1/mesh/stats` endpoint.
    #[must_use]
    pub fn issued(&self, network: &str) -> u16 {
        let slot = network_slot(network);
        self.per_network
            .get(&slot)
            .map_or(0, |c| c.load(Ordering::Acquire))
    }

    /// Advance a slot's counter to at least `idx` (monotonic — no-op if the
    /// current value is already `>= idx`).
    ///
    /// Used during replay so the allocator skips past indices that were
    /// already issued in a prior coordinator lifetime. The `slot` is taken
    /// straight from the stored ULA's `<network16>` hextet. Safe under
    /// concurrent advances: loses races where another thread bumped
    /// higher, never regresses.
    pub fn bump_slot_at_least(&self, slot: u16, idx: u16) {
        let counter = self
            .per_network
            .entry(slot)
            .or_insert_with(|| AtomicU16::new(0));
        let mut current = counter.load(Ordering::Acquire);
        while current < idx {
            match counter.compare_exchange(current, idx, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return,
                Err(now) => current = now,
            }
        }
    }
}

/// Map a `network` string to its 16-bit block selector.
///
/// Empty string → [`DEFAULT_NETWORK_SLOT`] (`0`). Otherwise an FNV-1a hash
/// folded to 16 bits, nudged off `0` so a named network never lands in the
/// default block. Deterministic across builds.
#[must_use]
pub fn network_slot(network: &str) -> u16 {
    if network.is_empty() {
        return DEFAULT_NETWORK_SLOT;
    }
    let h = fnv1a64(network.as_bytes());
    // Fold 64 → 16 bits by XORing the four 16-bit lanes; mask to the low
    // 16 bits so the conversion is lossless (no truncation lint).
    let folded = ((h >> 48) ^ (h >> 32) ^ (h >> 16) ^ h) & 0xffff;
    let folded = u16::try_from(folded).unwrap_or(0);
    if folded == DEFAULT_NETWORK_SLOT {
        1
    } else {
        folded
    }
}

/// FNV-1a 64-bit hash — deterministic across builds.
fn fnv1a64(bytes: &[u8]) -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut hash = OFFSET;
    for &b in bytes {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

/// Errors returned by the allocator.
#[derive(Debug, thiserror::Error)]
pub enum AllocError {
    /// All `u16::MAX` indices in a network's block have been issued.
    #[error("ULA index space exhausted ({max} peers per network)", max = u16::MAX)]
    Exhausted,
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn allocates_sequential_indices_from_one_per_network() {
        let alloc = UlaAllocator::new();
        let (i1, _) = alloc.allocate("alice").expect("first");
        let (i2, _) = alloc.allocate("alice").expect("second");
        let (i3, _) = alloc.allocate("alice").expect("third");
        assert_eq!((i1, i2, i3), (1, 2, 3));
    }

    #[test]
    fn distinct_addresses_per_peer_index() {
        let alloc = UlaAllocator::new();
        let (_, a1) = alloc.allocate("alice").expect("ok");
        let (_, a2) = alloc.allocate("alice").expect("ok");
        assert_ne!(a1, a2);
        assert!(a1.to_string().starts_with(ULA_PREFIX_LITERAL));
        assert!(a2.to_string().starts_with(ULA_PREFIX_LITERAL));
    }

    /// Different networks occupy disjoint blocks: their addresses never
    /// overlap, and each carries its own independent index counter.
    #[test]
    fn distinct_networks_get_disjoint_blocks() {
        let alloc = UlaAllocator::new();
        let (ia, addr_a) = alloc.allocate("alice").expect("alice");
        let (ib, addr_b) = alloc.allocate("bob").expect("bob");
        // Both are the first peer in their own network → both index 1.
        assert_eq!(ia, 1);
        assert_eq!(ib, 1);
        // ...but the <network16> hextet differs, so the addresses differ.
        assert_ne!(addr_a, addr_b);
        assert_ne!(
            addr_a.segments()[2],
            addr_b.segments()[2],
            "network slot hextet must differ for distinct networks",
        );
        // And the index lands in the 4th hextet within each block.
        assert_eq!(addr_a.segments()[3], 1);
        assert_eq!(addr_b.segments()[3], 1);
    }

    /// A peer's index is scoped to its network: allocating in network B
    /// does not advance network A's counter.
    #[test]
    fn per_network_counters_are_independent() {
        let alloc = UlaAllocator::new();
        let _ = alloc.allocate("alice").expect("a1");
        let _ = alloc.allocate("alice").expect("a2");
        let (ib, _) = alloc.allocate("bob").expect("b1");
        assert_eq!(ib, 1, "bob's first peer is index 1, unaffected by alice");
        assert_eq!(alloc.issued("alice"), 2);
        assert_eq!(alloc.issued("bob"), 1);
    }

    #[test]
    fn idx_stays_within_network_block() {
        let alloc = UlaAllocator::new();
        let slot = network_slot("svc");
        let (idx, addr) = alloc.allocate("svc").expect("ok");
        assert_eq!(
            addr.segments()[2],
            slot,
            "block hextet matches network slot"
        );
        assert_eq!(addr.segments()[3], idx, "idx hextet matches returned index");
    }

    #[test]
    fn empty_network_uses_default_slot() {
        assert_eq!(network_slot(""), DEFAULT_NETWORK_SLOT);
        let alloc = UlaAllocator::new();
        let (_, addr) = alloc.allocate("").expect("ok");
        assert_eq!(addr.segments()[2], DEFAULT_NETWORK_SLOT);
    }

    #[test]
    fn network_slot_is_deterministic() {
        assert_eq!(network_slot("alice"), network_slot("alice"));
        // Distinct names almost-certainly differ (and these two do).
        assert_ne!(network_slot("alice"), network_slot("bob"));
    }

    #[test]
    fn named_network_never_lands_in_default_slot() {
        // Sweep a batch of names; none may collide with the reserved 0.
        for i in 0..2000 {
            let name = format!("network-{i}");
            assert_ne!(
                network_slot(&name),
                DEFAULT_NETWORK_SLOT,
                "name {name} hit slot 0"
            );
        }
    }

    #[test]
    fn address_for_is_deterministic() {
        let a = UlaAllocator::address_for(7, 3);
        let b = UlaAllocator::address_for(7, 3);
        assert_eq!(a, b);
        assert_eq!(a.segments()[0], 0xfd5a);
        assert_eq!(a.segments()[1], 0x1f00);
        assert_eq!(a.segments()[2], 7);
        assert_eq!(a.segments()[3], 3);
        assert_eq!(a.segments()[7], 1);
    }

    #[test]
    fn issued_reflects_allocations() {
        let alloc = UlaAllocator::new();
        assert_eq!(alloc.issued("alice"), 0);
        let _ = alloc.allocate("alice").expect("ok");
        let _ = alloc.allocate("alice").expect("ok");
        assert_eq!(alloc.issued("alice"), 2);
    }

    #[test]
    fn bump_slot_at_least_is_monotonic() {
        let alloc = UlaAllocator::new();
        let slot = network_slot("alice");
        alloc.bump_slot_at_least(slot, 10);
        assert_eq!(alloc.issued("alice"), 10);
        // Lower value must not regress.
        alloc.bump_slot_at_least(slot, 5);
        assert_eq!(alloc.issued("alice"), 10);
        // Equal value is a no-op.
        alloc.bump_slot_at_least(slot, 10);
        assert_eq!(alloc.issued("alice"), 10);
        // Higher advances; next allocation continues from it.
        alloc.bump_slot_at_least(slot, 42);
        let (idx, _) = alloc.allocate("alice").expect("ok");
        assert_eq!(idx, 43);
    }
}
