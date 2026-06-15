//! Ephemeral pubkey → live relay WS connection registry.

use dashmap::DashMap;
use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// Per-peer live connection. Two send channels feed the SAME WS, drained by a
/// biased send task that empties `hi` before `lo`: `WireGuard` HANDSHAKE/cookie
/// frames go to `hi`, bulk transport DATA to `lo`. Without this, a saturated
/// bulk download (e.g. a multi-MB OCI image pull) fills the single FIFO and
/// STARVES the peer's rekey handshake response behind thousands of data frames
/// → `REKEY_TIMEOUT` at the ~2-min rekey → the tunnel (and the long transfer)
/// dies. Prioritising handshakes lets the rekey complete mid-transfer.
struct RelayConn {
    id: u64,
    hi: mpsc::UnboundedSender<Vec<u8>>,
    lo: mpsc::UnboundedSender<Vec<u8>>,
}

/// A frame held for a pubkey that had no live connection at send time, tagged
/// with the priority it must flush to on (re)register.
struct SpooledFrame {
    at: Instant,
    hi_prio: bool,
    frame: Vec<u8>,
}

/// Max frames spooled per destination pubkey before the oldest is evicted.
/// Tight on purpose: the spool only bridges the sub-second registration race
/// right after a peer reconnects (its WS upgrade landing a few hundred ms
/// AFTER the first handshake frame already arrived for it), not a real
/// backlog. Memory ceiling is `SPOOL_CAP * live-races * frame_size`.
const SPOOL_CAP: usize = 16;

/// How long a spooled frame stays deliverable. A `WireGuard` handshake init is
/// useless after a couple of seconds (boringtun's `REKEY` window), so anything
/// older is dropped rather than delivered stale.
const SPOOL_TTL: Duration = Duration::from_secs(2);

/// Ephemeral pubkey → live-WS registry. Keyed by the RAW 32-byte X25519
/// pubkey, exactly like `Inner.by_pubkey`. Cheap to clone (Arc inside).
/// NOT event-sourced — a live socket can't be replayed.
#[derive(Clone, Default)]
pub struct RelayRegistry {
    conns: Arc<DashMap<Vec<u8>, RelayConn>>,
    /// Frames briefly held for a pubkey that has no *currently* live
    /// connection, flushed the instant it (re)registers. This turns the
    /// post-reconnect registration race — a handshake-init that lands a few
    /// hundred ms before the destination's relay WS re-upgrades — from a
    /// SILENT FRAME DROP (which left boringtun retrying forever, the
    /// `REKEY_TIMEOUT` storm) into a recoverable hiccup that converges on the
    /// first attempt. Bounded by [`SPOOL_CAP`] + [`SPOOL_TTL`].
    spool: Arc<DashMap<Vec<u8>, VecDeque<SpooledFrame>>>,
    next_id: Arc<AtomicU64>,
}

impl RelayRegistry {
    /// Empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a connection's two send channels under `pubkey` (last
    /// connection wins), then FLUSH any non-expired spooled frames to the right
    /// channel (in arrival order) so a handshake frame that arrived microseconds
    /// before this WS upgrade is delivered, not lost.
    pub fn register(
        &self,
        pubkey: Vec<u8>,
        hi: mpsc::UnboundedSender<Vec<u8>>,
        lo: mpsc::UnboundedSender<Vec<u8>>,
    ) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        if let Some((_, held)) = self.spool.remove(&pubkey) {
            let now = Instant::now();
            for sf in held {
                if now.duration_since(sf.at) > SPOOL_TTL {
                    continue; // stale handshake frame — useless, drop it
                }
                let ch = if sf.hi_prio { &hi } else { &lo };
                if ch.send(sf.frame).is_err() {
                    break; // the brand-new receiver is already gone
                }
            }
        }
        self.conns.insert(pubkey, RelayConn { id, hi, lo });
        id
    }

    /// Forward a fully-encoded downlink frame to `pubkey` on the priority lane
    /// `hi_prio` selects (handshake/cookie → `hi`, bulk data → `lo`). Returns
    /// `true` only when delivered to a LIVE connection. When there is no live
    /// connection (or the live send races a just-closed receiver), the frame is
    /// SPOOLED briefly instead of discarded (see [`Self::spool`]) and the method
    /// returns `false` — "not forwarded yet", but the frame is held, not lost.
    #[must_use]
    pub fn forward(&self, pubkey: &[u8], frame: Vec<u8>, hi_prio: bool) -> bool {
        if let Some(ch) = self
            .conns
            .get(pubkey)
            .map(|c| if hi_prio { c.hi.clone() } else { c.lo.clone() })
        {
            match ch.send(frame) {
                Ok(()) => return true,
                Err(mpsc::error::SendError(frame)) => {
                    // Entry existed but its receiver just died — hold the
                    // recovered frame for the imminent reconnect.
                    self.push_spool(pubkey, hi_prio, frame);
                    return false;
                }
            }
        }
        self.push_spool(pubkey, hi_prio, frame);
        false
    }

    /// Hold `frame` (with its priority) for `pubkey` until it (re)registers,
    /// bounded to the newest [`SPOOL_CAP`] frames (oldest evicted first).
    fn push_spool(&self, pubkey: &[u8], hi_prio: bool, frame: Vec<u8>) {
        let mut q = self.spool.entry(pubkey.to_vec()).or_default();
        if q.len() >= SPOOL_CAP {
            q.pop_front();
        }
        q.push_back(SpooledFrame {
            at: Instant::now(),
            hi_prio,
            frame,
        });
    }

    /// Remove the entry only if it is still the connection with `id`
    /// (avoids racing a newer reconnect that replaced it).
    pub fn unregister(&self, pubkey: &[u8], id: u64) {
        self.conns.remove_if(pubkey, |_, c| c.id == id);
    }

    /// Remove any connection for `pubkey` (peer left the roster). Also clears
    /// any spool for it — a peer that LEFT is not reconnecting, so holding its
    /// frames would be pointless.
    pub fn drop_pubkey(&self, pubkey: &[u8]) {
        self.conns.remove(pubkey);
        self.spool.remove(pubkey);
    }

    /// Reap entries whose receivers have been dropped — i.e. the relay WS task
    /// ended without a matched [`Self::unregister`] (a panic or abnormal close).
    /// Returns the number removed. Both lanes share the one send task, so they
    /// close together; testing either is a PRECISE liveness signal (no TTL
    /// guesswork). Called periodically by the background sweeper.
    pub fn reap_closed(&self) -> usize {
        let before = self.conns.len();
        self.conns.retain(|_, c| !c.lo.is_closed());
        before - self.conns.len()
    }

    /// Drop spooled frames older than [`SPOOL_TTL`] (and now-empty queues), so
    /// a pubkey that never reconnects can't hold memory. Called by the same
    /// background sweeper as [`Self::reap_closed`]. Returns frames dropped.
    pub fn reap_expired_spool(&self) -> usize {
        let now = Instant::now();
        let mut dropped = 0usize;
        self.spool.retain(|_, q| {
            let before = q.len();
            q.retain(|sf| now.duration_since(sf.at) <= SPOOL_TTL);
            dropped += before - q.len();
            !q.is_empty()
        });
        dropped
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

    /// Register a pubkey and return its (`hi_rx`, `lo_rx`) so a test can assert
    /// which lane a frame landed on.
    fn register(
        reg: &RelayRegistry,
        pubkey: Vec<u8>,
    ) -> (
        mpsc::UnboundedReceiver<Vec<u8>>,
        mpsc::UnboundedReceiver<Vec<u8>>,
    ) {
        let (hi, hi_rx) = mpsc::unbounded_channel();
        let (lo, lo_rx) = mpsc::unbounded_channel();
        reg.register(pubkey, hi, lo);
        (hi_rx, lo_rx)
    }

    #[test]
    fn register_returns_increasing_ids() {
        let reg = RelayRegistry::new();
        let (hi_a, _) = mpsc::unbounded_channel();
        let (lo_a, _) = mpsc::unbounded_channel();
        let (hi_b, _) = mpsc::unbounded_channel();
        let (lo_b, _) = mpsc::unbounded_channel();
        let id_a = reg.register(vec![1u8; 32], hi_a, lo_a);
        let id_b = reg.register(vec![2u8; 32], hi_b, lo_b);
        assert!(id_b > id_a, "ids must strictly increase");
    }

    #[test]
    fn forward_routes_to_the_priority_lane() {
        let reg = RelayRegistry::new();
        let (mut hi_rx, mut lo_rx) = register(&reg, vec![9u8; 32]);
        // A handshake frame goes to the HI lane.
        assert!(reg.forward(&[9u8; 32], vec![1, 0, 0, 0], true));
        assert_eq!(hi_rx.try_recv().expect("hi lane"), vec![1, 0, 0, 0]);
        assert!(lo_rx.try_recv().is_err(), "data lane stays empty");
        // A bulk data frame goes to the LO lane.
        assert!(reg.forward(&[9u8; 32], vec![4, 0, 0, 0], false));
        assert_eq!(lo_rx.try_recv().expect("lo lane"), vec![4, 0, 0, 0]);
        assert!(hi_rx.try_recv().is_err(), "hi lane stays empty");
    }

    #[test]
    fn forward_to_unknown_pubkey_is_false() {
        let reg = RelayRegistry::new();
        // No live conn -> returns false (not delivered) but the frame is HELD.
        assert!(!reg.forward(&[0u8; 32], vec![1, 2, 3], true));
    }

    #[test]
    fn forward_to_unregistered_spools_and_register_flushes_to_the_right_lane() {
        // THE regression for the REKEY_TIMEOUT storm: a frame for a pubkey
        // whose relay WS is momentarily unregistered must be held and delivered
        // — on its ORIGINAL priority lane — the instant it (re)registers.
        let reg = RelayRegistry::new();
        assert!(!reg.forward(&[7u8; 32], vec![2, 9, 9], true), "no live conn");
        assert!(!reg.forward(&[7u8; 32], vec![4, 8, 8], false), "no live conn");
        let (mut hi_rx, mut lo_rx) = register(&reg, vec![7u8; 32]);
        assert_eq!(hi_rx.try_recv().expect("hi spooled flush"), vec![2, 9, 9]);
        assert_eq!(lo_rx.try_recv().expect("lo spooled flush"), vec![4, 8, 8]);
    }

    #[test]
    fn spool_is_bounded_to_cap_keeping_newest() {
        let reg = RelayRegistry::new();
        let n = u8::try_from(SPOOL_CAP).expect("cap fits u8") + 5;
        for i in 0..n {
            let _ = reg.forward(&[8u8; 32], vec![i], false);
        }
        let (_, mut lo_rx) = register(&reg, vec![8u8; 32]);
        let mut got = vec![];
        while let Ok(f) = lo_rx.try_recv() {
            got.push(f[0]);
        }
        assert_eq!(got.len(), SPOOL_CAP, "spool holds at most SPOOL_CAP frames");
        assert_eq!(*got.first().unwrap(), 5, "oldest 5 evicted");
        assert_eq!(*got.last().unwrap(), n - 1, "newest kept");
    }

    #[test]
    fn reap_expired_spool_keeps_fresh_frames() {
        let reg = RelayRegistry::new();
        let _ = reg.forward(&[1u8; 32], vec![9], true);
        assert_eq!(reg.reap_expired_spool(), 0, "fresh frame is not reaped");
        let (mut hi_rx, _) = register(&reg, vec![1u8; 32]);
        assert_eq!(hi_rx.try_recv().expect("fresh survives reap"), vec![9]);
    }

    #[test]
    fn drop_pubkey_clears_spool() {
        let reg = RelayRegistry::new();
        let _ = reg.forward(&[2u8; 32], vec![1], false);
        reg.drop_pubkey(&[2u8; 32]);
        let (_, mut lo_rx) = register(&reg, vec![2u8; 32]);
        assert!(lo_rx.try_recv().is_err(), "spool cleared on drop_pubkey");
    }

    #[test]
    fn unregister_only_removes_matching_id() {
        let reg = RelayRegistry::new();
        let (hi_old, _) = mpsc::unbounded_channel();
        let (lo_old, _) = mpsc::unbounded_channel();
        let old_id = reg.register(vec![5u8; 32], hi_old, lo_old);
        // A newer connection replaces the entry under the same pubkey.
        let (mut hi_new_rx, _lo_new_rx) = register(&reg, vec![5u8; 32]);
        // Unregistering the OLD id must be a no-op (the new conn still wins).
        reg.unregister(&[5u8; 32], old_id);
        assert!(reg.forward(&[5u8; 32], vec![1, 7], true));
        assert_eq!(hi_new_rx.try_recv().expect("new conn still live"), vec![1, 7]);
    }

    #[test]
    fn drop_pubkey_removes_unconditionally() {
        let reg = RelayRegistry::new();
        let _ = register(&reg, vec![3u8; 32]);
        assert_eq!(reg.len(), 1);
        reg.drop_pubkey(&[3u8; 32]);
        assert!(reg.is_empty());
        assert!(!reg.forward(&[3u8; 32], vec![1], false));
    }

    #[test]
    fn reap_closed_removes_only_dead_connections() {
        let reg = RelayRegistry::new();
        // A live connection — keep its receivers alive so the senders stay open.
        let (_hi_live_rx, _lo_live_rx) = register(&reg, vec![1u8; 32]);
        // A dead connection — drop its receivers so the senders report closed.
        {
            let _ = register(&reg, vec![2u8; 32]);
        } // both receivers dropped here

        assert_eq!(reg.len(), 2);
        assert_eq!(reg.reap_closed(), 1, "only the dead conn is reaped");
        assert_eq!(reg.len(), 1);
        assert!(reg.forward(&[1u8; 32], vec![9], false), "live conn survives");
        assert!(!reg.forward(&[2u8; 32], vec![9], false), "dead conn is gone");
    }

    #[test]
    fn reap_closed_is_a_noop_when_all_live() {
        let reg = RelayRegistry::new();
        let (_hi_rx, _lo_rx) = register(&reg, vec![4u8; 32]);
        assert_eq!(reg.reap_closed(), 0);
        assert_eq!(reg.len(), 1);
    }
}
