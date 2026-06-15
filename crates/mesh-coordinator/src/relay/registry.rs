//! Ephemeral pubkey → live relay WS connection registry.

use dashmap::DashMap;
use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// Which of a peer's two relay sockets a frame rides.
///
/// `WireGuard` handshake/cookie frames (types 1-3) take [`Lane::Hi`]; bulk
/// transport DATA (type 4) takes [`Lane::Lo`]. The two lanes are PHYSICALLY
/// SEPARATE WebSocket connections (each joiner opens one per lane, `?lane=hi` /
/// `?lane=lo`), so a saturated bulk download on `Lo` — which bufferbloats its
/// kernel TCP send buffer to ~10 s — cannot delay a rekey handshake on the
/// near-empty `Hi` socket. App-level frame priority over ONE socket could not
/// fix this: the backlog sits in the kernel buffer below the app layer.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Lane {
    /// Handshake/cookie — the near-empty, never-bloated socket.
    Hi,
    /// Bulk transport data — may bloat, but only ITS own socket.
    Lo,
}

/// One live single-lane relay socket: a send channel drained by that socket's
/// send task, tagged with the registration `id` so an id-matched
/// [`RelayRegistry::unregister`] never clobbers a newer reconnect.
struct LaneConn {
    id: u64,
    tx: mpsc::UnboundedSender<Vec<u8>>,
}

/// A peer's pair of live relay sockets. A new joiner populates BOTH (`hi` +
/// `lo`); a legacy single-WS joiner (no `?lane=`) populates only `lo` and
/// relies on the hi→lo fallback in [`PeerConns::pick`]. Either slot may be
/// `None` (peer not yet connected on that lane, or the lane's socket died).
#[derive(Default)]
struct PeerConns {
    hi: Option<LaneConn>,
    lo: Option<LaneConn>,
}

impl PeerConns {
    /// Mutable handle to the slot for `lane` (so `register`/`unregister` touch
    /// exactly one lane, never the other).
    const fn slot_mut(&mut self, lane: Lane) -> &mut Option<LaneConn> {
        match lane {
            Lane::Hi => &mut self.hi,
            Lane::Lo => &mut self.lo,
        }
    }

    /// The send channel a frame of priority `hi_prio` must ride.
    ///
    /// `hi_prio` (handshake/cookie) prefers the `hi` socket but FALLS BACK to
    /// `lo` when `hi` is absent — a legacy single-WS peer only ever populated
    /// `lo`, and its handshakes must still flow during a mixed-version
    /// rollout. Bulk data (`!hi_prio`) uses `lo` ONLY and NEVER falls back to
    /// `hi`: letting bulk onto the handshake socket would re-bloat it and undo
    /// the entire fix.
    fn pick(&self, hi_prio: bool) -> Option<&mpsc::UnboundedSender<Vec<u8>>> {
        if hi_prio {
            self.hi.as_ref().or(self.lo.as_ref()).map(|c| &c.tx)
        } else {
            self.lo.as_ref().map(|c| &c.tx)
        }
    }

    /// No live socket on either lane — the pubkey entry can be dropped.
    const fn is_empty(&self) -> bool {
        self.hi.is_none() && self.lo.is_none()
    }
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

/// Ephemeral pubkey → live-WS registry.
///
/// Keyed by the RAW 32-byte X25519 pubkey, exactly like `Inner.by_pubkey`.
/// Cheap to clone (Arc inside). NOT event-sourced — a live socket can't be
/// replayed. Each pubkey holds up to TWO live sockets ([`PeerConns`]), one per
/// [`Lane`].
#[derive(Clone, Default)]
pub struct RelayRegistry {
    conns: Arc<DashMap<Vec<u8>, PeerConns>>,
    /// Frames briefly held for a pubkey that has no *currently* live
    /// connection on the lane they need, flushed the instant a matching lane
    /// (re)registers. This turns the post-reconnect registration race — a
    /// handshake-init that lands a few hundred ms before the destination's
    /// relay WS re-upgrades — from a SILENT FRAME DROP (which left boringtun
    /// retrying forever, the `REKEY_TIMEOUT` storm) into a recoverable hiccup
    /// that converges on the first attempt. Bounded by [`SPOOL_CAP`] +
    /// [`SPOOL_TTL`]. Keyed by pubkey, each frame tagged with its `hi_prio` so
    /// the flush re-routes it through [`Self::forward`] (lane + fallback).
    spool: Arc<DashMap<Vec<u8>, VecDeque<SpooledFrame>>>,
    next_id: Arc<AtomicU64>,
}

impl RelayRegistry {
    /// Empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a single-lane connection's send channel under `(pubkey,
    /// lane)` (last connection on that lane wins; the OTHER lane is left
    /// untouched), then FLUSH any non-expired spooled frames by re-`forward`ing
    /// each one — so a frame that arrived microseconds before this WS upgrade
    /// is delivered on whichever lane now claims it (or re-held for the lane
    /// still connecting). Returns the connection id.
    pub fn register(&self, pubkey: &[u8], lane: Lane, tx: mpsc::UnboundedSender<Vec<u8>>) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        {
            // Scope the entry guard: it write-locks the shard, and the spool
            // flush below calls `forward`, which re-locks the same map.
            let mut entry = self.conns.entry(pubkey.to_vec()).or_default();
            *entry.slot_mut(lane) = Some(LaneConn { id, tx });
        }
        if let Some((_, held)) = self.spool.remove(pubkey) {
            let now = Instant::now();
            for sf in held {
                if now.duration_since(sf.at) > SPOOL_TTL {
                    continue; // stale handshake frame — useless, drop it
                }
                // Re-route through forward: delivers to the lane that just
                // registered (or its hi→lo fallback), re-spools anything still
                // destined for a lane that hasn't connected yet.
                let _ = self.forward(pubkey, sf.frame, sf.hi_prio);
            }
        }
        id
    }

    /// Forward a fully-encoded downlink frame to `pubkey` on the lane
    /// `hi_prio` selects.
    ///
    /// Handshake/cookie → `hi` (falling back to `lo` for a legacy single-WS
    /// peer), bulk data → `lo` only. Returns `true` only when delivered to a
    /// LIVE socket. When there is no usable live socket (or the send races a
    /// just-closed receiver), the frame is SPOOLED briefly instead of
    /// discarded (see [`Self::spool`]) and the method returns `false` — "not
    /// forwarded yet", but the frame is held, not lost.
    #[must_use]
    pub fn forward(&self, pubkey: &[u8], frame: Vec<u8>, hi_prio: bool) -> bool {
        if let Some(tx) = self.conns.get(pubkey).and_then(|c| c.pick(hi_prio).cloned()) {
            match tx.send(frame) {
                Ok(()) => return true,
                Err(mpsc::error::SendError(frame)) => {
                    // The chosen lane's receiver just died — hold the recovered
                    // frame (with its ORIGINAL priority) for the imminent
                    // reconnect.
                    self.push_spool(pubkey, hi_prio, frame);
                    return false;
                }
            }
        }
        self.push_spool(pubkey, hi_prio, frame);
        false
    }

    /// Hold `frame` (with its priority) for `pubkey` until a matching lane
    /// (re)registers, bounded to the newest [`SPOOL_CAP`] frames (oldest
    /// evicted first).
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

    /// Clear the `lane` slot for `pubkey` only if it is still the connection
    /// with `id` (avoids racing a newer reconnect that replaced it), leaving
    /// the OTHER lane untouched. Removes the pubkey entry once both lanes are
    /// gone.
    pub fn unregister(&self, pubkey: &[u8], lane: Lane, id: u64) {
        let now_empty = {
            let Some(mut entry) = self.conns.get_mut(pubkey) else {
                return;
            };
            let slot = entry.slot_mut(lane);
            if slot.as_ref().is_some_and(|c| c.id == id) {
                *slot = None;
            }
            entry.is_empty()
        }; // drop the get_mut guard before remove_if re-locks the shard
        if now_empty {
            // Re-check under the removal lock: a brand-new conn may have
            // registered on either lane in the gap.
            self.conns.remove_if(pubkey, |_, c| c.is_empty());
        }
    }

    /// Remove BOTH lanes for `pubkey` (peer left the roster). Also clears any
    /// spool for it — a peer that LEFT is not reconnecting, so holding its
    /// frames would be pointless.
    pub fn drop_pubkey(&self, pubkey: &[u8]) {
        self.conns.remove(pubkey);
        self.spool.remove(pubkey);
    }

    /// Reap dead lane sockets — a relay WS task that ended without a matched
    /// [`Self::unregister`] (a panic or abnormal close). Each lane is now an
    /// INDEPENDENT socket/task, so liveness is tested PER LANE (a dead `hi`
    /// paired with a live `lo` must drop only `hi`). A pubkey whose last live
    /// lane is reaped is removed entirely. Returns the number of lane sockets
    /// reaped. Called periodically by the background sweeper.
    pub fn reap_closed(&self) -> usize {
        let mut reaped = 0usize;
        self.conns.retain(|_, c| {
            if c.hi.as_ref().is_some_and(|l| l.tx.is_closed()) {
                c.hi = None;
                reaped += 1;
            }
            if c.lo.as_ref().is_some_and(|l| l.tx.is_closed()) {
                c.lo = None;
                reaped += 1;
            }
            !c.is_empty()
        });
        reaped
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

    /// Number of pubkeys with at least one live lane socket. NOTE: a pubkey
    /// may hold up to TWO sockets (hi + lo), so this counts PEERS, not
    /// sockets.
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

    /// Register BOTH lanes for a pubkey (the new dual-WS joiner shape) and
    /// return their (`hi_rx`, `lo_rx`) so a test can assert which lane a frame
    /// landed on.
    fn register_both(
        reg: &RelayRegistry,
        pubkey: &[u8],
    ) -> (
        mpsc::UnboundedReceiver<Vec<u8>>,
        mpsc::UnboundedReceiver<Vec<u8>>,
    ) {
        let (hi, hi_rx) = mpsc::unbounded_channel();
        let (lo, lo_rx) = mpsc::unbounded_channel();
        reg.register(pubkey, Lane::Hi, hi);
        reg.register(pubkey, Lane::Lo, lo);
        (hi_rx, lo_rx)
    }

    /// Register ONLY the lo lane (the legacy single-WS joiner shape).
    fn register_lo(reg: &RelayRegistry, pubkey: &[u8]) -> mpsc::UnboundedReceiver<Vec<u8>> {
        let (lo, lo_rx) = mpsc::unbounded_channel();
        reg.register(pubkey, Lane::Lo, lo);
        lo_rx
    }

    #[test]
    fn register_returns_increasing_ids() {
        let reg = RelayRegistry::new();
        let (hi_a, _) = mpsc::unbounded_channel();
        let (lo_b, _) = mpsc::unbounded_channel();
        let id_a = reg.register(&[1u8; 32], Lane::Hi, hi_a);
        let id_b = reg.register(&[2u8; 32], Lane::Lo, lo_b);
        assert!(id_b > id_a, "ids must strictly increase");
    }

    #[test]
    fn both_lanes_coexist_neither_clobbers_the_other() {
        // The core Option A invariant: registering the lo socket for a pubkey
        // must NOT evict its already-live hi socket (the old flat-map design
        // last-write-wins would).
        let reg = RelayRegistry::new();
        let (mut hi_rx, mut lo_rx) = register_both(&reg, &[9u8; 32]);
        assert!(reg.forward(&[9u8; 32], vec![1, 0, 0, 0], true), "hi delivers");
        assert_eq!(hi_rx.try_recv().expect("hi lane"), vec![1, 0, 0, 0]);
        assert!(reg.forward(&[9u8; 32], vec![4, 0, 0, 0], false), "lo delivers");
        assert_eq!(lo_rx.try_recv().expect("lo lane"), vec![4, 0, 0, 0]);
    }

    #[test]
    fn forward_routes_to_the_priority_lane() {
        let reg = RelayRegistry::new();
        let (mut hi_rx, mut lo_rx) = register_both(&reg, &[9u8; 32]);
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
    fn hi_prio_falls_back_to_lo_for_legacy_single_ws_peer() {
        // Rollout-critical: a legacy joiner only registers the lo lane. A
        // handshake (hi_prio) to it MUST fall back to lo and deliver, else the
        // legacy peer never rekeys (the REKEY_TIMEOUT storm).
        let reg = RelayRegistry::new();
        let mut lo_rx = register_lo(&reg, &[7u8; 32]);
        assert!(
            reg.forward(&[7u8; 32], vec![1, 2, 3], true),
            "handshake falls back to the lo lane"
        );
        assert_eq!(lo_rx.try_recv().expect("lo lane got the handshake"), vec![1, 2, 3]);
    }

    #[test]
    fn data_never_falls_back_to_the_hi_lane() {
        // The asymmetry that protects Option A: bulk data must NEVER ride the
        // handshake-only socket (that would re-bloat it). With only a hi lane
        // live, a data frame is spooled, not delivered to hi.
        let reg = RelayRegistry::new();
        let (hi, mut hi_rx) = mpsc::unbounded_channel();
        reg.register(&[8u8; 32], Lane::Hi, hi);
        assert!(
            !reg.forward(&[8u8; 32], vec![4, 0, 0], false),
            "data is spooled, not delivered, when only hi is live"
        );
        assert!(hi_rx.try_recv().is_err(), "data must never land on the hi socket");
    }

    #[test]
    fn forward_to_unknown_pubkey_is_false() {
        let reg = RelayRegistry::new();
        // No live conn -> returns false (not delivered) but the frame is HELD.
        assert!(!reg.forward(&[0u8; 32], vec![1, 2, 3], true));
    }

    #[test]
    fn spool_flushes_each_frame_to_its_lane_on_register() {
        // A frame for a pubkey whose relay WS is momentarily unregistered must
        // be held and delivered — on its ORIGINAL priority lane — the instant
        // a matching lane (re)registers.
        let reg = RelayRegistry::new();
        assert!(!reg.forward(&[7u8; 32], vec![2, 9, 9], true), "no live conn");
        assert!(!reg.forward(&[7u8; 32], vec![4, 8, 8], false), "no live conn");
        let (mut hi_rx, mut lo_rx) = register_both(&reg, &[7u8; 32]);
        assert_eq!(hi_rx.try_recv().expect("hi spooled flush"), vec![2, 9, 9]);
        assert_eq!(lo_rx.try_recv().expect("lo spooled flush"), vec![4, 8, 8]);
    }

    #[test]
    fn spooled_handshake_falls_back_to_lo_when_only_lo_registers() {
        // A handshake spooled while NO lane is live must flush to lo when only
        // the lo lane registers (legacy single-WS peer, or the lo socket of a
        // new joiner winning the connect race). A freshly-registered lo socket
        // has an empty kernel buffer, so this is safe — and refusing it would
        // strand a legacy peer's rekey forever.
        let reg = RelayRegistry::new();
        assert!(!reg.forward(&[6u8; 32], vec![1, 1, 1], true), "handshake spooled");
        let mut lo_rx = register_lo(&reg, &[6u8; 32]);
        assert_eq!(
            lo_rx.try_recv().expect("handshake flushed to lo via fallback"),
            vec![1, 1, 1]
        );
    }

    #[test]
    fn spooled_data_is_never_flushed_to_the_hi_lane() {
        // The spool flush must respect the no-lo→hi-fallback asymmetry: a
        // spooled DATA frame must NOT be delivered to a freshly-registered hi
        // socket — it stays held until the lo lane registers.
        let reg = RelayRegistry::new();
        assert!(!reg.forward(&[6u8; 32], vec![4, 2, 2], false), "data spooled");
        // hi registers first: the data frame must NOT flush to hi.
        let (hi, mut hi_rx) = mpsc::unbounded_channel();
        reg.register(&[6u8; 32], Lane::Hi, hi);
        assert!(hi_rx.try_recv().is_err(), "data must never ride the hi socket");
        // lo registers: now the data frame flushes to lo.
        let mut lo_rx = register_lo(&reg, &[6u8; 32]);
        assert_eq!(
            lo_rx.try_recv().expect("data flushed to lo once lo registered"),
            vec![4, 2, 2]
        );
    }

    #[test]
    fn spool_is_bounded_to_cap_keeping_newest() {
        let reg = RelayRegistry::new();
        let n = u8::try_from(SPOOL_CAP).expect("cap fits u8") + 5;
        for i in 0..n {
            let _ = reg.forward(&[8u8; 32], vec![i], false);
        }
        let mut lo_rx = register_lo(&reg, &[8u8; 32]);
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
        let mut lo_rx = register_lo(&reg, &[1u8; 32]);
        // hi never registered, so the hi-prio frame fell back to lo on register.
        assert_eq!(lo_rx.try_recv().expect("fresh survives reap"), vec![9]);
    }

    #[test]
    fn drop_pubkey_clears_spool() {
        let reg = RelayRegistry::new();
        let _ = reg.forward(&[2u8; 32], vec![1], false);
        reg.drop_pubkey(&[2u8; 32]);
        let mut lo_rx = register_lo(&reg, &[2u8; 32]);
        assert!(lo_rx.try_recv().is_err(), "spool cleared on drop_pubkey");
    }

    #[test]
    fn unregister_clears_only_the_named_lane() {
        // Tearing down the hi socket must leave the live lo socket intact
        // (independent sockets now).
        let reg = RelayRegistry::new();
        let (hi, _hi_rx) = mpsc::unbounded_channel();
        let (lo, mut lo_rx) = mpsc::unbounded_channel();
        let hi_id = reg.register(&[5u8; 32], Lane::Hi, hi);
        reg.register(&[5u8; 32], Lane::Lo, lo);
        reg.unregister(&[5u8; 32], Lane::Hi, hi_id);
        // lo still delivers data; the pubkey entry survives.
        assert!(reg.forward(&[5u8; 32], vec![4, 1], false), "lo lane still live");
        assert_eq!(lo_rx.try_recv().expect("lo survives hi unregister"), vec![4, 1]);
        assert_eq!(reg.len(), 1, "pubkey kept while one lane lives");
    }

    #[test]
    fn unregister_only_removes_matching_id() {
        let reg = RelayRegistry::new();
        let (lo_old, _) = mpsc::unbounded_channel();
        let old_id = reg.register(&[5u8; 32], Lane::Lo, lo_old);
        // A newer connection replaces the lo slot under the same pubkey.
        let (lo_new, mut lo_new_rx) = mpsc::unbounded_channel();
        reg.register(&[5u8; 32], Lane::Lo, lo_new);
        // Unregistering the OLD id must be a no-op (the new conn still wins).
        reg.unregister(&[5u8; 32], Lane::Lo, old_id);
        assert!(reg.forward(&[5u8; 32], vec![4, 7], false));
        assert_eq!(lo_new_rx.try_recv().expect("new conn still live"), vec![4, 7]);
    }

    #[test]
    fn unregister_removes_pubkey_when_last_lane_gone() {
        let reg = RelayRegistry::new();
        let (lo, _lo_rx) = mpsc::unbounded_channel();
        let lo_id = reg.register(&[3u8; 32], Lane::Lo, lo);
        assert_eq!(reg.len(), 1);
        reg.unregister(&[3u8; 32], Lane::Lo, lo_id);
        assert!(reg.is_empty(), "pubkey dropped once its only lane unregistered");
    }

    #[test]
    fn drop_pubkey_removes_both_lanes_unconditionally() {
        let reg = RelayRegistry::new();
        let _ = register_both(&reg, &[3u8; 32]);
        assert_eq!(reg.len(), 1);
        reg.drop_pubkey(&[3u8; 32]);
        assert!(reg.is_empty());
        assert!(!reg.forward(&[3u8; 32], vec![1], false));
    }

    #[test]
    fn reap_closed_reaps_a_dead_lane_keeping_the_live_one() {
        let reg = RelayRegistry::new();
        // hi alive (keep its rx), lo dead (drop its rx so the sender closes).
        let (hi, _hi_rx) = mpsc::unbounded_channel();
        reg.register(&[1u8; 32], Lane::Hi, hi);
        {
            let (lo, _lo_rx) = mpsc::unbounded_channel();
            reg.register(&[1u8; 32], Lane::Lo, lo);
        } // lo receiver dropped here -> lo sender closed
        assert_eq!(reg.reap_closed(), 1, "only the dead lo lane is reaped");
        assert_eq!(reg.len(), 1, "pubkey survives on its live hi lane");
        // hi still delivers (handshake), lo is gone (data spools).
        assert!(reg.forward(&[1u8; 32], vec![1, 9], true), "hi lane survives");
        assert!(!reg.forward(&[1u8; 32], vec![4, 9], false), "dead lo lane is gone");
    }

    #[test]
    fn reap_closed_drops_pubkey_when_both_lanes_dead() {
        let reg = RelayRegistry::new();
        {
            let _ = register_both(&reg, &[2u8; 32]);
        } // both receivers dropped here
        assert_eq!(reg.len(), 1);
        assert_eq!(reg.reap_closed(), 2, "both lanes reaped");
        assert!(reg.is_empty(), "pubkey removed once both lanes dead");
    }

    #[test]
    fn reap_closed_is_a_noop_when_all_live() {
        let reg = RelayRegistry::new();
        let (_hi_rx, _lo_rx) = register_both(&reg, &[4u8; 32]);
        assert_eq!(reg.reap_closed(), 0);
        assert_eq!(reg.len(), 1);
    }
}
