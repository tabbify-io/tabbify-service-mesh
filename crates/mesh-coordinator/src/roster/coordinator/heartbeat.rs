//! Heartbeat ingestion + reflexive endpoint roaming + Stage 2 hole-punch
//! pairing + deregister.
//!
//! Everything triggered after a peer is in the roster: refreshing
//! `last_heartbeat`, rolling the reflexive endpoint over when the peer's
//! observed public IP changes (without clobbering an explicit
//! advertise-endpoint), pairing eligible peers for `HolePunchInitiate`,
//! and finally removing a peer with `deregister`.

use super::{Coordinator, CoordinatorError, PEER_SEGMENT, PeerEntry, now_unix_micros};
use crate::http::sse::PeerEvent;
use crate::nat::holepunch::{PunchPeer, try_emit_pair};
use crate::nat::reflexive::{is_sticky_explicit_endpoint, resolve_listen_endpoint};
use crate::publisher::publish_event;
use crate::roster::events::{PeerHeartbeat, PeerLeft};
use std::net::SocketAddr;
use tracing::{debug, info};
use uuid::Uuid;

impl Coordinator {
    /// Stamp a heartbeat on `peer_id`. Builds a `PeerHeartbeat` event,
    /// publishes it, then applies the event to in-memory state (bumping
    /// `last_heartbeat`). Re-broadcasts `PeerInfo` so SSE subscribers
    /// see fresh listen-endpoint info.
    ///
    /// `observed_external` is the source `SocketAddr` of the heartbeat
    /// request (string form; empty when unavailable). `wg_listen_port` is
    /// the peer's reported `WireGuard` UDP port. Together they refresh the
    /// peer's reflexive endpoint: if the peer's observed public IP changed
    /// (`NAT` rebind / roaming) the stored `listen_endpoint` is updated so
    /// other peers re-learn the new dial target on their next roster sync.
    /// A self-reported public endpoint is never clobbered (see
    /// [`crate::nat::reflexive::resolve_listen_endpoint`]).
    ///
    /// Stage 2 side-effect: after applying the heartbeat, scan the roster
    /// for every other peer with a known `observed_external` and emit a
    /// `HolePunchInitiate` pair (deduped per canonical (a,b) — see
    /// [`crate::nat::holepunch`]). Real punching logic is deferred — this
    /// just pins the protocol shape.
    ///
    /// # Errors
    /// `UnknownPeer` if `peer_id` is not in the roster.
    #[allow(clippy::too_many_arguments)]
    pub async fn heartbeat(
        &self,
        peer_id: Uuid,
        observed_external: String,
        wg_listen_port: Option<u16>,
        hosted_app_ulas: Vec<String>,
        software_version: Option<String>,
        mesh_version: Option<String>,
        relay_only: bool,
    ) -> Result<PeerEntry, CoordinatorError> {
        // Pre-check membership so we can surface UnknownPeer without
        // emitting a heartbeat event for a peer that doesn't exist. Capture
        // the prior hosted-app-ULA set in the same lookup so we can detect
        // a change after apply and re-broadcast only when it actually moved
        // (per-app-ULA routing).
        let Some(prior_hosted) = self
            .inner
            .roster
            .get(&peer_id)
            .map(|e| e.hosted_app_ulas.clone())
        else {
            return Err(CoordinatorError::UnknownPeer(peer_id));
        };
        let event = PeerHeartbeat {
            peer_id: peer_id.to_string(),
            observed_external: observed_external.clone(),
            // Carry the supervisor's current hosted set through the event
            // so the apply layer (and any future durable replay) replaces
            // the stored set from one source of truth.
            hosted_app_ulas,
            // Carry the reported version through the event so the apply
            // layer updates the stored value (when present); `None` leaves
            // it untouched (spec P0: never a downgrade).
            software_version,
            mesh_version,
            at_micros: now_unix_micros(),
        };
        publish_event(self.inner.publisher.as_ref(), PEER_SEGMENT, &event).await;
        self.apply_peer_heartbeat(&event);
        // Re-assert the relay-only flag from this heartbeat so a peer that
        // flips reachability is reflected without a full re-register. Done
        // BEFORE the reflexive refresh so the refresh sees the live value
        // and never rolls a relay-only peer onto a (black-hole) endpoint.
        if let Some(mut e) = self.inner.roster.get_mut(&peer_id) {
            e.relay_only = relay_only;
        }
        // Refresh the reflexive endpoint from this heartbeat's observed
        // source addr. The peer's existing stored endpoint is fed back in
        // as the "self-reported" input so a public / hostname endpoint is
        // preserved and only a NAT-derived reflexive endpoint rolls over.
        // A relay-only peer is short-circuited inside the helper (its
        // endpoint stays `None` — it has no reachable direct path).
        self.refresh_reflexive_endpoint(peer_id, &observed_external, wg_listen_port, relay_only);
        // Re-read after apply so the snapshot reflects the new
        // last_heartbeat. If the entry vanished between contains_key and
        // here (concurrent deregister), bail with UnknownPeer.
        let snapshot = self
            .inner
            .roster
            .get(&peer_id)
            .map(|e| e.clone())
            .ok_or(CoordinatorError::UnknownPeer(peer_id))?;
        let hosted_changed = snapshot.hosted_app_ulas != prior_hosted;
        debug!(
            peer_id = %peer_id,
            observed_external,
            hosted_changed,
            "heartbeat stamped"
        );
        // Every heartbeat already re-broadcasts `Updated` so endpoint
        // roaming converges on SSE subscribers; the per-app-ULA set rides
        // along in `to_info()`, so a changed hosted set is published the
        // same way (spec: "if changed, broadcast PeerEvent::Updated"). The
        // broadcast stays unconditional to avoid regressing the existing
        // endpoint-roaming path; `hosted_changed` is logged for
        // observability.
        self.inner
            .broadcaster
            .broadcast(PeerEvent::Updated(snapshot.to_info()));
        self.try_emit_holepunch_pairs(&snapshot).await;
        Ok(snapshot)
    }

    /// Refresh a peer's reflexive `listen_endpoint` from a fresh observed
    /// source addr + reported WG port on a heartbeat.
    ///
    /// A heartbeat carries NO `listen_endpoint` self-report (the joiner
    /// sends only its id + WG port), so this must NOT treat the stored
    /// endpoint as a self-report. Instead it uses the stored
    /// `endpoint_is_reflexive` flag to decide:
    ///
    /// * stored endpoint is **explicit** (an `--advertise-endpoint` public
    ///   IP / hostname, `endpoint_is_reflexive == false` AND non-empty) →
    ///   leave it untouched. Operator intent is sticky.
    /// * stored endpoint is **reflexive** (or absent) → recompute from the
    ///   observed public IP + WG port. This is what makes a reflexive
    ///   endpoint ROAM when the peer's NAT public IP changes, and what
    ///   lets a peer that started passive become reachable once a public
    ///   source is seen.
    ///
    /// No-ops when the observed addr is empty / unparseable or the port is
    /// unknown — exactly the back-compat / test paths.
    fn refresh_reflexive_endpoint(
        &self,
        peer_id: Uuid,
        observed_external: &str,
        wg_listen_port: Option<u16>,
        relay_only: bool,
    ) {
        // A relay-only peer has no reachable direct endpoint, so a heartbeat
        // must never synthesize one for it (it would be a black hole that
        // makes peers double-init handshakes). Leave its stored endpoint
        // (`None`) untouched.
        if relay_only {
            return;
        }
        let Ok(observed) = observed_external.parse::<SocketAddr>() else {
            return;
        };
        if let Some(mut e) = self.inner.roster.get_mut(&peer_id) {
            // Never clobber an explicit, sticky self-reported endpoint —
            // but ONLY when it is actually reachable (a public IP or a
            // hostname). A non-reflexive *loopback / private* endpoint is a
            // fallback, not an operator advertisement, so it stays eligible
            // for reflexive rollover. This keeps the decision independent
            // of whether the first register happened to carry connect-info.
            let has_sticky_explicit = !e.endpoint_is_reflexive
                && e.listen_endpoint
                    .as_deref()
                    .is_some_and(is_sticky_explicit_endpoint);
            if has_sticky_explicit {
                return;
            }
            // Recompute reflexive from the observed addr alone (no
            // self-report on a heartbeat). `resolved.reflexive` will be
            // true on a public observed IP, false when the observed IP is
            // private (same-host) — in which case we leave the endpoint as
            // it was rather than regress a prior reflexive value to None.
            // `relay_only == false` here (guarded above), so pass `false`.
            let resolved = resolve_listen_endpoint(None, Some(observed), wg_listen_port, false);
            if resolved.reflexive && resolved.endpoint != e.listen_endpoint {
                debug!(
                    peer_id = %peer_id,
                    old = ?e.listen_endpoint,
                    new = ?resolved.endpoint,
                    "heartbeat: reflexive endpoint rolled over",
                );
                e.listen_endpoint = resolved.endpoint;
                e.endpoint_is_reflexive = true;
            }
        }
    }

    /// Build a punch candidate for `e` IN THE CONTEXT of a specific peer pair.
    ///
    /// A peer is normally eligible once it has heartbeated (non-empty
    /// `observed_external`) AND has a dialable `listen_endpoint`. The punch
    /// TARGET is that reflexive `WireGuard` endpoint (`ip:wg_port`), NOT the raw
    /// heartbeat TCP source — a punch fired at the TCP source would miss the
    /// `WireGuard` UDP NAT mapping entirely.
    ///
    /// A **relay-only** peer is NEVER a punch candidate (returns `None`) for an
    /// UNFLAGGED pair: `try_emit_holepunch_pairs` builds each pair from
    /// `punch_peer_for_pair(a, b)` AND `punch_peer_for_pair(b, a)`, so returning
    /// `None` for either end suppresses the whole pair — preserving the
    /// 2026-06-07 contract (no punch when EITHER peer is relay-only, so neither
    /// side double-inits a handshake at a black-hole endpoint).
    ///
    /// Track A-a is the ONE deliberate relaxation: when the `(e, other)` pair is
    /// explicitly flagged `direct`, a `relay_only` peer is NOT skipped — instead
    /// its reflexive endpoint is synthesized ON THE FLY from its observed
    /// heartbeat source so the flagged punch has a dial target. The synthesized
    /// endpoint is computed HERE and never stored on the entry, so an unflagged
    /// peer's `listen_endpoint` invariant (`None` for `relay_only`) is untouched
    /// — it never sees a black-hole endpoint. Only an explicitly-flagged pair
    /// gets a direct dial target; every other pair stays on the relay floor.
    fn punch_peer_for_pair(&self, e: &PeerEntry, other: Uuid) -> Option<PunchPeer> {
        if e.observed_external.is_empty() {
            return None;
        }
        if e.relay_only {
            // Relay-only is normally suppressed. Relax ONLY for a flagged pair.
            if !self.inner.direct_pair_flags.is_direct(e.peer_id, other) {
                return None;
            }
            // Synthesize the reflexive endpoint from the observed source +
            // reported WG port for THIS punch only — never stored on the entry.
            let observed: SocketAddr = e.observed_external.parse().ok()?;
            // Reuse the joiner-reported WG port if the reflexive listen_endpoint
            // carried one; fall back to the well-known WG port when absent.
            let port = e
                .listen_endpoint
                .as_deref()
                .and_then(|s| s.rsplit(':').next())
                .and_then(|p| p.parse::<u16>().ok())
                .unwrap_or(51820);
            let dial = crate::nat::reflexive::reflexive_endpoint(observed.ip(), port);
            return Some(PunchPeer {
                peer_id: e.peer_id,
                dial_endpoint: dial,
            });
        }
        // Non-relay-only: the standard reflexive listen_endpoint.
        let dial = e.listen_endpoint.clone().filter(|s| !s.is_empty())?;
        Some(PunchPeer {
            peer_id: e.peer_id,
            dial_endpoint: dial,
        })
    }

    /// Stage 2 hook called after a heartbeat lands. Emits a `HolePunchInitiate`
    /// pair for every other dialable peer that hasn't yet been paired.
    /// Best-effort — publish failures are swallowed via `publish_event`.
    async fn try_emit_holepunch_pairs(&self, just_heartbeated: &PeerEntry) {
        let a_id = just_heartbeated.peer_id;
        // Snapshot candidate entries before await (no DashMap guard held).
        let candidates: Vec<PeerEntry> = self
            .inner
            .roster
            .iter()
            .filter(|kv| kv.value().peer_id != a_id)
            .map(|kv| kv.value().clone())
            .collect();
        let now = now_unix_micros();
        for b in candidates {
            // Pair-aware builder: a flagged direct pair relaxes the relay_only
            // suppression for THIS pair only; every unflagged pair stays
            // suppressed (returns None for the relay_only end exactly as before).
            let (Some(pa), Some(pb)) = (
                self.punch_peer_for_pair(just_heartbeated, b.peer_id),
                self.punch_peer_for_pair(&b, a_id),
            ) else {
                continue;
            };
            try_emit_pair(
                self.inner.publisher.as_ref(),
                &self.inner.broadcaster,
                &self.inner.punch_tracker,
                &pa,
                &pb,
                now,
            )
            .await;
        }
    }

    /// Remove `peer_id` from the roster. Idempotent — removing an unknown
    /// peer is a no-op (the public API maps this to 204 No Content).
    pub async fn deregister(&self, peer_id: Uuid, reason: &str) -> bool {
        // Capture the departing peer's tags before removal so the SSE
        // remove frame can be ACL-filtered per viewer (the viewer should
        // only learn of a removal for a peer it could previously see).
        // Returning early here also covers the unknown-peer case so we
        // don't emit a spurious PeerLeft into the log.
        let Some(tags) = self.inner.roster.get(&peer_id).map(|e| e.tags.clone()) else {
            return false;
        };
        let event = PeerLeft {
            peer_id: peer_id.to_string(),
            reason: reason.to_owned(),
            left_at_micros: now_unix_micros(),
        };
        publish_event(self.inner.publisher.as_ref(), PEER_SEGMENT, &event).await;
        self.apply_peer_left(&event);
        info!(peer_id = %peer_id, reason, "peer deregistered");
        self.inner.broadcaster.broadcast(PeerEvent::Removed {
            peer_id: peer_id.to_string(),
            tags,
        });
        // Membership changed — refresh the durable roster snapshot so the
        // departed peer is not resurrected on the next coordinator restart.
        self.persist_roster().await;
        true
    }
}
