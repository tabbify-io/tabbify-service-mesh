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
    pub async fn heartbeat(
        &self,
        peer_id: Uuid,
        observed_external: String,
        wg_listen_port: Option<u16>,
        hosted_app_ulas: Vec<String>,
        software_version: Option<String>,
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
            at_micros: now_unix_micros(),
        };
        publish_event(self.inner.publisher.as_ref(), PEER_SEGMENT, &event).await;
        self.apply_peer_heartbeat(&event);
        // Refresh the reflexive endpoint from this heartbeat's observed
        // source addr. The peer's existing stored endpoint is fed back in
        // as the "self-reported" input so a public / hostname endpoint is
        // preserved and only a NAT-derived reflexive endpoint rolls over.
        self.refresh_reflexive_endpoint(peer_id, &observed_external, wg_listen_port);
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
    ) {
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
            let resolved = resolve_listen_endpoint(None, Some(observed), wg_listen_port);
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

    /// Build a punch candidate from a roster entry. A peer is eligible once
    /// it has heartbeated (we've seen its public source -> non-empty
    /// `observed_external`) AND has a dialable endpoint (`listen_endpoint`).
    /// The punch TARGET is that reflexive `WireGuard` endpoint (`ip:wg_port`),
    /// NOT the raw heartbeat TCP source — a punch fired at the TCP source
    /// would miss the `WireGuard` UDP NAT mapping entirely.
    fn punch_peer(e: &PeerEntry) -> Option<PunchPeer> {
        if e.observed_external.is_empty() {
            return None;
        }
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
        let Some(a) = Self::punch_peer(just_heartbeated) else {
            return;
        };
        // Collect candidates before await to avoid holding the DashMap
        // shard locks across .await points.
        let candidates: Vec<PunchPeer> = self
            .inner
            .roster
            .iter()
            .filter_map(|kv| {
                let e = kv.value();
                if e.peer_id == a.peer_id {
                    return None;
                }
                Self::punch_peer(e)
            })
            .collect();
        let now = now_unix_micros();
        for b in candidates {
            try_emit_pair(
                self.inner.publisher.as_ref(),
                &self.inner.broadcaster,
                &self.inner.punch_tracker,
                &a,
                &b,
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
        true
    }
}
