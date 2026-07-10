//! Register / re-register / auth / ULA resolution.
//!
//! Methods that grow the roster — entry points (`register`,
//! `register_authenticated`), join-token authentication
//! (`authenticate`), the re-registration fast path (`refresh_existing`),
//! and the `requested_ula` vs idx-based fallback decision tree
//! (`resolve_ula`).

use super::{
    Coordinator, CoordinatorError, PEER_SEGMENT, PeerEntry, RegisterOutcome, decode_pubkey,
    now_unix_micros,
};
use crate::auth::{ValidatedClaims, ValidationError};
use crate::http::api::RegisterRequest;
use crate::http::sse::PeerEvent;
use crate::nat::reflexive::{ResolvedEndpoint, resolve_listen_endpoint};
use crate::publisher::publish_event;
use crate::roster::events::PeerJoined;
use crate::roster::identity::stamp_identity;
use std::net::{Ipv6Addr, SocketAddr};
use std::time::Instant;
use tracing::info;
use uuid::Uuid;

impl Coordinator {
    /// Register (or re-register) a peer — escape-hatch convenience that
    /// performs **no** join-token validation and supplies **no** observed
    /// source address (so no reflexive-endpoint reflection).
    ///
    /// Equivalent to [`Self::register_authenticated`] with no bearer token
    /// and no observed addr. When a validator is configured this will fail
    /// with [`CoordinatorError::Unauthorized`] (a token is required); when
    /// no validator is configured it is the dev/E1 path that trusts the
    /// request-supplied `network` + `tags`. Production code goes through
    /// the HTTP handler, which forwards the `Authorization` header AND the
    /// observed source addr to [`Self::register_authenticated`].
    ///
    /// # Errors
    /// See [`CoordinatorError`].
    pub async fn register(
        &self,
        req: RegisterRequest,
    ) -> Result<(PeerEntry, RegisterOutcome), CoordinatorError> {
        self.register_authenticated(req, None, None).await
    }

    /// Register (or re-register) a peer, validating its join token first.
    ///
    /// `bearer` is the raw value of the joiner's `Authorization: Bearer
    /// <token>` header (without the `Bearer ` prefix), or `None` if absent.
    ///
    /// Validation (spec §8):
    /// - If a validator is configured (`AUTH_URL` set) the token is
    ///   **required** and validated against the auth service. A
    ///   missing / invalid / revoked / wrong-kind token, or an unreachable
    ///   validator, yields [`CoordinatorError::Unauthorized`] (HTTP 401)
    ///   and the register is rejected. On success the node's `network` +
    ///   `tags` are taken from the validated **claims** (authoritative) —
    ///   whatever the joiner put in `req.network` / `req.tags` is ignored.
    ///   This closes the §5.1 spoofing gap.
    /// - If no validator is configured (dev/E1 escape hatch) the token is
    ///   ignored and the request-supplied `network` + `tags` are trusted.
    ///
    /// Idempotent in `wg_public_key`: a second register with the same key
    /// returns the original `peer_id` + ULA and does **not** re-emit
    /// `PeerJoined`. The listen-endpoint / display-name from the new
    /// request DO overwrite the prior values; tags are re-stamped through
    /// the same authoritative seam.
    ///
    /// `observed` is the source `SocketAddr` of the register HTTP request
    /// (the peer's NAT public IP + an unrelated TCP port), read by the
    /// handler from [`axum::extract::ConnectInfo`]. Combined with the
    /// request's `wg_listen_port` it yields the peer's reflexive endpoint
    /// (`<observed-public-ip>:<wg_listen_port>`) for cone-NAT traversal:
    /// when the joiner self-reported a loopback / private address we store
    /// the reflexive public endpoint instead so other peers can dial it.
    /// See [`crate::nat::reflexive`]. `None` (e.g. tests without
    /// connect-info) disables reflection and the self-reported endpoint is
    /// used verbatim.
    ///
    /// Data flow on the first-time path: **validate → resolve reflexive
    /// endpoint → build event → publish → apply event → broadcast.**
    /// Publish is best-effort (logged on failure); strict-ordering is a
    /// future tightening.
    ///
    /// # Errors
    /// See [`CoordinatorError`] — auth rejection, allocator exhaustion, and
    /// key length validation.
    pub async fn register_authenticated(
        &self,
        req: RegisterRequest,
        bearer: Option<&str>,
        observed: Option<SocketAddr>,
    ) -> Result<(PeerEntry, RegisterOutcome), CoordinatorError> {
        // Authenticate FIRST, before touching the roster or allocator, so
        // a rejected join has zero side effects. The registering peer's
        // base64 wg_public_key is forwarded to the auth service so it can
        // merge that peer's user-assigned per-peer tags into the returned
        // claims (P2-TAG-PLUMB). Purely additive: an empty key is treated as
        // absent, preserving the prior validate behavior.
        let pubkey_b64 = Some(req.wg_public_key.trim()).filter(|k| !k.is_empty());
        let claims = self.authenticate(bearer, pubkey_b64).await?;

        let pubkey = decode_pubkey(&req.wg_public_key)?;
        if pubkey.len() != 32 {
            return Err(CoordinatorError::InvalidPubkey(pubkey.len()));
        }

        // Resolve the endpoint other peers should dial: prefer the
        // reflexive public endpoint over a self-reported loopback/private
        // address (NAT traversal); keep a self-reported public endpoint or
        // explicit hostname verbatim. The `reflexive` flag records which it
        // was so the heartbeat path knows whether to roam it. Computed
        // identically on the re-register path inside `refresh_existing`.
        let resolved = resolve_listen_endpoint(
            req.listen_endpoint.as_deref(),
            observed,
            req.wg_listen_port,
            req.relay_only,
        );

        // Re-registration path. Holding the by_pubkey shard lock while
        // we look up the peer_id is fine — the roster is keyed by
        // peer_id, so there's no inverse-lookup contention. `refresh_existing`
        // owns its own event emission (a steady `Updated`, or a re-home's
        // `Removed`+`Added` when validated claims move the peer to a new
        // network) so the ULA-move re-advertise stays in one place.
        if let Some(existing_id) = self.inner.by_pubkey.get(&pubkey).map(|v| *v) {
            let entry = self
                .refresh_existing(existing_id, &req, claims.as_ref(), &resolved, observed)
                .await?;
            return Ok((entry, RegisterOutcome::Existed));
        }

        // Stamp authoritative identity (network + tags) in ONE place: the
        // validated claims win when present (production), else the request
        // (escape hatch). See `crate::roster::identity::stamp_identity`.
        let identity = stamp_identity(&req, claims.as_ref());
        // Adopt-on-stale (identity rotation): if this fresh pubkey requests a
        // ULA that a DIFFERENT, STALE peer still pins (the classic node-redeploy
        // pubkey churn), evict the dead holder first so the ULA is free to
        // grant below. A genuinely LIVE holder is kept and the request 409s in
        // `resolve_ula`. Runs BEFORE `resolve_ula` so its uniqueness scan sees
        // the freed ULA. No-op when `requested_ula` is absent / malformed.
        self.evict_stale_ula_holder(req.requested_ula.as_deref())
            .await;
        // First-time path. Resolve the ULA: honour `requested_ula` when it
        // is present, well-formed, and unclaimed (or claimed by this same
        // peer — prevented from reaching here by the re-registration guard
        // above). Fall back to idx-based allocation otherwise.
        let (peer_index, ula) =
            self.resolve_ula(&identity.network, req.requested_ula.as_deref())?;
        let peer_id = Uuid::now_v7();
        let now_micros = now_unix_micros();
        let event = PeerJoined {
            peer_id: peer_id.to_string(),
            wg_public_key: pubkey,
            ula: ula.to_string(),
            // The reflexive-resolved endpoint, not the raw self-report —
            // this is what lands in the roster and is handed to peers.
            listen_endpoint: resolved.endpoint.clone().unwrap_or_default(),
            display_name: req.display_name.clone(),
            network: identity.network,
            tags: identity.tags,
            // The set of app-ULAs the registrant declares it already hosts.
            // Opaque /128s to the coordinator — advertised to viewers like
            // the peer's own ULA (per-app-ULA routing).
            hosted_app_ulas: req.hosted_app_ulas.clone(),
            joined_at_micros: now_micros,
            kind: req.kind.clone(),
            parent: req.parent.clone(),
            app_uuid: req.app_uuid.clone(),
            software_version: req.software_version.clone(),
            mesh_version: req.mesh_version.clone(),
            // Carry the relay-only declaration onto the durable event so it
            // round-trips through replay + is visible to viewers. Drives the
            // hole-punch suppression downstream (`punch_peer`).
            relay_only: req.relay_only,
        };
        // Publish first so the sink sees the event before in-memory state
        // changes; then apply the event to in-memory state from the same
        // data so both stay derived from one source.
        publish_event(self.inner.publisher.as_ref(), PEER_SEGMENT, &event).await;
        let mut entry = self.apply_peer_joined(&event)?;
        // Record the reflexive flag + seed `observed_external` from the
        // register request's source addr (so the hole-punch pairing path
        // has a value before the first heartbeat). Done after apply so it
        // mutates the stored entry.
        entry.endpoint_is_reflexive = resolved.reflexive;
        if let Some(obs) = observed {
            entry.observed_external = obs.to_string();
        }
        if let Some(mut e) = self.inner.roster.get_mut(&peer_id) {
            e.endpoint_is_reflexive = resolved.reflexive;
            e.observed_external.clone_from(&entry.observed_external);
        }
        info!(
            peer_id = %peer_id,
            peer_index,
            ula = %ula,
            display_name = %req.display_name,
            "peer registered",
        );
        self.inner
            .broadcaster
            .broadcast(PeerEvent::Added(entry.to_info()));
        // Membership changed — persist the durable roster snapshot so a
        // coordinator restart restores this peer at the same ULA (no reshuffle,
        // no sticky-ULA 409). Best-effort; the store logs any failure.
        self.persist_roster().await;
        Ok((entry, RegisterOutcome::Created))
    }

    /// Authenticate a register against the configured join-token validator.
    ///
    /// Returns:
    /// - `Ok(Some(claims))` — a validator is configured and the token
    ///   validated as a live `join` token. The caller stamps identity from
    ///   these authoritative claims.
    /// - `Ok(None)` — no validator is configured (dev/E1 escape hatch); the
    ///   caller falls back to the request-supplied tags.
    /// - `Err(Unauthorized)` — a validator is configured but the token was
    ///   missing, the auth service was unreachable / errored, or the token
    ///   was invalid / revoked. Fail closed.
    async fn authenticate(
        &self,
        bearer: Option<&str>,
        wg_public_key: Option<&str>,
    ) -> Result<Option<ValidatedClaims>, CoordinatorError> {
        // Escape hatch: no validator → no claims, trust the request later.
        let Some(validator) = self.inner.validator.as_ref() else {
            return Ok(None);
        };

        // A validator is configured → a token is mandatory.
        let token = bearer
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .ok_or_else(|| {
                CoordinatorError::Unauthorized("missing join token (Authorization: Bearer)".into())
            })?;

        match validator.validate(token, wg_public_key).await {
            // Token validated AND the auth service says it's live.
            Ok(claims) if claims.valid => Ok(Some(claims)),
            // Auth service reachable but token is expired / revoked /
            // tampered (it returns 200 { valid: false } for those).
            Ok(_) => Err(CoordinatorError::Unauthorized(
                "join token invalid or revoked".into(),
            )),
            // Transport / status / decode / wrong-kind — all fail closed.
            Err(ValidationError::WrongKind(kind)) => Err(CoordinatorError::Unauthorized(format!(
                "join token has wrong kind: {kind}"
            ))),
            Err(e) => Err(CoordinatorError::Unauthorized(format!(
                "join token validation failed: {e}"
            ))),
        }
    }

    /// Refresh an existing peer's record on a same-`wg_public_key`
    /// re-register. Owns its own event emission.
    ///
    /// Two modes:
    ///
    /// - **Steady (default):** re-stamp identity (endpoint / tags / metadata)
    ///   IN PLACE at the peer's existing ULA and broadcast `Updated`. The tags
    ///   flow through the same authoritative seam as first-time register so a
    ///   re-register can't smuggle in spoofed identity tags (validated claims
    ///   win when present).
    ///
    /// - **Network re-home (authenticated):** when the register presents
    ///   VALIDATED claims whose `network` DIFFERS from the stored one — a host
    ///   re-tagged from one network to another with a fresh join token bound to
    ///   the SAME wireguard identity (the dedik system→tenant case) — move the
    ///   peer: allocate a FRESH ULA in the new network's slot, reconcile
    ///   `network` + `ula` + `tags`, and re-advertise the `/128` as
    ///   `Removed(old)` then `Added(new)` so every joiner tears down the old
    ///   slot's session/route (the joiner keys sessions by ULA and only drops
    ///   them on `Removed` — a bare `Updated` would strand the old-ULA session)
    ///   and installs the new one. Persisted so the move survives a coordinator
    ///   restart.
    ///
    /// The re-home is GATED on validated claims: an unauthenticated / escape-
    /// hatch re-register never moves networks, so a re-register can no more
    /// smuggle a peer into another network than it can spoof identity tags —
    /// the move requires a token the auth service signed for the new network.
    /// `req.requested_ula` (which still carries the peer's OLD sticky ULA, in
    /// the OLD network's slot) is intentionally ignored on a re-home: it is
    /// meaningless in the new network, so a fresh idx-based ULA is allocated.
    async fn refresh_existing(
        &self,
        peer_id: Uuid,
        req: &RegisterRequest,
        claims: Option<&ValidatedClaims>,
        resolved: &ResolvedEndpoint,
        observed: Option<SocketAddr>,
    ) -> Result<PeerEntry, CoordinatorError> {
        let identity = stamp_identity(req, claims);

        // Detect an AUTHENTICATED network change. Only a validated-claims
        // re-register may move a peer between networks; the escape hatch keeps
        // the legacy "network never changes on re-register" behavior.
        let old_network = self
            .inner
            .roster
            .get(&peer_id)
            .map(|e| e.network.clone())
            .ok_or(CoordinatorError::UnknownPeer(peer_id))?;
        let rehome = claims.is_some() && identity.network != old_network;

        // A re-home allocates the fresh ULA BEFORE taking the roster write
        // guard: the allocator is a distinct lock and can fail (exhaustion), so
        // a failed allocation must leave the entry untouched (fail closed).
        let realloc = if rehome {
            Some(self.inner.allocator.allocate(&identity.network)?)
        } else {
            None
        };

        let (entry, old_ula, old_tags) = {
            let mut e = self
                .inner
                .roster
                .get_mut(&peer_id)
                .ok_or(CoordinatorError::UnknownPeer(peer_id))?;
            let old_ula = e.ula;
            let old_tags = e.tags.clone();
            // Store the reflexive-resolved endpoint, not the raw
            // self-report — a re-register from behind NAT must refresh the
            // peer's reachable endpoint, not regress it to a loopback guess.
            e.listen_endpoint.clone_from(&resolved.endpoint);
            e.endpoint_is_reflexive = resolved.reflexive;
            e.display_name.clone_from(&req.display_name);
            e.tags.clone_from(&identity.tags);
            // Refresh the hosted app-ULA set from the (re-)register request
            // so a re-register reflects the supervisor's current hosting
            // state, mirroring the heartbeat replace semantics.
            e.hosted_app_ulas.clone_from(&req.hosted_app_ulas);
            // Refresh peer metadata — a re-register can update kind/parent/
            // app_uuid if the runner restarts with a different role.
            e.kind.clone_from(&req.kind);
            e.parent.clone_from(&req.parent);
            e.app_uuid.clone_from(&req.app_uuid);
            // A re-register refreshes the reported version when present;
            // an omitting re-register leaves the stored value untouched.
            if req.software_version.is_some() {
                e.software_version.clone_from(&req.software_version);
            }
            if req.mesh_version.is_some() {
                e.mesh_version.clone_from(&req.mesh_version);
            }
            // Re-assert relay-only on every re-register so a peer that flips
            // its reachability is reflected (and the resolved endpoint above
            // — already `None` for relay-only — stays consistent with it).
            e.relay_only = req.relay_only;
            e.last_heartbeat = Instant::now();
            if let Some(obs) = observed {
                e.observed_external = obs.to_string();
            }
            // Re-home: move the peer into the new network at its fresh ULA.
            if let Some((new_index, new_ula)) = realloc {
                e.network.clone_from(&identity.network);
                e.ula = new_ula;
                e.peer_index = new_index;
            }
            (e.clone(), old_ula, old_tags)
        };

        if rehome {
            info!(
                peer_id = %peer_id,
                display_name = %entry.display_name,
                old_network = %old_network,
                new_network = %entry.network,
                old_ula = %old_ula,
                new_ula = %entry.ula,
                old_tags = ?old_tags,
                new_tags = ?entry.tags,
                "peer re-homed to a new network on authenticated re-register \
                 (fresh ULA allocated, /128 re-advertised)",
            );
            // Re-advertise the /128: tear down the OLD slot's session/route on
            // every joiner FIRST (the `Removed` frame carries the OLD tags so
            // the same ACL-filtered set of viewers that had the old peer drop
            // it), then install the NEW ULA via `Added`. Ordering matters —
            // `Removed` before `Added` — so a viewer never briefly holds two
            // sessions for one peer.
            self.inner.broadcaster.broadcast(PeerEvent::Removed {
                peer_id: peer_id.to_string(),
                tags: old_tags,
            });
            self.inner
                .broadcaster
                .broadcast(PeerEvent::Added(entry.to_info()));
            // Membership changed (network + ULA) — persist so a coordinator
            // restart restores the peer in its NEW network/slot, not the old.
            self.persist_roster().await;
        } else {
            info!(peer_id = %peer_id, "peer re-registered (idempotent)");
            self.inner
                .broadcaster
                .broadcast(PeerEvent::Updated(entry.to_info()));
        }
        Ok(entry)
    }

    /// Adopt-on-stale eviction (staleness-gated): if `requested_ula` is held
    /// by a DIFFERENT peer whose `last_heartbeat` is older than
    /// `heartbeat_timeout`, evict that dead holder so the ULA can be granted
    /// to the requesting (fresh) pubkey.
    ///
    /// This is the coordinator half of identity-rotation resilience: a node
    /// redeploy churns its WG pubkey, so its re-register misses the idempotent
    /// `by_pubkey` fast path and arrives here as a "first-time" register that
    /// re-requests its sticky ULA. The STALE old record still pins that ULA, so
    /// without this it would 409 and the node couldn't rejoin until the old
    /// record timed out (up to `heartbeat_timeout`), while peers loop on a dead
    /// `WireGuard` session.
    ///
    /// Strictly staleness-gated: a holder whose heartbeat is CURRENT (a
    /// genuinely live different peer) is NOT evicted — the caller's
    /// `resolve_ula` then returns [`CoordinatorError::UlaConflict`] (409). This
    /// is critical under `--insecure-no-mtls`, where a register is
    /// unauthenticated and must never be able to kick a live peer off its ULA.
    ///
    /// Eviction order mirrors a clean deregister: publish `PeerLeft`, broadcast
    /// `Removed(old)`, `apply_peer_left` (drops roster, `by_pubkey`, relay conn,
    /// punch pairs), then persist the durable roster. The caller then grants the
    /// ULA and broadcasts `Added(new)`, so subscribers always see
    /// `Removed(old)` before `Added(new)`.
    ///
    /// No-op when `requested_ula` is `None` / malformed, unclaimed, or held by
    /// a CURRENT peer.
    async fn evict_stale_ula_holder(&self, requested_ula: Option<&str>) {
        let Some(raw) = requested_ula else {
            return;
        };
        let Ok(addr) = raw.parse::<Ipv6Addr>() else {
            return;
        };
        // Find the peer (if any) holding this exact ULA. The same-pubkey
        // re-register fast path already returned upstream, so a hit here is a
        // DIFFERENT peer.
        let Some(holder_id) = self
            .inner
            .roster
            .iter()
            .find(|kv| kv.value().ula == addr)
            .map(|kv| kv.value().peer_id)
        else {
            return; // unclaimed — nothing to evict
        };
        // Staleness gate: only evict a holder whose last heartbeat is older
        // than the timeout. A live holder is kept (→ 409 in resolve_ula).
        let is_stale = self
            .inner
            .roster
            .get(&holder_id)
            .is_some_and(|e| e.last_heartbeat.elapsed() > self.inner.heartbeat_timeout);
        if !is_stale {
            return;
        }
        tracing::info!(
            stale_peer_id = %holder_id,
            ula = %addr,
            event = "adopt_on_stale_evict",
            "register: evicting stale peer pinning a requested ULA so a rotated identity can adopt it",
        );
        // Mirror a clean deregister: publish first, broadcast Removed, then
        // apply (drops roster + by_pubkey + relay conn + punch pairs).
        let event = crate::roster::events::PeerLeft {
            peer_id: holder_id.to_string(),
            reason: "evicted_stale_ula_holder".to_owned(),
            left_at_micros: now_unix_micros(),
        };
        publish_event(self.inner.publisher.as_ref(), PEER_SEGMENT, &event).await;
        // Capture the departing peer's tags so the SSE remove frame is
        // ACL-filterable per viewer (same contract as `deregister`).
        let tags = self
            .inner
            .roster
            .get(&holder_id)
            .map(|e| e.tags.clone())
            .unwrap_or_default();
        self.inner.broadcaster.broadcast(PeerEvent::Removed {
            peer_id: holder_id.to_string(),
            tags,
        });
        self.apply_peer_left(&event);
        // Membership changed — persist so a coordinator restart doesn't
        // resurrect the evicted holder at the now-reassigned ULA.
        self.persist_roster().await;
    }

    /// Resolve the ULA and peer-index for a first-time register.
    ///
    /// When `requested_ula` is `Some` and parses as a valid `Ipv6Addr`:
    /// - If another peer in the roster already holds that ULA → `UlaConflict`.
    /// - Otherwise → assign it verbatim. The allocator is bumped past the
    ///   address's embedded index so future idx-based allocations in the same
    ///   network block don't collide. The returned `peer_index` is derived
    ///   from the address layout (`segments()[3]`), matching `apply_peer_joined`.
    ///
    /// When `requested_ula` is `None` or malformed → fall back to the
    /// normal sequential idx-based allocation (malformed ULA silently falls
    /// through to idx-based; the caller learns the assigned address from the
    /// returned `PeerEntry`, not the request).
    fn resolve_ula(
        &self,
        network: &str,
        requested_ula: Option<&str>,
    ) -> Result<(u16, Ipv6Addr), CoordinatorError> {
        if let Some(raw) = requested_ula {
            if let Ok(addr) = raw.parse::<Ipv6Addr>() {
                // Uniqueness check: scan the roster for any peer already
                // holding this exact ULA. The re-registration path (same
                // wg_public_key) was already handled above — so if we find
                // a match here it MUST be a different peer.
                let already_claimed = self.inner.roster.iter().any(|kv| kv.value().ula == addr);
                if already_claimed {
                    return Err(CoordinatorError::UlaConflict(raw.to_owned()));
                }
                // Honour the requested address. Derive the index from the
                // address layout (`fd5a:1f00:<slot>:<idx>::1`) so the
                // PeerEntry and the allocator stay consistent.
                let peer_index = addr.segments()[3];
                let slot = addr.segments()[2];
                // Advance the allocator so subsequent idx-based allocations
                // in this network block skip past the manually-assigned index.
                self.inner.allocator.bump_slot_at_least(slot, peer_index);
                return Ok((peer_index, addr));
            }
        }
        // Fall back to the standard sequential idx-based allocation.
        Ok(self.inner.allocator.allocate(network)?)
    }
}
