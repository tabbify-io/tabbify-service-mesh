//! Register / re-register / auth / ULA resolution.
//!
//! Methods that grow the roster — entry points (`register`,
//! `register_authenticated`), join-token authentication
//! (`authenticate`), the re-registration fast path (`refresh_existing`),
//! and the `requested_ula` vs idx-based fallback decision tree
//! (`resolve_ula`).

use super::{
    Coordinator, CoordinatorError, PeerEntry, PEER_SEGMENT, RegisterOutcome, decode_pubkey,
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
        // a rejected join has zero side effects.
        let claims = self.authenticate(bearer).await?;

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
        let resolved =
            resolve_listen_endpoint(req.listen_endpoint.as_deref(), observed, req.wg_listen_port);

        // Re-registration path. Holding the by_pubkey shard lock while
        // we look up the peer_id is fine — the roster is keyed by
        // peer_id, so there's no inverse-lookup contention.
        if let Some(existing_id) = self.inner.by_pubkey.get(&pubkey).map(|v| *v) {
            let entry =
                self.refresh_existing(existing_id, &req, claims.as_ref(), &resolved, observed)?;
            self.inner
                .broadcaster
                .broadcast(PeerEvent::Updated(entry.to_info()));
            return Ok((entry, RegisterOutcome::Existed));
        }

        // Stamp authoritative identity (network + tags) in ONE place: the
        // validated claims win when present (production), else the request
        // (escape hatch). See `crate::roster::identity::stamp_identity`.
        let identity = stamp_identity(&req, claims.as_ref());
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

        match validator.validate(token).await {
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

    fn refresh_existing(
        &self,
        peer_id: Uuid,
        req: &RegisterRequest,
        claims: Option<&ValidatedClaims>,
        resolved: &ResolvedEndpoint,
        observed: Option<SocketAddr>,
    ) -> Result<PeerEntry, CoordinatorError> {
        // Re-stamp identity through the same authoritative seam as
        // first-time register so a re-register can't be used to smuggle in
        // spoofed tags either: the validated claims win when present. The
        // network is NOT changed on re-register: a peer keeps the ULA block
        // it was first allocated in (changing it would orphan its address).
        let identity = stamp_identity(req, claims);
        let entry = {
            let mut e = self
                .inner
                .roster
                .get_mut(&peer_id)
                .ok_or(CoordinatorError::UnknownPeer(peer_id))?;
            // Store the reflexive-resolved endpoint, not the raw
            // self-report — a re-register from behind NAT must refresh the
            // peer's reachable endpoint, not regress it to a loopback guess.
            e.listen_endpoint.clone_from(&resolved.endpoint);
            e.endpoint_is_reflexive = resolved.reflexive;
            e.display_name.clone_from(&req.display_name);
            e.tags = identity.tags;
            // Refresh the hosted app-ULA set from the (re-)register request
            // so a re-register reflects the supervisor's current hosting
            // state, mirroring the heartbeat replace semantics.
            e.hosted_app_ulas.clone_from(&req.hosted_app_ulas);
            // Refresh peer metadata — a re-register can update kind/parent/
            // app_uuid if the runner restarts with a different role.
            e.kind.clone_from(&req.kind);
            e.parent.clone_from(&req.parent);
            e.app_uuid.clone_from(&req.app_uuid);
            e.last_heartbeat = Instant::now();
            if let Some(obs) = observed {
                e.observed_external = obs.to_string();
            }
            e.clone()
        };
        info!(peer_id = %peer_id, "peer re-registered (idempotent)");
        Ok(entry)
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
