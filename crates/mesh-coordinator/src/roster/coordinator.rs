//! In-memory peer roster + register/heartbeat/deregister state machine.
//!
//! The roster lives in a `DashMap<Uuid, PeerEntry>` plus a sister
//! `DashMap<wg_public_key, Uuid>` for idempotent re-registration. Both
//! maps are kept consistent under each mutating method.

use crate::auth::{AuthValidator, ValidatedClaims, ValidationError};
use crate::http::api::{PeerInfo, RegisterRequest};
use crate::http::sse::{PeerBroadcaster, PeerEvent};
use crate::nat::holepunch::{PunchPeer, PunchTracker, try_emit_pair};
use crate::nat::reflexive::{is_sticky_explicit_endpoint, resolve_listen_endpoint};
use crate::policy::PolicyStore;
use crate::publisher::{SharedPublisher, publish_event};
use crate::roster::allocator::{AllocError, UlaAllocator};
use crate::roster::events::{PeerHeartbeat, PeerJoined, PeerLeft};
use crate::roster::identity::stamp_identity;
use dashmap::DashMap;
use std::net::{Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tracing::{debug, info};
use uuid::Uuid;

/// Logical segment label for every peer-lifecycle event this coordinator
/// emits to its [`crate::publisher::EventPublisher`].
pub const PEER_SEGMENT: &str = "platform.mesh.peers";

/// Coordinator-internal record. The wire-facing `PeerInfo` is derived
/// from this on read so the broadcast format stays in lock-step with
/// the roster snapshot.
#[derive(Debug, Clone)]
pub struct PeerEntry {
    /// Coordinator-assigned UUID v7.
    pub peer_id: Uuid,
    /// 32-byte X25519 public key — used to detect re-registration.
    pub wg_public_key: Vec<u8>,
    /// IPv6 ULA in `fd5a:1f00:<network16>:<idx>::1`.
    pub ula: Ipv6Addr,
    /// Sequential index *within this peer's network* in the ULA scheme.
    /// Useful for debugging. Not globally unique — scoped to `network`.
    pub peer_index: u16,
    /// Joiner-reported listen socket (may be `None` for peers behind NAT).
    pub listen_endpoint: Option<String>,
    /// Human-readable nickname.
    pub display_name: String,
    /// Network this peer belongs to (selects its ULA block, spec §6).
    pub network: String,
    /// Effective tags — drive policy visibility. Stamped via the identity
    /// seam ([`crate::roster::identity`]) so the source can be swapped to
    /// JWT claims in E4 without touching the roster/policy code.
    pub tags: Vec<String>,
    /// App-ULAs (IPv6 literals, `fd5a:1f02:...`) this peer currently
    /// hosts. Set on register, REPLACED wholesale on every heartbeat (a
    /// supervisor re-sends its full hosted set each tick). The coordinator
    /// treats these as opaque `/128`s — `derive_app_ula` lives in the app
    /// layer — and advertises them to every viewer like [`Self::ula`]
    /// (per-app-ULA routing).
    pub hosted_app_ulas: Vec<String>,
    /// Joined-at, wall-clock micros (matches event field).
    pub joined_at_micros: i64,
    /// Last heartbeat — monotonic clock; only used for timeout sweeps.
    pub last_heartbeat: Instant,
    /// Last `observed_external` socket addr the coordinator saw on this
    /// peer's heartbeat (source IP+port from the HTTP request). Empty when
    /// no heartbeat has been recorded yet or the source addr was
    /// unavailable (e.g. tests driving the router without connect-info).
    /// Used by the Stage 2 hole punch skeleton to know which pairs
    /// are eligible for a `HolePunchInitiate` emission.
    pub observed_external: String,
    /// Whether [`Self::listen_endpoint`] was DERIVED from the
    /// coordinator-observed reflexive address (`true`) rather than
    /// explicitly self-reported by the joiner (`false`).
    ///
    /// This is the discriminator the heartbeat path needs: a reflexive
    /// endpoint should ROAM (follow the peer's observed public IP across
    /// heartbeats), whereas an explicit `--advertise-endpoint` (public IP
    /// or hostname the operator chose) must be STICKY and never clobbered
    /// by a heartbeat's observed source. Both land in `listen_endpoint` as
    /// opaque strings, so we can't tell them apart without this flag.
    pub endpoint_is_reflexive: bool,
    /// Peer role. `"peer"` for a normal supervisor/joiner; `"runner"` for
    /// a per-app runner that joins the mesh as its own peer. Defaults to
    /// `"peer"` for existing joiners that do not supply the field.
    pub kind: String,
    /// ULA of the supervisor that owns this runner. `None` for plain peers.
    pub parent: Option<String>,
    /// UUID of the app this runner serves. `None` for plain peers.
    pub app_uuid: Option<String>,
}

impl PeerEntry {
    /// Snapshot for SSE / GET handlers. Strings are clones — that's fine
    /// since this fires on register / heartbeat / SSE bootstrap, not the
    /// hot path.
    #[must_use]
    pub fn to_info(&self) -> PeerInfo {
        PeerInfo {
            peer_id: self.peer_id.to_string(),
            wg_public_key: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                &self.wg_public_key,
            ),
            ula: self.ula.to_string(),
            listen_endpoint: self.listen_endpoint.clone(),
            display_name: self.display_name.clone(),
            network: self.network.clone(),
            tags: self.tags.clone(),
            hosted_app_ulas: self.hosted_app_ulas.clone(),
            joined_at_micros: self.joined_at_micros,
            kind: self.kind.clone(),
            parent: self.parent.clone(),
            app_uuid: self.app_uuid.clone(),
        }
    }
}

/// Errors a coordinator method can surface to its HTTP handler.
#[derive(Debug, Error)]
pub enum CoordinatorError {
    /// `peer_id` is not a valid UUID.
    #[error("invalid peer id: {0}")]
    InvalidPeerId(String),
    /// The `wg_public_key` was empty or not exactly 32 bytes.
    #[error("invalid wireguard public key (expected 32 bytes, got {0})")]
    InvalidPubkey(usize),
    /// The base64 `wg_public_key` was malformed.
    #[error("invalid base64 in wg_public_key: {0}")]
    PubkeyDecode(String),
    /// The peer index space is exhausted.
    #[error(transparent)]
    Allocation(#[from] AllocError),
    /// Heartbeat or deregister referenced a peer that was never registered.
    #[error("peer not found: {0}")]
    UnknownPeer(Uuid),
    /// The register could not be authenticated: the join token was
    /// missing, invalid, revoked, of the wrong kind, or the auth service
    /// was unreachable. The HTTP layer maps this to `401`. Carries a short
    /// reason for the coordinator log (never echoed to the joiner beyond
    /// the status code).
    #[error("unauthorized join: {0}")]
    Unauthorized(String),
    /// The `requested_ula` is already held by a DIFFERENT peer. The HTTP
    /// layer maps this to `409 Conflict`. The string carries the conflicting
    /// ULA so the coordinator log can surface it.
    #[error("requested ULA already claimed by another peer: {0}")]
    UlaConflict(String),
}

/// Outcome of `register`: whether the peer was new or already in the
/// roster (re-registration). Both paths return the same `PeerEntry`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisterOutcome {
    /// First time we see this `wg_public_key` — `PeerJoined` was emitted.
    Created,
    /// Same `wg_public_key` as a previously-registered peer — same
    /// `peer_id` + ULA returned, no `PeerJoined` re-emitted.
    Existed,
}

/// Wrapper over the roster + allocator + publisher + broadcaster. Cheap
/// to clone — every field is `Arc`-shared internally.
#[derive(Clone)]
pub struct Coordinator {
    pub(crate) inner: Arc<Inner>,
}

/// Shared internal state — `pub(crate)` so the sibling `apply` module
/// can mutate the roster without going through the public API.
pub(crate) struct Inner {
    pub(crate) roster: DashMap<Uuid, PeerEntry>,
    pub(crate) by_pubkey: DashMap<Vec<u8>, Uuid>,
    pub(crate) allocator: UlaAllocator,
    pub(crate) publisher: SharedPublisher,
    pub(crate) broadcaster: PeerBroadcaster,
    /// Live ACL policy. The coordinator filters every node's view of the
    /// roster through this (register response + SSE stream) so a node only
    /// learns the peers it may reach. Default-deny when empty.
    pub(crate) policy: PolicyStore,
    /// Join-token validator (spec §8). `Some` in production: every
    /// register must present a join token that validates against the auth
    /// service, and the node's `network` + `tags` are taken from the
    /// returned claims (authoritative). `None` is the dev/E1 escape hatch
    /// (no `AUTH_URL`): no validation, request-supplied tags trusted.
    pub(crate) validator: Option<AuthValidator>,
    pub(crate) heartbeat_timeout: Duration,
    /// Stage 2 skeleton — tracks which canonical `(peer_id, peer_id)`
    /// pairs have already had their `HolePunchInitiate` events emitted
    /// so a noisy heartbeat stream doesn't re-publish each tick.
    pub(crate) punch_tracker: PunchTracker,
}

impl Coordinator {
    /// Build a fresh coordinator with an empty roster and a default-deny
    /// (empty) ACL policy.
    ///
    /// With an empty policy, [`Self::visible_peers`] returns nothing for
    /// every viewer — useful for tests that focus on the roster state
    /// machine. Use [`Self::with_policy`] to wire a real policy.
    #[must_use]
    pub fn new(publisher: SharedPublisher, heartbeat_timeout: Duration) -> Self {
        Self::with_policy(publisher, heartbeat_timeout, PolicyStore::empty())
    }

    /// Build a coordinator with an explicit ACL [`PolicyStore`] and **no**
    /// join-token validator (the dev/E1 escape hatch — request-supplied
    /// tags are trusted). Use [`Self::with_policy_and_validator`] to wire
    /// the auth service and make claims authoritative.
    #[must_use]
    pub fn with_policy(
        publisher: SharedPublisher,
        heartbeat_timeout: Duration,
        policy: PolicyStore,
    ) -> Self {
        Self::with_policy_and_validator(publisher, heartbeat_timeout, policy, None)
    }

    /// Build a coordinator with an explicit ACL [`PolicyStore`] and an
    /// optional join-token [`AuthValidator`].
    ///
    /// - `validator = Some(_)` — production: every register must present a
    ///   valid join token (`Authorization: Bearer`); `network` + `tags`
    ///   come from the validated claims (authoritative, spec §8).
    /// - `validator = None` — dev/E1 escape hatch: no validation,
    ///   request-supplied `network` + `tags` are trusted.
    #[must_use]
    pub fn with_policy_and_validator(
        publisher: SharedPublisher,
        heartbeat_timeout: Duration,
        policy: PolicyStore,
        validator: Option<AuthValidator>,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                roster: DashMap::new(),
                by_pubkey: DashMap::new(),
                allocator: UlaAllocator::new(),
                publisher,
                broadcaster: PeerBroadcaster::new(),
                policy,
                validator,
                heartbeat_timeout,
                punch_tracker: PunchTracker::new(),
            }),
        }
    }

    /// Borrow the live policy store — the policy HTTP handlers read/replace
    /// through it, and a PUT re-filters the roster + pushes SSE updates.
    #[must_use]
    pub fn policy(&self) -> &PolicyStore {
        &self.inner.policy
    }

    /// Heartbeat timeout used by the background sweeper.
    #[must_use]
    pub fn heartbeat_timeout(&self) -> Duration {
        self.inner.heartbeat_timeout
    }

    /// Borrow the broadcaster — the SSE handler subscribes through it.
    #[must_use]
    pub fn broadcaster(&self) -> &PeerBroadcaster {
        &self.inner.broadcaster
    }

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

    /// Borrow the hole-punch tracker. Tests use this to inspect which
    /// pairs have already been emitted; production code never reaches
    /// past `Inner` to touch this directly.
    #[must_use]
    pub fn punch_tracker(&self) -> &PunchTracker {
        &self.inner.punch_tracker
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

    /// Snapshot the entire roster, ordered by `peer_index` for stable output.
    #[must_use]
    pub fn snapshot(&self) -> Vec<PeerInfo> {
        let mut entries: Vec<PeerEntry> = self
            .inner
            .roster
            .iter()
            .map(|kv| kv.value().clone())
            .collect();
        entries.sort_by_key(|p| p.peer_index);
        entries.iter().map(PeerEntry::to_info).collect()
    }

    /// Iterate over peer ids whose `last_heartbeat` is older than
    /// `heartbeat_timeout`. Used by the background sweeper.
    #[must_use]
    pub fn stale_peers(&self, now: Instant) -> Vec<Uuid> {
        let timeout = self.inner.heartbeat_timeout;
        self.inner
            .roster
            .iter()
            .filter_map(|kv| {
                if now.duration_since(kv.value().last_heartbeat) > timeout {
                    Some(*kv.key())
                } else {
                    None
                }
            })
            .collect()
    }

    fn refresh_existing(
        &self,
        peer_id: Uuid,
        req: &RegisterRequest,
        claims: Option<&ValidatedClaims>,
        resolved: &crate::nat::reflexive::ResolvedEndpoint,
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
    ) -> Result<(u16, std::net::Ipv6Addr), CoordinatorError> {
        if let Some(raw) = requested_ula {
            if let Ok(addr) = raw.parse::<std::net::Ipv6Addr>() {
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

fn decode_pubkey(s: &str) -> Result<Vec<u8>, CoordinatorError> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| CoordinatorError::PubkeyDecode(e.to_string()))
}

/// Wall-clock micros since UNIX epoch. Saturates on overflow — fine for
/// the next ~290 000 years.
fn now_unix_micros() -> i64 {
    // SystemTime → micros. We intentionally don't reach for `time::OffsetDateTime`
    // here: this is one int field on an event and bringing the full time
    // crate into the hot path is overkill.
    let dur = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    i64::try_from(dur.as_micros()).unwrap_or(i64::MAX)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::http::api::RegisterRequest;
    use crate::publisher::NoopPublisher;
    use base64::Engine as _;

    fn pubkey(seed: u8) -> String {
        let bytes = [seed; 32];
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    fn coordinator() -> Coordinator {
        Coordinator::new(Arc::new(NoopPublisher), Duration::from_secs(60))
    }

    fn req(seed: u8, name: &str) -> RegisterRequest {
        RegisterRequest {
            wg_public_key: pubkey(seed),
            listen_endpoint: Some("127.0.0.1:51820".into()),
            wg_listen_port: Some(51820),
            display_name: name.into(),
            network: String::new(),
            tags: vec!["dev-machine".into()],
            hosted_app_ulas: vec![],
            kind: "peer".into(),
            parent: None,
            app_uuid: None,
            requested_ula: None,
        }
    }

    #[tokio::test]
    async fn register_assigns_sequential_ulas() {
        let c = coordinator();
        let (p1, o1) = c.register(req(1, "alice")).await.expect("register 1");
        let (p2, o2) = c.register(req(2, "bob")).await.expect("register 2");
        assert_eq!(o1, RegisterOutcome::Created);
        assert_eq!(o2, RegisterOutcome::Created);
        assert_eq!(p1.peer_index, 1);
        assert_eq!(p2.peer_index, 2);
        assert_ne!(p1.peer_id, p2.peer_id);
        assert_ne!(p1.ula, p2.ula);
    }

    #[tokio::test]
    async fn re_register_same_pubkey_is_idempotent() {
        let c = coordinator();
        let (first, o1) = c.register(req(7, "alice")).await.expect("first");
        let (second, o2) = c
            .register(RegisterRequest {
                display_name: "alice-renamed".into(),
                ..req(7, "ignored")
            })
            .await
            .expect("re-register");
        assert_eq!(o1, RegisterOutcome::Created);
        assert_eq!(o2, RegisterOutcome::Existed);
        assert_eq!(first.peer_id, second.peer_id);
        assert_eq!(first.ula, second.ula);
        assert_eq!(second.display_name, "alice-renamed");
        // Only one ULA index issued, despite two register calls.
        assert_eq!(c.snapshot().len(), 1);
    }

    #[tokio::test]
    async fn heartbeat_updates_only_known_peers() {
        let c = coordinator();
        let (entry, _) = c.register(req(3, "carol")).await.expect("register");
        let updated = c
            .heartbeat(
                entry.peer_id,
                "203.0.113.1:51820".into(),
                Some(51820),
                vec![],
            )
            .await
            .expect("heartbeat");
        assert_eq!(updated.peer_id, entry.peer_id);

        let bogus = Uuid::now_v7();
        let err = c
            .heartbeat(bogus, "ignored".into(), None, vec![])
            .await
            .expect_err("unknown peer");
        assert!(matches!(err, CoordinatorError::UnknownPeer(_)));
    }

    #[tokio::test]
    async fn deregister_is_idempotent() {
        let c = coordinator();
        let (entry, _) = c.register(req(4, "dave")).await.expect("register");
        assert!(c.deregister(entry.peer_id, "test").await);
        // Second call returns false, no panic, no double-publish.
        assert!(!c.deregister(entry.peer_id, "test").await);
        // After deregister the by_pubkey index is also clear, so the
        // same pubkey can register fresh and earn a new peer_id.
        let (replacement, outcome) = c
            .register(req(4, "dave-prime"))
            .await
            .expect("register again");
        assert_ne!(replacement.peer_id, entry.peer_id);
        assert_eq!(outcome, RegisterOutcome::Created);
    }

    #[tokio::test]
    async fn snapshot_is_ordered_by_peer_index() {
        let c = coordinator();
        let _ = c.register(req(10, "p10")).await.expect("ok");
        let _ = c.register(req(11, "p11")).await.expect("ok");
        let _ = c.register(req(12, "p12")).await.expect("ok");
        let snap = c.snapshot();
        let names: Vec<_> = snap.iter().map(|p| p.display_name.clone()).collect();
        assert_eq!(names, vec!["p10".to_string(), "p11".into(), "p12".into()]);
    }

    #[tokio::test]
    async fn invalid_pubkey_length_is_rejected() {
        let c = coordinator();
        let too_short = base64::engine::general_purpose::STANDARD.encode([0u8; 16]);
        let err = c
            .register(RegisterRequest {
                wg_public_key: too_short,
                listen_endpoint: None,
                wg_listen_port: None,
                display_name: "short".into(),
                network: String::new(),
                tags: vec![],
                hosted_app_ulas: vec![],
                kind: "peer".into(),
                parent: None,
                app_uuid: None,
                requested_ula: None,
            })
            .await
            .expect_err("invalid pubkey");
        assert!(matches!(err, CoordinatorError::InvalidPubkey(16)));
    }

    #[tokio::test]
    async fn stale_peers_returns_only_timed_out_entries() {
        let c = Coordinator::new(Arc::new(NoopPublisher), Duration::from_millis(50));
        let (a, _) = c.register(req(20, "a")).await.expect("ok");
        let _ = c.register(req(21, "b")).await.expect("ok");
        // Backdate `a` past the timeout.
        {
            let mut e = c.inner.roster.get_mut(&a.peer_id).expect("entry");
            e.last_heartbeat = Instant::now()
                .checked_sub(Duration::from_millis(500))
                .expect("instant arithmetic");
        }
        let stale = c.stale_peers(Instant::now());
        assert_eq!(stale, vec![a.peer_id]);
    }

    // -----------------------------------------------------------------
    // Stage 2 skeleton — hole punch initiation tests.
    //
    // These verify the coordinator's heartbeat hook calls the holepunch
    // emit logic at the right times. Detailed semantics of the emit
    // function itself are covered in `crate::nat::holepunch::tests` —
    // here we focus on the wiring: «does heartbeat actually trigger it
    // when both peers have external addrs, and stay quiet otherwise».
    // -----------------------------------------------------------------

    use crate::publisher::EventPublisher;
    use crate::roster::events::HolePunchInitiate;
    use async_trait::async_trait;
    use parking_lot::Mutex;
    use std::sync::Arc as StdArc;

    /// A single captured publish: `(event_type, segment, payload)`.
    type CapturedEvent = (String, String, Vec<u8>);

    /// Test-only publisher that records every `(event_type, segment,
    /// payload)` tuple so assertions can inspect what the coordinator
    /// emitted. Cheap to clone — wraps a `Mutex<Vec<...>>` in `Arc`.
    #[derive(Clone, Default)]
    struct CapturingPublisher {
        events: StdArc<Mutex<Vec<CapturedEvent>>>,
    }

    impl CapturingPublisher {
        fn new() -> Self {
            Self::default()
        }

        fn events(&self) -> Vec<CapturedEvent> {
            self.events.lock().clone()
        }

        fn count_by_type(&self, ty: &str) -> usize {
            self.events
                .lock()
                .iter()
                .filter(|(event_type, _, _)| event_type == ty)
                .count()
        }
    }

    #[async_trait]
    impl EventPublisher for CapturingPublisher {
        async fn publish(
            &self,
            event_type: &str,
            segment: &str,
            payload: Vec<u8>,
        ) -> Result<(), String> {
            self.events
                .lock()
                .push((event_type.to_owned(), segment.to_owned(), payload));
            Ok(())
        }
    }

    fn coordinator_with(publisher: StdArc<CapturingPublisher>) -> Coordinator {
        Coordinator::new(publisher, Duration::from_secs(60))
    }

    #[tokio::test]
    async fn heartbeat_emits_holepunch_pair_when_both_peers_have_external() {
        let pub_ = StdArc::new(CapturingPublisher::new());
        let c = coordinator_with(pub_.clone());
        let (alice, _) = c.register(req(40, "alice")).await.expect("a");
        let (bob, _) = c.register(req(41, "bob")).await.expect("b");

        // First heartbeats — neither peer has been seen yet, so each
        // populates its own observed_external. After the first heartbeat
        // from each, both peers have non-empty external addrs.
        c.heartbeat(
            alice.peer_id,
            "203.0.113.10:11111".into(),
            Some(51820),
            vec![],
        )
        .await
        .expect("a hb1");
        // Only alice has external so far — no holepunch event yet.
        assert_eq!(
            pub_.count_by_type("holepunch_initiate"),
            0,
            "should not emit until both peers have observed_external"
        );

        c.heartbeat(
            bob.peer_id,
            "198.51.100.20:22222".into(),
            Some(51820),
            vec![],
        )
        .await
        .expect("b hb1");

        // Now both have external addrs → exactly one pair = 2 events.
        let punch_events = pub_.count_by_type("holepunch_initiate");
        assert_eq!(
            punch_events, 2,
            "expected exactly 2 HolePunchInitiate events (one per peer)"
        );

        // Decode and verify field values.
        let events: Vec<HolePunchInitiate> = pub_
            .events()
            .into_iter()
            .filter(|(t, _, _)| t == "holepunch_initiate")
            .map(|(_, _, bytes)| {
                serde_json::from_slice::<HolePunchInitiate>(&bytes).expect("decode")
            })
            .collect();
        let from_alice = events
            .iter()
            .find(|e| e.initiator_peer_id == alice.peer_id.to_string())
            .expect("event from alice");
        assert_eq!(from_alice.target_peer_id, bob.peer_id.to_string());
        // Target is bob's REFLEXIVE WG endpoint (observed-ip:wg-port), not the
        // raw heartbeat TCP source (:22222).
        assert_eq!(from_alice.target_external_endpoint, "198.51.100.20:51820");
        let from_bob = events
            .iter()
            .find(|e| e.initiator_peer_id == bob.peer_id.to_string())
            .expect("event from bob");
        assert_eq!(from_bob.target_peer_id, alice.peer_id.to_string());
        assert_eq!(from_bob.target_external_endpoint, "203.0.113.10:51820");

        // Sanity: the tracker should know about this pair now.
        assert_eq!(c.punch_tracker().len(), 1);

        // Another heartbeat from alice should NOT re-emit (dedup).
        c.heartbeat(
            alice.peer_id,
            "203.0.113.10:11111".into(),
            Some(51820),
            vec![],
        )
        .await
        .expect("a hb2");
        assert_eq!(
            pub_.count_by_type("holepunch_initiate"),
            2,
            "dedup must prevent re-emit on subsequent heartbeats"
        );
    }

    /// The hole-punch pair must reach live SSE subscribers over the
    /// broadcast channel — not just the event-log publisher. Without this
    /// the joiner (which consumes the SSE stream) never learns to punch.
    #[tokio::test]
    async fn heartbeat_broadcasts_holepunch_pair_to_sse_subscribers() {
        let pub_ = StdArc::new(CapturingPublisher::new());
        let c = coordinator_with(pub_.clone());
        let (alice, _) = c.register(req(70, "alice")).await.expect("a");
        let (bob, _) = c.register(req(71, "bob")).await.expect("b");

        // Subscribe AFTER register so the channel only carries the
        // heartbeat-time frames we care about.
        let mut rx = c.broadcaster().subscribe();
        c.heartbeat(
            alice.peer_id,
            "203.0.113.70:11111".into(),
            Some(51820),
            vec![],
        )
        .await
        .expect("a hb");
        c.heartbeat(
            bob.peer_id,
            "198.51.100.71:22222".into(),
            Some(51820),
            vec![],
        )
        .await
        .expect("b hb");

        // Drain the channel and keep only the hole-punch frames.
        let mut punches = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            if let PeerEvent::HolePunch(hp) = ev {
                punches.push(hp);
            }
        }
        assert_eq!(
            punches.len(),
            2,
            "expected the hole-punch pair on the broadcast channel"
        );
        // Each event points the initiator at the OTHER peer's REFLEXIVE WG
        // endpoint (observed-ip:wg-port), not the raw heartbeat TCP source.
        assert!(
            punches
                .iter()
                .any(|p| p.target_external_endpoint == "203.0.113.70:51820")
        );
        assert!(
            punches
                .iter()
                .any(|p| p.target_external_endpoint == "198.51.100.71:51820")
        );
    }

    #[tokio::test]
    async fn heartbeat_does_not_emit_when_one_peer_lacks_external() {
        let pub_ = StdArc::new(CapturingPublisher::new());
        let c = coordinator_with(pub_.clone());
        let (alice, _) = c.register(req(50, "alice")).await.expect("a");
        let (_bob, _) = c.register(req(51, "bob")).await.expect("b");

        // Alice heartbeats with a known external — bob never heartbeats,
        // so its observed_external stays empty.
        c.heartbeat(alice.peer_id, "203.0.113.30:33333".into(), None, vec![])
            .await
            .expect("a hb");

        assert_eq!(
            pub_.count_by_type("holepunch_initiate"),
            0,
            "must not emit when target peer's external is unknown"
        );
        assert!(c.punch_tracker().is_empty());
    }

    #[tokio::test]
    async fn heartbeat_with_empty_external_skips_emit() {
        let pub_ = StdArc::new(CapturingPublisher::new());
        let c = coordinator_with(pub_.clone());
        let (alice, _) = c.register(req(60, "alice")).await.expect("a");
        let (bob, _) = c.register(req(61, "bob")).await.expect("b");

        // Alice gets an external on heartbeat 1.
        c.heartbeat(alice.peer_id, "203.0.113.50:44444".into(), None, vec![])
            .await
            .expect("a hb");

        // Bob heartbeats but ConnectInfo wasn't captured — empty string.
        // This mirrors the test-router path that drives via Router::call
        // without the make_service wrapper.
        c.heartbeat(bob.peer_id, String::new(), None, vec![])
            .await
            .expect("b hb empty external");

        assert_eq!(
            pub_.count_by_type("holepunch_initiate"),
            0,
            "empty observed_external must not trigger an emit"
        );
    }

    // -----------------------------------------------------------------
    // Stage 2 — reflexive endpoint reflection (the NAT-traversal path).
    //
    // These drive `register_authenticated` / `heartbeat` with a synthetic
    // PUBLIC observed `SocketAddr` (what the HTTP handler reads off
    // `ConnectInfo` in production) and assert the coordinator STORES the
    // reflexive `<observed-public-ip>:<wg-port>` endpoint, not the
    // joiner's loopback self-report. The pure decision table is covered in
    // `crate::nat::reflexive::tests`; this is the roster-integration wiring.
    // -----------------------------------------------------------------

    /// A joiner behind NAT self-reports `127.0.0.1:<port>` but the
    /// coordinator observes a PUBLIC source IP. The stored
    /// `listen_endpoint` must be the reflexive `<public-ip>:<wg-port>`.
    #[tokio::test]
    async fn register_stores_reflexive_endpoint_for_natted_peer() {
        let c = coordinator();
        // req() self-reports 127.0.0.1:51820 with wg_listen_port 51820.
        let observed: SocketAddr = "203.0.113.7:34812".parse().expect("addr");
        let (entry, outcome) = c
            .register_authenticated(req(1, "natted"), None, Some(observed))
            .await
            .expect("register");
        assert_eq!(outcome, RegisterOutcome::Created);
        // Reflexive: observed public IP + REPORTED wg port (51820), NOT the
        // HTTP source port 34812 and NOT the loopback self-report.
        assert_eq!(entry.listen_endpoint.as_deref(), Some("203.0.113.7:51820"));
        // The observed external (full sockaddr) is seeded for hole-punch.
        assert_eq!(entry.observed_external, "203.0.113.7:34812");
        // And the stored roster entry agrees.
        let stored = c.snapshot();
        assert_eq!(
            stored[0].listen_endpoint.as_deref(),
            Some("203.0.113.7:51820")
        );
    }

    /// An explicit `--advertise-endpoint` pointing at a PUBLIC address must
    /// survive — reflexive discovery must not clobber an operator override.
    #[tokio::test]
    async fn register_preserves_public_self_report_over_reflexive() {
        let c = coordinator();
        let req = RegisterRequest {
            wg_public_key: pubkey(2),
            listen_endpoint: Some("198.51.100.50:51820".into()), // explicit public advert
            wg_listen_port: Some(51820),
            display_name: "advertised".into(),
            network: String::new(),
            tags: vec!["dev-machine".into()],
            hosted_app_ulas: vec![],
            kind: "peer".into(),
            parent: None,
            app_uuid: None,
            requested_ula: None,
        };
        let observed: SocketAddr = "203.0.113.7:34812".parse().expect("addr");
        let (entry, _) = c
            .register_authenticated(req, None, Some(observed))
            .await
            .expect("register");
        assert_eq!(
            entry.listen_endpoint.as_deref(),
            Some("198.51.100.50:51820"),
            "explicit public advertise-endpoint must win over reflexive"
        );
    }

    /// Same-host smoke test: coordinator observes a loopback / private
    /// source (it's on the same machine), so there's nothing public to
    /// advertise — the loopback self-report is kept verbatim. This is the
    /// back-compat path that keeps local two-peer runs working.
    #[tokio::test]
    async fn register_keeps_loopback_when_observed_is_private() {
        let c = coordinator();
        let observed: SocketAddr = "127.0.0.1:55001".parse().expect("addr");
        let (entry, _) = c
            .register_authenticated(req(3, "local"), None, Some(observed))
            .await
            .expect("register");
        assert_eq!(entry.listen_endpoint.as_deref(), Some("127.0.0.1:51820"));
    }

    /// A heartbeat from a NEW public IP (NAT rebind / roaming) rolls the
    /// stored reflexive endpoint over to the new IP, keeping the WG port.
    #[tokio::test]
    async fn heartbeat_rolls_reflexive_endpoint_over_on_ip_change() {
        let c = coordinator();
        let observed1: SocketAddr = "203.0.113.7:34812".parse().expect("addr");
        let (entry, _) = c
            .register_authenticated(req(4, "roamer"), None, Some(observed1))
            .await
            .expect("register");
        assert_eq!(entry.listen_endpoint.as_deref(), Some("203.0.113.7:51820"));

        // Heartbeat arrives from a different public IP — same WG port.
        let updated = c
            .heartbeat(
                entry.peer_id,
                "198.51.100.99:60000".into(),
                Some(51820),
                vec![],
            )
            .await
            .expect("heartbeat");
        assert_eq!(
            updated.listen_endpoint.as_deref(),
            Some("198.51.100.99:51820"),
            "reflexive endpoint must follow the peer's new public IP"
        );
    }

    /// A heartbeat must NOT clobber an explicit public advertise-endpoint:
    /// the peer's stored public endpoint is fed back as the self-report and
    /// preserved.
    #[tokio::test]
    async fn heartbeat_preserves_public_advertised_endpoint() {
        let c = coordinator();
        let req = RegisterRequest {
            wg_public_key: pubkey(5),
            listen_endpoint: Some("198.51.100.50:51820".into()),
            wg_listen_port: Some(51820),
            display_name: "advertised".into(),
            network: String::new(),
            tags: vec![],
            hosted_app_ulas: vec![],
            kind: "peer".into(),
            parent: None,
            app_uuid: None,
            requested_ula: None,
        };
        let observed: SocketAddr = "203.0.113.7:34812".parse().expect("addr");
        let (entry, _) = c
            .register_authenticated(req, None, Some(observed))
            .await
            .expect("register");
        // Heartbeat from a public IP that differs from the advertised one.
        let updated = c
            .heartbeat(
                entry.peer_id,
                "203.0.113.7:34900".into(),
                Some(51820),
                vec![],
            )
            .await
            .expect("heartbeat");
        assert_eq!(
            updated.listen_endpoint.as_deref(),
            Some("198.51.100.50:51820"),
            "explicit public advert must survive heartbeats"
        );
    }

    /// A peer whose stored endpoint is a non-reflexive LOOPBACK fallback
    /// (e.g. registered before connect-info was available) must still be
    /// able to roll over to a reflexive public endpoint on a heartbeat
    /// that reveals a public source IP — loopback is a fallback, not a
    /// sticky operator advertisement.
    #[tokio::test]
    async fn heartbeat_promotes_loopback_fallback_to_reflexive() {
        let c = coordinator();
        // Register with NO observed addr → loopback self-report kept,
        // endpoint_is_reflexive == false.
        let (entry, _) = c.register(req(8, "late")).await.expect("register");
        assert_eq!(entry.listen_endpoint.as_deref(), Some("127.0.0.1:51820"));
        assert!(!entry.endpoint_is_reflexive);
        // Heartbeat from a public IP → must promote to reflexive.
        let updated = c
            .heartbeat(
                entry.peer_id,
                "203.0.113.7:34812".into(),
                Some(51820),
                vec![],
            )
            .await
            .expect("heartbeat");
        assert_eq!(
            updated.listen_endpoint.as_deref(),
            Some("203.0.113.7:51820")
        );
        assert!(updated.endpoint_is_reflexive);
    }

    /// Re-register from behind NAT must refresh (not regress) the reflexive
    /// endpoint: the idempotent re-register path stores the reflexive
    /// endpoint, not the loopback self-report.
    #[tokio::test]
    async fn re_register_refreshes_reflexive_endpoint() {
        let c = coordinator();
        // First register with NO observed (e.g. early bring-up) → loopback.
        let (first, _) = c.register(req(6, "peer")).await.expect("first");
        assert_eq!(first.listen_endpoint.as_deref(), Some("127.0.0.1:51820"));
        // Re-register (same pubkey) WITH a public observed addr → reflexive.
        let observed: SocketAddr = "203.0.113.7:34812".parse().expect("addr");
        let (second, outcome) = c
            .register_authenticated(req(6, "peer"), None, Some(observed))
            .await
            .expect("re-register");
        assert_eq!(outcome, RegisterOutcome::Existed);
        assert_eq!(first.peer_id, second.peer_id);
        assert_eq!(second.listen_endpoint.as_deref(), Some("203.0.113.7:51820"));
    }

    // -----------------------------------------------------------------
    // Per-app-ULA routing — the coordinator carries opaque hosted
    // app-ULA /128s through register + heartbeat and advertises them to
    // viewers exactly like the peer's own ULA. The coordinator stays
    // app-agnostic: it never derives or validates an app-ULA, it just
    // relays the set the peer declares. These tests pin the control-plane
    // contract the joiner's app-route layer (Component 2) consumes.
    // -----------------------------------------------------------------

    /// A request that also declares a set of hosted app-ULAs.
    fn req_hosting(seed: u8, name: &str, hosted: &[&str]) -> RegisterRequest {
        RegisterRequest {
            hosted_app_ulas: hosted.iter().map(|s| (*s).to_owned()).collect(),
            ..req(seed, name)
        }
    }

    /// Register must STORE the declared hosted app-ULAs and surface them
    /// on the roster entry + the wire `PeerInfo` (snapshot), with the same
    /// visibility as the peer's own ULA.
    #[tokio::test]
    async fn register_stores_and_advertises_hosted_app_ulas() {
        let c = coordinator();
        let app_a = "fd5a:1f02:dead:beef:cafe:0:0:1";
        let app_b = "fd5a:1f02:dead:beef:cafe:0:0:2";
        let (entry, outcome) = c
            .register(req_hosting(1, "supervisor", &[app_a, app_b]))
            .await
            .expect("register");
        assert_eq!(outcome, RegisterOutcome::Created);
        assert_eq!(
            entry.hosted_app_ulas,
            vec![app_a.to_owned(), app_b.to_owned()]
        );
        // The wire-facing snapshot carries them too (advertised to viewers).
        let snap = c.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(
            snap[0].hosted_app_ulas,
            vec![app_a.to_owned(), app_b.to_owned()]
        );
    }

    /// A heartbeat REPLACES the stored hosted set wholesale: a supervisor
    /// re-sends its full hosted set each tick, so an added app appears and
    /// a removed app disappears purely from the replace.
    #[tokio::test]
    async fn heartbeat_replaces_hosted_app_ula_set() {
        let c = coordinator();
        let app_a = "fd5a:1f02:dead:beef:cafe:0:0:1";
        let app_b = "fd5a:1f02:dead:beef:cafe:0:0:2";
        let (entry, _) = c
            .register(req_hosting(2, "supervisor", &[app_a]))
            .await
            .expect("register");
        assert_eq!(entry.hosted_app_ulas, vec![app_a.to_owned()]);

        // Heartbeat now advertises a DIFFERENT set: drop app_a, add app_b.
        let updated = c
            .heartbeat(
                entry.peer_id,
                "203.0.113.1:51820".into(),
                Some(51820),
                vec![app_b.to_owned()],
            )
            .await
            .expect("heartbeat");
        assert_eq!(
            updated.hosted_app_ulas,
            vec![app_b.to_owned()],
            "heartbeat must replace the stored hosted set wholesale"
        );

        // An empty heartbeat set clears everything (supervisor stopped all).
        let cleared = c
            .heartbeat(
                entry.peer_id,
                "203.0.113.1:51820".into(),
                Some(51820),
                vec![],
            )
            .await
            .expect("heartbeat clear");
        assert!(cleared.hosted_app_ulas.is_empty());
    }

    /// A heartbeat that CHANGES the hosted set must reach SSE subscribers
    /// as an `Updated` frame carrying the new set — that is how a viewer
    /// re-learns which apps a supervisor hosts (per-app-ULA routing).
    #[tokio::test]
    async fn heartbeat_broadcasts_updated_with_new_hosted_set() {
        let c = coordinator();
        let app_a = "fd5a:1f02:dead:beef:cafe:0:0:1";
        let (entry, _) = c.register(req(3, "supervisor")).await.expect("register");

        // Subscribe AFTER register so we only see heartbeat-time frames.
        let mut rx = c.broadcaster().subscribe();
        c.heartbeat(
            entry.peer_id,
            "203.0.113.1:51820".into(),
            Some(51820),
            vec![app_a.to_owned()],
        )
        .await
        .expect("heartbeat");

        // Drain the channel; find an Updated frame for this peer carrying
        // the new hosted set.
        let mut saw_hosted = false;
        while let Ok(ev) = rx.try_recv() {
            if let PeerEvent::Updated(info) = ev {
                if info.peer_id == entry.peer_id.to_string()
                    && info.hosted_app_ulas == vec![app_a.to_owned()]
                {
                    saw_hosted = true;
                }
            }
        }
        assert!(
            saw_hosted,
            "a changed hosted set must be broadcast as Updated with the new set"
        );
    }

    /// Re-register also refreshes the hosted set from the request, mirroring
    /// the heartbeat replace semantics (so a restart that re-declares its
    /// apps converges).
    #[tokio::test]
    async fn re_register_refreshes_hosted_app_ula_set() {
        let c = coordinator();
        let app_a = "fd5a:1f02:dead:beef:cafe:0:0:1";
        let app_b = "fd5a:1f02:dead:beef:cafe:0:0:2";
        let (first, o1) = c
            .register(req_hosting(4, "supervisor", &[app_a]))
            .await
            .expect("first");
        assert_eq!(o1, RegisterOutcome::Created);
        // Re-register (same pubkey/seed) with a different hosted set.
        let (second, o2) = c
            .register(req_hosting(4, "supervisor", &[app_b]))
            .await
            .expect("re-register");
        assert_eq!(o2, RegisterOutcome::Existed);
        assert_eq!(first.peer_id, second.peer_id);
        assert_eq!(second.hosted_app_ulas, vec![app_b.to_owned()]);
    }

    /// An older joiner that omits `hosted_app_ulas` (serde default) is
    /// treated as hosting no apps — the field defaults to empty and never
    /// errors. This guards the back-compat contract.
    #[tokio::test]
    async fn register_defaults_hosted_app_ulas_to_empty() {
        let c = coordinator();
        let (entry, _) = c.register(req(5, "legacy")).await.expect("register");
        assert!(entry.hosted_app_ulas.is_empty());
    }

    // -----------------------------------------------------------------
    // Per-app-runner peer metadata (kind / parent / app_uuid).
    //
    // A runner peer joins with kind="runner", parent=<supervisor ULA>,
    // app_uuid=<uuid>. A plain supervisor peer joins without those fields
    // and gets the defaults. Both round-trip through the roster snapshot
    // (GET /v1/mesh/peers → PeerInfo). This is Task 0.1 of the per-app-
    // runner architecture refactor.
    // -----------------------------------------------------------------

    fn req_runner(seed: u8, name: &str, parent: &str, app_uuid: &str) -> RegisterRequest {
        RegisterRequest {
            kind: "runner".into(),
            parent: Some(parent.into()),
            app_uuid: Some(app_uuid.into()),
            ..req(seed, name)
        }
    }

    /// A peer registered with kind="runner", parent, and `app_uuid` must
    /// appear in the roster snapshot with those exact values.
    #[tokio::test]
    async fn runner_peer_metadata_round_trips_through_roster() {
        let c = coordinator();
        let parent_ula = "fd5a:1f00:0:1::1";
        let app_id = "01910f10-0000-7000-8000-000000000001";
        let (entry, outcome) = c
            .register(req_runner(80, "runner-1", parent_ula, app_id))
            .await
            .expect("register");
        assert_eq!(outcome, RegisterOutcome::Created);
        // PeerEntry carries the fields.
        assert_eq!(entry.kind, "runner");
        assert_eq!(entry.parent.as_deref(), Some(parent_ula));
        assert_eq!(entry.app_uuid.as_deref(), Some(app_id));
        // PeerInfo (the wire/roster snapshot) must carry them too.
        let snap = c.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].kind, "runner");
        assert_eq!(snap[0].parent.as_deref(), Some(parent_ula));
        assert_eq!(snap[0].app_uuid.as_deref(), Some(app_id));
    }

    /// A plain peer (no `kind/parent/app_uuid` in request) defaults to
    /// kind="peer" and absent `parent/app_uuid` in the roster.
    #[tokio::test]
    async fn plain_peer_defaults_to_kind_peer_with_no_parent_or_app_uuid() {
        let c = coordinator();
        let (entry, _) = c.register(req(81, "plain")).await.expect("register");
        assert_eq!(entry.kind, "peer");
        assert!(entry.parent.is_none());
        assert!(entry.app_uuid.is_none());
        // Wire snapshot agrees.
        let snap = c.snapshot();
        assert_eq!(snap[0].kind, "peer");
        assert!(snap[0].parent.is_none());
        assert!(snap[0].app_uuid.is_none());
    }

    // -----------------------------------------------------------------
    // Task 0.2 — requested_ula: peers can request a specific ULA instead
    // of the idx-derived one. The coordinator honours it if it is
    // well-formed AND unclaimed (or claimed by the SAME peer on re-join).
    // A DIFFERENT peer trying to claim an already-held ULA is rejected.
    // -----------------------------------------------------------------

    fn req_with_requested_ula(seed: u8, name: &str, requested_ula: &str) -> RegisterRequest {
        RegisterRequest {
            requested_ula: Some(requested_ula.into()),
            ..req(seed, name)
        }
    }

    /// A peer that supplies a valid, unclaimed `requested_ula` receives
    /// exactly that address — not an idx-derived one.
    #[tokio::test]
    async fn register_honours_requested_ula_when_unclaimed() {
        let c = coordinator();
        let want = "fd5a:1f02:aaaa::1";
        let (entry, outcome) = c
            .register(req_with_requested_ula(90, "runner-a", want))
            .await
            .expect("register");
        assert_eq!(outcome, RegisterOutcome::Created);
        assert_eq!(
            entry.ula.to_string(),
            want,
            "assigned ULA must be exactly the requested one"
        );
        // The snapshot must also reflect it.
        let snap = c.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].ula, want);
    }

    /// A second, DIFFERENT peer requesting the same ULA that a prior peer
    /// already holds must be rejected with a clear conflict error.
    #[tokio::test]
    async fn register_rejects_requested_ula_claimed_by_different_peer() {
        let c = coordinator();
        let want = "fd5a:1f02:bbbb::1";
        // Peer A claims it first.
        c.register(req_with_requested_ula(91, "peer-a", want))
            .await
            .expect("peer-a register");
        // Peer B (different pubkey / identity) tries the same ULA.
        let err = c
            .register(req_with_requested_ula(92, "peer-b", want))
            .await
            .expect_err("peer-b must be rejected");
        assert!(
            matches!(err, CoordinatorError::UlaConflict(_)),
            "expected UlaConflict, got {err:?}"
        );
        // Only one peer in the roster.
        assert_eq!(c.snapshot().len(), 1);
    }

    /// The SAME peer re-registering with its own previously-assigned ULA
    /// (sticky identity on restart) must succeed — outcome Existed, same
    /// `peer_id`, same ULA.
    #[tokio::test]
    async fn register_allows_same_peer_to_reclaim_its_own_ula() {
        let c = coordinator();
        let want = "fd5a:1f02:cccc::1";
        let (first, o1) = c
            .register(req_with_requested_ula(93, "runner-c", want))
            .await
            .expect("first register");
        assert_eq!(o1, RegisterOutcome::Created);
        assert_eq!(first.ula.to_string(), want);

        // Same pubkey (seed 93) re-registers, requesting the same ULA.
        let (second, o2) = c
            .register(req_with_requested_ula(93, "runner-c-restart", want))
            .await
            .expect("re-register");
        assert_eq!(o2, RegisterOutcome::Existed);
        assert_eq!(first.peer_id, second.peer_id, "peer_id must be stable");
        assert_eq!(
            second.ula.to_string(),
            want,
            "re-registered peer keeps its ULA"
        );
    }

    /// When no `requested_ula` is supplied, the coordinator falls back to
    /// the original idx-based assignment (regression guard).
    #[tokio::test]
    async fn register_fallback_to_idx_when_no_requested_ula() {
        let c = coordinator();
        let (p1, _) = c.register(req(94, "plain-a")).await.expect("ok");
        let (p2, _) = c.register(req(95, "plain-b")).await.expect("ok");
        // Both get idx-derived addresses (sequential within the default network).
        assert_ne!(p1.ula, p2.ula);
        assert_eq!(p1.peer_index, 1);
        assert_eq!(p2.peer_index, 2);
    }
}

// ---------------------------------------------------------------------
// JWT join-token validation (spec §8 / E4).
//
// These exercise `register_authenticated` against a fake auth service
// (wiremock). The central guarantee: when a validator is configured a
// node's effective network + tags equal exactly what the validator
// returns — spoofed `RegisterRequest` values are ignored — and an
// invalid / missing / revoked token rejects the register. The escape
// hatch (no validator) preserves the legacy request-trusting behavior.
// ---------------------------------------------------------------------
#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod jwt_tests {
    use super::*;
    use crate::auth::AuthValidator;
    use crate::policy::{AclRule, Policy, PolicyStore};
    use crate::publisher::NoopPublisher;
    use base64::Engine as _;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn pubkey(seed: u8) -> String {
        base64::engine::general_purpose::STANDARD.encode([seed; 32])
    }

    /// A register request that self-asserts a (potentially spoofed)
    /// network + tag set. Whether those survive depends entirely on
    /// whether a validator is wired.
    fn req_with(seed: u8, network: &str, tags: &[&str]) -> RegisterRequest {
        RegisterRequest {
            wg_public_key: pubkey(seed),
            listen_endpoint: Some("127.0.0.1:51820".into()),
            wg_listen_port: Some(51820),
            display_name: "node".into(),
            network: network.into(),
            tags: tags.iter().map(|s| (*s).to_owned()).collect(),
            hosted_app_ulas: vec![],
            kind: "peer".into(),
            parent: None,
            app_uuid: None,
            requested_ula: None,
        }
    }

    /// Permissive policy so visibility filtering doesn't get in the way —
    /// these tests are about identity stamping, not roster filtering.
    fn permissive() -> PolicyStore {
        PolicyStore::new(Policy::new(vec![AclRule::accept(&["*"], &["*"])]))
    }

    fn coordinator_with_validator(validator: AuthValidator) -> Coordinator {
        Coordinator::with_policy_and_validator(
            Arc::new(NoopPublisher),
            Duration::from_secs(60),
            permissive(),
            Some(validator),
        )
    }

    /// Mount a `/v1/validate` mock returning the given JSON body.
    async fn mock_validate(server: &MockServer, body: serde_json::Value) {
        Mock::given(method("POST"))
            .and(path("/v1/validate"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(server)
            .await;
    }

    /// Valid token → admit, and the node's network + tags come from the
    /// CLAIMS, not the request.
    #[tokio::test]
    async fn valid_token_admits_with_claims_network_and_tags() {
        let server = MockServer::start().await;
        mock_validate(
            &server,
            serde_json::json!({
                "valid": true,
                "subject": "node-alice",
                "network": "alice",
                "tags": ["tag:user-alice"],
                "kind": "join",
                "exp": 1_900_000_000_i64,
            }),
        )
        .await;
        let c = coordinator_with_validator(AuthValidator::new(server.uri()).unwrap());

        // Request asserts a DIFFERENT network/tags than the claims.
        let req = req_with(1, "request-network", &["tag:request-supplied"]);
        let (entry, outcome) = c
            .register_authenticated(req, Some("good-token"), None)
            .await
            .expect("admit");
        assert_eq!(outcome, RegisterOutcome::Created);
        assert_eq!(entry.network, "alice", "network must come from claims");
        assert_eq!(
            entry.tags,
            vec!["tag:user-alice".to_owned()],
            "tags must come from claims"
        );
    }

    /// The headline spoofing test: a node sends `tag:admin` + a foreign
    /// network in its request, but the validator says it's a plain alice
    /// node. The roster entry must reflect ONLY the claims.
    #[tokio::test]
    async fn spoofed_request_tags_are_ignored_in_favor_of_claims() {
        let server = MockServer::start().await;
        mock_validate(
            &server,
            serde_json::json!({
                "valid": true,
                "subject": "node-alice",
                "network": "alice",
                "tags": ["tag:user-alice"],
                "kind": "join",
                "exp": 1_900_000_000_i64,
            }),
        )
        .await;
        let c = coordinator_with_validator(AuthValidator::new(server.uri()).unwrap());

        // Malicious request: claim bob's network + an admin tag.
        let spoof = req_with(2, "bob", &["tag:user-bob", "tag:admin"]);
        let (entry, _) = c
            .register_authenticated(spoof, Some("good-token"), None)
            .await
            .expect("admit");
        assert_eq!(entry.network, "alice");
        assert_eq!(entry.tags, vec!["tag:user-alice".to_owned()]);
        assert!(
            !entry.tags.iter().any(|t| t == "tag:admin"),
            "spoofed admin tag must not appear"
        );
        // The ULA must be allocated in the CLAIMS network's block, not the
        // spoofed one — derive the expected slot from the claims network.
        let claims_slot = crate::roster::allocator::network_slot("alice");
        assert_eq!(
            entry.ula.segments()[2],
            claims_slot,
            "ULA block must be derived from the claims network"
        );
    }

    /// `valid: false` (expired / revoked / tampered) → Unauthorized.
    #[tokio::test]
    async fn invalid_or_revoked_token_is_rejected() {
        let server = MockServer::start().await;
        mock_validate(
            &server,
            serde_json::json!({
                "valid": false,
                "subject": "",
                "network": "",
                "tags": [],
                "kind": "join",
                "exp": 0,
            }),
        )
        .await;
        let c = coordinator_with_validator(AuthValidator::new(server.uri()).unwrap());

        let err = c
            .register_authenticated(req_with(3, "alice", &[]), Some("revoked-token"), None)
            .await
            .expect_err("must reject");
        assert!(matches!(err, CoordinatorError::Unauthorized(_)), "{err:?}");
        // Rejected join leaves zero roster state behind.
        assert_eq!(c.snapshot().len(), 0);
    }

    /// A validator is configured but no token is presented → Unauthorized,
    /// before any roster mutation.
    #[tokio::test]
    async fn missing_token_is_rejected_when_validator_configured() {
        let server = MockServer::start().await;
        // No mock needed — we should never reach the auth service.
        let c = coordinator_with_validator(AuthValidator::new(server.uri()).unwrap());

        let err = c
            .register_authenticated(req_with(4, "alice", &[]), None, None)
            .await
            .expect_err("must reject");
        assert!(matches!(err, CoordinatorError::Unauthorized(_)), "{err:?}");
        assert_eq!(c.snapshot().len(), 0);
    }

    /// Auth service unreachable → fail closed (Unauthorized), never admit.
    #[tokio::test]
    async fn auth_service_unreachable_fails_closed() {
        // Port 1 refuses; nothing is listening.
        let c = coordinator_with_validator(AuthValidator::new("http://127.0.0.1:1").unwrap());
        let err = c
            .register_authenticated(req_with(5, "alice", &[]), Some("token"), None)
            .await
            .expect_err("must fail closed");
        assert!(matches!(err, CoordinatorError::Unauthorized(_)), "{err:?}");
        assert_eq!(c.snapshot().len(), 0);
    }

    /// Escape hatch: no validator → the request-supplied network + tags are
    /// trusted (legacy dev/E1 behavior), token ignored.
    #[tokio::test]
    async fn escape_hatch_without_validator_trusts_request() {
        let c = Coordinator::with_policy_and_validator(
            Arc::new(NoopPublisher),
            Duration::from_secs(60),
            permissive(),
            None,
        );
        let (entry, _) = c
            .register_authenticated(req_with(6, "alice", &["tag:user-alice"]), None, None)
            .await
            .expect("admit (escape hatch)");
        assert_eq!(entry.network, "alice");
        assert_eq!(entry.tags, vec!["tag:user-alice".to_owned()]);
    }

    /// Re-register with the same pubkey must also stamp tags from claims —
    /// a re-register can't be used to swap in spoofed tags either.
    #[tokio::test]
    async fn re_register_restamps_tags_from_claims() {
        let server = MockServer::start().await;
        mock_validate(
            &server,
            serde_json::json!({
                "valid": true,
                "subject": "node-alice",
                "network": "alice",
                "tags": ["tag:user-alice"],
                "kind": "join",
                "exp": 1_900_000_000_i64,
            }),
        )
        .await;
        let c = coordinator_with_validator(AuthValidator::new(server.uri()).unwrap());

        let (first, o1) = c
            .register_authenticated(req_with(7, "x", &["tag:request"]), Some("token"), None)
            .await
            .expect("first");
        assert_eq!(o1, RegisterOutcome::Created);
        // Second register, same pubkey, tries to assert admin again.
        let (second, o2) = c
            .register_authenticated(req_with(7, "x", &["tag:admin"]), Some("token"), None)
            .await
            .expect("re-register");
        assert_eq!(o2, RegisterOutcome::Existed);
        assert_eq!(first.peer_id, second.peer_id);
        assert_eq!(
            second.tags,
            vec!["tag:user-alice".to_owned()],
            "re-register tags must still come from claims"
        );
    }
}
