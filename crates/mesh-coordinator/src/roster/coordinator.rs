//! In-memory peer roster + register/heartbeat/deregister state machine.
//!
//! The roster lives in a `DashMap<Uuid, PeerEntry>` plus a sister
//! `DashMap<wg_public_key, Uuid>` for idempotent re-registration. Both
//! maps are kept consistent under each mutating method.

use crate::auth::{AuthValidator, ValidatedClaims, ValidationError};
use crate::http::api::{PeerInfo, RegisterRequest};
use crate::http::sse::{PeerBroadcaster, PeerEvent};
use crate::nat::holepunch::{PunchPeer, PunchTracker, try_emit_pair};
use crate::policy::PolicyStore;
use crate::publisher::{SharedPublisher, publish_event};
use crate::roster::allocator::{AllocError, UlaAllocator};
use crate::roster::events::{PeerHeartbeat, PeerJoined, PeerLeft};
use crate::roster::identity::stamp_identity;
use dashmap::DashMap;
use std::net::Ipv6Addr;
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
            joined_at_micros: self.joined_at_micros,
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
    /// performs **no** join-token validation.
    ///
    /// Equivalent to [`Self::register_authenticated`] with no bearer token.
    /// When a validator is configured this will fail with
    /// [`CoordinatorError::Unauthorized`] (a token is required); when no
    /// validator is configured it is the dev/E1 path that trusts the
    /// request-supplied `network` + `tags`. Production code goes through
    /// the HTTP handler, which forwards the `Authorization` header to
    /// [`Self::register_authenticated`].
    ///
    /// # Errors
    /// See [`CoordinatorError`].
    pub async fn register(
        &self,
        req: RegisterRequest,
    ) -> Result<(PeerEntry, RegisterOutcome), CoordinatorError> {
        self.register_authenticated(req, None).await
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
    /// Data flow on the first-time path: **validate → build event →
    /// publish → apply event → broadcast.** Publish is best-effort
    /// (logged on failure); strict-ordering is a future tightening.
    ///
    /// # Errors
    /// See [`CoordinatorError`] — auth rejection, allocator exhaustion, and
    /// key length validation.
    pub async fn register_authenticated(
        &self,
        req: RegisterRequest,
        bearer: Option<&str>,
    ) -> Result<(PeerEntry, RegisterOutcome), CoordinatorError> {
        // Authenticate FIRST, before touching the roster or allocator, so
        // a rejected join has zero side effects.
        let claims = self.authenticate(bearer).await?;

        let pubkey = decode_pubkey(&req.wg_public_key)?;
        if pubkey.len() != 32 {
            return Err(CoordinatorError::InvalidPubkey(pubkey.len()));
        }

        // Re-registration path. Holding the by_pubkey shard lock while
        // we look up the peer_id is fine — the roster is keyed by
        // peer_id, so there's no inverse-lookup contention.
        if let Some(existing_id) = self.inner.by_pubkey.get(&pubkey).map(|v| *v) {
            let entry = self.refresh_existing(existing_id, &req, claims.as_ref())?;
            self.inner
                .broadcaster
                .broadcast(PeerEvent::Updated(entry.to_info()));
            return Ok((entry, RegisterOutcome::Existed));
        }

        // Stamp authoritative identity (network + tags) in ONE place: the
        // validated claims win when present (production), else the request
        // (escape hatch). See `crate::roster::identity::stamp_identity`.
        let identity = stamp_identity(&req, claims.as_ref());
        // First-time path. Allocate the ULA from the node's network block
        // *before* building the event so a failed allocation doesn't emit a
        // half-formed PeerJoined.
        let (peer_index, ula) = self.inner.allocator.allocate(&identity.network)?;
        let peer_id = Uuid::now_v7();
        let now_micros = now_unix_micros();
        let event = PeerJoined {
            peer_id: peer_id.to_string(),
            wg_public_key: pubkey,
            ula: ula.to_string(),
            listen_endpoint: req.listen_endpoint.clone().unwrap_or_default(),
            display_name: req.display_name.clone(),
            network: identity.network,
            tags: identity.tags,
            joined_at_micros: now_micros,
        };
        // Publish first so the sink sees the event before in-memory state
        // changes; then apply the event to in-memory state from the same
        // data so both stay derived from one source.
        publish_event(self.inner.publisher.as_ref(), PEER_SEGMENT, &event).await;
        let entry = self.apply_peer_joined(&event)?;
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
    ) -> Result<PeerEntry, CoordinatorError> {
        // Pre-check membership so we can surface UnknownPeer without
        // emitting a heartbeat event for a peer that doesn't exist.
        if !self.inner.roster.contains_key(&peer_id) {
            return Err(CoordinatorError::UnknownPeer(peer_id));
        }
        let event = PeerHeartbeat {
            peer_id: peer_id.to_string(),
            observed_external: observed_external.clone(),
            at_micros: now_unix_micros(),
        };
        publish_event(self.inner.publisher.as_ref(), PEER_SEGMENT, &event).await;
        self.apply_peer_heartbeat(&event);
        // Re-read after apply so the snapshot reflects the new
        // last_heartbeat. If the entry vanished between contains_key and
        // here (concurrent deregister), bail with UnknownPeer.
        let snapshot = self
            .inner
            .roster
            .get(&peer_id)
            .map(|e| e.clone())
            .ok_or(CoordinatorError::UnknownPeer(peer_id))?;
        debug!(peer_id = %peer_id, observed_external, "heartbeat stamped");
        self.inner
            .broadcaster
            .broadcast(PeerEvent::Updated(snapshot.to_info()));
        self.try_emit_holepunch_pairs(&snapshot).await;
        Ok(snapshot)
    }

    /// Stage 2 hook called after a heartbeat lands. Iterates over the
    /// roster and emits a `HolePunchInitiate` pair for every other peer
    /// with a non-empty `observed_external` that hasn't yet been paired.
    /// Best-effort — publish failures are swallowed via `publish_event`.
    async fn try_emit_holepunch_pairs(&self, just_heartbeated: &PeerEntry) {
        if just_heartbeated.observed_external.is_empty() {
            return;
        }
        let a = PunchPeer {
            peer_id: just_heartbeated.peer_id,
            observed_external: just_heartbeated.observed_external.clone(),
        };
        // Collect candidates before await to avoid holding the DashMap
        // shard locks across .await points.
        let candidates: Vec<PunchPeer> = self
            .inner
            .roster
            .iter()
            .filter_map(|kv| {
                let e = kv.value();
                if e.peer_id == a.peer_id || e.observed_external.is_empty() {
                    None
                } else {
                    Some(PunchPeer {
                        peer_id: e.peer_id,
                        observed_external: e.observed_external.clone(),
                    })
                }
            })
            .collect();
        let now = now_unix_micros();
        for b in candidates {
            try_emit_pair(
                self.inner.publisher.as_ref(),
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
        let Some(tags) = self
            .inner
            .roster
            .get(&peer_id)
            .map(|e| e.tags.clone())
        else {
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
        let mut entries: Vec<PeerEntry> =
            self.inner.roster.iter().map(|kv| kv.value().clone()).collect();
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
            e.listen_endpoint.clone_from(&req.listen_endpoint);
            e.display_name.clone_from(&req.display_name);
            e.tags = identity.tags;
            e.last_heartbeat = Instant::now();
            e.clone()
        };
        info!(peer_id = %peer_id, "peer re-registered (idempotent)");
        Ok(entry)
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
            display_name: name.into(),
            network: String::new(),
            tags: vec!["dev-machine".into()],
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
            .heartbeat(entry.peer_id, "203.0.113.1:51820".into())
            .await
            .expect("heartbeat");
        assert_eq!(updated.peer_id, entry.peer_id);

        let bogus = Uuid::now_v7();
        let err = c
            .heartbeat(bogus, "ignored".into())
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
        let (replacement, outcome) =
            c.register(req(4, "dave-prime")).await.expect("register again");
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
                display_name: "short".into(),
                network: String::new(),
                tags: vec![],
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
        c.heartbeat(alice.peer_id, "203.0.113.10:11111".into())
            .await
            .expect("a hb1");
        // Only alice has external so far — no holepunch event yet.
        assert_eq!(
            pub_.count_by_type("holepunch_initiate"),
            0,
            "should not emit until both peers have observed_external"
        );

        c.heartbeat(bob.peer_id, "198.51.100.20:22222".into())
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
        assert_eq!(from_alice.target_external_endpoint, "198.51.100.20:22222");
        let from_bob = events
            .iter()
            .find(|e| e.initiator_peer_id == bob.peer_id.to_string())
            .expect("event from bob");
        assert_eq!(from_bob.target_peer_id, alice.peer_id.to_string());
        assert_eq!(from_bob.target_external_endpoint, "203.0.113.10:11111");

        // Sanity: the tracker should know about this pair now.
        assert_eq!(c.punch_tracker().len(), 1);

        // Another heartbeat from alice should NOT re-emit (dedup).
        c.heartbeat(alice.peer_id, "203.0.113.10:11111".into())
            .await
            .expect("a hb2");
        assert_eq!(
            pub_.count_by_type("holepunch_initiate"),
            2,
            "dedup must prevent re-emit on subsequent heartbeats"
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
        c.heartbeat(alice.peer_id, "203.0.113.30:33333".into())
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
        c.heartbeat(alice.peer_id, "203.0.113.50:44444".into())
            .await
            .expect("a hb");

        // Bob heartbeats but ConnectInfo wasn't captured — empty string.
        // This mirrors the test-router path that drives via Router::call
        // without the make_service wrapper.
        c.heartbeat(bob.peer_id, String::new())
            .await
            .expect("b hb empty external");

        assert_eq!(
            pub_.count_by_type("holepunch_initiate"),
            0,
            "empty observed_external must not trigger an emit"
        );
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
            display_name: "node".into(),
            network: network.into(),
            tags: tags.iter().map(|s| (*s).to_owned()).collect(),
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
            .register_authenticated(req, Some("good-token"))
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
            .register_authenticated(spoof, Some("good-token"))
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
            .register_authenticated(req_with(3, "alice", &[]), Some("revoked-token"))
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
            .register_authenticated(req_with(4, "alice", &[]), None)
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
            .register_authenticated(req_with(5, "alice", &[]), Some("token"))
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
            .register_authenticated(req_with(6, "alice", &["tag:user-alice"]), None)
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
            .register_authenticated(req_with(7, "x", &["tag:request"]), Some("token"))
            .await
            .expect("first");
        assert_eq!(o1, RegisterOutcome::Created);
        // Second register, same pubkey, tries to assert admin again.
        let (second, o2) = c
            .register_authenticated(req_with(7, "x", &["tag:admin"]), Some("token"))
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
