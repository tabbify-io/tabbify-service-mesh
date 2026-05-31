//! In-memory peer roster + register/heartbeat/deregister state machine.
//!
//! The roster lives in a `DashMap<Uuid, PeerEntry>` plus a sister
//! `DashMap<wg_public_key, Uuid>` for idempotent re-registration. Both
//! maps are kept consistent under each mutating method.
//!
//! Layout:
//!
//! - [`mod@registration`] — `register` / `register_authenticated` / auth +
//!   ULA resolution / re-register refresh.
//! - [`mod@heartbeat`] — heartbeat ingestion, reflexive endpoint roaming,
//!   Stage 2 hole-punch pairing, deregister.
//! - This file — shared types (`PeerEntry`, `CoordinatorError`,
//!   `RegisterOutcome`, `Coordinator`, `Inner`), constructors / accessors,
//!   snapshot / `stale_peers`, free helpers, the `PEER_SEGMENT` constant.

mod heartbeat;
mod registration;

#[cfg(test)]
mod jwt_tests;
#[cfg(test)]
mod tests;

use crate::auth::AuthValidator;
use crate::http::api::PeerInfo;
use crate::http::sse::PeerBroadcaster;
use crate::nat::holepunch::PunchTracker;
use crate::policy::PolicyStore;
use crate::publisher::SharedPublisher;
use crate::roster::allocator::UlaAllocator;
use dashmap::DashMap;
use std::net::Ipv6Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
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
    /// Software version this peer reports running (e.g. `"v1.4.0"`).
    /// `None` = unknown. Set on register, refreshed on re-register and on
    /// every heartbeat that carries a value; a heartbeat with `None` leaves
    /// it untouched (never a downgrade trigger — spec P0).
    pub software_version: Option<String>,
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
            software_version: self.software_version.clone(),
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
    Allocation(#[from] crate::roster::allocator::AllocError),
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
    /// Ephemeral pubkey → live relay WS connection (Stage-3 relay floor).
    pub(crate) relay: crate::relay::RelayRegistry,
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
                relay: crate::relay::RelayRegistry::new(),
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

    /// Borrow the hole-punch tracker. Tests use this to inspect which
    /// pairs have already been emitted; production code never reaches
    /// past `Inner` to touch this directly.
    #[must_use]
    pub fn punch_tracker(&self) -> &PunchTracker {
        &self.inner.punch_tracker
    }

    /// Borrow the relay registry — the WS handler registers/forwards through it.
    #[must_use]
    pub fn relay(&self) -> &crate::relay::RelayRegistry {
        &self.inner.relay
    }

    /// Whether `pk` (raw 32-byte X25519 key) belongs to a registered peer.
    /// The relay WS handler rejects an upgrade from an unknown pubkey.
    #[must_use]
    pub fn is_registered_pubkey(&self, pk: &[u8]) -> bool {
        self.inner.by_pubkey.contains_key(pk)
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
}

pub(crate) fn decode_pubkey(s: &str) -> Result<Vec<u8>, CoordinatorError> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| CoordinatorError::PubkeyDecode(e.to_string()))
}

/// Wall-clock micros since UNIX epoch. Saturates on overflow — fine for
/// the next ~290 000 years.
pub(super) fn now_unix_micros() -> i64 {
    // SystemTime → micros. We intentionally don't reach for `time::OffsetDateTime`
    // here: this is one int field on an event and bringing the full time
    // crate into the hot path is overkill.
    let dur = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    i64::try_from(dur.as_micros()).unwrap_or(i64::MAX)
}
