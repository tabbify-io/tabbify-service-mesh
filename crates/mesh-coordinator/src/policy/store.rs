//! In-memory policy store with optimistic-concurrency `ETag`s.
//!
//! Holds the current [`Policy`] behind an `RwLock` and tags each version
//! with a monotonically-derived `ETag`. The store is loaded from a
//! declarative file at startup (path via CLI/env) and mutated at runtime
//! through `PUT /v1/policy`, which requires an `If-Match` `ETag` so two
//! concurrent admins can't silently clobber each other (lost-update
//! protection, spec §7).
//!
//! Source-of-truth note (OQ-2): the store is the live authority; a
//! `GET /v1/policy` export is what gets committed to git for versioning.
//! This module owns only the in-memory side.

use crate::policy::model::{Policy, PolicyValidationError};
use parking_lot::RwLock;
use std::path::Path;
use std::sync::Arc;

/// A versioned policy snapshot: the policy plus its current `ETag`.
#[derive(Debug, Clone)]
pub struct PolicySnapshot {
    /// The policy document.
    pub policy: Policy,
    /// Opaque version tag, bumped on every successful replace.
    pub etag: String,
}

/// Thread-safe, cheaply-clonable handle to the live policy. Every clone
/// shares the same underlying `RwLock` via `Arc`.
#[derive(Clone, Debug)]
pub struct PolicyStore {
    inner: Arc<RwLock<PolicySnapshot>>,
}

/// Error returned by [`PolicyStore::replace`].
#[derive(Debug, thiserror::Error)]
pub enum PolicyReplaceError {
    /// The caller's `If-Match` `ETag` did not match the current version.
    #[error("etag mismatch: expected {current}, got {provided}")]
    EtagMismatch {
        /// The store's current `ETag`.
        current: String,
        /// The `ETag` the caller supplied.
        provided: String,
    },
    /// The proposed policy failed validation (e.g. a cross-tenant glob
    /// source) and was rejected before it could be installed.
    #[error("policy rejected: {0}")]
    Invalid(#[from] PolicyValidationError),
}

impl PolicyStore {
    /// Build a store around an initial policy. The first `ETag` is derived
    /// from the policy content so a reload of the same file is stable.
    #[must_use]
    pub fn new(policy: Policy) -> Self {
        let etag = etag_for(&policy, 0);
        Self {
            inner: Arc::new(RwLock::new(PolicySnapshot { policy, etag })),
        }
    }

    /// Build a store with an empty (default-deny) policy. Used by tests that
    /// focus on the roster state machine in isolation.
    #[must_use]
    pub fn empty() -> Self {
        Self::new(Policy::default())
    }

    /// Build a store seeded with the Phase-2 [`Policy::bootstrap`] policy —
    /// the coordinator's default when no `--policy-file` is supplied. It
    /// carries exactly the two system rules (`tag:system → tag:system` and
    /// `tag:system → tag:net-*`) so shared infra can serve every tenant
    /// runner while distinct tenant networks stay isolated by default-deny.
    #[must_use]
    pub fn bootstrap() -> Self {
        Self::new(Policy::bootstrap())
    }

    /// Load a policy from a JSON file on disk. Used at startup when a
    /// policy path is configured.
    ///
    /// The loaded policy is [`Policy::validate`]d before it is installed, so a
    /// hand-written file that would break cross-tenant isolation (e.g. a
    /// `tag:net-*` source) is rejected at startup instead of silently
    /// enforced.
    ///
    /// # Errors
    /// Returns a human-readable error string if the file can't be read,
    /// parsed, or fails policy validation.
    pub fn load_from_file(path: &Path) -> Result<Self, String> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| format!("read policy file {}: {e}", path.display()))?;
        let policy: Policy = serde_json::from_str(&raw)
            .map_err(|e| format!("parse policy file {}: {e}", path.display()))?;
        policy
            .validate()
            .map_err(|e| format!("invalid policy file {}: {e}", path.display()))?;
        Ok(Self::new(policy))
    }

    /// Snapshot the current policy + `ETag`.
    #[must_use]
    pub fn snapshot(&self) -> PolicySnapshot {
        self.inner.read().clone()
    }

    /// Just the current policy (clone). Used on the roster-filter hot-ish
    /// path; cheap relative to the network work it gates.
    #[must_use]
    pub fn current(&self) -> Policy {
        self.inner.read().policy.clone()
    }

    /// The current `ETag`.
    #[must_use]
    pub fn etag(&self) -> String {
        self.inner.read().etag.clone()
    }

    /// Replace the policy, requiring the caller's `if_match` `ETag` to equal
    /// the current one. On success the version counter advances and a new
    /// `ETag` is minted; the new snapshot is returned.
    ///
    /// The proposed policy is [`Policy::validate`]d *before* the `ETag` check,
    /// so a policy that would break cross-tenant isolation (e.g. a `tag:net-*`
    /// source) is rejected outright over `PUT /v1/policy` and never installed.
    ///
    /// # Errors
    /// - [`PolicyReplaceError::Invalid`] when the proposed policy fails
    ///   validation.
    /// - [`PolicyReplaceError::EtagMismatch`] when `if_match` is stale.
    pub fn replace(
        &self,
        if_match: &str,
        new_policy: Policy,
    ) -> Result<PolicySnapshot, PolicyReplaceError> {
        // Reject an isolation-breaking policy up front, before touching the
        // lock or the ETag — a bad payload never gets installed regardless of
        // whether its If-Match was fresh.
        new_policy.validate()?;
        // Derive the next `ETag` from the new content + a fresh nonce so two
        // different policies never collide, and replacing back to a prior
        // policy still advances the tag (avoids ABA confusion for clients
        // holding a stale handle).
        let mut guard = self.inner.write();
        if guard.etag != if_match {
            let current = guard.etag.clone();
            drop(guard);
            return Err(PolicyReplaceError::EtagMismatch {
                current,
                provided: if_match.to_owned(),
            });
        }
        let next = etag_for(&new_policy, next_nonce());
        let snapshot = PolicySnapshot {
            policy: new_policy,
            etag: next,
        };
        *guard = snapshot.clone();
        drop(guard);
        Ok(snapshot)
    }
}

/// Process-wide monotonic nonce so successive replaces always mint a fresh
/// `ETag` even if the policy content repeats.
fn next_nonce() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// Derive a short, stable `ETag` from policy content + a nonce. Uses an
/// inline `FNV-1a` hash so there's no external dependency and the value is
/// deterministic for a given (content, nonce) pair.
fn etag_for(policy: &Policy, nonce: u64) -> String {
    let serialized = serde_json::to_vec(policy).unwrap_or_default();
    let mut hash = fnv1a64(&serialized);
    // Mix the nonce in so distinct versions differ even with equal content.
    hash ^= nonce.wrapping_mul(0x100_0000_01b3);
    format!("\"{hash:016x}\"")
}

/// `FNV-1a` 64-bit hash. Deterministic across builds (unlike the std
/// `DefaultHasher`, which is `SipHash` with a per-process key).
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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::policy::model::AclRule;

    fn sample_policy() -> Policy {
        Policy::new(vec![AclRule::accept(&["tag:user-*"], &["tag:svc"])])
    }

    #[test]
    fn new_store_exposes_policy_and_etag() {
        let store = PolicyStore::new(sample_policy());
        let snap = store.snapshot();
        assert_eq!(snap.policy.acls.len(), 1);
        assert!(snap.etag.starts_with('"'));
        assert_eq!(store.etag(), snap.etag);
    }

    #[test]
    fn replace_with_matching_etag_succeeds_and_bumps() {
        let store = PolicyStore::new(sample_policy());
        let first_etag = store.etag();
        let new = Policy::new(vec![
            AclRule::accept(&["tag:user-*"], &["tag:svc"]),
            AclRule::accept(&["tag:admin"], &["*"]),
        ]);
        let snap = store.replace(&first_etag, new).expect("replace ok");
        assert_eq!(snap.policy.acls.len(), 2);
        assert_ne!(snap.etag, first_etag, "etag must change on replace");
        assert_eq!(store.etag(), snap.etag);
    }

    #[test]
    fn replace_with_stale_etag_is_rejected() {
        let store = PolicyStore::new(sample_policy());
        let stale = "\"deadbeef\"".to_owned();
        let err = store
            .replace(&stale, Policy::default())
            .expect_err("stale etag must fail");
        match err {
            PolicyReplaceError::EtagMismatch { provided, .. } => {
                assert_eq!(provided, stale);
            }
            other @ PolicyReplaceError::Invalid(_) => {
                panic!("expected EtagMismatch, got {other:?}")
            }
        }
        // Policy is unchanged after a rejected replace.
        assert_eq!(store.current().acls.len(), 1);
    }

    #[test]
    fn second_replace_needs_the_new_etag() {
        let store = PolicyStore::new(sample_policy());
        let e0 = store.etag();
        let snap = store
            .replace(&e0, Policy::default())
            .expect("first replace");
        // The old etag is now stale.
        assert!(store.replace(&e0, sample_policy()).is_err());
        // The fresh etag works.
        assert!(store.replace(&snap.etag, sample_policy()).is_ok());
    }

    #[test]
    fn load_from_file_parses_json() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("policy.json");
        std::fs::write(
            &path,
            r#"{ "acls": [ { "action": "accept", "src": ["tag:user-*"], "dst": ["tag:svc"] } ] }"#,
        )
        .unwrap();
        let store = PolicyStore::load_from_file(&path).expect("load");
        assert_eq!(store.current().acls.len(), 1);
    }

    #[test]
    fn load_from_missing_file_errors() {
        let err = PolicyStore::load_from_file(Path::new("/nonexistent/policy.json"))
            .expect_err("missing file");
        assert!(err.contains("read policy file"));
    }

    #[test]
    fn empty_store_is_default_deny() {
        let store = PolicyStore::empty();
        assert!(store.current().acls.is_empty());
    }

    #[test]
    fn bootstrap_store_carries_only_the_system_self_rule() {
        let store = PolicyStore::bootstrap();
        let policy = store.current();
        assert_eq!(
            policy.acls.len(),
            1,
            "bootstrap store must carry only the system self-rule"
        );
        // Strict default-deny: infra does NOT reach a tenant runner without an
        // explicit rule, and distinct tenants stay isolated.
        let system = vec!["tag:system".to_owned()];
        let net_x = vec!["tag:net-n_x".to_owned()];
        let net_y = vec!["tag:net-n_y".to_owned()];
        assert!(policy.can_see(&system, &system), "system sees itself");
        assert!(
            !policy.can_see(&system, &net_x),
            "system must not serve a tenant net without an explicit rule"
        );
        assert!(!policy.can_see(&net_x, &net_y), "tenant nets isolated");
    }

    #[test]
    fn load_from_file_rejects_cross_tenant_glob_source() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("bad-policy.json");
        std::fs::write(
            &path,
            r#"{ "acls": [ { "action": "accept", "src": ["tag:net-*"], "dst": ["tag:system"] } ] }"#,
        )
        .unwrap();
        let err = PolicyStore::load_from_file(&path)
            .expect_err("a tag:net-* source must be rejected at load");
        assert!(err.contains("invalid policy file"), "got: {err}");
        assert!(err.contains("tag:net-*"), "got: {err}");
    }

    #[test]
    fn load_from_file_accepts_concrete_tenant_self_rule() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("good-policy.json");
        std::fs::write(
            &path,
            r#"{ "acls": [ { "src": ["tag:net-n_slug"], "dst": ["tag:net-n_slug"] } ] }"#,
        )
        .unwrap();
        let store = PolicyStore::load_from_file(&path).expect("concrete tenant self-rule is valid");
        assert_eq!(store.current().acls.len(), 1);
    }

    #[test]
    fn replace_rejects_cross_tenant_glob_source() {
        let store = PolicyStore::bootstrap();
        let etag = store.etag();
        let bad = Policy::new(vec![AclRule::accept(&["tag:net-*"], &["tag:system"])]);
        let err = store
            .replace(&etag, bad)
            .expect_err("replace must reject a tag:net-* source");
        assert!(
            matches!(err, PolicyReplaceError::Invalid(_)),
            "expected Invalid, got {err:?}"
        );
        // The store is unchanged: still the single bootstrap rule, same ETag.
        assert_eq!(store.current().acls.len(), 1);
        assert_eq!(
            store.etag(),
            etag,
            "a rejected replace must not bump the ETag"
        );
    }

    #[test]
    fn replace_rejects_invalid_policy_even_with_fresh_etag() {
        // Validation runs before the ETag check, so a fresh If-Match doesn't
        // let an isolation-breaking policy through.
        let store = PolicyStore::bootstrap();
        let fresh = store.etag();
        let bad = Policy::new(vec![AclRule::accept(&["*"], &["tag:system"])]);
        assert!(matches!(
            store.replace(&fresh, bad),
            Err(PolicyReplaceError::Invalid(_))
        ));
    }

    #[test]
    fn replace_still_accepts_a_valid_per_network_self_rule() {
        let store = PolicyStore::bootstrap();
        let etag = store.etag();
        let mut acls = store.current().acls;
        acls.push(AclRule::accept(&["tag:net-n_slug"], &["tag:net-n_slug"]));
        let snap = store
            .replace(&etag, Policy::new(acls))
            .expect("a concrete per-network self-rule is valid");
        // The single bootstrap rule plus the appended per-network self-rule.
        assert_eq!(snap.policy.acls.len(), 2);
    }

    #[test]
    fn etag_is_deterministic_for_same_content_at_construction() {
        // Two stores built from equal policies share the construction-time
        // ETag (nonce 0), so reloading the same file is stable.
        let a = PolicyStore::new(sample_policy());
        let b = PolicyStore::new(sample_policy());
        assert_eq!(a.etag(), b.etag());
    }
}
