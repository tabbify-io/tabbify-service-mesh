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

use crate::policy::model::Policy;
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

/// Error returned by [`PolicyStore::replace`] on an `If-Match` mismatch.
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

    /// Build a store with an empty (default-deny) policy.
    #[must_use]
    pub fn empty() -> Self {
        Self::new(Policy::default())
    }

    /// Load a policy from a JSON file on disk. Used at startup when a
    /// policy path is configured.
    ///
    /// # Errors
    /// Returns a human-readable error string if the file can't be read or
    /// parsed.
    pub fn load_from_file(path: &Path) -> Result<Self, String> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| format!("read policy file {}: {e}", path.display()))?;
        let policy: Policy = serde_json::from_str(&raw)
            .map_err(|e| format!("parse policy file {}: {e}", path.display()))?;
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
    /// # Errors
    /// [`PolicyReplaceError::EtagMismatch`] when `if_match` is stale.
    pub fn replace(
        &self,
        if_match: &str,
        new_policy: Policy,
    ) -> Result<PolicySnapshot, PolicyReplaceError> {
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
        }
        // Policy is unchanged after a rejected replace.
        assert_eq!(store.current().acls.len(), 1);
    }

    #[test]
    fn second_replace_needs_the_new_etag() {
        let store = PolicyStore::new(sample_policy());
        let e0 = store.etag();
        let snap = store.replace(&e0, Policy::default()).expect("first replace");
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
    fn etag_is_deterministic_for_same_content_at_construction() {
        // Two stores built from equal policies share the construction-time
        // ETag (nonce 0), so reloading the same file is stable.
        let a = PolicyStore::new(sample_policy());
        let b = PolicyStore::new(sample_policy());
        assert_eq!(a.etag(), b.etag());
    }
}
