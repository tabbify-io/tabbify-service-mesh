//! Node identity stamping — the single seam where a peer's authoritative
//! `tags` + `network` are decided at register time.
//!
//! ## Why this exists (the §5.1 / §8 spoofing fix)
//!
//! A node's `tags` + `network` drive ACL roster filtering. If they were
//! taken from the joiner-supplied [`RegisterRequest`], any node could
//! self-assert `tag:user-bob` and read bob's roster — the spoofing hole
//! called out in spec §5.1.
//!
//! [`stamp_identity`] is the **single** place that decides identity, so
//! the source can be chosen here without touching the coordinator,
//! allocator, or policy filter (they all consume the stamped
//! [`NodeIdentity`], never the raw request):
//!
//! - **Authoritative (E4, default in prod):** when the coordinator has
//!   validated the join token against the auth service, the
//!   [`ValidatedClaims`] `network` + `tags` are used and the
//!   request-supplied values are ignored. This closes the spoofing gap —
//!   a node's effective identity equals exactly what the validator
//!   returned, regardless of what it sent.
//! - **Escape hatch (dev / E1 only):** when no auth service is configured
//!   (`AUTH_URL` unset), there are no validated claims, so the
//!   request-supplied values are used as-is. This is the legacy
//!   trust-on-assert behavior, acceptable ONLY for a local smoke / insecure
//!   run behind a firewall — it is NOT safe for any multi-tenant
//!   deployment.

use crate::auth::ValidatedClaims;
use crate::http::api::RegisterRequest;

/// The authoritative identity attributes of a node, as decided by the
/// coordinator at register time. Policy evaluation and ULA allocation read
/// from here — never from the raw request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeIdentity {
    /// The node's network (selects its ULA block; a tag/claim per §6).
    pub network: String,
    /// The node's effective tags (drive policy visibility).
    pub tags: Vec<String>,
}

/// Decide a node's authoritative identity for this register.
///
/// This is the single seam where the source of `network` + `tags` is
/// chosen (see the module docs):
///
/// - `claims = Some(_)` — the join token was validated by the auth
///   service; `network` + `tags` come from the **claims** (authoritative),
///   and `req`'s values are ignored. This is what closes the §5.1 spoofing
///   gap.
/// - `claims = None` — escape hatch (no `AUTH_URL` configured, dev/E1
///   only); fall back to the joiner-supplied `req` values verbatim.
#[must_use]
pub fn stamp_identity(req: &RegisterRequest, claims: Option<&ValidatedClaims>) -> NodeIdentity {
    claims.map_or_else(
        // Escape hatch: no validator configured, trust the request. Dev /
        // local-smoke only.
        || NodeIdentity {
            network: req.network.clone(),
            tags: req.tags.clone(),
        },
        // Authoritative path: the validator's claims win. A node cannot
        // influence its own tags/network here — whatever it put in `req`
        // is deliberately dropped.
        |c| NodeIdentity {
            network: c.network.clone(),
            tags: c.tags.clone(),
        },
    )
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn req(network: &str, tags: &[&str]) -> RegisterRequest {
        RegisterRequest {
            wg_public_key: "AAAA".into(),
            listen_endpoint: None,
            display_name: "n".into(),
            network: network.into(),
            tags: tags.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    fn claims(network: &str, tags: &[&str]) -> ValidatedClaims {
        ValidatedClaims {
            valid: true,
            subject: "node".into(),
            network: network.into(),
            tags: tags.iter().map(|s| (*s).to_owned()).collect(),
            kind: "join".into(),
            exp: 1_900_000_000,
        }
    }

    #[test]
    fn escape_hatch_stamps_network_and_tags_from_request() {
        // No claims (AUTH_URL unset) → trust the request.
        let id = stamp_identity(&req("alice", &["tag:user-alice"]), None);
        assert_eq!(id.network, "alice");
        assert_eq!(id.tags, vec!["tag:user-alice".to_owned()]);
    }

    #[test]
    fn escape_hatch_preserves_empty_network() {
        let id = stamp_identity(&req("", &[]), None);
        assert_eq!(id.network, "");
        assert!(id.tags.is_empty());
    }

    /// The spoofing fix: when claims are present they are authoritative —
    /// the request's network + tags are ignored entirely.
    #[test]
    fn claims_override_request_network_and_tags() {
        // Node tries to self-assert bob's identity in the request...
        let spoofed = req("bob", &["tag:user-bob", "tag:admin"]);
        // ...but the validated claims say it is alice.
        let validated = claims("alice", &["tag:user-alice"]);
        let id = stamp_identity(&spoofed, Some(&validated));
        assert_eq!(id.network, "alice", "network must come from claims");
        assert_eq!(
            id.tags,
            vec!["tag:user-alice".to_owned()],
            "tags must come from claims, spoofed request tags ignored"
        );
    }

    /// Claims with empty tags still win — a node can't sneak tags in via
    /// the request when the validator returns none.
    #[test]
    fn claims_with_empty_tags_still_override_request() {
        let spoofed = req("bob", &["tag:user-bob"]);
        let validated = claims("alice", &[]);
        let id = stamp_identity(&spoofed, Some(&validated));
        assert_eq!(id.network, "alice");
        assert!(id.tags.is_empty(), "request tags must not leak through");
    }
}
