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
//!   [`ValidatedClaims`] `network` + identity/security `tags` are used and the
//!   request-supplied values for them are ignored. This closes the spoofing gap
//!   for identity (`tag:user-*`, `tag:net-*`, `tag:system`, network). The ONE
//!   exception is the self-advertised CAPABILITY tags
//!   (`firecracker`/`docker`/`builder`, see [`SELF_ADVERTISABLE_CAPABILITY_TAGS`]):
//!   they are merged on top of the claims, because they describe hardware/role
//!   the node proves and forging one only breaks the forger — so a per-network
//!   join token (carrying only `tag:net-<slug>`) still yields a working worker.
//! - **Escape hatch (dev / E1 only):** when no auth service is configured
//!   (`AUTH_URL` unset), there are no validated claims, so the
//!   request-supplied values are used as-is. This is the legacy
//!   trust-on-assert behavior, acceptable ONLY for a local smoke / insecure
//!   run behind a firewall — it is NOT safe for any multi-tenant
//!   deployment.

use crate::auth::ValidatedClaims;
use crate::http::api::RegisterRequest;

/// Capability / role tags a node MAY contribute even on the authoritative path.
///
/// Unlike network and identity tags (`tag:user-*`, `tag:net-*`, `tag:system`),
/// these describe **hardware/role the node proves at boot** — running
/// `supervisord` ⇒ `supervisor` (the node directory lists a peer as a supervisor
/// only if it carries this tag), `/dev/kvm` ⇒ `firecracker`, a reachable docker
/// daemon ⇒ `docker`, operator designation ⇒ `builder`. Forging one is NOT a
/// privilege escalation: work routed to a node that lied about a capability
/// simply fails on that node. So the coordinator merges them ON TOP of the
/// claims, which is what lets a per-network join token — which carries only
/// `tag:net-<slug>` because the admin minting it cannot know the node's hardware
/// — still yield a working supervisor/firecracker/builder worker.
const SELF_ADVERTISABLE_CAPABILITY_TAGS: [&str; 4] =
    ["supervisor", "firecracker", "docker", "builder"];

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
        // Authoritative path: network + identity/security tags come from the
        // validated claims (a node cannot self-assert `tag:user-*`, `tag:system`,
        // or another network — the §5.1 spoofing fix). ON TOP of that the node
        // may contribute its self-advertised CAPABILITY tags (see
        // [`SELF_ADVERTISABLE_CAPABILITY_TAGS`]) — hardware/role facts whose
        // forgery only breaks the forger. Claims first (stable order), then any
        // new capability tag the node advertised.
        |c| {
            let mut tags = c.tags.clone();
            for t in &req.tags {
                if SELF_ADVERTISABLE_CAPABILITY_TAGS.contains(&t.as_str()) && !tags.contains(t) {
                    tags.push(t.clone());
                }
            }
            NodeIdentity {
                network: c.network.clone(),
                tags,
            }
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
            wg_listen_port: None,
            display_name: "n".into(),
            network: network.into(),
            tags: tags.iter().map(|s| (*s).to_owned()).collect(),
            hosted_app_ulas: vec![],
            kind: "peer".into(),
            parent: None,
            app_uuid: None,
            requested_ula: None,
            software_version: None,
            mesh_version: None,
            relay_only: false,
        }
    }

    fn claims(network: &str, tags: &[&str]) -> ValidatedClaims {
        ValidatedClaims {
            valid: true,
            subject: "node".into(),
            network: network.into(),
            tags: tags.iter().map(|s| (*s).to_owned()).collect(),
            requested_ulas: Vec::new(),
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
        // A capability tag the node advertises still merges (it proves a role);
        // an identity tag does not. Here `tag:user-bob` is identity → dropped.
        assert!(
            id.tags.is_empty(),
            "non-capability request tags must not leak through"
        );
    }

    /// The fix for self-serve "Add a node": a per-network join token carries only
    /// `tag:net-<slug>`, yet the node still becomes a usable worker because its
    /// self-advertised CAPABILITY tags merge on top. Identity tags it tries to
    /// sneak in are still dropped.
    #[test]
    fn capability_tags_merge_over_claims_identity_tags_do_not() {
        let advertised = req(
            "bob",
            &[
                "supervisor",
                "firecracker",
                "builder",
                "docker",
                "tag:user-bob",
                "tag:system",
            ],
        );
        let validated = claims("alice", &["tag:net-alice"]);
        let id = stamp_identity(&advertised, Some(&validated));
        assert_eq!(id.network, "alice", "network still from claims");
        // Claims first, then the allowlisted capability tags — in request order.
        assert_eq!(
            id.tags,
            vec![
                "tag:net-alice".to_owned(),
                "supervisor".to_owned(),
                "firecracker".to_owned(),
                "builder".to_owned(),
                "docker".to_owned(),
            ],
            "supervisor/firecracker/builder/docker merge; tag:user-bob + tag:system are dropped"
        );
    }

    /// A capability already present in the claims is not duplicated.
    #[test]
    fn merged_capability_tag_is_not_duplicated() {
        let advertised = req("alice", &["firecracker", "supervisor"]);
        let validated = claims("alice", &["tag:net-alice", "firecracker"]);
        let id = stamp_identity(&advertised, Some(&validated));
        assert_eq!(
            id.tags,
            vec![
                "tag:net-alice".to_owned(),
                "firecracker".to_owned(),
                "supervisor".to_owned(),
            ],
        );
    }
}
