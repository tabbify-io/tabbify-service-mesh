//! Tag-based ACL policy model — a Tailscale-style allow-graph.
//!
//! A [`Policy`] is an ordered set of `accept` rules, each an edge from a
//! set of source tags to a set of destination tags. Evaluation is
//! **default-deny**: two nodes can see each other only if some rule
//! permits it.
//!
//! ## Symmetric visibility (OQ-7 decision)
//!
//! For now the mesh enforces **SYMMETRIC** visibility: node A sees node B
//! iff B may also see A. The evaluation entry-point [`Policy::can_see`]
//! returns `true` when an allow edge exists in *either* direction, so a
//! single `user-* → svc` rule grants mutual visibility between users and
//! shared services, and the absence of any `user-a ↔ user-b` rule denies
//! both directions at once. Asymmetric per-direction visibility (and the
//! `/128` allowed-ips enforcement it would require) is deferred — see
//! spec §5.4 / §5.5 and OQ-7.
//!
//! ## Wildcards
//!
//! A tag in a rule may end in `*` to match by prefix, e.g. `tag:user-*`
//! matches `tag:user-alice` and `tag:user-bob`. A bare `*` matches any
//! tag. Matching is plain prefix matching on the tag string — there is no
//! glob/regex engine.
//!
//! ## Source of tags (E4 forward-compat)
//!
//! Today a node's tags arrive on `RegisterRequest` and are stamped onto
//! the roster entry in a single place (see the coordinator's identity
//! seam). The policy engine only ever reads a node's *effective* tags, so
//! when E4 swaps the source to authoritative JWT claims, nothing in this
//! module changes.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// The `tag:net-` namespace prefix shared by every per-tenant network tag.
///
/// A concrete tenant tag is `tag:net-<slug>` (e.g. `tag:net-n_jpegxik72nng`).
/// A *source* pattern that wildcards over this whole namespace
/// (`tag:net-*`, `tag:net-n*`, …) is forbidden — see [`Policy::validate`].
const TAG_NET_PREFIX: &str = "tag:net-";

/// A single `accept` rule: every source tag may reach every destination
/// tag. Tags support trailing-`*` prefix wildcards (and a bare `*`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct AclRule {
    /// Always `"accept"` today; kept explicit so a future `"deny"`/`"drop"`
    /// action slots in without a wire-format break. Unknown actions are
    /// treated as non-accepting by [`Policy::can_see`].
    #[serde(default = "default_action")]
    pub action: String,
    /// Source tag patterns.
    pub src: Vec<String>,
    /// Destination tag patterns.
    pub dst: Vec<String>,
}

fn default_action() -> String {
    "accept".to_owned()
}

/// The tag worn by shared infrastructure peers.
///
/// Supervisor, node, registry, auth and the coordinator all carry
/// `tag:system`. Phase-2: infra is *never* in a tenant network — `tag:system`
/// lets it both talk among itself and serve every tenant's runners.
pub const TAG_SYSTEM: &str = "tag:system";

/// Prefix wildcard matching every per-tenant network tag.
///
/// E.g. `tag:net-n_jpegxik72nng`. Used only as a *destination* in the
/// bootstrap policy so `tag:system` can reach any tenant runner; it is
/// deliberately **never** used as a source paired with this same destination,
/// which would (under symmetric `can_see`) collapse cross-tenant isolation.
pub const TAG_NET_WILDCARD: &str = "tag:net-*";

impl AclRule {
    /// Convenience constructor for an `accept` rule.
    #[must_use]
    pub fn accept(src: &[&str], dst: &[&str]) -> Self {
        Self {
            action: default_action(),
            src: src.iter().map(|s| (*s).to_owned()).collect(),
            dst: dst.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    /// Whether this rule is an `accept` rule. Non-accept actions never
    /// grant visibility under the current symmetric model.
    fn is_accept(&self) -> bool {
        self.action == "accept"
    }
}

/// The full ACL policy: an ordered list of [`AclRule`]s. Default-deny —
/// an empty policy denies everything.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Policy {
    /// Accept rules, evaluated as a set (order is not significant for
    /// default-deny visibility, but preserved for round-trip fidelity).
    #[serde(default)]
    pub acls: Vec<AclRule>,
}

impl Policy {
    /// Build a policy from a list of rules.
    #[must_use]
    pub const fn new(acls: Vec<AclRule>) -> Self {
        Self { acls }
    }

    /// The Phase-2 mesh **bootstrap** policy — the default a coordinator
    /// starts with when no `--policy-file` is supplied. EXACTLY two rules
    /// and nothing else:
    ///
    /// 1. `tag:system → tag:system` — shared infra peers (supervisor, node,
    ///    registry, auth, coordinator) talk among themselves.
    /// 2. `tag:system → tag:net-*` — infra can reach *any* tenant runner so
    ///    it can serve it; being symmetric, the runner can also reach infra.
    ///
    /// Crucially there is **no** `tag:net-* → tag:net-*` (or `tag:net-* ↔
    /// tag:net-*`) edge: that glob would, under the symmetric
    /// [`Self::can_see`], let `net-A` reach `net-B` and break tenant
    /// isolation. Per-tenant intra-network visibility comes from per-network
    /// self-rules (`tag:net-<slug> ↔ tag:net-<slug>`) that the auth service
    /// PUTs on network-create — NOT from the bootstrap policy.
    ///
    /// Default-deny + these two system rules + per-network self-rules =
    /// isolation, while infra can still serve every tenant's FC runner.
    #[must_use]
    pub fn bootstrap() -> Self {
        Self::new(vec![
            AclRule::accept(&[TAG_SYSTEM], &[TAG_SYSTEM]),
            AclRule::accept(&[TAG_SYSTEM], &[TAG_NET_WILDCARD]),
        ])
    }

    /// Does some `accept` rule have a source matching any of `src_tags`
    /// **and** a destination matching any of `dst_tags`? This is the raw
    /// directional check; [`Self::can_see`] symmetrises it.
    fn allows_directed(&self, src_tags: &[String], dst_tags: &[String]) -> bool {
        self.acls
            .iter()
            .filter(|r| r.is_accept())
            .any(|rule| tags_match_any(&rule.src, src_tags) && tags_match_any(&rule.dst, dst_tags))
    }

    /// SYMMETRIC visibility check: may a node carrying `a_tags` and a node
    /// carrying `b_tags` see each other?
    ///
    /// Returns `true` if an allow edge exists in *either* direction
    /// (a→b or b→a). This is the OQ-7 symmetric decision: shared-service
    /// rules like `user-* → svc` grant mutual visibility, and mutual deny
    /// between distinct user groups falls out of the absence of any edge.
    #[must_use]
    pub fn can_see(&self, a_tags: &[String], b_tags: &[String]) -> bool {
        self.allows_directed(a_tags, b_tags) || self.allows_directed(b_tags, a_tags)
    }

    /// Reject policies that would collapse cross-tenant isolation.
    ///
    /// [`Self::can_see`] is **symmetric**, so a single rule whose *source*
    /// wildcards over the whole `tag:net-` namespace (e.g. `tag:net-*`) would
    /// let any tenant network reach any other — the exact failure mode the
    /// Phase-2 bootstrap policy is built to avoid. The wildcard is legal as a
    /// *destination* (the bootstrap `tag:system → tag:net-*` rule lets shared
    /// infra serve every tenant), but never as a *source*.
    ///
    /// A concrete single-tenant source such as `tag:net-n_jpegxik72nng` (no
    /// trailing `*`) is fine — that is exactly the per-network self-rule the
    /// auth service PUTs on network-create.
    ///
    /// Called at every boundary that admits an externally-authored policy
    /// (file load + runtime `PUT /v1/policy`), so a misconfiguration that
    /// would break tenant isolation is rejected up front rather than silently
    /// enforced.
    ///
    /// # Errors
    /// [`PolicyValidationError::CrossTenantGlobSource`] if any `accept` rule
    /// carries a source pattern that wildcards over the `tag:net-` namespace.
    pub fn validate(&self) -> Result<(), PolicyValidationError> {
        for rule in &self.acls {
            if let Some(pattern) = rule.src.iter().find(|s| is_cross_tenant_glob_source(s)) {
                return Err(PolicyValidationError::CrossTenantGlobSource {
                    pattern: pattern.clone(),
                });
            }
        }
        Ok(())
    }
}

/// A source pattern is a forbidden cross-tenant glob when it would match
/// **more than one** tenant network. That is any prefix wildcard whose prefix
/// is at or above the `tag:net-` namespace boundary:
///
/// - a bare `*` (matches every tenant — and everything else),
/// - `tag:net-*` / `tag:net-n*` / any `tag:net-…*` (matches a slice of the
///   namespace spanning multiple tenants),
/// - any wildcard whose prefix is itself a prefix of `tag:net-`
///   (e.g. `tag:ne*`, `tag:*`), which would also sweep the whole namespace.
///
/// A non-wildcard tag (`tag:net-n_slug`) matches exactly one tenant and is
/// allowed; so is any wildcard that cannot reach into the `tag:net-`
/// namespace (e.g. `tag:user-*`).
fn is_cross_tenant_glob_source(pattern: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    let Some(prefix) = pattern.strip_suffix('*') else {
        // Not a wildcard: an exact tag matches a single tenant at most.
        return false;
    };
    // The wildcard sweeps multiple tenants iff its prefix sits at or above the
    // `tag:net-` boundary, i.e. `tag:net-` starts with the prefix
    // (`tag:ne*`, `tag:net-*`) OR the prefix reaches into the namespace
    // (`tag:net-n*` has prefix `tag:net-n`, which starts with `tag:net-`).
    TAG_NET_PREFIX.starts_with(prefix) || prefix.starts_with(TAG_NET_PREFIX)
}

/// Error returned by [`Policy::validate`] when a policy would break
/// cross-tenant isolation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PolicyValidationError {
    /// An `accept` rule carries a source pattern that wildcards over the
    /// `tag:net-` namespace, which — under the symmetric [`Policy::can_see`] —
    /// would let distinct tenant networks reach each other.
    #[error(
        "cross-tenant glob '{pattern}' as a policy source is forbidden: it would let \
         distinct tenant networks see each other (tag:net-* is allowed only as a destination)"
    )]
    CrossTenantGlobSource {
        /// The offending source pattern.
        pattern: String,
    },
}

/// Does any pattern in `patterns` match the node carrying `tags`?
///
/// A bare `*` pattern matches the node **unconditionally** — including a
/// node with no tags at all — because `*` means "any node" (Tailscale
/// semantics), not "any tag". Every other pattern needs at least one tag
/// to match against, so a tagless node is denied by tag/prefix rules.
fn tags_match_any(patterns: &[String], tags: &[String]) -> bool {
    patterns.iter().any(|pat| {
        if pat == "*" {
            return true;
        }
        tags.iter().any(|tag| tag_matches(pat, tag))
    })
}

/// Match a single pattern against a single tag.
///
/// - A bare `*` matches anything.
/// - A trailing `*` is a prefix match: `tag:user-*` matches
///   `tag:user-alice`.
/// - Otherwise an exact string match.
fn tag_matches(pattern: &str, tag: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return tag.starts_with(prefix);
    }
    pattern == tag
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
#[path = "model_tests.rs"]
mod tests;
