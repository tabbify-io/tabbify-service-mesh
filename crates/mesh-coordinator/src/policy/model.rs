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

/// A single `accept` rule: every source tag may reach every destination
/// tag. Tags support trailing-`*` prefix wildcards (and a bare `*`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
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
mod tests {
    use super::*;

    fn tags(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    /// An explicit same-tag rule lets two nodes carrying that tag see each
    /// other.
    #[test]
    fn same_tag_allow() {
        let policy = Policy::new(vec![AclRule::accept(
            &["tag:user-alice"],
            &["tag:user-alice"],
        )]);
        assert!(policy.can_see(&tags(&["tag:user-alice"]), &tags(&["tag:user-alice"])));
    }

    /// Default-deny: an empty policy denies every pair.
    #[test]
    fn default_deny_empty_policy() {
        let policy = Policy::default();
        assert!(!policy.can_see(&tags(&["tag:user-alice"]), &tags(&["tag:user-alice"])));
        assert!(!policy.can_see(&tags(&["tag:user-alice"]), &tags(&["tag:svc"])));
    }

    /// Two distinct user groups with no connecting edge cannot see each
    /// other (implicit deny = private networks).
    #[test]
    fn distinct_user_groups_denied() {
        let policy = Policy::new(vec![
            AclRule::accept(&["tag:user-alice"], &["tag:user-alice"]),
            AclRule::accept(&["tag:user-bob"], &["tag:user-bob"]),
        ]);
        assert!(!policy.can_see(&tags(&["tag:user-alice"]), &tags(&["tag:user-bob"])));
        // ...but each can still see its own group.
        assert!(policy.can_see(&tags(&["tag:user-alice"]), &tags(&["tag:user-alice"])));
        assert!(policy.can_see(&tags(&["tag:user-bob"]), &tags(&["tag:user-bob"])));
    }

    /// A `user-* → svc` rule grants visibility from any user to the shared
    /// service pool — and, being symmetric, from svc back to the user.
    #[test]
    fn wildcard_src_to_service() {
        let policy = Policy::new(vec![AclRule::accept(&["tag:user-*"], &["tag:svc"])]);
        assert!(policy.can_see(&tags(&["tag:user-alice"]), &tags(&["tag:svc"])));
        assert!(policy.can_see(&tags(&["tag:user-bob"]), &tags(&["tag:svc"])));
        // Symmetric: the edge is user→svc, but svc→user is also visible.
        assert!(policy.can_see(&tags(&["tag:svc"]), &tags(&["tag:user-alice"])));
    }

    /// The symmetric check fires even when the matching edge is the
    /// reverse of the queried direction.
    #[test]
    fn symmetric_reverse_direction() {
        // Only a user→svc rule exists.
        let policy = Policy::new(vec![AclRule::accept(&["tag:user-*"], &["tag:svc"])]);
        // Query svc-first (b→a is the edge direction).
        assert!(policy.can_see(&tags(&["tag:svc"]), &tags(&["tag:user-carol"])));
    }

    /// A bare `*` destination matches any tag.
    #[test]
    fn bare_star_matches_anything() {
        let policy = Policy::new(vec![AclRule::accept(&["tag:admin"], &["*"])]);
        assert!(policy.can_see(&tags(&["tag:admin"]), &tags(&["tag:whatever"])));
        assert!(policy.can_see(&tags(&["tag:literally-anything"]), &tags(&["tag:admin"])));
    }

    /// Wildcard does NOT over-match: `tag:user-*` must not match
    /// `tag:userspace` style false-prefix only when it genuinely shares the
    /// prefix. (Prefix semantics are intentional; this documents them.)
    #[test]
    fn wildcard_is_prefix_not_substring() {
        let policy = Policy::new(vec![AclRule::accept(&["tag:user-*"], &["tag:svc"])]);
        // `tag:admin-user` does NOT start with `tag:user-`.
        assert!(!policy.can_see(&tags(&["tag:admin-user"]), &tags(&["tag:svc"])));
    }

    /// A node with no tags at all is denied under any non-wildcard policy.
    #[test]
    fn untagged_node_denied() {
        let policy = Policy::new(vec![AclRule::accept(&["tag:user-*"], &["tag:svc"])]);
        assert!(!policy.can_see(&tags(&[]), &tags(&["tag:svc"])));
    }

    /// A non-`accept` action does not grant visibility.
    #[test]
    fn non_accept_action_denied() {
        let policy = Policy::new(vec![AclRule {
            action: "deny".to_owned(),
            src: tags(&["tag:user-alice"]),
            dst: tags(&["tag:user-alice"]),
        }]);
        assert!(!policy.can_see(&tags(&["tag:user-alice"]), &tags(&["tag:user-alice"])));
    }

    /// JSON round-trips through the HuJSON-style `{ "acls": [...] }` shape.
    #[test]
    fn json_round_trip() {
        let json = r#"{
            "acls": [
                { "action": "accept", "src": ["tag:user-*"], "dst": ["tag:svc"] }
            ]
        }"#;
        let policy: Policy = serde_json::from_str(json).expect("parse");
        assert_eq!(policy.acls.len(), 1);
        assert!(policy.can_see(&tags(&["tag:user-z"]), &tags(&["tag:svc"])));
        // Re-serialize and re-parse for fidelity.
        let s = serde_json::to_string(&policy).expect("serialize");
        let again: Policy = serde_json::from_str(&s).expect("reparse");
        assert_eq!(policy, again);
    }

    /// `action` defaults to `accept` when omitted in the JSON.
    #[test]
    fn action_defaults_to_accept() {
        let json = r#"{ "acls": [ { "src": ["tag:a"], "dst": ["tag:a"] } ] }"#;
        let policy: Policy = serde_json::from_str(json).expect("parse");
        assert_eq!(policy.acls[0].action, "accept");
        assert!(policy.can_see(&tags(&["tag:a"]), &tags(&["tag:a"])));
    }
}
