//! Unit tests for the [`super`] ACL policy model — split out to keep
//! `model.rs` under the 500-line file budget. Same module path as an
//! inline `#[cfg(test)] mod tests` (declared via `#[path]` in the parent).

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

// -----------------------------------------------------------------
// Phase-2 bootstrap policy (step 17): the coordinator's default.
// -----------------------------------------------------------------

/// The bootstrap policy is EXACTLY the single `tag:system → tag:system`
/// self-rule — no more, no less. A drift here (e.g. someone re-adding the
/// broad `tag:system → tag:net-*` rule, or a `net-* ↔ net-*` glob) is the
/// exact failure mode this test exists to catch.
#[test]
fn bootstrap_is_system_self_rule_only() {
    let p = Policy::bootstrap();
    assert_eq!(
        p.acls.len(),
        1,
        "bootstrap must carry only the system self-rule: {:?}",
        p.acls
    );
    assert_eq!(p.acls[0].src, vec!["tag:system".to_string()]);
    assert_eq!(p.acls[0].dst, vec!["tag:system".to_string()]);
    // Infra no longer reaches tenants by default (strict default-deny).
    let net = vec!["tag:net-n_aaaaaaaaaaaa".to_string()];
    let sys = vec!["tag:system".to_string()];
    assert!(
        !p.can_see(&sys, &net),
        "system must not see a tenant without an explicit rule"
    );
    // Belt-and-suspenders: assert NO rule has a tag:net-* source — that
    // would be the cross-tenant glob the contract forbids.
    assert!(
        p.acls
            .iter()
            .all(|r| !r.src.iter().any(|s| s.starts_with("tag:net-"))),
        "bootstrap must NOT carry any tag:net-* source rule: {:?}",
        p.acls
    );
}

/// Under bootstrap, shared infra (`tag:system`) sees itself.
#[test]
fn bootstrap_system_sees_system() {
    let policy = Policy::bootstrap();
    assert!(policy.can_see(&tags(&["tag:system"]), &tags(&["tag:system"])));
}

/// Under bootstrap ALONE, infra (`tag:system`) does NOT reach a tenant
/// runner (`tag:net-X`): strict default-deny. Infra→tenant reachability
/// (serving a deployed app) is now an EXPLICIT per-network rule that auth
/// writes (`tag:system → tag:net-<slug>`), not a bootstrap concern.
#[test]
fn bootstrap_system_does_not_see_tenant_net() {
    let policy = Policy::bootstrap();
    assert!(
        !policy.can_see(&tags(&["tag:system"]), &tags(&["tag:net-n_jpegxik72nng"])),
        "system must NOT reach a tenant net peer without an explicit rule"
    );
    // Symmetric direction (runner -> infra) is likewise denied.
    assert!(
        !policy.can_see(&tags(&["tag:net-n_jpegxik72nng"]), &tags(&["tag:system"])),
        "tenant net peer must NOT reach system without an explicit rule"
    );
}

/// THE isolation invariant: two distinct tenant networks do NOT see each
/// other under the bootstrap policy. This is what guards against the
/// forbidden `tag:net-* ↔ tag:net-*` glob — with that glob present (and
/// `can_see` being symmetric) this assertion would flip and fail.
#[test]
fn bootstrap_distinct_tenant_nets_are_isolated() {
    let policy = Policy::bootstrap();
    let net_x = tags(&["tag:net-n_aaaaaaaaaaaa"]);
    let net_y = tags(&["tag:net-n_bbbbbbbbbbbb"]);
    assert!(
        !policy.can_see(&net_x, &net_y),
        "net-X and net-Y MUST be isolated under bootstrap"
    );
    assert!(
        !policy.can_see(&net_y, &net_x),
        "isolation holds in both directions"
    );
}

/// Under bootstrap ALONE, two peers in the SAME tenant network do not yet
/// see each other — same-net visibility is NOT a bootstrap concern. It is
/// granted by a per-network self-rule (`tag:net-<slug> ↔ tag:net-<slug>`)
/// that the auth service PUTs on network-create. This test proves the
/// separation: bootstrap denies same-net, the added self-rule enables it,
/// and that self-rule does NOT leak into a *different* network.
#[test]
fn same_net_visibility_requires_an_added_per_network_rule() {
    let net_x_a = tags(&["tag:net-n_aaaaaaaaaaaa"]);
    let net_x_b = tags(&["tag:net-n_aaaaaaaaaaaa"]);
    let net_y = tags(&["tag:net-n_bbbbbbbbbbbb"]);

    // Bootstrap alone: same-net peers cannot see each other yet.
    let bootstrap = Policy::bootstrap();
    assert!(
        !bootstrap.can_see(&net_x_a, &net_x_b),
        "bootstrap alone must NOT grant same-net visibility"
    );

    // Auth service PUTs the per-network self-rule on network-create. We
    // model that by appending it to the bootstrap rules.
    let mut acls = Policy::bootstrap().acls;
    acls.push(AclRule::accept(
        &["tag:net-n_aaaaaaaaaaaa"],
        &["tag:net-n_aaaaaaaaaaaa"],
    ));
    let with_self_rule = Policy::new(acls);

    // Now same-net peers in net-X see each other...
    assert!(
        with_self_rule.can_see(&net_x_a, &net_x_b),
        "the per-network self-rule must grant same-net visibility"
    );
    // ...but the self-rule for net-X does NOT leak into net-Y, and
    // cross-tenant isolation still holds.
    assert!(
        !with_self_rule.can_see(&net_x_a, &net_y),
        "a net-X self-rule must not expose net-Y"
    );
}

// -----------------------------------------------------------------
// Policy::validate — reject isolation-breaking cross-tenant globs as a
// SOURCE (the misconfiguration the major finding asks us to make
// impossible). tag:net-* is fine as a destination, never as a source.
// -----------------------------------------------------------------

/// The bootstrap policy itself MUST pass validation: under strict
/// default-deny it is just the `tag:system → tag:system` self-rule, which
/// carries no `tag:net-*` source and is trivially valid.
#[test]
fn validate_accepts_bootstrap() {
    assert!(Policy::bootstrap().validate().is_ok());
}

/// The empty (default-deny) policy is trivially valid.
#[test]
fn validate_accepts_empty_policy() {
    assert!(Policy::default().validate().is_ok());
}

/// A per-network self-rule with a CONCRETE tenant source is allowed — that
/// is exactly what the auth service PUTs on network-create.
#[test]
fn validate_accepts_concrete_tenant_self_rule() {
    let policy = Policy::new(vec![AclRule::accept(
        &["tag:net-n_jpegxik72nng"],
        &["tag:net-n_jpegxik72nng"],
    )]);
    assert!(policy.validate().is_ok());
}

/// THE finding: a `tag:net-*` SOURCE is rejected with a clear error.
#[test]
fn validate_rejects_net_wildcard_source() {
    let policy = Policy::new(vec![AclRule::accept(&[TAG_NET_WILDCARD], &["tag:system"])]);
    let err = policy
        .validate()
        .expect_err("net-* source must be rejected");
    match err {
        PolicyValidationError::CrossTenantGlobSource { pattern } => {
            assert_eq!(pattern, "tag:net-*");
        }
    }
    // The message names the offending pattern and explains why.
    assert!(err_to_string(&policy).contains("tag:net-*"));
    assert!(err_to_string(&policy).contains("forbidden"));
}

fn err_to_string(policy: &Policy) -> String {
    policy
        .validate()
        .expect_err("expected validation error")
        .to_string()
}

/// A narrower-but-still-cross-tenant glob (`tag:net-n*`) is rejected too —
/// it would sweep every `n_…` tenant slug.
#[test]
fn validate_rejects_partial_net_wildcard_source() {
    let policy = Policy::new(vec![AclRule::accept(&["tag:net-n*"], &["tag:system"])]);
    assert!(matches!(
        policy.validate(),
        Err(PolicyValidationError::CrossTenantGlobSource { .. })
    ));
}

/// A bare `*` source is rejected — it matches every tenant (and more).
#[test]
fn validate_rejects_bare_star_source() {
    let policy = Policy::new(vec![AclRule::accept(&["*"], &["tag:system"])]);
    assert!(matches!(
        policy.validate(),
        Err(PolicyValidationError::CrossTenantGlobSource { .. })
    ));
}

/// A wildcard whose prefix is *above* the `tag:net-` boundary (`tag:ne*`)
/// also reaches into the namespace and is rejected.
#[test]
fn validate_rejects_prefix_above_net_boundary() {
    let policy = Policy::new(vec![AclRule::accept(&["tag:ne*"], &["tag:system"])]);
    assert!(matches!(
        policy.validate(),
        Err(PolicyValidationError::CrossTenantGlobSource { .. })
    ));
}

/// FALSE-POSITIVE GUARD: an unrelated wildcard source (`tag:user-*`) that
/// cannot reach the `tag:net-` namespace MUST remain valid.
#[test]
fn validate_allows_unrelated_wildcard_source() {
    let policy = Policy::new(vec![AclRule::accept(&["tag:user-*"], &["tag:svc"])]);
    assert!(policy.validate().is_ok());
}

/// `tag:net-*` is legal as a DESTINATION in an externally-authored policy —
/// only a source is forbidden.
#[test]
fn validate_allows_net_wildcard_destination() {
    let policy = Policy::new(vec![AclRule::accept(&["tag:system"], &[TAG_NET_WILDCARD])]);
    assert!(policy.validate().is_ok());
}

/// A non-`accept` rule with a net-* source is still flagged — validation
/// guards the *shape* of the policy regardless of action, so a future
/// `deny`/`accept` flip can't smuggle a cross-tenant source past us.
#[test]
fn validate_flags_net_wildcard_source_on_any_action() {
    let policy = Policy::new(vec![AclRule {
        action: "deny".to_owned(),
        src: tags(&[TAG_NET_WILDCARD]),
        dst: tags(&["tag:system"]),
    }]);
    assert!(matches!(
        policy.validate(),
        Err(PolicyValidationError::CrossTenantGlobSource { .. })
    ));
}
