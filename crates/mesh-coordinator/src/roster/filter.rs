//! Policy-aware roster filtering.
//!
//! The coordinator is the ACL enforcement point (spec §5.3): it filters
//! each node's view of the roster through the live [`crate::policy::Policy`]
//! so a node only ever learns the peers it is allowed to reach. The
//! `register` response and the `peers/stream` SSE both go through here.
//!
//! Visibility is SYMMETRIC (OQ-7): a viewer sees a peer iff
//! [`crate::policy::Policy::can_see`] permits the pair in either direction.
//! A node never sees itself in its own filtered view.
//!
//! ## Downstream effect (isolation as a consequence)
//!
//! The joiner builds its `WireGuard` session table purely from the roster
//! the coordinator hands it (`register` response + SSE add/remove frames).
//! Because the coordinator only ever reveals policy-permitted peers, the
//! joiner only forms tunnels with those peers — isolation between distinct
//! user-networks falls out automatically (no peer in the roster → no
//! session → no tunnel). Per-peer `/128` allowed-ips hardening at the
//! joiner is the next step (spec §5.5 / phase E3 task 5b) and is
//! intentionally NOT done here.

use crate::http::api::PeerInfo;
use crate::http::sse::PeerEvent;
use crate::roster::coordinator::Coordinator;
use uuid::Uuid;

impl Coordinator {
    /// Re-broadcast every current peer as an `Updated` event so connected
    /// SSE subscribers re-evaluate visibility against the (just-changed)
    /// policy. The per-viewer SSE adapter is stateful — it turns each of
    /// these into the right `peer_added` / `peer_updated` / `peer_removed`
    /// frame for that viewer based on what it had previously revealed (see
    /// [`crate::http::api`]). Called after a successful `PUT /v1/policy`.
    pub fn resync_all_peers(&self) {
        for info in self.snapshot() {
            self.inner.broadcaster.broadcast(PeerEvent::Updated(info));
        }
    }

    /// The tags of a peer by id, if present in the roster. Used to resolve
    /// a viewer's identity for SSE-stream filtering from just its peer id.
    #[must_use]
    pub fn peer_tags(&self, peer_id: Uuid) -> Option<Vec<String>> {
        self.inner.roster.get(&peer_id).map(|e| e.tags.clone())
    }

    /// Whether `viewer_tags` may see a peer carrying `peer_tags` under the
    /// current policy. Thin wrapper over the policy evaluator so callers
    /// (here + the SSE adapter) share one definition of "visible".
    #[must_use]
    pub fn viewer_can_see(&self, viewer_tags: &[String], peer_tags: &[String]) -> bool {
        self.inner.policy.current().can_see(viewer_tags, peer_tags)
    }

    /// The roster as seen by a viewer carrying `viewer_tags`, filtered by
    /// policy and excluding the viewer itself (matched by `viewer_id`).
    ///
    /// Ordered by peer index for stable output, matching
    /// [`Coordinator::snapshot`].
    #[must_use]
    pub fn visible_peers(&self, viewer_id: Uuid, viewer_tags: &[String]) -> Vec<PeerInfo> {
        let policy = self.inner.policy.current();
        let mut entries: Vec<_> = self
            .inner
            .roster
            .iter()
            .filter(|kv| {
                let e = kv.value();
                e.peer_id != viewer_id && policy.can_see(viewer_tags, &e.tags)
            })
            .map(|kv| kv.value().clone())
            .collect();
        entries.sort_by_key(|p| p.peer_index);
        entries
            .iter()
            .map(crate::roster::coordinator::PeerEntry::to_info)
            .collect()
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::http::api::RegisterRequest;
    use crate::policy::{AclRule, Policy, PolicyStore};
    use crate::publisher::NoopPublisher;
    use base64::Engine as _;
    use std::sync::Arc;
    use std::time::Duration;

    fn pubkey(seed: u8) -> String {
        base64::engine::general_purpose::STANDARD.encode([seed; 32])
    }

    /// Policy implementing the §5 two-scenario model:
    /// - each user-group sees itself,
    /// - every user reaches the shared service pool,
    /// - distinct user-groups have NO edge → mutual deny.
    fn shared_service_policy() -> Policy {
        Policy::new(vec![
            AclRule::accept(&["tag:user-a"], &["tag:user-a"]),
            AclRule::accept(&["tag:user-b"], &["tag:user-b"]),
            AclRule::accept(&["tag:user-*"], &["tag:svc"]),
        ])
    }

    fn coordinator_with(policy: Policy) -> Coordinator {
        Coordinator::with_policy(
            Arc::new(NoopPublisher),
            Duration::from_secs(60),
            PolicyStore::new(policy),
        )
    }

    fn req(seed: u8, name: &str, network: &str, tags: &[&str]) -> RegisterRequest {
        RegisterRequest {
            wg_public_key: pubkey(seed),
            listen_endpoint: Some("127.0.0.1:51820".into()),
            wg_listen_port: Some(51820),
            display_name: name.into(),
            network: network.into(),
            tags: tags.iter().map(|s| (*s).to_owned()).collect(),
            hosted_app_ulas: vec![],
        }
    }

    /// KEY ACCEPTANCE TEST (isolation).
    ///
    /// Nodes tagged `user-a`, `user-b`, `svc`. Policy = {user-*→svc,
    /// same-user↔same-user, user-a↮user-b deny}. Assert:
    /// - `user-a` sees {its own user-a peers + svc}, NOT `user-b`;
    /// - symmetrically `user-b` sees {its own + svc}, NOT `user-a`;
    /// - svc sees both users (symmetric to the user-*→svc edge).
    #[tokio::test]
    async fn user_networks_are_isolated_but_both_reach_shared_service() {
        let c = coordinator_with(shared_service_policy());

        // Two nodes in network "a", one in "b", one shared service.
        let (a1, _) = c
            .register(req(1, "a1", "a", &["tag:user-a"]))
            .await
            .expect("a1");
        let (a2, _) = c
            .register(req(2, "a2", "a", &["tag:user-a"]))
            .await
            .expect("a2");
        let (b1, _) = c
            .register(req(3, "b1", "b", &["tag:user-b"]))
            .await
            .expect("b1");
        let (svc, _) = c
            .register(req(4, "svc1", "svc", &["tag:svc"]))
            .await
            .expect("svc");

        // ---- a1's view: a2 + svc, never b1, never itself. ----
        let a1_view = c.visible_peers(a1.peer_id, &["tag:user-a".to_owned()]);
        let a1_names: Vec<_> = a1_view.iter().map(|p| p.display_name.clone()).collect();
        assert!(
            a1_names.contains(&"a2".to_owned()),
            "a1 must see a2: {a1_names:?}"
        );
        assert!(
            a1_names.contains(&"svc1".to_owned()),
            "a1 must see svc: {a1_names:?}"
        );
        assert!(
            !a1_names.contains(&"b1".to_owned()),
            "a1 must NOT see b1: {a1_names:?}"
        );
        assert!(
            !a1_names.contains(&"a1".to_owned()),
            "a1 must NOT see itself"
        );
        assert_eq!(a1_view.len(), 2, "a1 sees exactly a2 and svc");

        // ---- b1's view (symmetric): svc only (no other user-b peer). ----
        let b1_view = c.visible_peers(b1.peer_id, &["tag:user-b".to_owned()]);
        let b1_names: Vec<_> = b1_view.iter().map(|p| p.display_name.clone()).collect();
        assert!(
            b1_names.contains(&"svc1".to_owned()),
            "b1 must see svc: {b1_names:?}"
        );
        assert!(
            !b1_names.contains(&"a1".to_owned()),
            "b1 must NOT see a1: {b1_names:?}"
        );
        assert!(
            !b1_names.contains(&"a2".to_owned()),
            "b1 must NOT see a2: {b1_names:?}"
        );
        assert_eq!(b1_view.len(), 1, "b1 sees exactly svc");

        // ---- svc's view: all three users (symmetric to user-*→svc). ----
        let svc_view = c.visible_peers(svc.peer_id, &["tag:svc".to_owned()]);
        let svc_names: Vec<_> = svc_view.iter().map(|p| p.display_name.clone()).collect();
        assert!(
            svc_names.contains(&"a1".to_owned()),
            "svc sees a1: {svc_names:?}"
        );
        assert!(
            svc_names.contains(&"a2".to_owned()),
            "svc sees a2: {svc_names:?}"
        );
        assert!(
            svc_names.contains(&"b1".to_owned()),
            "svc sees b1: {svc_names:?}"
        );
        assert_eq!(svc_view.len(), 3, "svc sees all three user nodes");

        // a2 is in a DIFFERENT ULA block than b1 (multi-network allocator).
        assert_ne!(
            a2.ula.segments()[2],
            b1.ula.segments()[2],
            "user-a and user-b networks must occupy disjoint ULA blocks",
        );
    }

    /// Default-deny: with an empty policy a node sees nobody.
    #[tokio::test]
    async fn empty_policy_hides_everyone() {
        let c = coordinator_with(Policy::default());
        let (a, _) = c
            .register(req(1, "a", "a", &["tag:user-a"]))
            .await
            .expect("a");
        let _ = c
            .register(req(2, "b", "a", &["tag:user-a"]))
            .await
            .expect("b");
        let view = c.visible_peers(a.peer_id, &["tag:user-a".to_owned()]);
        assert!(
            view.is_empty(),
            "default-deny: empty policy reveals nothing"
        );
    }

    /// `peer_tags` resolves a viewer's identity from just its id.
    #[tokio::test]
    async fn peer_tags_resolves_registered_peer() {
        let c = coordinator_with(shared_service_policy());
        let (a, _) = c
            .register(req(1, "a", "a", &["tag:user-a"]))
            .await
            .expect("a");
        assert_eq!(c.peer_tags(a.peer_id), Some(vec!["tag:user-a".to_owned()]),);
        assert_eq!(c.peer_tags(Uuid::now_v7()), None);
    }

    /// `viewer_can_see` agrees with `Policy::can_see` for the shared-svc
    /// scenario.
    #[tokio::test]
    async fn viewer_can_see_matches_policy() {
        let c = coordinator_with(shared_service_policy());
        assert!(c.viewer_can_see(&["tag:user-a".to_owned()], &["tag:svc".to_owned()]));
        assert!(!c.viewer_can_see(&["tag:user-a".to_owned()], &["tag:user-b".to_owned()]));
    }
}
