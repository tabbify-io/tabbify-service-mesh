//! The `POST /v1/tokens/join` request body — the ONE wire definition shared by
//! the auth service (deserializes) and the node (serializes).
//!
//! Field ORDER and skip rules are load-bearing: the node has always emitted
//! `{network, tags, role?, serve, subject, name?, ttl}` and never the
//! admin-only fields, so `system` / `kind` / `requested_ulas` are skipped at
//! their defaults and declared last. The `wire` tests below pin the exact
//! bytes; do not reorder fields or change a skip without treating it as a wire
//! migration.

use serde::{Deserialize, Serialize};

/// Join-token issuance request body (`POST /v1/tokens/join`).
///
/// Auth is the authoritative consumer; the node builds this struct for its
/// runner-mint and push-token-mint calls instead of keeping a local mirror.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct JoinRequest {
    /// Mesh network (goes into claims, authoritative).
    #[cfg_attr(feature = "openapi", schema(example = "alice"))]
    pub network: String,
    /// Tags (go into claims, authoritative). Empty by default. ALWAYS
    /// serialized — the push-token mint sends `"tags": []` on the wire.
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(example = json!(["tag:user-alice"])))]
    pub tags: Vec<String>,
    /// Token role. `"runner"` mints a per-app runner token (Approach A): the
    /// `subject` MUST be the app uuid; auth stamps the AUTHORITATIVE
    /// `tag:app-<subject>` and STRIPS any requested `tag:net-<slug>` so the
    /// app is not reachable via the network/deploy grant. `"supervisor"`
    /// stamps the deploy tag. Omitted ⇒ an ordinary join.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(example = "runner"))]
    pub role: Option<String>,
    /// Node-served runner (Approach A). `true` requests the explicit serving
    /// grant `tag:proxy → tag:app-<subject>` at enrollment, so the control
    /// node can reach this runner over the mesh WITHOUT the network being
    /// make-public (what a WORKSPACE mint sets). Mesh-reachability only —
    /// public HTTP exposure remains a separate node proxy-route + auth
    /// decision.
    #[serde(default)]
    pub serve: bool,
    /// Node label (subject). If omitted, the network name is used. For a
    /// `role=runner` mint this MUST be the app uuid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(example = "laptop"))]
    pub subject: Option<String>,
    /// Human container name for the apps registry (0026). REQUIRED for
    /// `kind=devbox`; for other kinds auth derives a fallback when omitted.
    /// Only meaningful for a `role=runner` mint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(example = "my-scratch-box"))]
    pub name: Option<String>,
    /// TTL in seconds. If omitted, the service default (`join_ttl_secs`) is
    /// used. Ignored for `system` mints.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(example = 600_i64))]
    pub ttl: Option<i64>,
    /// Mint an UNLIMITED system/infra token (admin only). When true, `ttl` is
    /// ignored and a far-future (~100y) expiry is used. Tenant tokens never
    /// set this. Off the wire at its default — the node never sends it.
    #[serde(default, skip_serializing_if = "is_false")]
    pub system: bool,
    /// Container kind for the named-typed apps registry (0026): one of
    /// [`crate::CONTAINER_KINDS`]. Only meaningful for a `role=runner` mint;
    /// when omitted auth INFERS the kind from `serve` for back-compat.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(example = "devbox"))]
    pub kind: Option<String>,
    /// Fixed infrastructure ULA this token may request — at most ONE address
    /// (decision 0008: one token per service, one address). Admin system mint
    /// only; never allowed on `role=runner` tokens.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requested_ulas: Vec<String>,
}

/// Serde skip helper: keep `system` off the wire at its default so the node's
/// emitted bytes stay identical to the historical hand-written mirror.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_false(value: &bool) -> bool {
    !*value
}

#[cfg(test)]
mod wire {
    use super::*;

    const APP: &str = "0191e7c2-1111-7222-8333-444455556666";

    fn runner_mint() -> JoinRequest {
        JoinRequest {
            network: "n_jpegxik72nng".into(),
            tags: vec!["runner".into()],
            role: Some("runner".into()),
            serve: false,
            subject: Some(APP.into()),
            name: None,
            ttl: Some(31_536_000),
            system: false,
            kind: None,
            requested_ulas: vec![],
        }
    }

    /// The node's runner mint must serialize to EXACTLY the bytes its
    /// hand-written mirror produced: `{network, tags, role, serve, subject,
    /// ttl}` — no admin-only fields, this field order.
    #[test]
    fn runner_mint_bytes_match_the_historical_node_shape() {
        assert_eq!(
            serde_json::to_string(&runner_mint()).unwrap(),
            r#"{"network":"n_jpegxik72nng","tags":["runner"],"role":"runner","serve":false,"subject":"0191e7c2-1111-7222-8333-444455556666","ttl":31536000}"#
        );
    }

    /// A named, node-served mint (the `deploy` tool path) rides `name` between
    /// `subject` and `ttl`, exactly where the old mirror declared it.
    #[test]
    fn named_serving_mint_bytes_place_name_before_ttl() {
        let req = JoinRequest {
            serve: true,
            name: Some("my-cool-app".into()),
            ..runner_mint()
        };
        assert_eq!(
            serde_json::to_string(&req).unwrap(),
            r#"{"network":"n_jpegxik72nng","tags":["runner"],"role":"runner","serve":true,"subject":"0191e7c2-1111-7222-8333-444455556666","name":"my-cool-app","ttl":31536000}"#
        );
    }

    /// The push-token mint omits `role`/`name` but still sends `tags: []` and
    /// `serve: false` explicitly — the historical bytes, unchanged.
    #[test]
    fn push_mint_bytes_omit_role_and_name() {
        let req = JoinRequest {
            tags: vec![],
            role: None,
            ttl: Some(7200),
            ..runner_mint()
        };
        assert_eq!(
            serde_json::to_string(&req).unwrap(),
            r#"{"network":"n_jpegxik72nng","tags":[],"serve":false,"subject":"0191e7c2-1111-7222-8333-444455556666","ttl":7200}"#
        );
    }

    /// Admin-only fields appear on the wire only when actually set.
    #[test]
    fn admin_only_fields_serialize_when_set() {
        let req = JoinRequest {
            network: "system".into(),
            tags: vec![],
            role: None,
            serve: false,
            subject: Some("registry".into()),
            name: None,
            ttl: None,
            system: true,
            kind: Some("devbox".into()),
            requested_ulas: vec!["fd5a:1f00:0:3::1".into()],
        };
        assert_eq!(
            serde_json::to_string(&req).unwrap(),
            r#"{"network":"system","tags":[],"serve":false,"subject":"registry","system":true,"kind":"devbox","requested_ulas":["fd5a:1f00:0:3::1"]}"#
        );
    }

    #[test]
    fn round_trips_through_json() {
        for req in [
            runner_mint(),
            JoinRequest {
                system: true,
                kind: Some("workspace".into()),
                requested_ulas: vec!["fd5a:1f00:fffe::1".into()],
                ..runner_mint()
            },
        ] {
            let json = serde_json::to_string(&req).unwrap();
            let back: JoinRequest = serde_json::from_str(&json).unwrap();
            assert_eq!(back, req);
        }
    }

    /// Auth-side compatibility: a minimal admin body deserializes with every
    /// optional field at its documented default.
    #[test]
    fn deserializes_a_minimal_body_with_defaults() {
        let req: JoinRequest = serde_json::from_str(r#"{"network":"netx"}"#).unwrap();
        assert_eq!(
            req,
            JoinRequest {
                network: "netx".into(),
                tags: vec![],
                role: None,
                serve: false,
                subject: None,
                name: None,
                ttl: None,
                system: false,
                kind: None,
                requested_ulas: vec![],
            }
        );
    }

    /// Unknown fields stay tolerated (no `deny_unknown_fields`) — older/newer
    /// clients must not be rejected for extra keys.
    #[test]
    fn tolerates_unknown_fields() {
        let req: JoinRequest =
            serde_json::from_str(r#"{"network":"n","future_field":true}"#).unwrap();
        assert_eq!(req.network, "n");
    }
}
