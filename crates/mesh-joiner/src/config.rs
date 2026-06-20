//! Caller-facing configuration for [`crate::Joiner::join`].
//!
//! All fields are documented on the struct itself. The defaults are
//! chosen to match what `tools/tabbify-mesh` exposes through clap, so a
//! `Joiner::join(JoinConfig::default())` call against
//! `http://127.0.0.1:8888` is a usable smoke test out of the box.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

/// Caller-facing configuration for `Joiner::join`.
//
// `struct_excessive_bools`: this is a flat, caller-facing config struct;
// each bool is an independent opt-in documented on its field. Folding
// them into enums would only obscure the clap/env mapping.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone)]
pub struct JoinConfig {
    /// HTTP base URL of the mesh-coordinator (e.g.
    /// `http://127.0.0.1:8888`). Trailing slashes are tolerated.
    pub coordinator_url: String,
    /// Human-readable display name. Surfaced in the coordinator's
    /// peer list + in the `peer_joined` event.
    pub display_name: String,
    /// Role tags (e.g. `["dev-machine", "wasm-host", "test"]`). Advisory:
    /// a coordinator with join-token validation enabled (spec §8) ignores
    /// these and takes the node's authoritative tags from the validated
    /// token claims. Only honored by a coordinator running without
    /// `AUTH_URL` (the dev/E1 escape hatch).
    pub tags: Vec<String>,
    /// Node-join JWT issued by the auth service. Sent to the coordinator
    /// as `Authorization: Bearer <token>` on register (spec §8). The
    /// coordinator validates it and derives the node's authoritative
    /// `network` + `tags` from the claims. `None` (default) is the dev/E1
    /// escape hatch — only works against a coordinator started without
    /// `AUTH_URL`; a validating coordinator rejects a tokenless register
    /// with 401.
    pub join_token: Option<String>,
    /// UDP port `boringtun` listens on. `None` means use the default
    /// well-known `WireGuard` port 51820
    /// ([`crate::joiner::DEFAULT_WG_LISTEN_PORT`]), falling back to an
    /// OS-picked port if it's busy. A stable port is what makes
    /// coordinator-driven reflexive endpoint discovery work across a cone
    /// `NAT`; pin a specific port only for a manual port-forward.
    pub listen_port: Option<u16>,
    /// TUN device name preference. `None` = auto.
    ///
    /// * macOS: must start with `utun` if set (e.g. `utun7`).
    /// * Linux: any name ≤ 15 bytes; `tabbify-mesh0` is a sane
    ///   default.
    pub tun_name: Option<String>,
    /// How often to send `POST /v1/mesh/heartbeat`. Default 20s,
    /// matches the coordinator's 60s timeout with comfortable headroom.
    pub heartbeat_interval: Duration,
    /// Explicit public/reachable endpoint advertised to other peers,
    /// OVERRIDING automatic reflexive discovery. `None` (default) → the
    /// coordinator derives the reachable endpoint from the observed source
    /// IP + the WG listen port (works for public hosts + cone NAT with no
    /// config). Set explicitly only for a non-matching manual port-forward,
    /// a name-based advertisement (e.g.
    /// `Some("host.lima.internal:51820".into())` for a Lima guest reaching
    /// its macOS host), or a symmetric NAT that reflexive discovery can't
    /// solve. The joiner no longer auto-advertises its loopback / LAN bind
    /// address (that was unreachable for off-host peers).
    pub advertise_endpoint: Option<String>,
    /// Where to persist the X25519 private key so the joiner keeps a
    /// stable identity across restarts. `None` (default) → use
    /// `$HOME/.tabbify-mesh/keypair`. The file is read on every start;
    /// missing → generate + write atomically with mode 0600 on Unix.
    /// See [`crate::wg::persistent_keypair::load_or_generate`].
    pub keypair_path: Option<PathBuf>,
    /// PEM-encoded client certificate signed by the mesh CA. Sent to
    /// the coordinator as part of the TLS handshake. Required when
    /// `insecure_no_mtls == false`.
    pub tls_cert: Option<PathBuf>,
    /// PEM-encoded private key matching [`Self::tls_cert`]. Required
    /// when `insecure_no_mtls == false`.
    pub tls_key: Option<PathBuf>,
    /// PEM-encoded CA bundle the joiner trusts when validating the
    /// coordinator's server cert. Required when
    /// `insecure_no_mtls == false`. We do NOT fall back to the
    /// system trust store: the mesh CA is private to a deployment and
    /// nothing else should ever vouch for the coordinator.
    pub tls_ca: Option<PathBuf>,
    /// Escape hatch for dev / smoke-test setups against a plaintext
    /// coordinator. When `true`, all three `tls_*` fields are ignored
    /// and the joiner talks plain HTTP — must match the coordinator's
    /// `--insecure-no-mtls`, otherwise the handshake fails.
    pub insecure_no_mtls: bool,
    /// Explicit IPv6 ULA to request from the coordinator (Task 0.2
    /// per-app-runner architecture). When `Some`, the coordinator attempts
    /// to honor it; on conflict it returns 409. `None` (default) = let
    /// the coordinator derive the ULA from the peer index. Used by runner
    /// peers that pre-derive their ULA as `derive_app_ula(uuid)` so the
    /// address is known before joining.
    pub requested_ula: Option<String>,
    /// Peer role for the coordinator roster. `Some("runner")` for a
    /// per-app runner; `None` (default) = plain supervisor / joiner peer.
    /// Omitted from the wire when `None` for backward compat with
    /// coordinators that predate Task 0.1.
    pub kind: Option<String>,
    /// ULA of the supervisor that owns this runner. `None` (default) for
    /// plain peers. Set by runner peers so `tabbify-node` can build the
    /// supervisor → runners topology tree. Omitted from the wire when `None`.
    pub parent: Option<String>,
    /// UUID of the app this runner serves. `None` (default) for plain
    /// peers. Omitted from the wire when `None`.
    pub app_uuid: Option<String>,
    /// Path to the persistent identity file `{private_key, ula}` (Task 0.4).
    /// When `Some` and the file exists, the joiner reuses the persisted
    /// keypair and re-requests the same ULA (`requested_ula` is set
    /// automatically — do not set both). When the file is absent the joiner
    /// joins fresh, then persists `{keypair, assigned_ula}` to this path.
    /// `None` (default) — no identity persistence, each restart gets a fresh
    /// identity; backward-compatible with all existing callers. Runners that
    /// derive their ULA deterministically from `app_uuid` (via
    /// `derive_app_ula`) should leave this `None` and set `requested_ula`
    /// directly instead.
    pub identity_path: Option<PathBuf>,
    /// Software version of THIS host's binary (e.g. `"v1.4.0"`), supplied by
    /// the caller (supervisor). Sent on register + every heartbeat as
    /// `software_version` so the control plane sees `actual` version drift
    /// toward `desired` (spec P0 OBSERVE). `None` (default) — the joiner
    /// never invents a value; an omitting host stays back-compatible.
    pub software_version: Option<String>,
    /// Whether to open the Stage-3 DERP-style relay client (the
    /// connectivity floor). `true` (default) — the joiner keeps a
    /// persistent WebSocket to the coordinator's `/v1/mesh/relay` endpoint
    /// and relays WG packets to peers it has no direct path to. Set `false`
    /// (`--no-relay`) to opt out and rely solely on direct + hole-punch.
    pub relay_enabled: bool,
    /// Explicit relay endpoint URL, OVERRIDING the default derivation from
    /// `coordinator_url`. `None` (default) — derive
    /// `ws(s)://{host}/v1/mesh/relay` from [`Self::coordinator_url`]. Set
    /// only when the relay lives at a non-default location.
    pub relay_url: Option<String>,
    /// Declare this peer **relay-only**: it has NO reachable direct endpoint
    /// (e.g. it runs in a container netns with no inbound mesh port, reachable
    /// ONLY via its outbound DERP relay connection). `false` (default) — the
    /// peer participates in direct + hole-punch traversal as usual.
    ///
    /// When `true`, the coordinator (a) never synthesizes a reflexive listen
    /// endpoint for this peer (it advertises no direct dial target), and (b)
    /// never emits a hole-punch directive for ANY pair involving this peer.
    /// With no punch directive, neither side double-inits a `WireGuard`
    /// handshake at an unreachable direct endpoint, so the handshake becomes
    /// single-sided (whoever has data initiates, the other responds) and
    /// completes cleanly over the relay — eliminating the simultaneous-init
    /// thrash that otherwise stalls a relay-only ↔ NAT'd pair.
    pub relay_only: bool,
    /// Install this joiner's peer `/128` routes into a PRIVATE,
    /// source-scoped routing table instead of `main` (Linux policy
    /// routing). For hosts that run MORE THAN ONE joiner in a single
    /// network namespace (a supervisor + its per-app runners): every
    /// joiner tries to install the same peer `/128`s into `main`, the
    /// kernel keeps only the first (`File exists` is swallowed as
    /// idempotent), and the loser's RETURN traffic egresses through the
    /// WRONG TUN — the remote peer then drops it against the per-session
    /// source allowed-set (spec §5.5). With this flag the joiner derives
    /// a per-instance table from its own ULA, routes its peers there, and
    /// installs one `ip -6 rule from <own_ula> lookup <table>` so its
    /// egress always uses its OWN TUN regardless of what `main` says —
    /// the lightweight equivalent of "≤1 joiner per netns". `false`
    /// (default): plain `main`-table routes (single joiner per netns —
    /// the common case). Linux-only; falls back to `main` elsewhere.
    pub source_scoped_routes: bool,
    /// Self-manage host-firewall trust for the overlay TUN, the way
    /// tailscaled does: keep an `INPUT -i <tun> -j ACCEPT` rule for THIS
    /// joiner's TUN device (asserted at bring-up, re-asserted
    /// periodically so a firewall reload cannot strand it, removed on
    /// [`leave`](crate::Joiner::leave)). Without it, distro default
    /// firewalls (e.g. NixOS `nixos-fw`) DROP decrypted overlay packets
    /// arriving inbound on the TUN, so app listeners never even see the
    /// SYN. The overlay is the trust boundary: packets only reach the
    /// TUN after `WireGuard` authenticated the sender, and RX enforces
    /// the per-peer source allowed-set (spec §5.5). Best-effort: a
    /// missing or unprivileged `ip6tables` logs a warning and NEVER
    /// fails the join (containers). `false` (default): firewall
    /// untouched.
    pub manage_firewall: bool,
    /// Optional STUN server to discover this node's `WireGuard` UDP mapping from
    /// the WG socket itself (Track A-a), correcting the symmetric-NAT port
    /// nuance the coordinator's TCP-observed reflexive guess cannot.
    ///
    /// When `Some`, the joiner issues a STUN binding request over its WG socket
    /// and advertises the discovered `ip:port` (overriding reflexive discovery).
    /// `None` (default) — today's coordinator-reflexive behaviour, unchanged.
    /// NOTE: this only ever affects the ADVERTISED endpoint; `relay_enabled`
    /// stays the floor, so a failed direct path always falls back to relay.
    pub stun_server: Option<SocketAddr>,
}

impl Default for JoinConfig {
    fn default() -> Self {
        Self {
            coordinator_url: "http://127.0.0.1:8888".to_owned(),
            display_name: "tabbify-mesh-joiner".to_owned(),
            tags: vec![],
            join_token: None,
            listen_port: None,
            tun_name: None,
            heartbeat_interval: Duration::from_secs(20),
            advertise_endpoint: None,
            keypair_path: None,
            tls_cert: None,
            tls_key: None,
            tls_ca: None,
            // Defaults to insecure for backward compat: existing smoke
            // tests + the historical `http://127.0.0.1:8888` URL above
            // both speak plaintext. CLI / operator opt in by clearing
            // this flag and supplying the three cert paths.
            insecure_no_mtls: true,
            requested_ula: None,
            kind: None,
            parent: None,
            app_uuid: None,
            identity_path: None,
            software_version: None,
            // Relay (Stage-3 connectivity floor) is ON by default: the
            // joiner should always have a path to every peer it can see,
            // even behind a hard NAT. Opt out via `--no-relay`.
            relay_enabled: true,
            relay_url: None,
            // A peer is reachable directly by default; only a host that KNOWS
            // it has no inbound mesh port (e.g. a container netns) opts into
            // relay-only so the coordinator suppresses its direct endpoint +
            // hole-punch directives.
            relay_only: false,
            // Both host-integration behaviors are OPT-IN: a plain peer is
            // the only joiner in its netns (no route collision to scope
            // away) and may live in a container without ip6tables / with a
            // host-shared netns where touching the firewall is wrong
            // (tabbify-node). Hosts that run multiple joiners per netns
            // (supervisor + runners) flip both.
            source_scoped_routes: false,
            manage_firewall: false,
            // No STUN by default: keep today's coordinator-reflexive advertise
            // behaviour. An operator opts in via `--mesh-stun-server` for a
            // symmetric-NAT-correct WG mapping. Relay stays the floor regardless.
            stun_server: None,
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    /// The defaults must round-trip through Clone without surprising
    /// the caller — guards against accidentally changing the default
    /// of `heartbeat_interval` to something silly like 0s.
    #[test]
    fn defaults_are_sane() {
        let cfg = JoinConfig::default();
        assert_eq!(cfg.coordinator_url, "http://127.0.0.1:8888");
        assert_eq!(cfg.heartbeat_interval, Duration::from_secs(20));
        assert!(cfg.tags.is_empty());
        assert!(cfg.listen_port.is_none());
        assert!(cfg.tun_name.is_none());
        // Relay is the connectivity floor — it must default ON so every
        // peer is reachable even when direct + hole-punch fail.
        assert!(cfg.relay_enabled, "relay must default on");
        assert!(cfg.relay_url.is_none());
        // Host-integration behaviors are opt-in: a plain peer must not
        // touch policy routing or the host firewall.
        assert!(
            !cfg.source_scoped_routes,
            "source-scoped routes must default off"
        );
        assert!(
            !cfg.manage_firewall,
            "firewall self-management must default off"
        );
    }

    #[test]
    fn clone_preserves_all_fields() {
        let cfg = JoinConfig {
            coordinator_url: "http://10.0.0.1:9000".into(),
            display_name: "alice".into(),
            tags: vec!["dev".into()],
            join_token: Some("join-jwt".into()),
            listen_port: Some(51820),
            tun_name: Some("utun7".into()),
            heartbeat_interval: Duration::from_secs(15),
            advertise_endpoint: Some("198.51.100.7:51820".into()),
            keypair_path: Some(PathBuf::from("/tmp/kp")),
            tls_cert: Some(PathBuf::from("/tmp/cert.pem")),
            tls_key: Some(PathBuf::from("/tmp/key.pem")),
            tls_ca: Some(PathBuf::from("/tmp/ca.pem")),
            insecure_no_mtls: false,
            requested_ula: Some("fd5a:1f02:aabb::1".into()),
            kind: Some("runner".into()),
            parent: Some("fd5a:1f00:1::1".into()),
            app_uuid: Some("01910f10-0000-7000-8000-000000000099".into()),
            identity_path: Some(PathBuf::from("/tmp/id.json")),
            software_version: Some("v1.4.0".into()),
            relay_enabled: false,
            relay_url: Some("ws://10.0.0.1:9000/v1/mesh/relay".into()),
            relay_only: true,
            source_scoped_routes: true,
            manage_firewall: true,
            stun_server: Some("203.0.113.1:3478".parse().unwrap()),
        };
        let cloned = cfg.clone();
        assert_eq!(cloned.coordinator_url, cfg.coordinator_url);
        assert_eq!(cloned.tun_name, cfg.tun_name);
        assert_eq!(cloned.heartbeat_interval, cfg.heartbeat_interval);
        assert_eq!(cloned.advertise_endpoint, cfg.advertise_endpoint);
        assert_eq!(cloned.keypair_path, cfg.keypair_path);
        assert_eq!(cloned.join_token, cfg.join_token);
        assert_eq!(cloned.tls_cert, cfg.tls_cert);
        assert_eq!(cloned.tls_key, cfg.tls_key);
        assert_eq!(cloned.tls_ca, cfg.tls_ca);
        assert_eq!(cloned.insecure_no_mtls, cfg.insecure_no_mtls);
        assert_eq!(cloned.requested_ula, cfg.requested_ula);
        assert_eq!(cloned.kind, cfg.kind);
        assert_eq!(cloned.parent, cfg.parent);
        assert_eq!(cloned.app_uuid, cfg.app_uuid);
        assert_eq!(cloned.identity_path, cfg.identity_path);
        assert_eq!(cloned.software_version, cfg.software_version);
        assert_eq!(cloned.relay_enabled, cfg.relay_enabled);
        assert_eq!(cloned.relay_url, cfg.relay_url);
        assert_eq!(cloned.relay_only, cfg.relay_only);
        assert_eq!(cloned.source_scoped_routes, cfg.source_scoped_routes);
        assert_eq!(cloned.manage_firewall, cfg.manage_firewall);
        assert_eq!(cloned.stun_server, cfg.stun_server);
    }

    /// A-a: the optional STUN server (for symmetric-NAT-correct reflexive
    /// discovery from the WG socket) defaults to None (today's behaviour) and
    /// round-trips through Clone. Relay stays the floor regardless — a STUN
    /// mapping is an ADVERTISE input, never a relay opt-out.
    #[test]
    fn stun_server_default_is_none_and_clones() {
        let cfg = JoinConfig::default();
        assert!(cfg.stun_server.is_none(), "no STUN server by default");
        assert!(cfg.relay_enabled, "relay stays the floor with or without STUN");
        let cfg2 = JoinConfig {
            stun_server: Some("203.0.113.1:3478".parse().unwrap()),
            ..JoinConfig::default()
        };
        let cloned = cfg2.clone();
        assert_eq!(cloned.stun_server, cfg2.stun_server);
        assert!(cloned.relay_enabled, "relay floor preserved through clone");
    }

    /// `relay_only` defaults OFF (a peer is directly reachable unless it
    /// declares otherwise) and round-trips through Clone.
    #[test]
    fn relay_only_default_is_false_and_clones() {
        let cfg = JoinConfig::default();
        assert!(!cfg.relay_only, "relay_only must default off");
        let cfg2 = JoinConfig {
            relay_only: true,
            ..JoinConfig::default()
        };
        let cloned = cfg2.clone();
        assert!(cfg2.relay_only);
        assert!(cloned.relay_only);
    }

    /// SV-2: the host-supplied `software_version` round-trips through clone
    /// and defaults to `None` (joiner never invents a value).
    #[test]
    fn software_version_default_is_none_and_clones() {
        let cfg = JoinConfig::default();
        assert_eq!(cfg.software_version, None);
        let cfg2 = JoinConfig {
            software_version: Some("v1.4.0".to_owned()),
            ..JoinConfig::default()
        };
        let cloned = cfg2.clone();
        assert_eq!(cfg2.software_version, Some("v1.4.0".to_owned()));
        assert_eq!(cloned.software_version, Some("v1.4.0".to_owned()));
    }
}
