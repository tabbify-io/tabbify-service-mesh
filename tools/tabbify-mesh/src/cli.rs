//! `clap` definitions for the `tabbify-mesh` binary.

use std::net::{Ipv6Addr, SocketAddr};
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

/// Default coordinator URL (zero-config fallback).
///
/// Used when neither `--coordinator` nor `TABBIFY_MESH_COORDINATOR` are set.
/// The production EIP is baked in so `tabbify-mesh join --name X` is enough.
/// Override with `--coordinator http://127.0.0.1:8888` for a local smoke run.
pub const DEFAULT_COORDINATOR_URL: &str = "http://3.124.69.92:8888";

fn parse_ula(value: &str) -> Result<Ipv6Addr, String> {
    let address = value
        .parse::<Ipv6Addr>()
        .map_err(|error| format!("invalid IPv6 ULA: {error}"))?;
    if address.segments()[0] & 0xfe00 != 0xfc00 {
        return Err("requested address must be an IPv6 ULA (fc00::/7)".to_owned());
    }
    Ok(address)
}

/// `tabbify-mesh` — overlay-mesh peer CLI.
#[derive(Debug, Parser)]
#[command(name = "tabbify-mesh", version, about = "Overlay mesh peer CLI")]
pub struct Cli {
    /// Subcommand to dispatch.
    #[command(subcommand)]
    pub cmd: Cmd,
}

/// Top-level subcommands.
#[derive(Debug, Subcommand)]
pub enum Cmd {
    /// Join the mesh and run as a foreground daemon until Ctrl-C.
    /// Boxed: `JoinArgs` is much larger than the other variants, so
    /// boxing it keeps `Cmd` small (clippy `large_enum_variant`).
    Join(Box<JoinArgs>),
    /// Print a local status snapshot written by a running `join` daemon.
    Status,
    /// List peers currently registered with the coordinator.
    Peers(PeersArgs),
    /// Deregister from the coordinator and exit cleanly.
    Leave(LeaveArgs),
}

/// Arguments for the `join` subcommand.
//
// `struct_excessive_bools`: flat clap surface; every bool is an
// independent opt-in flag mirroring a `JoinConfig` field.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Args, Clone)]
pub struct JoinArgs {
    /// Coordinator base URL.
    #[arg(
        long,
        env = "TABBIFY_MESH_COORDINATOR",
        default_value = DEFAULT_COORDINATOR_URL,
    )]
    pub coordinator: String,

    /// Display name advertised to other peers.
    #[arg(long)]
    pub name: String,

    /// Free-form tag. Repeat `--tag` to add multiple tags. Advisory: a
    /// coordinator with join-token validation enabled (`AUTH_URL` set)
    /// ignores these and uses the authoritative tags from the validated
    /// `--join-token` claims. Only honored against a coordinator running
    /// without `AUTH_URL` (the dev/E1 escape hatch).
    #[arg(long = "tag")]
    pub tags: Vec<String>,

    /// Node-join JWT issued by the auth service. Sent to the coordinator
    /// as `Authorization: Bearer <token>` on register (spec §8); the
    /// coordinator validates it and derives this node's authoritative
    /// `network` + `tags` from the token claims. Required by any
    /// coordinator started with `AUTH_URL`; omit only for a local smoke
    /// run against a coordinator with no validation configured.
    #[arg(long, env = "MESH_JOIN_TOKEN")]
    pub join_token: Option<String>,

    /// Fixed `WireGuard` UDP listen port. Defaults to 51820 (the
    /// well-known `WireGuard` port) when unset — a STABLE, PREDICTABLE port
    /// is what makes automatic reflexive endpoint discovery work across a
    /// cone `NAT` (the coordinator advertises `<your-public-ip>:<this-port>`
    /// to peers, and a port-preserving `NAT` maps the same port). If 51820
    /// is already in use the joiner falls back to an OS-picked port. Set
    /// this explicitly only when you port-forward a specific UDP port.
    ///
    /// CO-RESIDENCE (FIX 8): when TWO joiners run on ONE host (e.g. the
    /// supervisor in-process joiner on 51820 + the standalone LIFELINE joiner),
    /// the lifeline MUST be given its OWN port (e.g. `--listen-port 51821`).
    /// `SO_REUSEPORT` makes a same-port bind succeed but then load-balances
    /// inbound UDP across both sockets, so co-resident joiners on the same port
    /// would steal each other's frames — distinct ports keep them isolated.
    #[arg(long)]
    pub listen_port: Option<u16>,

    /// Optional fixed TUN interface name (e.g. `utun5`).
    #[arg(long)]
    pub tun_name: Option<String>,

    /// Path to a persistent IDENTITY file (keypair + sticky ULA in one JSON,
    /// see [`tabbify_mesh_joiner`]'s `persistent_identity`). When set, this
    /// standalone joiner hosts a STICKY identity: it reuses the same keypair AND
    /// re-requests the same mesh ULA across restarts — what a long-lived
    /// lifeline joiner needs so its address is stable. Takes PRECEDENCE over the
    /// keypair-only default: when `--identity-path` is given the joiner ignores
    /// the `$HOME/.tabbify-mesh/keypair` fallback entirely.
    #[arg(long)]
    pub identity_path: Option<PathBuf>,

    /// Claim this exact ULA. Conflicts fail closed and never fall back to an
    /// allocator-assigned address. Fixed infrastructure addresses require the
    /// exact address in the validated join token's signed capability.
    #[arg(long, env = "MESH_REQUESTED_ULA", value_parser = parse_ula)]
    pub requested_ula: Option<Ipv6Addr>,

    /// Super-admin Ed25519 pubkey as 64-char hex (Track C). When set, this
    /// standalone joiner becomes a signed-remote-command TARGET: it verifies
    /// every command against this key end-to-end and, on an accepted verb,
    /// drives a host effect (`systemctl restart tabbify-supervisor` for
    /// `RestartJoiner`, a guarded `systemctl reboot` ≤3/hr for `RebootHost`).
    /// This is exactly what makes the redundant lifeline joiner the recovery
    /// lever when the in-process supervisor joiner is wedged. Unset / empty /
    /// malformed ⇒ remote commands stay FAIL-CLOSED (every command rejected).
    #[arg(long, env = "TABBIFY_MESH_SUPER_ADMIN_PUBKEY")]
    pub super_admin_pubkey: Option<String>,

    /// Heartbeat interval (seconds).
    #[arg(long, default_value_t = 20)]
    pub heartbeat_interval: u64,

    /// Explicit public/reachable endpoint to advertise to other peers,
    /// OVERRIDING automatic reflexive discovery.
    ///
    /// Normally you do NOT need this: the coordinator derives your
    /// reachable endpoint from the source IP it observes plus your
    /// `--listen-port`, which works for public hosts and common (cone /
    /// port-preserving) `NAT`s with zero configuration. Set it only for a
    /// manual port-forward to a NON-matching external port (e.g. external
    /// `:51999` to internal `:51820`), for a name-based advertisement (e.g.
    /// `--advertise-endpoint host.lima.internal:51820` for a Lima guest
    /// reaching its macOS host), or for a symmetric / port-randomizing
    /// `NAT` that reflexive discovery cannot solve (which otherwise needs a
    /// relay — see the Stage-3 follow-up).
    #[arg(long)]
    pub advertise_endpoint: Option<String>,

    /// PEM-encoded client certificate signed by the mesh CA. Required
    /// when talking to a TLS-protected coordinator (default). Pair with
    /// `--tls-key` and `--tls-ca`. Ignored when `--insecure-no-mtls`
    /// is set.
    #[arg(long)]
    pub tls_cert: Option<PathBuf>,

    /// PEM-encoded private key matching `--tls-cert`. Required when
    /// talking to a TLS-protected coordinator.
    #[arg(long)]
    pub tls_key: Option<PathBuf>,

    /// PEM-encoded CA bundle the joiner trusts for the coordinator's
    /// server cert. This is the ONLY root the joiner will validate
    /// against — system / webpki roots are NOT consulted, so a
    /// misconfigured public CA can't MITM the mesh control plane.
    #[arg(long)]
    pub tls_ca: Option<PathBuf>,

    /// Skip mTLS entirely. Use ONLY for local smoke tests against a
    /// coordinator launched with the matching `--insecure-no-mtls`
    /// flag. Production deployments must leave this off and supply
    /// the three `--tls-*` paths.
    #[arg(long)]
    pub insecure_no_mtls: bool,

    /// Opt OUT of the Stage-3 relay (the connectivity floor). By default
    /// the joiner keeps a persistent relay connection to the coordinator
    /// and forwards WG packets through it to any peer it has no direct
    /// path to — so connectivity works even behind a hard NAT. Pass
    /// `--no-relay` to disable that and rely solely on direct +
    /// hole-punch.
    #[arg(long)]
    pub no_relay: bool,

    /// Explicit relay endpoint URL(s), OVERRIDING the default derivation from
    /// `--coordinator`. REPEATABLE for HA-relay failover (primary first):
    /// `--relay-url wss://a/v1/mesh/relay --relay-url wss://b/v1/mesh/relay`.
    /// The `TABBIFY_MESH_RELAY_URL` env stays a SINGLE var but accepts a
    /// COMMA-separated list (`value_delimiter = ','`) so a systemd/compose
    /// drop-in ships the failover list with no new env var — the prod rollout
    /// lever. Normally unset: the joiner derives
    /// `ws(s)://<coordinator-host>/v1/mesh/relay`. A single value is
    /// byte-identical to today (one-element list ⇒ failover dormant).
    #[arg(
        long = "relay-url",
        env = "TABBIFY_MESH_RELAY_URL",
        value_delimiter = ','
    )]
    pub relay_url: Vec<String>,

    /// Declare this peer RELAY-ONLY: it has no reachable direct endpoint
    /// (e.g. it runs in a container netns with no inbound mesh port). The
    /// coordinator then advertises no direct endpoint for it and never makes
    /// it a hole-punch target, so a relay-only ↔ NAT'd `WireGuard` handshake
    /// completes over the relay without simultaneous-init thrash. Off by
    /// default — a normal peer participates in direct + hole-punch.
    #[arg(long, env = "TABBIFY_MESH_RELAY_ONLY")]
    pub relay_only: bool,

    /// Install this joiner's peer routes into a private SOURCE-SCOPED
    /// routing table (`ip -6 rule from <own-ula> lookup <table>`) instead
    /// of `main`. For hosts that run multiple joiners in ONE network
    /// namespace (a supervisor + per-app runners), so each joiner's
    /// egress always uses its OWN TUN. Linux-only.
    #[arg(long, env = "TABBIFY_MESH_SOURCE_SCOPED_ROUTES")]
    pub source_scoped_routes: bool,

    /// Self-manage the host firewall (tailscaled-style): keep an
    /// `INPUT -i <tun> -j ACCEPT` rule for this joiner's TUN device
    /// (asserted at bring-up, re-asserted periodically, removed on exit)
    /// so distro default firewalls don't drop inbound overlay
    /// connections. Best-effort: missing ip6tables only warns.
    #[arg(long, env = "TABBIFY_MESH_MANAGE_FIREWALL")]
    pub manage_firewall: bool,

    /// Routing metric every peer `/128` this joiner installs is given
    /// (Linux). Defaults to the kernel's own implicit IPv6 default
    /// (1024), so the PRIMARY/data-plane joiner's routes are byte-for-byte
    /// unchanged.
    ///
    /// Raise it for a SECONDARY joiner that shares one network namespace
    /// with the primary in `main`-table mode — the crash-survival LIFELINE
    /// (e.g. `--route-metric 4096`). Both joiners install the same peer
    /// `/128`s; at an EQUAL metric the kernel keeps only one per prefix
    /// (last-writer race) and the secondary can steal the primary's route,
    /// sending that peer's return traffic out the WRONG WG session →
    /// dropped. A worse (higher) metric makes the two routes distinct, so
    /// the kernel prefers the lower-metric primary while its TUN is up and
    /// only falls back to the secondary's routes when the primary is gone.
    #[arg(long, env = "TABBIFY_MESH_ROUTE_METRIC", default_value_t = tabbify_mesh_joiner::platform::DEFAULT_ROUTE_METRIC)]
    pub route_metric: u32,

    /// Optional STUN server (`ip:port`) used to discover this node's
    /// `WireGuard` UDP mapping FROM the WG socket itself (Track A-a), correcting
    /// the symmetric-NAT port nuance the coordinator's TCP-observed reflexive
    /// guess cannot. When set, the joiner advertises the STUN-discovered
    /// `ip:port` (overriding reflexive discovery). Unset (default) keeps today's
    /// coordinator-reflexive behaviour. Relay always stays the floor regardless.
    #[arg(long, env = "TABBIFY_MESH_STUN_SERVER")]
    pub mesh_stun_server: Option<SocketAddr>,

    /// Path where, on a SUCCESSFUL join, this joiner atomically records its own
    /// identity as `{ "peer_id", "ula", "name" }` JSON. The supervisor's
    /// lifeline systemd unit points this at `<dataDir>/data/lifeline-status.json`
    /// so that — after a supervisord crash wedges the in-process joiner — an
    /// operator can read the standalone lifeline's node-id from this file and
    /// address a Track-C signed restart command to it. Unset (default) ⇒ no
    /// such file is written. This is SEPARATE from the running-daemon status
    /// snapshot in `~/.tabbify-mesh/status.json`.
    #[arg(long)]
    pub status_file: Option<PathBuf>,
}

/// Arguments for the `peers` subcommand.
#[derive(Debug, Args, Clone)]
pub struct PeersArgs {
    /// Coordinator base URL.
    #[arg(
        long,
        env = "TABBIFY_MESH_COORDINATOR",
        default_value = DEFAULT_COORDINATOR_URL,
    )]
    pub coordinator: String,

    /// Coordinator admin token. `GET /v1/mesh/peers` returns the roster
    /// across every tenant, so it is admin-gated: the request is sent as
    /// `Authorization: Bearer <token>` and the coordinator answers `401`
    /// without it. This is the operator's `MESH_ADMIN_TOKEN`.
    #[arg(long, env = "MESH_ADMIN_TOKEN")]
    pub admin_token: Option<String>,
}

/// Arguments for the `leave` subcommand.
#[derive(Debug, Args, Clone)]
pub struct LeaveArgs {
    /// Explicit peer id. Defaults to the value found in the local
    /// status file.
    #[arg(long)]
    pub peer_id: Option<uuid::Uuid>,

    /// Coordinator base URL. Defaults to the value found in the local
    /// status file, or to `TABBIFY_MESH_COORDINATOR` /
    /// `http://127.0.0.1:8888`.
    #[arg(long, env = "TABBIFY_MESH_COORDINATOR")]
    pub coordinator: Option<String>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Parse a `join` invocation through the real top-level [`Cli`] (the actual
    /// entrypoint) and return the inner [`JoinArgs`]. `argv` is the args AFTER
    /// the binary name (e.g. `["join", "--name", "x", …]`).
    fn parse_join(argv: &[&str]) -> JoinArgs {
        let mut full = vec!["tabbify-mesh"];
        full.extend_from_slice(argv);
        match Cli::parse_from(full).cmd {
            Cmd::Join(join_args) => *join_args,
            other => panic!("expected Cmd::Join, got {other:?}"),
        }
    }

    /// `--identity-path` parses into `JoinArgs::identity_path`.
    #[test]
    fn join_parses_identity_path() {
        let args = parse_join(&[
            "join",
            "--coordinator",
            "http://u",
            "--name",
            "lifeline",
            "--identity-path",
            "/x/id.json",
        ]);
        assert_eq!(
            args.identity_path,
            Some(PathBuf::from("/x/id.json")),
            "--identity-path must populate JoinArgs::identity_path"
        );
    }

    /// Omitting `--identity-path` leaves it `None` (the keypair-only default).
    #[test]
    fn join_identity_path_defaults_none() {
        let args = parse_join(&["join", "--coordinator", "http://u", "--name", "x"]);
        assert_eq!(args.identity_path, None);
    }

    #[test]
    fn join_parses_requested_ula() {
        let args = parse_join(&[
            "join",
            "--coordinator",
            "http://u",
            "--name",
            "store-control",
            "--requested-ula",
            "fd5a:1f00:fffe::1",
        ]);
        assert_eq!(
            args.requested_ula.map(|ula| ula.to_string()).as_deref(),
            Some("fd5a:1f00:fffe::1")
        );
    }

    #[test]
    fn join_rejects_non_ula_requested_address() {
        let parsed = Cli::try_parse_from([
            "tabbify-mesh",
            "join",
            "--name",
            "store-control",
            "--requested-ula",
            "2001:db8::1",
        ]);
        assert!(parsed.is_err());
    }

    /// `--super-admin-pubkey <hex>` parses into `JoinArgs::super_admin_pubkey`.
    #[test]
    fn join_parses_super_admin_pubkey() {
        let hex = "aa".repeat(32);
        let args = parse_join(&[
            "join",
            "--coordinator",
            "http://u",
            "--name",
            "lifeline",
            "--super-admin-pubkey",
            &hex,
        ]);
        assert_eq!(
            args.super_admin_pubkey.as_deref(),
            Some(hex.as_str()),
            "--super-admin-pubkey must populate JoinArgs::super_admin_pubkey"
        );
    }

    /// Omitting `--super-admin-pubkey` leaves it `None` (remote commands off).
    #[test]
    fn join_super_admin_pubkey_defaults_none() {
        let args = parse_join(&["join", "--coordinator", "http://u", "--name", "x"]);
        assert_eq!(args.super_admin_pubkey, None);
    }

    /// `--status-file <path>` parses into `JoinArgs::status_file`.
    #[test]
    fn join_parses_status_file() {
        let args = parse_join(&[
            "join",
            "--coordinator",
            "http://u",
            "--name",
            "lifeline",
            "--status-file",
            "/x/lifeline-status.json",
        ]);
        assert_eq!(
            args.status_file,
            Some(PathBuf::from("/x/lifeline-status.json")),
            "--status-file must populate JoinArgs::status_file"
        );
    }

    /// Omitting `--status-file` leaves it `None` (no lifeline-status write).
    #[test]
    fn join_status_file_defaults_none() {
        let args = parse_join(&["join", "--coordinator", "http://u", "--name", "x"]);
        assert_eq!(args.status_file, None);
    }

    /// HA-relay C7: `--relay-url` is REPEATABLE — multiple flags accumulate into
    /// the ordered failover list (primary first).
    #[test]
    fn join_parses_repeated_relay_url() {
        let args = parse_join(&[
            "join",
            "--coordinator",
            "http://u",
            "--name",
            "x",
            "--relay-url",
            "wss://a/v1/mesh/relay",
            "--relay-url",
            "wss://b/v1/mesh/relay",
        ]);
        assert_eq!(
            args.relay_url,
            vec![
                "wss://a/v1/mesh/relay".to_owned(),
                "wss://b/v1/mesh/relay".to_owned()
            ],
            "repeated --relay-url must accumulate in order"
        );
    }

    /// HA-relay C7: a COMMA-separated value splits into the ordered list. This
    /// is the SAME `value_delimiter = ','` code path clap applies to the
    /// `TABBIFY_MESH_RELAY_URL` env value (the prod rollout lever — one
    /// systemd/compose drop-in, no new env var). Driven via a comma-bearing
    /// flag so the test never mutates the (workspace-`deny(unsafe_code)`)
    /// process environment.
    #[test]
    fn join_parses_comma_env_relay_url() {
        let args = parse_join(&[
            "join",
            "--coordinator",
            "http://u",
            "--name",
            "x",
            "--relay-url",
            "wss://a/v1/mesh/relay,wss://b/v1/mesh/relay",
        ]);
        assert_eq!(
            args.relay_url,
            vec![
                "wss://a/v1/mesh/relay".to_owned(),
                "wss://b/v1/mesh/relay".to_owned()
            ],
            "comma value must split into the ordered list (same path as the env var)"
        );
    }

    /// HA-relay C7: omitting the flag/env leaves the list EMPTY ⇒ the joiner
    /// derives the single relay from `--coordinator` (today's behaviour). This
    /// asserts the value-source-precedence default; it does not read the env
    /// (env-mutation is forbidden under `deny(unsafe_code)`).
    #[test]
    fn join_relay_url_defaults_empty() {
        let args = parse_join(&["join", "--coordinator", "http://u", "--name", "x"]);
        assert!(
            args.relay_url.is_empty(),
            "omitted --relay-url must be an empty list (derive single)"
        );
    }

    /// Omitting `--route-metric` leaves it at the joiner's default (1024 — the
    /// kernel's implicit IPv6 default), so a plain/primary join is byte-for-byte
    /// unchanged.
    #[test]
    fn join_route_metric_defaults_to_kernel_default() {
        let args = parse_join(&["join", "--coordinator", "http://u", "--name", "x"]);
        assert_eq!(
            args.route_metric,
            tabbify_mesh_joiner::platform::DEFAULT_ROUTE_METRIC
        );
        assert_eq!(args.route_metric, 1024);
    }

    /// `--route-metric 4096` (the lifeline / secondary joiner) parses into
    /// `JoinArgs::route_metric` so it can ride onto `JoinConfig` and install
    /// the peer routes at the worse, lower-priority metric.
    #[test]
    fn join_parses_route_metric_override() {
        let args = parse_join(&[
            "join",
            "--coordinator",
            "http://u",
            "--name",
            "thinkpad-lifeline",
            "--route-metric",
            "4096",
        ]);
        assert_eq!(args.route_metric, 4096);
    }
}
