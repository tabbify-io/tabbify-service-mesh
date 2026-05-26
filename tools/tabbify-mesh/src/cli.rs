//! `clap` definitions for the `tabbify-mesh` binary.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

/// Default coordinator URL (zero-config fallback).
///
/// Used when neither `--coordinator` nor `TABBIFY_MESH_COORDINATOR` are set.
/// The production EIP is baked in so `tabbify-mesh join --name X` is enough.
/// Override with `--coordinator http://127.0.0.1:8888` for a local smoke run.
pub const DEFAULT_COORDINATOR_URL: &str = "http://3.124.69.92:8888";

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
    Join(JoinArgs),
    /// Print a local status snapshot written by a running `join` daemon.
    Status,
    /// List peers currently registered with the coordinator.
    Peers(PeersArgs),
    /// Deregister from the coordinator and exit cleanly.
    Leave(LeaveArgs),
}

/// Arguments for the `join` subcommand.
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
    #[arg(long)]
    pub listen_port: Option<u16>,

    /// Optional fixed TUN interface name (e.g. `utun5`).
    #[arg(long)]
    pub tun_name: Option<String>,

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
