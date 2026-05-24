//! `clap` definitions for the `tabbify-mesh` binary.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

/// Default coordinator URL used when neither `--coordinator` nor the
/// `TABBIFY_MESH_COORDINATOR` env var are set.
pub const DEFAULT_COORDINATOR_URL: &str = "http://127.0.0.1:8888";

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

    /// Optional fixed `WireGuard` listen port.
    #[arg(long)]
    pub listen_port: Option<u16>,

    /// Optional fixed TUN interface name (e.g. `utun5`).
    #[arg(long)]
    pub tun_name: Option<String>,

    /// Heartbeat interval (seconds).
    #[arg(long, default_value_t = 20)]
    pub heartbeat_interval: u64,

    /// Public/reachable endpoint to advertise to other peers via the
    /// coordinator. Overrides the auto-detected bound address. Use this
    /// when the joiner is behind a NAT / port-forward and the address
    /// other peers must dial differs from what `bind` returns. Example:
    /// `--advertise-endpoint host.lima.internal:51820` from a Mac peer
    /// so a Lima peer can reach it; `--advertise-endpoint 127.0.0.1:51821`
    /// from a Lima peer if Lima forwards its `:51820` to Mac's `:51821`.
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
