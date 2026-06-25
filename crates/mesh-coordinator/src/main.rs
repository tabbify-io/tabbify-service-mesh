//! mesh-coordinator binary.
//!
//! Boots the axum router on `--bind`, wires an in-memory roster sink, and
//! spawns the heartbeat-timeout sweeper.
//!
//! Persistence is in-memory by default: on restart, joiners re-register
//! within one heartbeat interval, so the roster self-heals. A durable
//! backend can be added later behind the
//! [`tabbify_mesh_coordinator::EventPublisher`] seam without changing the
//! state machine.

use anyhow::{Context, Result, anyhow, bail};
use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tabbify_mesh_coordinator::{
    AuthValidator, Coordinator, FileRosterStore, NoopPublisher, NoopRosterStore, PolicyStore,
    SharedRosterStore, build_router_with_admin, build_server_config, timeout,
};
use tracing::{info, warn};

#[derive(Debug, Parser)]
#[command(name = "tabbify-mesh-coordinator", version)]
struct Args {
    /// Address the HTTP server binds to.
    #[arg(long, env = "TABBIFY_MESH_BIND", default_value = "0.0.0.0:8888")]
    bind: SocketAddr,

    /// Seconds since the last heartbeat after which a peer is dropped.
    #[arg(
        long,
        env = "TABBIFY_MESH_HEARTBEAT_TIMEOUT_SECS",
        default_value_t = 60
    )]
    heartbeat_timeout_secs: u64,

    /// Path to coordinator's server certificate (PEM). Required unless
    /// `--insecure-no-mtls` is set.
    #[arg(long, env = "TABBIFY_MESH_TLS_CERT")]
    tls_cert: Option<PathBuf>,

    /// Path to coordinator's server private key (PEM). Required unless
    /// `--insecure-no-mtls` is set.
    #[arg(long, env = "TABBIFY_MESH_TLS_KEY")]
    tls_key: Option<PathBuf>,

    /// Path to CA cert (trusts peer client certs, PEM). Required unless
    /// `--insecure-no-mtls` is set.
    #[arg(long, env = "TABBIFY_MESH_TLS_CA")]
    tls_ca: Option<PathBuf>,

    /// Allow plaintext HTTP (insecure — dev only). Combined safeguard:
    /// the flag is only honored when `TABBIFY_ALLOW_INSECURE=1` is in the
    /// process environment, so an accidental flag in a systemd unit can
    /// not silently strip the prod TLS protection.
    #[arg(long)]
    insecure_no_mtls: bool,

    /// Enable the GLOBAL proactive (always-direct) gate (R7). OFF by default:
    /// the coordinator emits a hole-punch ONLY for admin-`direct`-flagged pairs
    /// (byte-identical to a pre-Tailscale deploy). ON: every non-pinned,
    /// non-`relay_only` pair attempts direct, governed entirely joiner-side. The
    /// Stage-4 default-on lever AND its kill-switch (unset + restart re-suppresses
    /// all punches; the coordinator can also flip it live).
    #[arg(long, env = "TABBIFY_MESH_PROACTIVE", default_value_t = false)]
    proactive: bool,

    /// Path to the declarative ACL policy file (JSON, `{ "acls": [...] }`).
    /// Loaded into the in-memory store at startup. When omitted, the
    /// coordinator starts with the Phase-2 BOOTSTRAP policy — exactly two
    /// system rules (`tag:system → tag:system` and `tag:system → tag:net-*`)
    /// so shared infra can serve every tenant runner while distinct tenant
    /// networks stay isolated (default-deny). Per-network self-rules are
    /// added at runtime by the auth service via `PUT /v1/policy`.
    #[arg(long, env = "MESH_POLICY_FILE")]
    policy_file: Option<PathBuf>,

    /// Admin bearer token for the policy API (`GET/PUT /v1/policy`). When
    /// unset, those endpoints are disabled (fail-closed) and the policy can
    /// only be set from `--policy-file` at startup.
    #[arg(long, env = "MESH_ADMIN_TOKEN")]
    admin_token: Option<String>,

    /// Directory for the durable roster snapshot (`<dir>/roster.json`). When
    /// set, the coordinator restores its peer roster on startup and persists
    /// it on every membership change, so a restart keeps each peer's
    /// `peer_id ↔ ULA ↔ wg_public_key` mapping instead of reshuffling ULAs /
    /// 409-crashing sticky peers. Back it with a docker volume so the snapshot
    /// survives container redeploys. When UNSET, the roster is in-memory only
    /// (joiners re-register on heartbeat-timeout — the dev / self-healing path).
    #[arg(long, env = "TABBIFY_MESH_STATE_DIR")]
    state_dir: Option<PathBuf>,

    /// Base URL of the auth service used to validate node-join tokens
    /// (spec §8), e.g. `http://127.0.0.1:8080`. The coordinator calls
    /// `POST <AUTH_URL>/v1/validate` over plain HTTP (NOT over the mesh)
    /// on every `register`, and takes the node's `network` + `tags` from
    /// the validated claims (authoritative — closes the spoofing gap).
    ///
    /// When SET: every register MUST present a valid `Authorization:
    /// Bearer <join-token>`; invalid / missing / revoked → 401.
    ///
    /// When UNSET (dev/E1 escape hatch ONLY): join tokens are NOT
    /// validated and the joiner-supplied `network` + `tags` are trusted.
    /// This is acceptable only for a local smoke run / `--insecure-no-mtls`
    /// behind a firewall — NEVER for a multi-tenant deployment.
    #[arg(long, env = "AUTH_URL")]
    auth_url: Option<String>,

    /// UDP address for the co-located STUN BINDING responder (RFC 5389), e.g.
    /// `0.0.0.0:3478`. When set, NAT'd joiners pointed at this address (their
    /// `--mesh-stun-server`) discover their reflexive WG endpoint — the punch
    /// target governed-direct needs. When UNSET (default), no STUN server runs
    /// and behaviour is unchanged (joiners fall back to the coordinator's
    /// reflexive guess; relay always remains the floor).
    #[arg(long, env = "TABBIFY_MESH_STUN_BIND")]
    stun_bind: Option<SocketAddr>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tabbify_mesh_log::init_logging("mesh-coordinator");

    let args = Args::parse();
    // Don't log the full args struct — it carries the admin token. Log the
    // operationally-relevant fields explicitly instead.
    info!(
        bind = %args.bind,
        heartbeat_timeout_secs = args.heartbeat_timeout_secs,
        policy_file = ?args.policy_file,
        admin_api_enabled = args.admin_token.is_some(),
        join_token_validation = args.auth_url.is_some(),
        "tabbify-mesh-coordinator starting",
    );

    // Load the ACL policy from disk if configured, else start with the
    // bootstrap policy (the single system self-rule — strict default-deny:
    // tenants are isolated and infra reaches them only via explicit rules the
    // auth service PUTs at runtime).
    let policy_store = if let Some(path) = &args.policy_file {
        let store =
            PolicyStore::load_from_file(path).map_err(|e| anyhow!("load policy file: {e}"))?;
        info!(path = %path.display(), "loaded ACL policy");
        store
    } else {
        info!(
            "no --policy-file: starting with the bootstrap policy \
             (tag:system->tag:system + tag:system->tag:net-*)"
        );
        PolicyStore::bootstrap()
    };

    // Build the join-token validator from AUTH_URL, if configured. When
    // absent we run the dev/E1 escape hatch: no validation, request-
    // supplied tags trusted (logged loudly so it's never a silent prod
    // misconfiguration).
    let validator = build_validator(args.auth_url.as_deref())?;

    // Durable roster store: a file-backed snapshot when --state-dir is set
    // (survives coordinator restarts — no ULA reshuffle / sticky-ULA 409),
    // else the no-op store (in-memory, self-heals via re-register).
    let roster_store = build_roster_store(args.state_dir.as_ref());

    let coordinator = Coordinator::with_policy_validator_store(
        Arc::new(NoopPublisher),
        Duration::from_secs(args.heartbeat_timeout_secs),
        policy_store,
        validator,
        roster_store,
    );
    // Seed the global proactive (always-direct) gate from the CLI/env (R7).
    coordinator.set_proactive(args.proactive);

    // Restore any persisted roster BEFORE serving + before the sweeper runs,
    // so the first re-register hits the idempotent by_pubkey path (same ULA)
    // and restored peers get a full heartbeat-timeout grace.
    coordinator.restore().await;

    let _sweeper = timeout::spawn(coordinator.clone());

    // Optional co-located STUN BINDING responder (R1). Spawned only when
    // `--stun-bind` is set; absent ⇒ no STUN server, behaviour unchanged. It
    // ONLY discovers a joiner's reflexive WG endpoint — never touches any
    // relay/punch decision (direct is still adopted only on real DATA).
    if let Some(stun_bind) = args.stun_bind {
        tokio::spawn(async move {
            if let Err(e) =
                tabbify_mesh_coordinator::nat::stun_server::run_stun_server(stun_bind).await
            {
                tracing::error!(error = %e, "STUN server exited");
            }
        });
    }

    let router = build_router_with_admin(coordinator, args.admin_token);
    // `into_make_service_with_connect_info` lets the heartbeat handler
    // read the peer's external socket addr from the request — the
    // joiner uses it for hole-punch coordination in Stage 2. The same
    // make-service wraps both the plaintext and TLS serve paths so the
    // request-level extractors don't care which transport is below them.
    let make_service = router.into_make_service_with_connect_info::<SocketAddr>();

    if args.insecure_no_mtls {
        // Belt-and-suspenders: the flag alone isn't enough; an explicit
        // env var must also be set. This makes accidental prod misuse via
        // a stale systemd unit harder — operators have to opt in twice.
        if std::env::var("TABBIFY_ALLOW_INSECURE").as_deref() != Ok("1") {
            bail!(
                "--insecure-no-mtls requires TABBIFY_ALLOW_INSECURE=1 in the environment; \
                 refusing to serve plaintext HTTP without explicit opt-in"
            );
        }
        let listener = tokio::net::TcpListener::bind(args.bind)
            .await
            .with_context(|| format!("bind {}", args.bind))?;
        warn!(bind = %args.bind, "INSECURE: serving plaintext HTTP (no mTLS)");
        axum::serve(listener, make_service)
            .await
            .context("axum::serve")?;
    } else {
        let cert = args
            .tls_cert
            .ok_or_else(|| anyhow!("--tls-cert is required (or pass --insecure-no-mtls)"))?;
        let key = args
            .tls_key
            .ok_or_else(|| anyhow!("--tls-key is required (or pass --insecure-no-mtls)"))?;
        let ca = args
            .tls_ca
            .ok_or_else(|| anyhow!("--tls-ca is required (or pass --insecure-no-mtls)"))?;
        let mtls = build_server_config(&cert, &key, &ca)
            .map_err(|e| anyhow!("mtls server config: {e}"))?;
        // axum-server's rustls integration needs a synchronous std listener;
        // we bind via tokio for the same error UX as the plaintext path,
        // then convert. `into_std` preserves the bound fd.
        let listener = tokio::net::TcpListener::bind(args.bind)
            .await
            .with_context(|| format!("bind {}", args.bind))?;
        info!(bind = %args.bind, "serving HTTPS with mTLS (peer cert required)");
        let std_listener = listener.into_std().context("convert listener to std")?;
        let tls_config = axum_server::tls_rustls::RustlsConfig::from_config(mtls.config);
        axum_server::from_tcp_rustls(std_listener, tls_config)
            .serve(make_service)
            .await
            .context("axum-server::serve")?;
    }
    Ok(())
}

/// Build the durable roster store from an optional `--state-dir`.
///
/// `Some(dir)` → a file-backed snapshot at `<dir>/roster.json` so the roster
/// survives a coordinator restart (no ULA reshuffle / sticky-ULA 409).
/// `None` → the no-op store: the roster is in-memory and self-heals as
/// joiners re-register. Logged either way so the durability posture is never
/// a silent surprise. (`let ... else` lets each `Arc::new` coerce to the
/// trait-object return type — no explicit cast, no Option-combinator lint.)
fn build_roster_store(state_dir: Option<&PathBuf>) -> SharedRosterStore {
    let Some(dir) = state_dir else {
        warn!(
            "TABBIFY_MESH_STATE_DIR unset: roster is IN-MEMORY only. A coordinator \
             restart drops the roster — joiners re-register on heartbeat-timeout."
        );
        return Arc::new(NoopRosterStore);
    };
    info!(state_dir = %dir.display(), "durable roster ENABLED (restore + persist)");
    Arc::new(FileRosterStore::new(dir.clone()))
}

/// Build the join-token validator from an optional `AUTH_URL`.
///
/// `Some(url)` → production: a validator that makes the auth service's
/// claims authoritative for every node's `network` + `tags`.
/// `None` → dev/E1 escape hatch: no validation; the joiner-supplied
/// `network` + `tags` are trusted. Logged loudly either way so the
/// security posture is never a silent surprise.
fn build_validator(auth_url: Option<&str>) -> Result<Option<AuthValidator>> {
    let Some(url) = auth_url else {
        warn!(
            "AUTH_URL unset: join-token validation DISABLED (dev/E1 escape hatch). \
             Joiner-supplied tags/network are TRUSTED — do not use in production."
        );
        return Ok(None);
    };
    let validator = AuthValidator::new(url).map_err(|e| anyhow!("build auth validator: {e}"))?;
    info!(auth_url = %url, "join-token validation ENABLED (authoritative tags/network)");
    Ok(Some(validator))
}
