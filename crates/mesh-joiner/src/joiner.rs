//! Top-level [`Joiner`] orchestrator.
//!
//! Wires together:
//!
//! 1. [`crate::wg::keypair`] — fresh X25519 keypair.
//! 2. [`crate::coordinator::client`] — register, heartbeat, deregister.
//! 3. [`tabbify_mesh_fabric::tun`] — open the TUN device.
//! 4. [`crate::platform`] — assign ULA + add overlay route via shell-outs.
//! 5. [`crate::wg::session`] — boringtun sessions per peer.
//! 6. [`crate::coordinator::peer_sync`] + [`crate::coordinator::heartbeat`]
//!    — background tasks.
//! 7. [`crate::wg::loops`] — UDP / TUN / timer background loops.

use crate::config::JoinConfig;
use crate::coordinator::client::{CoordinatorClient, remote_to_info};
use crate::coordinator::{heartbeat, peer_sync};
use crate::error::JoinerError;
use crate::nat::holepunch;
use crate::peer::PeerInfo;
use crate::platform;
use crate::wg::loops::{timer_loop, tun_read_loop, udp_recv_loop};
use crate::wg::persistent_identity;
use crate::wg::session::{PeerSession, SessionTable};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tabbify_mesh_fabric::tun::{self as fabric_tun, TunDevice, TunOptions};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use uuid::Uuid;

/// Default `WireGuard` UDP listen port used when
/// [`JoinConfig::listen_port`] is `None` — the well-known `WireGuard` port.
///
/// A stable, predictable port is what makes reflexive endpoint discovery
/// viable across a cone `NAT`: the coordinator advertises
/// `<observed-public-ip>:<this-port>` and a port-preserving `NAT` maps the
/// same port externally. Override with `--listen-port` when 51820 is
/// unavailable or already port-forwarded to a different external port.
pub const DEFAULT_WG_LISTEN_PORT: u16 = 51820;

/// Handle to a running joiner.
///
/// Drop = abrupt shutdown (background tasks abort, TUN device closes,
/// sessions vanish); call [`Joiner::leave`] for a graceful
/// deregistration that also tells the coordinator we're going away.
pub struct Joiner {
    /// Coordinator-assigned peer id.
    peer_id: Uuid,
    /// Our assigned ULA. Stable for the lifetime of this `Joiner`.
    my_ula: Ipv6Addr,
    /// Shared session table — readable for [`Self::peers`].
    sessions: SessionTable,
    /// Per-peer metadata snapshot. Maintained in parallel with
    /// `sessions` because `PeerSession` deliberately doesn't keep the
    /// `display_name` / `tags` (the encryption layer doesn't care).
    peer_info: Arc<dashmap::DashMap<Ipv6Addr, PeerInfo>>,
    /// Coordinator HTTP client — retained so `leave` can deregister.
    client: Arc<CoordinatorClient>,
    /// Cancellation signal for all background tasks.
    shutdown_tx: watch::Sender<bool>,
    /// Background task handles. Owned so `leave` can join them; on
    /// `Drop` they are simply forgotten and the runtime aborts them.
    tasks: Vec<JoinHandle<()>>,
    /// Holds the TUN device alive — kernel auto-removes the iface on
    /// fd close. Wrapped in Option so `leave` can drop it explicitly
    /// after the deregister round-trip succeeds.
    tun: Option<Arc<dyn TunDevice>>,
    /// The overlay TUN interface name captured at join time. `None` in
    /// `--no-mesh` / no-TUN modes. Callers that host an app-ULA need this
    /// to assign the `/128` alias (per-app-ULA routing — supervisor side);
    /// exposed via [`Self::tun_name`].
    iface_name: Option<String>,
    /// App-ULAs THIS node currently hosts (per-app-ULA routing —
    /// supervisor side). [`Self::host_app_ula`] inserts (and assigns the
    /// TUN alias); [`Self::unhost_app_ula`] removes (and releases it). The
    /// register + heartbeat payloads advertise this set as
    /// `hosted_app_ulas` so other peers learn to route to us. Shared with
    /// the heartbeat task (lock-free reads via `DashMap`).
    hosted_app_ulas: Arc<dashmap::DashMap<Ipv6Addr, ()>>,
}

impl Joiner {
    /// Register with the coordinator, open the TUN device, start WG
    /// sessions for the initial roster, and spawn the heartbeat +
    /// peer-stream background tasks. Returns once the initial
    /// registration + TUN setup are complete; further peer additions
    /// happen in the background.
    ///
    /// # Errors
    ///
    /// Surfaces `anyhow::Result` because the failure surface is broad —
    /// HTTP, TUN setup, UDP bind, and sudo all share this path. The
    /// underlying error is a [`JoinerError`] variant in every case.
    pub async fn join(config: JoinConfig) -> anyhow::Result<Self> {
        let (keypair, sticky_ula, effective_requested_ula) = resolve_identity(&config)?;

        // 1) Open the UDP socket. We bind to v4 wildcard because the
        //    overlay rides on top of v4 transport, exactly like the
        //    existing WireGuardFabric.
        //
        //    Port selection: default to the well-known WireGuard port
        //    51820 when `--listen-port` is unset, rather than letting the
        //    OS pick an ephemeral port. A STABLE, PREDICTABLE port is what
        //    makes reflexive endpoint discovery work: the coordinator
        //    advertises `<observed-public-ip>:<this-port>` to other peers,
        //    and a port-preserving (cone) NAT maps that same port
        //    externally. An OS-picked ephemeral port still works for
        //    same-host loopback but is a poor advertisement across NAT.
        //    If 51820 is busy (e.g. two peers on one host in a smoke
        //    test) we fall back to an OS-picked port so the bind still
        //    succeeds.
        let preferred_port = config.listen_port.unwrap_or(DEFAULT_WG_LISTEN_PORT);
        let socket = bind_udp_with_fallback(preferred_port).await?;
        let bound = socket
            .local_addr()
            .map_err(|e| JoinerError::HttpTransport(format!("udp local_addr: {e}")))?;
        let wg_listen_port = bound.port();
        let socket = Arc::new(socket);
        tracing::info!(local = %bound, wg_listen_port, "joiner: udp socket bound");

        // 2) Register with the coordinator.
        //
        // Endpoint discovery (Stage 2 — cone NAT):
        //   * If the operator passed an explicit `--advertise-endpoint`,
        //     send it verbatim — it's their authoritative "dial me here"
        //     (port-forward / cross-VM name like `host.lima.internal`).
        //     It takes precedence over reflexive discovery.
        //   * OTHERWISE send NO `listen_endpoint` and let the coordinator
        //     synthesize our reflexive endpoint from the source IP it
        //     observes + the `wg_listen_port` we report. We deliberately
        //     no longer auto-advertise a loopback / LAN bind address: it
        //     is unreachable for off-host peers and was the source of the
        //     `127.0.0.1:<port>` bug. Same-host smoke tests still work
        //     because the coordinator keeps a loopback observed-IP as-is
        //     and falls back to no endpoint → passive, while the WG
        //     roaming path learns the real source on first contact.
        // The advertised string (when present) is metadata for *other*
        // peers — they resolve it in their own environment at dial time
        // (`coordinator::client::remote_to_info`), so we must NOT resolve
        // it locally.
        let advertised: Option<String> = config.advertise_endpoint.clone();
        let client = Arc::new(CoordinatorClient::new(
            config.coordinator_url.clone(),
            config.tls_cert.as_deref(),
            config.tls_key.as_deref(),
            config.tls_ca.as_deref(),
            config.insecure_no_mtls,
        )?);
        let resp = client
            .register(
                keypair.public.as_bytes(),
                advertised,
                Some(wg_listen_port),
                &config.display_name,
                &config.tags,
                config.join_token.as_deref(),
                effective_requested_ula,
                config.kind.clone(),
                config.parent.clone(),
                config.app_uuid.clone(),
            )
            .await?;
        let peer_id = resp.peer_id;
        let my_ula: Ipv6Addr = resp.ula.parse().map_err(|e| {
            JoinerError::MalformedPeer(format!("coordinator returned bad ula {:?}: {e}", resp.ula))
        })?;
        tracing::info!(
            %peer_id,
            %my_ula,
            peers = resp.peers.len(),
            observed_ip = ?resp.observed_ip,
            observed_endpoint = ?resp.observed_endpoint,
            "joiner: registered (reflexive endpoint from coordinator)"
        );

        // ── Persist identity after a fresh join ───────────────────────────
        // Only persist when an identity_path was configured AND we didn't
        // already have a loaded identity (sticky_ula was None → fresh join).
        // On a restart with an existing file we would have loaded it above
        // (sticky_ula was Some), so there is nothing new to write.
        if let Some(id_path) = config.identity_path.as_ref() {
            if sticky_ula.is_none() {
                persistent_identity::store(id_path, &keypair, my_ula).map_err(|e| {
                    anyhow::anyhow!("persist identity {}: {}", id_path.display(), e)
                })?;
                tracing::info!(
                    identity_path = %id_path.display(),
                    %my_ula,
                    "joiner: persisted identity (keypair + ULA)"
                );
            }
        }

        // 3) Open + configure the TUN device. The fabric crate already
        //    has a polished cross-platform open() that returns
        //    Box<dyn TunDevice>; we just need to feed it a TunOptions.
        let tun_name = config.tun_name.clone().unwrap_or_default();
        let tun_dev = fabric_tun::open(TunOptions {
            name: tun_name,
            ula: my_ula,
            mtu: 1_420,
        })
        .await
        .map_err(|e| JoinerError::TunSetup(format!("open: {e}")))?;
        let iface_name = tun_dev.name().to_owned();
        let tun_arc: Arc<dyn TunDevice> = Arc::from(tun_dev);
        tracing::info!(iface = %iface_name, "joiner: tun device opened");

        // 4) Tell the kernel about our ULA. We DO NOT add a blanket
        //    `/48` overlay route any more (spec §5.5): per-peer `/128`
        //    routes are installed by the `TunRouteSink` below as each
        //    session is upserted, so the kernel only routes addresses we
        //    have a permitted session for. macOS needs the explicit
        //    `assign_ula` because the fabric's tun/macos.rs is a
        //    skeleton; the Linux backend assigns the address itself, so
        //    the call is a no-op there modulo `File exists` tolerance.
        platform::assign_ula(&iface_name, my_ula).await?;

        // 5) Seed the session table from the initial roster. The table is
        //    wired to a `TunRouteSink` so every upsert installs the peer's
        //    `/128` host route (TX scoping) and every advertised app-ULA
        //    its app-route (per-app-ULA routing). See `seed_initial_roster`.
        let route_sink = Arc::new(platform::TunRouteSink::new(iface_name.clone()));
        let sessions = SessionTable::with_route_sink(route_sink);
        let peer_info: Arc<dashmap::DashMap<Ipv6Addr, PeerInfo>> = Arc::default();
        seed_initial_roster(&sessions, &peer_info, &keypair.private, &resp.peers).await;

        // 6) Spawn the background tasks. The locally-hosted app-ULA set is
        //    shared with the heartbeat task so each heartbeat advertises
        //    the CURRENT set (per-app-ULA routing — supervisor side).
        let hosted_app_ulas: Arc<dashmap::DashMap<Ipv6Addr, ()>> = Arc::default();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let tasks = spawn_background_tasks(SpawnContext {
            socket: socket.clone(),
            sessions: sessions.clone(),
            tun: tun_arc.clone(),
            client: client.clone(),
            our_private: keypair.private,
            peer_id,
            my_ula,
            wg_listen_port,
            heartbeat_interval: config.heartbeat_interval,
            hosted_app_ulas: hosted_app_ulas.clone(),
            shutdown_rx,
        });

        Ok(Self {
            peer_id,
            my_ula,
            sessions,
            peer_info,
            client,
            shutdown_tx,
            tasks,
            tun: Some(tun_arc),
            iface_name: Some(iface_name),
            hosted_app_ulas,
        })
    }

    /// Our assigned ULA. Stable for the lifetime of this `Joiner`.
    #[must_use]
    pub const fn my_ula(&self) -> Ipv6Addr {
        self.my_ula
    }

    /// Our coordinator-assigned peer id.
    #[must_use]
    pub const fn my_peer_id(&self) -> Uuid {
        self.peer_id
    }

    /// The overlay TUN interface name, for callers that need to assign
    /// app-ULA `/128` aliases themselves. `None` in `--no-mesh` / no-TUN
    /// modes.
    #[must_use]
    pub fn tun_name(&self) -> Option<String> {
        self.iface_name.clone()
    }

    /// SUPERVISOR side: start hosting `app_ula` on THIS node
    /// (per-app-ULA routing).
    ///
    /// Two effects:
    /// 1. assigns a local `/128` alias for `app_ula` on the overlay TUN
    ///    ([`platform::assign_app_ula`]) so inbound packets addressed to
    ///    `app_ula` are delivered to a local listener bound on it;
    /// 2. records `app_ula` in the locally-hosted set, which the next
    ///    register / heartbeat advertises as `hosted_app_ulas` — so other
    ///    peers learn to route `app_ula`-bound traffic to us.
    ///
    /// Idempotent: hosting an already-hosted `app_ula` re-asserts the
    /// (idempotent) alias and leaves the set unchanged.
    ///
    /// # Errors
    /// - [`anyhow::Error`] wrapping [`JoinerError::TunSetup`] if the alias
    ///   can't be assigned (missing privileges, bad interface).
    /// - Fails if the joiner has no TUN interface (`--no-mesh` mode): an
    ///   app-ULA can't be hosted without an interface to bind it on.
    pub async fn host_app_ula(&self, app_ula: Ipv6Addr) -> anyhow::Result<()> {
        let iface = self
            .iface_name
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("cannot host app-ULA: joiner has no TUN interface"))?;
        platform::assign_app_ula(iface, app_ula).await?;
        self.hosted_app_ulas.insert(app_ula, ());
        tracing::info!(%app_ula, iface, "joiner: now hosting app-ULA");
        Ok(())
    }

    /// SUPERVISOR side: stop hosting `app_ula` — release the `/128` alias
    /// and drop it from the advertised set. Idempotent (un-hosting an
    /// app-ULA we don't host releases the alias and is otherwise a no-op).
    ///
    /// # Errors
    /// [`anyhow::Error`] wrapping [`JoinerError::TunSetup`] on a
    /// non-idempotent alias-release failure. No-op (Ok) in `--no-mesh`
    /// mode — there's nothing hosted to release.
    pub async fn unhost_app_ula(&self, app_ula: Ipv6Addr) -> anyhow::Result<()> {
        self.hosted_app_ulas.remove(&app_ula);
        if let Some(iface) = self.iface_name.as_deref() {
            platform::release_app_ula(iface, app_ula).await?;
            tracing::info!(%app_ula, iface, "joiner: stopped hosting app-ULA");
        }
        Ok(())
    }

    /// Snapshot of currently-known peers (excluding self).
    #[must_use]
    pub fn peers(&self) -> Vec<PeerInfo> {
        // We mirror metadata into `peer_info` from the SSE / heartbeat
        // paths via the session table; for MVP just snapshot the table
        // and look up metadata where available. Sessions without
        // matching metadata (shouldn't happen) are returned with empty
        // display_name + tags so callers still see them.
        self.sessions
            .snapshot()
            .into_iter()
            .map(|s| {
                self.peer_info
                    .get(&s.ula)
                    .map_or_else(|| synth_info(&s), |kv| kv.value().clone())
            })
            .collect()
    }

    /// Gracefully deregister and shut down background tasks. Best
    /// effort — if the coordinator is unreachable we still tear down
    /// local state.
    pub async fn leave(mut self) -> anyhow::Result<()> {
        tracing::info!(peer_id = %self.peer_id, "joiner: leaving");
        // Tell the coordinator first; if this fails we still want to
        // close the local fd / kill tasks.
        if let Err(e) = self.client.deregister(self.peer_id).await {
            tracing::warn!(error = %e, "joiner: deregister failed (continuing teardown)");
        }
        // Signal background tasks to exit.
        let _ = self.shutdown_tx.send(true);
        for task in self.tasks.drain(..) {
            // Wait up to 2s per task — if a task hangs (e.g. stuck on
            // a sync syscall) we abort it. `if let` because we only
            // care about the elapsed case; success is silent.
            if tokio::time::timeout(Duration::from_secs(2), task)
                .await
                .is_err()
            {
                tracing::warn!("joiner: background task didn't exit within 2s");
            }
        }
        self.sessions.clear();
        // Drop the TUN device last so the kernel tears the interface
        // down only after every other consumer has stopped.
        self.tun.take();
        Ok(())
    }
}

impl Drop for Joiner {
    fn drop(&mut self) {
        // If `leave` wasn't called, at least signal tasks to exit so
        // they don't leak across reload tests.
        let _ = self.shutdown_tx.send(true);
    }
}

/// Bundle of state that gets handed to the per-task spawn helper. Split
/// out so the giant `Joiner::join` constructor stays under the
/// clippy-imposed 100-line cap without resorting to clippy `allow`.
struct SpawnContext {
    socket: Arc<UdpSocket>,
    sessions: SessionTable,
    tun: Arc<dyn TunDevice>,
    client: Arc<CoordinatorClient>,
    our_private: x25519_dalek::StaticSecret,
    peer_id: Uuid,
    my_ula: Ipv6Addr,
    /// Our `WireGuard` UDP listen port — re-sent on every heartbeat so the
    /// coordinator can refresh our reflexive endpoint on an observed-IP
    /// change.
    wg_listen_port: u16,
    heartbeat_interval: Duration,
    /// App-ULAs this node hosts — advertised on every heartbeat
    /// (per-app-ULA routing). Shared with [`Joiner`] so `host_app_ula` /
    /// `unhost_app_ula` mutate the set the heartbeat task reads.
    hosted_app_ulas: Arc<dashmap::DashMap<Ipv6Addr, ()>>,
    shutdown_rx: watch::Receiver<bool>,
}

/// Spawn all five background loops and return their join handles in
/// the order they were spawned.
fn spawn_background_tasks(ctx: SpawnContext) -> Vec<JoinHandle<()>> {
    let SpawnContext {
        socket,
        sessions,
        tun,
        client,
        our_private,
        peer_id,
        my_ula,
        wg_listen_port,
        heartbeat_interval,
        hosted_app_ulas,
        shutdown_rx,
    } = ctx;
    let mut tasks: Vec<JoinHandle<()>> = Vec::with_capacity(6);

    // UDP receive loop — drains ciphertext, decapsulates, writes
    // plaintext IPv6 packets to the TUN device.
    tasks.push(tokio::spawn(udp_recv_loop(
        socket.clone(),
        sessions.clone(),
        tun.clone(),
        shutdown_rx.clone(),
    )));

    // TUN read loop — drains plaintext from the kernel, encapsulates,
    // and sends ciphertext to the right peer.
    tasks.push(tokio::spawn(tun_read_loop(
        socket.clone(),
        sessions.clone(),
        tun,
        my_ula,
        shutdown_rx.clone(),
    )));

    // Timer loop — keeps each `Tunn` alive (rekey, keepalives).
    tasks.push(tokio::spawn(timer_loop(
        socket.clone(),
        sessions.clone(),
        shutdown_rx.clone(),
    )));

    // Punch channel: the SSE consumer forwards `HolePunchInitiate` frames
    // to the hole-punch task, which fires the UDP burst (Stage 2).
    let (punch_tx, punch_rx) = mpsc::unbounded_channel::<holepunch::HolePunchInitiate>();

    // SSE consumer. Passes our own `peer_id` so the coordinator returns an
    // ACL-filtered peer stream (spec §5.3 / 5a decision #3), and the punch
    // sender so hole-punch frames reach the punch task.
    {
        let sessions = sessions.clone();
        let our_private = our_private.clone();
        let client = client.clone();
        let shutdown_rx = shutdown_rx.clone();
        tasks.push(tokio::spawn(async move {
            peer_sync::run(
                client,
                sessions,
                our_private,
                Some(punch_tx),
                peer_id,
                shutdown_rx,
            )
            .await;
        }));
    }

    // Stage 2 hole-punch task. Receives forwarded initiate events and fires
    // handshake-init bursts at the target's reflexive endpoint. `socket` is
    // moved in here (its last use); `sessions` is cloned because the
    // heartbeat task below still needs the original.
    {
        let sessions = sessions.clone();
        let shutdown_rx = shutdown_rx.clone();
        tasks.push(tokio::spawn(async move {
            holepunch::run(peer_id, socket, sessions, punch_rx, shutdown_rx).await;
        }));
    }

    // Heartbeat — the last task, so it moves the remaining handles. It
    // reads `hosted_app_ulas` each tick to advertise our current hosted
    // set to the coordinator (per-app-ULA routing).
    tasks.push(tokio::spawn(async move {
        heartbeat::run(heartbeat::HeartbeatTask {
            client,
            sessions,
            our_private,
            peer_id,
            wg_listen_port,
            hosted_app_ulas,
            interval: heartbeat_interval,
            shutdown: shutdown_rx,
        })
        .await;
    }));

    tasks
}

/// Bind the `WireGuard` UDP socket on the v4 wildcard, preferring
/// `preferred_port`. If that port is already in use (e.g. a second peer on
/// the same host during a smoke test, or a stale process), fall back to an
/// OS-picked ephemeral port (`:0`) so the bind still succeeds.
///
/// The preferred (stable) port is what makes reflexive discovery work
/// across a cone NAT; the ephemeral fallback keeps multi-peer same-host
/// runs working at the cost of a less predictable advertised port — fine
/// because same-host peers reach each other via loopback / WG roaming, not
/// via the coordinator-advertised reflexive endpoint.
async fn bind_udp_with_fallback(preferred_port: u16) -> Result<UdpSocket, JoinerError> {
    let preferred = SocketAddr::new(IpAddr::from([0u8, 0, 0, 0]), preferred_port);
    match UdpSocket::bind(preferred).await {
        Ok(sock) => Ok(sock),
        Err(e) if preferred_port != 0 => {
            tracing::warn!(
                port = preferred_port,
                error = %e,
                "joiner: preferred WG port unavailable, falling back to OS-picked port"
            );
            let ephemeral = SocketAddr::new(IpAddr::from([0u8, 0, 0, 0]), 0);
            UdpSocket::bind(ephemeral)
                .await
                .map_err(|source| JoinerError::UdpBind {
                    addr: ephemeral,
                    source,
                })
        }
        Err(source) => Err(JoinerError::UdpBind {
            addr: preferred,
            source,
        }),
    }
}

/// Resolve the local peer identity from `config`.
///
/// Returns `(keypair, sticky_ula, effective_requested_ula)`.
///
/// When `identity_path` is set the richer identity file (keypair + ULA) is
/// used and any persisted ULA becomes the `effective_requested_ula` so the
/// peer re-requests its sticky mesh address on restart.  When absent the
/// legacy keypair-only path is used.
fn resolve_identity(
    config: &JoinConfig,
) -> anyhow::Result<(
    crate::wg::keypair::WgKeypair,
    Option<std::net::Ipv6Addr>,
    Option<String>,
)> {
    let (keypair, sticky_ula) = if let Some(id_path) = config.identity_path.as_ref() {
        let (kp, sticky) = persistent_identity::load_or_fresh(id_path)
            .map_err(|e| anyhow::anyhow!("load identity {}: {}", id_path.display(), e))?;
        if let Some(ula) = sticky {
            tracing::info!(
                display_name = %config.display_name,
                identity_path = %id_path.display(),
                %ula,
                "joiner: loaded persisted identity (will re-request sticky ULA)"
            );
        } else {
            tracing::info!(
                display_name = %config.display_name,
                identity_path = %id_path.display(),
                "joiner: no prior identity file, joining fresh (will persist after registration)"
            );
        }
        (kp, sticky)
    } else {
        let kp_path = config
            .keypair_path
            .clone()
            .unwrap_or_else(default_keypair_path);
        let kp = crate::wg::persistent_keypair::load_or_generate(&kp_path)
            .map_err(|e| anyhow::anyhow!("load keypair {}: {}", kp_path.display(), e))?;
        tracing::info!(
            display_name = %config.display_name,
            tags = ?config.tags,
            keypair_path = %kp_path.display(),
            "joiner: starting registration"
        );
        (kp, None)
    };

    // Sticky ULA from a prior identity file takes precedence over any
    // explicit `config.requested_ula` (re-request path on restart).
    let effective_requested_ula = sticky_ula
        .map(|u| u.to_string())
        .or_else(|| config.requested_ula.clone());

    Ok((keypair, sticky_ula, effective_requested_ula))
}

/// Default location for the persistent keypair file. Used when the
/// caller passes `keypair_path: None` in [`JoinConfig`]. Falls back to
/// the current directory when `$HOME` is missing (e.g. inside an empty
/// systemd unit env), which is good enough for the smoke-test paths
/// that go through CLI subcommands with explicit `--keypair-path`.
fn default_keypair_path() -> std::path::PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    std::path::PathBuf::from(home)
        .join(".tabbify-mesh")
        .join("keypair")
}

/// Seed the session table + metadata map from the initial register
/// roster, dropping any malformed records with a warning. For each good
/// peer this upserts its session AND reconciles the app-ULAs it
/// advertises (per-app-ULA routing) — so a supervisor that was already
/// hosting apps when we joined is routable immediately, not only after
/// the next heartbeat. Pulled out of [`Joiner::join`] to keep that
/// constructor under the clippy line cap.
async fn seed_initial_roster(
    sessions: &SessionTable,
    peer_info: &dashmap::DashMap<Ipv6Addr, PeerInfo>,
    our_private: &x25519_dalek::StaticSecret,
    remote: &[crate::peer::RemotePeer],
) {
    for r in remote {
        match remote_to_info(r).await {
            Ok(info) => {
                peer_info.insert(info.ula, info.clone());
                sessions.upsert(our_private, &info);
                sessions.reconcile_app_routes(info.ula, &info.hosted_app_ulas);
            }
            Err(e) => tracing::warn!(error = %e, "joiner: skipping malformed initial peer"),
        }
    }
}

/// Build a placeholder [`PeerInfo`] from a session when we somehow
/// lost the rich metadata. Keeps the public API non-fallible.
fn synth_info(s: &PeerSession) -> PeerInfo {
    PeerInfo {
        peer_id: s.peer_id,
        wg_public_key: [0u8; 32],
        ula: s.ula,
        listen_endpoint: s.endpoint(),
        display_name: String::new(),
        tags: Vec::new(),
        // We lost the rich metadata; hosted app-ULAs aren't reconstructable
        // from a `PeerSession` alone, so report none. The next roster
        // upsert re-applies the real set.
        hosted_app_ulas: Vec::new(),
        joined_at_micros: 0,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    /// `synth_info` round-trips ula + `peer_id` + endpoint so callers
    /// that hit the fallback path still see something usable.
    #[test]
    fn synth_info_preserves_known_fields() {
        let me = x25519_dalek::StaticSecret::from([1u8; 32]);
        let info = PeerInfo {
            peer_id: Uuid::nil(),
            wg_public_key: *x25519_dalek::PublicKey::from(&me).as_bytes(),
            ula: "fd5a:1f00:1::42".parse().unwrap(),
            listen_endpoint: Some("127.0.0.1:51820".parse().unwrap()),
            display_name: "irrelevant".into(),
            tags: vec![],
            hosted_app_ulas: vec![],
            joined_at_micros: 0,
        };
        let table = SessionTable::new();
        table.upsert(&me, &info);
        let session = table.by_ula(info.ula).unwrap();
        let synth = synth_info(&session);
        assert_eq!(synth.ula, info.ula);
        assert_eq!(synth.listen_endpoint, info.listen_endpoint);
    }
}
