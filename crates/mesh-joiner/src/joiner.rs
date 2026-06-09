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
use crate::coordinator::client::{CoordinatorClient, PeerPath, remote_to_info};
use crate::coordinator::heartbeat::{ReregisterInputs, SharedPeerId};
use crate::coordinator::{heartbeat, peer_sync};
use crate::error::JoinerError;
use crate::nat::holepunch;
use crate::peer::PeerInfo;
use crate::platform;
use crate::wg::loops::{now_micros, timer_loop, tun_read_loop, udp_recv_loop};
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

/// This joiner crate's own compile-time version (from its `Cargo.toml` via
/// `env!("CARGO_PKG_VERSION")`), self-reported on register + every heartbeat as
/// `mesh_version` so the control plane sees the mesh-stack version each peer
/// runs — independent of the host binary's caller-supplied `software_version`.
const MESH_VERSION: &str = env!("CARGO_PKG_VERSION");

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
    /// Coordinator-assigned peer id captured at the INITIAL join. Surfaced
    /// by the synchronous [`Self::my_peer_id`] accessor. A 404 re-register
    /// in the heartbeat task can change the LIVE id (see
    /// [`Self::shared_peer_id`]); this field intentionally holds the
    /// original so the sync accessor stays infallible and lock-free.
    peer_id: Uuid,
    /// The LIVE peer id, shared with the heartbeat + SSE tasks. Replaced
    /// in place when a coordinator roster loss forces a re-register, so
    /// [`Self::leave`] deregisters the id the coordinator actually knows.
    shared_peer_id: SharedPeerId,
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
    /// Source-scoped policy-routing parameters when this joiner runs in
    /// `source_scoped_routes` mode. Kept so [`Self::leave`] can remove
    /// the policy rule and flush the private table — unlike the peer
    /// `/128`s (which die with the TUN device), neither is bound to the
    /// iface and both would LEAK past TUN teardown otherwise.
    source_scope: Option<platform::SourceScope>,
    /// Whether this joiner manages the host-firewall trust rule for its
    /// TUN — kept so [`Self::leave`] removes the rule it added.
    manage_firewall: bool,
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
    #[allow(clippy::too_many_lines)]
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
        let (socket, wg_listen_port) = bind_wg_socket(preferred_port).await?;

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
        // it locally. Passed straight into `register` below.
        let client = Arc::new(CoordinatorClient::new(
            config.coordinator_url.clone(),
            config.tls_cert.as_deref(),
            config.tls_key.as_deref(),
            config.tls_ca.as_deref(),
            config.insecure_no_mtls,
        )?);
        // Build the re-register inputs ONCE — the same sticky identity is used
        // for the cold-start register here AND the heartbeat task's 404
        // recovery below.
        let reregister = build_reregister_inputs(
            &config,
            *keypair.public.as_bytes(),
            effective_requested_ula.as_ref(),
        );
        // Cold-start register, with the SAME sticky-then-free 409 self-heal the
        // heartbeat re-register uses: if the requested (sticky) ULA is held by
        // a stale peer the coordinator hasn't evicted yet, retry once with a
        // coordinator-allocated address rather than failing the entire join.
        // Guarantees a node ALWAYS joins (defense in depth alongside the
        // coordinator's adopt-on-stale eviction).
        let resp = heartbeat::register_with_409_fallback(
            &client,
            &reregister,
            wg_listen_port,
            config.software_version.clone(),
            Some(MESH_VERSION.to_string()),
            effective_requested_ula.clone(),
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

        persist_identity_if_fresh(&config, &keypair, my_ula, sticky_ula)?;

        // 3) Open + configure the TUN device (cross-platform open() in
        //    the fabric crate). Extracted into a helper to keep this
        //    constructor under the clippy line cap.
        let (tun_arc, iface_name) =
            open_tun_device(resolve_tun_name(&config, my_ula), my_ula).await?;

        // 4) Tell the kernel about our ULA. We DO NOT add a blanket
        //    `/48` overlay route any more (spec §5.5): per-peer `/128`
        //    routes are installed by the `TunRouteSink` below as each
        //    session is upserted, so the kernel only routes addresses we
        //    have a permitted session for. macOS needs the explicit
        //    `assign_ula` because the fabric's tun/macos.rs is a
        //    skeleton; the Linux backend assigns the address itself, so
        //    the call is a no-op there modulo `File exists` tolerance.
        platform::assign_ula(&iface_name, my_ula).await?;

        // 4b/4c) Host-integration opt-ins (scoped routing + firewall
        //     trust) — BEFORE the roster seeds the first session, so the
        //     first peer `/128` already lands in the scoped table.
        let source_scope = setup_host_integration(&config, my_ula, &iface_name).await?;

        // 5) Seed the session table from the initial roster. The table is
        //    wired to a `TunRouteSink` so every upsert installs the peer's
        //    `/128` host route (TX scoping) and every advertised app-ULA
        //    its app-route (per-app-ULA routing). See `seed_initial_roster`.
        // Relay (Stage-3 connectivity floor): when enabled, create the
        // handle the WG TX seams use to relay packets to peers with no
        // direct path, plus the receiver the relay client task drains. The
        // handle is wired into the SessionTable so the loops can reach it;
        // the receiver is handed to the relay task in `spawn_background_tasks`.
        let (relay_handle, relay_outbound_rx) = build_relay_channel(
            config.relay_enabled,
            config.insecure_no_mtls,
            config.relay_only,
        );

        let route_sink = Arc::new(source_scope.map_or_else(
            || platform::TunRouteSink::new(iface_name.clone()),
            |scope| platform::TunRouteSink::source_scoped(iface_name.clone(), scope),
        ));
        let sessions = SessionTable::with_route_sink_and_relay(route_sink, relay_handle);
        let peer_info: Arc<dashmap::DashMap<Ipv6Addr, PeerInfo>> = Arc::default();
        seed_initial_roster(&sessions, &peer_info, &keypair.private, &resp.peers).await;

        // 6) Spawn the background tasks. `hosted_app_ulas` is shared with the
        //    heartbeat task (advertises the CURRENT set each tick — per-app-ULA
        //    routing). `shared_peer_id` is shared (mutable) with the heartbeat,
        //    SSE, AND hole-punch tasks so a coordinator roster loss can swap in
        //    the re-registered id and all three observe it. `reregister`
        //    carries the inputs for that 404 recovery — same sticky identity
        //    the initial join used.
        let hosted_app_ulas: Arc<dashmap::DashMap<Ipv6Addr, ()>> = Arc::default();
        let shared_peer_id: SharedPeerId = Arc::new(tokio::sync::RwLock::new(peer_id));
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let mut tasks = spawn_background_tasks(SpawnContext {
            socket: socket.clone(),
            sessions: sessions.clone(),
            tun: tun_arc.clone(),
            client: client.clone(),
            our_private: keypair.private,
            peer_id: shared_peer_id.clone(),
            reregister,
            my_ula,
            wg_listen_port,
            heartbeat_interval: config.heartbeat_interval,
            hosted_app_ulas: hosted_app_ulas.clone(),
            software_version: config.software_version.clone(),
            mesh_version: Some(MESH_VERSION.to_string()),
            relay_outbound_rx,
            relay_url: config.relay_url.clone(),
            coordinator_url: config.coordinator_url.clone(),
            my_pubkey: *keypair.public.as_bytes(),
            insecure_no_mtls: config.insecure_no_mtls,
            shutdown_rx,
        });

        spawn_host_integration_loops(
            &config,
            source_scope,
            &iface_name,
            &sessions,
            &shutdown_tx,
            &mut tasks,
        );

        Ok(Self {
            peer_id,
            shared_peer_id,
            my_ula,
            sessions,
            peer_info,
            client,
            shutdown_tx,
            tasks,
            tun: Some(tun_arc),
            iface_name: Some(iface_name),
            hosted_app_ulas,
            source_scope,
            manage_firewall: config.manage_firewall,
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

    /// Snapshot THIS node's live per-peer data paths (connectivity
    /// visibility). One [`PeerPath`] per session: whether our current data
    /// path to that peer is direct (p2p) or relay, plus how long since the
    /// last valid inbound datagram. The heartbeat task reports the same
    /// snapshot to the coordinator, which aggregates it into per-vantage
    /// connectivity. Reads the live session table — direct/age reflect the
    /// data plane's confirm/downgrade state right now.
    #[must_use]
    pub fn peer_paths(&self) -> Vec<PeerPath> {
        peer_paths_from_sessions(&self.sessions, now_micros())
    }

    /// Gracefully deregister and shut down background tasks. Best
    /// effort — if the coordinator is unreachable we still tear down
    /// local state.
    pub async fn leave(mut self) -> anyhow::Result<()> {
        // Deregister the LIVE id: a 404 recovery may have replaced the
        // initial `peer_id`, and the coordinator only knows the current one.
        let live_id = *self.shared_peer_id.read().await;
        tracing::info!(peer_id = %live_id, "joiner: leaving");
        // Tell the coordinator first; if this fails we still want to
        // close the local fd / kill tasks.
        if let Err(e) = self.client.deregister(live_id).await {
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
        // Remove host-level state that is NOT bound to the TUN device and
        // would therefore outlive it: the firewall trust rule and the
        // source-scoped policy rule + its private table. Best-effort —
        // an abrupt Drop/SIGKILL skips this entirely, which is safe
        // BECAUSE every key is stable across respawns: the table id and
        // the iface name are both derived from the ULA (`stable_tun_name`),
        // so the next start re-adopts the leaked rule (list-then-insert)
        // and re-replaces the leaked routes instead of orphaning them.
        if self.manage_firewall {
            if let Some(iface) = &self.iface_name {
                platform::firewall::remove_tun_trust(iface).await;
            }
        }
        if let Some(scope) = self.source_scope.take() {
            platform::remove_source_rule(&scope).await;
        }
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
    /// Shared, mutable peer id — handed to the heartbeat task (which can
    /// replace it on a 404 re-register), the SSE consumer (which reads it
    /// on every reconnect), and the hole-punch task (which reads it per
    /// initiate event). After a 404 re-register all three observe the new
    /// id: the punch task therefore filters initiate events against the
    /// LIVE id, so post-recovery hole-punching keeps firing instead of
    /// silently matching a dead id.
    peer_id: SharedPeerId,
    /// Register inputs for the heartbeat task's 404 recovery path.
    reregister: ReregisterInputs,
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
    /// Software version advertised on register + every heartbeat (spec P0
    /// OBSERVE). Host-supplied; `None` = unknown, never invented here.
    software_version: Option<String>,
    /// This joiner's own compile-time version ([`MESH_VERSION`]), self-reported
    /// on register + every heartbeat alongside `software_version`.
    mesh_version: Option<String>,
    /// Receiver the relay client task drains for outbound relayed
    /// datagrams. `Some` only when relay is enabled; `None` (`--no-relay`)
    /// skips spawning the relay task entirely.
    relay_outbound_rx: Option<mpsc::UnboundedReceiver<crate::relay::client::RelayOutbound>>,
    /// Explicit relay endpoint URL override; `None` derives it from
    /// `coordinator_url`.
    relay_url: Option<String>,
    /// Coordinator base URL — the relay URL is derived from it when
    /// `relay_url` is `None`.
    coordinator_url: String,
    /// Our raw WG public key — sent as the relay `?pubkey=` query param.
    my_pubkey: [u8; 32],
    /// `true` for a plaintext (`--insecure-no-mtls`) coordinator. The relay
    /// task only connects under insecure mode (wss/mTLS not yet built).
    insecure_no_mtls: bool,
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
        reregister,
        my_ula,
        wg_listen_port,
        heartbeat_interval,
        hosted_app_ulas,
        software_version,
        mesh_version,
        relay_outbound_rx,
        relay_url,
        coordinator_url,
        my_pubkey,
        insecure_no_mtls,
        shutdown_rx,
    } = ctx;
    let mut tasks: Vec<JoinHandle<()>> = Vec::with_capacity(7);

    // UDP receive loop — drains ciphertext, decapsulates, writes
    // plaintext IPv6 packets to the TUN device.
    tasks.push(tokio::spawn(udp_recv_loop(
        socket.clone(),
        sessions.clone(),
        tun.clone(),
        shutdown_rx.clone(),
    )));

    // TUN read loop — drains plaintext from the kernel, encapsulates,
    // and sends ciphertext to the right peer. `tun.clone()` so the relay
    // task below can still hand relayed RX to the SAME device.
    tasks.push(tokio::spawn(tun_read_loop(
        socket.clone(),
        sessions.clone(),
        tun.clone(),
        my_ula,
        shutdown_rx.clone(),
    )));

    // Timer loop — keeps each `Tunn` alive (rekey, keepalives).
    tasks.push(tokio::spawn(timer_loop(
        socket.clone(),
        sessions.clone(),
        shutdown_rx.clone(),
    )));

    // Relay client task (Stage-3 connectivity floor). Spawned only when
    // relay is enabled. It keeps a persistent WS to the coordinator,
    // drains the outbound queue, and injects inbound relayed datagrams into
    // the SAME session table + TUN the UDP loops use. Spawned BEFORE the
    // hole-punch block because that block MOVES `socket`; the relay clones
    // what it needs here.
    if let Some(relay_outbound_rx) = relay_outbound_rx {
        tasks.push(tokio::spawn(crate::relay::client::run(
            crate::relay::client::RelayTask {
                coordinator_url,
                relay_url,
                my_pubkey,
                insecure_no_mtls,
                sessions: sessions.clone(),
                socket: socket.clone(),
                tun: tun.clone(),
                outbound_rx: relay_outbound_rx,
                shutdown: shutdown_rx.clone(),
            },
        )));
    }

    // Punch channel: the SSE consumer forwards `HolePunchInitiate` frames
    // to the hole-punch task, which fires the UDP burst (Stage 2).
    let (punch_tx, punch_rx) = mpsc::unbounded_channel::<holepunch::HolePunchInitiate>();

    // SSE consumer. Passes our own (shared) `peer_id` so the coordinator
    // returns an ACL-filtered peer stream (spec §5.3 / 5a decision #3),
    // and the punch sender so hole-punch frames reach the punch task. The
    // shared id lets the consumer re-subscribe to the LIVE id after a 404
    // re-register instead of staying filtered to a dead one.
    {
        let sessions = sessions.clone();
        let our_private = our_private.clone();
        let client = client.clone();
        let shutdown_rx = shutdown_rx.clone();
        let peer_id = peer_id.clone();
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
    // handshake-init bursts at the target's reflexive endpoint. It shares the
    // SAME live `peer_id` handle as the heartbeat + SSE tasks: it reads the
    // current id per initiate event, so a 404 re-register that swaps in a new
    // id keeps punches firing (the coordinator keys post-recovery events to
    // the new id). `socket` is moved in here (its last use); `sessions` is
    // cloned because the heartbeat task below still needs the original.
    {
        let sessions = sessions.clone();
        let shutdown_rx = shutdown_rx.clone();
        let peer_id = peer_id.clone();
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
            reregister,
            wg_listen_port,
            hosted_app_ulas,
            software_version,
            mesh_version,
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

/// Persist the `{keypair, ULA}` identity after a FRESH join.
///
/// Only writes when an `identity_path` was configured AND we did not
/// already load a sticky identity (`sticky_ula` is `None` → fresh join).
/// On a restart with an existing file we loaded it earlier (`sticky_ula`
/// is `Some`), so there is nothing new to write.
///
/// # Errors
/// [`anyhow::Error`] when the on-disk write fails.
fn persist_identity_if_fresh(
    config: &JoinConfig,
    keypair: &crate::wg::keypair::WgKeypair,
    my_ula: Ipv6Addr,
    sticky_ula: Option<Ipv6Addr>,
) -> anyhow::Result<()> {
    if let Some(id_path) = config.identity_path.as_ref()
        && sticky_ula.is_none()
    {
        persistent_identity::store(id_path, keypair, my_ula)
            .map_err(|e| anyhow::anyhow!("persist identity {}: {}", id_path.display(), e))?;
        tracing::info!(
            identity_path = %id_path.display(),
            %my_ula,
            "joiner: persisted identity (keypair + ULA)"
        );
    }
    Ok(())
}

/// Build the [`ReregisterInputs`] handed to the heartbeat task for its
/// 404-recovery path. Mirrors the arguments the INITIAL register used so a
/// re-register requests the same sticky identity (preserving the ULA across
/// a coordinator roster loss). `effective_requested_ula` already folds a
/// persisted sticky ULA over any explicit `config.requested_ula`.
fn build_reregister_inputs(
    config: &JoinConfig,
    our_public: [u8; 32],
    effective_requested_ula: Option<&String>,
) -> ReregisterInputs {
    ReregisterInputs {
        our_public,
        advertise_endpoint: config.advertise_endpoint.clone(),
        display_name: config.display_name.clone(),
        tags: config.tags.clone(),
        join_token: config.join_token.clone(),
        requested_ula: effective_requested_ula.cloned(),
        kind: config.kind.clone(),
        parent: config.parent.clone(),
        app_uuid: config.app_uuid.clone(),
        relay_only: config.relay_only,
    }
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

/// Spawn the host-integration healing loops onto `tasks`.
///
/// * Firewall re-assert ([`platform::firewall::trust_loop`]): a host
///   firewall reload flushes our INPUT rule; this keeps it alive (and is
///   the warn-once site for hosts where the assert can never succeed).
/// * Source-scope re-assert ([`source_scope_reassert_loop`]): policy
///   rules and scoped routes have the SAME external-flush exposure
///   (networkd / `NetworkManager` reconciles, `nixos-rebuild switch`
///   wipe FOREIGN policy rules), so they get the same periodic healing.
fn spawn_host_integration_loops(
    config: &JoinConfig,
    source_scope: Option<platform::SourceScope>,
    iface_name: &str,
    sessions: &SessionTable,
    shutdown_tx: &watch::Sender<bool>,
    tasks: &mut Vec<JoinHandle<()>>,
) {
    if config.manage_firewall {
        tasks.push(tokio::spawn(platform::firewall::trust_loop(
            iface_name.to_owned(),
            shutdown_tx.subscribe(),
        )));
    }
    if let Some(scope) = source_scope {
        tasks.push(tokio::spawn(source_scope_reassert_loop(
            scope,
            iface_name.to_owned(),
            sessions.clone(),
            shutdown_tx.subscribe(),
        )));
    }
}

/// Periodic re-assert for the source-scoped policy rule + scoped peer
/// routes — the policy-routing twin of `firewall::trust_loop`. Both
/// guard against the reload/reconcile class of external flushes: a
/// `nixos-rebuild switch` or a networkd/NetworkManager reconcile can
/// drop foreign `ip -6 rule`s, after which return traffic silently
/// egresses via the wrong TUN with no local error. The rule re-assert
/// is presence-checked (read-only in steady state); the per-session
/// route re-assert rides `ip -6 route replace` (atomic + idempotent).
async fn source_scope_reassert_loop(
    scope: platform::SourceScope,
    iface: String,
    sessions: SessionTable,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut ticker = tokio::time::interval(Duration::from_secs(60));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    return;
                }
            }
            _ = ticker.tick() => {
                platform::route::reassert_source_rule(&scope).await;
                for session in sessions.snapshot() {
                    if let Err(e) =
                        platform::route::add_peer_route_in_table(&iface, session.ula, scope.table)
                            .await
                    {
                        tracing::debug!(error = %e, ula = %session.ula, "route: scoped re-assert failed");
                    }
                }
            }
        }
    }
}

/// Bind the WG UDP socket (preferred port, OS-picked fallback) and
/// report the actually-bound port — the one the coordinator advertises
/// for reflexive endpoint discovery.
///
/// # Errors
/// [`JoinerError::HttpTransport`] when the local addr cannot be read.
async fn bind_wg_socket(preferred_port: u16) -> anyhow::Result<(Arc<UdpSocket>, u16)> {
    let socket = bind_udp_with_fallback(preferred_port).await?;
    let bound = socket
        .local_addr()
        .map_err(|e| JoinerError::HttpTransport(format!("udp local_addr: {e}")))?;
    let wg_listen_port = bound.port();
    tracing::info!(local = %bound, wg_listen_port, "joiner: udp socket bound");
    Ok((Arc::new(socket), wg_listen_port))
}

/// Pick the TUN device name for this join.
///
/// An explicit `config.tun_name` always wins. Otherwise host-integrated
/// joiners (scoped routes / managed firewall) get a STABLE, ULA-derived
/// name ([`platform::stable_tun_name`]) instead of the kernel's recycled
/// `tun%d`: their host state (the firewall trust rule, the scoped
/// routes' `dev`) is keyed on the iface NAME, and a SIGKILL respawn
/// landing on a different auto-index would orphan the old entries
/// instead of re-adopting them. Linux-only (macOS requires `utun%d`
/// names); plain joiners keep kernel auto-naming.
fn resolve_tun_name(config: &JoinConfig, my_ula: Ipv6Addr) -> Option<String> {
    config.tun_name.clone().or_else(|| {
        (cfg!(target_os = "linux") && (config.source_scoped_routes || config.manage_firewall))
            .then(|| platform::stable_tun_name(my_ula))
    })
}

/// Apply the host-integration opt-ins right after TUN bring-up.
///
/// * `source_scoped_routes`: derive the per-instance routing table from
///   our OWN ULA and install the `from <own_ula>` policy rule, so this
///   joiner's egress always uses its OWN TUN even when another joiner in
///   the same netns owns the `main`-table `/128`s (supervisor + per-app
///   runners on one machine). Installation failure propagates like
///   `assign_ula`'s: a host that opted in but cannot install the rule
///   would silently egress via the wrong TUN — fail loudly instead.
/// * `manage_firewall`: assert the tailscaled-style `INPUT -i <tun> -j
///   ACCEPT` trust rule. Best-effort by contract (containers without
///   ip6tables must still join); re-asserted by the background loop.
///
/// Returns the [`platform::SourceScope`] to hand to the route sink
/// (`None` when scoping is off).
///
/// # Errors
/// [`JoinerError::TunSetup`] when the opted-in policy rule cannot be
/// installed.
async fn setup_host_integration(
    config: &JoinConfig,
    my_ula: Ipv6Addr,
    iface_name: &str,
) -> anyhow::Result<Option<platform::SourceScope>> {
    let source_scope = if config.source_scoped_routes {
        let scope = platform::SourceScope::for_ula(my_ula);
        platform::install_source_rule(&scope).await?;
        tracing::info!(
            table = scope.table,
            pref = scope.pref,
            "joiner: source-scoped routing installed (from {my_ula} lookup {})",
            scope.table
        );
        Some(scope)
    } else {
        None
    };
    if config.manage_firewall {
        platform::firewall::ensure_tun_trust(iface_name).await;
    }
    Ok(source_scope)
}

/// Open + configure the overlay TUN device, returning the shared device
/// handle and the kernel-assigned interface name. Pulled out of
/// [`Joiner::join`] to keep that constructor under the clippy line cap.
///
/// # Errors
/// [`JoinerError::TunSetup`] if the device cannot be opened.
async fn open_tun_device(
    tun_name: Option<String>,
    my_ula: Ipv6Addr,
) -> anyhow::Result<(Arc<dyn TunDevice>, String)> {
    let tun_dev = fabric_tun::open(TunOptions {
        name: tun_name.unwrap_or_default(),
        ula: my_ula,
        mtu: 1_420,
    })
    .await
    .map_err(|e| JoinerError::TunSetup(format!("open: {e}")))?;
    let iface_name = tun_dev.name().to_owned();
    let tun_arc: Arc<dyn TunDevice> = Arc::from(tun_dev);
    tracing::info!(iface = %iface_name, "joiner: tun device opened");
    Ok((tun_arc, iface_name))
}

/// Build the relay handle + outbound receiver when relay is active.
///
/// Returns `(Some(handle), Some(rx))` only when relay is enabled AND we
/// are in insecure (`--insecure-no-mtls`) mode — the only mode the relay
/// client supports today (wss/mTLS is not yet implemented). In that case
/// the [`SessionTable`] carries the handle and the relay task drains the
/// receiver. Otherwise `(None, None)`: the WG TX seams keep the pre-relay
/// silent-drop behaviour and no relay task is spawned. Gating on
/// `insecure_no_mtls` here is what stops a secure-mode joiner from queuing
/// outbound datagrams into a channel that the (early-returning) secure
/// relay task would never drain.
fn build_relay_channel(
    relay_enabled: bool,
    insecure_no_mtls: bool,
    relay_only: bool,
) -> (
    Option<crate::relay::RelayHandle>,
    Option<mpsc::UnboundedReceiver<crate::relay::client::RelayOutbound>>,
) {
    if relay_enabled && insecure_no_mtls {
        let (h, rx) = crate::relay::RelayHandle::new(relay_only);
        (Some(h), Some(rx))
    } else if relay_enabled {
        // Enabled but secure: the relay client can't connect yet (wss/mTLS
        // unimplemented), so install no handle — otherwise the TX seams
        // would queue into a channel nothing drains.
        tracing::warn!(
            "relay enabled but coordinator is secure (mTLS); relay disabled \
             (wss/mTLS not implemented) — direct + hole-punch still active"
        );
        (None, None)
    } else {
        (None, None)
    }
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

/// Map the live session table to the per-peer path snapshot reported in the
/// heartbeat (connectivity visibility). Shared by [`Joiner::peer_paths`] and
/// the heartbeat sender so both stamp ages against the SAME clock. For each
/// session: `direct` comes from `PeerSession::path_status`; `last_rx_age_ms`
/// is the micros age floored to millis and clamped to non-negative (a
/// negative age from a confirm/now clock skew becomes `0`).
pub(crate) fn peer_paths_from_sessions(sessions: &SessionTable, now_micros: i64) -> Vec<PeerPath> {
    sessions
        .snapshot()
        .into_iter()
        .map(|s| {
            let (direct, age_micros) = s.path_status(now_micros);
            #[allow(clippy::cast_sign_loss)] // clamped to >= 0 by `.max(0)`.
            let last_rx_age_ms = (age_micros / 1_000).max(0) as u64;
            PeerPath {
                peer_id: s.peer_id,
                direct,
                last_rx_age_ms,
            }
        })
        .collect()
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
        software_version: None,
        mesh_version: None,
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
            software_version: None,
            mesh_version: None,
            joined_at_micros: 0,
        };
        let table = SessionTable::new();
        table.upsert(&me, &info);
        let session = table.by_ula(info.ula).unwrap();
        let synth = synth_info(&session);
        assert_eq!(synth.ula, info.ula);
        assert_eq!(synth.listen_endpoint, info.listen_endpoint);
    }

    /// `peer_paths_from_sessions` reflects each session's live confirm
    /// state: a direct-confirmed session reports `direct = true`, an
    /// unconfirmed one `direct = false`. This is the snapshot the heartbeat
    /// reports to the coordinator.
    #[test]
    fn peer_paths_reflect_direct_confirmed() {
        let me = x25519_dalek::StaticSecret::from([7u8; 32]);
        let mk = |ula: &str, peer_id: Uuid| PeerInfo {
            peer_id,
            wg_public_key: *x25519_dalek::PublicKey::from(&me).as_bytes(),
            ula: ula.parse().unwrap(),
            listen_endpoint: None,
            display_name: String::new(),
            tags: vec![],
            hosted_app_ulas: vec![],
            software_version: None,
            mesh_version: None,
            joined_at_micros: 0,
        };
        let direct_id = Uuid::from_u128(1);
        let relay_id = Uuid::from_u128(2);
        let table = SessionTable::new();
        table.upsert(&me, &mk("fd5a:1f00:1::a", direct_id));
        table.upsert(&me, &mk("fd5a:1f00:1::b", relay_id));

        // Confirm the FIRST peer direct at t = 1_000_000 micros (1 s).
        let direct_session = table.by_ula("fd5a:1f00:1::a".parse().unwrap()).unwrap();
        direct_session.confirm_direct(1_000_000);

        // Read 5_000 micros later → direct peer: direct=true, age 5ms→0ms
        // (5_000 micros / 1_000 = 5); relay peer: never confirmed.
        let paths = peer_paths_from_sessions(&table, 1_005_000);
        let by_id: std::collections::HashMap<Uuid, &PeerPath> =
            paths.iter().map(|p| (p.peer_id, p)).collect();

        assert_eq!(paths.len(), 2, "one PeerPath per session");
        let d = by_id.get(&direct_id).expect("direct peer reported");
        assert!(d.direct, "confirmed session reports direct");
        assert_eq!(d.last_rx_age_ms, 5, "age 5_000 micros → 5 ms");
        let r = by_id.get(&relay_id).expect("relay peer reported");
        assert!(!r.direct, "unconfirmed session reports relay");
    }
}
