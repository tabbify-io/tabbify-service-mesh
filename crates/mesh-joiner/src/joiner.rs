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
use crate::coordinator::client::{remote_to_info, CoordinatorClient};
use crate::coordinator::{heartbeat, peer_sync};
use crate::error::JoinerError;
use crate::nat::holepunch;
use crate::peer::PeerInfo;
use crate::platform;
use crate::wg::loops::{timer_loop, tun_read_loop, udp_recv_loop};
use crate::wg::session::{PeerSession, SessionTable};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tabbify_mesh_fabric::tun::{self as fabric_tun, TunDevice, TunOptions};
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use uuid::Uuid;

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
        let kp_path = config.keypair_path.clone().unwrap_or_else(default_keypair_path);
        let keypair = crate::wg::persistent_keypair::load_or_generate(&kp_path)
            .map_err(|e| anyhow::anyhow!("load keypair {}: {}", kp_path.display(), e))?;
        tracing::info!(
            display_name = %config.display_name,
            tags = ?config.tags,
            keypair_path = %kp_path.display(),
            "joiner: starting registration"
        );

        // 1) Open the UDP socket. listen_port = None -> let the OS
        //    pick. We bind to v4 wildcard because the overlay rides on
        //    top of v4 transport, exactly like the existing
        //    WireGuardFabric.
        let listen_addr =
            SocketAddr::new(IpAddr::from([0u8, 0, 0, 0]), config.listen_port.unwrap_or(0));
        let socket = UdpSocket::bind(listen_addr)
            .await
            .map_err(|source| JoinerError::UdpBind { addr: listen_addr, source })?;
        let bound = socket
            .local_addr()
            .map_err(|e| JoinerError::HttpTransport(format!("udp local_addr: {e}")))?;
        let socket = Arc::new(socket);
        tracing::info!(local = %bound, "joiner: udp socket bound");

        // 2) Register with the coordinator. We hand it our public key
        //    and our locally-known endpoint — the coordinator may
        //    rewrite the endpoint based on what it actually saw on the
        //    request socket, but we don't model NAT-rewrite this stage.
        //
        // Endpoint rewrite priority:
        //   1. Caller-supplied `advertise_endpoint` wins — it's the
        //      operator's explicit "this is the address other peers
        //      should dial me on" (used for cross-NAT / port-forwarded
        //      topologies like Mac+Lima where each side sees the other
        //      via a different address).
        //   2. Bound to 0.0.0.0 → no usable host portion to advertise;
        //      substitute 127.0.0.1 + bound port so same-host smoke
        //      tests work out of the box.
        //   3. Otherwise the bound socket addr is a fine advertisement.
        // Real NAT-traversal (Stage 2) will eventually replace step 1
        // with coordinator-driven hole punching.
        // The `advertised` string is metadata for *other* peers — they
        // resolve it themselves when they go to dial us. We must NOT
        // try to resolve it locally: a Mac peer that advertises
        // `host.lima.internal:51820` for the benefit of a Lima
        // counterpart can't resolve that name on its own DNS resolver.
        // Keep it as a free-form string and let the dial-time path
        // (`coordinator_client::remote_to_info` → `wg_session::upsert`)
        // do the lookup in the consumer's own environment.
        // `option_if_let_else` would force a nested closure that's
        // strictly less readable than this three-arm cascade — skip.
        #[allow(clippy::option_if_let_else)]
        let advertised: String = if let Some(advert) = &config.advertise_endpoint {
            advert.clone()
        } else if bound.ip().is_unspecified() {
            format!("127.0.0.1:{}", bound.port())
        } else {
            bound.to_string()
        };
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
                Some(advertised),
                &config.display_name,
                &config.tags,
                config.join_token.as_deref(),
            )
            .await?;
        let peer_id = resp.peer_id;
        let my_ula: Ipv6Addr = resp.ula.parse().map_err(|e| {
            JoinerError::MalformedPeer(format!("coordinator returned bad ula {:?}: {e}", resp.ula))
        })?;
        tracing::info!(%peer_id, %my_ula, peers = resp.peers.len(), "joiner: registered");

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

        // 5) Seed the session table from the initial roster, dropping
        //    any malformed records with a warning. The table is wired to
        //    a `TunRouteSink` so every successful upsert installs the
        //    peer's `/128` host route (TX scoping); removals tear it
        //    down.
        let route_sink = Arc::new(platform::TunRouteSink::new(iface_name.clone()));
        let sessions = SessionTable::with_route_sink(route_sink);
        let peer_info: Arc<dashmap::DashMap<Ipv6Addr, PeerInfo>> = Arc::default();
        for r in &resp.peers {
            match remote_to_info(r).await {
                Ok(info) => {
                    peer_info.insert(info.ula, info.clone());
                    sessions.upsert(&keypair.private, &info);
                }
                Err(e) => tracing::warn!(error = %e, "joiner: skipping malformed initial peer"),
            }
        }

        // 6) Spawn the background tasks.
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let tasks = spawn_background_tasks(SpawnContext {
            socket: socket.clone(),
            sessions: sessions.clone(),
            tun: tun_arc.clone(),
            client: client.clone(),
            our_private: keypair.private,
            peer_id,
            my_ula,
            heartbeat_interval: config.heartbeat_interval,
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
                self.peer_info.get(&s.ula).map_or_else(
                    || synth_info(&s),
                    |kv| kv.value().clone(),
                )
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
    heartbeat_interval: Duration,
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
        heartbeat_interval,
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
        socket,
        sessions.clone(),
        shutdown_rx.clone(),
    )));

    // SSE consumer. Passes our own `peer_id` so the coordinator returns
    // an ACL-filtered peer stream (spec §5.3 / 5a decision #3).
    {
        let sessions = sessions.clone();
        let our_private = our_private.clone();
        let client = client.clone();
        let shutdown_rx = shutdown_rx.clone();
        tasks.push(tokio::spawn(async move {
            peer_sync::run(client, sessions, our_private, peer_id, shutdown_rx).await;
        }));
    }

    // Heartbeat.
    {
        let shutdown_rx = shutdown_rx.clone();
        tasks.push(tokio::spawn(async move {
            heartbeat::run(
                client,
                sessions,
                our_private,
                peer_id,
                heartbeat_interval,
                shutdown_rx,
            )
            .await;
        }));
    }

    // Stage 2 hole-punch subscriber stub. Currently a no-op loop; once
    // the SSE / event-stream mechanism for `HolePunchInitiate` events
    // lands, swap the body for a real subscriber. The task is spawned
    // now so the joiner's shutdown plumbing already covers it and a
    // future wire-up doesn't need to touch joiner.rs.
    tasks.push(tokio::spawn(async move {
        holepunch::run(peer_id, shutdown_rx).await;
    }));

    tasks
}

/// Default location for the persistent keypair file. Used when the
/// caller passes `keypair_path: None` in [`JoinConfig`]. Falls back to
/// the current directory when `$HOME` is missing (e.g. inside an empty
/// systemd unit env), which is good enough for the smoke-test paths
/// that go through CLI subcommands with explicit `--keypair-path`.
fn default_keypair_path() -> std::path::PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    std::path::PathBuf::from(home).join(".tabbify-mesh").join("keypair")
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
