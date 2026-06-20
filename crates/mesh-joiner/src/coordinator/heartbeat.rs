//! Periodic heartbeat task.
//!
//! Spawned by [`crate::joiner::Joiner::join`] once registration
//! succeeds. The task:
//!
//! 1. Sleeps for `interval`.
//! 2. Calls [`crate::coordinator::client::CoordinatorClient::heartbeat`].
//! 3. Reconciles the returned roster against the local session table —
//!    insertions cover sessions that we missed via SSE, deletions cover
//!    peers the coordinator timed out. This is the "self-heal" path
//!    that lets the joiner stay correct even if the SSE stream is
//!    flaky.
//! 4. Loops.
//!
//! ## Coordinator roster loss (404 recovery)
//!
//! If the coordinator forgets our peer record — it restarted with an
//! empty roster, or timed us out and pruned us while our SSE stream was
//! wedged — a heartbeat for an unknown `peer_id` comes back `404`. A bare
//! retry would loop forever against a coordinator that will never know us
//! again. Instead, on a `404` we perform a FULL re-register (same sticky
//! identity inputs the initial join used), adopt the freshly-assigned
//! `peer_id`, reconcile the roster the register response carries, and
//! resume normal heartbeats. The new `peer_id` is shared (an
//! `Arc<RwLock<Uuid>>`) with the SSE consumer so it reconnects its stream
//! filtered to the LIVE id rather than the dead one. Re-register failures
//! are non-fatal (logged, retried next tick); a one-shot guard makes the
//! re-register fire once per detected `404` transition, not every tick.
//!
//! Cancellation comes through a `tokio_util::sync::CancellationToken`
//! style channel — we use a plain `tokio::sync::watch` to avoid pulling
//! `tokio-util` just for one token.

use crate::coordinator::client::{CoordinatorClient, RegisterResponse, remote_to_info};
use crate::coordinator::command_exec::CommandSink;
use crate::coordinator::command_gate::CommandGate;
use crate::error::JoinerError;
use crate::wg::session::SessionTable;
use dashmap::DashMap;
use std::collections::HashSet;
use std::net::Ipv6Addr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{RwLock, watch};
use uuid::Uuid;
use x25519_dalek::StaticSecret;

/// Mutably-shared coordinator-assigned peer id.
///
/// Shared between the heartbeat task (which can replace it on a 404
/// re-register) and the SSE consumer (which must reconnect its stream
/// filtered to the LIVE id). A `tokio::sync::RwLock` is used over a
/// `std::sync` one because both holders are async and may be polled across
/// `.await` points; reads are short and never held across the network I/O
/// that could deadlock.
pub type SharedPeerId = Arc<RwLock<Uuid>>;

/// Inputs captured for re-registering after a coordinator roster loss.
///
/// The exact arguments [`CoordinatorClient::register`] needs, captured once
/// at spawn time from the already-resolved keypair +
/// [`crate::config::JoinConfig`] so a 404-triggered re-register requests the
/// SAME sticky identity the initial join did — preserving the node's ULA
/// across the coordinator's amnesia.
#[derive(Clone)]
pub struct ReregisterInputs {
    /// Our X25519 public key — the coordinator keys our record by it.
    pub our_public: [u8; 32],
    /// Explicit advertise endpoint override (`None` = reflexive).
    pub advertise_endpoint: Option<String>,
    /// Human-readable display name.
    pub display_name: String,
    /// Role tags (advisory when a join token is present).
    pub tags: Vec<String>,
    /// Node-join JWT, re-sent so a validating coordinator re-authorises us.
    pub join_token: Option<String>,
    /// Sticky ULA to re-request so the coordinator hands us the same
    /// overlay address (identity preservation). `None` = coordinator-derived.
    pub requested_ula: Option<String>,
    /// Runner role metadata (all `None` for a plain peer).
    pub kind: Option<String>,
    /// ULA of the supervisor that owns this runner.
    pub parent: Option<String>,
    /// UUID of the app this runner serves.
    pub app_uuid: Option<String>,
    /// Declare this peer relay-only (no reachable direct endpoint). Re-sent on
    /// every register + heartbeat so the coordinator suppresses our direct
    /// endpoint + hole-punch directives. See [`crate::config::JoinConfig::relay_only`].
    pub relay_only: bool,
}

/// Snapshot the locally-hosted app-ULA set into the wire form
/// (`Vec<String>` of IPv6 literals) the heartbeat advertises. Sorted for
/// deterministic ordering (stable change-detection on the coordinator).
fn hosted_app_ula_strings(hosted: &DashMap<Ipv6Addr, ()>) -> Vec<String> {
    let mut v: Vec<String> = hosted.iter().map(|kv| kv.key().to_string()).collect();
    v.sort();
    v
}

/// Inputs to the heartbeat loop. Bundled into one struct so [`run`]
/// stays under the clippy argument-count cap without an `allow` — same
/// pattern as the joiner's `SpawnContext`.
pub struct HeartbeatTask {
    /// Coordinator HTTP client.
    pub client: Arc<CoordinatorClient>,
    /// Shared session table (reconciled against each heartbeat roster).
    pub sessions: SessionTable,
    /// Our X25519 private key — needed to (re)build peer sessions on
    /// reconcile.
    pub our_private: StaticSecret,
    /// Our coordinator-assigned peer id, shared with the SSE consumer so a
    /// 404 re-register that yields a NEW id is observed by both.
    pub peer_id: SharedPeerId,
    /// Inputs for a full re-register on a coordinator roster loss (404).
    pub reregister: ReregisterInputs,
    /// Our `WireGuard` UDP listen port — re-sent for reflexive refresh.
    pub wg_listen_port: u16,
    /// App-ULAs this node hosts — advertised on every heartbeat
    /// (per-app-ULA routing). Shared with [`crate::Joiner`].
    pub hosted_app_ulas: Arc<DashMap<Ipv6Addr, ()>>,
    /// Software version advertised on every heartbeat (spec P0 OBSERVE).
    /// Host-supplied; `None` = unknown.
    pub software_version: Option<String>,
    /// Mesh-joiner's own version, self-reported on every heartbeat alongside
    /// `software_version`.
    pub mesh_version: Option<String>,
    /// Heartbeat interval.
    pub interval: Duration,
    /// Track C: verify + replay-guard gate for incoming signed commands. A
    /// fail-closed gate (no super-admin pubkey) rejects every command, so a
    /// host that does not configure remote commands simply never acts.
    pub command_gate: CommandGate,
    /// Track C: host-side process-effects sink (`RestartJoiner` / `RebootHost`).
    /// A `NoopCommandSink` for a host that does not wire remote commands.
    pub command_sink: Arc<dyn CommandSink>,
    /// Cancellation signal.
    pub shutdown: watch::Receiver<bool>,
}

/// Per-tick context borrowed from [`HeartbeatTask`]. Keeps [`tick_once`]
/// under the clippy argument-count cap without an `allow`, and lets the
/// unit tests drive a single tick without a real ticker.
pub struct TickCtx<'a> {
    /// Coordinator HTTP client.
    pub client: &'a CoordinatorClient,
    /// Shared session table to reconcile.
    pub sessions: &'a SessionTable,
    /// Our X25519 private key for (re)building sessions.
    pub our_private: &'a StaticSecret,
    /// Shared, mutable peer id — read for the heartbeat, replaced on a
    /// 404 re-register.
    pub peer_id: &'a SharedPeerId,
    /// Inputs for the re-register fallback.
    pub reregister: &'a ReregisterInputs,
    /// Our `WireGuard` UDP listen port.
    pub wg_listen_port: u16,
    /// Locally-hosted app-ULA set advertised this tick.
    pub hosted_app_ulas: &'a DashMap<Ipv6Addr, ()>,
    /// Software version advertised this tick.
    pub software_version: Option<String>,
    /// Mesh-joiner version advertised this tick.
    pub mesh_version: Option<String>,
    /// One-shot guard: set once a 404 has been handled, cleared on the
    /// next successful heartbeat. Stops a thundering herd of re-registers
    /// while the coordinator is still bringing its roster back.
    pub handling_roster_loss: &'a mut bool,
    /// Track C: verify + replay-guard gate (mutated — `mark_executed`).
    pub command_gate: &'a mut CommandGate,
    /// Track C: host-side process-effects sink.
    pub command_sink: &'a dyn CommandSink,
    /// Track C: acks to send on the NEXT heartbeat. `tick_once` first sends the
    /// buffered acks (commands executed LAST tick), then refills the buffer with
    /// the acks for the commands THIS tick's response carried — the at-least-once
    /// heartbeat carrier (≤20s latency is fine for a restart, spec §5).
    pub pending_acks: &'a mut Vec<String>,
}

/// Run the heartbeat loop until `shutdown` flips to `true`.
///
/// Designed to be spawned with `tokio::spawn(run(task))` — does not
/// return until cancelled.
pub async fn run(task: HeartbeatTask) {
    let HeartbeatTask {
        client,
        sessions,
        our_private,
        peer_id,
        reregister,
        wg_listen_port,
        hosted_app_ulas,
        software_version,
        mesh_version,
        interval,
        mut command_gate,
        command_sink,
        mut shutdown,
    } = task;
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Skip the immediate first tick — the initial roster was already
    // installed from the register response.
    ticker.tick().await;

    // One-shot guard so a re-register fires once per detected 404
    // transition rather than on every tick while the coordinator is
    // still re-learning us.
    let mut handling_roster_loss = false;
    // Track C: acks for commands executed on the PREVIOUS tick, carried on the
    // next heartbeat request (the at-least-once carrier).
    let mut pending_acks: Vec<String> = Vec::new();

    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    // Read the id into a local first: holding the lock guard
                    // across the tracing macro's await would make this future
                    // non-Send (the guard isn't Sync).
                    let current = *peer_id.read().await;
                    tracing::debug!(
                        peer_id = %current,
                        "heartbeat: shutdown signalled, exiting"
                    );
                    return;
                }
            }
            _ = ticker.tick() => {
                tick_once(TickCtx {
                    client: &client,
                    sessions: &sessions,
                    our_private: &our_private,
                    peer_id: &peer_id,
                    reregister: &reregister,
                    wg_listen_port,
                    hosted_app_ulas: &hosted_app_ulas,
                    software_version: software_version.clone(),
                    mesh_version: mesh_version.clone(),
                    handling_roster_loss: &mut handling_roster_loss,
                    command_gate: &mut command_gate,
                    command_sink: command_sink.as_ref(),
                    pending_acks: &mut pending_acks,
                })
                .await;
            }
        }
    }
}

/// One heartbeat round-trip + roster reconciliation. Pulled out so unit
/// tests can drive it without waiting on a real ticker.
///
/// `wg_listen_port` is re-sent so the coordinator can refresh our
/// reflexive endpoint if our observed public IP changed.
///
/// `software_version` is re-sent so the control plane observes the host's
/// `actual` version (spec P0). `None` = unknown — the coordinator leaves
/// its stored value untouched.
///
/// On a `404` (coordinator forgot us — roster loss) the heartbeat is
/// converted into a full re-register; see `reregister_after_roster_loss`.
/// Any other error keeps the existing log-and-retry behaviour.
pub async fn tick_once(ctx: TickCtx<'_>) {
    let TickCtx {
        client,
        sessions,
        our_private,
        peer_id,
        reregister,
        wg_listen_port,
        hosted_app_ulas,
        software_version,
        mesh_version,
        handling_roster_loss,
        command_gate,
        command_sink,
        pending_acks,
    } = ctx;

    // Advertise our CURRENT hosted app-ULA set so the coordinator replaces
    // its stored set (per-app-ULA routing — supervisor side).
    let hosted = hosted_app_ula_strings(hosted_app_ulas);
    // Report our live per-peer data paths (connectivity visibility): for
    // each session, direct (p2p) vs relay + staleness. The coordinator
    // aggregates these into per-vantage connectivity. Built from the SAME
    // session table this tick reconciles, stamped with the data-plane clock.
    let peer_paths =
        crate::joiner::peer_paths_from_sessions(sessions, crate::wg::loops::now_micros());
    // Track K keystone: report THIS node's live data-plane health on every
    // heartbeat, stamped with the SAME clock as `peer_paths` above so the two
    // views agree. The coordinator surfaces it (visibility pill / Track V);
    // the local OTA gate (Track D) reads its own value directly.
    let dataplane_healthy = sessions.dataplane_healthy(
        crate::wg::loops::now_micros(),
        crate::joiner::DATAPLANE_RX_SILENCE_THRESHOLD_MICROS,
    );
    let current_id = *peer_id.read().await;
    // Track C: carry the acks for commands executed on the PREVIOUS tick. Taken
    // (drained) before the send — once the coordinator sees them it removes them
    // from the pending queue; if the request fails the acks are re-buffered below
    // so the at-least-once carrier keeps trying.
    let acks_to_send = std::mem::take(pending_acks);
    match client
        .heartbeat(
            current_id,
            Some(wg_listen_port),
            &hosted,
            software_version,
            mesh_version,
            reregister.relay_only,
            peer_paths,
            dataplane_healthy,
            &acks_to_send,
        )
        .await
    {
        Ok(resp) => {
            // A successful heartbeat clears the roster-loss guard so a
            // FUTURE 404 transition is handled again.
            *handling_roster_loss = false;
            reconcile_roster(sessions, our_private, &resp.peers).await;
            // Track C: execute any signed commands the response carried AFTER
            // reconcile (a RestartJoiner/ResetWg acts on the freshly-reconciled
            // session table). The returned acks ride the NEXT heartbeat. A
            // fail-closed gate (no super-admin pubkey) rejects everything, so a
            // host without remote-command wiring is a no-op here.
            if !resp.pending_commands.is_empty() {
                let acks = crate::coordinator::command_exec::process_commands(
                    &resp.pending_commands,
                    command_gate,
                    command_sink,
                    sessions,
                    our_private,
                    reregister.relay_only,
                    crate::wg::loops::now_micros(),
                )
                .await;
                *pending_acks = acks;
            }
        }
        Err(JoinerError::HttpStatus { status: 404, body }) => {
            // The coordinator no longer knows this peer_id — its roster
            // was lost (restart) or it pruned us behind our back. Re-join
            // with the same sticky identity so we get a fresh peer_id +
            // the current roster, instead of retrying a dead id forever.
            if *handling_roster_loss {
                tracing::debug!(
                    peer_id = %current_id,
                    "heartbeat: still recovering from roster loss, skipping duplicate re-register"
                );
                return;
            }
            *handling_roster_loss = true;
            tracing::warn!(
                peer_id = %current_id,
                body = %body,
                "heartbeat: coordinator returned 404 (roster loss) — re-registering"
            );
            reregister_after_roster_loss(
                client,
                sessions,
                our_private,
                peer_id,
                reregister,
                wg_listen_port,
            )
            .await;
        }
        Err(e) => {
            // Track C: the heartbeat that would have carried our acks failed
            // (transient transport error, same peer_id). Re-buffer them so the
            // at-least-once carrier retries the ack on the next tick rather than
            // dropping it (which would let the coordinator re-deliver an
            // already-executed verb). The 404 arm above deliberately does NOT
            // re-buffer: a re-register mints a fresh, empty queue, so stale acks
            // for the old peer_id are correctly discarded.
            if !acks_to_send.is_empty() {
                *pending_acks = acks_to_send;
            }
            tracing::warn!(
                peer_id = %current_id,
                error = %e,
                "heartbeat failed — will retry on next tick"
            );
        }
    }
}

/// Register against the coordinator, transparently self-healing a sticky-ULA
/// `409`.
///
/// Tries `requested_ula` first. A `409` means a DIFFERENT peer holds that ULA
/// — e.g. a node redeploy churned its pubkey so the coordinator minted a new
/// peer record while the STALE old record still pins the sticky ULA, or the
/// coordinator's durable roster was lost on a box-replace and the slot was
/// reallocated. Rather than dead-end on the same conflict, retry ONCE with a
/// FREE allocation (`requested_ula = None`) so the node rejoins at a fresh
/// coordinator-assigned address.
///
/// Shared by BOTH the cold-start (initial [`crate::joiner::Joiner::join`]) and
/// the heartbeat roster-loss re-register paths so a node ALWAYS joins instead
/// of failing the entire join on a 409 (defense in depth alongside the
/// coordinator's adopt-on-stale eviction). The control plane re-derives
/// `software_version` from heartbeats, so the FALLBACK register carries
/// `None`; the first attempt carries the caller-supplied value.
///
/// # Errors
/// Surfaces the underlying [`JoinerError`] when the first attempt fails with
/// anything other than a 409, or when the free-allocation fallback also fails.
pub(crate) async fn register_with_409_fallback(
    client: &CoordinatorClient,
    inputs: &ReregisterInputs,
    wg_listen_port: u16,
    software_version: Option<String>,
    mesh_version: Option<String>,
    requested_ula: Option<String>,
) -> crate::error::Result<RegisterResponse> {
    match register_attempt(
        client,
        inputs,
        wg_listen_port,
        software_version,
        mesh_version,
        requested_ula,
    )
    .await
    {
        Ok(resp) => Ok(resp),
        Err(JoinerError::HttpStatus { status: 409, body }) => {
            tracing::warn!(
                requested_ula = ?inputs.requested_ula,
                body = %body,
                "register: 409 (sticky ULA held by a different/stale peer) — \
                 retrying with a coordinator-allocated address"
            );
            // Fallback carries no version (re-derived from heartbeats) and no
            // requested_ula (free allocation).
            register_attempt(client, inputs, wg_listen_port, None, None, None).await
        }
        Err(e) => Err(e),
    }
}

/// Issue a single `register` from `inputs` with explicit `requested_ula` +
/// `software_version` overrides. Factored out so the sticky-then-free 409
/// fallback can vary both without duplicating the long argument list. The
/// cold-start path forwards a `software_version` so the host version is
/// advertised on the first attempt; the heartbeat path passes `None` (the
/// control plane re-derives it from heartbeats).
async fn register_attempt(
    client: &CoordinatorClient,
    inputs: &ReregisterInputs,
    wg_listen_port: u16,
    software_version: Option<String>,
    mesh_version: Option<String>,
    requested_ula: Option<String>,
) -> crate::error::Result<RegisterResponse> {
    client
        .register(
            &inputs.our_public,
            inputs.advertise_endpoint.clone(),
            Some(wg_listen_port),
            &inputs.display_name,
            &inputs.tags,
            inputs.join_token.as_deref(),
            requested_ula,
            inputs.kind.clone(),
            inputs.parent.clone(),
            inputs.app_uuid.clone(),
            software_version,
            mesh_version,
            inputs.relay_only,
        )
        .await
}

/// Perform a full re-register after a coordinator roster loss, then
/// reconcile the roster the register response carries and adopt the
/// freshly-assigned `peer_id` (shared with the SSE consumer).
///
/// Failure is non-fatal: it is logged and the loop retries on the next
/// tick (the `handling_roster_loss` guard is left set, so the retry
/// happens on the regular cadence rather than as a tight loop).
async fn reregister_after_roster_loss(
    client: &CoordinatorClient,
    sessions: &SessionTable,
    our_private: &StaticSecret,
    peer_id: &SharedPeerId,
    inputs: &ReregisterInputs,
    wg_listen_port: u16,
) {
    // Sticky-then-free 409 self-heal shared with the cold-start path. The
    // control plane re-derives `software_version` from heartbeats, so the
    // re-register carries identity + roster only (`software_version = None`).
    let resp = match register_with_409_fallback(
        client,
        inputs,
        wg_listen_port,
        None,
        None,
        inputs.requested_ula.clone(),
    )
    .await
    {
        Ok(resp) => resp,
        Err(e) => {
            tracing::warn!(
                error = %e,
                "heartbeat: re-register after roster loss failed — will retry next tick"
            );
            return;
        }
    };

    // Adopt the freshly-assigned peer_id so subsequent heartbeats AND the
    // SSE consumer (on its next reconnect) use the LIVE id, not the dead
    // one. Write the lock in its own scope so it is never held across the
    // roster reconcile that follows.
    {
        let mut id = peer_id.write().await;
        *id = resp.peer_id;
    }
    tracing::info!(
        peer_id = %resp.peer_id,
        ula = %resp.ula,
        peers = resp.peers.len(),
        "heartbeat: re-registered after roster loss"
    );

    // Reinstall the roster the coordinator just handed back, reusing the
    // same reconcile path a normal heartbeat would.
    reconcile_roster(sessions, our_private, &resp.peers).await;
}

/// Compute the (insert, delete) deltas between the local session table
/// and the coordinator's roster, then apply them.
///
/// Peers with malformed records are logged and skipped — the joiner
/// keeps running on its last-good view rather than dropping every
/// session over one bad peer.
async fn reconcile_roster(
    sessions: &SessionTable,
    our_private: &StaticSecret,
    remote: &[crate::peer::RemotePeer],
) {
    let mut remote_ulas: HashSet<std::net::Ipv6Addr> = HashSet::new();
    for r in remote {
        match remote_to_info(r).await {
            Ok(info) => {
                remote_ulas.insert(info.ula);
                // Re-peer observability: only log a `reconcile_add` for a
                // peer the heartbeat backfill is learning for the FIRST time
                // (i.e. the SSE stream missed it). A steady-state upsert
                // re-handshakes every tick, so logging those would be pure
                // noise — gate on "no prior session for this ULA" to keep
                // the line low-cardinality and meaningful.
                if sessions.by_ula(info.ula).is_none() {
                    tracing::info!(
                        peer_id = %info.peer_id,
                        ula = %info.ula,
                        endpoint = ?info.listen_endpoint,
                        event = "reconcile_add",
                        "heartbeat: backfilling peer the SSE stream missed"
                    );
                }
                // upsert is a no-op for unchanged endpoints (well — it
                // re-handshakes; we accept that cost for simplicity in
                // MVP). Future work: skip when (peer_id, endpoint,
                // pubkey) match.
                sessions.upsert(our_private, &info);
                // Per-app-ULA routing self-heal: reconcile the peer's
                // advertised app-ULAs even if the SSE stream missed a
                // frame. Same wholesale-replace semantics as peer_sync.
                sessions.reconcile_app_routes(info.ula, &info.hosted_app_ulas);
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "heartbeat: skipping malformed peer record"
                );
            }
        }
    }
    // Anyone in the local table but absent from the coordinator's
    // roster has been timed out or deregistered behind our back.
    for ula in sessions.ulas() {
        if !remote_ulas.contains(&ula) {
            // Re-peer observability: the coordinator no longer lists this
            // ULA, so the SSE `peer_removed` was missed or the peer was
            // timed out behind our back. Capture the peer_id (best-effort
            // from the live session) so the prune correlates with its
            // earlier add by peer_id, not just ULA.
            let peer_id = sessions.by_ula(ula).map(|s| s.peer_id);
            tracing::info!(
                peer_id = ?peer_id,
                %ula,
                event = "reconcile_prune",
                "heartbeat: pruning timed-out peer the SSE stream missed"
            );
            sessions.remove(ula);
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::peer::{PeerInfo, RemotePeer};
    use base64::engine::{Engine as _, general_purpose::STANDARD as B64};
    use std::net::Ipv6Addr;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    use x25519_dalek::PublicKey;

    fn pubkey_b64(n: u8) -> String {
        let secret = StaticSecret::from([n; 32]);
        let public = PublicKey::from(&secret);
        B64.encode(public.as_bytes())
    }

    /// A fail-closed command gate (no super-admin pubkey → rejects every
    /// command) backed by a throwaway nonce sidecar — Track-C wiring for the
    /// heartbeat-loop tests that don't exercise commands.
    fn noop_command_gate() -> (tempfile::TempDir, CommandGate) {
        let dir = tempfile::tempdir().expect("tempdir");
        let gate = CommandGate::new(None, &dir.path().join("nonces.json"));
        (dir, gate)
    }

    fn noop_command_sink() -> std::sync::Arc<crate::coordinator::command_exec::NoopCommandSink> {
        std::sync::Arc::new(crate::coordinator::command_exec::NoopCommandSink)
    }

    fn remote(ula: &str, n: u8) -> RemotePeer {
        RemotePeer {
            peer_id: Uuid::nil(),
            wg_public_key: pubkey_b64(n),
            ula: ula.into(),
            listen_endpoint: Some("127.0.0.1:51820".into()),
            display_name: format!("peer-{n}"),
            tags: vec![],
            hosted_app_ulas: vec![],
            software_version: None,
            mesh_version: None,
            joined_at_micros: 0,
        }
    }

    fn local_info(ula: &str, n: u8) -> PeerInfo {
        let secret = StaticSecret::from([n; 32]);
        PeerInfo {
            peer_id: Uuid::nil(),
            wg_public_key: *PublicKey::from(&secret).as_bytes(),
            ula: ula.parse().unwrap(),
            // Distinct port per peer keeps the endpoint index unique
            // across the test population without burning real OS ports.
            listen_endpoint: Some(
                format!("127.0.0.1:{}", 30_000 + u16::from(n))
                    .parse()
                    .unwrap(),
            ),
            display_name: format!("peer-{n}"),
            tags: vec![],
            hosted_app_ulas: vec![],
            software_version: None,
            mesh_version: None,
            joined_at_micros: 0,
        }
    }

    /// Minimal `ReregisterInputs` for a plain peer — no runner metadata,
    /// no join token, no sticky ULA.
    fn reregister_inputs() -> ReregisterInputs {
        ReregisterInputs {
            our_public: [0xAB; 32],
            advertise_endpoint: None,
            display_name: "test-peer".into(),
            tags: vec![],
            join_token: None,
            requested_ula: None,
            kind: None,
            parent: None,
            app_uuid: None,
            relay_only: false,
        }
    }

    /// Track C end-to-end (joiner side): tick 1's heartbeat response carries a
    /// signed `RestartJoiner`; the gate accepts it, the sink fires, and tick 2's
    /// heartbeat REQUEST carries the `executed_command_ids` ack. A wiremock
    /// `body_partial_json` matcher mounted with `.expect(1)` proves the ack rode
    /// the next request (verified on server drop).
    #[tokio::test]
    async fn tick_executes_command_and_acks_on_next_request() {
        use crate::coordinator::command::{CommandVerb, NodeCommand};
        use crate::coordinator::command_exec::CommandSink;
        use ed25519_dalek::SigningKey;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use wiremock::matchers::body_partial_json;

        #[derive(Default)]
        struct CountingSink {
            restarts: AtomicUsize,
        }
        impl CommandSink for CountingSink {
            fn restart_joiner(&self) {
                self.restarts.fetch_add(1, Ordering::SeqCst);
            }
            fn reboot_host(&self) {}
        }

        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let command_id = Uuid::now_v7();
        let signed = NodeCommand::new(
            command_id,
            CommandVerb::RestartJoiner,
            Uuid::nil().to_string(),
            "n-tickC".to_owned(),
            1,
            i64::MAX,
        )
        .signed_by(&sk);

        let server = MockServer::start().await;
        // Tick 1: a heartbeat with NO acks → respond with the signed command.
        Mock::given(method("POST"))
            .and(path("/v1/mesh/heartbeat"))
            .and(body_partial_json(
                serde_json::json!({ "executed_command_ids": [command_id.to_string()] }),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "peers": []
            })))
            .expect(1)
            .mount(&server)
            .await;
        // Default heartbeat response (tick 1 + any request without the ack):
        // carry the pending command so the joiner executes it this tick.
        Mock::given(method("POST"))
            .and(path("/v1/mesh/heartbeat"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "peers": [],
                "pending_commands": [serde_json::to_value(&signed).unwrap()]
            })))
            .mount(&server)
            .await;

        let client = CoordinatorClient::new(server.uri(), None, None, None, true).unwrap();
        let sessions = SessionTable::new();
        let me = StaticSecret::from([0xAA; 32]);
        let peer_id: SharedPeerId = Arc::new(RwLock::new(Uuid::nil()));
        let hosted: DashMap<Ipv6Addr, ()> = DashMap::new();
        let inputs = reregister_inputs();
        let mut handling_roster_loss = false;
        let nonce_dir = tempfile::tempdir().unwrap();
        let mut command_gate = CommandGate::new(
            Some(sk.verifying_key().to_bytes()),
            &nonce_dir.path().join("nonces.json"),
        );
        let sink = Arc::new(CountingSink::default());
        let command_sink: Arc<dyn CommandSink> = sink.clone();
        let mut pending_acks: Vec<String> = Vec::new();

        // Tick 1: executes the command, buffers the ack.
        tick_once(TickCtx {
            client: &client,
            sessions: &sessions,
            our_private: &me,
            peer_id: &peer_id,
            reregister: &inputs,
            wg_listen_port: 51820,
            hosted_app_ulas: &hosted,
            software_version: None,
            mesh_version: None,
            handling_roster_loss: &mut handling_roster_loss,
            command_gate: &mut command_gate,
            command_sink: command_sink.as_ref(),
            pending_acks: &mut pending_acks,
        })
        .await;
        assert_eq!(sink.restarts.load(Ordering::SeqCst), 1, "command executed");
        assert_eq!(
            pending_acks,
            vec![command_id.to_string()],
            "ack buffered for the next tick"
        );

        // Tick 2: sends the buffered ack — the `.expect(1)` ack mock matches.
        tick_once(TickCtx {
            client: &client,
            sessions: &sessions,
            our_private: &me,
            peer_id: &peer_id,
            reregister: &inputs,
            wg_listen_port: 51820,
            hosted_app_ulas: &hosted,
            software_version: None,
            mesh_version: None,
            handling_roster_loss: &mut handling_roster_loss,
            command_gate: &mut command_gate,
            command_sink: command_sink.as_ref(),
            pending_acks: &mut pending_acks,
        })
        .await;
        // The ack-matching mock (`.expect(1)`) is verified on drop.
        drop(server);
    }

    /// `reconcile_roster` must add peers that the coordinator advertises
    /// but we don't have locally.
    #[tokio::test]
    async fn reconcile_adds_new_peers() {
        let sessions = SessionTable::new();
        let me = StaticSecret::from([0xAA; 32]);
        let remote = vec![remote("fd5a:1f00:1::1", 1), remote("fd5a:1f00:1::2", 2)];
        reconcile_roster(&sessions, &me, &remote).await;
        assert!(
            sessions
                .by_ula("fd5a:1f00:1::1".parse::<Ipv6Addr>().unwrap())
                .is_some()
        );
        assert!(
            sessions
                .by_ula("fd5a:1f00:1::2".parse::<Ipv6Addr>().unwrap())
                .is_some()
        );
        assert_eq!(sessions.len(), 2);
    }

    /// `reconcile_roster` must drop local peers that aren't in the
    /// coordinator's response — that's how timeouts get cleaned up.
    #[tokio::test]
    async fn reconcile_prunes_local_peers_absent_from_response() {
        let sessions = SessionTable::new();
        let me = StaticSecret::from([0xAA; 32]);
        sessions.upsert(&me, &local_info("fd5a:1f00:1::1", 1));
        sessions.upsert(&me, &local_info("fd5a:1f00:1::2", 2));
        // The coordinator only knows about ::1 now — ::2 should be
        // pruned.
        reconcile_roster(&sessions, &me, &[remote("fd5a:1f00:1::1", 1)]).await;
        assert!(
            sessions
                .by_ula("fd5a:1f00:1::1".parse::<Ipv6Addr>().unwrap())
                .is_some()
        );
        assert!(
            sessions
                .by_ula("fd5a:1f00:1::2".parse::<Ipv6Addr>().unwrap())
                .is_none()
        );
    }

    /// A malformed peer record should be skipped, not crash the
    /// reconciliation. Good peers in the same batch still apply.
    #[tokio::test]
    async fn reconcile_skips_malformed_records() {
        let sessions = SessionTable::new();
        let me = StaticSecret::from([0xAA; 32]);
        let mut bad = remote("oops-not-ipv6", 1);
        bad.ula = "not-an-ipv6".into();
        let good = remote("fd5a:1f00:1::5", 5);
        reconcile_roster(&sessions, &me, &[bad, good]).await;
        assert!(
            sessions
                .by_ula("fd5a:1f00:1::5".parse::<Ipv6Addr>().unwrap())
                .is_some()
        );
        assert_eq!(sessions.len(), 1);
    }

    /// S bug#2: a heartbeat that comes back `404` (the coordinator lost
    /// our roster entry) must trigger a FULL re-register — not a bare
    /// retry — and then reinstall the roster the register response
    /// carries. Proven by:
    ///
    /// * the register mock being hit exactly once,
    /// * the local session table containing the peer from the REGISTER
    ///   roster (a bare retry would never reach register, so the table
    ///   would stay empty),
    /// * the shared `peer_id` being replaced by the coordinator's freshly
    ///   assigned id (so the SSE consumer reconnects to the live id).
    #[tokio::test]
    async fn heartbeat_404_triggers_reregister_and_roster_reinstall() {
        let server = MockServer::start().await;

        // (a) Every heartbeat returns 404 — the coordinator forgot us.
        Mock::given(method("POST"))
            .and(path("/v1/mesh/heartbeat"))
            .respond_with(ResponseTemplate::new(404).set_body_string("unknown peer_id"))
            .mount(&server)
            .await;

        // (b) Exactly one register, returning a fresh peer_id + a one-peer
        //     roster.
        let new_peer_id = "01910f10-0000-7000-8000-0000000000aa";
        let roster_peer_ula = "fd5a:1f00:9::7";
        let register_body = serde_json::json!({
            "peer_id": new_peer_id,
            "ula": "fd5a:1f00:9::1",
            "peers": [
                {
                    "peer_id": "01910f10-0000-7000-8000-0000000000bb",
                    "wg_public_key": pubkey_b64(7),
                    "ula": roster_peer_ula,
                    "listen_endpoint": "127.0.0.1:51999",
                    "display_name": "roster-peer",
                    "tags": [],
                    "joined_at_micros": 0
                }
            ]
        });
        Mock::given(method("POST"))
            .and(path("/v1/mesh/register"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/json")
                    .set_body_json(register_body),
            )
            .expect(1)
            .mount(&server)
            .await;

        let client = CoordinatorClient::new(server.uri(), None, None, None, true).unwrap();
        let sessions = SessionTable::new();
        let me = StaticSecret::from([0xAA; 32]);
        let original_id = Uuid::nil();
        let peer_id: SharedPeerId = Arc::new(RwLock::new(original_id));
        let hosted: DashMap<Ipv6Addr, ()> = DashMap::new();
        let inputs = reregister_inputs();
        let mut handling_roster_loss = false;
        let (_nonce_dir, mut command_gate) = noop_command_gate();
        let command_sink = noop_command_sink();
        let mut pending_acks: Vec<String> = Vec::new();

        // Drive a single tick: heartbeat -> 404 -> re-register -> reconcile.
        tick_once(TickCtx {
            client: &client,
            sessions: &sessions,
            our_private: &me,
            peer_id: &peer_id,
            reregister: &inputs,
            wg_listen_port: 51820,
            hosted_app_ulas: &hosted,
            software_version: None,
            mesh_version: None,
            handling_roster_loss: &mut handling_roster_loss,
            command_gate: &mut command_gate,
            command_sink: command_sink.as_ref(),
            pending_acks: &mut pending_acks,
        })
        .await;

        // The peer from the REGISTER roster is now installed — proves the
        // 404 path re-registered AND reinstalled the roster, not a bare
        // retry (which would leave the table empty).
        assert!(
            sessions
                .by_ula(roster_peer_ula.parse::<Ipv6Addr>().unwrap())
                .is_some(),
            "register-roster peer must be installed after a 404 re-register"
        );
        assert_eq!(sessions.len(), 1);

        // The shared peer_id was adopted from the register response, so the
        // SSE consumer will reconnect filtered to the live id.
        assert_eq!(
            *peer_id.read().await,
            Uuid::parse_str(new_peer_id).unwrap(),
            "shared peer_id must adopt the coordinator's freshly assigned id"
        );

        // The guard is set so a duplicate re-register won't fire next tick.
        assert!(handling_roster_loss, "roster-loss guard must be set");

        // The register `.expect(1)` is verified on server drop — a second
        // re-register inside this single tick would trip it.
        drop(server);
    }

    /// The one-shot guard must stop a thundering herd: while
    /// `handling_roster_loss` is already set, a second 404 tick must NOT
    /// re-register again. The register mock is mounted with `.expect(0)`.
    #[tokio::test]
    async fn second_404_tick_does_not_reregister_while_guard_set() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/mesh/heartbeat"))
            .respond_with(ResponseTemplate::new(404).set_body_string("unknown"))
            .mount(&server)
            .await;
        // If this is ever hit while the guard is set, the test fails.
        Mock::given(method("POST"))
            .and(path("/v1/mesh/register"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "peer_id": "01910f10-0000-7000-8000-0000000000cc",
                "ula": "fd5a:1f00:9::1",
                "peers": []
            })))
            .expect(0)
            .mount(&server)
            .await;

        let client = CoordinatorClient::new(server.uri(), None, None, None, true).unwrap();
        let sessions = SessionTable::new();
        let me = StaticSecret::from([0xAA; 32]);
        let peer_id: SharedPeerId = Arc::new(RwLock::new(Uuid::nil()));
        let hosted: DashMap<Ipv6Addr, ()> = DashMap::new();
        let inputs = reregister_inputs();
        // Guard already set — simulates a re-register in flight from a
        // prior tick.
        let mut handling_roster_loss = true;
        let (_nonce_dir, mut command_gate) = noop_command_gate();
        let command_sink = noop_command_sink();
        let mut pending_acks: Vec<String> = Vec::new();

        tick_once(TickCtx {
            client: &client,
            sessions: &sessions,
            our_private: &me,
            peer_id: &peer_id,
            reregister: &inputs,
            wg_listen_port: 51820,
            hosted_app_ulas: &hosted,
            software_version: None,
            mesh_version: None,
            handling_roster_loss: &mut handling_roster_loss,
            command_gate: &mut command_gate,
            command_sink: command_sink.as_ref(),
            pending_acks: &mut pending_acks,
        })
        .await;

        // Still set — a guarded tick is a no-op for the register endpoint.
        assert!(handling_roster_loss);
        drop(server);
    }

    /// A non-404 error must keep the existing log-and-retry behaviour:
    /// no re-register, the session table is untouched, and the guard is
    /// NOT set (so a later genuine 404 still triggers recovery).
    #[tokio::test]
    async fn heartbeat_non_404_error_does_not_reregister() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/mesh/heartbeat"))
            .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/mesh/register"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "peer_id": "01910f10-0000-7000-8000-0000000000dd",
                "ula": "fd5a:1f00:9::1",
                "peers": []
            })))
            .expect(0)
            .mount(&server)
            .await;

        let client = CoordinatorClient::new(server.uri(), None, None, None, true).unwrap();
        let sessions = SessionTable::new();
        let me = StaticSecret::from([0xAA; 32]);
        let original_id = Uuid::nil();
        let peer_id: SharedPeerId = Arc::new(RwLock::new(original_id));
        let hosted: DashMap<Ipv6Addr, ()> = DashMap::new();
        let inputs = reregister_inputs();
        let mut handling_roster_loss = false;
        let (_nonce_dir, mut command_gate) = noop_command_gate();
        let command_sink = noop_command_sink();
        let mut pending_acks: Vec<String> = Vec::new();

        tick_once(TickCtx {
            client: &client,
            sessions: &sessions,
            our_private: &me,
            peer_id: &peer_id,
            reregister: &inputs,
            wg_listen_port: 51820,
            hosted_app_ulas: &hosted,
            software_version: None,
            mesh_version: None,
            handling_roster_loss: &mut handling_roster_loss,
            command_gate: &mut command_gate,
            command_sink: command_sink.as_ref(),
            pending_acks: &mut pending_acks,
        })
        .await;

        assert_eq!(sessions.len(), 0, "non-404 error must not touch sessions");
        assert_eq!(
            *peer_id.read().await,
            original_id,
            "non-404 error must not change the peer_id"
        );
        assert!(
            !handling_roster_loss,
            "non-404 error must not set the roster-loss guard"
        );
        drop(server);
    }

    /// Cold-start (initial join) self-heal: the FIRST `register` returns a
    /// 409 (sticky ULA held by a stale peer the coordinator hasn't evicted
    /// yet) → the shared fallback helper retries ONCE with no `requested_ula`
    /// and joins at a coordinator-allocated address. This is the cold-start
    /// counterpart of the heartbeat 409 fallback — both call the same helper,
    /// so a node ALWAYS joins instead of dead-ending on a 409 at boot.
    #[tokio::test]
    async fn cold_start_register_409_retries_without_requested_ula_and_joins() {
        use wiremock::matchers::body_partial_json;
        let server = MockServer::start().await;
        // Sticky register (carries `requested_ula`) → 409 Conflict.
        Mock::given(method("POST"))
            .and(path("/v1/mesh/register"))
            .and(body_partial_json(serde_json::json!({
                "requested_ula": "fd5a:1f00:0:5::1"
            })))
            .respond_with(
                ResponseTemplate::new(409).set_body_string("requested ULA already claimed"),
            )
            .expect(1)
            .mount(&server)
            .await;
        // Free-allocation register (no `requested_ula`) → 200 with a roster.
        let new_peer_id = "01910f10-0000-7000-8000-00000000c01d";
        let assigned_ula = "fd5a:1f00:0:42::1";
        Mock::given(method("POST"))
            .and(path("/v1/mesh/register"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "peer_id": new_peer_id,
                "ula": assigned_ula,
                "peers": []
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = CoordinatorClient::new(server.uri(), None, None, None, true).unwrap();
        let inputs = ReregisterInputs {
            requested_ula: Some("fd5a:1f00:0:5::1".into()),
            ..reregister_inputs()
        };

        // The shared cold-start helper: sticky 409 → retry free → 200.
        let resp = register_with_409_fallback(
            &client,
            &inputs,
            51820,
            None,
            None,
            inputs.requested_ula.clone(),
        )
        .await
        .expect("cold-start register must self-heal past a sticky 409");

        assert_eq!(
            resp.peer_id,
            Uuid::parse_str(new_peer_id).unwrap(),
            "after a sticky 409 the cold-start join adopts the free-allocation peer_id"
        );
        assert_eq!(resp.ula, assigned_ula);
        // Both `.expect(1)` verified on drop: one sticky 409 + one free 200.
        drop(server);
    }

    /// A sticky-ULA `409` on re-register must NOT crash-loop: the joiner falls
    /// back to a coordinator-allocated address (no `requested_ula`) and adopts
    /// the freshly-assigned `peer_id`. Defensive for the residual case where the
    /// coordinator's durable roster was lost and the sticky slot was reused.
    #[tokio::test]
    async fn sticky_ula_409_falls_back_to_free_allocation() {
        use wiremock::matchers::body_partial_json;
        let server = MockServer::start().await;
        // Heartbeat 404 → triggers the re-register path.
        Mock::given(method("POST"))
            .and(path("/v1/mesh/heartbeat"))
            .respond_with(ResponseTemplate::new(404).set_body_string("unknown peer"))
            .mount(&server)
            .await;
        // Sticky register (carries `requested_ula`) → 409 Conflict. Mounted
        // FIRST + matched by the `requested_ula` in the body. wiremock matches
        // mounts in order (first-mounted wins ties), so this specific mock
        // catches the sticky attempt; the fallback (no `requested_ula`) falls
        // through to the catch-all below.
        Mock::given(method("POST"))
            .and(path("/v1/mesh/register"))
            .and(body_partial_json(serde_json::json!({
                "requested_ula": "fd5a:1f00:0:5::1"
            })))
            .respond_with(
                ResponseTemplate::new(409).set_body_string("requested ULA already claimed"),
            )
            .expect(1)
            .mount(&server)
            .await;
        // Free-allocation register (no `requested_ula`) → 200 with a roster.
        let new_peer_id = "01910f10-0000-7000-8000-00000000beef";
        Mock::given(method("POST"))
            .and(path("/v1/mesh/register"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "peer_id": new_peer_id,
                "ula": "fd5a:1f00:0:42::1",
                "peers": []
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = CoordinatorClient::new(server.uri(), None, None, None, true).unwrap();
        let sessions = SessionTable::new();
        let me = StaticSecret::from([0xAA; 32]);
        let peer_id: SharedPeerId = Arc::new(RwLock::new(Uuid::nil()));
        let hosted: DashMap<Ipv6Addr, ()> = DashMap::new();
        let inputs = ReregisterInputs {
            requested_ula: Some("fd5a:1f00:0:5::1".into()),
            ..reregister_inputs()
        };
        let mut handling_roster_loss = false;
        let (_nonce_dir, mut command_gate) = noop_command_gate();
        let command_sink = noop_command_sink();
        let mut pending_acks: Vec<String> = Vec::new();

        tick_once(TickCtx {
            client: &client,
            sessions: &sessions,
            our_private: &me,
            peer_id: &peer_id,
            reregister: &inputs,
            wg_listen_port: 51820,
            hosted_app_ulas: &hosted,
            software_version: None,
            mesh_version: None,
            handling_roster_loss: &mut handling_roster_loss,
            command_gate: &mut command_gate,
            command_sink: command_sink.as_ref(),
            pending_acks: &mut pending_acks,
        })
        .await;

        // The fallback (free-allocation) register succeeded → its peer_id was
        // adopted, proving the 409 did NOT dead-end the re-register.
        assert_eq!(
            *peer_id.read().await,
            Uuid::parse_str(new_peer_id).unwrap(),
            "after a sticky 409, the joiner must adopt the free-allocation peer_id"
        );
        assert!(handling_roster_loss, "roster-loss guard set after recovery");
        // Both register `.expect(1)` are verified on drop: exactly one sticky
        // attempt (409) + one free-allocation fallback (200).
        drop(server);
    }
}
