# Per-App-ULA Cross-Host Routing — Design

> Removes the Phase-1 shortcut (node queries supervisors + proxies via their peer-ULA).
> Goal: an app IS a deterministic mesh address. The node computes
> `derive_app_ula(uuid)` and dials it directly; the mesh delivers to whichever
> supervisor hosts it. This is **new distributed routing** — substrate's Wave-2
> only verified the same-host/loopback case; cross-host was never solved.
>
> This spec is the integration seam. All three repos (tabbify-service-mesh,
> tabbify-service-supervisor, tabbify-service-node) build against it.

## App ULA (unchanged, vendored identically in supervisor + node)
`derive_app_ula(uuid) = fd5a:1f02:<blake3(uuid)[0..6] as 3×u16 BE>::1`. Peer ULAs are `fd5a:1f00:...`; app ULAs are `fd5a:1f02:...` — the prefix distinguishes them.

## Ports
- coordinator control: `3.124.69.92:8888` (unchanged).
- supervisor **control** API: `[peer_ula]:8730` (`/health`, `/v1/apps`, start/stop). Unchanged.
- supervisor **app** traffic: `[app_ula]:8730` — one listener per hosted app, on its own ULA. Same port 8730; the ULA prefix disambiguates control vs app.
- node public: `0.0.0.0:8090`.

---

## Component 1 — Coordinator (tabbify-service-mesh/crates/mesh-coordinator)

Carry per-peer hosted app-ULAs through the control plane. The coordinator stays
**app-agnostic** — it routes opaque `/128`s a peer declares; `derive_app_ula`
lives only in the app layer.

Add `hosted_app_ulas: Vec<String>` (IPv6 literals) to:
- `RegisterRequest` (`http/api.rs`) — `#[serde(default)]`.
- `HeartbeatRequest` (`http/api.rs`) — `#[serde(default)]`. The supervisor sends
  its CURRENT full hosted set on every heartbeat.
- `PeerInfo` (roster entry returned to peers) — `#[serde(default)]`.
- `PeerEntry` (coordinator internal, `roster/coordinator.rs`).
- `PeerJoined` event + a heartbeat-carried update (`roster/events.rs`) — so the
  event-sourced state + replay stay correct.

Behavior:
- On register: store `hosted_app_ulas`.
- On heartbeat: replace the peer's stored set with the heartbeat's set; if it
  changed, broadcast `PeerEvent::Updated(peer.to_info())` (existing SSE path).
- ACL/filter: app-ULAs are advertised to all viewers (same visibility as `ula`).

## Component 2 — Joiner (tabbify-service-mesh/crates/mesh-joiner)

The app-route layer. **Strictly additive** — peer-ULA routing (`by_ula`,
`allowed_ips_for`, `add_peer_route`) is untouched; app-ULA is a parallel path.
All existing tests MUST stay green (E1 cross-NAT, hole-punch).

New PUBLIC API on `Joiner`:
```rust
/// The TUN interface name (for callers that assign app-ULA aliases). None in --no-mesh.
pub fn tun_name(&self) -> Option<String>;

/// SUPERVISOR side: start hosting an app-ULA on THIS node.
/// - adds a local /128 alias on the TUN (platform::assign_app_ula) so inbound
///   packets to app_ula are delivered to a local listener;
/// - records app_ula in the locally-hosted set, which is included in the next
///   register/heartbeat `hosted_app_ulas` (so peers learn to route to us).
pub async fn host_app_ula(&self, app_ula: Ipv6Addr) -> anyhow::Result<()>;

/// Stop hosting: release the alias + drop from the advertised set.
pub async fn unhost_app_ula(&self, app_ula: Ipv6Addr) -> anyhow::Result<()>;
```

Internal (roster-driven, in `coordinator/peer_sync.rs` + `wg/session.rs`):
- The locally-hosted set lives in the joiner; `heartbeat`/`register` payloads
  include it as `hosted_app_ulas`.
- Roster consumer: when a remote peer `P` (peer-ULA `pu`) advertises
  `hosted_app_ulas = [X, …]`, for each app-ULA `X` NEW for `P`:
  1. `platform::add_peer_route(iface, X)` — kernel `/128` route `X → utun`
     (so the OS hands X-bound packets to the joiner on the caller side).
  2. `SessionTable`: record `X → P`'s session in a new secondary index
     `app_routes: DashMap<Ipv6Addr, Ipv6Addr>` (app_ula → peer_ula).
  3. Add `X` to `P`'s `PeerSession.allowed_ips` (so a RESPONSE sourced from `X`
     passes the RX source check — `allowed_ips` is already a `HashSet`).
  When `P` drops `X` (or `P` leaves): reverse all three (release route, unmap,
  remove from allowed_ips).
- `tun_read` dst lookup (`wg/loops.rs`): `sessions.by_ula(dst)` is extended — if
  `dst` is not a peer-ULA, consult `app_routes` → resolve to the peer's session.
  (Keep the peer-ULA fast path first; app_routes is the fallback.)

Data path (cross-host, node → app on supervisor):
```
node app dials [app_ula]:8730
 → node OS: /128 route app_ula→utun  → node joiner tun_read
 → by_ula(app_ula) via app_routes → supervisor's session → WG encap (src=node_ula,dst=app_ula)
 → supervisor joiner RX: allowed_source(node_ula) ✓ → writes inner pkt to supervisor utun
 → supervisor OS: app_ula is a local /128 alias → delivers to [app_ula]:8730 listener
 → response (src=app_ula,dst=node_ula) → supervisor tun_read by_ula(node_ula) → node session → WG
 → node joiner RX: allowed_source(app_ula) ✓ (app_ula ∈ supervisor-session.allowed_ips) → node utun → node app
```

## Component 3 — Supervisor (tabbify-service-supervisor)

- Depends on the joiner's new API (git dep, same rev or a new pinned rev after the mesh change lands).
- On hosting app `U` (per lifecycle always_on / on_request first request):
  - `let app_ula = derive_app_ula(U);`
  - `joiner.host_app_ula(app_ula).await?;`
  - bind an axum listener on `[app_ula]:8730` that serves the WASM for `U`
    (the WHOLE request path → the wasm runtime; no `/apps/<uuid>` prefix — the
    ULA IS the app identity). Reuse the existing `WasmRuntime` + `normalize_uri`.
- On stop / idle-reap (on_request): drop the listener + `joiner.unhost_app_ula(app_ula)`.
- Control API on `[peer_ula]:8730` keeps `/health`, `GET /v1/apps`,
  `GET /v1/apps/:uuid`, `POST /v1/apps/:uuid/{start,stop}` (start now also
  hosts the app-ULA; stop unhosts). API-start still pins.
- `--no-mesh` / loopback test mode: bind apps on `[::1]:port` keyed by a Host
  header (existing pattern) so tests don't need a TUN.

## Component 4 — Node (tabbify-service-node)

- Depends on the joiner's new API (joins mesh; the roster consumer auto-installs
  app-routes when supervisors advertise — no node code needed for that, it's in
  the joiner).
- `ANY /app/:uuid` + `/app/:uuid/*rest` → `app_ula = derive_app_ula(uuid)` →
  **proxy directly** to `http://[app_ula]:8730/<rest>` (method, headers, body,
  query). NO supervisor query, NO cache (the mesh route is the discovery). If the
  dial fails (no host / not routed yet) → 502 with a clear body, or 404 if the
  roster shows no supervisor hosts it.
- `GET /v1/apps` → read the coordinator roster; aggregate `hosted_app_ulas`
  across `supervisor`-tagged peers (the roster now carries them — no per-supervisor
  control call needed for listing). Map app-ULA back to uuid is not possible
  (one-way hash), so `/v1/apps` lists app-ULAs + which supervisor; richer
  metadata (name/version) still comes from a supervisor control call if wanted.
- `GET /v1/supervisors` → roster filtered to `supervisor` tag (unchanged).
- `POST /v1/apps/:uuid/{start,stop}` → resolve a supervisor (roster) → proxy to
  its control API `[peer_ula]:8730` (so an app gets hosted before first dial).
- **Full MCP Streamable-HTTP** at `/mcp`: replace the minimal JSON-RPC with the
  proper Streamable-HTTP transport (use `rmcp` official Rust SDK server +
  streamable-http, with `Mcp-Session-Id`, POST→JSON-or-SSE, GET→SSE). Tools:
  `list_supervisors`, `list_apps`, `get_app{uuid}`, `start_app{uuid}`,
  `stop_app{uuid}` — backed by the same service layer as REST.
- **Streaming proxy**: forward the upstream response body as a stream
  (`reqwest::Response::bytes_stream` → `axum::body::Body::from_stream`), not
  buffered. Strip hop-by-hop headers both ways (already done).

---

## Implementation order + parallelism
Contract-first: this spec locks the seam, so the three repos build in PARALLEL
against it, then integrate.
1. **mesh** (coordinator field + joiner app-route layer) — the foundation; TDD;
   keep ALL existing tests green; additive only.
2. **supervisor** — host app-ULA + bind per-app listener + advertise via joiner.
3. **node** — direct app-ULA proxy + full MCP (rmcp streamable-http) + streaming.
After mesh lands, supervisor/node may need a Cargo rev bump to the new mesh commit.

## Test strategy
- mesh: unit-test `app_routes` lookup + allowed_ips growth + the roster→route
  install/remove logic with fakes; do NOT regress the peer-ULA path (run the
  full existing suite). A loopback two-joiner integration test for app-ULA
  delivery if feasible.
- supervisor: existing WasmRuntime/router tests + a test that hosting an app
  calls `host_app_ula` + binds the per-app listener (loopback mode).
- node: direct-proxy via wiremock on a fake app-ULA listener; MCP
  initialize/tools.list/tools.call over streamable-http; streaming passthrough.

## Risk
Modifies the verified joiner data path. Mitigations: additive (peer-ULA path
untouched), `allowed_ips` is already a set built for this, full TDD, the entire
existing mesh suite must stay green before commit.

## Deferred (still)
Stable peer-ULA (idx churn); node reserved ULA; Firecracker runtime; deploy
(mesh-auth/CI/EC2 — separate phase).
