# NAT Traversal + Zero-Config Endpoint Discovery (Stage 2 — cone NAT)

Status: implemented (2026-05-25)
Scope: `tabbify-service-mesh` (mesh-coordinator + mesh-joiner)

## Problem

Peers behind NAT could not reach each other. The joiner auto-detected its
WireGuard `listen_endpoint` from its locally bound socket, which is
typically `0.0.0.0:<port>` (substituted to `127.0.0.1:<port>`) or a LAN
address — none of which any off-host peer can dial. Confirmed live: a node
advertised `127.0.0.1:49046`. The manual `--advertise-endpoint` override
required an operator to find and type their public IP, which is error-prone
(a dropped digit produced `:5182` instead of `:51820`) and impossible
behind NAT where the public mapping isn't locally knowable.

## Goal

Peers discover their reachable endpoint automatically via the coordinator
(no manual `--advertise-endpoint`), and peers behind common (cone) NATs can
establish WireGuard tunnels and `ping6` each other over their mesh ULAs.

## Approach: coordinator reflexive-address reflection

The coordinator already terminates every peer's register/heartbeat HTTP
request and (via `into_make_service_with_connect_info::<SocketAddr>()`) can
read the request's source socket address — which, for a NAT'd peer, is the
**NAT's public IP**. That is half of the peer's reflexive endpoint. The
other half is the peer's **WireGuard UDP listen port**, which the joiner
now reports in the request body.

The coordinator combines them: `reflexive = <observed-public-ip>:<reported-wg-port>`.

### The port nuance (critical)

The HTTP connection's **source IP** is the NAT's public IP — correct and
reusable. But the HTTP **source port** is the TCP port the NAT mapped for
the *control-plane* connection; it is unrelated to the UDP port the NAT
mapped for WireGuard. So the coordinator must NOT read the WG port off the
HTTP connection — it uses the joiner-reported `wg_listen_port`.

Pairing `<observed-public-ip>:<reported-wg-port>` is correct when:

- the host is directly reachable (public IP, no NAT), or
- the NAT is **full-cone** or otherwise **port-preserving** — it maps the
  internal UDP port to the *same* external port and, once a mapping exists,
  accepts inbound from any source.

It is **wrong** for **symmetric** / **port-randomizing** NAT, where the
external UDP port differs from the internal one and varies per destination.
That case is OUT OF SCOPE here — see "Deferred (Stage 3)" below.

### Decision table (coordinator, pure logic in `nat::reflexive`)

Given the joiner's self-reported endpoint, the observed source addr, and
the reported WG port, the stored `listen_endpoint` is resolved as
(first match wins):

1. self-reported endpoint is a **public** IP literal, or a **hostname**
   (anything not parseable as a socket addr) → keep it verbatim, marked
   **not reflexive** (sticky). This preserves an explicit
   `--advertise-endpoint`.
2. observed source IP is **public** and a WG port was reported → store the
   reflexive `<observed-public-ip>:<wg-port>`, marked **reflexive**.
3. otherwise → keep the self-report (possibly a loopback fallback for
   same-host smoke tests, possibly `None`), marked **not reflexive**.

"Public" is classified explicitly (not via the still-unstable
`IpAddr::is_global`): loopback, RFC1918 private, link-local, CGNAT
(100.64.0.0/10), the unspecified address, IPv6 ULA (fc00::/7) and IPv6
link-local (fe80::/10) are all treated as unreachable-for-peers.

### Reflexive vs sticky (endpoint roaming on heartbeat)

A heartbeat carries **no** `listen_endpoint` self-report (only `peer_id` +
`wg_listen_port`), so the coordinator must know whether a stored endpoint
came from reflection or from an explicit advertisement. The roster entry
carries an `endpoint_is_reflexive` flag for exactly this:

- a **reflexive** (or absent) endpoint is recomputed from each heartbeat's
  observed public IP — so it **roams** when the peer's NAT public IP
  changes (NAT rebind), and a peer that started passive becomes reachable
  once a public source is first seen;
- a **sticky explicit** endpoint (public IP / hostname the operator chose)
  is never clobbered by a heartbeat's observed source.

A non-reflexive **loopback / private** endpoint is treated as a fallback,
not an advertisement, so it remains eligible for reflexive promotion (keeps
the behaviour independent of whether the first register happened to carry
connect-info).

## Wire-format additions (back-compatible — all `#[serde(default)]`)

Request fields added:

- `RegisterRequest.wg_listen_port: Option<u16>`
- `HeartbeatRequest.wg_listen_port: Option<u16>`

Response fields added (skipped when `None`):

- `RegisterResponse.observed_ip: Option<String>` — the peer's own observed
  external IP (its NAT public IP), echoed back.
- `RegisterResponse.observed_endpoint: Option<String>` — the reflexive
  endpoint the coordinator stored for it (what other peers will dial).
- `HeartbeatResponse.observed_ip` / `observed_endpoint` — same, refreshed.

Existing register/heartbeat/roster JSON is unchanged otherwise; an older
joiner that omits `wg_listen_port` degrades to its prior behaviour (the
self-reported endpoint is used verbatim), and an older coordinator that
omits the observed fields parses cleanly on the joiner (they default to
`None`).

## Joiner changes (auto-endpoint)

- **Default WG port 51820** when `--listen-port` is unset (was OS-picked
  ephemeral), falling back to an OS-picked port only if 51820 is busy. A
  stable, predictable port is what makes reflexive discovery work across a
  cone NAT (the advertised port matches the port-preserving NAT mapping).
- **No more loopback auto-advertisement.** When no explicit
  `--advertise-endpoint` is given, the joiner sends **no** `listen_endpoint`
  and lets the coordinator reflect. `--advertise-endpoint` still wins when
  set (explicit override, e.g. a non-matching port-forward or a hostname).
- The joiner reports `wg_listen_port` on register **and** every heartbeat,
  and logs the coordinator-returned `observed_ip` / `observed_endpoint`.

## WireGuard keepalive + endpoint roaming

- **Persistent-keepalive 25s** on every peer session
  (`WG_PERSISTENT_KEEPALIVE_SECS`), so the NAT's UDP mapping for the WG
  socket stays open between sparse data packets and boringtun's roaming has
  live traffic to latch onto. (This was already present; it is now a named
  constant with a pinning test.)
- **Endpoint roaming** is handled by the UDP receive loop: a datagram from
  an unknown source addr is tried against each session's `Tunn`; on a
  successful decapsulate the source is learned (`SessionTable::learn_endpoint`).
  A passive peer (no advertised endpoint) adopts the learned source as its
  outbound default; an active peer keeps its advertised endpoint as the
  outbound default but indexes the new source for inbound demux + response
  targeting (standard WireGuard roaming). Locked in with unit tests.

## End-to-end flow

```
joiner bind UDP :51820
  → POST /v1/mesh/register { wg_listen_port: 51820, (no listen_endpoint) }
      coordinator reads source IP = <NAT public IP> from ConnectInfo
      stores listen_endpoint = <NAT public IP>:51820 (reflexive)
      responds { observed_ip, observed_endpoint, peers: [...] }
  → other peers learn <NAT public IP>:51820 via roster (register resp / SSE / heartbeat)
  → WireGuard handshake to that endpoint; cone NAT maps :51820 → same external port
  → persistent-keepalive keeps the mapping open; roaming follows port changes
  → ping6 over mesh ULAs works
```

## Limitations

- **Cone / port-preserving NAT only.** Symmetric / port-randomizing NAT
  presents a *different* external UDP port per destination, so the
  `<observed-ip>:<wg-port>` pair is wrong for it. Direct dialing fails;
  those peers need Stage 3 (below). The operator can still use
  `--advertise-endpoint` for a manual port-forward.
- The reflexive *rewrite* itself cannot be exercised over a loopback test
  connection (the observed IP is private), so it is verified by coordinator
  unit tests that inject a synthetic public observed `SocketAddr`; the HTTP
  layer (the new request/response fields) is covered by integration tests.
- Live cross-NAT verification is performed by the operator out-of-band.

## Deferred (Stage 3 — symmetric NAT / relay)

Out of scope for this iteration; left as a clear follow-up:

1. **STUN from the WireGuard UDP socket.** To learn the *WG* NAT mapping
   (not the TCP control-plane one), the joiner must STUN from its own WG
   UDP socket and report the STUN-observed `ip:port`. This makes the
   reflexive port correct under address-dependent mappings, and improves
   accuracy for some symmetric NATs.
2. **UDP hole punching.** A coordinator-driven simultaneous-open. The
   protocol shape already exists as a skeleton: the coordinator emits a
   pair of `HolePunchInitiate` events (one per peer, initiator/target
   swapped) once both peers have a known observed external addr
   (`nat::holepunch`), and the joiner has a subscriber stub
   (`mesh-joiner::nat::holepunch`). The real timing/retry state machine and
   the event-delivery wire (an SSE extension or a sibling stream) are TODO.
3. **Relay fallback (TURN-like).** For symmetric-to-symmetric pairs that
   hole punching can't solve, relay WireGuard UDP through the coordinator
   or a dedicated relay. Not designed yet.

## Touched code

- `crates/mesh-coordinator/src/nat/reflexive.rs` — new pure decision module
  (`resolve_listen_endpoint`, `is_public`, `is_sticky_explicit_endpoint`).
- `crates/mesh-coordinator/src/http/api.rs` — request/response fields;
  `register_handler` reads `ConnectInfo`; both handlers echo observed
  fields.
- `crates/mesh-coordinator/src/roster/coordinator.rs` — register/heartbeat
  apply the reflexive endpoint; `endpoint_is_reflexive` flag;
  `refresh_reflexive_endpoint` (heartbeat roaming).
- `crates/mesh-coordinator/src/roster/apply.rs` — `endpoint_is_reflexive`
  default.
- `crates/mesh-joiner/src/joiner.rs` — default WG port 51820 +
  `bind_udp_with_fallback`; stop auto-advertising loopback; report port.
- `crates/mesh-joiner/src/coordinator/client.rs` — request/response fields.
- `crates/mesh-joiner/src/coordinator/heartbeat.rs` — thread the WG port.
- `crates/mesh-joiner/src/wg/session.rs` — keepalive constant; roaming
  tests.
- `tools/tabbify-mesh/src/cli.rs`, `crates/mesh-joiner/src/config.rs` — doc
  updates for the new auto-discovery behaviour.
