//! HTTP client wrapper around the `mesh-coordinator` REST surface.
//!
//! The coordinator exposes four endpoints; we model each one with a
//! dedicated method so the joiner doesn't have to remember URL paths or
//! deal with `serde_json::Value` shapes. SSE consumption lives in
//! [`crate::coordinator::peer_sync`] — this module is request/response
//! only.
//!
//! # Wire contract (mirrored from the dispatch spec)
//!
//! | Method | Path                       | Body                                  | Returns                |
//! |--------|----------------------------|---------------------------------------|------------------------|
//! | POST   | `/v1/mesh/register`        | [`RegisterRequest`]                   | [`RegisterResponse`]   |
//! | POST   | `/v1/mesh/heartbeat`       | [`HeartbeatRequest`]                  | [`HeartbeatResponse`]  |
//! | POST   | `/v1/mesh/deregister`      | [`DeregisterRequest`]                 | `204 No Content`       |
//! | GET    | `/v1/mesh/peers/stream`    | —                                     | SSE — see `peer_sync`  |
//!
//! All bodies are JSON. The `wg_public_key` field is base64 (standard
//! padded). ULAs and listen endpoints are textual.

use crate::error::{JoinerError, Result};
use crate::peer::{PeerInfo, RemotePeer};
use base64::engine::{Engine as _, general_purpose::STANDARD as B64};
use serde::{Deserialize, Serialize};
use std::net::{Ipv6Addr, SocketAddr};
use std::path::Path;
use uuid::Uuid;

/// Body of `POST /v1/mesh/register`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterRequest {
    /// 32-byte X25519 public key, base64-encoded.
    pub wg_public_key: String,
    /// Locally-known UDP listen address, if any. With reflexive endpoint
    /// discovery this is usually `None` — the joiner lets the coordinator
    /// derive the reachable endpoint from the observed source IP + the
    /// `wg_listen_port` below. Set only when the operator passed an
    /// explicit `--advertise-endpoint` override.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen_endpoint: Option<String>,
    /// UDP port our `WireGuard` socket is bound to. Sent so the coordinator
    /// can synthesize our reflexive endpoint (`<observed-ip>:<port>`) for
    /// cone-NAT traversal without a manual `--advertise-endpoint`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wg_listen_port: Option<u16>,
    /// Human-readable display name.
    pub display_name: String,
    /// Role tags ("dev-machine", "wasm-host", ...).
    pub tags: Vec<String>,
    /// App-ULAs (IPv6 literals, `fd5a:1f02:...`) this node hosts at
    /// register time. Usually empty — apps are typically hosted after
    /// join via [`crate::Joiner::host_app_ula`], which advertises them on
    /// the next heartbeat. Omitted from the wire when empty for a tidy
    /// body (per-app-ULA routing).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hosted_app_ulas: Vec<String>,
    /// Explicit IPv6 ULA the peer wants to be assigned (e.g.
    /// `"fd5a:1f02:aabb::1"`). When `Some`, the coordinator attempts to
    /// honor it; when `None` (default) the coordinator derives the ULA
    /// from the peer index. Omitted from the wire when `None` for back-compat
    /// with coordinators that predate Task 0.2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_ula: Option<String>,
    /// Peer role. `Some("runner")` for a per-app runner; `None` (default)
    /// for a plain supervisor/joiner — omitted from the wire so older
    /// coordinators are unaffected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// ULA of the supervisor that owns this runner. `None` for plain peers.
    /// Omitted from the wire when `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    /// UUID of the app this runner serves. `None` for plain peers.
    /// Omitted from the wire when `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_uuid: Option<String>,
}

/// Body of `POST /v1/mesh/register`'s response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterResponse {
    /// UUID v7 assigned by the coordinator.
    pub peer_id: Uuid,
    /// IPv6 ULA assigned to this joiner.
    pub ula: String,
    /// Initial roster (excluding the joiner itself).
    pub peers: Vec<RemotePeer>,
    /// Our own observed external IP, as the coordinator saw the register
    /// request arrive (our NAT's public IP). `None` from an older
    /// coordinator that doesn't reflect it. Informational — lets the
    /// joiner log whether it is behind NAT.
    #[serde(default)]
    pub observed_ip: Option<String>,
    /// The reflexive endpoint the coordinator stored for us (what other
    /// peers will dial). `None` from an older coordinator.
    #[serde(default)]
    pub observed_endpoint: Option<String>,
}

/// Body of `POST /v1/mesh/heartbeat`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatRequest {
    /// The peer id this joiner was assigned at registration time.
    pub peer_id: Uuid,
    /// Our `WireGuard` UDP listen port — re-sent on every heartbeat so the
    /// coordinator can refresh our reflexive endpoint if our observed
    /// public IP changes (NAT rebind / roaming).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wg_listen_port: Option<u16>,
    /// Our CURRENT full set of hosted app-ULAs (IPv6 literals), re-sent on
    /// every heartbeat. The coordinator replaces our stored set with this
    /// one (per-app-ULA routing). Omitted from the wire when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hosted_app_ulas: Vec<String>,
}

/// Body of the heartbeat response. The coordinator returns the current
/// roster so the joiner can self-heal if the SSE stream missed an event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatResponse {
    /// Current full roster (excluding this peer).
    pub peers: Vec<RemotePeer>,
    /// Our own observed external IP on this heartbeat. `None` from an
    /// older coordinator.
    #[serde(default)]
    pub observed_ip: Option<String>,
    /// The reflexive endpoint currently stored for us. `None` from an
    /// older coordinator.
    #[serde(default)]
    pub observed_endpoint: Option<String>,
}

/// Body of `POST /v1/mesh/deregister`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeregisterRequest {
    /// Our peer id.
    pub peer_id: Uuid,
}

/// HTTP client wrapper. Cheap to clone — shares a single
/// `reqwest::Client` internally.
#[derive(Debug, Clone)]
pub struct CoordinatorClient {
    http: reqwest::Client,
    base_url: String,
}

impl CoordinatorClient {
    /// Build a client targeting `base_url` (e.g.
    /// `https://127.0.0.1:8888`). Trailing slashes are tolerated.
    ///
    /// When `insecure == true` (dev/smoke-test path) the three TLS
    /// path arguments are ignored and a plain `reqwest::Client` is
    /// built — talks to a coordinator launched with
    /// `--insecure-no-mtls`.
    ///
    /// When `insecure == false` (production path) all three TLS paths
    /// must be provided:
    ///
    /// * `tls_cert` — PEM-encoded client cert signed by the mesh CA.
    /// * `tls_key` — PEM-encoded private key matching the cert.
    /// * `tls_ca` — PEM-encoded CA bundle the joiner trusts when
    ///   validating the coordinator's server cert.
    ///
    /// The CA bundle is the ONLY root trusted for this client; we do
    /// not fall back to the system trust store because the mesh CA is
    /// private and nothing public should ever vouch for the coordinator.
    ///
    /// # Errors
    ///
    /// * [`JoinerError::InvalidConfig`] when `insecure == false` and
    ///   any of the three TLS paths is missing.
    /// * [`JoinerError::TunSetup`] is *not* used here — TLS file read
    ///   / parse errors surface as [`JoinerError::HttpTransport`]
    ///   carrying the underlying message.
    /// * [`JoinerError::HttpTransport`] for any reqwest builder
    ///   failure or PEM read/parse failure.
    pub fn new(
        base_url: impl Into<String>,
        tls_cert: Option<&Path>,
        tls_key: Option<&Path>,
        tls_ca: Option<&Path>,
        insecure: bool,
    ) -> Result<Self> {
        let trimmed = base_url.into().trim_end_matches('/').to_owned();

        let builder = if insecure {
            reqwest::Client::builder()
        } else {
            // mTLS branch: validate the trio before touching disk so
            // the operator gets a precise error instead of a generic
            // "file not found" if they forgot a flag.
            let (Some(cert_path), Some(key_path), Some(ca_path)) = (tls_cert, tls_key, tls_ca)
            else {
                return Err(JoinerError::InvalidConfig(
                    "mTLS requires all three paths: --tls-cert, --tls-key, --tls-ca \
                     (or use --insecure-no-mtls for dev)"
                        .to_owned(),
                ));
            };
            build_mtls_client_builder(cert_path, key_path, ca_path)?
        };

        let http = builder
            .build()
            .map_err(|e| JoinerError::HttpTransport(e.to_string()))?;

        Ok(Self {
            http,
            base_url: trimmed,
        })
    }

    /// Expose the configured base URL — used by `peer_sync` to build
    /// the SSE GET request without re-parsing the joiner config.
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Borrow the inner `reqwest::Client` so the SSE consumer can share
    /// the connection pool.
    #[must_use]
    pub const fn http(&self) -> &reqwest::Client {
        &self.http
    }

    /// `POST /v1/mesh/register` — exchange `(pubkey, endpoint, name,
    /// tags)` for `(peer_id, ula, roster)`.
    ///
    /// `listen_endpoint` is a free-form `host:port` string forwarded to
    /// the coordinator verbatim — it is the address OTHER peers must
    /// dial to reach us. We do not resolve it locally because the local
    /// resolver may not know the name we want others to use (e.g. a Mac
    /// peer advertising `host.lima.internal:51820` to a Lima
    /// counterpart; Mac itself can't resolve that name). DNS happens at
    /// the consuming peer in `remote_to_info`.
    ///
    /// `join_token` is the node-join JWT issued by the auth service. When
    /// `Some`, it is sent as `Authorization: Bearer <token>` — the
    /// coordinator validates it and takes the node's authoritative
    /// `network` + `tags` from the token claims (spec §8). When `None`
    /// (dev/E1 escape hatch against a coordinator with no `AUTH_URL`) no
    /// auth header is sent and the coordinator trusts `tags` verbatim. The
    /// `tags` we send are advisory either way — a validating coordinator
    /// ignores them in favor of the claims.
    ///
    /// `requested_ula` — explicit IPv6 ULA to request from the coordinator
    /// (Task 0.2). `None` = coordinator-derived. `kind` / `parent` /
    /// `app_uuid` — runner peer metadata (Task 0.1/0.3). All `None` for
    /// plain peers — omitted from the wire for backward compat.
    #[allow(clippy::too_many_arguments)]
    pub async fn register(
        &self,
        wg_public_key: &[u8; 32],
        listen_endpoint: Option<String>,
        wg_listen_port: Option<u16>,
        display_name: &str,
        tags: &[String],
        join_token: Option<&str>,
        requested_ula: Option<String>,
        kind: Option<String>,
        parent: Option<String>,
        app_uuid: Option<String>,
    ) -> Result<RegisterResponse> {
        let body = RegisterRequest {
            wg_public_key: B64.encode(wg_public_key),
            listen_endpoint,
            wg_listen_port,
            display_name: display_name.to_owned(),
            tags: tags.to_vec(),
            // Initial register hosts no apps — they are hosted after join
            // via `Joiner::host_app_ula` and advertised on the next
            // heartbeat (per-app-ULA routing). The field exists on the wire
            // for forward-compat + symmetry with heartbeat.
            hosted_app_ulas: Vec::new(),
            requested_ula,
            kind,
            parent,
            app_uuid,
        };
        let url = format!("{}/v1/mesh/register", self.base_url);
        let mut builder = self.http.post(&url).json(&body);
        // Attach the join token as a Bearer credential when present. Use
        // reqwest's `bearer_auth` so the `Authorization: Bearer <token>`
        // header is formatted exactly as the coordinator's extractor
        // expects.
        if let Some(token) = join_token.map(str::trim).filter(|t| !t.is_empty()) {
            builder = builder.bearer_auth(token);
        }
        let resp = builder
            .send()
            .await
            .map_err(|e| JoinerError::HttpTransport(e.to_string()))?;
        ensure_success(&url, resp).await
    }

    /// `POST /v1/mesh/heartbeat` — keepalive that also refreshes the
    /// caller's view of the roster.
    ///
    /// `wg_listen_port` is our `WireGuard` UDP port, re-sent so the
    /// coordinator can refresh our reflexive endpoint on an observed-IP
    /// change.
    pub async fn heartbeat(
        &self,
        peer_id: Uuid,
        wg_listen_port: Option<u16>,
        hosted_app_ulas: &[String],
    ) -> Result<HeartbeatResponse> {
        let url = format!("{}/v1/mesh/heartbeat", self.base_url);
        let body = HeartbeatRequest {
            peer_id,
            wg_listen_port,
            hosted_app_ulas: hosted_app_ulas.to_vec(),
        };
        let resp = self
            .http
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| JoinerError::HttpTransport(e.to_string()))?;
        ensure_success(&url, resp).await
    }

    /// `POST /v1/mesh/deregister` — best-effort graceful exit.
    ///
    /// The coordinator responds with 204 on success. Some
    /// implementations also accept 200 — we tolerate both, anything
    /// else surfaces as [`JoinerError::HttpStatus`].
    pub async fn deregister(&self, peer_id: Uuid) -> Result<()> {
        let url = format!("{}/v1/mesh/deregister", self.base_url);
        let body = DeregisterRequest { peer_id };
        let resp = self
            .http
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| JoinerError::HttpTransport(e.to_string()))?;
        let status = resp.status();
        if status.is_success() {
            return Ok(());
        }
        Err(JoinerError::HttpStatus {
            status: status.as_u16(),
            body: take_body_excerpt(resp).await,
        })
    }
}

/// Decode a 32-byte X25519 public key from the coordinator's base64
/// representation, surfacing a typed error on malformed input.
pub fn decode_pubkey(s: &str) -> Result<[u8; 32]> {
    let bytes = B64
        .decode(s)
        .map_err(|e| JoinerError::MalformedPeer(format!("wg_public_key base64: {e}")))?;
    if bytes.len() != 32 {
        return Err(JoinerError::MalformedPeer(format!(
            "wg_public_key length {} != 32",
            bytes.len()
        )));
    }
    // Length checked above — copy into a fixed-size array for the API.
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Decode a [`RemotePeer`] (wire shape) into the public [`PeerInfo`].
///
/// Splits parsing failures into a typed error so the joiner can log
/// and skip the bad entry without dropping the entire roster update.
///
/// `listen_endpoint` resolution: tries `SocketAddr::parse` first (IP
/// literal — common case, no I/O). Falls back to async DNS via
/// `tokio::net::lookup_host` when the string contains a hostname like
/// `host.lima.internal:51820`. The remote peer is responsible for
/// advertising a name resolvable in the consumer's environment.
pub async fn remote_to_info(r: &RemotePeer) -> Result<PeerInfo> {
    let wg_public_key = decode_pubkey(&r.wg_public_key)?;
    let ula = r
        .ula
        .parse()
        .map_err(|e| JoinerError::MalformedPeer(format!("ula {:?}: {e}", r.ula)))?;
    // `listen_endpoint` resolution. Three outcomes:
    //   * `None` (or empty) — peer registered without one (passive / NAT).
    //   * Valid SocketAddr literal — use as-is, no I/O.
    //   * Hostname — try async DNS via tokio. If we CAN'T resolve in this
    //     environment (e.g. Mac peer reading its own roster entry whose
    //     advertised name is `host.lima.internal`, which only resolves
    //     inside Lima), demote to `None` (passive). The wg_session will
    //     wait for the other side to initiate the handshake instead of
    //     dialing — that's still correct in same-host / cross-VM dev
    //     setups because the OTHER peer can resolve the name.
    let listen_endpoint = match r.listen_endpoint.as_ref().filter(|s| !s.is_empty()) {
        None => None,
        Some(s) => {
            if let Ok(addr) = s.parse::<SocketAddr>() {
                Some(addr)
            } else {
                match tokio::net::lookup_host(s.as_str()).await {
                    Ok(mut hosts) => hosts.next(),
                    Err(e) => {
                        tracing::debug!(
                            endpoint = %s,
                            error = %e,
                            "remote_to_info: hostname unresolvable in this env, treating peer as passive"
                        );
                        None
                    }
                }
            }
        }
    };
    // Parse hosted app-ULAs (per-app-ULA routing). A malformed literal is
    // dropped with a warning rather than failing the whole peer record —
    // one bad app-ULA must not cost us the peer's session.
    let mut hosted_app_ulas = Vec::with_capacity(r.hosted_app_ulas.len());
    for s in &r.hosted_app_ulas {
        match s.parse::<Ipv6Addr>() {
            Ok(addr) => hosted_app_ulas.push(addr),
            Err(e) => tracing::warn!(
                app_ula = %s,
                error = %e,
                "remote_to_info: skipping malformed hosted app-ULA"
            ),
        }
    }
    Ok(PeerInfo {
        peer_id: r.peer_id,
        wg_public_key,
        ula,
        listen_endpoint,
        display_name: r.display_name.clone(),
        tags: r.tags.clone(),
        hosted_app_ulas,
        joined_at_micros: r.joined_at_micros,
    })
}

/// Drain a [`reqwest::Response`] into either a deserialised body or a
/// typed `JoinerError` if status or JSON shape disagree with what the
/// caller asked for.
async fn ensure_success<T>(url: &str, resp: reqwest::Response) -> Result<T>
where
    T: serde::de::DeserializeOwned,
{
    let status = resp.status();
    if !status.is_success() {
        return Err(JoinerError::HttpStatus {
            status: status.as_u16(),
            body: take_body_excerpt(resp).await,
        });
    }
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| JoinerError::HttpTransport(format!("{url}: {e}")))?;
    serde_json::from_slice(&bytes).map_err(|e| {
        let excerpt = body_excerpt_bytes(&bytes);
        JoinerError::JsonCodec(format!("{url}: {e} (body excerpt: {excerpt})"))
    })
}

/// Pull up to ~2 KiB out of a response body for logging in an error
/// path. Never returns an error — best-effort.
async fn take_body_excerpt(resp: reqwest::Response) -> String {
    match resp.bytes().await {
        Ok(b) => body_excerpt_bytes(&b),
        Err(e) => format!("<body read failed: {e}>"),
    }
}

fn body_excerpt_bytes(bytes: &[u8]) -> String {
    let s = String::from_utf8_lossy(bytes);
    if s.len() > 2_048 {
        format!("{}...<truncated>", &s[..2_048])
    } else {
        s.into_owned()
    }
}

/// Read PEM cert + key + CA off disk and build a `reqwest::ClientBuilder`
/// pre-configured with a client identity and a single trusted root.
///
/// All I/O errors surface as [`JoinerError::HttpTransport`] because
/// they're effectively transport-setup failures from the caller's POV
/// (the coordinator request never even leaves the host).
fn build_mtls_client_builder(
    cert_path: &Path,
    key_path: &Path,
    ca_path: &Path,
) -> Result<reqwest::ClientBuilder> {
    let cert_pem = std::fs::read(cert_path).map_err(|e| {
        JoinerError::HttpTransport(format!("read tls_cert {}: {e}", cert_path.display()))
    })?;
    let key_pem = std::fs::read(key_path).map_err(|e| {
        JoinerError::HttpTransport(format!("read tls_key {}: {e}", key_path.display()))
    })?;
    let ca_pem = std::fs::read(ca_path).map_err(|e| {
        JoinerError::HttpTransport(format!("read tls_ca {}: {e}", ca_path.display()))
    })?;

    // `Identity::from_pem` expects cert + key concatenated into one PEM
    // blob — the rustls backend internally parses the sections. Order
    // doesn't matter but we put cert first for diagnostic convenience.
    // Move `cert_pem` (not clone) — original isn't referenced again.
    let mut bundle = cert_pem;
    if !bundle.ends_with(b"\n") {
        bundle.push(b'\n');
    }
    bundle.extend_from_slice(&key_pem);

    let identity = reqwest::Identity::from_pem(&bundle).map_err(|e| {
        JoinerError::HttpTransport(format!(
            "parse client identity (cert={}, key={}): {e}",
            cert_path.display(),
            key_path.display()
        ))
    })?;
    let root_ca = reqwest::Certificate::from_pem(&ca_pem).map_err(|e| {
        JoinerError::HttpTransport(format!("parse tls_ca {}: {e}", ca_path.display()))
    })?;

    // `tls_built_in_root_certs(false)` — drop the OS / webpki bundle
    // so ONLY our mesh CA is trusted. A misconfigured public CA must
    // not be able to MITM the mesh control plane.
    Ok(reqwest::Client::builder()
        .use_rustls_tls()
        .tls_built_in_root_certs(false)
        .add_root_certificate(root_ca)
        .identity(identity))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn sample_pubkey_b64() -> (String, [u8; 32]) {
        let raw: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];
        (B64.encode(raw), raw)
    }

    #[test]
    fn decode_pubkey_round_trip() {
        let (encoded, raw) = sample_pubkey_b64();
        let got = decode_pubkey(&encoded).unwrap();
        assert_eq!(got, raw);
    }

    #[test]
    fn decode_pubkey_rejects_wrong_length() {
        let short = B64.encode([0u8; 16]);
        let err = decode_pubkey(&short).unwrap_err();
        assert!(matches!(err, JoinerError::MalformedPeer(_)));
    }

    #[test]
    fn decode_pubkey_rejects_garbage_base64() {
        let err = decode_pubkey("!!! not base64 !!!").unwrap_err();
        assert!(matches!(err, JoinerError::MalformedPeer(_)));
    }

    #[tokio::test]
    async fn remote_to_info_parses_full_record() {
        let (b64, raw) = sample_pubkey_b64();
        let remote = RemotePeer {
            peer_id: Uuid::nil(),
            wg_public_key: b64,
            ula: "fd5a:1f00:1::1".into(),
            listen_endpoint: Some("127.0.0.1:51820".into()),
            display_name: "alice".into(),
            tags: vec!["dev".into()],
            hosted_app_ulas: vec![],
            joined_at_micros: 1_700_000_000_000_000,
        };
        let info = remote_to_info(&remote).await.unwrap();
        assert_eq!(info.peer_id, Uuid::nil());
        assert_eq!(info.wg_public_key, raw);
        assert_eq!(info.ula.to_string(), "fd5a:1f00:1::1");
        assert_eq!(info.listen_endpoint.unwrap().to_string(), "127.0.0.1:51820");
        assert_eq!(info.display_name, "alice");
        assert_eq!(info.tags, vec!["dev".to_string()]);
    }

    /// `remote_to_info` parses well-formed hosted app-ULAs into typed
    /// addresses (per-app-ULA routing). A peer hosting no apps yields an
    /// empty vec.
    #[tokio::test]
    async fn remote_to_info_parses_hosted_app_ulas() {
        let (b64, _) = sample_pubkey_b64();
        let remote = RemotePeer {
            peer_id: Uuid::nil(),
            wg_public_key: b64,
            ula: "fd5a:1f00:1::1".into(),
            listen_endpoint: None,
            display_name: "supervisor".into(),
            tags: vec![],
            hosted_app_ulas: vec![
                "fd5a:1f02:dead:beef:cafe:0:0:1".into(),
                "fd5a:1f02:dead:beef:cafe:0:0:2".into(),
            ],
            joined_at_micros: 0,
        };
        let info = remote_to_info(&remote).await.unwrap();
        assert_eq!(
            info.hosted_app_ulas,
            vec![
                "fd5a:1f02:dead:beef:cafe:0:0:1"
                    .parse::<Ipv6Addr>()
                    .unwrap(),
                "fd5a:1f02:dead:beef:cafe:0:0:2"
                    .parse::<Ipv6Addr>()
                    .unwrap(),
            ]
        );
    }

    /// A malformed hosted app-ULA literal is SKIPPED (logged), not fatal —
    /// the peer's session must survive one bad app-ULA. Good ones in the
    /// same record still parse.
    #[tokio::test]
    async fn remote_to_info_skips_malformed_hosted_app_ula() {
        let (b64, _) = sample_pubkey_b64();
        let remote = RemotePeer {
            peer_id: Uuid::nil(),
            wg_public_key: b64,
            ula: "fd5a:1f00:1::1".into(),
            listen_endpoint: None,
            display_name: "supervisor".into(),
            tags: vec![],
            hosted_app_ulas: vec![
                "not-an-ipv6".into(),
                "fd5a:1f02:dead:beef:cafe:0:0:9".into(),
            ],
            joined_at_micros: 0,
        };
        let info = remote_to_info(&remote).await.unwrap();
        // The bad one is dropped; the good one survives.
        assert_eq!(
            info.hosted_app_ulas,
            vec![
                "fd5a:1f02:dead:beef:cafe:0:0:9"
                    .parse::<Ipv6Addr>()
                    .unwrap()
            ]
        );
    }

    /// A peer behind NAT registers with an empty `listen_endpoint`; we
    /// must accept that as `None` rather than failing the roster
    /// update.
    #[tokio::test]
    async fn remote_to_info_treats_empty_endpoint_as_none() {
        let (b64, _) = sample_pubkey_b64();
        let remote = RemotePeer {
            peer_id: Uuid::nil(),
            wg_public_key: b64,
            ula: "fd5a:1f00:1::2".into(),
            listen_endpoint: Some(String::new()),
            display_name: "bob".into(),
            tags: vec![],
            hosted_app_ulas: vec![],
            joined_at_micros: 0,
        };
        let info = remote_to_info(&remote).await.unwrap();
        assert!(info.listen_endpoint.is_none());
    }

    #[tokio::test]
    async fn remote_to_info_rejects_bad_ula() {
        let (b64, _) = sample_pubkey_b64();
        let remote = RemotePeer {
            peer_id: Uuid::nil(),
            wg_public_key: b64,
            ula: "not-an-ipv6".into(),
            listen_endpoint: None,
            display_name: "x".into(),
            tags: vec![],
            hosted_app_ulas: vec![],
            joined_at_micros: 0,
        };
        let err = remote_to_info(&remote).await.unwrap_err();
        assert!(matches!(err, JoinerError::MalformedPeer(_)));
    }

    /// End-to-end happy path against a `wiremock` fake coordinator. We
    /// assert the joiner sends the registration body in the correct
    /// shape (POST + JSON + base64 pubkey) and parses the response.
    #[tokio::test]
    async fn register_round_trip_against_mock_coordinator() {
        let server = MockServer::start().await;
        let response_body = serde_json::json!({
            "peer_id": "01910f10-0000-7000-8000-000000000001",
            "ula": "fd5a:1f00:1::1",
            "peers": [
                {
                    "peer_id": "01910f10-0000-7000-8000-000000000002",
                    "wg_public_key": B64.encode([7u8; 32]),
                    "ula": "fd5a:1f00:1::2",
                    "listen_endpoint": "10.0.0.2:51820",
                    "display_name": "peer-two",
                    "tags": ["wasm-host"],
                    "joined_at_micros": 1_700_000_000_000_000_i64
                }
            ]
        });
        Mock::given(method("POST"))
            .and(path("/v1/mesh/register"))
            .and(header("content-type", "application/json"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/json")
                    .set_body_json(response_body),
            )
            .expect(1)
            .mount(&server)
            .await;

        let client = CoordinatorClient::new(server.uri(), None, None, None, true).unwrap();
        let pubkey = [0xAAu8; 32];
        let resp = client
            .register(
                &pubkey,
                Some("127.0.0.1:51820".parse().unwrap()),
                Some(51820),
                "alice",
                &["dev-machine".to_owned()],
                None,
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap();
        assert_eq!(resp.ula, "fd5a:1f00:1::1");
        assert_eq!(resp.peers.len(), 1);
        assert_eq!(resp.peers[0].display_name, "peer-two");
    }

    /// When a join token is supplied, the register request must carry it
    /// as an `Authorization: Bearer <token>` header (spec §8). The mock
    /// only matches when that exact header is present, so a passing test
    /// proves the header was sent.
    #[tokio::test]
    async fn register_sends_bearer_header_when_join_token_present() {
        let server = MockServer::start().await;
        let response_body = serde_json::json!({
            "peer_id": "01910f10-0000-7000-8000-000000000001",
            "ula": "fd5a:1f00:1::1",
            "peers": []
        });
        Mock::given(method("POST"))
            .and(path("/v1/mesh/register"))
            .and(header("authorization", "Bearer my-join-jwt"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/json")
                    .set_body_json(response_body),
            )
            .expect(1)
            .mount(&server)
            .await;

        let client = CoordinatorClient::new(server.uri(), None, None, None, true).unwrap();
        let resp = client
            .register(
                &[0xAAu8; 32],
                None,
                Some(51820),
                "alice",
                &[],
                Some("my-join-jwt"),
                None,
                None,
                None,
                None,
            )
            .await
            .expect("register with bearer should succeed");
        assert_eq!(resp.ula, "fd5a:1f00:1::1");
    }

    /// The register body must carry `wg_listen_port` (for reflexive
    /// discovery) and, when no explicit advertise-endpoint is given, must
    /// OMIT `listen_endpoint` — the joiner no longer auto-advertises a
    /// loopback address; it lets the coordinator reflect. A body matcher
    /// proves both on the wire.
    #[tokio::test]
    async fn register_sends_wg_port_and_omits_listen_endpoint() {
        use wiremock::matchers::body_partial_json;
        let server = MockServer::start().await;
        let response_body = serde_json::json!({
            "peer_id": "01910f10-0000-7000-8000-000000000001",
            "ula": "fd5a:1f00:1::1",
            "peers": []
        });
        Mock::given(method("POST"))
            .and(path("/v1/mesh/register"))
            // Requires wg_listen_port == 51820 in the JSON body.
            .and(body_partial_json(
                serde_json::json!({ "wg_listen_port": 51820 }),
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/json")
                    .set_body_json(&response_body),
            )
            .expect(1)
            .mount(&server)
            .await;

        let client = CoordinatorClient::new(server.uri(), None, None, None, true).unwrap();
        // listen_endpoint = None → must be omitted from the body (serde
        // skip_serializing_if). The mock only matched on wg_listen_port, so
        // also assert the serialized body has no listen_endpoint key.
        let body = serde_json::to_value(RegisterRequest {
            wg_public_key: B64.encode([0xAAu8; 32]),
            listen_endpoint: None,
            wg_listen_port: Some(51820),
            display_name: "alice".into(),
            tags: vec![],
            hosted_app_ulas: vec![],
            requested_ula: None,
            kind: None,
            parent: None,
            app_uuid: None,
        })
        .unwrap();
        assert!(
            body.get("listen_endpoint").is_none(),
            "listen_endpoint must be omitted when None: {body}"
        );
        assert_eq!(body["wg_listen_port"], 51820);

        client
            .register(
                &[0xAAu8; 32],
                None,
                Some(51820),
                "alice",
                &[],
                None,
                None,
                None,
                None,
                None,
            )
            .await
            .expect("register should succeed and match the wg_listen_port body");
    }

    /// The register response must surface the coordinator-reflected
    /// `observed_ip` + `observed_endpoint` (the reflexive endpoint other
    /// peers will dial). Older coordinators omit them → `None`.
    #[tokio::test]
    async fn register_parses_observed_reflexive_fields() {
        let server = MockServer::start().await;
        let response_body = serde_json::json!({
            "peer_id": "01910f10-0000-7000-8000-000000000001",
            "ula": "fd5a:1f00:1::1",
            "peers": [],
            "observed_ip": "203.0.113.7",
            "observed_endpoint": "203.0.113.7:51820"
        });
        Mock::given(method("POST"))
            .and(path("/v1/mesh/register"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/json")
                    .set_body_json(response_body),
            )
            .mount(&server)
            .await;
        let client = CoordinatorClient::new(server.uri(), None, None, None, true).unwrap();
        let resp = client
            .register(
                &[0xAAu8; 32],
                None,
                Some(51820),
                "alice",
                &[],
                None,
                None,
                None,
                None,
                None,
            )
            .await
            .expect("register");
        assert_eq!(resp.observed_ip.as_deref(), Some("203.0.113.7"));
        assert_eq!(resp.observed_endpoint.as_deref(), Some("203.0.113.7:51820"));
    }

    /// Back-compat: a response WITHOUT the observed fields parses cleanly
    /// (they default to `None`) — older coordinators must still work.
    #[tokio::test]
    async fn register_tolerates_missing_observed_fields() {
        let server = MockServer::start().await;
        let response_body = serde_json::json!({
            "peer_id": "01910f10-0000-7000-8000-000000000001",
            "ula": "fd5a:1f00:1::1",
            "peers": []
        });
        Mock::given(method("POST"))
            .and(path("/v1/mesh/register"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/json")
                    .set_body_json(response_body),
            )
            .mount(&server)
            .await;
        let client = CoordinatorClient::new(server.uri(), None, None, None, true).unwrap();
        let resp = client
            .register(
                &[0xAAu8; 32],
                None,
                Some(51820),
                "alice",
                &[],
                None,
                None,
                None,
                None,
                None,
            )
            .await
            .expect("register");
        assert!(resp.observed_ip.is_none());
        assert!(resp.observed_endpoint.is_none());
    }

    /// With no join token, the register request must NOT carry an
    /// Authorization header — the dev/E1 escape hatch against a
    /// non-validating coordinator. The mock requires the header to be
    /// ABSENT (matches only when there's no auth), so a pass proves we
    /// didn't send one.
    #[tokio::test]
    async fn register_omits_bearer_header_when_no_join_token() {
        use wiremock::matchers::header_exists;
        let server = MockServer::start().await;
        let response_body = serde_json::json!({
            "peer_id": "01910f10-0000-7000-8000-000000000001",
            "ula": "fd5a:1f00:1::1",
            "peers": []
        });
        // A mock that requires the Authorization header to exist; we then
        // assert it received ZERO calls, i.e. our tokenless request did
        // not match because it carried no auth header.
        Mock::given(method("POST"))
            .and(path("/v1/mesh/register"))
            .and(header_exists("authorization"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .expect(0)
            .mount(&server)
            .await;
        // Fallback mock with no header requirement so the call still gets
        // a valid response to parse.
        Mock::given(method("POST"))
            .and(path("/v1/mesh/register"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/json")
                    .set_body_json(response_body),
            )
            .mount(&server)
            .await;

        let client = CoordinatorClient::new(server.uri(), None, None, None, true).unwrap();
        client
            .register(
                &[0xAAu8; 32],
                None,
                Some(51820),
                "alice",
                &[],
                None,
                None,
                None,
                None,
                None,
            )
            .await
            .expect("tokenless register should succeed");
        // The `.expect(0)` on the header-requiring mock is verified on
        // server drop — if our request had carried an auth header it would
        // have matched and tripped the expectation.
    }

    #[tokio::test]
    async fn heartbeat_returns_roster_snapshot() {
        let server = MockServer::start().await;
        let response_body = serde_json::json!({ "peers": [] });
        Mock::given(method("POST"))
            .and(path("/v1/mesh/heartbeat"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/json")
                    .set_body_json(response_body),
            )
            .expect(1)
            .mount(&server)
            .await;
        let client = CoordinatorClient::new(server.uri(), None, None, None, true).unwrap();
        let resp = client
            .heartbeat(Uuid::nil(), Some(51820), &[])
            .await
            .unwrap();
        assert!(resp.peers.is_empty());
    }

    /// Per-app-ULA routing: when the joiner hosts app-ULAs, the heartbeat
    /// body must carry them as `hosted_app_ulas`. A body matcher proves the
    /// set is on the wire.
    #[tokio::test]
    async fn heartbeat_sends_hosted_app_ulas() {
        use wiremock::matchers::body_partial_json;
        let server = MockServer::start().await;
        let response_body = serde_json::json!({ "peers": [] });
        Mock::given(method("POST"))
            .and(path("/v1/mesh/heartbeat"))
            .and(body_partial_json(serde_json::json!({
                "hosted_app_ulas": ["fd5a:1f02:dead:beef:cafe:0:0:1"]
            })))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/json")
                    .set_body_json(response_body),
            )
            .expect(1)
            .mount(&server)
            .await;
        let client = CoordinatorClient::new(server.uri(), None, None, None, true).unwrap();
        client
            .heartbeat(
                Uuid::nil(),
                Some(51820),
                &["fd5a:1f02:dead:beef:cafe:0:0:1".to_owned()],
            )
            .await
            .expect("heartbeat with hosted app-ULAs should match the body");
    }

    /// Back-compat: an EMPTY hosted set is omitted from the heartbeat body
    /// (serde `skip_serializing_if`), so older coordinators see no new key.
    #[tokio::test]
    async fn heartbeat_omits_empty_hosted_app_ulas() {
        let body = serde_json::to_value(HeartbeatRequest {
            peer_id: Uuid::nil(),
            wg_listen_port: Some(51820),
            hosted_app_ulas: vec![],
        })
        .unwrap();
        assert!(
            body.get("hosted_app_ulas").is_none(),
            "empty hosted_app_ulas must be omitted: {body}"
        );
    }

    #[tokio::test]
    async fn deregister_accepts_204() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/mesh/deregister"))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&server)
            .await;
        let client = CoordinatorClient::new(server.uri(), None, None, None, true).unwrap();
        client.deregister(Uuid::nil()).await.unwrap();
    }

    #[tokio::test]
    async fn deregister_surfaces_http_status_on_failure() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/mesh/deregister"))
            .respond_with(ResponseTemplate::new(500).set_body_string("kaboom"))
            .expect(1)
            .mount(&server)
            .await;
        let client = CoordinatorClient::new(server.uri(), None, None, None, true).unwrap();
        let err = client.deregister(Uuid::nil()).await.unwrap_err();
        match err {
            JoinerError::HttpStatus { status, body } => {
                assert_eq!(status, 500);
                assert!(body.contains("kaboom"), "body: {body}");
            }
            other => panic!("expected HttpStatus, got {other:?}"),
        }
    }

    /// A 200 with garbled JSON must surface as [`JoinerError::JsonCodec`]
    /// — not silently swallowed — so the operator notices the
    /// coordinator/joiner version mismatch.
    #[tokio::test]
    async fn register_surfaces_json_codec_error_on_garbage_body() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/mesh/register"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/json")
                    .set_body_string("not json at all"),
            )
            .expect(1)
            .mount(&server)
            .await;
        let client = CoordinatorClient::new(server.uri(), None, None, None, true).unwrap();
        let err = client
            .register(
                &[0u8; 32],
                None,
                Some(51820),
                "x",
                &[],
                None,
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, JoinerError::JsonCodec(_)), "{err:?}");
    }

    /// When `requested_ula`, `kind`, `parent`, and `app_uuid` are set on the
    /// register request, they must all appear in the JSON body sent to the
    /// coordinator, and the coordinator-returned ULA (which mirrors the
    /// requested one when honored) must be returned in the response.
    #[tokio::test]
    async fn register_sends_requested_ula_and_peer_metadata() {
        use wiremock::matchers::body_partial_json;
        let server = MockServer::start().await;
        let app_uuid_str = "01910f10-0000-7000-8000-000000000099";
        let sup_ula = "fd5a:1f00:1::1";
        let runner_ula = "fd5a:1f02:aabb::1";
        let response_body = serde_json::json!({
            "peer_id": "01910f10-0000-7000-8000-000000000002",
            // Coordinator honors the requested ULA and echoes it back.
            "ula": runner_ula,
            "peers": []
        });
        Mock::given(method("POST"))
            .and(path("/v1/mesh/register"))
            .and(body_partial_json(serde_json::json!({
                "requested_ula": runner_ula,
                "kind": "runner",
                "parent": sup_ula,
                "app_uuid": app_uuid_str,
            })))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/json")
                    .set_body_json(response_body),
            )
            .expect(1)
            .mount(&server)
            .await;

        let client = CoordinatorClient::new(server.uri(), None, None, None, true).unwrap();
        let resp = client
            .register(
                &[0xAAu8; 32],
                None,
                Some(51820),
                "runner-abc",
                &[],
                None,
                Some(runner_ula.to_owned()),
                Some("runner".to_owned()),
                Some(sup_ula.to_owned()),
                Some(app_uuid_str.to_owned()),
            )
            .await
            .expect("register with requested_ula + metadata should succeed");
        // The coordinator echoed back the requested ULA.
        assert_eq!(resp.ula, runner_ula);
    }

    /// Backward compat: existing callers that pass `None` for all four new
    /// fields must NOT have `requested_ula` / `kind` / `parent` /
    /// `app_uuid` in the body (omitted by `skip_serializing_if`). This
    /// keeps the wire format unchanged for plain peer joiners.
    #[test]
    fn register_request_omits_optional_runner_fields_when_none() {
        let body = serde_json::to_value(RegisterRequest {
            wg_public_key: B64.encode([0xAAu8; 32]),
            listen_endpoint: None,
            wg_listen_port: Some(51820),
            display_name: "alice".into(),
            tags: vec![],
            hosted_app_ulas: vec![],
            requested_ula: None,
            kind: None,
            parent: None,
            app_uuid: None,
        })
        .unwrap();
        assert!(
            body.get("requested_ula").is_none(),
            "requested_ula must be omitted when None: {body}"
        );
        assert!(
            body.get("kind").is_none(),
            "kind must be omitted when None: {body}"
        );
        assert!(
            body.get("parent").is_none(),
            "parent must be omitted when None: {body}"
        );
        assert!(
            body.get("app_uuid").is_none(),
            "app_uuid must be omitted when None: {body}"
        );
    }

    #[test]
    fn base_url_trims_trailing_slash() {
        let c = CoordinatorClient::new("http://127.0.0.1:8888/", None, None, None, true).unwrap();
        assert_eq!(c.base_url(), "http://127.0.0.1:8888");
    }

    /// Insecure (dev) path must build successfully with all TLS args
    /// at `None` — the cert paths are intentionally ignored so the
    /// joiner can hit a plaintext coordinator without ceremony.
    #[test]
    fn new_insecure_skips_tls() {
        let c = CoordinatorClient::new("http://example.com".to_owned(), None, None, None, true);
        assert!(c.is_ok(), "expected ok, got {:?}", c.err());
    }

    /// Production path requires all three cert paths. Missing ANY one
    /// of them surfaces as [`JoinerError::InvalidConfig`] BEFORE any
    /// I/O — gives the operator a precise actionable error instead of
    /// a vague "file not found" mid-handshake.
    #[test]
    fn new_secure_requires_all_three_paths() {
        let err = CoordinatorClient::new(
            "https://coordinator.mesh".to_owned(),
            None,
            None,
            None,
            false,
        )
        .unwrap_err();
        assert!(
            matches!(err, JoinerError::InvalidConfig(_)),
            "expected InvalidConfig, got {err:?}"
        );
    }

    /// Even with two of the three paths supplied, the validation must
    /// still trip — guards against a copy-paste deploy script that
    /// forgot to pass the CA bundle.
    #[test]
    fn new_secure_requires_ca_too() {
        let dir = tempfile::TempDir::new().unwrap();
        let cert = dir.path().join("c.pem");
        let key = dir.path().join("k.pem");
        // Files don't need to exist — validation runs before disk I/O.
        let err = CoordinatorClient::new(
            "https://coordinator.mesh".to_owned(),
            Some(cert.as_path()),
            Some(key.as_path()),
            None,
            false,
        )
        .unwrap_err();
        assert!(matches!(err, JoinerError::InvalidConfig(_)));
    }

    /// Happy path mTLS build: generate a self-signed cert on the fly,
    /// reuse it as both client cert and CA, and confirm the client
    /// builder succeeds. Doesn't actually open a connection — just
    /// asserts the cert parse / loader pipeline is wired up right.
    #[test]
    fn new_secure_builds_client_with_valid_pems() {
        let dir = tempfile::TempDir::new().unwrap();
        let cert = rcgen::generate_simple_self_signed(vec!["mesh-joiner".to_owned()]).unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();

        let cert_path = dir.path().join("client.pem");
        let key_path = dir.path().join("client.key");
        let ca_path = dir.path().join("ca.pem");
        std::fs::write(&cert_path, &cert_pem).unwrap();
        std::fs::write(&key_path, &key_pem).unwrap();
        // Self-sign so we can reuse the cert as a trust anchor.
        std::fs::write(&ca_path, &cert_pem).unwrap();

        let client = CoordinatorClient::new(
            "https://coordinator.mesh".to_owned(),
            Some(cert_path.as_path()),
            Some(key_path.as_path()),
            Some(ca_path.as_path()),
            false,
        );
        assert!(client.is_ok(), "expected ok, got error: {:?}", client.err());
    }
}
