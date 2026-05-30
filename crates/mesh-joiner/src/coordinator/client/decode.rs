//! Wire-shape decoders + HTTP-response unpacking shared by every
//! [`super::CoordinatorClient`] method.
//!
//! * [`decode_pubkey`] — base64 → `[u8; 32]` with a typed error.
//! * [`remote_to_info`] — turn a [`RemotePeer`] (wire shape) into the
//!   public [`PeerInfo`], resolving listen-endpoint hostnames if any.
//! * [`ensure_success`] / [`take_body_excerpt`] / [`body_excerpt_bytes`]
//!   — drain a [`reqwest::Response`] into either the parsed `T` or a
//!   typed [`JoinerError`] with a short body excerpt for the operator.

use crate::error::{JoinerError, Result};
use crate::peer::{PeerInfo, RemotePeer};
use base64::engine::{Engine as _, general_purpose::STANDARD as B64};
use std::net::{Ipv6Addr, SocketAddr};

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
        software_version: r.software_version.clone(),
        joined_at_micros: r.joined_at_micros,
    })
}

/// Drain a [`reqwest::Response`] into either a deserialised body or a
/// typed `JoinerError` if status or JSON shape disagree with what the
/// caller asked for.
pub(super) async fn ensure_success<T>(url: &str, resp: reqwest::Response) -> Result<T>
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
pub(super) async fn take_body_excerpt(resp: reqwest::Response) -> String {
    match resp.bytes().await {
        Ok(b) => body_excerpt_bytes(&b),
        Err(e) => format!("<body read failed: {e}>"),
    }
}

pub(super) fn body_excerpt_bytes(bytes: &[u8]) -> String {
    let s = String::from_utf8_lossy(bytes);
    if s.len() > 2_048 {
        format!("{}...<truncated>", &s[..2_048])
    } else {
        s.into_owned()
    }
}
