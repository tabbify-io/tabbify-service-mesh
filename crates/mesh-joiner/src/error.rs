//! Library-level error types for `tabbify-mesh-joiner`.
//!
//! Public functions that orchestrate the whole join lifecycle
//! ([`crate::Joiner::join`], [`crate::Joiner::leave`]) return
//! `anyhow::Result` so callers can use `?` without caring about the
//! exact failure mode. Internal helpers return the concrete
//! [`JoinerError`] variants below so unit tests can pattern-match
//! against them.

use std::net::SocketAddr;
use thiserror::Error;

/// All non-anyhow errors produced by `tabbify-mesh-joiner`.
#[derive(Debug, Error)]
pub enum JoinerError {
    /// HTTP transport failure while talking to the coordinator (network
    /// down, TLS handshake refused, DNS, etc.). The contained string
    /// quotes `reqwest::Error::to_string` so we don't pull `reqwest`
    /// types into the public surface.
    #[error("coordinator http transport: {0}")]
    HttpTransport(String),

    /// Coordinator returned a non-success status code.
    #[error("coordinator http status {status}: {body}")]
    HttpStatus {
        /// HTTP status code as reported by the coordinator.
        status: u16,
        /// First few KB of the response body — useful for debugging
        /// authentication / validation failures.
        body: String,
    },

    /// JSON serialisation / deserialisation failed for a coordinator
    /// payload. Distinct from [`Self::HttpStatus`] because a 200 with
    /// garbled JSON is just as fatal as a 5xx.
    #[error("coordinator json codec: {0}")]
    JsonCodec(String),

    /// Coordinator returned a `wg_public_key` that decodes from base64
    /// but isn't 32 bytes, an `ula` that doesn't parse as IPv6, or
    /// otherwise malformed peer metadata.
    #[error("coordinator returned malformed peer record: {0}")]
    MalformedPeer(String),

    /// The locally requested UDP port could not be bound.
    #[error("udp bind {addr}: {source}")]
    UdpBind {
        /// The address the joiner attempted to bind.
        addr: SocketAddr,
        /// Underlying OS error.
        source: std::io::Error,
    },

    /// Opening the TUN device or assigning the ULA to it failed. Almost
    /// always a missing-sudo / missing-`CAP_NET_ADMIN` situation.
    #[error("tun device setup failed: {0}")]
    TunSetup(String),

    /// The background SSE stream from the coordinator dropped and the
    /// joiner could not reconnect within the configured budget. The
    /// joiner keeps running with its last-known roster but new peers
    /// won't be discovered until SSE recovers.
    #[error("coordinator peer-stream lost: {0}")]
    PeerStreamLost(String),

    /// Caller-supplied `JoinConfig` rejected validation before any I/O
    /// (bad `advertise_endpoint` string, etc.).
    #[error("invalid join config: {0}")]
    InvalidConfig(String),
}

/// Convenience alias for internal `Result`s.
pub type Result<T> = std::result::Result<T, JoinerError>;
