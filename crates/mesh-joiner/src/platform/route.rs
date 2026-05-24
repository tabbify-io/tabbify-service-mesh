//! Per-peer `/128` route management (spec §5.5 — TX route scoping).
//!
//! The joiner no longer routes the blanket overlay `/48` to the TUN
//! device. Instead it installs one host route per peer it has a session
//! with, so the kernel only delivers the TUN packets bound for addresses
//! we have a permitted session for. [`TunRouteSink`] bridges this into
//! [`crate::wg::session::SessionTable`]: every session insert installs
//! the peer's `/128`, every removal tears it down.
//!
//! Address assignment + the blanket-route helper retained for reference
//! live in the parent [`super`] module; this submodule is route-only.
//! Both share the [`super::run_command`] shell-out helper.

use crate::error::{JoinerError, Result};
use crate::platform::run_command;
use crate::wg::session::RouteSink;
use std::net::Ipv6Addr;
use std::sync::Arc;

/// Install a per-peer `/128` host route for `peer_ula` via `iface`
/// (spec §5.5 — TX route scoping).
///
/// Idempotent: a duplicate add (route already present from a prior
/// session) is treated as success by [`super::run_command`]'s
/// `File exists` tolerance.
///
/// # Errors
///
/// Returns [`JoinerError::TunSetup`] on any non-idempotent failure
/// (missing privileges, bad interface, etc.).
pub async fn add_peer_route(iface: &str, peer_ula: Ipv6Addr) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        run_command(
            "route",
            &[
                "-n",
                "add",
                "-inet6",
                "-host",
                &peer_ula.to_string(),
                "-interface",
                iface,
            ],
        )
        .await
    }
    #[cfg(target_os = "linux")]
    {
        run_command(
            "ip",
            &[
                "-6",
                "route",
                "add",
                &format!("{peer_ula}/128"),
                "dev",
                iface,
            ],
        )
        .await
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (iface, peer_ula);
        Err(JoinerError::TunSetup(
            "unsupported platform — only macOS and Linux are wired".into(),
        ))
    }
}

/// Remove the per-peer `/128` host route for `peer_ula` from `iface`.
///
/// Idempotent: removing an absent route ("not in table" / "no such
/// process") is treated as success.
///
/// # Errors
///
/// Returns [`JoinerError::TunSetup`] on any other failure.
pub async fn del_peer_route(iface: &str, peer_ula: Ipv6Addr) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        run_command(
            "route",
            &[
                "-n",
                "delete",
                "-inet6",
                "-host",
                &peer_ula.to_string(),
                "-interface",
                iface,
            ],
        )
        .await
        .or_else(|e| {
            if let JoinerError::TunSetup(ref msg) = e {
                let lower = msg.to_lowercase();
                if lower.contains("not in table") || lower.contains("no such") {
                    return Ok(());
                }
            }
            Err(e)
        })
    }
    #[cfg(target_os = "linux")]
    {
        run_command(
            "ip",
            &[
                "-6",
                "route",
                "del",
                &format!("{peer_ula}/128"),
                "dev",
                iface,
            ],
        )
        .await
        .or_else(|e| {
            if let JoinerError::TunSetup(ref msg) = e {
                let lower = msg.to_lowercase();
                if lower.contains("no such process") || lower.contains("not found") {
                    return Ok(());
                }
            }
            Err(e)
        })
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (iface, peer_ula);
        Err(JoinerError::TunSetup(
            "unsupported platform — only macOS and Linux are wired".into(),
        ))
    }
}

/// [`RouteSink`] backed by the host kernel routing table.
///
/// Holds the overlay TUN interface name and translates every session
/// insert / removal in [`crate::wg::session::SessionTable`] into a
/// per-peer `/128` route add / delete (spec §5.5 — TX scoping). Because
/// `RouteSink` is synchronous but the route commands are async
/// shell-outs, each call spawns a detached task: route installation is
/// fire-and-forget relative to session insertion, and failures are
/// logged (a missing route only costs reachability, never correctness —
/// the RX source check still enforces the invariant on the receive
/// side). The sink is only ever constructed inside the tokio runtime the
/// joiner runs under, so `tokio::spawn` always has a handle.
#[derive(Debug, Clone)]
pub struct TunRouteSink {
    iface: Arc<str>,
}

impl TunRouteSink {
    /// Build a sink for the given overlay TUN interface name.
    #[must_use]
    pub fn new(iface: impl Into<String>) -> Self {
        Self {
            iface: Arc::from(iface.into()),
        }
    }
}

impl RouteSink for TunRouteSink {
    fn add_allowed(&self, ula: Ipv6Addr) {
        let iface = self.iface.clone();
        tokio::spawn(async move {
            if let Err(e) = add_peer_route(&iface, ula).await {
                tracing::warn!(error = %e, %ula, iface = %iface, "route: add /128 failed");
            } else {
                tracing::debug!(%ula, iface = %iface, "route: installed peer /128");
            }
        });
    }

    fn remove_allowed(&self, ula: Ipv6Addr) {
        let iface = self.iface.clone();
        tokio::spawn(async move {
            if let Err(e) = del_peer_route(&iface, ula).await {
                tracing::warn!(error = %e, %ula, iface = %iface, "route: del /128 failed");
            } else {
                tracing::debug!(%ula, iface = %iface, "route: removed peer /128");
            }
        });
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    /// `add_peer_route` surfaces a typed `TunSetup` error against a bogus
    /// interface — the kernel rejects the interface name before any
    /// privilege check, so this needs no root.
    #[tokio::test]
    async fn add_peer_route_surfaces_typed_error_on_bogus_iface() {
        let ula: Ipv6Addr = "fd5a:1f00:1::1".parse().unwrap();
        match add_peer_route("tabbify-no-such-iface-xyzzy", ula).await {
            Err(JoinerError::TunSetup(_)) => {}
            Err(other) => panic!("expected TunSetup, got {other:?}"),
            Ok(()) => panic!("unexpectedly succeeded against bogus iface"),
        }
    }

    /// `del_peer_route` either swallows the absent-route case as success
    /// (its idempotent contract) or surfaces a typed `TunSetup`. Either
    /// way it must not panic or leak a foreign error variant.
    #[tokio::test]
    async fn del_peer_route_is_idempotent_or_typed_on_bogus_iface() {
        let ula: Ipv6Addr = "fd5a:1f00:1::1".parse().unwrap();
        match del_peer_route("tabbify-no-such-iface-xyzzy", ula).await {
            Ok(()) | Err(JoinerError::TunSetup(_)) => {}
            Err(other) => panic!("expected TunSetup, got {other:?}"),
        }
    }

    /// `TunRouteSink::new` accepts both `&str` and `String` (via
    /// `Into<String>`) — a small ergonomics guard for the call site in
    /// `joiner.rs`, which passes an owned interface name.
    #[test]
    fn route_sink_constructs_from_str_and_string() {
        let _ = TunRouteSink::new("utun7");
        let _ = TunRouteSink::new(String::from("tabbify-mesh0"));
    }
}
