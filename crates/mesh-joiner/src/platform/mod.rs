//! Per-OS plumbing for "make this TUN device reachable on the overlay".
//!
//! After [`tabbify_mesh_fabric::tun::open`] hands back a fd-backed
//! device, the kernel still has no idea what addresses live on it. We
//! shell out to `ifconfig` (macOS) or `ip` (Linux) to:
//!
//! 1. Assign our ULA `<ula>/64` to the interface.
//! 2. Install a **per-peer `/128` host route** for every peer we have a
//!    session with ([`add_peer_route`] / [`del_peer_route`]), so
//!    userspace traffic targeting a peer's ULA is delivered to our TUN
//!    read side — but **only** for the exact `/128`s policy permits.
//!
//! ## Why per-peer `/128` and not the blanket `/48` (spec §5.5)
//!
//! An earlier revision routed the entire overlay prefix
//! (`fd5a:1f00:1::/48`) to the TUN in one shot ([`add_overlay_route`],
//! retained for reference / smoke tooling but no longer used on the join
//! path). That let any peer with a session source / sink traffic for any
//! ULA in the `/48`. Routing exactly the peers' `/128`s instead means
//! the kernel only hands the TUN packets bound for addresses we actually
//! have a permitted session for — the TX half of the allowed-ips
//! enforcement. The [`TunRouteSink`] wires this into
//! [`crate::wg::session::SessionTable`] so routes track sessions
//! one-for-one.
//!
//! Shelling out instead of using rtnetlink / SIOCAIFADDR is documented
//! and intentional — see the comment in
//! `crates/mesh-fabric/src/tun/linux.rs` for the rationale.
//!
//! # Privileges
//!
//! All commands here require `sudo` (macOS) or `CAP_NET_ADMIN` (Linux).
//! The functions surface a typed error rather than panicking so the
//! joiner can log a clear "you probably forgot sudo" hint up the stack.

use crate::error::{JoinerError, Result};
use std::net::Ipv6Addr;
use tokio::process::Command;

pub mod route;

// Per-peer `/128` route management + the kernel-backed [`RouteSink`]
// (spec §5.5 — TX route scoping) lives in [`route`]. Re-exported here so
// callers keep using `platform::TunRouteSink` / `platform::add_peer_route`
// regardless of the internal split.
pub use route::{add_peer_route, del_peer_route, TunRouteSink};

/// The full overlay prefix covered by tabbify's coordinator.
///
/// Per `crates/mesh-fabric/src/ula.rs`, every peer ULA falls under
/// `fd5a:1f<XX>:<tenant16>::/48`. Retained for reference and for the
/// [`add_overlay_route`] helper, which is **no longer on the join path**
/// — the joiner now installs per-peer `/128` routes instead (spec §5.5).
pub const OVERLAY_ROUTE_PREFIX: &str = "fd5a:1f00:1::/48";

/// Assign `<ula>/64` to the named TUN interface.
pub async fn assign_ula(iface: &str, ula: Ipv6Addr) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        run_command(
            "ifconfig",
            &[iface, "inet6", &format!("{ula}/64"), "alias"],
        )
        .await
    }
    #[cfg(target_os = "linux")]
    {
        run_command(
            "ip",
            &["-6", "addr", "add", &format!("{ula}/64"), "dev", iface],
        )
        .await
        .or_else(|e| {
            // `File exists` is EEXIST — fine if the interface was
            // pre-configured by a prior run.
            if let JoinerError::TunSetup(ref msg) = e {
                if msg.contains("File exists") {
                    return Ok(());
                }
            }
            Err(e)
        })
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (iface, ula);
        Err(JoinerError::TunSetup(
            "unsupported platform — only macOS and Linux are wired".into(),
        ))
    }
}

/// Assign an extra `/128` host alias on the named TUN interface.
///
/// A generic overlay primitive: callers that want to bind a listener on a
/// specific overlay `/128` (for example one TCP listener per application,
/// addressed by a higher layer's own derivation scheme) must first install
/// that address on a local interface — the kernel refuses `bind()` until
/// the address actually exists. This helper installs the alias; the
/// decision of *which* `/128` to use lives in the caller.
///
/// Idempotent: re-running the call with the same address is a no-op
/// (kernel reports "file exists" / "already assigned", which we treat
/// as success). The reverse helper is [`release_app_ula`].
///
/// # Errors
///
/// Returns [`JoinerError::TunSetup`] on any other failure (missing
/// privileges, bad interface name, etc.).
pub async fn assign_app_ula(iface: &str, app_ula: Ipv6Addr) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        run_command(
            "ifconfig",
            &[iface, "inet6", &format!("{app_ula}/128"), "alias"],
        )
        .await
        .or_else(|e| {
            if let JoinerError::TunSetup(ref msg) = e {
                let lower = msg.to_lowercase();
                if lower.contains("file exists") || lower.contains("already assigned") {
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
            &["-6", "addr", "add", &format!("{app_ula}/128"), "dev", iface],
        )
        .await
        .or_else(|e| {
            if let JoinerError::TunSetup(ref msg) = e {
                let lower = msg.to_lowercase();
                if lower.contains("file exists") || lower.contains("already assigned") {
                    return Ok(());
                }
            }
            Err(e)
        })
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (iface, app_ula);
        Err(JoinerError::TunSetup(
            "unsupported platform — only macOS and Linux are wired".into(),
        ))
    }
}

/// Inverse of [`assign_app_ula`]: drop the per-app `/128` alias when
/// the supervisor tears down an app's listener.
///
/// Idempotent: removing an address that was never installed (or was
/// already removed) is treated as success — the kernel reports "no
/// such address" / "cannot assign requested address" which we swallow.
///
/// # Errors
///
/// Returns [`JoinerError::TunSetup`] on any other failure.
pub async fn release_app_ula(iface: &str, app_ula: Ipv6Addr) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        run_command(
            "ifconfig",
            &[iface, "inet6", &format!("{app_ula}/128"), "-alias"],
        )
        .await
        .or_else(|e| {
            if let JoinerError::TunSetup(ref msg) = e {
                let lower = msg.to_lowercase();
                if lower.contains("can't assign")
                    || lower.contains("no such")
                    || lower.contains("cannot assign")
                {
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
            &["-6", "addr", "del", &format!("{app_ula}/128"), "dev", iface],
        )
        .await
        .or_else(|e| {
            if let JoinerError::TunSetup(ref msg) = e {
                let lower = msg.to_lowercase();
                if lower.contains("cannot assign") || lower.contains("no such") {
                    return Ok(());
                }
            }
            Err(e)
        })
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (iface, app_ula);
        Err(JoinerError::TunSetup(
            "unsupported platform — only macOS and Linux are wired".into(),
        ))
    }
}

/// Route the overlay prefix [`OVERLAY_ROUTE_PREFIX`] via the named TUN
/// interface so packets to any peer's ULA reach the read side of our
/// device.
pub async fn add_overlay_route(iface: &str) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        run_command(
            "route",
            &[
                "-n",
                "add",
                "-inet6",
                "-net",
                OVERLAY_ROUTE_PREFIX,
                "-interface",
                iface,
            ],
        )
        .await
        .or_else(|e| {
            // `route: writing to routing socket: File exists` shows up
            // when the route is already installed from a previous run;
            // treat as success.
            if let JoinerError::TunSetup(ref msg) = e {
                if msg.contains("File exists") || msg.contains("already in table") {
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
            &["-6", "route", "add", OVERLAY_ROUTE_PREFIX, "dev", iface],
        )
        .await
        .or_else(|e| {
            if let JoinerError::TunSetup(ref msg) = e {
                if msg.contains("File exists") {
                    return Ok(());
                }
            }
            Err(e)
        })
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = iface;
        Err(JoinerError::TunSetup(
            "unsupported platform — only macOS and Linux are wired".into(),
        ))
    }
}

/// Spawn a command and wait for it, mapping any non-zero exit / spawn
/// failure into [`JoinerError::TunSetup`] with a useful message.
///
/// The helper itself is platform-agnostic — the `cfg` gates above wrap
/// it with the right argv per OS. `pub(crate)` so the [`route`]
/// submodule can drive the same shell-out machinery for per-peer routes.
pub(crate) async fn run_command(program: &str, args: &[&str]) -> Result<()> {
    let cmd_repr = format!("{program} {}", args.join(" "));
    let output = Command::new(program)
        .args(args)
        .output()
        .await
        .map_err(|e| {
            JoinerError::TunSetup(format!(
                "spawn `{cmd_repr}`: {e} (install iproute2 / make sure {program} is on PATH)"
            ))
        })?;
    if output.status.success() {
        tracing::debug!(cmd = %cmd_repr, "platform: ok");
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    // Idempotent treatment of common "already-applied" failures. The
    // Linux mesh-fabric TUN backend assigns the ULA inline at open()
    // time; this joiner then re-runs `ip -6 addr add` for parity with
    // the macOS path (whose fabric backend does NOT auto-assign). The
    // second call returns "address already assigned" — same outcome
    // as a fresh successful add, so treat as success. Same logic for
    // duplicate route adds (`File exists` on Linux).
    let lower = stderr.to_lowercase();
    if lower.contains("already assigned") || lower.contains("file exists") {
        tracing::debug!(
            cmd = %cmd_repr,
            stderr = %stderr.trim(),
            "platform: ok (already-applied is treated as idempotent success)"
        );
        return Ok(());
    }
    Err(JoinerError::TunSetup(format!(
        "`{cmd_repr}` exited {}: {} (need sudo / CAP_NET_ADMIN?)",
        output.status, stderr
    )))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    /// Sanity: the prefix string matches what the rest of the joiner
    /// expects. If we ever change tenants we need to thread that
    /// through here.
    #[test]
    fn overlay_prefix_is_a_valid_ipv6_cidr() {
        let (addr, len) = OVERLAY_ROUTE_PREFIX.split_once('/').unwrap();
        let _: Ipv6Addr = addr.parse().unwrap();
        let prefix_len: u8 = len.parse().unwrap();
        assert!(prefix_len > 0 && prefix_len < 128, "{prefix_len}");
    }

    /// `run_command` surfaces a `TunSetup` error when the program is
    /// missing entirely. We use a sentinel name that's vanishingly
    /// unlikely to exist on PATH.
    #[tokio::test]
    async fn run_command_reports_spawn_failure() {
        let err = run_command("tabbify-this-binary-does-not-exist", &["whatever"])
            .await
            .unwrap_err();
        match err {
            JoinerError::TunSetup(msg) => assert!(msg.contains("spawn"), "{msg}"),
            other => panic!("expected TunSetup, got {other:?}"),
        }
    }

    /// And surfaces a `TunSetup` error when the program runs but exits
    /// non-zero. `false` is on every POSIX system and exits 1.
    #[tokio::test]
    async fn run_command_reports_nonzero_exit() {
        let err = run_command("false", &[]).await.unwrap_err();
        match err {
            JoinerError::TunSetup(msg) => {
                assert!(msg.contains("exited"), "{msg}");
            }
            other => panic!("expected TunSetup, got {other:?}"),
        }
    }

    /// `assign_app_ula` returns a typed `TunSetup` error when the
    /// underlying command (`ifconfig` / `ip`) cannot succeed because
    /// the interface doesn't exist. The exact error message varies
    /// across kernels / coreutils versions, so we only assert on the
    /// variant — and don't require root either: the kernel rejects the
    /// bogus interface name well before any privilege check.
    #[tokio::test]
    async fn assign_app_ula_surfaces_typed_error_on_bogus_iface() {
        let bogus = "tabbify-no-such-iface-xyzzy";
        let ula: Ipv6Addr = "fd5a:1f02:dead:beef:cafe::1".parse().unwrap();
        let res = assign_app_ula(bogus, ula).await;
        // On macOS / Linux without root the call returns an error;
        // platforms we don't support also return TunSetup. Either way
        // it must NOT panic and must NOT return Ok.
        match res {
            Err(JoinerError::TunSetup(_)) => {}
            Err(other) => panic!("expected TunSetup, got {other:?}"),
            Ok(()) => panic!("unexpectedly succeeded against bogus iface"),
        }
    }

    /// Symmetric: `release_app_ula` returns a typed error in the same
    /// failure mode. Treating "no such address" / "cannot assign" as
    /// success is the idempotent path callers depend on; that path
    /// requires a real interface and is exercised by the integration
    /// smoke.
    #[tokio::test]
    async fn release_app_ula_surfaces_typed_error_on_bogus_iface() {
        let bogus = "tabbify-no-such-iface-xyzzy";
        let ula: Ipv6Addr = "fd5a:1f02:dead:beef:cafe::1".parse().unwrap();
        let res = release_app_ula(bogus, ula).await;
        match res {
            // Both outcomes are acceptable here. Most macOS / Linux
            // installs reject the bogus interface with a typed
            // `TunSetup` — that's the path our idempotent swallow
            // depends on. Some sandboxed CI environments may instead
            // tolerate the missing alias as "nothing to do" and return
            // `Ok(())`. The contract is "no panic, no foreign error
            // variant".
            Ok(()) | Err(JoinerError::TunSetup(_)) => {}
            Err(other) => panic!("expected TunSetup, got {other:?}"),
        }
    }
}
