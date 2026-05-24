//! Integration test for the `WireGuardFabric` + cross-platform TUN
//! integration. **`#[ignore]` by default.**
//!
//! # Running this test
//!
//! ```bash
//! # macOS — currently always errors with UnsupportedPlatform; the
//! # macOS backend is still a skeleton (separate FU.6 follow-up).
//! sudo -E cargo test -p tabbify-mesh-fabric \
//!   --features wireguard \
//!   --test wireguard_tun \
//!   -- --ignored --nocapture
//!
//! # Linux — fully implemented. Requires root or CAP_NET_ADMIN on
//! # the test binary (`setcap cap_net_admin+ep` against the test
//! # binary under `target/debug/deps/wireguard_tun-*`).
//! sudo -E cargo test -p tabbify-mesh-fabric \
//!   --features wireguard \
//!   --test wireguard_tun \
//!   -- --ignored --nocapture
//! ```
//!
//! On a Mac dev host the easiest way to exercise the Linux path is
//! the Lima harness: see `scripts/lima-test-linux.sh` and
//! `docs/testing-on-linux.md`.
//!
//! # Why it's `#[ignore]`
//!
//! Opening a TUN device requires elevated privileges on every
//! supported OS:
//!
//! * **macOS** gates `socket(PF_SYSTEM, SOCK_DGRAM,
//!   SYSPROTO_CONTROL)` behind either the
//!   `com.apple.private.networkextension` entitlement (only granted
//!   to signed network-extension targets) or root.
//! * **Linux** requires `CAP_NET_ADMIN` (typically root, or `setcap
//!   cap_net_admin+ep` on the binary) to open `/dev/net/tun` and
//!   invoke `TUNSETIFF`.
//!
//! CI environments rarely grant either; running this test
//! unprivileged returns an `UnsupportedPlatform` / `PermissionDenied`
//! error and a misleading "test failed" signal.
//!
//! # What this test covers
//!
//! 1. Open a Linux TUN device with a unique name, assign an IPv6
//!    ULA, set MTU, bring the link up.
//! 2. Verify the interface exists via `ip -6 addr show <iface>` and
//!    that the configured ULA appears in the listing.
//! 3. Drop the device handle and verify the interface goes away
//!    (the kernel auto-removes it once the last fd referencing it is
//!    closed; we assert via `ip link show <iface>` exiting non-zero).
//!
//! Pure-WireGuard-over-UDP (no TUN) is covered by
//! `tests/wireguard_udp.rs` and runs unprivileged on every platform.
#![cfg(all(feature = "wireguard", any(target_os = "macos", target_os = "linux")))]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic, unsafe_code)]

use std::net::Ipv6Addr;
#[cfg(target_os = "linux")]
use std::process::Command;

#[tokio::test]
#[ignore = "requires sudo + macOS/Linux; on macOS the backend is still \
            a skeleton (FU.6 follow-up); on Linux this exercises real \
            /dev/net/tun ioctl"]
async fn tun_open_creates_real_interface_with_ula() {
    use tabbify_mesh_fabric::tun::{self, TunError, TunOptions};

    let ula: Ipv6Addr = "fd5a:1f00:0001::1".parse().expect("parse ula");

    // Use a unique-ish interface name so concurrent test runs (or
    // repeated runs without teardown) don't collide. Keep within
    // IFNAMSIZ-1 = 15 bytes on Linux.
    #[cfg(target_os = "macos")]
    let name = "utun9".to_owned();
    #[cfg(target_os = "linux")]
    let name = format!("tbfy{}", std::process::id() % 10_000); // <= 8 bytes

    let opts = TunOptions {
        name: name.clone(),
        ula,
        mtu: 1420,
    };

    let dev = match tun::open(opts).await {
        Ok(d) => d,
        Err(TunError::UnsupportedPlatform) => {
            // Currently only macOS hits this — surface a clear marker
            // pointing at the remaining skeleton.
            eprintln!(
                "tun::open returned UnsupportedPlatform — this is \
                 expected on macOS (skeleton, see \
                 crates/mesh-fabric/src/tun/macos.rs). Skipping \
                 interface assertions."
            );
            return;
        }
        Err(TunError::PermissionDenied(msg)) => {
            panic!(
                "tun::open returned PermissionDenied: {msg}\n\
                 \n\
                 Re-run with sudo (Linux: `sudo -E cargo test ... -- \
                 --ignored`) or grant CAP_NET_ADMIN to the test \
                 binary.",
            );
        }
        Err(other) => {
            panic!("unexpected tun error variant: {other:?}");
        }
    };

    let assigned_name = dev.name().to_owned();
    eprintln!("tun::open succeeded — interface name = {assigned_name}");

    // On Linux, query the kernel via `ip` to confirm the interface
    // exists and the ULA is bound. On macOS we'd shell out to
    // `ifconfig <iface>` — but the macOS path is still a skeleton, so
    // we returned early above.
    #[cfg(target_os = "linux")]
    {
        // 1. `ip -6 addr show <iface>` should list our ULA.
        let out = Command::new("ip")
            .args(["-6", "addr", "show", "dev", &assigned_name])
            .output()
            .expect("spawn ip -6 addr show");
        assert!(
            out.status.success(),
            "ip -6 addr show {assigned_name} exited {}: stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stderr),
        );
        let stdout = String::from_utf8_lossy(&out.stdout);
        let ula_str = ula.to_string();
        assert!(
            stdout.contains(&ula_str),
            "ip -6 addr show output did not contain ULA {ula_str}:\n\
             ---\n{stdout}---",
        );

        // 2. The interface should be UP — `ip link show` carries a
        //    `UP` flag in the brackets, e.g.
        //    `<BROADCAST,MULTICAST,UP,LOWER_UP>`.
        let link_out = Command::new("ip")
            .args(["link", "show", "dev", &assigned_name])
            .output()
            .expect("spawn ip link show");
        let link_stdout = String::from_utf8_lossy(&link_out.stdout);
        assert!(
            link_stdout.contains(",UP,") || link_stdout.contains("<UP,"),
            "interface {assigned_name} is not UP:\n---\n{link_stdout}---",
        );
    }

    // 3. Drop the device — the kernel should auto-remove the
    // interface since IFF_PERSIST wasn't set.
    drop(dev);

    // Give the kernel a beat to tear down. RTNL is fast but not
    // synchronous wrt the fd close on every kernel version.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    #[cfg(target_os = "linux")]
    {
        let teardown_out = Command::new("ip")
            .args(["link", "show", "dev", &assigned_name])
            .output()
            .expect("spawn ip link show (post-drop)");
        assert!(
            !teardown_out.status.success(),
            "interface {assigned_name} still exists after drop — \
             expected `ip link show` to fail with non-zero exit. \
             stdout={} stderr={}",
            String::from_utf8_lossy(&teardown_out.stdout),
            String::from_utf8_lossy(&teardown_out.stderr),
        );
    }
}
