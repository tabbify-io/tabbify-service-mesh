//! Cross-platform TUN device abstraction for [`crate::wireguard::WireGuardFabric`].
//!
//! # Why this module exists
//!
//! `WireGuardFabric` runs the same boringtun state machine on every
//! host, but the kernel-side "give me a userspace IP interface" API is
//! **completely different per OS**:
//!
//! * **macOS** uses the `PF_SYSTEM` socket family + the
//!   `com.apple.net.utun_control` kernel control. Device names must
//!   start with `utun` and the kernel picks the index.
//! * **Linux** uses `open("/dev/net/tun")` + the `TUNSETIFF` ioctl on
//!   the returned fd. Device names are arbitrary up to `IFNAMSIZ-1`.
//! * **BSDs, Windows, ...** each have their own variant we don't
//!   support today.
//!
//! Instead of sprinkling `#[cfg(target_os = "...")]` through the
//! fabric, this module wraps the OS-specific code in a single
//! [`crate::tun::TunDevice`] trait. `WireGuardFabric` only ever calls
//! [`crate::tun::open`] / [`crate::tun::TunDevice::read_packet`] /
//! [`crate::tun::TunDevice::write_packet`] — the per-OS pain stays
//! under `tun/`.
//!
//! # Backend status
//!
//! Both the macOS and Linux backends are **real implementations**, not
//! skeletons:
//!
//! * macOS (`tun/macos.rs`): `socket(PF_SYSTEM)` → `ioctl(CTLIOCGINFO)`
//!   → `connect(sockaddr_ctl)` → `getsockopt(UTUN_OPT_IFNAME)` →
//!   `fcntl(O_NONBLOCK)`, with `AsyncFd`-based `read_packet` /
//!   `write_packet` stripping / prepending the 4-byte AF header.
//! * Linux (`tun/linux.rs`): `open("/dev/net/tun")` →
//!   `ioctl(TUNSETIFF, IFF_TUN|IFF_NO_PI)` → `ip -6 addr add` +
//!   `ip link set up`, with `AsyncFd` I/O.
//!
//! Opening a device performs genuine syscalls and requires elevated
//! privileges (root / `sudo` on macOS, `CAP_NET_ADMIN` on Linux). Only
//! unsupported platforms return
//! [`crate::tun::TunError::UnsupportedPlatform`].
//!
//! Pure-UDP `WireGuardFabric` tests
//! (`tests/wireguard_udp.rs`) do not depend on this module at all and
//! continue to pass on every platform.
//!
//! # Intended caller
//!
//! ```ignore
//! use tabbify_mesh_fabric::tun::{self, TunOptions};
//!
//! let dev = tun::open(TunOptions {
//!     name: "utun7".into(),       // or "wg-tabbify" on Linux
//!     ula: "fd5a:1f00:0001::1".parse().unwrap(),
//!     mtu: 1420,
//! })
//! .await?;
//!
//! // Read inbound IPv6 frames from the kernel, hand them to
//! // `WireGuardFabric::send`. Write decrypted IPv6 frames from
//! // `WireGuardFabric`'s receive path back to the device.
//! ```

use async_trait::async_trait;
use std::io;
use std::net::Ipv6Addr;
use thiserror::Error;

/// Options for opening a TUN device.
///
/// Some fields are interpreted differently per OS — see the platform
/// modules (`macos` / `linux`, each cfg-gated to its OS) for the
/// constraints.
#[derive(Debug, Clone)]
pub struct TunOptions {
    /// Suggested interface name.
    ///
    /// * **macOS**: MUST start with `utun` (e.g., `utun7`) or be left
    ///   empty for the kernel to auto-assign the next free index.
    /// * **Linux**: Any name up to `IFNAMSIZ - 1` bytes
    ///   (15 on current kernels). Empty string asks the kernel to
    ///   allocate `tun%d`.
    pub name: String,

    /// IPv6 ULA to assign to the interface. The `/64` prefix is
    /// implied — the OS-specific code writes the prefix length
    /// separately (`64`).
    pub ula: Ipv6Addr,

    /// MTU in bytes.
    ///
    /// Typical `WireGuard` MTU = **1420** (Ethernet 1500 − IPv6 40 −
    /// UDP 8 − WG 32). Values outside `[576, 9000]` will be rejected
    /// by most kernels.
    pub mtu: u16,
}

/// Async TUN device handle. Drop tears down the kernel-side interface
/// (closes the fd and lets the OS reclaim the index).
///
/// Implementations must be `Send + Sync + 'static` so callers can park
/// them inside `Arc<dyn TunDevice>`.
#[async_trait]
pub trait TunDevice: Send + Sync + 'static {
    /// Interface name as assigned by the kernel.
    ///
    /// On macOS this is always `utun<N>`. On Linux this is whatever
    /// the kernel returned via `TUNSETIFF` — typically the requested
    /// [`TunOptions::name`], possibly substituted if a `%d` template
    /// was used.
    fn name(&self) -> &str;

    /// Read one IP packet from the device. Returns the number of
    /// bytes written into `buf`. Blocks asynchronously until a packet
    /// arrives.
    ///
    /// The buffer should be at least MTU+4 bytes on macOS (the kernel
    /// prepends a 4-byte address-family header to every utun frame)
    /// or MTU bytes on Linux when `IFF_NO_PI` is set (the default
    /// here).
    async fn read_packet(&self, buf: &mut [u8]) -> io::Result<usize>;

    /// Write one IP packet to the device.
    ///
    /// `buf` must contain a valid IP packet (IPv6 frame in our
    /// case). On macOS the implementation prepends the 4-byte
    /// address-family header before passing the bytes to the kernel.
    async fn write_packet(&self, buf: &[u8]) -> io::Result<usize>;
}

/// Errors returned by TUN management.
#[derive(Debug, Error)]
pub enum TunError {
    /// This platform has no TUN implementation in mesh-fabric.
    /// Currently emitted by every backend while the skeleton stands
    /// (see module docs).
    #[error("tun unsupported on this platform")]
    UnsupportedPlatform,

    /// Underlying I/O failure (typically wrapping `open(2)`,
    /// `ioctl(2)`, or async read/write).
    #[error("io: {0}")]
    Io(#[from] io::Error),

    /// Caller lacks privilege to open the device (e.g., not root on
    /// macOS, missing `CAP_NET_ADMIN` on Linux).
    #[error("permission denied: {0}")]
    PermissionDenied(String),

    /// [`TunOptions::name`] violates a kernel constraint (e.g., not
    /// starting with `utun` on macOS, too long for `IFNAMSIZ`).
    #[error("invalid name: {0}")]
    InvalidName(String),

    /// The requested interface name is already in use by another
    /// process or instance. On macOS this surfaces when
    /// `connect(sockaddr_ctl)` returns `EBUSY` because the chosen
    /// `utun<N>` unit is already bound by another fd. The caller
    /// should retry with a different name (or pass an empty string to
    /// let the kernel auto-assign).
    #[error("device busy: {0}")]
    DeviceBusy(String),
}

/// Open a TUN device with the given options.
///
/// The returned trait object holds the kernel-side resources until
/// dropped. Concrete behaviour is selected at compile time by the
/// per-OS modules.
///
/// # Errors
///
/// Returns [`TunError::UnsupportedPlatform`] on any platform without a
/// concrete backend (and currently on macOS / Linux too, while the
/// skeleton stands — see module docs).
#[cfg(target_os = "macos")]
pub async fn open(opts: TunOptions) -> Result<Box<dyn TunDevice>, TunError> {
    let dev = macos::open_impl(opts).await?;
    let boxed: Box<dyn TunDevice> = Box::new(dev);
    Ok(boxed)
}

/// Open a TUN device with the given options.
///
/// See the macOS arm of this function for full docs.
#[cfg(target_os = "linux")]
pub async fn open(opts: TunOptions) -> Result<Box<dyn TunDevice>, TunError> {
    let dev = linux::open_impl(opts).await?;
    let boxed: Box<dyn TunDevice> = Box::new(dev);
    Ok(boxed)
}

/// Open a TUN device with the given options.
///
/// See the macOS arm of this function for full docs.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub async fn open(_opts: TunOptions) -> Result<Box<dyn TunDevice>, TunError> {
    Err(TunError::UnsupportedPlatform)
}

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub mod unsupported;

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    /// Construction of [`TunOptions`] is a pure data shape — this test
    /// just guards against accidental signature drift.
    #[test]
    fn tun_options_round_trips_fields() {
        let opts = TunOptions {
            name: "utun7".into(),
            ula: "fd5a:1f00:0001::1".parse().unwrap(),
            mtu: 1420,
        };
        assert_eq!(opts.name, "utun7");
        assert_eq!(opts.mtu, 1420);
    }

    /// Unprivileged [`open`] surfaces a non-success error on every
    /// supported OS without panicking.
    ///
    /// We don't pin the exact variant because it varies by host:
    ///
    /// * **macOS** (real impl): `PermissionDenied` when not root, or
    ///   `Io` if the syscall fails for a non-EPERM reason. Could even
    ///   succeed if the test happens to run with sudo — fine,
    ///   the device drops out of scope on return.
    /// * **Linux** (real impl): `PermissionDenied` without
    ///   `CAP_NET_ADMIN`, `Io` if `iproute2` is missing.
    /// * **Other targets**: `UnsupportedPlatform` from the cfg-gated
    ///   fallback arm.
    ///
    /// We avoid `Result::expect_err` because `Box<dyn TunDevice>`
    /// intentionally does not implement `Debug` (the trait keeps the
    /// per-OS surface narrow — `name()` is the only string-shaped
    /// accessor).
    #[tokio::test]
    async fn open_returns_expected_error_when_unprivileged() {
        // macOS rejects non-`utun*` names eagerly with InvalidName,
        // so use a name that survives validation on both platforms.
        #[cfg(target_os = "macos")]
        let name = "utun9".to_owned();
        #[cfg(not(target_os = "macos"))]
        let name = String::new();

        let opts = TunOptions {
            name,
            ula: "fd5a:1f00:0001::1".parse().unwrap(),
            mtu: 1420,
        };
        match open(opts).await {
            Ok(_dev) => {
                // Running with privileges — fine, the dev handle drops
                // out of scope and the kernel tears the interface down.
                eprintln!(
                    "open() unexpectedly succeeded — test is running \
                     with elevated privileges; device handle will be \
                     dropped on return."
                );
            }
            Err(
                TunError::UnsupportedPlatform
                | TunError::PermissionDenied(_)
                | TunError::Io(_)
                | TunError::DeviceBusy(_),
            ) => {
                // All four are plausible unprivileged outcomes.
            }
            Err(other) => panic!("unexpected variant: {other:?}"),
        }
    }
}
