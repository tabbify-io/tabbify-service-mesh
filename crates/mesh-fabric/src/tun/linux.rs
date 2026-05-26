// SAFETY: the entire Linux TUN backend talks to the kernel via
// `libc::{open, ioctl, read, write}`. Every unsafe block in this file
// is annotated with a per-call SAFETY comment justifying the
// invariants. The cfg-gate above guarantees we only compile this on
// Linux, so we don't smuggle unsafe code into the macOS host build.
#![allow(unsafe_code)]

//! Linux `/dev/net/tun` backend for the cross-platform
//! [`super::TunDevice`] abstraction.
//!
//! # Background
//!
//! Linux exposes virtual TUN/TAP devices via the multi-purpose
//! character device `/dev/net/tun`. The per-device sequence is:
//!
//! 1. `open("/dev/net/tun", O_RDWR | O_NONBLOCK | O_CLOEXEC)`
//! 2. Fill an `ifreq`:
//!    ```c
//!    struct ifreq ifr = { 0 };
//!    strncpy(ifr.ifr_name, "wg-tabbify", IFNAMSIZ);
//!    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
//!    ```
//! 3. `ioctl(fd, TUNSETIFF, &ifr)` — bind the fd to the named
//!    interface (creating it if needed). The kernel echoes the final
//!    name back into `ifr.ifr_name` (e.g., if `tun%d` was passed it
//!    becomes `tun0`).
//! 4. Bring the interface up + assign IPv6 via shell-out to `ip` (see
//!    [`bring_up`] and [`assign_ula`]). Production deploys can
//!    replace these with `rtnetlink` later — the trait surface stays
//!    the same.
//!
//! With `IFF_NO_PI` set, reads and writes carry **no** address-family
//! header — the bytes are pure IP packets. This is symmetric with the
//! macOS implementation modulo the 4-byte `AF_INET6` prefix that
//! macOS adds.
//!
//! # Async I/O
//!
//! The raw fd is wrapped in [`tokio::io::unix::AsyncFd`] so reads and
//! writes integrate with the tokio runtime. We use the
//! `ready_mut`/`try_io` dance rather than holding the readiness guard
//! across awaits, which would deadlock the runtime when multiple
//! consumers want to read concurrently.
//!
//! # Permissions
//!
//! Opening `/dev/net/tun` and calling `TUNSETIFF` both require
//! `CAP_NET_ADMIN`. The simplest deployment grants the capability via
//! `setcap cap_net_admin+ep tabbify-edge` on the binary, but root /
//! `sudo` works too. Integration tests are marked `#[ignore]` for the
//! same reason as on macOS.
//!
//! # Why shell out to `ip`?
//!
//! The kernel-side `TUNSETIFF` only creates the interface and binds
//! the fd — bringing the link up, setting MTU, and adding the IPv6
//! address are all separate operations that go via `rtnetlink`. We
//! shell out to the `ip` binary (always present on Linux distros that
//! ship `iproute2`) because:
//!
//! * `rtnetlink` is correct but ~500 LoC of typed message juggling for
//!   what is two-line `ip` commands.
//! * The substrate event log can carry the exact `ip` command for
//!   auditability without leaking netlink framing details.
//! * Production hardening is a clean swap behind [`bring_up`] /
//!   [`assign_ula`] — the trait surface in [`super::TunDevice`] does
//!   not change.
//!
//! If `ip` is missing (slim container images), we surface the failure
//! as [`super::TunError::Io`] with a hint pointing at `iproute2`.

use async_trait::async_trait;
use std::io;
use std::mem::MaybeUninit;
use std::net::Ipv6Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::process::Command;
use std::sync::Arc;
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;

use super::{TunDevice, TunError, TunOptions};

/// Maximum interface name length on current Linux kernels. Matches
/// `IFNAMSIZ - 1` from `<linux/if.h>` (the C constant is 16 including
/// the NUL terminator).
const LINUX_IFNAME_MAX: usize = 15;

/// `IFNAMSIZ` from `<linux/if.h>` — buffer size for the `ifr_name`
/// field, including the trailing NUL.
const IFNAMSIZ: usize = 16;

/// `IFF_TUN` from `<linux/if_tun.h>` — request a TUN (layer-3) device.
const IFF_TUN: libc::c_short = 0x0001;

/// `IFF_NO_PI` from `<linux/if_tun.h>` — suppress the 4-byte protocol
/// information header that the kernel would otherwise prepend to every
/// frame. With this flag set, reads/writes carry raw IP packets.
const IFF_NO_PI: libc::c_short = 0x1000;

/// `TUNSETIFF` ioctl number, as expanded by `_IOW('T', 202, int)` on
/// Linux. This is stable across all currently-supported kernel
/// versions (2.6+).
///
/// Encoded manually rather than via a `nix::ioctl_write_int!` macro to
/// avoid pulling in another crate. The four-byte hex form is what
/// `<linux/if_tun.h>` resolves to after macro expansion.
const TUNSETIFF: libc::c_ulong = 0x4004_54ca;

/// `ifreq` mirror — only the `ifr_name` + `ifr_flags` union members
/// are used during `TUNSETIFF`.
///
/// The real C `ifreq` is a discriminated union of ~12 variants
/// (`ifr_addr`, `ifr_mtu`, `ifr_data`, ...). For `TUNSETIFF` the
/// kernel only reads the name + flags, so we define exactly the layout
/// we need plus a tail-pad so the struct size matches `sizeof(struct
/// ifreq)` (40 bytes on glibc, identical on musl).
#[repr(C)]
struct Ifreq {
    /// Interface name. Must be NUL-terminated unless it fills the
    /// full 16 bytes (in which case the kernel does not require NUL).
    ifr_name: [libc::c_char; IFNAMSIZ],
    /// Flags union. We only ever store `IFF_TUN | IFF_NO_PI` here.
    ifr_flags: libc::c_short,
    /// Padding so the struct size matches the real `ifreq`. The
    /// kernel only inspects `ifr_name` + the first 2 bytes of the
    /// trailing union for `TUNSETIFF`, but it still memcpy's the full
    /// length back out, so the buffer must be the right size.
    _pad: [u8; 22],
}

const _ASSERT_IFREQ_SIZE: () = assert!(
    std::mem::size_of::<Ifreq>() == 40,
    "linux Ifreq must match sizeof(struct ifreq) = 40 bytes",
);

/// Open a Linux `/dev/net/tun` device.
///
/// # Errors
///
/// * [`super::TunError::InvalidName`] if `opts.name` exceeds 15 bytes
///   (the kernel's `IFNAMSIZ - 1`) or contains a `/` or NUL.
/// * [`super::TunError::PermissionDenied`] if the process lacks
///   `CAP_NET_ADMIN` (open(2) returns EPERM/EACCES, or TUNSETIFF does).
/// * [`super::TunError::Io`] for any other syscall failure, including
///   `ip link set` / `ip -6 addr add` shell-outs.
pub async fn open_impl(opts: TunOptions) -> Result<LinuxTunDevice, TunError> {
    if opts.name.len() > LINUX_IFNAME_MAX {
        return Err(TunError::InvalidName(format!(
            "linux interface names must be <= {LINUX_IFNAME_MAX} \
             bytes (got {} = {:?})",
            opts.name.len(),
            opts.name
        )));
    }
    if opts.name.contains('/') || opts.name.contains('\0') {
        return Err(TunError::InvalidName(format!(
            "linux interface names cannot contain '/' or NUL (got \
             {:?})",
            opts.name
        )));
    }

    // Step 1: open the multiplexer.
    let owned_fd = open_tun_dev()?;

    // Step 2 + 3: bind the fd to a named TUN interface. The kernel
    // echoes the final name back into the ifreq (relevant when
    // `opts.name` is empty — it'll be filled with `tun%d`).
    let final_name = tunsetiff(owned_fd.as_raw_fd(), &opts.name)?;

    tracing::debug!(
        requested = %if opts.name.is_empty() { "<auto>" } else { &opts.name },
        assigned = %final_name,
        ula = %opts.ula,
        mtu = opts.mtu,
        "tun/linux: TUNSETIFF bound fd to interface",
    );

    // Step 4a: assign the IPv6 ULA. Must happen before bringing the
    // link up so DAD (duplicate address detection) sees the address
    // when the interface first transitions to UP.
    assign_ula(&final_name, opts.ula).map_err(|e| {
        TunError::Io(io::Error::other(format!(
            "ip -6 addr add failed for {final_name}: {e}"
        )))
    })?;

    // Step 4b: bring the link up + set MTU. We do this in a single
    // `ip link set` invocation so a half-configured interface isn't
    // observable from userspace.
    bring_up(&final_name, opts.mtu).map_err(|e| {
        TunError::Io(io::Error::other(format!(
            "ip link set failed for {final_name}: {e}"
        )))
    })?;

    // Wrap the fd in an AsyncFd for tokio integration. The fd was
    // opened with O_NONBLOCK so all I/O is non-blocking and ready
    // notifications come via epoll.
    let async_fd = AsyncFd::with_interest(owned_fd, Interest::READABLE | Interest::WRITABLE)
        .map_err(TunError::Io)?;

    Ok(LinuxTunDevice {
        name: final_name,
        fd: Arc::new(async_fd),
        mtu: opts.mtu,
    })
}

/// Open `/dev/net/tun` with the flags required for TUN multiplexing.
///
/// Returns an [`OwnedFd`] so the kernel resource is dropped
/// deterministically if any later step (TUNSETIFF, `ip` shell-out)
/// fails.
fn open_tun_dev() -> Result<OwnedFd, TunError> {
    let path = c"/dev/net/tun";
    // SAFETY: `path` is a `&CStr` (compile-time NUL-terminated). The
    // flags are documented as a bitwise OR of `O_*` constants. open(2)
    // returns -1 on error, otherwise a valid file descriptor — we
    // adopt it into an `OwnedFd` so Drop closes it.
    let raw = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDWR | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        let err = io::Error::last_os_error();
        return Err(match err.raw_os_error() {
            Some(libc::EPERM | libc::EACCES) => TunError::PermissionDenied(format!(
                "open(/dev/net/tun) failed: {err} (need CAP_NET_ADMIN \
                 or root)"
            )),
            Some(libc::ENOENT) => TunError::Io(io::Error::new(
                err.kind(),
                "/dev/net/tun missing — load the `tun` kernel module \
                 (modprobe tun) or run on a kernel built with \
                 CONFIG_TUN=y",
            )),
            _ => TunError::Io(err),
        });
    }
    // SAFETY: `raw` is a fresh fd from open(2) that we've just
    // checked is non-negative. We have not transferred ownership
    // elsewhere yet, so this is the unique owner.
    Ok(unsafe { OwnedFd::from_raw_fd(raw as RawFd) })
}

/// Issue the `TUNSETIFF` ioctl to bind `fd` to a TUN interface.
///
/// Returns the final interface name as assigned by the kernel.
fn tunsetiff(fd: RawFd, requested_name: &str) -> Result<String, TunError> {
    // Zero-init the ifreq first; the kernel reads past `ifr_flags`
    // for some operations (not TUNSETIFF, but cheap insurance).
    // SAFETY: An all-zero `Ifreq` is valid — `[c_char; 16]` and
    // `c_short` both accept any bit pattern, and `_pad` is just bytes.
    let mut ifr: Ifreq = unsafe { MaybeUninit::zeroed().assume_init() };
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    // Copy the requested name into the fixed-size buffer. We rely on
    // the up-front length check in `open_impl` (<= 15 bytes), so the
    // copy can never overflow.
    for (dst, src) in ifr.ifr_name.iter_mut().zip(requested_name.bytes()) {
        // c_char is `i8` on most platforms — clippy::cast_possible_wrap
        // is meaningless here (we're just reinterpreting bytes).
        #[allow(clippy::cast_possible_wrap)]
        let signed = src as libc::c_char;
        *dst = signed;
    }
    // Trailing NUL guaranteed by the zero-init above.

    // SAFETY: ioctl(2) with TUNSETIFF expects a pointer to an
    // `ifreq`. We pass exactly that. The fd is the one we just
    // opened. Return value: 0 on success, -1 on error.
    //
    // `TUNSETIFF as _` coerces the request to ioctl's per-target request
    // type: `c_ulong` on glibc, but `c_int` on musl (where passing a
    // `c_ulong` is an i32/u64 mismatch — E0308). The constant 0x400454ca
    // fits in i32, so the conversion is lossless.
    let rc = unsafe { libc::ioctl(fd, TUNSETIFF as _, &raw mut ifr) };
    if rc < 0 {
        let err = io::Error::last_os_error();
        return Err(match err.raw_os_error() {
            Some(libc::EPERM) => TunError::PermissionDenied(format!(
                "ioctl(TUNSETIFF) failed: {err} (need CAP_NET_ADMIN \
                 or root)"
            )),
            Some(libc::EBUSY) => TunError::Io(io::Error::new(
                err.kind(),
                format!(
                    "ioctl(TUNSETIFF) returned EBUSY — an interface \
                     named {requested_name:?} already exists. Remove \
                     it via `ip link delete {requested_name}` or pick \
                     a different name."
                ),
            )),
            _ => TunError::Io(err),
        });
    }

    // Read back the final name. The kernel writes a NUL-terminated
    // C string of up to 16 bytes; find the first NUL to size the
    // Rust string.
    let nul_pos = ifr
        .ifr_name
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(IFNAMSIZ);
    let name_bytes: Vec<u8> = ifr.ifr_name[..nul_pos]
        .iter()
        .map(|&b| {
            // Reinterpret signed c_char as the unsigned byte the
            // kernel actually stored.
            #[allow(clippy::cast_sign_loss)]
            let unsigned = b as u8;
            unsigned
        })
        .collect();
    String::from_utf8(name_bytes).map_err(|e| {
        TunError::Io(io::Error::other(format!(
            "kernel returned non-UTF8 interface name: {e}"
        )))
    })
}

/// Run `ip -6 addr add <ula>/64 dev <iface>`.
///
/// Returns `Err` if the binary is missing, exits non-zero, or stderr
/// contains anything other than the "File exists" line that signals
/// idempotent re-runs.
fn assign_ula(iface: &str, ula: Ipv6Addr) -> Result<(), String> {
    let arg = format!("{ula}/64");
    let out = Command::new("ip")
        .args(["-6", "addr", "add", &arg, "dev", iface])
        .output()
        .map_err(|e| format!("spawn `ip`: {e} (install iproute2)"))?;
    if out.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    // EEXIST is fine — the test harness re-runs against a fresh VM
    // most of the time, but interactive runs frequently restart the
    // process without tearing the interface down.
    if stderr.contains("File exists") || stderr.contains("RTNETLINK answers: File exists") {
        return Ok(());
    }
    Err(format!(
        "ip -6 addr add {arg} dev {iface} exited {}: {}",
        out.status, stderr,
    ))
}

/// Run `ip link set dev <iface> mtu <N> up`.
fn bring_up(iface: &str, mtu: u16) -> Result<(), String> {
    let mtu_str = mtu.to_string();
    let out = Command::new("ip")
        .args(["link", "set", "dev", iface, "mtu", &mtu_str, "up"])
        .output()
        .map_err(|e| format!("spawn `ip`: {e} (install iproute2)"))?;
    if out.status.success() {
        return Ok(());
    }
    Err(format!(
        "ip link set dev {iface} mtu {mtu_str} up exited {}: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr),
    ))
}

/// Linux-side `/dev/net/tun` device.
///
/// The fd is wrapped in `Arc<AsyncFd>` so concurrent
/// readers/writers (one task draining inbound packets, another
/// pushing outbound) can share ownership without holding any
/// readiness guard across awaits.
#[derive(Debug)]
pub struct LinuxTunDevice {
    /// Interface name as assigned by the kernel.
    name: String,
    /// Tokio-wrapped fd. Holding `Arc` means concurrent
    /// readers/writers don't fight over a `&mut self`.
    fd: Arc<AsyncFd<OwnedFd>>,
    /// MTU as configured via `ip link set`. Tracked for debugging
    /// and for the eventual writev-with-MTU-check path.
    ///
    /// `#[allow(dead_code)]` — read by `Debug`-derived format only
    /// today; future paths may enforce the cap.
    #[allow(dead_code)]
    mtu: u16,
}

impl Drop for LinuxTunDevice {
    fn drop(&mut self) {
        // `OwnedFd::drop` closes the fd. The kernel auto-removes the
        // TUN interface when the last fd referencing it goes away
        // (provided `IFF_PERSIST` wasn't set — we don't set it).
        tracing::debug!(
            iface = %self.name,
            "tun/linux: dropping fd, kernel will tear down interface",
        );
    }
}

#[async_trait]
impl TunDevice for LinuxTunDevice {
    fn name(&self) -> &str {
        &self.name
    }

    async fn read_packet(&self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.fd.readable().await?;
            let raw_fd = self.fd.as_raw_fd();
            // `try_io` automatically clears readiness on WouldBlock,
            // so we can spin the outer loop until a real result.
            match guard.try_io(|_| {
                // SAFETY: read(2) takes (fd, *mut u8, size_t) and
                // returns ssize_t. The buffer is borrowed for the
                // duration of the syscall (which is non-blocking),
                // and we pass its real length.
                let rc = unsafe {
                    libc::read(raw_fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len())
                };
                if rc < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    // rc is ssize_t (signed); for read(2) the only
                    // non-negative value is bytes-read, fits in usize
                    // on every supported target.
                    #[allow(clippy::cast_sign_loss)]
                    Ok(rc as usize)
                }
            }) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }

    async fn write_packet(&self, buf: &[u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.fd.writable().await?;
            let raw_fd = self.fd.as_raw_fd();
            match guard.try_io(|_| {
                // SAFETY: write(2) takes (fd, *const u8, size_t). The
                // buffer is borrowed for the duration of the
                // syscall; the fd is non-blocking so this either
                // completes or returns EAGAIN immediately.
                let rc =
                    unsafe { libc::write(raw_fd, buf.as_ptr().cast::<libc::c_void>(), buf.len()) };
                if rc < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    #[allow(clippy::cast_sign_loss)]
                    Ok(rc as usize)
                }
            }) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn open_rejects_oversized_name() {
        let ula: Ipv6Addr = "fd5a:1f00:0001::1".parse().unwrap();
        let opts = TunOptions {
            // 16 bytes — exceeds IFNAMSIZ-1 (15).
            name: "wg-tabbify-too-".repeat(2),
            ula,
            mtu: 1420,
        };
        let err = open_impl(opts).await.unwrap_err();
        assert!(
            matches!(err, TunError::InvalidName(_)),
            "expected InvalidName, got {err:?}"
        );
    }

    #[tokio::test]
    async fn open_rejects_nul_in_name() {
        let ula: Ipv6Addr = "fd5a:1f00:0001::1".parse().unwrap();
        let opts = TunOptions {
            name: "wg\0bad".into(),
            ula,
            mtu: 1420,
        };
        let err = open_impl(opts).await.unwrap_err();
        assert!(
            matches!(err, TunError::InvalidName(_)),
            "expected InvalidName, got {err:?}"
        );
    }

    /// Unprivileged `open_impl` should fail cleanly with either
    /// `PermissionDenied` (open returned EPERM/EACCES) or `Io` (the
    /// kernel allowed the open but TUNSETIFF rejected it, or `ip` is
    /// missing in a slim container). We don't assert on the exact
    /// variant because both are valid depending on capabilities.
    ///
    /// The privileged path is exercised by the `#[ignore]` test in
    /// `tests/wireguard_tun.rs`.
    #[tokio::test]
    async fn open_without_caps_fails_cleanly() {
        let ula: Ipv6Addr = "fd5a:1f00:0001::1".parse().unwrap();
        let opts = TunOptions {
            name: "tabbify-tst0".into(),
            ula,
            mtu: 1420,
        };
        match open_impl(opts).await {
            Ok(_) => {
                // Surprise — test is running as root. That's fine,
                // but we don't want to leak the interface across the
                // test suite, and the device drops out of scope on
                // return.
                eprintln!(
                    "open_impl unexpectedly succeeded — test is \
                     running as root or with CAP_NET_ADMIN"
                );
            }
            Err(TunError::PermissionDenied(_) | TunError::Io(_)) => {
                // expected unprivileged outcome
            }
            Err(other) => {
                panic!("unexpected error variant: {other:?}");
            }
        }
    }
}
