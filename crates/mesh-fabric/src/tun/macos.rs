// SAFETY: the entire macOS utun backend talks to the kernel via
// `libc::{socket, ioctl, connect, getsockopt, fcntl, read, write,
// close}`. Every unsafe block in this file is annotated with a
// per-call SAFETY comment justifying the invariants. The cfg-gate
// above guarantees we only compile this on macOS, so we don't smuggle
// unsafe code into the Linux host build.
#![allow(unsafe_code)]

//! macOS `utun` backend for the cross-platform [`super::TunDevice`]
//! abstraction.
//!
//! # Background
//!
//! macOS exposes virtual TUN devices via the `PF_SYSTEM` socket
//! family and the `com.apple.net.utun_control` kernel control. The
//! per-device sequence is:
//!
//! 1. `socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)`
//! 2. `ioctl(fd, CTLIOCGINFO, &ctl_info)` — translate the control
//!    name `com.apple.net.utun_control` into an opaque control id.
//! 3. `connect(fd, &sockaddr_ctl)` with the chosen `sc_unit`
//!    (1-indexed `utun` interface number; 0 lets the kernel pick).
//! 4. `getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, ...)` —
//!    discover the actual name (e.g., `utun7`).
//! 5. `SIOCAIFADDR_IN6` (or shelling out to `ifconfig`) to bind the
//!    ULA + prefix length.
//!
//! Reads and writes carry a 4-byte address-family header per frame
//! (`AF_INET6` = big-endian `0x0000_001E` for v6). The `read_packet`
//! implementation strips it; `write_packet` prepends it.
//!
//! # Address assignment is out of scope here
//!
//! [`open_impl`] only performs the socket / connect / name-discovery
//! dance. Binding the ULA prefix and bringing the interface up is the
//! responsibility of `crates/mesh-joiner/src/platform.rs::assign_ula`
//! (which shells out to `ifconfig`). The Linux backend pre-runs `ip
//! link set up` inside `open_impl` because the same `ip` binary
//! handles both address assignment and link-state changes; on macOS
//! `ifconfig` already understands both, so keeping `open_impl`
//! pure-syscall keeps the boundary clean.
//!
//! # Why opening a utun requires sudo
//!
//! macOS gates `PF_SYSTEM` socket creation behind the
//! `com.apple.private.networkextension` entitlement (granted only to
//! signed network-extension binaries) OR root privileges. Tests that
//! exercise the privileged path are marked `#[ignore]` and must be
//! run with `sudo -E cargo test --features wireguard -- --ignored
//! wireguard_tun`.

use async_trait::async_trait;
use std::ffi::{CStr, c_void};
use std::io;
use std::mem::{MaybeUninit, size_of};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::Arc;
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;

use super::{TunDevice, TunError, TunOptions};

// --- Darwin syscall constants, mirroring the C headers cited in
// each comment. Encoded manually to avoid pulling in nix/etc.

/// `PF_SYSTEM` from `<sys/socket.h>`.
const PF_SYSTEM: libc::c_int = 32;
/// `SYSPROTO_CONTROL` from `<sys/sys_domain.h>`.
const SYSPROTO_CONTROL: libc::c_int = 2;
/// `AF_SYS_CONTROL` from `<sys/sys_domain.h>` — value for
/// [`SockaddrCtl::ss_sysaddr`].
const AF_SYS_CONTROL: u16 = 2;
/// `UTUN_OPT_IFNAME` from `<net/if_utun.h>` — `getsockopt` opt that
/// returns the assigned interface name.
const UTUN_OPT_IFNAME: libc::c_int = 2;
/// `CTLIOCGINFO` from `<sys/kern_control.h>` — expansion of
/// `_IOWR('N', 3, struct ctl_info)`. Stable across all utun-shipping
/// macOS releases (10.6+).
const CTLIOCGINFO: libc::c_ulong = 0xC064_4E03;
/// `MAX_KCTL_NAME` from `<sys/kern_control.h>`.
const MAX_KCTL_NAME: usize = 96;
/// `IFNAMSIZ` from `<net/if.h>`.
const IFNAMSIZ: usize = 16;
/// Kernel-control name we connect to. Anything else gives `ENOENT`.
const UTUN_CONTROL_NAME: &[u8] = b"com.apple.net.utun_control\0";
/// `AF_INET6` (= 30) in network byte order — each utun frame is
/// prefixed with this 4-byte header. The substrate fabric is
/// IPv6-only so we hard-code v6.
const AF_INET6_PREFIX: [u8; 4] = [0, 0, 0, 30];
/// Length of the macOS per-frame address-family prefix.
const AF_PREFIX_LEN: usize = 4;

/// Mirror of `struct ctl_info` from `<sys/kern_control.h>`. The
/// kernel reads `ctl_name` and writes back `ctl_id`.
#[repr(C)]
struct CtlInfo {
    ctl_id: u32,
    ctl_name: [libc::c_char; MAX_KCTL_NAME],
}

/// Mirror of `struct sockaddr_ctl` from `<sys/kern_control.h>`. The
/// `connect(2)` address that binds the socket to a specific
/// `(ctl_id, sc_unit)` pair. `sc_unit = 0` asks the kernel for the
/// next free utun; `sc_unit = N` (N >= 1) requests `utun{N-1}`
/// specifically.
#[repr(C)]
struct SockaddrCtl {
    sc_len: libc::c_uchar,
    sc_family: libc::c_uchar,
    ss_sysaddr: u16,
    sc_id: u32,
    sc_unit: u32,
    sc_reserved: [u32; 5],
}

// Compile-time guards against accidental field bloat that would
// silently de-sync our mirrors from the kernel layout.
const _ASSERT_CTL_INFO_SIZE: () = assert!(size_of::<CtlInfo>() == 100);
const _ASSERT_SOCKADDR_CTL_SIZE: () = assert!(size_of::<SockaddrCtl>() == 32);

/// Open a macOS `utun` device.
///
/// # Errors
///
/// * [`super::TunError::InvalidName`] if a non-empty `opts.name` does
///   not start with `utun` or does not have a valid integer suffix.
/// * [`super::TunError::PermissionDenied`] if `socket(PF_SYSTEM, ...)`
///   returns `EPERM` (typically: the process is not root and lacks the
///   `com.apple.private.networkextension` entitlement).
/// * [`super::TunError::DeviceBusy`] if a specific `utun<N>` was
///   requested but is already in use (`connect()` returned `EBUSY`).
/// * [`super::TunError::Io`] for any other syscall failure.
//
// `#[allow(clippy::unused_async)]` — the function body is pure syscall
// dance and contains no `.await` points (every I/O step is blocking),
// but `tun/mod.rs::open` calls us as `.await?` so the trait surface
// stays uniform with Linux (where `bring_up` could legitimately grow
// an async tokio Command in the future). Dropping `async` here would
// force a churn in `tun/mod.rs::open`.
#[allow(clippy::unused_async)]
pub async fn open_impl(opts: TunOptions) -> Result<MacOsTunDevice, TunError> {
    // ----- step 0: validate the name and compute the requested unit.
    let requested_unit = parse_requested_unit(&opts.name)?;

    // ----- step 1: open the kernel-control socket.
    let owned_fd = open_kctl_socket()?;
    let raw_fd = owned_fd.as_raw_fd();

    // ----- step 2: resolve the utun control name to a control id.
    let ctl_id = ctl_info_lookup(raw_fd)?;

    // ----- step 3: connect to the control with the chosen unit.
    connect_sockaddr_ctl(raw_fd, ctl_id, requested_unit, &opts.name)?;

    // ----- step 4: discover the actual interface name.
    let final_name = get_assigned_ifname(raw_fd)?;

    // ----- step 5: switch the fd to non-blocking for tokio integration.
    set_nonblocking(raw_fd)?;

    tracing::debug!(
        requested = %if opts.name.is_empty() { "<auto>" } else { &opts.name },
        assigned = %final_name,
        ula = %opts.ula,
        mtu = opts.mtu,
        "tun/macos: utun fd bound to interface",
    );

    // Wrap the fd in an AsyncFd for tokio integration. We registered
    // O_NONBLOCK above, so all I/O is non-blocking and ready
    // notifications come via kqueue.
    let async_fd = AsyncFd::with_interest(owned_fd, Interest::READABLE | Interest::WRITABLE)
        .map_err(TunError::Io)?;

    Ok(MacOsTunDevice {
        name: final_name,
        fd: Arc::new(async_fd),
        mtu: opts.mtu,
    })
}

/// Validate `opts.name` and return the `sc_unit` value to pass to
/// `connect()`.
///
/// * Empty name -> 0 (kernel auto-assigns).
/// * `"utun"` (no suffix) -> 0 (same as empty).
/// * `"utun<N>"` -> N + 1 (off-by-one quirk: `sc_unit = K` means
///   `utun{K-1}` because the kernel reserves `K = 0` for "auto").
///
/// Returns [`TunError::InvalidName`] if the prefix is wrong or the
/// suffix is not a valid `u32`.
fn parse_requested_unit(name: &str) -> Result<u32, TunError> {
    if name.is_empty() {
        return Ok(0);
    }
    let suffix = name.strip_prefix("utun").ok_or_else(|| {
        TunError::InvalidName(format!(
            "macOS utun names must start with `utun` (got {name:?}); \
             pass an empty string to let the kernel auto-assign"
        ))
    })?;
    if suffix.is_empty() {
        return Ok(0);
    }
    let unit_index: u32 = suffix.parse().map_err(|_| {
        TunError::InvalidName(format!(
            "macOS utun suffix must be a non-negative integer (got \
             {name:?})"
        ))
    })?;
    // sc_unit = 0 is "auto". To request utun<N> the kernel wants
    // sc_unit = N + 1. Guard against overflow (utun unit indices are
    // small in practice — single digits — but we cap explicitly).
    unit_index.checked_add(1).ok_or_else(|| {
        TunError::InvalidName(format!(
            "macOS utun suffix overflow (got {name:?}); pick a smaller \
             unit"
        ))
    })
}

/// `socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)`.
///
/// Returns an [`OwnedFd`] so the kernel resource is dropped
/// deterministically if any later step (`ioctl`, `connect`,
/// `getsockopt`) fails.
fn open_kctl_socket() -> Result<OwnedFd, TunError> {
    // SAFETY: socket(2) is a pure syscall taking three integers. It
    // returns -1 on error (then we read `errno`) or a valid file
    // descriptor we adopt into an `OwnedFd` so Drop closes it.
    let raw = unsafe { libc::socket(PF_SYSTEM, libc::SOCK_DGRAM, SYSPROTO_CONTROL) };
    if raw < 0 {
        let err = io::Error::last_os_error();
        return Err(match err.raw_os_error() {
            Some(libc::EPERM | libc::EACCES) => TunError::PermissionDenied(format!(
                "socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL) \
                 failed: {err} — utun open requires sudo on macOS \
                 (or the com.apple.private.networkextension \
                 entitlement, which we don't have)"
            )),
            _ => TunError::Io(err),
        });
    }
    // SAFETY: `raw` is a fresh fd from socket(2) that we've just
    // checked is non-negative. We have not transferred ownership
    // elsewhere yet, so this is the unique owner. `c_int` is `i32`
    // on every supported macOS target, matching `RawFd` exactly, so
    // the coercion is the identity.
    let raw_fd: RawFd = raw;
    Ok(unsafe { OwnedFd::from_raw_fd(raw_fd) })
}

/// `ioctl(fd, CTLIOCGINFO, &ctl_info)` — resolve
/// `com.apple.net.utun_control` to a kernel control id.
fn ctl_info_lookup(fd: RawFd) -> Result<u32, TunError> {
    // SAFETY: An all-zero `CtlInfo` is valid — `u32` and `[c_char; N]`
    // both accept any bit pattern, and we overwrite the relevant bytes
    // immediately below.
    let mut ci: CtlInfo = unsafe { MaybeUninit::zeroed().assume_init() };
    // Copy the C string into the fixed-size buffer. `UTUN_CONTROL_NAME`
    // is a compile-time-known 27-byte NUL-terminated byte slice that
    // fits well inside the 96-byte field.
    debug_assert!(UTUN_CONTROL_NAME.len() <= MAX_KCTL_NAME);
    for (dst, &src) in ci.ctl_name.iter_mut().zip(UTUN_CONTROL_NAME.iter()) {
        // c_char is `i8` on macOS; reinterpret the bytes without
        // changing their value.
        #[allow(clippy::cast_possible_wrap)]
        let signed = src as libc::c_char;
        *dst = signed;
    }

    // SAFETY: ioctl(2) with CTLIOCGINFO expects a pointer to a
    // `ctl_info`. We pass exactly that. The fd is the one we just
    // opened. Return value: 0 on success, -1 on error.
    let rc = unsafe { libc::ioctl(fd, CTLIOCGINFO, &raw mut ci) };
    if rc < 0 {
        let err = io::Error::last_os_error();
        return Err(TunError::Io(io::Error::other(format!(
            "ioctl(CTLIOCGINFO, com.apple.net.utun_control) failed: \
             {err} — kernel does not know about the utun control \
             (very old macOS?)",
        ))));
    }
    Ok(ci.ctl_id)
}

/// `connect(fd, &sockaddr_ctl)` — bind the socket to a specific
/// (`ctl_id`, `sc_unit`) tuple. After this call the socket
/// corresponds to a real `utun<N>` interface in the kernel.
fn connect_sockaddr_ctl(
    fd: RawFd,
    ctl_id: u32,
    sc_unit: u32,
    requested_name: &str,
) -> Result<(), TunError> {
    // `SockaddrCtl` is a compile-time-fixed 32-byte struct (asserted
    // above). Both 32 and `PF_SYSTEM` (= 32) fit in `u8` trivially.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    const SC_LEN: u8 = size_of::<SockaddrCtl>() as u8;
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    const SC_FAMILY: u8 = PF_SYSTEM as u8;

    let sc = SockaddrCtl {
        sc_len: SC_LEN,
        sc_family: SC_FAMILY,
        ss_sysaddr: AF_SYS_CONTROL,
        sc_id: ctl_id,
        sc_unit,
        sc_reserved: [0; 5],
    };

    // SAFETY: connect(2) expects (fd, *const sockaddr, socklen_t).
    // We pass a pointer to `sc` reinterpreted as `*const sockaddr`
    // and the matching length. The kernel reads exactly `sc_len`
    // bytes from the address.
    let rc = unsafe {
        libc::connect(
            fd,
            (&raw const sc).cast::<libc::sockaddr>(),
            libc::socklen_t::from(SC_LEN),
        )
    };
    if rc < 0 {
        let err = io::Error::last_os_error();
        return Err(match err.raw_os_error() {
            Some(libc::EBUSY) => TunError::DeviceBusy(format!(
                "connect(sockaddr_ctl, sc_unit={sc_unit}) returned \
                 EBUSY — interface {requested_name:?} is already in \
                 use; pick a different name or pass an empty string \
                 to let the kernel auto-assign"
            )),
            Some(libc::EPERM | libc::EACCES) => TunError::PermissionDenied(format!(
                "connect(sockaddr_ctl) failed: {err} — utun open \
                 requires sudo on macOS"
            )),
            _ => TunError::Io(err),
        });
    }
    Ok(())
}

/// `getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, ...)` — return
/// the interface name as assigned by the kernel.
fn get_assigned_ifname(fd: RawFd) -> Result<String, TunError> {
    let mut name_buf = [0_u8; IFNAMSIZ];
    // `IFNAMSIZ = 16` fits in `socklen_t` (= `u32`) trivially.
    #[allow(clippy::cast_possible_truncation)]
    let mut name_len = libc::socklen_t::from(IFNAMSIZ as u8);
    // SAFETY: getsockopt(2) expects (fd, level, optname, *mut void,
    // *mut socklen_t). We pass a buffer of IFNAMSIZ bytes and the
    // matching length cell. The kernel writes a NUL-terminated C
    // string up to `*optlen` and updates `*optlen` to the actual
    // length (including the NUL). Return value: 0 on success.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            SYSPROTO_CONTROL,
            UTUN_OPT_IFNAME,
            name_buf.as_mut_ptr().cast::<c_void>(),
            &raw mut name_len,
        )
    };
    if rc < 0 {
        let err = io::Error::last_os_error();
        return Err(TunError::Io(io::Error::other(format!(
            "getsockopt(SYSPROTO_CONTROL, UTUN_OPT_IFNAME) failed: \
             {err}",
        ))));
    }
    // The kernel writes a NUL-terminated string. Find the NUL to size
    // the Rust string; CStr does this safely.
    let cstr = CStr::from_bytes_until_nul(&name_buf).map_err(|_| {
        TunError::Io(io::Error::other(
            "kernel returned an unterminated interface name from \
             UTUN_OPT_IFNAME",
        ))
    })?;
    cstr.to_str()
        .map(str::to_owned)
        .map_err(|e| TunError::Io(io::Error::other(format!("non-UTF8 interface name: {e}"))))
}

/// `fcntl(fd, F_SETFL, O_NONBLOCK)` — required for the AsyncFd-based
/// I/O path.
fn set_nonblocking(fd: RawFd) -> Result<(), TunError> {
    // SAFETY: fcntl(F_GETFL) is a read-only query taking (fd, cmd) →
    // returns the current file-status flags or -1 on error.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(TunError::Io(io::Error::last_os_error()));
    }
    // SAFETY: fcntl(F_SETFL, new_flags) writes the file-status flags
    // for an existing fd. We OR in `O_NONBLOCK` while preserving any
    // flags the kernel set on socket() / connect().
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if rc < 0 {
        return Err(TunError::Io(io::Error::last_os_error()));
    }
    Ok(())
}

/// macOS-side `utun` device.
///
/// The fd is wrapped in `Arc<AsyncFd>` so concurrent readers/writers
/// (one task draining inbound packets, another pushing outbound) can
/// share ownership without holding any readiness guard across awaits.
#[derive(Debug)]
pub struct MacOsTunDevice {
    /// Interface name as assigned by the kernel (e.g., `utun7`).
    name: String,
    /// Tokio-wrapped fd. Holding `Arc` means concurrent
    /// readers/writers don't fight over a `&mut self`.
    fd: Arc<AsyncFd<OwnedFd>>,
    /// MTU as requested by the caller. The kernel doesn't track MTU
    /// inside `utun` itself — `ifconfig <iface> mtu N` (handled by
    /// `mesh-joiner::platform::assign_ula`) does. Tracked here for
    /// debugging and for a future writer-side bound check.
    ///
    /// `#[allow(dead_code)]` — read by the `Debug` derive only today.
    #[allow(dead_code)]
    mtu: u16,
}

impl Drop for MacOsTunDevice {
    fn drop(&mut self) {
        // `OwnedFd::drop` closes the fd. The kernel auto-removes the
        // utun interface when the last fd referencing it goes away.
        tracing::debug!(
            iface = %self.name,
            "tun/macos: dropping fd, kernel will tear down interface",
        );
    }
}

#[async_trait]
impl TunDevice for MacOsTunDevice {
    fn name(&self) -> &str {
        &self.name
    }

    async fn read_packet(&self, buf: &mut [u8]) -> io::Result<usize> {
        // The kernel writes <4-byte AF header><IP packet>. We read
        // into a local scratch buffer big enough for MTU + header,
        // then memmove the IP bytes into `buf` (so the caller sees a
        // raw IP packet, mirroring the IFF_NO_PI Linux behaviour).
        loop {
            let mut guard = self.fd.readable().await?;
            let raw_fd = self.fd.as_raw_fd();
            // Tokio's `try_io` swallows `WouldBlock` by clearing the
            // readiness and returning Err so we can re-arm.
            let res = guard.try_io(|_| {
                // Stack-allocated scratch sized for the largest
                // reasonable MTU we accept (Linux/macOS both cap at
                // ~9KB jumbo). Keeping it on the stack avoids per-read
                // allocations on the hot path.
                let mut scratch = [0_u8; 9216];
                let take = scratch.len().min(buf.len().saturating_add(AF_PREFIX_LEN));
                // SAFETY: read(2) takes (fd, *mut u8, size_t) and
                // returns ssize_t. The buffer is borrowed for the
                // duration of the syscall (which is non-blocking),
                // and we pass its real length.
                let rc = unsafe { libc::read(raw_fd, scratch.as_mut_ptr().cast::<c_void>(), take) };
                if rc < 0 {
                    return Err(io::Error::last_os_error());
                }
                // rc is ssize_t (signed); for read(2) the only
                // non-negative value is bytes-read, which fits in
                // usize on every supported target.
                #[allow(clippy::cast_sign_loss)]
                let n = rc as usize;
                if n < AF_PREFIX_LEN {
                    // The kernel always prepends the 4-byte header on
                    // utun; a shorter frame would be a kernel bug or
                    // a stray empty packet. Treat as a read error.
                    return Err(io::Error::other(format!(
                        "utun read returned {n} bytes, expected at \
                         least {AF_PREFIX_LEN} (AF header)"
                    )));
                }
                let payload_len = n - AF_PREFIX_LEN;
                if payload_len > buf.len() {
                    // Caller-provided buffer is too small. Surface
                    // the same kind that `read(2)` would for a short
                    // buffer on Linux — `InvalidInput` keeps the
                    // semantics distinct from "io error".
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!(
                            "buffer too small for utun frame: need \
                             {payload_len}, got {}",
                            buf.len()
                        ),
                    ));
                }
                buf[..payload_len].copy_from_slice(&scratch[AF_PREFIX_LEN..n]);
                Ok(payload_len)
            });
            if let Ok(result) = res {
                return result;
            }
            // Err means WouldBlock: try_io cleared readiness, so the
            // outer loop re-awaits the fd. Falling through to the next
            // iteration is the intended "retry" path.
        }
    }

    async fn write_packet(&self, buf: &[u8]) -> io::Result<usize> {
        // The kernel expects <4-byte AF header><IP packet>. We
        // assemble the frame in a stack-allocated scratch buffer and
        // hand it to write(2) in a single syscall — splitting via
        // writev would be marginally faster but pulls in an iovec
        // dance for no measurable benefit at typical MTUs.
        if buf.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "utun write_packet got empty buffer",
            ));
        }
        loop {
            let mut guard = self.fd.writable().await?;
            let raw_fd = self.fd.as_raw_fd();
            let res = guard.try_io(|_| {
                let mut scratch = [0_u8; 9216];
                let total = AF_PREFIX_LEN + buf.len();
                if total > scratch.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!(
                            "utun write payload too large: {} bytes \
                             exceeds jumbo MTU + header ({}); split \
                             upstream",
                            buf.len(),
                            scratch.len() - AF_PREFIX_LEN
                        ),
                    ));
                }
                scratch[..AF_PREFIX_LEN].copy_from_slice(&AF_INET6_PREFIX);
                scratch[AF_PREFIX_LEN..total].copy_from_slice(buf);
                // SAFETY: write(2) takes (fd, *const u8, size_t). The
                // buffer is borrowed for the duration of the syscall;
                // the fd is non-blocking so this either completes or
                // returns EAGAIN immediately.
                let rc = unsafe { libc::write(raw_fd, scratch.as_ptr().cast::<c_void>(), total) };
                if rc < 0 {
                    return Err(io::Error::last_os_error());
                }
                #[allow(clippy::cast_sign_loss)]
                let n = rc as usize;
                // The kernel either accepts the whole datagram or
                // none of it. Account for the prefix so the caller
                // sees "bytes of IP packet written".
                let payload_written = n.saturating_sub(AF_PREFIX_LEN);
                Ok(payload_written)
            });
            if let Ok(result) = res {
                return result;
            }
            // Err means WouldBlock: try_io cleared readiness, so the
            // outer loop re-awaits the fd. Falling through to the next
            // iteration is the intended "retry" path.
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    /// Test helper: returns `true` when the test process is running
    /// as root (effective uid 0). Used to skip the "should fail
    /// without sudo" assertion when the harness *is* running with
    /// sudo (e.g. `sudo -E cargo test -- --ignored`).
    fn running_as_root() -> bool {
        // SAFETY: geteuid(2) takes no arguments and cannot fail.
        unsafe { libc::geteuid() == 0 }
    }

    #[tokio::test]
    async fn open_impl_returns_invalid_name_for_non_utun_prefix() {
        let ula: Ipv6Addr = "fd5a:1f00:0001::1".parse().unwrap();
        let opts = TunOptions {
            name: "wg0".into(), // Linux-style name on a Mac
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
    async fn open_impl_rejects_non_numeric_utun_suffix() {
        let ula: Ipv6Addr = "fd5a:1f00:0001::1".parse().unwrap();
        let opts = TunOptions {
            name: "utunFOO".into(),
            ula,
            mtu: 1420,
        };
        let err = open_impl(opts).await.unwrap_err();
        assert!(
            matches!(err, TunError::InvalidName(_)),
            "expected InvalidName, got {err:?}"
        );
    }

    /// `parse_requested_unit` is the off-by-one quirk hot-spot. Test
    /// the table directly to avoid leaning on the syscall path.
    #[test]
    fn parse_requested_unit_table() {
        assert_eq!(parse_requested_unit("").unwrap(), 0, "empty -> auto");
        assert_eq!(
            parse_requested_unit("utun").unwrap(),
            0,
            "no suffix -> auto"
        );
        assert_eq!(
            parse_requested_unit("utun0").unwrap(),
            1,
            "utun0 -> sc_unit=1"
        );
        assert_eq!(
            parse_requested_unit("utun9").unwrap(),
            10,
            "utun9 -> sc_unit=10"
        );
        assert!(parse_requested_unit("wg0").is_err());
        assert!(parse_requested_unit("utun-1").is_err());
        assert!(parse_requested_unit("utunFOO").is_err());
        // u32::MAX would overflow on +1; confirm we catch it.
        let big = format!("utun{}", u32::MAX);
        assert!(parse_requested_unit(&big).is_err());
    }

    /// Empty name is the "let the kernel pick" sentinel and must not
    /// trip the `InvalidName` guard. We can't proceed to a successful
    /// open without root, so we accept any non-`InvalidName` outcome.
    #[tokio::test]
    async fn open_impl_accepts_empty_name() {
        let ula: Ipv6Addr = "fd5a:1f00:0001::1".parse().unwrap();
        let opts = TunOptions {
            name: String::new(),
            ula,
            mtu: 1420,
        };
        match open_impl(opts).await {
            Ok(_dev) => {
                // Running as root — fine; device drops on return.
                eprintln!("open_impl succeeded — running as root");
            }
            Err(TunError::InvalidName(msg)) => {
                panic!("empty name should not trip InvalidName guard, got: {msg}");
            }
            Err(_other) => {
                // PermissionDenied, Io, or DeviceBusy are all
                // plausible from the syscall path; we just guard the
                // name validation here.
            }
        }
    }

    /// When *not* running as root, `open_impl("utun99")` must return
    /// `PermissionDenied` (mapped from `EPERM` on `socket(PF_SYSTEM,
    /// ...)`). When running as root, this test self-skips so it
    /// still passes inside `sudo -E cargo test`.
    #[tokio::test]
    async fn open_impl_returns_permission_denied_when_not_root() {
        if running_as_root() {
            eprintln!(
                "skipping — running as root; the privileged path is \
                 covered by the #[ignore]-d integration test"
            );
            return;
        }
        let ula: Ipv6Addr = "fd5a:1f00:0001::1".parse().unwrap();
        let opts = TunOptions {
            name: "utun99".into(),
            ula,
            mtu: 1420,
        };
        let err = open_impl(opts).await.unwrap_err();
        assert!(
            matches!(err, TunError::PermissionDenied(_)),
            "expected PermissionDenied without sudo, got {err:?}"
        );
    }

    /// Real privileged smoke test — opens an auto-assigned utun,
    /// verifies the assigned name starts with `utun`, then drops.
    ///
    /// `#[ignore]` because it requires `sudo`. Run via:
    /// `sudo -E cargo test -p tabbify-mesh-fabric tun::macos -- \
    ///  --ignored --nocapture`
    #[tokio::test]
    #[ignore = "requires sudo on macOS — opens a real utun via PF_SYSTEM"]
    async fn open_impl_opens_real_utun_when_root() {
        assert!(
            running_as_root(),
            "this test must run with sudo — re-run via `sudo -E cargo \
             test -- --ignored`"
        );
        let ula: Ipv6Addr = "fd5a:1f00:0001::1".parse().unwrap();
        let opts = TunOptions {
            name: String::new(), // auto-assign
            ula,
            mtu: 1420,
        };
        let dev = open_impl(opts).await.expect("open utun");
        let name = dev.name().to_owned();
        eprintln!("opened utun, kernel assigned name = {name}");
        assert!(
            name.starts_with("utun"),
            "kernel-assigned name should start with `utun`, got {name:?}"
        );
        // MTU getter (via the Debug-serialised field) — sanity-check
        // the field round-trips. We don't have a `mtu()` accessor on
        // the trait yet; this is the closest equivalent until the
        // trait grows one.
        let dbg = format!("{dev:?}");
        assert!(
            dbg.contains("mtu: 1420"),
            "Debug output should mention configured mtu, got {dbg:?}"
        );
        // Drop tears down the interface.
        drop(dev);
    }
}
