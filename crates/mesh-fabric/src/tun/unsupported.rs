//! Fallback "no TUN here" backend for any OS that isn't macOS or
//! Linux.
//!
//! Today this covers Windows, FreeBSD, illumos, etc. The
//! [`super::open`] entry point is cfg-gated to return
//! [`super::TunError::UnsupportedPlatform`] directly on these
//! targets, so this module exists only to:
//!
//! * Keep the `pub mod` list in [`super`] uniform across all cfg
//!   arms.
//! * Provide a place for a future "supported on Windows via wintun"
//!   implementation without rewriting the module structure.
//!
//! There is intentionally no [`super::TunDevice`] implementation
//! here — the entry point never produces a concrete instance.

/// Placeholder type for symmetry with [`super::macos::MacOsTunDevice`]
/// and [`super::linux::LinuxTunDevice`].
///
/// Constructing one is impossible (the inner type is `Never`-shaped),
/// matching the runtime guarantee that [`super::open`] always returns
/// [`super::TunError::UnsupportedPlatform`] on this platform.
#[derive(Debug)]
pub struct UnsupportedTunDevice {
    /// An uninhabited witness — there is no way to construct this
    /// struct, so any code that *does* observe one is unreachable.
    _never: std::convert::Infallible,
}
