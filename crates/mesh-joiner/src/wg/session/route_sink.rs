//! Sink trait that lets the [`super::SessionTable`] mirror its set of
//! peer + app `/128`s into the kernel routing table without coupling the
//! data plane to a concrete platform implementation.

use std::net::Ipv6Addr;

/// Sink that mirrors a peer's allowed `/128`s into the kernel routing
/// table (spec §5.5 — per-peer allowed-ips, TX direction).
///
/// The [`super::SessionTable`] holds an optional implementor and calls it
/// on every session insert / removal so the set of `/128`s routed at the
/// host TUN device tracks exactly the set of peers we currently have a
/// session with — never the blanket `/48`. The real implementor
/// (`crate::platform::TunRouteSink`) shells out to `ip` / `route`; unit
/// tests use a recording fake (or `None` to skip routing entirely).
///
/// Object-safe so the table can store it behind `Arc<dyn RouteSink>`
/// without leaking a concrete platform type into the data plane.
pub trait RouteSink: Send + Sync {
    /// Install a host route for `ula/128` via the overlay TUN device.
    /// Called when a session for `ula` is first inserted. Idempotent on
    /// the implementor's side (re-adding an existing route is a no-op).
    fn add_allowed(&self, ula: Ipv6Addr);
    /// Remove the host route for `ula/128`. Called when the session is
    /// removed. Idempotent (removing an absent route is a no-op).
    fn remove_allowed(&self, ula: Ipv6Addr);
    /// Install a host route for an APP-ULA `app_ula/128` via the overlay
    /// TUN device (per-app-ULA routing — consumer side). Called when a
    /// remote peer advertises a NEW hosted app-ULA, so the OS hands
    /// app-bound packets to our TUN read side; the [`super::SessionTable`]'s
    /// `app_routes` index then steers them to the hosting peer's session.
    ///
    /// Mechanically identical to [`Self::add_allowed`] (both install a
    /// `/128` host route to the TUN); kept as a distinct method so a fake
    /// sink in tests can assert app-route installs separately from
    /// peer-route installs, and so the data path stays self-documenting.
    /// Default-implemented as a no-op so existing sinks need no change.
    fn add_app_route(&self, app_ula: Ipv6Addr) {
        let _ = app_ula;
    }
    /// Remove the host route for an app-ULA `app_ula/128`. Called when the
    /// hosting peer drops the app-ULA or leaves. Idempotent. Default
    /// no-op (see [`Self::add_app_route`]).
    fn remove_app_route(&self, app_ula: Ipv6Addr) {
        let _ = app_ula;
    }
}
