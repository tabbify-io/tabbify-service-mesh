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

/// Source-scoped policy-routing parameters for ONE joiner instance
/// (Linux).
///
/// Derived deterministically from the joiner's own ULA so a restarted
/// joiner re-derives the SAME table and `replace`s the same routes
/// instead of leaking a new table per restart.
///
/// Why this exists: when a supervisor and its per-app runners share one
/// network namespace, each joiner installs the same peer `/128`s into
/// `main`; the kernel keeps only the first, so the losers' return
/// traffic egresses through the wrong TUN and the remote peer drops it
/// against the per-session source allowed-set (spec §5.5). A
/// source-scoped table + one `from <own_ula>` rule pins each joiner's
/// egress to its OWN TUN — the lightweight form of "≤1 joiner per
/// netns".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceScope {
    /// The joiner's own overlay address — the `from` selector of the
    /// policy rule (a runner's own ULA IS its app-ULA).
    pub own_ula: Ipv6Addr,
    /// Private routing-table id in `[256, u32::MAX − 256)`. Never
    /// collides with the reserved kernel tables (0 unspec / 253 default /
    /// 254 main / 255 local) and stays clear of small admin-assigned ids.
    pub table: u32,
    /// Policy-rule preference. MUST sort before the `main`-table rule at
    /// pref 32766 or the scoped table is never consulted; kept in
    /// `[100, 32100)`. Duplicate prefs across co-tenant joiners are legal
    /// (their `from` selectors differ).
    pub pref: u32,
}

impl SourceScope {
    /// Derive the scope for a joiner whose own overlay address is
    /// `own_ula`. Pure + deterministic: same ULA → same table forever.
    #[must_use]
    pub fn for_ula(own_ula: Ipv6Addr) -> Self {
        let h = fnv1a64(&own_ula.octets());
        // `% (u32::MAX − 512)` keeps `256 + …` a valid u32; starting at
        // 256 skips the reserved tables and the low ids admins hand out.
        #[allow(clippy::cast_possible_truncation)]
        let table = 256 + (h % u64::from(u32::MAX - 512)) as u32;
        #[allow(clippy::cast_possible_truncation)]
        let pref = 100 + (h % 32_000) as u32;
        Self {
            own_ula,
            table,
            pref,
        }
    }
}

/// FNV-1a, 64-bit. Tiny, dependency-free, and — unlike std's
/// `DefaultHasher` — STABLE across Rust releases, so the table id
/// derived from a ULA never silently changes under a toolchain bump
/// (which would strand routes in an orphaned table after a restart).
fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

/// Stable, ULA-derived TUN device name for host-integrated joiners
/// (Linux): `tun` + 10 hex digits, 13 bytes — under the kernel's
/// 15-byte IFNAMSIZ limit.
///
/// The kernel's auto-assigned `tun%d` recycles indices, so host state
/// keyed on the iface NAME — the firewall trust rule (`-i <iface>`),
/// the scoped routes' `dev <iface>` — would mis-target or orphan stale
/// entries across SIGKILL respawns (a respawned joiner can land on a
/// different index). Deriving the name from the joiner's own ULA makes
/// the iface key exactly as stable as the ULA-derived table id: a
/// respawn re-adopts its own leaked rules instead of orphaning them.
/// The `tun` prefix is kept so distro-level `-i tun+` allowances
/// (e.g. the NixOS module's belt-and-braces rule) still match.
#[must_use]
pub fn stable_tun_name(own_ula: Ipv6Addr) -> String {
    let h = fnv1a64(&own_ula.octets());
    format!("tun{:010x}", h & 0xff_ffff_ffff)
}

/// Install the single source-scoped policy rule
/// `from <own_ula>/128 lookup <table> pref <pref>` (Linux).
///
/// `ip -6 rule add` is NOT idempotent — identical rules stack silently —
/// so an exact-match `del` (tolerant of "not found") runs first, making
/// the pair safe to re-run on every (re)start.
///
/// Non-Linux: warns and succeeds — there is no policy routing to scope;
/// the sink falls back to `main`-table routes there.
///
/// # Errors
///
/// Returns [`JoinerError::TunSetup`] when the rule cannot be installed
/// (missing privileges, no `ip` binary). A host that OPTED INTO scoped
/// routing but cannot install the rule would silently egress via the
/// wrong TUN — fail loudly instead.
pub async fn install_source_rule(scope: &SourceScope) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        del_source_rule_tolerant(scope).await;
        let from = format!("{}/128", scope.own_ula);
        let table = scope.table.to_string();
        let pref = scope.pref.to_string();
        run_command(
            "ip",
            &[
                "-6", "rule", "add", "from", &from, "lookup", &table, "pref", &pref,
            ],
        )
        .await
    }
    #[cfg(not(target_os = "linux"))]
    {
        tracing::warn!(
            own_ula = %scope.own_ula,
            "source-scoped routes are Linux-only; falling back to main-table routes"
        );
        Ok(())
    }
}

/// Remove the source-scoped policy rule and flush the private table.
///
/// Both are best-effort and idempotent (absent rule / empty table are
/// fine) — called from `Joiner::leave`, where failures must not block
/// the rest of the teardown. Unlike the peer `/128`s (which die with the
/// TUN device), the rule and the table are NOT bound to the iface and
/// would leak without this.
pub async fn remove_source_rule(scope: &SourceScope) {
    #[cfg(target_os = "linux")]
    {
        del_source_rule_tolerant(scope).await;
        let table = scope.table.to_string();
        if let Err(e) = run_command("ip", &["-6", "route", "flush", "table", &table])
            .await
            .or_else(tolerate_missing_route)
        {
            tracing::warn!(error = %e, table = %table, "route: flush scoped table failed");
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = scope;
    }
}

/// Re-assert the source-scoped policy rule if it has gone missing.
///
/// Host firewall/network reloads and networkd/NetworkManager reconciles
/// can flush FOREIGN policy rules — the same exposure the firewall trust
/// rule has, hence the same periodic healing. Presence is checked FIRST
/// (`ip -6 rule show` + textual match), so the steady-state tick is
/// read-only — no transient del/add window in which a return packet
/// could miss the scoped table.
#[cfg_attr(not(target_os = "linux"), allow(clippy::unused_async))]
pub async fn reassert_source_rule(scope: &SourceScope) {
    #[cfg(target_os = "linux")]
    {
        if source_rule_present(scope).await {
            return;
        }
        tracing::warn!(
            own_ula = %scope.own_ula,
            table = scope.table,
            "route: source-scoped rule went missing (external flush?) — reinstalling"
        );
        if let Err(e) = install_source_rule(scope).await {
            tracing::warn!(error = %e, "route: source-scoped rule reinstall failed");
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = scope;
    }
}

/// `true` when the scope's policy rule is currently installed.
/// Implemented by listing `ip -6 rule show` and matching the rule
/// textually — iproute2's selector-filtered listing is not portable
/// across the versions in the fleet.
#[cfg(target_os = "linux")]
async fn source_rule_present(scope: &SourceScope) -> bool {
    let out = tokio::process::Command::new("ip")
        .args(["-6", "rule", "show"])
        .output()
        .await;
    match out {
        Ok(o) if o.status.success() => {
            rule_listing_contains(&String::from_utf8_lossy(&o.stdout), scope)
        }
        // Listing failed (no `ip`, no privileges): claim presence so the
        // caller does NOT try to reinstall — an install would fail the
        // same way and only add log noise.
        _ => true,
    }
}

/// Pure matcher for one `ip -6 rule show` listing line. iproute2 prints
/// host rules WITHOUT the `/128` suffix (`5786: from fd5a:… lookup
/// 5786`), and Rust's `Ipv6Addr` Display is RFC 5952 like iproute2's,
/// so a plain substring match on `from <ula> lookup <table>` is exact.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn rule_listing_contains(listing: &str, scope: &SourceScope) -> bool {
    let needle = format!("from {} lookup {}", scope.own_ula, scope.table);
    listing.lines().any(|l| {
        l.split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .contains(&needle)
    })
}

/// Exact-match delete of the scope's policy rule, tolerating "it was
/// never there". Shared by install (de-dup before add) and removal.
#[cfg(target_os = "linux")]
async fn del_source_rule_tolerant(scope: &SourceScope) {
    let from = format!("{}/128", scope.own_ula);
    let table = scope.table.to_string();
    let pref = scope.pref.to_string();
    if let Err(e) = run_command(
        "ip",
        &[
            "-6", "rule", "del", "from", &from, "lookup", &table, "pref", &pref,
        ],
    )
    .await
    .or_else(tolerate_missing_route)
    {
        tracing::debug!(error = %e, %from, "route: scoped-rule del (non-fatal)");
    }
}

/// Treat the kernel's "that route/rule does not exist" answers as
/// success — the absent state IS the desired state for a delete.
/// (Only reachable from the Linux-gated paths on a lib build; tests
/// exercise it on every platform.)
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn tolerate_missing_route(e: JoinerError) -> Result<()> {
    if let JoinerError::TunSetup(ref msg) = e {
        let lower = msg.to_lowercase();
        if lower.contains("no such process")
            || lower.contains("no such file")
            || lower.contains("not found")
            || lower.contains("not in table")
            // `ip -6 route flush table T` on a never-created table:
            // "Error: ipv6: FIB table does not exist."
            || lower.contains("does not exist")
        {
            return Ok(());
        }
    }
    Err(e)
}

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

/// Install a per-peer `/128` host route via `iface` into the private
/// routing table `table` (source-scoped mode, Linux).
///
/// Uses `replace` rather than `add`: idempotent by design, and it
/// silently repairs a stale entry left by a previous instance of the
/// same joiner (the table id is derived from the ULA, so a restart
/// targets the same table).
///
/// Non-Linux: falls back to the plain main-table [`add_peer_route`]
/// (macOS `route(8)` has no policy-routing tables).
///
/// # Errors
///
/// Returns [`JoinerError::TunSetup`] on any non-idempotent failure.
pub async fn add_peer_route_in_table(iface: &str, peer_ula: Ipv6Addr, table: u32) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        run_command(
            "ip",
            &[
                "-6",
                "route",
                "replace",
                &format!("{peer_ula}/128"),
                "dev",
                iface,
                "table",
                &table.to_string(),
            ],
        )
        .await
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = table;
        add_peer_route(iface, peer_ula).await
    }
}

/// Remove the per-peer `/128` host route from the private routing table
/// `table`.
///
/// Idempotent (absent route is success). Non-Linux falls back to the
/// plain [`del_peer_route`].
///
/// # Errors
///
/// Returns [`JoinerError::TunSetup`] on any other failure.
pub async fn del_peer_route_in_table(iface: &str, peer_ula: Ipv6Addr, table: u32) -> Result<()> {
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
                "table",
                &table.to_string(),
            ],
        )
        .await
        .or_else(tolerate_missing_route)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = table;
        del_peer_route(iface, peer_ula).await
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
///
/// In source-scoped mode (`scope: Some`) every `/128` targets the
/// scope's private table instead of `main` — see [`SourceScope`].
#[derive(Debug, Clone)]
pub struct TunRouteSink {
    iface: Arc<str>,
    /// `Some` = source-scoped mode (Linux): peer `/128`s land in the
    /// scope's private table. `None` = plain `main`-table routes.
    scope: Option<SourceScope>,
}

impl TunRouteSink {
    /// Build a plain (main-table) sink for the given overlay TUN
    /// interface name.
    #[must_use]
    pub fn new(iface: impl Into<String>) -> Self {
        Self {
            iface: Arc::from(iface.into()),
            scope: None,
        }
    }

    /// Build a source-scoped sink: peer `/128`s go into `scope.table`
    /// instead of `main`. The caller is responsible for installing the
    /// matching policy rule via [`install_source_rule`] (the joiner does
    /// this once at bring-up, before the first session is seeded).
    #[must_use]
    pub fn source_scoped(iface: impl Into<String>, scope: SourceScope) -> Self {
        Self {
            iface: Arc::from(iface.into()),
            scope: Some(scope),
        }
    }
}

// NOTE: `add_app_route`/`remove_app_route` deliberately stay on the
// trait's no-op default — the fly model makes a runner's own peer ULA
// *be* its app-ULA, so `add_allowed` already routes everything that is
// reachable today. When a consumer-side app-route install is added, it
// MUST branch on `self.scope` exactly like `add_allowed` (scoped table,
// not `main`), or scoped joiners get app routes in the wrong table.
impl RouteSink for TunRouteSink {
    fn add_allowed(&self, ula: Ipv6Addr) {
        let iface = self.iface.clone();
        let scope = self.scope;
        tokio::spawn(async move {
            let res = match scope {
                Some(s) => add_peer_route_in_table(&iface, ula, s.table).await,
                None => add_peer_route(&iface, ula).await,
            };
            if let Err(e) = res {
                tracing::warn!(error = %e, %ula, iface = %iface, "route: add /128 failed");
            } else {
                tracing::debug!(%ula, iface = %iface, table = ?scope.map(|s| s.table), "route: installed peer /128");
            }
        });
    }

    fn remove_allowed(&self, ula: Ipv6Addr) {
        let iface = self.iface.clone();
        let scope = self.scope;
        tokio::spawn(async move {
            let res = match scope {
                Some(s) => del_peer_route_in_table(&iface, ula, s.table).await,
                None => del_peer_route(&iface, ula).await,
            };
            if let Err(e) = res {
                tracing::warn!(error = %e, %ula, iface = %iface, "route: del /128 failed");
            } else {
                tracing::debug!(%ula, iface = %iface, table = ?scope.map(|s| s.table), "route: removed peer /128");
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
        let scope = SourceScope::for_ula("fd5a:1f02:5786:b2d4:bd64::1".parse().unwrap());
        let _ = TunRouteSink::source_scoped("tun1", scope);
    }

    /// The derived scope is deterministic: the SAME ULA must yield the
    /// SAME table across restarts (and toolchain bumps — FNV-1a is
    /// stable by definition), or a restarted joiner would strand its
    /// routes in an orphaned table. The hardcoded expectation pins the
    /// algorithm: changing it silently is a deploy-breaking event.
    #[test]
    fn source_scope_is_deterministic_and_pinned() {
        let ula: Ipv6Addr = "fd5a:1f02:5786:b2d4:bd64::1".parse().unwrap();
        let a = SourceScope::for_ula(ula);
        let b = SourceScope::for_ula(ula);
        assert_eq!(a, b, "same ULA must derive the same scope");
        // Snapshot of the live TP app-ULA's derivation (cross-checked
        // against an independent Python FNV-1a implementation). If this
        // assert fires, the derivation algorithm changed — which orphans
        // every deployed runner's existing table on its next restart.
        assert_eq!(a.table, 2_058_618_667);
        assert_eq!(a.pref, 4_762);
    }

    /// Table ids must never collide with the kernel-reserved tables
    /// (0 unspec / 253 default / 254 main / 255 local) and rule prefs
    /// must sort BEFORE the main-table rule at 32766 — for every
    /// possible ULA, by construction of the ranges.
    #[test]
    fn source_scope_avoids_reserved_tables_and_main_pref() {
        // A spread of structurally different ULAs, including edge-ish ones.
        let ulas = [
            "fd5a:1f00:0:4::1",
            "fd5a:1f00:0:33::1",
            "fd5a:1f02:5786:b2d4:bd64::1",
            "fd5a:1f02::1",
            "::1",
            "fd5a:1f02:ffff:ffff:ffff:ffff:ffff:ffff",
        ];
        for s in ulas {
            let scope = SourceScope::for_ula(s.parse().unwrap());
            assert!(
                scope.table >= 256,
                "table {} reserved-range for {s}",
                scope.table
            );
            assert!(scope.pref >= 100, "pref {} too low for {s}", scope.pref);
            assert!(
                scope.pref < 32_766,
                "pref {} would sort after the main-table rule for {s}",
                scope.pref
            );
        }
    }

    /// Different ULAs should (overwhelmingly) land in different tables —
    /// the whole point is that co-tenant joiners never share one.
    #[test]
    fn source_scope_differs_across_ulas() {
        let a = SourceScope::for_ula("fd5a:1f00:0:4::1".parse().unwrap());
        let b = SourceScope::for_ula("fd5a:1f02:5786:b2d4:bd64::1".parse().unwrap());
        assert_ne!(a.table, b.table);
    }

    /// The stable TUN name must be deterministic, under the kernel's
    /// 15-byte IFNAMSIZ limit, keep the `tun` prefix (so `-i tun+`
    /// distro allowances match), and differ across ULAs. Pinned like the
    /// table id: silently changing the derivation orphans the firewall
    /// rule keyed on the old name after the next respawn.
    #[test]
    fn stable_tun_name_is_pinned_prefixed_and_short() {
        let ula: Ipv6Addr = "fd5a:1f02:5786:b2d4:bd64::1".parse().unwrap();
        let name = stable_tun_name(ula);
        assert_eq!(name, stable_tun_name(ula), "must be deterministic");
        assert!(name.starts_with("tun"), "must keep the tun prefix: {name}");
        assert!(name.len() <= 15, "IFNAMSIZ allows 15 bytes max: {name}");
        assert_eq!(name, "tun8e09734b36", "derivation algorithm changed");
        let other = stable_tun_name("fd5a:1f00:0:4::1".parse().unwrap());
        assert_ne!(name, other, "different ULAs must get different ifaces");
    }

    /// The rule-listing matcher must recognize iproute2's real output
    /// shape — host rules print WITHOUT `/128` and with a tab after the
    /// pref — and must not false-positive on other rules.
    #[test]
    fn rule_listing_matcher_handles_iproute2_output() {
        let ula: Ipv6Addr = "fd5a:1f02:5786:b2d4:bd64::1".parse().unwrap();
        let scope = SourceScope::for_ula(ula);
        // Real-shape listing (pref:\tfrom … lookup …) including unrelated
        // rules and the manual TP rule with a DIFFERENT table.
        let listing = format!(
            "0:\tfrom all lookup local\n\
             5786:\tfrom fd5a:1f02:5786:b2d4:bd64::1 lookup 5786\n\
             {}:\tfrom {} lookup {}\n\
             32766:\tfrom all lookup main\n",
            scope.pref, scope.own_ula, scope.table
        );
        assert!(rule_listing_contains(&listing, &scope));
        // Same ULA but only the manual (different-table) rule present →
        // OUR rule is missing and must be reported as such.
        let manual_only = "0:\tfrom all lookup local\n\
             5786:\tfrom fd5a:1f02:5786:b2d4:bd64::1 lookup 5786\n\
             32766:\tfrom all lookup main\n";
        assert!(!rule_listing_contains(manual_only, &scope));
    }

    /// `tolerate_missing_route` swallows every "it wasn't there" kernel
    /// phrasing but re-surfaces real failures (e.g. permission errors).
    #[test]
    fn tolerate_missing_route_swallows_absent_only() {
        for msg in [
            "RTNETLINK answers: No such process",
            "RTNETLINK answers: No such file or directory",
            "Error: ipv6: FIB table does not exist.\nFlush terminated",
            "route: not in table",
        ] {
            assert!(
                tolerate_missing_route(JoinerError::TunSetup(msg.into())).is_ok(),
                "should tolerate: {msg}"
            );
        }
        assert!(
            tolerate_missing_route(JoinerError::TunSetup(
                "RTNETLINK answers: Operation not permitted".into()
            ))
            .is_err(),
            "permission errors must surface"
        );
    }
}
