//! Self-managed host-firewall trust for the overlay TUN (Linux) — the
//! tailscaled pattern.
//!
//! Decrypted overlay traffic arrives INBOUND on the joiner's TUN device
//! (a peer dialing an app listener on `[ula]:port` is a NEW connection
//! from the kernel's point of view). Distro default firewalls (e.g. the
//! NixOS `nixos-fw` chain) accept only loopback / ESTABLISHED / a
//! handful of ports, so they DROP that SYN before any listener sees it:
//! the tunnel works, the decapsulation works, and the app is still
//! unreachable. A platform that installs with one command on a clean
//! machine cannot depend on every distro's firewall being hand-tuned —
//! the binary keeps itself reachable, exactly like `tailscaled` manages
//! its own netfilter rules.
//!
//! Trust rationale: a packet only reaches the TUN after `WireGuard`
//! authenticated the sending peer, and the joiner enforces the per-peer
//! source allowed-set on RX (spec §5.5). Accepting everything arriving
//! on the joiner's OWN TUN device is the standard `WireGuard` firewall
//! posture — the rule is scoped `-i <iface>`, never a wildcard.
//!
//! Everything here is BEST-EFFORT by contract: a missing `ip6tables`
//! binary or missing privileges (containers, unprivileged dev runs)
//! logs a warning and never fails the join. The assert is re-run
//! periodically ([`trust_loop`]) because a firewall reload flushes the
//! rule; removal happens in `Joiner::leave`.

use std::time::Duration;
use tokio::process::Command;

/// Re-assert cadence for [`trust_loop`]. A firewall reload strands the
/// rule for at most this long; 60s is far below any human-noticeable
/// outage while keeping the shell-out load negligible.
const REASSERT_INTERVAL: Duration = Duration::from_secs(60);

/// The iptables matcher/target for trusting one TUN device, minus the
/// chain verb. Split out so tests can pin the exact rule shape.
fn rule_args(iface: &str) -> [String; 4] {
    [
        "-i".to_owned(),
        iface.to_owned(),
        "-j".to_owned(),
        "ACCEPT".to_owned(),
    ]
}

/// Outcome of one raw firewall-binary invocation. Unlike
/// [`super::run_command`], `-C` needs the EXIT CODE distinguished from a
/// spawn failure: exit 1 means "rule absent" (normal!), not an error.
enum Exec {
    /// Binary missing / not executable.
    SpawnFailed(String),
    /// Ran to completion with this success flag and captured stderr.
    Done { ok: bool, stderr: String },
}

async fn exec(bin: &str, args: &[String]) -> Exec {
    match Command::new(bin).args(args).output().await {
        Err(e) => Exec::SpawnFailed(e.to_string()),
        Ok(out) => Exec::Done {
            ok: out.status.success(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        },
    }
}

/// Ensure `INPUT -i <iface> -j ACCEPT` exists (check-then-insert, so
/// re-running never stacks duplicates).
///
/// Returns `true` when the IPv6 rule is in place — the overlay is
/// IPv6-only, so that is the rule that matters; the IPv4 twin is
/// asserted for symmetry but its outcome only logs at debug.
///
/// Never returns an error: best-effort by contract (see module docs).
pub async fn ensure_tun_trust(iface: &str) -> bool {
    let v6 = ensure_one("ip6tables", iface).await;
    let v4 = ensure_one("iptables", iface).await;
    tracing::debug!(iface, v6, v4, "firewall: tun trust asserted");
    v6
}

/// Check-then-insert for one iptables binary. `-C` exit 0 = present;
/// any other completion = try `-I INPUT 1`.
async fn ensure_one(bin: &str, iface: &str) -> bool {
    let rule = rule_args(iface);
    let mut check: Vec<String> = vec!["-C".into(), "INPUT".into()];
    check.extend(rule.iter().cloned());
    match exec(bin, &check).await {
        Exec::SpawnFailed(e) => {
            tracing::debug!(bin, error = %e, "firewall: binary unavailable");
            false
        }
        Exec::Done { ok: true, .. } => true,
        Exec::Done { ok: false, .. } => {
            // Absent (or unreadable) — insert at position 1 so the rule
            // precedes any distro REJECT chain.
            let mut insert: Vec<String> = vec!["-I".into(), "INPUT".into(), "1".into()];
            insert.extend(rule.iter().cloned());
            match exec(bin, &insert).await {
                Exec::Done { ok: true, .. } => true,
                Exec::Done { ok: false, stderr } => {
                    tracing::debug!(bin, iface, stderr = %stderr.trim(), "firewall: insert failed");
                    false
                }
                Exec::SpawnFailed(e) => {
                    tracing::debug!(bin, error = %e, "firewall: binary unavailable");
                    false
                }
            }
        }
    }
}

/// Remove the trust rule for `iface` (both families).
///
/// Idempotent and best-effort — called from `Joiner::leave`; an absent
/// rule or missing binary is fine.
pub async fn remove_tun_trust(iface: &str) {
    for bin in ["ip6tables", "iptables"] {
        let rule = rule_args(iface);
        let mut del: Vec<String> = vec!["-D".into(), "INPUT".into()];
        del.extend(rule.iter().cloned());
        match exec(bin, &del).await {
            Exec::Done { ok: true, .. } => {
                tracing::debug!(bin, iface, "firewall: tun trust removed");
            }
            Exec::Done { .. } | Exec::SpawnFailed(_) => {
                // Absent rule / missing binary — nothing to remove.
            }
        }
    }
}

/// Background re-assert loop: keeps the trust rule alive across host
/// firewall reloads (which flush custom INPUT rules).
///
/// Warns ONCE when the assert fails, then stays quiet until it succeeds
/// again — a container without ip6tables must not spam a warning every
/// minute.
pub async fn trust_loop(iface: String, mut shutdown: tokio::sync::watch::Receiver<bool>) {
    let mut ticker = tokio::time::interval(REASSERT_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut warned = false;
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    return;
                }
            }
            _ = ticker.tick() => {
                let ok = ensure_tun_trust(&iface).await;
                if !ok && !warned {
                    tracing::warn!(
                        iface,
                        "firewall: could not assert TUN trust rule (ip6tables \
                         missing or unprivileged?) — inbound overlay \
                         connections may be dropped by the host firewall"
                    );
                    warned = true;
                } else if ok && warned {
                    tracing::info!(iface, "firewall: TUN trust rule restored");
                    warned = false;
                }
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    /// Pin the exact rule shape: iface-scoped (`-i <iface>`), plain
    /// ACCEPT, nothing else. A wildcard (`tun+`) or a port match
    /// sneaking in here would silently change the trust surface.
    #[test]
    fn rule_is_iface_scoped_accept() {
        let args = rule_args("tun1");
        assert_eq!(args, ["-i", "tun1", "-j", "ACCEPT"]);
    }

    /// A bogus binary name must surface as `SpawnFailed`, the
    /// warn-don't-fail path — never a panic or an `Err` that could
    /// bubble into the join.
    #[tokio::test]
    async fn exec_spawn_failure_is_contained() {
        match exec("tabbify-no-such-iptables-xyzzy", &["-L".into()]).await {
            Exec::SpawnFailed(_) => {}
            Exec::Done { .. } => panic!("bogus binary unexpectedly ran"),
        }
    }

    /// `ensure_tun_trust` and `remove_tun_trust` must complete without
    /// error even when no iptables exists (macOS dev hosts, containers)
    /// — the best-effort contract.
    #[tokio::test]
    async fn ensure_and_remove_are_best_effort() {
        // On macOS there is no ip6tables: ensure returns false, remove
        // is a no-op. On a Linux dev host with privileges this may
        // actually install+remove a rule for a nonexistent iface name,
        // which iptables accepts (rules on absent ifaces are legal).
        let _ = ensure_tun_trust("tabbify-test-tun-xyzzy").await;
        remove_tun_trust("tabbify-test-tun-xyzzy").await;
    }

    /// The shutdown signal terminates the loop promptly.
    #[tokio::test]
    async fn trust_loop_exits_on_shutdown() {
        let (tx, rx) = tokio::sync::watch::channel(false);
        let handle = tokio::spawn(trust_loop("tabbify-test-tun".into(), rx));
        tx.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("trust_loop must exit on shutdown")
            .unwrap();
    }
}
