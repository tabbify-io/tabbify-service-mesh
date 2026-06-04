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

/// Outcome of one raw firewall-binary invocation, with stdout captured
/// (the listing parse is the only presence check we trust — see
/// [`ensure_one`]).
enum Exec {
    /// Binary missing / not executable.
    SpawnFailed(String),
    /// Ran to completion with this success flag and captured streams.
    Done {
        ok: bool,
        stdout: String,
        stderr: String,
    },
}

async fn exec(bin: &str, args: &[String]) -> Exec {
    match Command::new(bin).args(args).output().await {
        Err(e) => Exec::SpawnFailed(e.to_string()),
        Ok(out) => Exec::Done {
            ok: out.status.success(),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        },
    }
}

/// The exact `-S INPUT` listing line of our trust rule. Listing-parse is
/// the ONLY presence check we trust: iptables-nft `-C` FALSE-POSITIVES
/// once any `-i <other-iface> -j ACCEPT` rule exists in the chain
/// (observed live on iptables v1.8.11 `nf_tables` / NixOS 25.11:
/// `-C INPUT -i tunZZZZZ -j ACCEPT` exits 0 with only a different
/// iface's rule installed), which silently skipped the second joiner's
/// insert. The `-S` listing, by contrast, is canonical and truthful.
fn accept_line(iface: &str) -> String {
    format!("-A INPUT -i {iface} -j ACCEPT")
}

/// 1-based position of our rule among the chain's `-A INPUT` lines, for
/// an index-based delete (`-D INPUT <n>`). Spec-based `-D` shares the
/// broken `-C` matcher and could delete ANOTHER joiner's trust rule.
fn find_rule_index(listing: &str, iface: &str) -> Option<usize> {
    let needle = accept_line(iface);
    listing
        .lines()
        .filter(|l| l.starts_with("-A INPUT"))
        .position(|l| l.trim() == needle)
        .map(|i| i + 1)
}

/// List the INPUT chain (`-S INPUT`). `None` = binary missing or listing
/// failed (containers, unprivileged) — the best-effort failure path.
async fn list_input(bin: &str) -> Option<String> {
    match exec(bin, &["-S".into(), "INPUT".into()]).await {
        Exec::Done {
            ok: true, stdout, ..
        } => Some(stdout),
        Exec::Done { stderr, .. } => {
            tracing::debug!(bin, stderr = %stderr.trim(), "firewall: list failed");
            None
        }
        Exec::SpawnFailed(e) => {
            tracing::debug!(bin, error = %e, "firewall: binary unavailable");
            None
        }
    }
}

/// Ensure `INPUT -i <iface> -j ACCEPT` exists (list-then-insert, so
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

/// List-then-insert for one iptables binary (NOT `-C`-then-insert — see
/// [`accept_line`] for why `-C` cannot be trusted on iptables-nft).
async fn ensure_one(bin: &str, iface: &str) -> bool {
    let Some(listing) = list_input(bin).await else {
        return false;
    };
    if find_rule_index(&listing, iface).is_some() {
        return true;
    }
    // Absent — insert at position 1 so the rule precedes any distro
    // REJECT chain.
    let rule = rule_args(iface);
    let mut insert: Vec<String> = vec!["-I".into(), "INPUT".into(), "1".into()];
    insert.extend(rule.iter().cloned());
    match exec(bin, &insert).await {
        Exec::Done { ok: true, .. } => true,
        Exec::Done {
            ok: false, stderr, ..
        } => {
            tracing::debug!(bin, iface, stderr = %stderr.trim(), "firewall: insert failed");
            false
        }
        Exec::SpawnFailed(e) => {
            tracing::debug!(bin, error = %e, "firewall: binary unavailable");
            false
        }
    }
}

/// Remove the trust rule for `iface` (both families).
///
/// Idempotent and best-effort — called from `Joiner::leave`; an absent
/// rule or missing binary is fine. Deletes BY INDEX (resolved from the
/// `-S` listing) because a spec-based `-D` shares iptables-nft's broken
/// rule matcher and could remove another joiner's trust rule. The tiny
/// list→delete race (a concurrent insert shifting indices) is bounded by
/// every joiner's 60s re-assert loop, which restores any casualty.
pub async fn remove_tun_trust(iface: &str) {
    for bin in ["ip6tables", "iptables"] {
        let Some(listing) = list_input(bin).await else {
            continue;
        };
        let Some(index) = find_rule_index(&listing, iface) else {
            continue; // never installed / already gone
        };
        let del: Vec<String> = vec!["-D".into(), "INPUT".into(), index.to_string()];
        match exec(bin, &del).await {
            Exec::Done { ok: true, .. } => {
                tracing::debug!(bin, iface, "firewall: tun trust removed");
            }
            Exec::Done { .. } | Exec::SpawnFailed(_) => {
                // Already gone / no privileges — nothing to remove.
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

    /// Presence detection must work off the `-S INPUT` listing, finding
    /// the EXACT rule and its delete index — and must NOT match a
    /// different iface's rule (that is precisely the iptables-nft `-C`
    /// bug this parser replaces: with `tun96…`'s rule installed,
    /// `-C INPUT -i tun8e… -j ACCEPT` falsely reported present and the
    /// second joiner's insert was silently skipped).
    #[test]
    fn listing_parse_finds_exact_rule_and_index() {
        // Real-shape listing captured from the live NixOS host.
        let listing = "-P INPUT ACCEPT\n\
             -A INPUT -i tun96d514b9fa -j ACCEPT\n\
             -A INPUT -p tcp -m tcp --dport 18080 -j ACCEPT\n\
             -A INPUT -j nixos-fw\n";
        assert_eq!(find_rule_index(listing, "tun96d514b9fa"), Some(1));
        // The OTHER joiner's iface must read as ABSENT, not present.
        assert_eq!(find_rule_index(listing, "tun8e09734b36"), None);
        // Policy line (-P) must not shift rule indices.
        let with_ours = format!("{listing}-A INPUT -i tun8e09734b36 -j ACCEPT\n");
        assert_eq!(find_rule_index(&with_ours, "tun8e09734b36"), Some(4));
        assert_eq!(accept_line("tun1"), "-A INPUT -i tun1 -j ACCEPT");
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
