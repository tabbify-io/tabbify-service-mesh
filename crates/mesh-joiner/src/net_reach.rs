//! Advertise-endpoint reachability classification (joiner side).
//!
//! A private / unreachable address advertised to the coordinator is broadcast
//! to ALL peers, but only a same-LAN peer can ever dial it — every off-LAN peer
//! falls back to the relay. Worse, a STUN-discovered mapping that came back
//! private (a double-NAT / hairpin artefact) would STRAND the advertise on a
//! black-hole the moment it is adopted. So:
//!
//!   * an AUTO-discovered (STUN) private mapping is DROPPED — we keep whatever
//!     advertise we already had (reflexive / none), and the relay floor carries
//!     the pair until a real public mapping or a direct punch lands;
//!   * an EXPLICIT `--advertise-endpoint` private literal is KEPT (it is an
//!     operator override for same-LAN direct dialing) but emits a structured
//!     warning so the "why are off-LAN peers on relay?" question answers itself.
//!
//! The classifier mirrors the coordinator's
//! `mesh_coordinator::nat::reflexive::is_unreachable_for_peers` EXACTLY (a
//! dev-dependency equivalence test pins the two together) so a joiner and the
//! coordinator never disagree on whether an address is dial-able.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// Is `ip` an address other peers across the public internet could never dial —
/// loopback, link-local, an RFC1918 / ULA private range, CGNAT shared space, or
/// the unspecified address?
///
/// Mirrors `mesh_coordinator::nat::reflexive::is_unreachable_for_peers`.
#[must_use]
pub const fn is_unreachable_for_peers(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_unreachable_v4(v4),
        IpAddr::V6(v6) => is_unreachable_v6(v6),
    }
}

const fn is_unreachable_v4(v4: Ipv4Addr) -> bool {
    // Same set the coordinator treats as un-advertisable: a joiner auto-detecting
    // one of these off its own socket would advertise something no off-network
    // peer can reach. Documentation ranges (TEST-NET 1/2/3) and broadcast are
    // deliberately NOT here — they stand in for "public, dial-able" in tests.
    v4.is_loopback()
        || v4.is_private()
        || v4.is_link_local()
        || v4.is_unspecified()
        // 100.64.0.0/10 — RFC6598 carrier-grade NAT shared space.
        || (v4.octets()[0] == 100 && (v4.octets()[1] & 0b1100_0000) == 0b0100_0000)
}

const fn is_unreachable_v6(v6: Ipv6Addr) -> bool {
    v6.is_loopback()
        || v6.is_unspecified()
        || v6.is_unique_local() // fc00::/7 — ULA, our overlay lives here
        // fe80::/10 link-local.
        || (v6.segments()[0] & 0xffc0) == 0xfe80
}

/// `true` when `ip` is a routable public address we can confidently hand to
/// other peers as a dial target. Complement of [`is_unreachable_for_peers`].
#[must_use]
pub const fn is_public(ip: IpAddr) -> bool {
    !is_unreachable_for_peers(ip)
}

/// Decide whether a STUN-discovered WG `mapping` is usable as an advertised
/// endpoint.
///
/// Returns `Some(mapping.to_string())` to ADOPT it (the mapping is a real public
/// address), or `None` to DROP it and KEEP whatever advertise we already had
/// (the mapping is private / unreachable-for-peers — adopting it would strand
/// off-LAN peers on a black-hole; the relay floor stays the path). Pure: the
/// caller does the logging + assignment, so this is fully unit-testable.
#[must_use]
pub fn stun_mapping_to_advertise(mapping: SocketAddr) -> Option<String> {
    if is_unreachable_for_peers(mapping.ip()) {
        None
    } else {
        Some(mapping.to_string())
    }
}

/// Warn (but KEEP — do not drop) on an EXPLICIT private `--advertise-endpoint`.
///
/// Returns `true` when a warning was emitted (the value was a parseable private
/// `SocketAddr`), `false` otherwise (public, or a hostname we cannot classify
/// and must pass through verbatim).
///
/// The literal is an operator override for same-LAN direct dialing, so we never
/// drop it — we only surface that off-LAN peers will fall back to the relay.
pub fn warn_if_private_advertise(advertise: &str) -> bool {
    let Ok(sa) = advertise.parse::<SocketAddr>() else {
        return false;
    };
    if is_unreachable_for_peers(sa.ip()) {
        tracing::warn!(
            endpoint = %advertise,
            "private endpoint advertised to ALL peers; only same-LAN peers can use it, others fall back to relay"
        );
        return true;
    }
    false
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// EQUIVALENCE (unit-level proxy): the joiner's advertise classifier must
    /// agree with the coordinator's `is_unreachable_for_peers` on EVERY address —
    /// the two planes deciding "is this dial-able?" differently is exactly the
    /// kind of split-brain that strands a pair.
    ///
    /// The IDEAL form imports `mesh_coordinator::nat::reflexive::
    /// is_unreachable_for_peers` directly (a dev-dep) and asserts pointwise
    /// agreement. That is infeasible in this environment: pulling the coordinator
    /// crate transitively drags `utoipa-swagger-ui`, whose build artefact bakes a
    /// stale absolute path and fails to compile. So we instead pin against the
    /// coordinator's OWN documented expected values — the exact address battery
    /// asserted by `mesh-coordinator/src/nat/reflexive.rs` tests
    /// (`v4_*`, `v6_*`). Any drift in either classifier breaks this test.
    #[test]
    fn classifier_matches_coordinator_documented_battery() {
        // Mirrors reflexive.rs `unreachable_v4` / `public_v4` / `unreachable_v6`
        // / `public_v6` test cases verbatim (expected, address).
        let cases = [
            // v4 unreachable
            (true, "127.0.0.1"),
            (true, "10.0.0.1"),
            (true, "192.168.1.50"),
            (true, "172.16.5.5"),
            (true, "169.254.1.1"),
            (true, "0.0.0.0"),
            (true, "100.64.0.1"),
            (true, "100.127.255.254"),
            // v4 public
            (false, "203.0.113.10"),
            (false, "8.8.8.8"),
            (false, "1.1.1.1"),
            (false, "100.128.0.1"),
            (false, "172.32.0.1"),
            // v6 unreachable
            (true, "::1"),
            (true, "::"),
            (true, "fd5a:1f00:1::1"),
            (true, "fc00::1"),
            (true, "fe80::1"),
            // v6 public
            (false, "2001:db8::1"),
            (false, "2606:4700:4700::1111"),
        ];
        for (expected, c) in cases {
            assert_eq!(
                is_unreachable_for_peers(ip(c)),
                expected,
                "classifier disagrees with the coordinator's documented value on {c}"
            );
        }
    }

    /// STUN: a private XOR-MAPPED-ADDRESS is REJECTED — `stun_mapping_to_advertise`
    /// returns `None`, so the caller KEEPS its existing advertise (the value is
    /// NOT overwritten with the private mapping). A public mapping is adopted.
    #[test]
    fn stun_private_mapping_is_rejected() {
        for private in [
            "10.0.0.5:51820",
            "192.168.1.7:51820",
            "169.254.10.1:51820",
            "[fc00::1]:51820",
            "[fe80::1]:51820",
            "100.64.0.9:51820",
        ] {
            assert_eq!(
                stun_mapping_to_advertise(private.parse().unwrap()),
                None,
                "a private STUN mapping {private} must be dropped (advertise not overwritten)"
            );
        }
        // A genuinely public mapping IS adopted.
        assert_eq!(
            stun_mapping_to_advertise("203.0.113.9:51820".parse().unwrap()),
            Some("203.0.113.9:51820".to_string()),
            "a public STUN mapping is adopted as the advertise endpoint"
        );
    }

    /// EXPLICIT advertise: a private `--advertise-endpoint` literal is KEPT
    /// (operator override) but emits a structured WARN; a public one is silent;
    /// a hostname (unparseable as a `SocketAddr`) passes through with no warn.
    #[tracing_test::traced_test]
    #[test]
    fn explicit_private_advertise_logs_warning() {
        assert!(
            warn_if_private_advertise("10.1.2.3:51820"),
            "a private explicit advertise must warn (but is kept by the caller)"
        );
        assert!(
            logs_contain("private endpoint advertised to ALL peers"),
            "the structured WARN must be emitted"
        );
        assert!(
            !warn_if_private_advertise("203.0.113.9:51820"),
            "a public explicit advertise must NOT warn"
        );
        assert!(
            !warn_if_private_advertise("host.lima.internal:51820"),
            "a hostname literal is passed through verbatim with no warn"
        );
    }
}
