//! Fixed platform-infrastructure ULA predicates.
//!
//! Auth refuses to MINT a `requested_ulas` capability for any address outside
//! this shape, and the mesh coordinator refuses to GRANT such an address
//! without an exact signed capability. Both sides call the SAME predicate: the
//! last time the two copies diverged from reality (the registry's legacy
//! address matched neither), a registry restart broke image pulls
//! platform-wide (2026-07-21 incident).

use std::net::Ipv6Addr;

/// Second 16-bit segment (`segments()[1]`) of the coordinator's host/infra
/// ULA block (`fd5a:1f00:…`). Distinct from the supervisor-minted
/// per-app-runner slot (`fd5a:1f02:…`, `is_ephemeral_peer` in `mesh-joiner`).
pub const HOST_ULA_SLOT: u16 = 0x1f00;

/// The ULA index (`segments()[3]`) the dynamic allocator NEVER hands out (it
/// starts at 1). Idx 0 therefore marks a FIXED platform-infra address (e.g.
/// the forge's `fd5a:1f00:ffff::1`) requiring an exact signed join-token
/// capability.
pub const INFRA_ULA_IDX: u16 = 0;

/// True when `addr` is a FIXED platform-infra ULA: a unique-local address
/// (`fc00::/7`) in the coordinator host slot at the reserved infra index, or
/// the grandfathered legacy registry address ([`is_legacy_infra_ula`]).
#[must_use]
pub const fn is_fixed_infra_ula(addr: &Ipv6Addr) -> bool {
    let segments = addr.segments();
    (segments[0] & 0xfe00 == 0xfc00 && segments[1] == HOST_ULA_SLOT && segments[3] == INFRA_ULA_IDX)
        || is_legacy_infra_ula(&segments)
}

/// Legacy fixed platform-infra ULA: the mesh registry has served at
/// `fd5a:1f00:0:3::1` since before per-network address blocks existed, so its
/// index is 3 rather than the reserved [`INFRA_ULA_IDX`]. Every stored OCI ref
/// embeds that address. Exact-match only — neighbours are NOT exempt, so the
/// clause cannot widen into a general out-of-block escape hatch.
#[must_use]
pub const fn is_legacy_infra_ula(s: &[u16; 8]) -> bool {
    s[0] == 0xfd5a
        && s[1] == 0x1f00
        && s[2] == 0
        && s[3] == 3
        && s[4] == 0
        && s[5] == 0
        && s[6] == 0
        && s[7] == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> Ipv6Addr {
        s.parse().expect("test address parses")
    }

    /// The reserved idx-0 shape is fixed-infra, across the whole fc00::/7
    /// ULA range — not just the production fd5a prefix.
    #[test]
    fn reserved_index_zero_addresses_are_fixed_infra() {
        for a in ["fd5a:1f00:ffff::1", "fd5a:1f00:fffe::1", "fdaa:1f00:7::1"] {
            assert!(is_fixed_infra_ula(&addr(a)), "{a} must be fixed-infra");
        }
    }

    /// The registry's legacy address predates the idx-0 scheme. Losing this
    /// grandfather clause re-homes the registry on restart and breaks every
    /// stored OCI ref (2026-07-21 incident).
    #[test]
    fn legacy_registry_address_is_fixed_infra() {
        assert!(is_fixed_infra_ula(&addr("fd5a:1f00:0:3::1")));
        assert!(is_legacy_infra_ula(&addr("fd5a:1f00:0:3::1").segments()));
    }

    /// The grandfather clause is exact: neighbours of the legacy address are
    /// NOT exempt, so it cannot smuggle an arbitrary out-of-block request.
    #[test]
    fn addresses_near_the_legacy_one_are_not_fixed_infra() {
        for near in [
            "fd5a:1f00:0:3::2",
            "fd5a:1f00:0:4::1",
            "fd5a:1f00:1:3::1",
            "fd5a:1f00:4ed8:16::1",
            "fd5b:1f00:0:3::1",
        ] {
            assert!(
                !is_fixed_infra_ula(&addr(near)),
                "{near} must not be fixed-infra"
            );
        }
    }

    /// Normal allocator-issued host peers (idx >= 1) are never fixed-infra.
    #[test]
    fn allocated_host_indexes_are_not_fixed_infra() {
        for a in [
            "fd5a:1f00:fffe:1::1",
            "fd5a:1f00:0:1::1",
            "fd5a:1f00:12:7::1",
        ] {
            assert!(!is_fixed_infra_ula(&addr(a)), "{a} must not be fixed-infra");
        }
    }

    /// Outside fc00::/7, or outside the host slot, nothing qualifies.
    #[test]
    fn non_ula_and_wrong_slot_addresses_are_not_fixed_infra() {
        for a in [
            "2001:db8::1",
            "2001:1f00:0:0::1",
            "fd5a:1f02:5::1",
            "fe80:1f00::",
        ] {
            assert!(!is_fixed_infra_ula(&addr(a)), "{a} must not be fixed-infra");
        }
    }

    /// The constants are load-bearing wire/address-layout values.
    #[test]
    fn constants_pin_the_address_layout() {
        assert_eq!(HOST_ULA_SLOT, 0x1f00);
        assert_eq!(INFRA_ULA_IDX, 0);
    }
}
