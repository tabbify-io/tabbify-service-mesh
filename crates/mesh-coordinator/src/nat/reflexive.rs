//! Reflexive-endpoint reflection — Stage 2 cone-`NAT` endpoint discovery.
//!
//! When a joiner is behind `NAT`, the `WireGuard` listen socket it binds
//! locally (`0.0.0.0:<port>` → reported back as `127.0.0.1:<port>` or a
//! LAN address) is NOT reachable by other peers. The address other peers
//! must actually dial is the joiner's *reflexive* address: the public IP
//! its `NAT` presents to the outside world, paired with the UDP port the
//! `NAT` maps to the joiner's `WireGuard` socket.
//!
//! The coordinator sees one half of that for free: every register /
//! heartbeat HTTP request arrives from the `NAT`'s public IP (exposed via
//! axum's [`axum::extract::ConnectInfo`]). The joiner sends the other
//! half — its `WireGuard` UDP listen port — in the request body. Combining
//! them gives a reflexive endpoint the coordinator can hand to other
//! peers without any manual `--advertise-endpoint`.
//!
//! # The port nuance (read before trusting this for symmetric `NAT`)
//!
//! The HTTP *source IP* is the `NAT`'s public IP — correct. But the HTTP
//! *source port* is the TCP port the `NAT` mapped for the control-plane
//! connection, which is unrelated to the UDP port it mapped for
//! `WireGuard`. So we cannot read the WG port off the HTTP connection; we
//! must use the joiner-reported `wg_listen_port`.
//!
//! Pairing `<observed-public-ip>:<reported-wg-port>` is correct when:
//!
//! * the host is directly reachable (public IP, no `NAT`), or
//! * the `NAT` is **full-cone** or otherwise **port-preserving** — i.e. it
//!   maps the internal UDP port to the *same* external port and accepts
//!   inbound from any source once a mapping exists.
//!
//! It is WRONG for **symmetric** / **port-randomizing** `NAT`, where the
//! external port differs from the internal one and varies per
//! destination. Handling that requires `STUN` issued *from the `WireGuard`
//! UDP socket itself* (so the `NAT` mapping observed is the WG one) or a
//! relay. Both are explicitly OUT OF SCOPE for this iteration — see the
//! Stage-3 follow-up in
//! `docs/superpowers/specs/2026-05-25-nat-traversal-design.md`.
//!
//! This module is pure (no I/O, no clock) so the decision table is fully
//! unit-testable; the HTTP handler feeds it the observed `SocketAddr` and
//! the parsed request.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// Is `ip` an address other peers across the public internet could never
/// dial — i.e. loopback, link-local, an RFC1918 / ULA private range, or
/// the unspecified address?
///
/// These are exactly the addresses a joiner might auto-detect off its own
/// bound socket but that are useless as an advertised endpoint for a peer
/// on a different network. When the joiner self-reports one of these we
/// prefer the coordinator-observed reflexive public IP instead.
///
/// We classify explicitly rather than via the still-unstable
/// `IpAddr::is_global` so the crate builds on stable Rust (and the musl
/// release target) without a feature gate — and so the intent is legible.
#[must_use]
pub const fn is_unreachable_for_peers(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_unreachable_v4(v4),
        IpAddr::V6(v6) => is_unreachable_v6(v6),
    }
}

const fn is_unreachable_v4(v4: Ipv4Addr) -> bool {
    // We deliberately do NOT treat the documentation ranges
    // (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 — TEST-NET 1/2/3) or
    // the broadcast address as unreachable: a real deployment never has a
    // documentation IP as its NAT egress, and those ranges are the
    // codebase's established stand-in for "a public, dial-able address" in
    // tests. The set below is the one that actually matters operationally:
    // a joiner auto-detecting one of these off its own socket would
    // advertise something no off-network peer can reach.
    v4.is_loopback()
        || v4.is_private()
        || v4.is_link_local()
        || v4.is_unspecified()
        // 100.64.0.0/10 — RFC6598 carrier-grade NAT shared space. A peer
        // sitting in CGNAT space is not directly reachable; treat the
        // address as private for advertisement purposes.
        || (v4.octets()[0] == 100 && (v4.octets()[1] & 0b1100_0000) == 0b0100_0000)
}

const fn is_unreachable_v6(v6: Ipv6Addr) -> bool {
    v6.is_loopback()
        || v6.is_unspecified()
        || v6.is_unique_local() // fc00::/7 — ULA, our overlay lives here
        // fe80::/10 link-local.
        || (v6.segments()[0] & 0xffc0) == 0xfe80
}

/// `true` when `ip` is a routable public address we can confidently hand
/// to other peers as a dial target. The complement of
/// [`is_unreachable_for_peers`].
#[must_use]
pub const fn is_public(ip: IpAddr) -> bool {
    !is_unreachable_for_peers(ip)
}

/// The endpoint the coordinator decided to store for a peer, plus whether
/// it was derived from the observed reflexive address.
///
/// The `reflexive` flag is the discriminator the heartbeat path needs: a
/// reflexive endpoint roams (follows the peer's observed public IP across
/// heartbeats); a self-reported / explicit one is sticky.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedEndpoint {
    /// The endpoint string to store (`None` ≡ passive peer).
    pub endpoint: Option<String>,
    /// `true` when `endpoint` was synthesized from the observed reflexive
    /// address rather than taken from the joiner's self-report.
    pub reflexive: bool,
}

/// Decide the effective `listen_endpoint` to store for a peer.
///
/// Weighs what the joiner self-reported against what the coordinator
/// observed on the request socket.
///
/// Inputs:
/// * `self_reported` — the `listen_endpoint` string the joiner sent
///   (`None`/empty for a passive peer that can't advertise anything).
/// * `observed` — the source `SocketAddr` of the HTTP request (the NAT's
///   public IP + an unrelated TCP port). `None` in tests that drive the
///   router without the connect-info make-service.
/// * `wg_listen_port` — the UDP port the joiner reported its `WireGuard`
///   socket is bound to. `None` when the joiner didn't report one (older
///   joiner, back-compat).
///
/// Decision table (first match wins):
///
/// 1. The self-reported endpoint already parses to a **public** routable
///    address, OR is a non-IP-literal hostname → keep it (NOT reflexive).
///    The operator (or a public host) knows best; we must not clobber an
///    explicit `--advertise-endpoint`.
/// 2. We have a **public** observed IP **and** a reported WG port →
///    return the reflexive `<observed-public-ip>:<wg_port>` (reflexive).
///    This is the NAT-traversal happy path for cone / port-preserving NAT.
/// 3. Otherwise → keep whatever the joiner self-reported (possibly a
///    loopback address for same-host smoke tests, possibly `None`; NOT
///    reflexive). We have nothing better to offer.
///
/// `relay_only` short-circuits the whole table: a peer that declared it has
/// no reachable direct endpoint is ALWAYS resolved to `None` (and never
/// reflexive). Advertising any direct endpoint for such a peer — even a
/// self-reported public one — would make other peers fire `WireGuard`
/// handshake-inits at a black-hole endpoint in parallel with the relay,
/// producing the simultaneous-init thrash this fix removes (see the joiner's
/// `JoinConfig::relay_only`). The peer is reached exclusively via the relay.
#[must_use]
pub fn resolve_listen_endpoint(
    self_reported: Option<&str>,
    observed: Option<SocketAddr>,
    wg_listen_port: Option<u16>,
    relay_only: bool,
) -> ResolvedEndpoint {
    // (0) A relay-only peer never advertises a direct dial target. This wins
    // over every other branch — its reflexive endpoint is unreachable and a
    // self-reported one would be black-holed.
    if relay_only {
        return ResolvedEndpoint {
            endpoint: None,
            reflexive: false,
        };
    }

    let self_reported = self_reported.filter(|s| !s.is_empty());

    // (1) A self-reported PUBLIC endpoint (or hostname) is authoritative.
    if let Some(reported) = self_reported {
        if let Ok(addr) = reported.parse::<SocketAddr>() {
            if is_public(addr.ip()) {
                return ResolvedEndpoint {
                    endpoint: Some(reported.to_owned()),
                    reflexive: false,
                };
            }
        } else {
            // A non-socket-literal (e.g. `host.lima.internal:51820`) is an
            // explicit operator advertisement we can't classify as
            // public/private — trust it verbatim. The consuming peer
            // resolves the name in its own environment (see
            // `mesh-joiner::coordinator::client::remote_to_info`).
            return ResolvedEndpoint {
                endpoint: Some(reported.to_owned()),
                reflexive: false,
            };
        }
    }

    // (2) Reflexive happy path: public observed IP + reported WG port.
    if let (Some(obs), Some(port)) = (observed, wg_listen_port) {
        if is_public(obs.ip()) {
            return ResolvedEndpoint {
                endpoint: Some(reflexive_endpoint(obs.ip(), port)),
                reflexive: true,
            };
        }
    }

    // (3) Nothing better — keep the (possibly loopback / None) self-report.
    ResolvedEndpoint {
        endpoint: self_reported.map(ToOwned::to_owned),
        reflexive: false,
    }
}

/// Format the reflexive endpoint string from a public IP + WG UDP port.
/// IPv6 literals are bracketed so the `host:port` parse round-trips.
#[must_use]
pub fn reflexive_endpoint(ip: IpAddr, wg_port: u16) -> String {
    SocketAddr::new(ip, wg_port).to_string()
}

/// `true` when `endpoint` must be STICKY across heartbeats.
///
/// An operator-chosen advertisement — a public IP literal, or a hostname
/// (anything not parseable as a socket addr, resolved by the consuming
/// peer) — must never be auto-rolled to a reflexive value, so it is
/// sticky.
///
/// A loopback / private IP literal returns `false`: it is a same-host
/// fallback, not a real advertisement, so it stays eligible for reflexive
/// rollover. This lets the heartbeat decision be independent of whether
/// the first register carried the observed source addr.
#[must_use]
pub fn is_sticky_explicit_endpoint(endpoint: &str) -> bool {
    endpoint.parse::<SocketAddr>().map_or(
        // Not a socket literal → treat as a hostname advertisement: sticky.
        true,
        // A socket literal is sticky only if its IP is public.
        |addr| is_public(addr.ip()),
    )
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn sock(s: &str) -> SocketAddr {
        s.parse().expect("socket addr literal")
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("ip literal")
    }

    // ---- classification ----

    #[test]
    fn loopback_and_private_are_unreachable() {
        assert!(is_unreachable_for_peers(ip("127.0.0.1")));
        assert!(is_unreachable_for_peers(ip("10.0.0.1")));
        assert!(is_unreachable_for_peers(ip("192.168.1.50")));
        assert!(is_unreachable_for_peers(ip("172.16.5.5")));
        assert!(is_unreachable_for_peers(ip("169.254.1.1"))); // link-local
        assert!(is_unreachable_for_peers(ip("0.0.0.0")));
        assert!(is_unreachable_for_peers(ip("100.64.0.1"))); // CGNAT
        assert!(is_unreachable_for_peers(ip("100.127.255.254"))); // CGNAT top
    }

    #[test]
    fn public_v4_is_reachable() {
        assert!(is_public(ip("203.0.113.10"))); // TEST-NET-3, treated public
        assert!(is_public(ip("8.8.8.8")));
        assert!(is_public(ip("1.1.1.1")));
        // 100.128.0.0 is just OUTSIDE the CGNAT /10 — must be public.
        assert!(is_public(ip("100.128.0.1")));
        // 172.32 is outside the 172.16/12 private block.
        assert!(is_public(ip("172.32.0.1")));
    }

    #[test]
    fn v6_loopback_ula_linklocal_unreachable() {
        assert!(is_unreachable_for_peers(ip("::1")));
        assert!(is_unreachable_for_peers(ip("::")));
        assert!(is_unreachable_for_peers(ip("fd5a:1f00:1::1"))); // ULA (our overlay)
        assert!(is_unreachable_for_peers(ip("fc00::1"))); // ULA
        assert!(is_unreachable_for_peers(ip("fe80::1"))); // link-local
    }

    #[test]
    fn v6_global_unicast_is_reachable() {
        assert!(is_public(ip("2001:db8::1")));
        assert!(is_public(ip("2606:4700:4700::1111")));
    }

    // ---- resolve_listen_endpoint decision table ----

    /// (2) The headline NAT case: joiner self-reports a loopback endpoint
    /// (its own bound `0.0.0.0`-derived guess), but the coordinator sees a
    /// public source IP. We must advertise the reflexive
    /// `<public-ip>:<wg-port>`, NOT the useless loopback — and flag it
    /// reflexive so heartbeats roam it.
    #[test]
    fn loopback_self_report_becomes_reflexive_public() {
        let got = resolve_listen_endpoint(
            Some("127.0.0.1:49046"),
            Some(sock("203.0.113.7:34812")), // observed: public IP, unrelated TCP port
            Some(51820),                     // reported WG UDP port
            false,
        );
        // Reflexive endpoint pairs the OBSERVED IP with the REPORTED WG
        // port — NOT the HTTP source port 34812.
        assert_eq!(got.endpoint.as_deref(), Some("203.0.113.7:51820"));
        assert!(
            got.reflexive,
            "loopback→reflexive must be flagged reflexive"
        );
    }

    /// A LAN self-report (private 192.168) is likewise replaced by the
    /// reflexive public endpoint.
    #[test]
    fn private_lan_self_report_becomes_reflexive_public() {
        let got = resolve_listen_endpoint(
            Some("192.168.1.42:51820"),
            Some(sock("198.51.100.9:5555")),
            Some(51820),
            false,
        );
        assert_eq!(got.endpoint.as_deref(), Some("198.51.100.9:51820"));
        assert!(got.reflexive);
    }

    /// (1) A self-reported PUBLIC endpoint must be preserved (and NOT
    /// flagged reflexive — it must be sticky across heartbeats). An
    /// operator who passed `--advertise-endpoint 203.0.113.50:51820` knows
    /// their port-forward better than our reflexive guess.
    #[test]
    fn public_self_report_is_preserved() {
        let got = resolve_listen_endpoint(
            Some("203.0.113.50:51820"),
            Some(sock("198.51.100.9:5555")), // different public IP observed
            Some(51820),
            false,
        );
        assert_eq!(got.endpoint.as_deref(), Some("203.0.113.50:51820"));
        assert!(!got.reflexive, "explicit public advert must be sticky");
    }

    /// (1) A hostname advertisement (not an IP literal) is trusted
    /// verbatim (and sticky) — we can't classify it, and the consuming
    /// peer resolves it in its own DNS environment.
    #[test]
    fn hostname_self_report_is_trusted_verbatim() {
        let got = resolve_listen_endpoint(
            Some("host.lima.internal:51820"),
            Some(sock("203.0.113.7:34812")),
            Some(51820),
            false,
        );
        assert_eq!(got.endpoint.as_deref(), Some("host.lima.internal:51820"));
        assert!(!got.reflexive);
    }

    /// No WG port reported (older joiner) → we can't synthesize a
    /// reflexive endpoint, so the loopback self-report is kept as-is. This
    /// is the back-compat path: an old joiner behaves exactly as before.
    #[test]
    fn no_wg_port_keeps_self_report() {
        let got = resolve_listen_endpoint(
            Some("127.0.0.1:49046"),
            Some(sock("203.0.113.7:34812")),
            None,
            false,
        );
        assert_eq!(got.endpoint.as_deref(), Some("127.0.0.1:49046"));
        assert!(!got.reflexive);
    }

    /// No observed addr (test router without connect-info) → keep the
    /// self-report. Mirrors the production fallback when the source addr
    /// is somehow unavailable.
    #[test]
    fn no_observed_addr_keeps_self_report() {
        let got = resolve_listen_endpoint(Some("127.0.0.1:49046"), None, Some(51820), false);
        assert_eq!(got.endpoint.as_deref(), Some("127.0.0.1:49046"));
        assert!(!got.reflexive);
    }

    /// Observed IP is itself private (coordinator + joiner on the same LAN,
    /// e.g. local smoke test) → we have nothing public to offer, so keep
    /// the self-report rather than advertising a private observed IP that
    /// might still be unreachable for a third peer.
    #[test]
    fn private_observed_ip_keeps_self_report() {
        let got = resolve_listen_endpoint(
            Some("127.0.0.1:49046"),
            Some(sock("10.0.0.5:5555")),
            Some(51820),
            false,
        );
        assert_eq!(got.endpoint.as_deref(), Some("127.0.0.1:49046"));
        assert!(!got.reflexive);
    }

    /// Passive peer (no self-report) with a public observed IP + WG port
    /// still gets a reflexive endpoint — this is how a NAT-bound joiner
    /// that declines to guess its own address becomes reachable.
    #[test]
    fn passive_peer_with_public_observed_gets_reflexive() {
        let got = resolve_listen_endpoint(None, Some(sock("203.0.113.7:34812")), Some(51820), false);
        assert_eq!(got.endpoint.as_deref(), Some("203.0.113.7:51820"));
        assert!(got.reflexive);
    }

    /// Passive peer, no observed IP, no port → stays passive (`None`).
    #[test]
    fn fully_passive_peer_stays_none() {
        assert_eq!(resolve_listen_endpoint(None, None, None, false).endpoint, None);
        assert_eq!(
            resolve_listen_endpoint(Some(""), None, Some(51820), false).endpoint,
            None
        );
    }

    /// Stickiness classification: public IP + hostname are sticky;
    /// loopback / private literals are not (eligible for reflexive roam).
    #[test]
    fn sticky_explicit_classification() {
        assert!(is_sticky_explicit_endpoint("203.0.113.50:51820")); // public IP
        assert!(is_sticky_explicit_endpoint("host.lima.internal:51820")); // hostname
        assert!(is_sticky_explicit_endpoint("[2001:db8::1]:51820")); // public v6
        assert!(!is_sticky_explicit_endpoint("127.0.0.1:51820")); // loopback fallback
        assert!(!is_sticky_explicit_endpoint("192.168.1.5:51820")); // LAN fallback
        assert!(!is_sticky_explicit_endpoint("10.0.0.1:51820")); // private fallback
    }

    // ---- relay-only suppression (Fix D) ----

    /// A relay-only peer must NEVER be advertised with a direct endpoint,
    /// even when the coordinator observes a public source IP + WG port that
    /// would otherwise synthesize a reflexive endpoint. Its reflexive
    /// endpoint is a black hole (no inbound mesh port), so advertising one
    /// would make peers fire handshake-inits at it AND relay — the
    /// simultaneous-init thrash this fix eliminates.
    #[test]
    fn relay_only_suppresses_reflexive_endpoint() {
        let got = resolve_listen_endpoint(
            None,
            Some(sock("203.0.113.7:34812")), // public observed IP
            Some(51820),                     // reported WG port
            true,                            // relay_only
        );
        assert_eq!(got.endpoint, None, "relay-only peer must advertise no endpoint");
        assert!(!got.reflexive);
    }

    /// Relay-only ALSO suppresses a self-reported endpoint — even a public
    /// one or a hostname. A peer that knows it has no inbound path must not
    /// be dialed directly under any circumstance.
    #[test]
    fn relay_only_suppresses_even_self_reported_public() {
        let got = resolve_listen_endpoint(
            Some("203.0.113.50:51820"),
            Some(sock("198.51.100.9:5555")),
            Some(51820),
            true,
        );
        assert_eq!(got.endpoint, None);
        assert!(!got.reflexive);

        let got_host = resolve_listen_endpoint(
            Some("host.lima.internal:51820"),
            None,
            Some(51820),
            true,
        );
        assert_eq!(got_host.endpoint, None);
        assert!(!got_host.reflexive);
    }

    /// Sanity: with `relay_only = false` the resolver behaves exactly as it
    /// did before the flag existed (the reflexive happy path still fires).
    #[test]
    fn relay_only_false_preserves_reflexive_behaviour() {
        let got = resolve_listen_endpoint(
            None,
            Some(sock("203.0.113.7:34812")),
            Some(51820),
            false,
        );
        assert_eq!(got.endpoint.as_deref(), Some("203.0.113.7:51820"));
        assert!(got.reflexive);
    }

    /// IPv6 reflexive endpoint must bracket the host so it round-trips
    /// through a `SocketAddr` parse.
    #[test]
    fn reflexive_v6_is_bracketed() {
        let s = reflexive_endpoint(ip("2001:db8::1"), 51820);
        assert_eq!(s, "[2001:db8::1]:51820");
        assert!(s.parse::<SocketAddr>().is_ok());
    }
}
