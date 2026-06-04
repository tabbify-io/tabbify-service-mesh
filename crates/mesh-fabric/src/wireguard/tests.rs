//! IPv6 framing + keypair generation unit tests.
//!
//! Integration-level UDP round trips live in `tests/wireguard_udp.rs`.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use super::ipv6::{IPV6_HEADER_LEN, build_ipv6_packet, parse_ipv6_packet};
use super::keys::generate_keypair;
use crate::trait_def::FabricError;
use std::net::Ipv6Addr;

#[test]
fn ipv6_packet_roundtrip_preserves_payload() {
    let src: Ipv6Addr = "fd5a:1f00:0001::1".parse().unwrap();
    let dst: Ipv6Addr = "fd5a:1f00:0001::2".parse().unwrap();
    let payload = b"hello world";
    let packet = build_ipv6_packet(src, dst, payload).unwrap();
    let (parsed_src, parsed_dst, parsed_payload) = parse_ipv6_packet(&packet).unwrap();
    assert_eq!(parsed_src, src);
    assert_eq!(parsed_dst, dst);
    assert_eq!(parsed_payload, payload);
}

#[test]
fn ipv6_packet_rejects_short_input() {
    let err = parse_ipv6_packet(&[0u8; 10]).unwrap_err();
    assert!(matches!(err, FabricError::Encoding(_)));
}

#[test]
fn ipv6_packet_rejects_wrong_version() {
    let mut bytes = vec![0u8; IPV6_HEADER_LEN];
    bytes[0] = 0x40; // ipv4 nibble
    let err = parse_ipv6_packet(&bytes).unwrap_err();
    assert!(matches!(err, FabricError::Encoding(_)));
}

#[test]
fn ipv6_packet_rejects_length_mismatch() {
    let mut packet = build_ipv6_packet(Ipv6Addr::UNSPECIFIED, Ipv6Addr::UNSPECIFIED, b"x").unwrap();
    // Truncate the payload byte.
    packet.truncate(IPV6_HEADER_LEN);
    let err = parse_ipv6_packet(&packet).unwrap_err();
    assert!(matches!(err, FabricError::Encoding(_)));
}

#[test]
fn generate_keypair_produces_distinct_keys_each_call() {
    let kp1 = generate_keypair();
    let kp2 = generate_keypair();
    assert_ne!(kp1.public.as_bytes(), kp2.public.as_bytes());
}
