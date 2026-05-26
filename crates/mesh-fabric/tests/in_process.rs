#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic, unsafe_code)]

use std::net::Ipv6Addr;
use tabbify_mesh_fabric::{FabricError, MeshFabric, Ula, UlaPrefix, in_process::InProcessFabric};

#[tokio::test]
async fn register_send_recv_roundtrip() {
    let fabric = InProcessFabric::new();
    let ula_a: Ipv6Addr = "fd5a:1f00:0001:0000:0000:0000:0000:0001".parse().unwrap();
    let ula_b: Ipv6Addr = "fd5a:1f00:0001:0000:0000:0000:0000:0002".parse().unwrap();

    let mut a_rx = fabric
        .register_local(ula_a, "endpoint-a".into())
        .await
        .unwrap();
    let mut b_rx = fabric
        .register_local(ula_b, "endpoint-b".into())
        .await
        .unwrap();

    fabric.send(ula_b, b"hello from a".to_vec()).await.unwrap();
    fabric.send(ula_a, b"hello from b".to_vec()).await.unwrap();

    let (dst, msg) = b_rx.recv().await.unwrap();
    assert_eq!(
        dst, ula_b,
        "messages addressed to ula_b arrive on b_rx with dst=ula_b"
    );
    assert_eq!(msg, b"hello from a");

    let (dst, msg) = a_rx.recv().await.unwrap();
    assert_eq!(dst, ula_a);
    assert_eq!(msg, b"hello from b");
}

#[tokio::test]
async fn send_to_unknown_ula_returns_no_route() {
    let fabric = InProcessFabric::new();
    let ula_ghost: Ipv6Addr = "fd5a:1f00:dead:dead:dead:dead:dead:dead".parse().unwrap();
    let err = fabric.send(ula_ghost, b"nope".to_vec()).await.unwrap_err();
    assert!(matches!(err, FabricError::NoRoute(_)), "got: {err:?}");
}

#[tokio::test]
async fn unregister_removes_route() {
    let fabric = InProcessFabric::new();
    let ula: Ipv6Addr = "fd5a:1f00:0001:0000:0000:0000:0000:0010".parse().unwrap();
    let _rx = fabric.register_local(ula, "endpoint".into()).await.unwrap();

    fabric.send(ula, b"ok".to_vec()).await.unwrap();
    fabric.unregister_local(ula).await.unwrap();
    let err = fabric.send(ula, b"after-unreg".to_vec()).await.unwrap_err();
    assert!(matches!(err, FabricError::NoRoute(_)));
}

#[tokio::test]
async fn routing_snapshot_lists_local_endpoints() {
    let fabric = InProcessFabric::new();
    let ula1: Ipv6Addr = "fd5a:1f00:0001:0000:0000:0000:0000:0001".parse().unwrap();
    let ula2: Ipv6Addr = "fd5a:1f00:0001:0000:0000:0000:0000:0002".parse().unwrap();
    let _rx1 = fabric.register_local(ula1, "ep-1".into()).await.unwrap();
    let _rx2 = fabric.register_local(ula2, "ep-2".into()).await.unwrap();

    let snap = fabric.routing_snapshot();
    assert_eq!(snap.local_endpoints.len(), 2);
    assert!(
        snap.local_endpoints
            .iter()
            .any(|(addr, id)| *addr == ula1 && id == "ep-1")
    );
    assert!(
        snap.local_endpoints
            .iter()
            .any(|(addr, id)| *addr == ula2 && id == "ep-2")
    );
    assert!(
        snap.remote_routes.is_empty(),
        "InProcessFabric never has remote routes"
    );
}

#[test]
fn ula_from_uuid_components_is_deterministic() {
    let prefix = UlaPrefix::new(0x00, 1).unwrap();
    let app_uuid = uuid::Uuid::parse_str("019e2b78-78b8-7821-a416-46271c29632a").unwrap();
    let a = Ula::from_components(&prefix, app_uuid, 1);
    let b = Ula::from_components(&prefix, app_uuid, 1);
    assert_eq!(a.address(), b.address(), "deterministic for same inputs");
    let c = Ula::from_components(&prefix, app_uuid, 2);
    assert_ne!(
        a.address(),
        c.address(),
        "different instance => different addr"
    );
}

#[test]
fn ula_address_encodes_prefix_magic_and_tenant() {
    let prefix = UlaPrefix::new(0x00, 42).unwrap();
    let app_uuid = uuid::Uuid::parse_str("019e2b78-78b8-7821-a416-46271c29632a").unwrap();
    let ula = Ula::from_components(&prefix, app_uuid, 1);
    let segs = ula.address().segments();
    assert_eq!(segs[0], 0xfd5a, "ULA prefix high");
    assert_eq!(segs[1], 0x1f00, "ULA magic byte (0x00)");
    assert_eq!(segs[2], 42, "tenant id");
    assert_eq!(segs[7], 1, "instance id in low 16 bits");
}

#[test]
fn ula_address_encodes_full_64_bit_app_uuid_prefix() {
    // The leading 8 bytes of the UUID are spread across segs[3..=6].
    // UUID `019e2b78-78b8-7821-a416-46271c29632a` → bytes
    //   01 9e | 2b 78 | 78 b8 | 78 21 | a4 16 | 46 27 | 1c 29 | 63 2a
    //   segs[3]=0x019e segs[4]=0x2b78 segs[5]=0x78b8 segs[6]=0x7821
    let prefix = UlaPrefix::new(0x00, 1).unwrap();
    let app_uuid = uuid::Uuid::parse_str("019e2b78-78b8-7821-a416-46271c29632a").unwrap();
    let ula = Ula::from_components(&prefix, app_uuid, 1);
    let segs = ula.address().segments();
    assert_eq!(segs[3], 0x019e, "app64 byte 0..1");
    assert_eq!(segs[4], 0x2b78, "app64 byte 2..3");
    assert_eq!(segs[5], 0x78b8, "app64 byte 4..5");
    assert_eq!(segs[6], 0x7821, "app64 byte 6..7");
}

#[test]
fn ula_address_distinguishes_uuids_differing_only_in_byte_4_to_7() {
    // Sanity-check the upgrade from app32 → app64: two UUIDs that would
    // have collided under the old 32-bit truncation now produce distinct
    // ULAs because bytes 4..=7 are part of the slot.
    let prefix = UlaPrefix::new(0x00, 1).unwrap();
    let uuid_a = uuid::Uuid::parse_str("019e2b78-78b8-7821-a416-46271c29632a").unwrap();
    let uuid_b = uuid::Uuid::parse_str("019e2b78-aaaa-7821-a416-46271c29632a").unwrap();
    let ula_a = Ula::from_components(&prefix, uuid_a, 1);
    let ula_b = Ula::from_components(&prefix, uuid_b, 1);
    assert_ne!(
        ula_a.address(),
        ula_b.address(),
        "UUIDs differing in bytes 4..=5 produce distinct ULAs under app64",
    );
    let segs_a = ula_a.address().segments();
    let segs_b = ula_b.address().segments();
    assert_eq!(segs_a[3], segs_b[3], "byte 0..1 still identical");
    assert_eq!(segs_a[4], segs_b[4], "byte 2..3 still identical");
    assert_ne!(
        segs_a[5], segs_b[5],
        "byte 4..5 diverges (this is the upgrade payoff)"
    );
}

#[test]
fn ula_address_includes_magic_byte_in_segment_1() {
    let prefix = UlaPrefix::new(0xab, 7).unwrap();
    let app_uuid = uuid::Uuid::parse_str("019e2b78-78b8-7821-a416-46271c29632a").unwrap();
    let ula = Ula::from_components(&prefix, app_uuid, 1);
    let segs = ula.address().segments();
    assert_eq!(segs[1], 0x1fab, "magic byte 0xab combined into segment 1");
    assert_eq!(segs[2], 7);
}
