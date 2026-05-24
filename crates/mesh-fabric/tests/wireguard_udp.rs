//! Pure-UDP integration tests for [`WireGuardFabric`].
//!
//! These tests stand up two `WireGuardFabric` instances bound to
//! loopback UDP ports, exchange a real `WireGuard` handshake via
//! boringtun, and verify encrypted payload delivery — all without
//! touching a kernel utun device. They run on any developer
//! machine and CI without root.
//!
//! The utun-integrated tests live in `wireguard_utun.rs` and are
//! `#[ignore]` (require sudo + macOS).
#![cfg(feature = "wireguard")]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic, unsafe_code)]

use std::net::Ipv6Addr;
use std::time::Duration;
use tabbify_mesh_fabric::{
    wireguard::{
        generate_keypair, WireGuardFabric, WireGuardPeerSpec,
    },
    MeshFabric,
};
use tokio::time::timeout;

/// Stand up two fabrics, register them as peers of each other,
/// drive the handshake, and verify that an encrypted payload is
/// delivered.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_node_handshake_and_payload_delivery() {
    let _ = tracing_subscriber::fmt()
        .with_test_writer()
        .with_env_filter("warn,tabbify_mesh_fabric=debug,boringtun=warn")
        .try_init();

    let alpha_keys = generate_keypair();
    let beta_keys = generate_keypair();

    let alpha = WireGuardFabric::bind(
        "127.0.0.1:0".parse().expect("alpha addr"),
        "alpha".into(),
        alpha_keys.private.clone(),
    )
    .await
    .expect("bind alpha");

    let beta = WireGuardFabric::bind(
        "127.0.0.1:0".parse().expect("beta addr"),
        "beta".into(),
        beta_keys.private.clone(),
    )
    .await
    .expect("bind beta");

    let alpha_addr = alpha.local_addr();
    let beta_addr = beta.local_addr();

    alpha.add_wireguard_peer(WireGuardPeerSpec {
        node_id: "beta".into(),
        endpoint: beta_addr,
        public_key: beta_keys.public,
    });
    beta.add_wireguard_peer(WireGuardPeerSpec {
        node_id: "alpha".into(),
        endpoint: alpha_addr,
        public_key: alpha_keys.public,
    });

    // Register a local endpoint on beta that alpha will send to.
    let ula_b: Ipv6Addr = "fd5a:1f00:0001:0000:0000:0000:0000:0002"
        .parse()
        .expect("parse ula_b");
    let mut rx_b = beta
        .register_local(ula_b, "endpoint-beta".into())
        .await
        .expect("register beta endpoint");

    // Tell alpha how to reach ula_b.
    alpha.add_remote_route(ula_b, "beta".into());

    // Drive the handshake to completion before sending the
    // application payload — boringtun queues data while the
    // handshake is in progress and delivers it once the session
    // comes up, but waiting explicitly here makes the test
    // deterministic.
    alpha
        .wait_until_handshake("beta", Duration::from_secs(5))
        .await
        .expect("alpha->beta handshake");

    // Send the application payload.
    alpha
        .send(ula_b, b"hello over wireguard".to_vec())
        .await
        .expect("send from alpha");

    // Receive on beta.
    let (dst, msg) = timeout(Duration::from_secs(5), rx_b.recv())
        .await
        .expect("recv timeout")
        .expect("recv channel closed");

    assert_eq!(dst, ula_b, "delivered to expected ULA");
    assert_eq!(msg, b"hello over wireguard");
}

/// Two payloads back-to-back share a session — no second handshake
/// is required and both are delivered intact.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn multiple_payloads_reuse_the_session() {
    let _ = tracing_subscriber::fmt()
        .with_test_writer()
        .with_env_filter("warn")
        .try_init();

    let a_keys = generate_keypair();
    let b_keys = generate_keypair();

    let a = WireGuardFabric::bind(
        "127.0.0.1:0".parse().expect("a addr"),
        "a".into(),
        a_keys.private.clone(),
    )
    .await
    .expect("bind a");

    let b = WireGuardFabric::bind(
        "127.0.0.1:0".parse().expect("b addr"),
        "b".into(),
        b_keys.private.clone(),
    )
    .await
    .expect("bind b");

    a.add_wireguard_peer(WireGuardPeerSpec {
        node_id: "b".into(),
        endpoint: b.local_addr(),
        public_key: b_keys.public,
    });
    b.add_wireguard_peer(WireGuardPeerSpec {
        node_id: "a".into(),
        endpoint: a.local_addr(),
        public_key: a_keys.public,
    });

    let ula: Ipv6Addr = "fd5a:1f00:0001:0000:0000:0000:0000:0099"
        .parse()
        .expect("parse ula");
    let mut rx = b
        .register_local(ula, "ep-b".into())
        .await
        .expect("register");
    a.add_remote_route(ula, "b".into());

    a.wait_until_handshake("b", Duration::from_secs(5))
        .await
        .expect("handshake");

    for i in 0..5u8 {
        let payload = vec![i; 32];
        a.send(ula, payload.clone()).await.expect("send");
        let (_, got) = timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("recv timeout")
            .expect("recv channel closed");
        assert_eq!(got, payload, "payload {i} round-tripped intact");
    }
}

/// A `WireGuardFabric` with no remote route for the destination
/// returns `NoRoute`, mirroring the contract of the other fabrics.
#[tokio::test]
async fn unknown_ula_returns_no_route() {
    let keys = generate_keypair();
    let fabric = WireGuardFabric::bind(
        "127.0.0.1:0".parse().expect("addr"),
        "solo".into(),
        keys.private,
    )
    .await
    .expect("bind");

    let ghost: Ipv6Addr = "fd5a:1f00:dead::1".parse().expect("parse");
    let err = fabric.send(ghost, b"nope".to_vec()).await.unwrap_err();
    assert!(matches!(
        err,
        tabbify_mesh_fabric::FabricError::NoRoute(_)
    ));
}

/// Local endpoint delivery on a single `WireGuardFabric` instance
/// bypasses encryption (same shape as `InProcessFabric`).
#[tokio::test]
async fn local_endpoint_delivery_skips_encryption() {
    let keys = generate_keypair();
    let fabric = WireGuardFabric::bind(
        "127.0.0.1:0".parse().expect("addr"),
        "solo".into(),
        keys.private,
    )
    .await
    .expect("bind");

    let ula: Ipv6Addr = "fd5a:1f00:0001::42".parse().expect("parse");
    let mut rx = fabric
        .register_local(ula, "local-ep".into())
        .await
        .expect("register");

    fabric
        .send(ula, b"hi self".to_vec())
        .await
        .expect("send local");

    let (dst, msg) = timeout(Duration::from_secs(1), rx.recv())
        .await
        .expect("recv timeout")
        .expect("recv channel closed");
    assert_eq!(dst, ula);
    assert_eq!(msg, b"hi self");
}

/// Payloads larger than the IPv6 length field cap (~65 KiB) are
/// rejected with `Encoding`.
#[tokio::test]
async fn oversized_payload_rejected() {
    use tabbify_mesh_fabric::wireguard::MAX_APP_PAYLOAD;
    let keys = generate_keypair();
    let fabric = WireGuardFabric::bind(
        "127.0.0.1:0".parse().expect("addr"),
        "solo".into(),
        keys.private,
    )
    .await
    .expect("bind");

    let peer_keys = generate_keypair();
    fabric.add_wireguard_peer(WireGuardPeerSpec {
        node_id: "ghost".into(),
        endpoint: "127.0.0.1:1".parse().expect("addr"),
        public_key: peer_keys.public,
    });
    let ula: Ipv6Addr = "fd5a:1f00:0001::dead".parse().expect("parse");
    fabric.add_remote_route(ula, "ghost".into());

    let huge = vec![0u8; MAX_APP_PAYLOAD + 1];
    let err = fabric.send(ula, huge).await.unwrap_err();
    assert!(matches!(
        err,
        tabbify_mesh_fabric::FabricError::Encoding(_)
    ));
}
