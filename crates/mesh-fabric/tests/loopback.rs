#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic, unsafe_code)]

use std::net::Ipv6Addr;
use std::time::Duration;
use tabbify_mesh_fabric::{
    loopback::{LoopbackFabric, LoopbackPeerSpec},
    FabricError, MeshFabric,
};
use tokio::time::timeout;

async fn fresh_fabric(port: u16, node_id: &str) -> LoopbackFabric {
    LoopbackFabric::bind(
        format!("127.0.0.1:{port}").parse().unwrap(),
        node_id.into(),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn local_endpoint_delivery_within_one_node() {
    let fabric = fresh_fabric(0, "alpha").await;
    let ula: Ipv6Addr = "fd5a:1f00:0001:0000:0000:0000:0000:0001".parse().unwrap();
    let mut rx = fabric.register_local(ula, "ep".into()).await.unwrap();

    fabric.send(ula, b"hi".to_vec()).await.unwrap();

    let (dst, msg) = timeout(Duration::from_secs(1), rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(dst, ula);
    assert_eq!(msg, b"hi");
}

#[tokio::test]
async fn cross_node_delivery_via_tcp() {
    let alpha = fresh_fabric(0, "alpha").await;
    let beta = fresh_fabric(0, "beta").await;

    let alpha_addr = alpha.local_addr();
    let beta_addr = beta.local_addr();

    alpha.add_peer(LoopbackPeerSpec {
        node_id: "beta".into(),
        addr: beta_addr,
    });
    beta.add_peer(LoopbackPeerSpec {
        node_id: "alpha".into(),
        addr: alpha_addr,
    });

    let ula_b: Ipv6Addr = "fd5a:1f00:0001:0000:0000:0000:0000:0002".parse().unwrap();
    let mut rx_b = beta.register_local(ula_b, "ep-b".into()).await.unwrap();

    alpha.add_remote_route(ula_b, "beta".into());
    alpha.send(ula_b, b"hello from alpha".to_vec()).await.unwrap();

    let (dst, msg) = timeout(Duration::from_secs(2), rx_b.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(dst, ula_b);
    assert_eq!(msg, b"hello from alpha");
}

#[tokio::test]
async fn unknown_ula_returns_no_route() {
    let alpha = fresh_fabric(0, "alpha").await;
    let ghost: Ipv6Addr = "fd5a:1f00:dead::1".parse().unwrap();
    let err = alpha.send(ghost, b"nope".to_vec()).await.unwrap_err();
    assert!(matches!(err, FabricError::NoRoute(_)));
}

#[tokio::test]
async fn cross_node_reconnects_after_peer_restart() {
    let alpha = fresh_fabric(0, "alpha").await;

    // First beta instance — bind, register, get a message through.
    let beta_v1 = fresh_fabric(0, "beta").await;
    let beta_addr_v1 = beta_v1.local_addr();
    alpha.add_peer(LoopbackPeerSpec {
        node_id: "beta".into(),
        addr: beta_addr_v1,
    });
    let ula_b: Ipv6Addr = "fd5a:1f00:0001:0000:0000:0000:0000:0003".parse().unwrap();
    let mut rx_v1 = beta_v1.register_local(ula_b, "ep-b".into()).await.unwrap();
    alpha.add_remote_route(ula_b, "beta".into());
    alpha.send(ula_b, b"first".to_vec()).await.unwrap();
    let (_, msg) = timeout(Duration::from_secs(2), rx_v1.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(msg, b"first");

    // Drop beta_v1 (closes listener + cached conn on alpha will break).
    drop(rx_v1);
    drop(beta_v1);

    // Spin up a fresh beta on a new port.
    let beta_v2 = fresh_fabric(0, "beta").await;
    let beta_addr_v2 = beta_v2.local_addr();
    let mut rx_v2 = beta_v2.register_local(ula_b, "ep-b".into()).await.unwrap();

    // Re-announce the peer (new address) — add_peer drops the cached
    // connection so the next send opens a fresh TCP stream.
    alpha.add_peer(LoopbackPeerSpec {
        node_id: "beta".into(),
        addr: beta_addr_v2,
    });
    // Give the background spawn a moment to drop the cached connection.
    tokio::time::sleep(Duration::from_millis(50)).await;

    alpha.send(ula_b, b"second".to_vec()).await.unwrap();
    let (_, msg) = timeout(Duration::from_secs(2), rx_v2.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(msg, b"second");
}

#[tokio::test]
async fn routing_snapshot_includes_remote_routes() {
    let alpha = fresh_fabric(0, "alpha").await;
    let ula_local: Ipv6Addr = "fd5a:1f00:0001:0000:0000:0000:0000:0010".parse().unwrap();
    let ula_remote: Ipv6Addr = "fd5a:1f00:0001:0000:0000:0000:0000:0011".parse().unwrap();
    let _rx = alpha
        .register_local(ula_local, "ep-local".into())
        .await
        .unwrap();
    alpha.add_remote_route(ula_remote, "beta".into());

    let snap = alpha.routing_snapshot();
    assert!(snap
        .local_endpoints
        .iter()
        .any(|(addr, id)| *addr == ula_local && id == "ep-local"));
    assert!(snap
        .remote_routes
        .iter()
        .any(|(addr, node)| *addr == ula_remote && node == "beta"));
}

#[tokio::test]
async fn oversized_payload_is_rejected_with_encoding_error() {
    let alpha = fresh_fabric(0, "alpha").await;
    alpha.add_peer(LoopbackPeerSpec {
        node_id: "beta".into(),
        addr: "127.0.0.1:1".parse().unwrap(),
    });
    let ula: Ipv6Addr = "fd5a:1f00:0001:0000:0000:0000:0000:0020".parse().unwrap();
    alpha.add_remote_route(ula, "beta".into());

    // 4 MiB exactly + 1 byte header puts us over MAX_FRAME_BODY.
    let huge = vec![0u8; 4 * 1024 * 1024];
    let err = alpha.send(ula, huge).await.unwrap_err();
    assert!(matches!(err, FabricError::Encoding(_)), "got: {err:?}");
}
