//! `FabricConn::connect_mtls_with_transport`（spec §7 additive）回归。
//!
//! 语义必须与 `connect_mtls` 相同（mTLS + allowlist + peer pin），只是保留
//! 调用方提供的 `UdpTransport`（cand.local_addr / proxy tier）。

use nexus_fabric::{ConnConfig, FabricConn, FabricIdentity, FabricListener, StdUdpTransport};
use std::time::Duration;

fn identity(seed: u8) -> FabricIdentity {
    FabricIdentity::from_ed25519_seed([seed; 32]).unwrap()
}

fn config(listener: &FabricListener) -> ConnConfig {
    ConnConfig {
        addrs: vec![listener.local_addr().unwrap()],
        handshake_timeout: Duration::from_millis(700),
    }
}

#[test]
fn mtls_over_caller_transport_authenticates_and_carries_datagrams() {
    let server = identity(21);
    let client = identity(22);
    let listener =
        FabricListener::bind_mtls("127.0.0.1:0".parse().unwrap(), &server, &[client.peer_id()])
            .unwrap();
    let transport = Box::new(StdUdpTransport::bind("127.0.0.1:0".parse().unwrap()).unwrap());
    let conn = FabricConn::connect_mtls_with_transport(
        server.peer_id(),
        &client,
        &config(&listener),
        transport,
    )
    .unwrap();
    let accepted = listener.accept_timeout(Duration::from_millis(700)).unwrap();

    assert_eq!(conn.mutually_authenticated_peer(), Some(server.peer_id()));
    assert_eq!(
        accepted.mutually_authenticated_peer(),
        Some(client.peer_id())
    );
    assert_eq!(accepted.peer(), client.peer_id());

    conn.send_datagram(b"mtls over caller transport").unwrap();
    assert_eq!(
        accepted.recv_datagram().unwrap(),
        b"mtls over caller transport"
    );

    conn.close(0, b"done");
    accepted.close(0, b"done");
}

#[test]
fn mtls_over_caller_transport_rejects_unlisted_identity() {
    let server = identity(23);
    let client = identity(24);
    let listener = FabricListener::bind_mtls(
        "127.0.0.1:0".parse().unwrap(),
        &server,
        &[identity(25).peer_id()],
    )
    .unwrap();
    let transport = Box::new(StdUdpTransport::bind("127.0.0.1:0".parse().unwrap()).unwrap());
    assert!(
        FabricConn::connect_mtls_with_transport(
            server.peer_id(),
            &client,
            &config(&listener),
            transport
        )
        .is_err()
    );
    // 未知/未授权客户端不会进入 accept 队列（TLS 层拒绝）。
    assert!(matches!(
        listener.accept_timeout(Duration::from_millis(60)),
        Err(nexus_fabric::FabricError::Timeout)
    ));
}
