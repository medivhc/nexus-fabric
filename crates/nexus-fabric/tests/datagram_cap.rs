//! N1 datagram 有效上限的端到端证据（E3：真实 mTLS + 真实 quinn 连接）。
//!
//! 背景（诊断 run `n1-sender-send-path-diagnosis`）：fabric 各层曾各自按裸
//! `1200` 判定，而 quinn 在本仓库装配下的真实 `datagrams().max_size()` 是
//! `1200 − 29 − 9 = 1162`；1163..1200 的 datagram 因此被 quinn 在 flush 点
//! 静默丢弃（`Err(_) => {}`），上层却记成"已发送"。
//!
//! 本文件锁定的行为：
//! - 1200B 必须被**显式拒绝**（不再是"Ok 但没发出"）；
//! - 1162B 可以发出并被对端收到；
//! - 1163B 返回 `DatagramTooLarge{len, cap}` 且对端只收到后续 marker。

use nexus_fabric::{ConnConfig, FabricConn, FabricError, FabricIdentity, FabricListener};
use std::time::Duration;

fn identity(seed: u8) -> FabricIdentity {
    FabricIdentity::from_ed25519_seed([seed; 32]).unwrap()
}

/// 真实 mTLS 配对（与 `tests/mutual_auth.rs` 同写法）。
fn mtls_pair(client_seed: u8, server_seed: u8) -> (FabricConn, FabricConn) {
    let server = identity(server_seed);
    let client = identity(client_seed);
    let listener =
        FabricListener::bind_mtls("127.0.0.1:0".parse().unwrap(), &server, &[client.peer_id()])
            .unwrap();
    let config = ConnConfig {
        addrs: vec![listener.local_addr().unwrap()],
        handshake_timeout: Duration::from_millis(700),
    };
    let conn = FabricConn::connect_mtls(server.peer_id(), &client, &config).unwrap();
    let accepted = listener.accept_timeout(Duration::from_millis(700)).unwrap();
    (conn, accepted)
}

/// 本 run 的主 Red：1200B 的 datagram 必须被显式拒绝。
///
/// 在当前 HEAD 上必红：`send_datagram(1200)` 返回 `Ok(())`，包被 quinn 在
/// flush 点按 `TooLarge` 丢弃，对端只收到 marker。
#[test]
fn silent_drop_of_1200b_datagram_is_gone() {
    let (conn, accepted) = mtls_pair(1, 2);

    let res = conn.send_datagram(&vec![0u8; 1200]);
    conn.send_datagram(b"marker").unwrap();
    assert_eq!(accepted.recv_datagram().unwrap(), b"marker");
    assert!(
        res.is_err(),
        "1200B must be rejected explicitly, not silently dropped by quinn"
    );

    conn.close(0, b"done");
    accepted.close(0, b"done");
}
