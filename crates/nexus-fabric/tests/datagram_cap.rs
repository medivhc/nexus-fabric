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

use nexus_fabric::{
    CONSERVATIVE_DATAGRAM_CAP, ConnConfig, FabricConn, FabricError, FabricIdentity, FabricListener,
};
use std::time::{Duration, Instant};

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

/// 轮询到驱动线程首次采样（握手完成后最多一个 pump 周期）。
fn wait_for_cap(conn: &FabricConn) -> usize {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if let Some(cap) = conn.datagram_cap() {
            return cap;
        }
        assert!(Instant::now() < deadline, "datagram_cap() stayed None");
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// 对账：驱动采样的 quinn 真值必须等于我方保守常量（防 formula 漂移）。
#[test]
fn effective_cap_matches_quinn() {
    let (conn, accepted) = mtls_pair(3, 4);
    assert_eq!(wait_for_cap(&conn), CONSERVATIVE_DATAGRAM_CAP);
    assert_eq!(
        wait_for_cap(&accepted),
        CONSERVATIVE_DATAGRAM_CAP,
        "both ends of this repo's fabric assemble the same cap"
    );
    conn.close(0, b"done");
    accepted.close(0, b"done");
}

/// 1162/1163 边界：1162 发出且对端收到 1162；1163 同步 typed 拒绝，
/// 且对端只收到后续 marker（不是"Ok 但没发出"）。
#[test]
fn cap_boundary_is_1162_and_1163_is_rejected() {
    let (conn, accepted) = mtls_pair(5, 6);
    let cap = wait_for_cap(&conn);
    assert_eq!(cap, 1162);

    conn.send_datagram(&vec![0u8; cap]).expect("cap bytes fit");
    let too_big = conn.send_datagram(&vec![0u8; cap + 1]);
    assert!(
        matches!(
            too_big,
            Err(FabricError::DatagramTooLarge { len, cap: c }) if len == cap + 1 && c == cap
        ),
        "expected DatagramTooLarge{{len:{}, cap:{cap}}}, got {too_big:?}",
        cap + 1
    );
    conn.send_datagram(b"marker").unwrap();

    assert_eq!(
        accepted.recv_datagram().unwrap().len(),
        cap,
        "the max-size datagram must arrive whole"
    );
    assert_eq!(
        accepted.recv_datagram().unwrap(),
        b"marker",
        "the rejected datagram must never appear on the wire"
    );

    let deadline = Instant::now() + Duration::from_secs(2);
    while conn.stats().datagram_rejected != 1 {
        assert!(
            Instant::now() < deadline,
            "datagram_rejected never reached 1 (got {})",
            conn.stats().datagram_rejected
        );
        std::thread::sleep(Duration::from_millis(5));
    }

    conn.close(0, b"done");
    accepted.close(0, b"done");
}

/// QSEQ 对齐：上限是 `cap − 8`；超限不发、不烧序号。
#[test]
fn seqed_limit_is_cap_minus_header() {
    let (conn, accepted) = mtls_pair(7, 8);
    let cap = wait_for_cap(&conn);
    let limit = cap - 8;
    assert_eq!(limit, 1154);

    assert_eq!(
        conn.send_datagram_seqed(&vec![0u8; limit]).unwrap(),
        0,
        "cap − 8 fits and takes sequence 0"
    );
    let too_big = conn.send_datagram_seqed(&vec![0u8; limit + 1]);
    assert!(
        matches!(
            too_big,
            Err(FabricError::DatagramTooLarge { len, cap: c }) if len == limit + 1 && c == limit
        ),
        "expected DatagramTooLarge{{len:{}, cap:{limit}}}, got {too_big:?}",
        limit + 1
    );
    assert_eq!(
        conn.send_datagram_seqed(b"x").unwrap(),
        1,
        "a rejected seqed send must not consume a sequence number"
    );

    conn.close(0, b"done");
    accepted.close(0, b"done");
}
