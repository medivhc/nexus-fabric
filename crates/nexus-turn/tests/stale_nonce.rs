//! 438 (Stale Nonce) 恢复回归（RFC 8489 §9.2.4）。
//!
//! 服务端 nonce 过期时以 438 + 新 NONCE 应答，且该错误响应不带 MI。
//! 客户端必须：按 ERROR-CODE 分类 → 采纳新 nonce → 在同一事务内重试一次；
//! 持续 438 必须有界失败；事务不匹配响应携带的 nonce 不得采纳；
//! 其他错误码必须报出错误码本身（不再统一报 integrity failed）。

mod common;

use std::net::SocketAddr;

use common::{
    creds, expect_no_request, recv_request, response, signed_response, spawn_server, NONCE1,
    NONCE2, NONCE3, REALM,
};
use nexus_turn::stun::{
    Attribute, ALLOCATE_FAILURE, ALLOCATE_REQUEST, ALLOCATE_SUCCESS, REFRESH_FAILURE,
    REFRESH_REQUEST, REFRESH_SUCCESS,
};
use nexus_turn::TurnClient;

const RELAYED: &str = "127.0.0.1:49200";

fn relayed() -> SocketAddr {
    RELAYED.parse().unwrap()
}

/// T1：Refresh 命中 438（旧 nonce）→ 换响应携带的新 nonce 在同一事务内重试，
/// 最终成功；重试请求的 MI 必须按新 nonce 重新计算，且恢复不计失败。
#[test]
fn refresh_recovers_from_438_with_new_nonce_in_same_transaction() {
    let server = spawn_server(|sock| {
        let mut buf = vec![0u8; 4096];
        let mut seen = Vec::new();

        // 1) 未认证 Allocate → 401 质询（nonce1，无 MI）。
        let (req, src) = recv_request(sock, &mut buf);
        assert_eq!(req.msg_type, ALLOCATE_REQUEST);
        sock.send_to(
            &response(
                ALLOCATE_FAILURE,
                req.txn,
                &[
                    Attribute::ErrorCode(4, 1, b"Unauthorized".to_vec()),
                    Attribute::Realm(REALM.as_bytes().to_vec()),
                    Attribute::Nonce(NONCE1.as_bytes().to_vec()),
                ],
            ),
            src,
        )
        .unwrap();

        // 2) 认证 Allocate（nonce1）→ 成功（带 MI）。
        let (req, src) = recv_request(sock, &mut buf);
        assert_eq!(req.msg_type, ALLOCATE_REQUEST);
        assert_eq!(req.nonce_str(), Some(NONCE1));
        assert!(req.mi_valid(), "authenticated allocate must carry valid MI");
        sock.send_to(
            &signed_response(
                ALLOCATE_SUCCESS,
                req.txn,
                &[
                    Attribute::XorRelayedAddress(relayed()),
                    Attribute::XorMappedAddress(src),
                    Attribute::Lifetime(600),
                ],
                false,
                false,
            ),
            src,
        )
        .unwrap();

        // 3) Refresh（旧 nonce1）→ 438 + 新 nonce2（错误响应不带 MI）。
        let (req, src) = recv_request(sock, &mut buf);
        assert_eq!(req.msg_type, REFRESH_REQUEST);
        assert_eq!(req.nonce_str(), Some(NONCE1));
        let stale_txn = req.txn;
        seen.push(req);
        sock.send_to(
            &response(
                REFRESH_FAILURE,
                stale_txn,
                &[
                    Attribute::ErrorCode(4, 38, b"Stale Nonce".to_vec()),
                    Attribute::Nonce(NONCE2.as_bytes().to_vec()),
                ],
            ),
            src,
        )
        .unwrap();

        // 4) 同一事务内以 nonce2 重试 → 成功。
        let (req, src) = recv_request(sock, &mut buf);
        assert_eq!(req.msg_type, REFRESH_REQUEST);
        assert_eq!(
            req.nonce_str(),
            Some(NONCE2),
            "retry must adopt the NONCE from the 438 response"
        );
        assert_eq!(
            req.txn, stale_txn,
            "retry must stay in the same transaction"
        );
        assert!(
            req.mi_valid(),
            "retry MI must be recomputed with the new nonce"
        );
        seen.push(req);
        sock.send_to(
            &signed_response(
                REFRESH_SUCCESS,
                stale_txn,
                &[Attribute::Lifetime(600)],
                false,
                false,
            ),
            src,
        )
        .unwrap();

        seen
    });

    let client = TurnClient::allocate_bound(server.addr, creds(), "127.0.0.1:0".parse().unwrap())
        .expect("allocate before stale-nonce refresh");
    assert_eq!(client.relayed_addr(), relayed());

    client
        .refresh()
        .expect("438 must be recovered inside the transaction");

    let seen = server.finish();
    assert_eq!(
        seen.len(),
        2,
        "expected exactly the stale request + one retry"
    );
    let stats = client.stats();
    assert_eq!(stats.stale_nonce_retried, 1, "438 recovery must be counted");
    assert_eq!(
        stats.allocation_expired, 0,
        "a recovered 438 is not a refresh failure"
    );
    assert!(!client.is_expired());
}

/// T4：服务端持续回 438 → 重试有界（每个事务最多换一次 nonce），
/// 最终返回含错误码的明确错误，不得形成请求风暴。
#[test]
fn persistent_438_fails_after_one_bounded_retry() {
    let server = spawn_server(|sock| {
        let mut buf = vec![0u8; 4096];
        let mut seen = Vec::new();

        // 1) 401 质询。
        let (req, src) = recv_request(sock, &mut buf);
        sock.send_to(
            &response(
                ALLOCATE_FAILURE,
                req.txn,
                &[
                    Attribute::ErrorCode(4, 1, b"Unauthorized".to_vec()),
                    Attribute::Realm(REALM.as_bytes().to_vec()),
                    Attribute::Nonce(NONCE1.as_bytes().to_vec()),
                ],
            ),
            src,
        )
        .unwrap();

        // 2) Allocate 成功。
        let (req, src) = recv_request(sock, &mut buf);
        sock.send_to(
            &signed_response(
                ALLOCATE_SUCCESS,
                req.txn,
                &[
                    Attribute::XorRelayedAddress(relayed()),
                    Attribute::XorMappedAddress(src),
                    Attribute::Lifetime(600),
                ],
                false,
                false,
            ),
            src,
        )
        .unwrap();

        // 3) 第一次 Refresh → 438 nonce2。
        let (req, src) = recv_request(sock, &mut buf);
        assert_eq!(req.nonce_str(), Some(NONCE1));
        seen.push(req.clone());
        sock.send_to(
            &response(
                REFRESH_FAILURE,
                req.txn,
                &[
                    Attribute::ErrorCode(4, 38, b"Stale Nonce".to_vec()),
                    Attribute::Nonce(NONCE2.as_bytes().to_vec()),
                ],
            ),
            src,
        )
        .unwrap();

        // 4) 重试（nonce2）→ 仍然 438（nonce3）。客户端不得再重试。
        let (req, src) = recv_request(sock, &mut buf);
        assert_eq!(req.nonce_str(), Some(NONCE2));
        seen.push(req.clone());
        sock.send_to(
            &response(
                REFRESH_FAILURE,
                req.txn,
                &[
                    Attribute::ErrorCode(4, 38, b"Stale Nonce".to_vec()),
                    Attribute::Nonce(NONCE3.as_bytes().to_vec()),
                ],
            ),
            src,
        )
        .unwrap();

        // 5) 不得出现第三次 Refresh（有界性）。
        expect_no_request(sock);
        seen
    });

    let client = TurnClient::allocate_bound(server.addr, creds(), "127.0.0.1:0".parse().unwrap())
        .expect("allocate before stale-nonce refresh");

    let err = client.refresh().expect_err("persistent 438 must fail");
    let text = err.to_string();
    assert!(
        text.contains("438") && text.contains("Stale Nonce"),
        "error must carry the 438 code, got: {text}"
    );
    assert!(
        !text.contains("integrity"),
        "438 must not be reported as an integrity failure, got: {text}"
    );
    assert_eq!(
        client.stats().stale_nonce_retried,
        1,
        "only one recovery attempt"
    );

    let seen = server.finish();
    assert_eq!(
        seen.len(),
        2,
        "exactly one retry per transaction (no request storm): {seen:?}"
    );
}

/// T5：事务不匹配的响应携带 nonce → 不得采纳（沿用 txn 匹配机制）。
#[test]
fn nonce_from_foreign_transaction_is_not_adopted() {
    let server = spawn_server(|sock| {
        let mut buf = vec![0u8; 4096];
        let mut seen = Vec::new();

        // 1) 401 质询。
        let (req, src) = recv_request(sock, &mut buf);
        sock.send_to(
            &response(
                ALLOCATE_FAILURE,
                req.txn,
                &[
                    Attribute::ErrorCode(4, 1, b"Unauthorized".to_vec()),
                    Attribute::Realm(REALM.as_bytes().to_vec()),
                    Attribute::Nonce(NONCE1.as_bytes().to_vec()),
                ],
            ),
            src,
        )
        .unwrap();

        // 2) 认证 Allocate：先发一条 txn 不匹配的 438（携带伪造 nonce），
        //    再发真实 txn 的成功响应。客户端必须忽略前者。
        let (req, src) = recv_request(sock, &mut buf);
        assert_eq!(req.msg_type, ALLOCATE_REQUEST);
        assert_eq!(req.nonce_str(), Some(NONCE1));
        let mut foreign_txn = req.txn;
        foreign_txn[11] ^= 0xFF;
        sock.send_to(
            &response(
                ALLOCATE_FAILURE,
                foreign_txn,
                &[
                    Attribute::ErrorCode(4, 38, b"Stale Nonce".to_vec()),
                    Attribute::Nonce(b"foreign-nonce".to_vec()),
                ],
            ),
            src,
        )
        .unwrap();
        sock.send_to(
            &signed_response(
                ALLOCATE_SUCCESS,
                req.txn,
                &[
                    Attribute::XorRelayedAddress(relayed()),
                    Attribute::XorMappedAddress(src),
                    Attribute::Lifetime(600),
                ],
                false,
                false,
            ),
            src,
        )
        .unwrap();

        // 3) Refresh：nonce 必须还是 nonce1（未被外事务响应污染）。
        let (req, src) = recv_request(sock, &mut buf);
        assert_eq!(req.msg_type, REFRESH_REQUEST);
        seen.push(req.clone());
        sock.send_to(
            &signed_response(
                REFRESH_SUCCESS,
                req.txn,
                &[Attribute::Lifetime(600)],
                false,
                false,
            ),
            src,
        )
        .unwrap();
        seen
    });

    let client = TurnClient::allocate_bound(server.addr, creds(), "127.0.0.1:0".parse().unwrap())
        .expect("foreign-txn 438 must be ignored during allocate");
    assert_eq!(client.stats().stale_nonce_retried, 0);
    client.refresh().expect("refresh with the original nonce");

    let seen = server.finish();
    assert_eq!(seen.len(), 1);
    assert_eq!(
        seen[0].nonce_str(),
        Some(NONCE1),
        "nonce from a non-matching transaction must never be adopted"
    );
}

/// 其他错误码（437 Allocation Mismatch）→ 报出错误码与 reason，
/// 不再统一报 integrity failed；错误响应带 MI 也不影响分类。
#[test]
fn other_error_code_is_reported_explicitly() {
    let server = spawn_server(|sock| {
        let mut buf = vec![0u8; 4096];

        // 1) 401 质询。
        let (req, src) = recv_request(sock, &mut buf);
        sock.send_to(
            &response(
                ALLOCATE_FAILURE,
                req.txn,
                &[
                    Attribute::ErrorCode(4, 1, b"Unauthorized".to_vec()),
                    Attribute::Realm(REALM.as_bytes().to_vec()),
                    Attribute::Nonce(NONCE1.as_bytes().to_vec()),
                ],
            ),
            src,
        )
        .unwrap();

        // 2) Allocate 成功。
        let (req, src) = recv_request(sock, &mut buf);
        sock.send_to(
            &signed_response(
                ALLOCATE_SUCCESS,
                req.txn,
                &[
                    Attribute::XorRelayedAddress(relayed()),
                    Attribute::XorMappedAddress(src),
                    Attribute::Lifetime(600),
                ],
                false,
                false,
            ),
            src,
        )
        .unwrap();

        // 3) Refresh → 437（真实 server 会给已认证的错误响应带 MI）。
        let (req, src) = recv_request(sock, &mut buf);
        assert_eq!(req.msg_type, REFRESH_REQUEST);
        sock.send_to(
            &signed_response(
                REFRESH_FAILURE,
                req.txn,
                &[Attribute::ErrorCode(4, 37, b"Allocation Mismatch".to_vec())],
                false,
                false,
            ),
            src,
        )
        .unwrap();
        Vec::new()
    });

    let client = TurnClient::allocate_bound(server.addr, creds(), "127.0.0.1:0".parse().unwrap())
        .expect("allocate before 437");

    let err = client.refresh().expect_err("437 must fail the refresh");
    let text = err.to_string();
    assert!(
        text.contains("437") && text.contains("Allocation Mismatch"),
        "error must carry the error code and reason, got: {text}"
    );
    assert!(
        !text.contains("integrity"),
        "server error codes must not be reported as integrity failures, got: {text}"
    );
    assert!(
        client.is_expired(),
        "refresh failure keeps existing expiry semantics"
    );
    server.finish();
}
