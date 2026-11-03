//! 成功响应 MESSAGE-INTEGRITY 定位回归：
//! MI 不再假设「必须是报文最后一个属性」，按属性解析定位并容忍其后
//! 的 FINGERPRINT（RFC 5389 §15.4 / §15.5）；真 integrity 损坏仍 fail-closed。

mod common;

use common::{
    creds, recv_request, response, signed_response, spawn_server, ATTR_FINGERPRINT, NONCE1, REALM,
};
use nexus_turn::stun::{self, Attribute, ALLOCATE_FAILURE, ALLOCATE_REQUEST, ALLOCATE_SUCCESS};
use nexus_turn::TurnClient;

/// T2：MI 之后带 FINGERPRINT 的成功响应 → 验证通过（客户端容忍 MI 非末位）。
#[test]
fn success_response_with_fingerprint_after_mi_is_accepted() {
    let server = spawn_server(|sock| {
        let mut buf = vec![0u8; 4096];

        // 1) 401 质询。
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

        // 2) 认证 Allocate → 成功响应：MI 之后追加 FINGERPRINT。
        let (req, src) = recv_request(sock, &mut buf);
        assert_eq!(req.msg_type, ALLOCATE_REQUEST);
        assert_eq!(req.nonce_str(), Some(NONCE1));
        let bytes = signed_response(
            ALLOCATE_SUCCESS,
            req.txn,
            &[
                Attribute::XorRelayedAddress("127.0.0.1:49200".parse().unwrap()),
                Attribute::XorMappedAddress(src),
                Attribute::Lifetime(600),
            ],
            true,
            false,
        );
        // 自证向量形态：MI 不在末位，其后是 FINGERPRINT。
        let decoded = stun::decode(&bytes).expect("decode success response");
        let mi_off = decoded
            .mi_value_offset
            .expect("success response carries MI");
        assert!(
            matches!(
                decoded.attrs.last(),
                Some(Attribute::Unknown(ATTR_FINGERPRINT, _))
            ),
            "vector must end with FINGERPRINT after MI"
        );
        assert!(
            mi_off + 20 < decoded.consumed,
            "vector must not carry MI in the last position"
        );
        sock.send_to(&bytes, src).unwrap();

        Vec::new()
    });

    let client = TurnClient::allocate_bound(server.addr, creds(), "127.0.0.1:0".parse().unwrap())
        .expect("MI followed by FINGERPRINT must verify");
    assert_eq!(client.relayed_addr(), "127.0.0.1:49200".parse().unwrap());
    assert!(!client.is_expired());
    server.finish();
}

/// T3：MI 值被篡改 → 仍 fail-closed（integrity 错误，不静默接受）。
#[test]
fn tampered_mi_is_rejected_fail_closed() {
    let server = spawn_server(|sock| {
        let mut buf = vec![0u8; 4096];

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

        let (req, src) = recv_request(sock, &mut buf);
        assert_eq!(req.msg_type, ALLOCATE_REQUEST);
        let bytes = signed_response(
            ALLOCATE_SUCCESS,
            req.txn,
            &[
                Attribute::XorRelayedAddress("127.0.0.1:49200".parse().unwrap()),
                Attribute::XorMappedAddress(src),
                Attribute::Lifetime(600),
            ],
            false,
            true,
        );
        sock.send_to(&bytes, src).unwrap();
        Vec::new()
    });

    let err = match TurnClient::allocate_bound(server.addr, creds(), "127.0.0.1:0".parse().unwrap())
    {
        Ok(_) => panic!("tampered MI must not be accepted"),
        Err(e) => e,
    };
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    assert!(
        err.to_string().contains("integrity check failed"),
        "tampered MI must stay an integrity failure, got: {err}"
    );
    server.finish();
}
