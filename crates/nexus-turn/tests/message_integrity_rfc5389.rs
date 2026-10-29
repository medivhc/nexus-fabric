//! RFC 5389 §15.4 MESSAGE-INTEGRITY 互操作回归（server 侧）：
//! 测试内独立构造带 MI 的 Allocate 请求（不调用 `nexus-turn` 的 auth 实现），
//! 断言 `TurnServer` 接受（修复前恒 401），并独立校验成功响应的 MI。

use std::net::UdpSocket;
use std::time::Duration;

use hmac::{Hmac, Mac};
use nexus_turn::stun::{self, Attribute, StunMessage, ALLOCATE_REQUEST, ALLOCATE_SUCCESS};
use nexus_turn::{TurnCredentials, TurnServer};
use sha1::Sha1;

const USER: &str = "alice";
const REALM: &str = "nexus";
const PASSWORD: &str = "secret";

fn key() -> [u8; 16] {
    md5::compute(format!("{USER}:{REALM}:{PASSWORD}").as_bytes()).0
}

/// 按 RFC 5389 §15.4 独立计算 MI：`HMAC-SHA1(key, datagram[..MI 属性偏移])`，
/// 其中头 length 字段改写为 `(mi_attr_offset - 20) + 24`。
fn rfc5389_tag(datagram: &[u8], mi_value_offset: usize) -> [u8; 20] {
    let mi_attr_offset = mi_value_offset - 4;
    let adjusted_len = (mi_attr_offset - 20 + 24) as u16;
    let mut input = datagram[..mi_attr_offset].to_vec();
    input[2..4].copy_from_slice(&adjusted_len.to_be_bytes());
    let mut mac = Hmac::<Sha1>::new_from_slice(&key()).expect("hmac accepts any key length");
    mac.update(&input);
    mac.finalize().into_bytes().into()
}

fn recv(sock: &UdpSocket, buf: &mut [u8]) -> usize {
    sock.set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set read timeout");
    sock.recv(buf).expect("server response")
}

#[test]
fn server_accepts_rfc5389_message_integrity() {
    let server = TurnServer::bind(
        "127.0.0.1:0".parse().unwrap(),
        TurnCredentials {
            username: USER.into(),
            password: PASSWORD.into(),
            realm: REALM.into(),
        },
    )
    .expect("turn server bind");
    let sock = UdpSocket::bind("127.0.0.1:0").expect("client bind");
    sock.connect(server.main_addr()).expect("connect");
    let mut buf = [0u8; 2048];

    // 1) 无认证首轮 → 401 质询，取 REALM/NONCE。
    let probe = StunMessage::new(ALLOCATE_REQUEST).attr(Attribute::RequestedTransport(17));
    sock.send(&probe.encode()).expect("send probe");
    let n = recv(&sock, &mut buf);
    let challenge = stun::decode(&buf[..n]).expect("decode 401");
    let nonce = match challenge.get(stun::ATTR_NONCE) {
        Some(Attribute::Nonce(v)) => v.clone(),
        other => panic!("401 without NONCE: {other:?}"),
    };
    let realm = match challenge.get(stun::ATTR_REALM) {
        Some(Attribute::Realm(v)) => v.clone(),
        other => panic!("401 without REALM: {other:?}"),
    };

    // 2) 按 RFC 形式构造认证 Allocate（MI 由测试独立计算，不调用被测 stamp）。
    let mut req = StunMessage::new(ALLOCATE_REQUEST)
        .attr(Attribute::RequestedTransport(17))
        .attr(Attribute::Username(USER.as_bytes().to_vec()))
        .attr(Attribute::Realm(realm))
        .attr(Attribute::Nonce(nonce))
        .attr(Attribute::MessageIntegrity([0u8; 20]));
    req.txn = probe.txn;
    let mut bytes = req.encode();
    let mi_off = bytes.len() - 20;
    let tag = rfc5389_tag(&bytes, mi_off);
    bytes[mi_off..mi_off + 20].copy_from_slice(&tag);
    sock.send(&bytes).expect("send authenticated allocate");

    // 3) 必须得到 ALLOCATE_SUCCESS（修复前 server 侧整包清零 HMAC，恒 401）。
    let n = recv(&sock, &mut buf);
    let resp = stun::decode(&buf[..n]).expect("decode allocate response");
    assert_eq!(
        resp.msg_type, ALLOCATE_SUCCESS,
        "RFC 5389 形式 MI 不得被 401 拒绝"
    );

    // 4) 独立校验 server 侧成功响应 MI（stamp 方向同样符合 RFC）。
    let resp_mi = resp.mi_value_offset.expect("success response carries MI");
    assert_eq!(
        &buf[resp_mi..resp_mi + 20],
        &rfc5389_tag(&buf[..resp.consumed], resp_mi),
        "server 响应 MI 必须按 RFC 5389 §15.4 计算"
    );
}
