//! 测试支持：剧本式 UDP TURN server。
//!
//! 每个测试自带脚本，逐条请求按需回包；响应字节由本模块独立构造
//! （MI 按 RFC 5389 §15.4 在测试内独立计算，不调用 `nexus_turn::auth`），
//! 因此覆盖的是「第三方 TURN server 形态」而非本仓 server 的编码约定。

#![allow(dead_code)]

use std::io::ErrorKind;
use std::net::{SocketAddr, UdpSocket};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use hmac::{Hmac, Mac};
use nexus_turn::stun::{self, Attribute, StunMessage};
use nexus_turn::TurnCredentials;
use sha1::Sha1;

pub const USER: &str = "alice";
pub const REALM: &str = "nexus";
pub const PASSWORD: &str = "secret";

pub const NONCE1: &str = "nexus-nonce-1";
pub const NONCE2: &str = "nexus-nonce-2";
pub const NONCE3: &str = "nexus-nonce-3";

/// FINGERPRINT 属性类型（RFC 5389 §15.5）。client 不校验其值，
/// 本 helper 只用于验证「MI 之后允许出现 FINGERPRINT」这一位置语义。
pub const ATTR_FINGERPRINT: u16 = 0x8028;

pub fn creds() -> TurnCredentials {
    TurnCredentials {
        username: USER.into(),
        password: PASSWORD.into(),
        realm: REALM.into(),
    }
}

pub fn key() -> [u8; 16] {
    md5::compute(format!("{USER}:{REALM}:{PASSWORD}").as_bytes()).0
}

/// 按 RFC 5389 §15.4 独立计算 MI：`HMAC-SHA1(key, datagram[..MI 属性偏移])`，
/// 头 length 字段改写为 `(mi_attr_offset - 20) + 24`（只计入到 MI 为止）。
pub fn rfc5389_tag(datagram: &[u8], mi_value_offset: usize) -> [u8; 20] {
    let mi_attr_offset = mi_value_offset - 4;
    let adjusted_len = (mi_attr_offset - 20 + 24) as u16;
    let mut input = datagram[..mi_attr_offset].to_vec();
    input[2..4].copy_from_slice(&adjusted_len.to_be_bytes());
    let mut mac = Hmac::<Sha1>::new_from_slice(&key()).expect("hmac accepts any key length");
    mac.update(&input);
    mac.finalize().into_bytes().into()
}

/// 无 MI 响应（401 质询 / 438 等错误响应的形态）。
pub fn response(msg_type: u16, txn: [u8; 12], attrs: &[Attribute]) -> Vec<u8> {
    StunMessage {
        msg_type,
        txn,
        attrs: attrs.to_vec(),
    }
    .encode()
}

/// 带 MI 的成功响应；`fingerprint` 在 MI 之后追加 FINGERPRINT 属性，
/// `tamper` 翻转 MI 首字节（真 integrity 损坏向量）。
pub fn signed_response(
    msg_type: u16,
    txn: [u8; 12],
    attrs: &[Attribute],
    fingerprint: bool,
    tamper: bool,
) -> Vec<u8> {
    let mut msg = StunMessage {
        msg_type,
        txn,
        attrs: attrs.to_vec(),
    };
    msg.attrs.push(Attribute::MessageIntegrity([0u8; 20]));
    if fingerprint {
        msg.attrs
            .push(Attribute::Unknown(ATTR_FINGERPRINT, vec![0, 0, 0, 0]));
    }
    let mut bytes = msg.encode();
    let decoded = stun::decode(&bytes).expect("decode signed response");
    let mi_off = decoded.mi_value_offset.expect("signed response carries MI");
    let tag = rfc5389_tag(&bytes, mi_off);
    bytes[mi_off..mi_off + 20].copy_from_slice(&tag);
    if tamper {
        bytes[mi_off] ^= 0xFF;
    }
    bytes
}

/// 观察到的请求（scripted server 侧记录）。
#[derive(Clone, Debug)]
pub struct Observed {
    pub msg_type: u16,
    pub txn: [u8; 12],
    pub raw: Vec<u8>,
    pub nonce: Option<Vec<u8>>,
    pub mi_value_offset: Option<usize>,
}

impl Observed {
    pub fn nonce_str(&self) -> Option<&str> {
        self.nonce
            .as_deref()
            .and_then(|n| std::str::from_utf8(n).ok())
    }

    /// 请求携带的 MI 是否按 RFC 5389 §15.4 正确盖章。
    pub fn mi_valid(&self) -> bool {
        match self.mi_value_offset {
            Some(off) if self.raw.len() >= off + 20 => {
                self.raw[off..off + 20] == rfc5389_tag(&self.raw, off)
            }
            _ => false,
        }
    }
}

/// 接收一条请求（超时 → panic，说明客户端没有按剧本发请求）。
pub fn recv_request(sock: &UdpSocket, buf: &mut [u8]) -> (Observed, SocketAddr) {
    let (n, src) = sock
        .recv_from(buf)
        .expect("scripted server: expected request");
    let raw = buf[..n].to_vec();
    let decoded = stun::decode(&raw).expect("scripted server: decode request");
    let nonce = match decoded.get(stun::ATTR_NONCE) {
        Some(Attribute::Nonce(v)) => Some(v.clone()),
        _ => None,
    };
    let observed = Observed {
        msg_type: decoded.msg_type,
        txn: decoded.txn,
        raw,
        nonce,
        mi_value_offset: decoded.mi_value_offset,
    };
    (observed, src)
}

/// 断言脚本期内不再有请求到达（证明重试有界 / 未无限循环）。
pub fn expect_no_request(sock: &UdpSocket) {
    let mut buf = [0u8; 2048];
    sock.set_read_timeout(Some(Duration::from_millis(300)))
        .expect("set read timeout");
    match sock.recv_from(&mut buf) {
        Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {}
        other => panic!("expected no further request, got {other:?}"),
    }
}

/// 在 127.0.0.1:0 上起一个剧本式 server，返回 (地址, join 句柄)。
pub struct ScriptedServer {
    pub addr: SocketAddr,
    handle: Option<JoinHandle<Vec<Observed>>>,
}

pub fn spawn_server<F>(script: F) -> ScriptedServer
where
    F: FnOnce(&UdpSocket) -> Vec<Observed> + Send + 'static,
{
    let sock = UdpSocket::bind("127.0.0.1:0").expect("scripted server bind");
    sock.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("scripted server read timeout");
    let addr = sock.local_addr().expect("scripted server addr");
    let handle = thread::spawn(move || script(&sock));
    ScriptedServer {
        addr,
        handle: Some(handle),
    }
}

impl ScriptedServer {
    /// 等剧本跑完并取回观察到的请求序列。
    pub fn finish(mut self) -> Vec<Observed> {
        self.handle
            .take()
            .expect("scripted server handle")
            .join()
            .expect("scripted server script panicked")
    }
}
