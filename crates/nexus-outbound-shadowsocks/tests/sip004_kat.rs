//! SIP004 全流金样与负向测试。
//!
//! 期望字节来自 `tests/kat/generate_kat.py`（独立 Python `cryptography` 实现，
//! 不 import 本 crate；HKDF-SHA1 另经 RFC 5869 A.4 自检）。fixture 的 sha256 见
//! `tests/kat/README.md`。KAT-3 线长算术（16590 / 首 chunk 末 16449）也在本文件钉死。

use nexus_outbound_shadowsocks::{
    OutboundCipherError, Role, SsMethod, SsStream, SsTarget, encode_request,
};

const PW: &str = "ss-kat-password-3";
const KAT3_SALT: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];
const KAT4_SALT: [u8; 32] = [
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
];

const KAT3_WIRE: &[u8] = include_bytes!("fixtures/kat3_client_wire.bin");
const KAT4_WIRE: &[u8] = include_bytes!("fixtures/kat4_server_wire.bin");
const NEG_LEN_0X4000: &[u8] = include_bytes!("fixtures/kat_neg_len_0x4000.bin");
const NEG_LEN_0: &[u8] = include_bytes!("fixtures/kat_neg_len_0.bin");

const PAYLOAD_LEN: usize = 0x3FFF + 100;

fn plaintext() -> Vec<u8> {
    let mut out = encode_request(&SsTarget::Ipv4([1, 2, 3, 4], 8388));
    assert_eq!(out.len(), 7);
    out.extend((0..PAYLOAD_LEN).map(|i| ((i * 31 + 7) % 251) as u8));
    out
}

fn client() -> SsStream {
    SsStream::with_tx_salt(PW, SsMethod::Chacha20IetfPoly1305, Role::Client, KAT3_SALT).unwrap()
}

fn rx() -> SsStream {
    SsStream::new(PW, SsMethod::Chacha20IetfPoly1305, Role::Server).unwrap()
}

#[test]
fn kat3_client_wire_matches_independent_fixture() {
    let plain = plaintext();
    assert_eq!(plain.len(), 16490);
    let wire = client().seal(&plain).unwrap();
    // 线长自检（spec §1.2）：32 + 18 + 16399 + 18 + 123。
    assert_eq!(wire.len(), 16590);
    assert_eq!(&wire[..32], &KAT3_SALT);
    assert_eq!(wire, KAT3_WIRE, "KAT-3 线字节与独立 fixture 不一致");
}

#[test]
fn kat3_first_chunk_ends_at_16449() {
    let mut rx = rx();
    let first = rx.open(&KAT3_WIRE[..16449]).unwrap();
    assert_eq!(first.len(), 16383);
    assert_eq!(first, plaintext()[..16383]);
    let second = rx.open(&KAT3_WIRE[16449..]).unwrap();
    assert_eq!(second, plaintext()[16383..]);
}

#[test]
fn kat4_server_wire_decodes_under_three_feed_patterns() {
    let expected = plaintext();
    assert_eq!(&KAT4_WIRE[..32], &KAT4_SALT);

    // (1) 整段
    let mut a = rx();
    assert_eq!(a.open(KAT4_WIRE).unwrap(), expected);

    // (2) 逐字节
    let mut b = rx();
    let mut got = Vec::new();
    for byte in KAT4_WIRE {
        got.extend(b.open(std::slice::from_ref(byte)).unwrap());
    }
    assert_eq!(got, expected);

    // (3) 7B 步长
    let mut c = rx();
    let mut got = Vec::new();
    for chunk in KAT4_WIRE.chunks(7) {
        got.extend(c.open(chunk).unwrap());
    }
    assert_eq!(got, expected);
}

#[test]
fn kat4_decoded_plaintext_starts_with_complete_request_header() {
    let mut rx = rx();
    let plain = rx.open(KAT4_WIRE).unwrap();
    let target = nexus_outbound_shadowsocks::parse_request(&plain[..7]).unwrap();
    assert_eq!(target, SsTarget::Ipv4([1, 2, 3, 4], 8388));
}

#[test]
fn negative_wrong_password_is_decrypt_failed() {
    let wire = client().seal(&plaintext()).unwrap();
    let mut wrong = SsStream::new(
        "wrong-password",
        SsMethod::Chacha20IetfPoly1305,
        Role::Server,
    )
    .unwrap();
    assert!(matches!(
        wrong.open(&wire).unwrap_err(),
        OutboundCipherError::DecryptFailed
    ));
}

#[test]
fn negative_tampered_len_chunk_is_decrypt_failed() {
    let mut wire = KAT3_WIRE.to_vec();
    wire[35] ^= 0x01; // salt(32) + len chunk ct 内
    assert!(matches!(
        rx().open(&wire).unwrap_err(),
        OutboundCipherError::DecryptFailed
    ));
}

#[test]
fn negative_tampered_payload_chunk_is_decrypt_failed() {
    let mut wire = KAT3_WIRE.to_vec();
    wire[60] ^= 0x01; // salt(32) + len chunk(18) + payload ct 内
    assert!(matches!(
        rx().open(&wire).unwrap_err(),
        OutboundCipherError::DecryptFailed
    ));
}

#[test]
fn negative_decrypted_len_0x4000_is_invalid_frame() {
    assert!(matches!(
        rx().open(NEG_LEN_0X4000).unwrap_err(),
        OutboundCipherError::InvalidFrame
    ));
}

#[test]
fn negative_decrypted_len_0_is_invalid_frame() {
    assert!(matches!(
        rx().open(NEG_LEN_0).unwrap_err(),
        OutboundCipherError::InvalidFrame
    ));
}

#[test]
fn negative_31_byte_salt_prefix_is_ok_empty() {
    assert!(rx().open(&KAT3_WIRE[..31]).unwrap().is_empty());
}

#[test]
fn negative_truncated_then_forged_bytes_never_emit_chunk2() {
    let mut rx = rx();
    assert_eq!(rx.open(&KAT3_WIRE[..16449]).unwrap().len(), 16383);
    // 伪造的第二段 len chunk（32B：18B len 密文 + 多余字节）必须解密失败。
    assert!(matches!(
        rx.open(&[0xAA; 32]).unwrap_err(),
        OutboundCipherError::DecryptFailed
    ));
    // poisoned：后续即使喂入真实尾段也不得产出明文。
    assert!(matches!(
        rx.open(&KAT3_WIRE[16449..]).unwrap_err(),
        OutboundCipherError::DecryptFailed
    ));
}

#[test]
fn poisoned_stream_returns_same_variant() {
    let mut rx = rx();
    assert!(matches!(
        rx.open(NEG_LEN_0X4000).unwrap_err(),
        OutboundCipherError::InvalidFrame
    ));
    assert!(matches!(
        rx.open(KAT3_WIRE).unwrap_err(),
        OutboundCipherError::InvalidFrame
    ));
}
