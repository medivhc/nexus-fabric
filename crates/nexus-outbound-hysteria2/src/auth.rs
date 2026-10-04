//! Hysteria2 最小 HTTP/3 认证（文档 §2.1/§3.1）。
//!
//! 客户端在 QUIC 建连后：
//!
//! 1. 在单向控制流（client 首个 uni stream，id 2）上发空 SETTINGS：
//!    `[0x00, 0x04, 0x00]`（流类型 0=control + SETTINGS 帧类型 0x04 + 长度 0；
//!    空 SETTINGS，QPACK 动态表保持禁用）。
//! 2. 在 stream 0 上发 HEADERS 帧（`0x01` + varint 长度 + QPACK 块），7 个头：
//!    `:method/:scheme/:authority/:path` + `hysteria-auth/hysteria-cc-rx/hysteria-padding`。
//! 3. 读回响应 HEADERS：`:status == 233` 才算成功；解析 `hysteria-udp` 与
//!    `hysteria-cc-rx`。
//!
//! 注意：
//!
//! - 头字段名在线上用全小写（HTTP/3 要求）；文档表格中的 `Hysteria-Auth` 等
//!   大小写形式是逻辑名，线格式为 `hysteria-auth`。
//! - `:authority` 的值按文档取字面量 `"hysteria"`（非 server host）。
//! - 认证之后代理走裸 QUIC stream/datagram，不再使用 H3（文档 §2.1(5)）。

use super::Hysteria2Error;
use super::qpack;
use super::varint;

/// 认证控制流上发送的空 SETTINGS（流类型 0 + SETTINGS 帧 + 长度 0）。
pub const SETTINGS_FRAME: [u8; 3] = [0x00, 0x04, 0x00];

/// HTTP/3 HEADERS 帧类型。
pub const HEADERS_FRAME_TYPE: u8 = 0x01;

/// 认证成功的状态码（`233 HyOK`）。
pub const AUTH_STATUS_OK: &str = "233";

/// `Hysteria-Padding` 随机串长度范围（文档：256~2048 字节 `[a-zA-Z0-9]`）。
const PADDING_MIN: usize = 256;
const PADDING_MAX: usize = 2048;

/// 服务端返回的拥塞控制协商值（文档 §4）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CcRx {
    /// `0`：无限制，client 可任意速率发送。
    Unlimited,
    /// `"auto"`（或缺省）：server 不提供数值，client 必须用拥塞控制算法自适应。
    Auto,
    /// 具体字节/秒上限。
    Bps(u64),
}

impl CcRx {
    /// 解析 `hysteria-cc-rx` 响应值。缺省视为 [`CcRx::Auto`]（server 未提供数值
    /// 时 client 用拥塞控制算法自适应；// 未确认：文档未明确缺省语义，按最接近
    /// 的 "auto" 语义处理）。
    pub fn parse(value: Option<&str>) -> Self {
        match value {
            None => Self::Auto,
            Some("auto") => Self::Auto,
            Some("0") => Self::Unlimited,
            Some(v) => v.parse::<u64>().map(Self::Bps).unwrap_or(Self::Auto),
        }
    }
}

/// 认证响应（已校验）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthResponse {
    /// 是否启用 UDP（`hysteria-udp: true`）。
    pub udp_enabled: bool,
    /// 服务端 `hysteria-cc-rx` 协商值。
    pub cc_rx: CcRx,
}

/// 生成 `Hysteria-Padding` 随机串（256~2048 字节 `[a-zA-Z0-9]`，仅混淆）。
fn random_padding() -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut len_bytes = [0u8; 8];
    ring_rand_fill(&mut len_bytes);
    let len =
        PADDING_MIN + (u64::from_le_bytes(len_bytes) as usize % (PADDING_MAX - PADDING_MIN + 1));
    let mut raw = vec![0u8; len];
    ring_rand_fill(&mut raw);
    raw.iter()
        .map(|b| ALPHABET[(b % 62) as usize] as char)
        .collect()
}

fn ring_rand_fill(buf: &mut [u8]) {
    use ring::rand::{SecureRandom, SystemRandom};
    SystemRandom::new().fill(buf).expect("system RNG failure");
}

/// 构造认证请求：HEADERS 帧（`0x01` + varint 长度 + QPACK 块），含文档列出的
/// 7 个头。
///
/// `cc_rx_bps`: 客户端最大接收速率（bytes/s），`0` = 未知。
#[must_use]
pub fn build_auth_request(password: &str, cc_rx_bps: u64, authority: &str) -> Vec<u8> {
    let padding = random_padding();
    let cc_rx = cc_rx_bps.to_string();
    let headers = [
        (":method", "POST"),
        (":scheme", "https"),
        (":authority", authority),
        (":path", "/auth"),
        ("hysteria-auth", password),
        ("hysteria-cc-rx", cc_rx.as_str()),
        ("hysteria-padding", padding.as_str()),
    ];
    let block = qpack::encode_field_section(&headers);
    let mut frame = Vec::with_capacity(2 + block.len());
    frame.push(HEADERS_FRAME_TYPE);
    varint::encode(block.len() as u64, &mut frame);
    frame.extend_from_slice(&block);
    frame
}

/// 构造认证响应 HEADERS 帧（测试用最小 server；线上 server 行为以官方为准）。
#[must_use]
pub fn build_auth_response(status: &str, udp_enabled: bool, cc_rx: &str) -> Vec<u8> {
    let udp = if udp_enabled { "true" } else { "false" };
    let headers = [
        (":status", status),
        ("hysteria-udp", udp),
        ("hysteria-cc-rx", cc_rx),
    ];
    let block = qpack::encode_field_section(&headers);
    let mut frame = Vec::with_capacity(2 + block.len());
    frame.push(HEADERS_FRAME_TYPE);
    varint::encode(block.len() as u64, &mut frame);
    frame.extend_from_slice(&block);
    frame
}

/// 解析认证响应 HEADERS 帧（完整帧：`0x01` + varint 长度 + QPACK 块）。
///
/// 校验规则（文档 §5 坑 #2）：
/// - 首帧类型必须为 HEADERS（`0x01`）；DATA 先于 HEADERS 等一律拒绝；
/// - `:status == "233"` 否则 [`Hysteria2Error::AuthFailed`]；
/// - `hysteria-udp` 缺失或非法 → [`Hysteria2Error::InvalidFrame`]（文档 §3.1
///   要求响应至少包含该头）。
///
/// # Errors
///
/// 帧非法 → [`Hysteria2Error::InvalidFrame`]；认证失败 → [`Hysteria2Error::AuthFailed`]。
pub fn decode_auth_response(frame: &[u8]) -> Result<AuthResponse, Hysteria2Error> {
    let frame_type = *frame.first().ok_or(Hysteria2Error::InvalidFrame)?;
    if frame_type != HEADERS_FRAME_TYPE {
        return Err(Hysteria2Error::InvalidFrame);
    }
    let (len, n) = varint::decode(&frame[1..])?;
    let len = usize::try_from(len).map_err(|_| Hysteria2Error::InvalidFrame)?;
    let block = frame
        .get(1 + n..1 + n + len)
        .ok_or(Hysteria2Error::InvalidFrame)?;
    let headers = qpack::decode_field_section(block)?;
    let mut status: Option<&str> = None;
    let mut udp: Option<&str> = None;
    let mut cc_rx: Option<&str> = None;
    for (name, value) in &headers {
        match name.as_str() {
            ":status" => status = Some(value),
            "hysteria-udp" => udp = Some(value),
            "hysteria-cc-rx" => cc_rx = Some(value),
            _ => {}
        }
    }
    if status != Some(AUTH_STATUS_OK) {
        return Err(Hysteria2Error::AuthFailed);
    }
    let udp_enabled = match udp {
        Some("true") => true,
        Some("false") => false,
        _ => return Err(Hysteria2Error::InvalidFrame),
    };
    Ok(AuthResponse {
        udp_enabled,
        cc_rx: CcRx::parse(cc_rx),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 从请求帧中剥出 QPACK 块并解码，返回头列表（测试辅助）。
    fn decode_request_headers(frame: &[u8]) -> Vec<(String, String)> {
        assert_eq!(frame[0], HEADERS_FRAME_TYPE);
        let (len, n) = varint::decode(&frame[1..]).unwrap();
        let len = len as usize;
        qpack::decode_field_section(&frame[1 + n..1 + n + len]).unwrap()
    }

    #[test]
    fn auth_request_has_all_seven_headers() {
        let frame = build_auth_request("test-password", 1_250_000, "hysteria");
        let headers = decode_request_headers(&frame);
        assert_eq!(headers.len(), 7);
        let get = |name: &str| {
            headers
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.as_str())
        };
        assert_eq!(get(":method"), Some("POST"));
        assert_eq!(get(":scheme"), Some("https"));
        assert_eq!(get(":authority"), Some("hysteria"));
        assert_eq!(get(":path"), Some("/auth"));
        assert_eq!(get("hysteria-auth"), Some("test-password"));
        assert_eq!(get("hysteria-cc-rx"), Some("1250000"));
        // Padding：256~2048 字节 [a-zA-Z0-9]。
        let padding = get("hysteria-padding").unwrap();
        assert!((PADDING_MIN..=PADDING_MAX).contains(&padding.len()));
        assert!(
            padding.bytes().all(|b| b.is_ascii_alphanumeric()),
            "padding must be [a-zA-Z0-9]"
        );
    }

    #[test]
    fn auth_request_cc_rx_zero_means_unknown() {
        let frame = build_auth_request("pw", 0, "hysteria");
        let headers = decode_request_headers(&frame);
        let cc_rx = headers
            .iter()
            .find(|(k, _)| k == "hysteria-cc-rx")
            .map(|(_, v)| v.as_str());
        assert_eq!(cc_rx, Some("0"));
    }

    #[test]
    fn auth_response_233_ok() {
        let frame = build_auth_response("233", true, "0");
        let resp = decode_auth_response(&frame).unwrap();
        assert!(resp.udp_enabled);
        assert_eq!(resp.cc_rx, CcRx::Unlimited);

        let frame = build_auth_response("233", false, "auto");
        let resp = decode_auth_response(&frame).unwrap();
        assert!(!resp.udp_enabled);
        assert_eq!(resp.cc_rx, CcRx::Auto);

        let frame = build_auth_response("233", true, "1048576");
        let resp = decode_auth_response(&frame).unwrap();
        assert_eq!(resp.cc_rx, CcRx::Bps(1_048_576));
    }

    #[test]
    fn auth_response_non_233_rejected() {
        for status in ["200", "403", "404", "500"] {
            let frame = build_auth_response(status, true, "0");
            assert_eq!(
                decode_auth_response(&frame),
                Err(Hysteria2Error::AuthFailed),
                "status {status} must fail auth"
            );
        }
    }

    #[test]
    fn auth_response_data_frame_rejected() {
        // DATA 帧（0x00）先于 HEADERS：拒绝。
        let mut frame = vec![0x00];
        varint::encode(3, &mut frame);
        frame.extend_from_slice(b"abc");
        assert_eq!(
            decode_auth_response(&frame),
            Err(Hysteria2Error::InvalidFrame)
        );
    }

    #[test]
    fn auth_response_missing_hysteria_udp_rejected() {
        // 缺 hysteria-udp 头：按 §3.1 视为非法响应。
        let headers = [(":status", "233")];
        let block = qpack::encode_field_section(&headers);
        let mut frame = vec![HEADERS_FRAME_TYPE];
        varint::encode(block.len() as u64, &mut frame);
        frame.extend_from_slice(&block);
        assert_eq!(
            decode_auth_response(&frame),
            Err(Hysteria2Error::InvalidFrame)
        );
    }

    #[test]
    fn settings_frame_bytes() {
        // 文档 §2.1：空 SETTINGS = [0x00, 0x04, 0x00]。
        assert_eq!(SETTINGS_FRAME, [0x00, 0x04, 0x00]);
    }
}
