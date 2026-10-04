//! Hysteria2 出站配置（文档 §4 参数表）。
//!
//! `Hysteria2Target` 描述一个 Hysteria2 服务端目标：地址、认证口令、TLS 校验
//! 模式、拥塞协商、混淆与开关。`Debug` 实现对密码脱敏。

use std::fmt;
use std::time::Duration;

use super::Hysteria2Error;
use super::tls::CertVerify;

/// 默认握手超时（QUIC 握手 + H3 认证总计）。
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// 默认认证 `:authority` 值（文档 §2.1：线上用 `:authority: hysteria`）。
pub const DEFAULT_AUTHORITY: &str = "hysteria";

/// 混淆方式（文档 §4 `obfs` 参数）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Obfs {
    /// 不启用混淆。
    None,
    /// Salamander 整包混淆（`BLAKE2b-256(key || salt)` 循环 XOR）。
    Salamander {
        /// 预共享 key（`obfs-password` 的字节）。
        key: Vec<u8>,
    },
}

impl Obfs {
    /// 解析 `obfs` 配置字符串。
    ///
    /// - `""` / `"none"` → 不启用；
    /// - `"salamander"` → 启用（key 取 `obfs_password`）；
    /// - `"gecko"` → 直接拒绝（文档：Rust 后端明确不支持）；
    /// - 其他 → 拒绝。
    ///
    /// # Errors
    ///
    /// 不支持的混淆方式 → [`Hysteria2Error::UnsupportedObfs`]；
    /// salamander 但未给 key → [`Hysteria2Error::InvalidConfig`]。
    pub fn parse(s: &str, obfs_password: &[u8]) -> Result<Self, Hysteria2Error> {
        match s {
            "" | "none" => Ok(Self::None),
            "salamander" => {
                if obfs_password.is_empty() {
                    return Err(Hysteria2Error::InvalidConfig(
                        "salamander obfs requires obfs-password".to_string(),
                    ));
                }
                Ok(Self::Salamander {
                    key: obfs_password.to_vec(),
                })
            }
            _ => Err(Hysteria2Error::UnsupportedObfs),
        }
    }

    /// 是否为 Salamander。
    #[must_use]
    pub fn is_salamander(&self) -> bool {
        matches!(self, Self::Salamander { .. })
    }
}

/// Hysteria2 服务端目标（出站配置）。
#[derive(Clone)]
pub struct Hysteria2Target {
    /// 服务器地址（域名或 IP）。
    pub server: String,
    /// QUIC 端口。
    pub port: u16,
    /// 认证口令（`Hysteria-Auth`；`Debug` 脱敏）。
    pub password: String,
    /// QUIC TLS SNI；为空则用 `server` host。
    pub sni: Option<String>,
    /// 证书校验模式（默认：系统根证书）。
    pub verify: CertVerify,
    /// `Hysteria-CC-RX` 请求头：客户端最大接收速率（bytes/s），`0` = 未知。
    pub cc_rx_bps: u64,
    /// 混淆配置。
    pub obfs: Obfs,
    /// fast-open：TCP 请求发出后不等响应即返回（默认 `true`）。
    pub fast_open: bool,
    /// 是否启用 UDP（与 server 协商结果取交集；默认 `true`）。
    pub udp: bool,
    /// 握手超时（QUIC 握手 + H3 认证）。
    pub handshake_timeout: Duration,
}

// 密码不进 Debug 输出。
impl fmt::Debug for Hysteria2Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Hysteria2Target")
            .field("server", &self.server)
            .field("port", &self.port)
            .field("password", &"<redacted>")
            .field("sni", &self.sni)
            .field("verify", &self.verify)
            .field("cc_rx_bps", &self.cc_rx_bps)
            .field("obfs", &self.obfs)
            .field("fast_open", &self.fast_open)
            .field("udp", &self.udp)
            .field("handshake_timeout", &self.handshake_timeout)
            .finish()
    }
}

impl Hysteria2Target {
    /// 构造最小目标（server/port/password，其余取默认值）。
    #[must_use]
    pub fn new(server: impl Into<String>, port: u16, password: impl Into<String>) -> Self {
        Self {
            server: server.into(),
            port,
            password: password.into(),
            sni: None,
            verify: CertVerify::SystemRoots,
            cc_rx_bps: 0,
            obfs: Obfs::None,
            fast_open: true,
            udp: true,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
        }
    }

    /// 实际使用的 SNI：`sni` 为空则用 server host。
    #[must_use]
    pub fn effective_sni(&self) -> String {
        self.sni.clone().unwrap_or_else(|| self.server.clone())
    }

    /// `server:port` 形式的 locator。
    #[must_use]
    pub fn locator(&self) -> String {
        format!("{}:{}", self.server, self.port)
    }

    /// Salamander key（未启用时 `None`）。
    #[must_use]
    pub fn obfs_key(&self) -> Option<Vec<u8>> {
        match &self.obfs {
            Obfs::Salamander { key } => Some(key.clone()),
            Obfs::None => None,
        }
    }

    /// 配置门禁校验。
    ///
    /// # Errors
    ///
    /// server/password 为空 → [`Hysteria2Error::InvalidConfig`]。
    pub fn validate(&self) -> Result<(), Hysteria2Error> {
        if self.server.is_empty() {
            return Err(Hysteria2Error::InvalidConfig("server is empty".to_string()));
        }
        if self.password.is_empty() {
            return Err(Hysteria2Error::InvalidConfig(
                "password is empty".to_string(),
            ));
        }
        Ok(())
    }
}

/// 从 hex 文本解析 `pin-sha256`（64 hex 字符 → 32 字节）。
///
/// # Errors
///
/// 格式非法 → [`Hysteria2Error::InvalidConfig`]（不回显输入原文）。
pub fn parse_pin_sha256(hex: &str) -> Result<[u8; 32], Hysteria2Error> {
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Hysteria2Error::InvalidConfig("bad pin-sha256".to_string()));
    }
    let mut out = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        let hi = hex_val(chunk[0]);
        let lo = hex_val(chunk[1]);
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_val(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn obfs_parse_gates() {
        assert_eq!(Obfs::parse("", &[]).unwrap(), Obfs::None);
        assert_eq!(Obfs::parse("none", &[]).unwrap(), Obfs::None);
        assert!(Obfs::parse("salamander", b"key").unwrap().is_salamander());
        // gecko 明确不支持：配置即报错。
        assert_eq!(
            Obfs::parse("gecko", b"key"),
            Err(Hysteria2Error::UnsupportedObfs)
        );
        assert_eq!(
            Obfs::parse("weird", b"key"),
            Err(Hysteria2Error::UnsupportedObfs)
        );
        // salamander 但未给 key：门禁拒绝。
        assert!(matches!(
            Obfs::parse("salamander", &[]),
            Err(Hysteria2Error::InvalidConfig(_))
        ));
    }

    #[test]
    fn target_defaults() {
        let t = Hysteria2Target::new("example.com", 443, "pw");
        assert!(t.fast_open);
        assert!(t.udp);
        assert_eq!(t.effective_sni(), "example.com");
        assert_eq!(t.locator(), "example.com:443");
        assert_eq!(t.obfs_key(), None);
        t.validate().unwrap();
    }

    #[test]
    fn target_debug_redacts_password() {
        let t = Hysteria2Target::new("example.com", 443, "super-secret-pw");
        let d = format!("{t:?}");
        assert!(!d.contains("super-secret-pw"));
        assert!(d.contains("<redacted>"));
    }

    #[test]
    fn target_validate_rejects_empty() {
        let t = Hysteria2Target::new("", 443, "pw");
        assert!(t.validate().is_err());
        let t = Hysteria2Target::new("example.com", 443, "");
        assert!(t.validate().is_err());
    }

    #[test]
    fn pin_sha256_parse() {
        let hex = "ab".repeat(32);
        let pin = parse_pin_sha256(&hex).unwrap();
        assert_eq!(pin, [0xABu8; 32]);
        assert!(parse_pin_sha256("ab").is_err());
        assert!(parse_pin_sha256(&"zz".repeat(32)).is_err());
        // 错误中不回显输入。
        let err = parse_pin_sha256(&"zz".repeat(32)).unwrap_err().to_string();
        assert!(!err.contains('z'));
    }
}
