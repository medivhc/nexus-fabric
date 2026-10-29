//! nexus-outbound-vless
//!
//! VLESS 出站 adapter：实现 `nexus-connectivity::OutboundAdapter`，在一条已建立
//! 的字节流上完成 VLESS 请求/响应头握手，支持基础 VLESS（TCP/UDP/Mux 信令）与
//! XTLS-Vision padding 封装。
//!
//! 协议语义见 `docs/protocols/vless.md`（clean-room 实现，不拷贝任何既有代码）。
//! 本 crate 覆盖协议中已确认的部分：
//!
//! - 请求头：`version(1)=0x00 | uuid(16) | addon_len(1) | addon |
//!   command(1) | port(2 BE) | addr_type(1) | address(变长)`。
//!   **注意 port 在 addr_type 之前**（VMess/VLESS 惯例，文档 §2.1 明确强调）。
//! - UUID 文本（`xxxxxxxx-xxxx-...` 或 32 hex）↔ 16 字节二进制。
//! - Addon 手写 protobuf：`flow=""` → 空；`flow="xtls-rprx-vision"` →
//!   `[0x0A, 0x10] + "xtls-rprx-vision"`。未知 flow 直接拒绝（§5 坑 #6）。
//! - 命令 0x01 TCP / 0x02 UDP / 0x03 Mux（Mux 只做帧头编解码，复用逻辑不做）。
//! - **响应头惰性读**（§2.1 坑 / §5 坑 #1）：握手只管"请求头已发出"就返回；
//!   响应头 `[version(1) | addon_len(1)] + addon` 在第一次 `read` 时才消费——
//!   server 要先拨号目标，目标先说话的协议在握手时阻塞读响应会死锁。
//! - UDP-over-TCP：`u16 BE` 长度前缀分包，双向同格式。
//! - XTLS-Vision padding 帧编解码（首帧 21 字节头含 UUID / 后续帧 5 字节头）与
//!   写方向状态机（ClientHello `0x16` → Application Data `0x17` 后发 END；
//!   direct 模式发 DIRECT）。
//!
//! 未确认的细节（如 Mux 信令头是否省略 port/address、XTLS-UDP443 变体、
//! ServerHello 过滤器）按文档已确认部分实现，注释中标 `// 未确认：`。

#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr};

use nexus_proxy_config::outbound_seam::{OutboundAdapter, OutboundHandoff, OutboundHandoffError};

// ---------- 协议常量 ----------

/// VLESS 请求/响应头 version（固定）。
pub const VLESS_VERSION: u8 = 0x00;

/// XTLS-Vision 的 flow 字符串。
pub const FLOW_XTLS_RPRX_VISION: &str = "xtls-rprx-vision";

/// Vision padding 帧首帧头长度：`uuid(16) + command(1) + content_len(2) + padding_len(2)`。
pub const VISION_FIRST_HEADER_LEN: usize = 21;
/// Vision padding 帧后续帧头长度：`command(1) + content_len(2) + padding_len(2)`。
pub const VISION_HEADER_LEN: usize = 5;

// ---------- 结构化错误 ----------

/// VLESS 出站结构化错误（不以日志文本代替类型；错误展示绝不回显 UUID/密钥材料）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VlessError {
    /// UUID 文本解析失败（不回显输入原文）。
    InvalidUuid,
    /// 未知的 flow 字符串（按 ADR-0002 Class A 直接拒绝，不静默降级）。
    UnsupportedFlow,
    /// `flow=xtls-rprx-vision` 但未启用 TLS（§5 坑 #3：无外层 TLS 时 splice 无意义）。
    VisionRequiresTls,
    /// 未知的 command 值。
    InvalidCommand { cmd: u8 },
    /// 未知的 addr_type 值。
    InvalidAddressType { addr_type: u8 },
    /// 请求头/响应头字节不完整。
    TruncatedHeader,
    /// version 不是 0x00。
    InvalidVersion { version: u8 },
    /// 响应头非法。
    InvalidResponse,
    /// 域名长度非法（空或超过 255 字节）。
    InvalidDomain,
    /// TCP/UDP 命令缺少目标地址。
    MissingTarget,
    /// UDP 数据报超过 u16 上限。
    DatagramTooLarge { len: usize },
    /// UDP 数据报流尾部不完整。
    TruncatedDatagram,
    /// Vision 帧头/帧体非法。
    InvalidVisionFrame,
    /// Vision 首帧 UUID 与配置不一致（不回显 UUID）。
    VisionUuidMismatch,
    /// Vision 已 END/DIRECT 后仍调用帧解码。
    VisionAlreadyEnded,
    /// 底层 I/O 失败。
    Io,
}

impl core::fmt::Display for VlessError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidUuid => write!(f, "vless invalid uuid"),
            Self::UnsupportedFlow => write!(f, "vless unsupported flow"),
            Self::VisionRequiresTls => write!(f, "vless vision requires tls"),
            Self::InvalidCommand { cmd } => write!(f, "vless invalid command {cmd:#04x}"),
            Self::InvalidAddressType { addr_type } => {
                write!(f, "vless invalid address type {addr_type:#04x}")
            }
            Self::TruncatedHeader => write!(f, "vless truncated header"),
            Self::InvalidVersion { version } => write!(f, "vless invalid version {version:#04x}"),
            Self::InvalidResponse => write!(f, "vless invalid response"),
            Self::InvalidDomain => write!(f, "vless invalid domain"),
            Self::MissingTarget => write!(f, "vless missing target"),
            Self::DatagramTooLarge { len } => write!(f, "vless datagram too large ({len} bytes)"),
            Self::TruncatedDatagram => write!(f, "vless truncated datagram"),
            Self::InvalidVisionFrame => write!(f, "vless invalid vision frame"),
            Self::VisionUuidMismatch => write!(f, "vless vision uuid mismatch"),
            Self::VisionAlreadyEnded => write!(f, "vless vision already ended"),
            Self::Io => write!(f, "vless io error"),
        }
    }
}

impl std::error::Error for VlessError {}

impl From<std::io::Error> for VlessError {
    fn from(_: std::io::Error) -> Self {
        Self::Io
    }
}

// ---------- UUID ----------

/// VLESS 用户身份：16 字节二进制 UUID（线格式用二进制，非文本）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VlessUuid([u8; 16]);

impl VlessUuid {
    /// 从 16 字节二进制构造。
    #[must_use]
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// 二进制视图。
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// 解析 UUID 文本：接受标准带连字符形式 `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`
    ///（连字符位置严格校验），或 32 位纯 hex。大小写不敏感。
    ///
    /// # Errors
    ///
    /// 格式非法返回 [`VlessError::InvalidUuid`]（不回显输入原文）。
    pub fn parse(text: &str) -> Result<Self, VlessError> {
        let hex: Vec<u8> = if text.contains('-') {
            // 严格校验 8-4-4-4-12 分段。
            let parts: Vec<&str> = text.split('-').collect();
            if parts.len() != 5
                || parts[0].len() != 8
                || parts[1].len() != 4
                || parts[2].len() != 4
                || parts[3].len() != 4
                || parts[4].len() != 12
            {
                return Err(VlessError::InvalidUuid);
            }
            let mut out = Vec::with_capacity(32);
            for p in &parts {
                out.extend_from_slice(p.as_bytes());
            }
            out
        } else {
            if text.len() != 32 {
                return Err(VlessError::InvalidUuid);
            }
            text.as_bytes().to_vec()
        };
        if hex.len() != 32 || !hex.iter().all(|b| b.is_ascii_hexdigit()) {
            return Err(VlessError::InvalidUuid);
        }
        let mut bytes = [0u8; 16];
        for (i, chunk) in hex.chunks_exact(2).enumerate() {
            let hi = hex_val(chunk[0]).ok_or(VlessError::InvalidUuid)?;
            let lo = hex_val(chunk[1]).ok_or(VlessError::InvalidUuid)?;
            bytes[i] = (hi << 4) | lo;
        }
        Ok(Self(bytes))
    }

    /// 输出标准小写文本形式 `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`。
    #[must_use]
    pub fn to_text(&self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(36);
        for (i, b) in self.0.iter().enumerate() {
            if matches!(i, 4 | 6 | 8 | 10) {
                out.push('-');
            }
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0x0f) as usize] as char);
        }
        out
    }
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// ---------- Flow / Addon ----------

/// VLESS flow 配置（只收已确认的两个取值；未知直接拒绝，§5 坑 #6）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VlessFlow {
    /// `flow=""`：无 flow，addon 为空。
    #[default]
    None,
    /// `flow="xtls-rprx-vision"`：XTLS-Vision padding 封装。
    XtlsRprxVision,
}

impl VlessFlow {
    /// 解析 flow 字符串；未知取值返回 [`VlessError::UnsupportedFlow`]。
    ///
    /// 旧的 `xtls-rprx-direct` 等已废弃取值同样拒绝（文档 §4 明确）。
    pub fn parse(s: &str) -> Result<Self, VlessError> {
        match s {
            "" => Ok(Self::None),
            FLOW_XTLS_RPRX_VISION => Ok(Self::XtlsRprxVision),
            _ => Err(VlessError::UnsupportedFlow),
        }
    }

    /// flow 字符串。
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "",
            Self::XtlsRprxVision => FLOW_XTLS_RPRX_VISION,
        }
    }

    /// Addon 字节（手写 protobuf，无 prost）：
    /// - `flow=""` → 空；
    /// - `flow="xtls-rprx-vision"` → `[0x0A, 0x10] + "xtls-rprx-vision"`
    ///   （0x0A = protobuf field 1 / wire-type 2，0x10 = varint 16 = 字符串长度）。
    #[must_use]
    pub fn addon_bytes(self) -> Vec<u8> {
        match self {
            Self::None => Vec::new(),
            Self::XtlsRprxVision => {
                let s = FLOW_XTLS_RPRX_VISION.as_bytes();
                let mut out = Vec::with_capacity(2 + s.len());
                out.push(0x0A);
                out.push(0x10);
                out.extend_from_slice(s);
                out
            }
        }
    }
}

// ---------- 目标地址与命令 ----------

/// VLESS 目标地址。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VlessTarget {
    /// `addr_type = 0x01`，4 字节。
    Ipv4(Ipv4Addr),
    /// `addr_type = 0x02`，`len(1) + 内容`（1..=255 字节）。
    Domain(String),
    /// `addr_type = 0x03`，16 字节。
    Ipv6(Ipv6Addr),
}

impl VlessTarget {
    fn addr_type(&self) -> u8 {
        match self {
            Self::Ipv4(_) => 0x01,
            Self::Domain(_) => 0x02,
            Self::Ipv6(_) => 0x03,
        }
    }

    /// 编码 `addr_type + address`（不含 port；port 在 addr_type 之前，由请求头负责）。
    fn encode(&self, out: &mut Vec<u8>) -> Result<(), VlessError> {
        out.push(self.addr_type());
        match self {
            Self::Ipv4(ip) => out.extend_from_slice(&ip.octets()),
            Self::Domain(d) => {
                let b = d.as_bytes();
                if b.is_empty() || b.len() > 255 {
                    return Err(VlessError::InvalidDomain);
                }
                out.push(b.len() as u8);
                out.extend_from_slice(b);
            }
            Self::Ipv6(ip) => out.extend_from_slice(&ip.octets()),
        }
        Ok(())
    }
}

/// VLESS 命令。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum VlessCommand {
    /// 0x01：TCP。
    Tcp = 0x01,
    /// 0x02：UDP。
    Udp = 0x02,
    /// 0x03：Mux.Cool 信令（请求本身即信令，不带地址；复用逻辑不在本 crate）。
    Mux = 0x03,
}

impl VlessCommand {
    /// 从 u8 解析；未知值返回 [`VlessError::InvalidCommand`]（fail-closed）。
    pub fn from_u8(v: u8) -> Result<Self, VlessError> {
        match v {
            0x01 => Ok(Self::Tcp),
            0x02 => Ok(Self::Udp),
            0x03 => Ok(Self::Mux),
            _ => Err(VlessError::InvalidCommand { cmd: v }),
        }
    }

    #[must_use]
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

// ---------- 请求头 ----------

/// VLESS 请求头（client → server，握手时一次写出）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VlessRequest {
    /// 用户 UUID（二进制上线路）。
    pub uuid: VlessUuid,
    /// flow（决定 addon 内容）。
    pub flow: VlessFlow,
    /// 命令。
    pub command: VlessCommand,
    /// 目标端口。
    pub port: u16,
    /// 目标地址；`command = Mux` 时为 `None`（信令不带地址）。
    pub target: Option<VlessTarget>,
}

/// 编码请求头。
///
/// 线格式（§2.1/§2.2）：
///
/// ```text
/// version(1) | uuid(16) | addon_len(1) | addon |
/// command(1) | port(2 BE) | addr_type(1) | address(变长)
/// ```
///
/// **关键顺序：port 在 addr_type 之前**（VMess/VLESS 惯例，人读文档时容易写反）。
///
/// `command = Mux` 时只编码到 command 为止，不带 port/address
///（§3.2"不带地址"）。
/// // 未确认：Xray 上游 CommandMux 请求头是否完全省略 port/address 字段；
/// // 本实现按文档"不带地址"字面含义省略。
///
/// # Errors
///
/// 域名非法 / TCP/UDP 缺目标 → [`VlessError`]。
pub fn encode_request(req: &VlessRequest) -> Result<Vec<u8>, VlessError> {
    let addon = req.flow.addon_bytes();
    let mut out = Vec::with_capacity(1 + 16 + 1 + addon.len() + 1 + 2 + 1 + 16);
    out.push(VLESS_VERSION);
    out.extend_from_slice(req.uuid.as_bytes());
    out.push(addon.len() as u8);
    out.extend_from_slice(&addon);
    out.push(req.command.as_u8());
    if req.command == VlessCommand::Mux {
        return Ok(out);
    }
    let target = req.target.as_ref().ok_or(VlessError::MissingTarget)?;
    // port 在 addr_type 之前——不要写反。
    out.extend_from_slice(&req.port.to_be_bytes());
    target.encode(&mut out)?;
    Ok(out)
}

/// 解析请求头，返回 `(请求, 消费字节数)`。
///
/// # Errors
///
/// 字节不完整 → [`VlessError::TruncatedHeader`]；version 非 0x00 →
/// [`VlessError::InvalidVersion`]；未知 command/addr_type → 对应错误。
pub fn decode_request(buf: &[u8]) -> Result<(VlessRequest, usize), VlessError> {
    let mut pos = 0;
    let take = |pos: &mut usize, n: usize| -> Result<&[u8], VlessError> {
        if buf.len() < *pos + n {
            return Err(VlessError::TruncatedHeader);
        }
        let s = &buf[*pos..*pos + n];
        *pos += n;
        Ok(s)
    };
    let version = take(&mut pos, 1)?[0];
    if version != VLESS_VERSION {
        return Err(VlessError::InvalidVersion { version });
    }
    let uuid_bytes: [u8; 16] = take(&mut pos, 16)?.try_into().expect("16 bytes");
    let addon_len = take(&mut pos, 1)?[0] as usize;
    let addon = take(&mut pos, addon_len)?;
    let flow = match addon {
        [] => VlessFlow::None,
        [0x0A, 0x10, rest @ ..] if rest == FLOW_XTLS_RPRX_VISION.as_bytes() => {
            VlessFlow::XtlsRprxVision
        }
        _ => return Err(VlessError::UnsupportedFlow),
    };
    let command = VlessCommand::from_u8(take(&mut pos, 1)?[0])?;
    if command == VlessCommand::Mux {
        return Ok((
            VlessRequest {
                uuid: VlessUuid::from_bytes(uuid_bytes),
                flow,
                command,
                port: 0,
                target: None,
            },
            pos,
        ));
    }
    // port 在 addr_type 之前——与 encode_request 对称，不要读反。
    let port_bytes: [u8; 2] = take(&mut pos, 2)?.try_into().expect("2 bytes");
    let port = u16::from_be_bytes(port_bytes);
    let addr_type = take(&mut pos, 1)?[0];
    let target = match addr_type {
        0x01 => {
            let octets: [u8; 4] = take(&mut pos, 4)?.try_into().expect("4 bytes");
            VlessTarget::Ipv4(Ipv4Addr::from(octets))
        }
        0x02 => {
            let len = take(&mut pos, 1)?[0] as usize;
            let bytes = take(&mut pos, len)?;
            let domain =
                String::from_utf8(bytes.to_vec()).map_err(|_| VlessError::InvalidDomain)?;
            if domain.is_empty() {
                return Err(VlessError::InvalidDomain);
            }
            VlessTarget::Domain(domain)
        }
        0x03 => {
            let octets: [u8; 16] = take(&mut pos, 16)?.try_into().expect("16 bytes");
            VlessTarget::Ipv6(Ipv6Addr::from(octets))
        }
        _ => return Err(VlessError::InvalidAddressType { addr_type }),
    };
    Ok((
        VlessRequest {
            uuid: VlessUuid::from_bytes(uuid_bytes),
            flow,
            command,
            port,
            target: Some(target),
        },
        pos,
    ))
}

// ---------- 响应头（惰性读） ----------

/// VLESS 响应头（server → client）：`version(1) | addon_len(1) | addon`，通常全 0。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VlessResponse {
    /// 回显请求 version（0x00）。
    pub version: u8,
    /// addon 内容（读出后丢弃）。
    pub addon: Vec<u8>,
}

/// 编码响应头（server 侧 / 测试用）。
#[must_use]
pub fn encode_response(resp: &VlessResponse) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + resp.addon.len());
    out.push(resp.version);
    out.push(resp.addon.len() as u8);
    out.extend_from_slice(&resp.addon);
    out
}

/// 从流上读出并消费响应头。
///
/// **惰性读纪律**（§2.1 坑 / §5 坑 #1）：只在第一次上层 `read` 时调用；
/// 不要在写请求头后立刻阻塞读响应——server 要先拨号目标，目标先说话的
/// 协议会死锁。
///
/// # Errors
///
/// I/O 失败 → [`VlessError::Io`]；version 非 0x00 → [`VlessError::InvalidVersion`]。
pub fn read_response<R: Read>(r: &mut R) -> Result<VlessResponse, VlessError> {
    let mut head = [0u8; 2];
    r.read_exact(&mut head)?;
    if head[0] != VLESS_VERSION {
        return Err(VlessError::InvalidVersion { version: head[0] });
    }
    let mut addon = vec![0u8; head[1] as usize];
    r.read_exact(&mut addon)?;
    Ok(VlessResponse {
        version: head[0],
        addon,
    })
}

// ---------- VlessConn：握手写 + 响应惰性读 ----------

/// VLESS 连接包装：握手时只写请求头；响应头在第一次 `read` 时惰性消费。
///
/// 把"不要在握手时阻塞读响应"的纪律编码进类型，而不是靠调用方记忆。
pub struct VlessConn<S> {
    inner: S,
    response_pending: bool,
}

impl<S> VlessConn<S> {
    /// 包装一条已建立的字节流。
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            response_pending: false,
        }
    }

    /// 是否还有未消费的响应头。
    #[must_use]
    pub fn response_pending(&self) -> bool {
        self.response_pending
    }

    /// 拆出内层流。
    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: Read + Write> VlessConn<S> {
    /// 握手：**只写请求头**，不读响应（惰性读见 [`Read`] 实现）。
    ///
    /// # Errors
    ///
    /// 编码失败或写失败 → [`VlessError`]。
    pub fn handshake(&mut self, req: &VlessRequest) -> Result<(), VlessError> {
        let bytes = encode_request(req)?;
        self.inner.write_all(&bytes)?;
        self.response_pending = true;
        Ok(())
    }
}

impl<S: Read> Read for VlessConn<S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.response_pending {
            read_response(&mut self.inner)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
            self.response_pending = false;
        }
        self.inner.read(buf)
    }
}

impl<S: Write> Write for VlessConn<S> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

// ---------- UDP-over-TCP ----------

/// 编码一个 UDP 数据报：`长度(u16 BE) + 包内容`（§2.4，双向同格式）。
///
/// 没有 per-datagram 源地址字段（不像 SOCKS5 UDP 头）。
///
/// # Errors
///
/// 载荷超过 65535 字节 → [`VlessError::DatagramTooLarge`]。
pub fn encode_udp_datagram(payload: &[u8]) -> Result<Vec<u8>, VlessError> {
    if payload.len() > u16::MAX as usize {
        return Err(VlessError::DatagramTooLarge { len: payload.len() });
    }
    let mut out = Vec::with_capacity(2 + payload.len());
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// 从流上读一个 UDP 数据报（先读 2 字节长度，再读包体）。
///
/// # Errors
///
/// I/O 失败 → [`VlessError::Io`]。
pub fn read_udp_datagram<R: Read>(r: &mut R) -> Result<Vec<u8>, VlessError> {
    let mut len_buf = [0u8; 2];
    r.read_exact(&mut len_buf)?;
    let len = u16::from_be_bytes(len_buf) as usize;
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload)?;
    Ok(payload)
}

/// 把一段完整字节切分成 UDP 数据报序列。
///
/// 要求 `buf` 恰好由整数个 `u16BE长度 + 包体` 组成；尾部不完整 →
/// [`VlessError::TruncatedDatagram`]。
pub fn decode_udp_datagrams(buf: &[u8]) -> Result<Vec<Vec<u8>>, VlessError> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < buf.len() {
        if buf.len() - pos < 2 {
            return Err(VlessError::TruncatedDatagram);
        }
        let len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
        pos += 2;
        if buf.len() - pos < len {
            return Err(VlessError::TruncatedDatagram);
        }
        out.push(buf[pos..pos + len].to_vec());
        pos += len;
    }
    Ok(out)
}

// ---------- XTLS-Vision ----------

/// Vision padding 帧命令。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum VisionCommand {
    /// 0x00：继续 padding。
    Continue = 0x00,
    /// 0x01：结束 padding，后续透传。
    End = 0x01,
    /// 0x02：结束 padding 且写侧切裸 TCP 直通（splice）；读侧仍走 TLS。
    Direct = 0x02,
}

impl VisionCommand {
    /// 从 u8 解析；未知值 → [`VlessError::InvalidVisionFrame`]（fail-closed）。
    pub fn from_u8(v: u8) -> Result<Self, VlessError> {
        match v {
            0x00 => Ok(Self::Continue),
            0x01 => Ok(Self::End),
            0x02 => Ok(Self::Direct),
            _ => Err(VlessError::InvalidVisionFrame),
        }
    }

    #[must_use]
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// 编码一个 Vision padding 帧。
///
/// ```text
/// 首帧:   uuid(16) | command(1) | content_len(2 BE) | padding_len(2 BE) | content | padding(0填充)
/// 后续帧: command(1) | content_len(2 BE) | padding_len(2 BE) | content | padding(0填充)
/// ```
///
/// `first` 为 true 时带 16 字节 UUID（仅首帧）。
pub fn encode_vision_frame(
    first: bool,
    uuid: &[u8; 16],
    cmd: VisionCommand,
    content: &[u8],
    padding_len: usize,
) -> Vec<u8> {
    let header_len = if first {
        VISION_FIRST_HEADER_LEN
    } else {
        VISION_HEADER_LEN
    };
    let mut out = Vec::with_capacity(header_len + content.len() + padding_len);
    if first {
        out.extend_from_slice(uuid);
    }
    out.push(cmd.as_u8());
    out.extend_from_slice(&(content.len() as u16).to_be_bytes());
    out.extend_from_slice(&(padding_len as u16).to_be_bytes());
    out.extend_from_slice(content);
    out.extend(std::iter::repeat_n(0u8, padding_len));
    out
}

/// 解码一个 Vision padding 帧头，返回 `(command, content_len, padding_len, 头长度)`。
fn decode_vision_header(
    first: bool,
    uuid: &[u8; 16],
    header: &[u8],
) -> Result<(VisionCommand, usize, usize), VlessError> {
    let expected = if first {
        VISION_FIRST_HEADER_LEN
    } else {
        VISION_HEADER_LEN
    };
    if header.len() < expected {
        return Err(VlessError::InvalidVisionFrame);
    }
    let mut pos = 0;
    if first {
        if &header[..16] != uuid {
            return Err(VlessError::VisionUuidMismatch);
        }
        pos = 16;
    }
    let cmd = VisionCommand::from_u8(header[pos])?;
    let content_len = u16::from_be_bytes([header[pos + 1], header[pos + 2]]) as usize;
    let padding_len = u16::from_be_bytes([header[pos + 3], header[pos + 4]]) as usize;
    Ok((cmd, content_len, padding_len))
}

/// Vision 读侧解码器：对称解包 padding 帧，还原明文；END/DIRECT 后进入透传。
pub struct VisionReader {
    first: bool,
    ended: bool,
}

impl VisionReader {
    /// 新建读侧解码器（首帧期望 21 字节头）。
    pub fn new() -> Self {
        Self {
            first: true,
            ended: false,
        }
    }

    /// 是否已收到 END/DIRECT（之后应直接透传读）。
    #[must_use]
    pub fn is_ended(&self) -> bool {
        self.ended
    }

    /// 从流上读一帧，返回 `(command, content)`。
    ///
    /// padding 被消费并丢弃；END/DIRECT 帧的 content 一并返回，
    /// 之后 [`VisionReader::is_ended`] 为 true。
    ///
    /// # Errors
    ///
    /// I/O 失败 / 帧非法 / 首帧 UUID 不匹配 / 已结束后仍调用。
    pub fn read_frame<R: Read>(
        &mut self,
        r: &mut R,
        uuid: &[u8; 16],
    ) -> Result<(VisionCommand, Vec<u8>), VlessError> {
        if self.ended {
            return Err(VlessError::VisionAlreadyEnded);
        }
        let header_len = if self.first {
            VISION_FIRST_HEADER_LEN
        } else {
            VISION_HEADER_LEN
        };
        let mut header = vec![0u8; header_len];
        r.read_exact(&mut header)?;
        let (cmd, content_len, padding_len) = decode_vision_header(self.first, uuid, &header)?;
        let mut content = vec![0u8; content_len];
        r.read_exact(&mut content)?;
        // padding 直接消费丢弃。
        let mut padding = vec![0u8; padding_len];
        r.read_exact(&mut padding)?;
        self.first = false;
        if matches!(cmd, VisionCommand::End | VisionCommand::Direct) {
            self.ended = true;
        }
        Ok((cmd, content))
    }
}

impl Default for VisionReader {
    fn default() -> Self {
        Self::new()
    }
}

// ---------- 内部 PRNG（padding 长度随机源） ----------

/// xorshift64* 风格 PRNG：只用于 Vision padding 长度抖动，不做密钥材料。
///
/// 不引入外部 rand 依赖；测试用固定种子保证确定性，生产用 [`XorShift64::from_time`]。
struct XorShift64(u64);

impl XorShift64 {
    fn new(seed: u64) -> Self {
        // 种子 0 会卡死 xorshift，替换为黄金比例常数。
        Self(if seed == 0 {
            0x9E37_79B9_7F4A_7C15
        } else {
            seed
        })
    }

    /// 以当前时间（纳秒）为种子；无 getrandom 依赖。
    fn from_time() -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x9E37_79B9_7F4A_7C15);
        Self::new(nanos)
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}

/// Vision padding 长度策略（文档 §3.1）：
///
/// - `content.len() < 900`：见过 TLS 则补到约 900~1400（`rand % 500 + 900 - len`），
///   否则 `rand % 256`；
/// - `>= 900`：不填充。
fn vision_padding_len(content_len: usize, seen_tls: bool, rng: &mut XorShift64) -> usize {
    if content_len >= 900 {
        0
    } else if seen_tls {
        (rng.next_u64() % 500) as usize + 900 - content_len
    } else {
        (rng.next_u64() % 256) as usize
    }
}

/// 扫描一个上层写块中的内层 TLS 标记（§2.5 写状态机）：
///
/// - ClientHello：TLS record type `0x16`、版本 `0x03xx`，且 record 载荷首字节为
///   handshake type `0x01`（ClientHello）；
/// - Application Data：`0x17 0x03 ...`。
///
/// 返回 `(seen_client_hello, seen_app_data)`。这是启发式检测（按文档字面实现），
/// 误判只影响 padding 有无，不影响正确性（END 后透传）。
fn scan_tls_marks(data: &[u8]) -> (bool, bool) {
    let mut hello = false;
    let mut app_data = false;
    let mut i = 0;
    while i + 5 < data.len() {
        match data[i] {
            0x16 if data[i + 1] == 0x03 && data[i + 5] == 0x01 => hello = true,
            0x17 if data[i + 1] == 0x03 => app_data = true,
            _ => {}
        }
        i += 1;
    }
    // 尾部不足 6 字节的残片：只检查 0x17 0x03 前缀（Application Data 头只需 3 字节）。
    while i + 2 < data.len() {
        if data[i] == 0x17 && data[i + 1] == 0x03 {
            app_data = true;
        }
        i += 1;
    }
    (hello, app_data)
}

// ---------- Vision 写方向状态机 ----------

/// Vision 写方向阶段。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VisionWritePhase {
    /// 仍在 padding：上层写块被包成 padding 帧发出。
    Padding,
    /// 已 END/DIRECT：写方向透传（DIRECT 时为裸 TCP 直通，由调用方保证传输支持）。
    Passthrough,
}

/// Vision 写侧状态机（§2.5）：
///
/// 1. 初始 `Padding`：每个上层写块包成 padding 帧；
/// 2. 检测到内层 TLS ClientHello（`0x16`）后标记 `seen_tls`；
/// 3. 出现内层 TLS Application Data（`0x17 0x03`）且已见过 ClientHello → 发
///    `END`（含剩余数据），写方向停止 padding；direct 模式则发 `DIRECT`，
///    写侧切裸 TCP 直通（读侧仍走 TLS）；
/// 4. 首个写块即非 TLS（始终没见到握手）→ 直接 `END`，不做多余填充。
pub struct VisionWriter {
    uuid: [u8; 16],
    direct: bool,
    first_frame: bool,
    seen_tls: bool,
    phase: VisionWritePhase,
    rng: XorShift64,
}

impl VisionWriter {
    /// 新建写侧状态机。
    ///
    /// - `direct`：是否启用 direct 模式（END 时改发 DIRECT）；
    /// - `rng_seed`：padding 随机种子（测试用固定值；生产用时间种子见
    ///   [`VisionWriter::with_time_seed`]）。
    pub fn new(uuid: [u8; 16], direct: bool, rng_seed: u64) -> Self {
        Self {
            uuid,
            direct,
            first_frame: true,
            seen_tls: false,
            phase: VisionWritePhase::Padding,
            rng: XorShift64::new(rng_seed),
        }
    }

    /// 以当前时间为 padding 随机种子构造（生产路径）。
    pub fn with_time_seed(uuid: [u8; 16], direct: bool) -> Self {
        Self {
            uuid,
            direct,
            first_frame: true,
            seen_tls: false,
            phase: VisionWritePhase::Padding,
            rng: XorShift64::from_time(),
        }
    }

    /// 当前阶段。
    #[must_use]
    pub fn phase(&self) -> VisionWritePhase {
        self.phase
    }

    /// 是否已见过内层 TLS ClientHello。
    #[must_use]
    pub fn seen_tls(&self) -> bool {
        self.seen_tls
    }

    /// 处理一个上层写块，返回应写入传输的字节。
    ///
    /// - `Padding` 阶段：包成 padding 帧（含状态机推进）；
    /// - `Passthrough` 阶段：原样返回（裸透传）。
    pub fn write_chunk(&mut self, data: &[u8]) -> Vec<u8> {
        if self.phase == VisionWritePhase::Passthrough {
            return data.to_vec();
        }
        let (hello, app_data) = scan_tls_marks(data);
        if hello {
            self.seen_tls = true;
        }
        let cmd = if self.seen_tls && app_data {
            // 规则 3：见过 ClientHello 后出现 Application Data → 结束 padding。
            self.phase = VisionWritePhase::Passthrough;
            if self.direct {
                VisionCommand::Direct
            } else {
                VisionCommand::End
            }
        } else if !self.seen_tls && !hello {
            // 规则 4：非 TLS 内层流量 → 直接 END，不做多余填充。
            // （能走到这里说明之前也没有见过 ClientHello，否则 seen_tls 为 true。）
            self.phase = VisionWritePhase::Passthrough;
            VisionCommand::End
        } else {
            VisionCommand::Continue
        };
        let padding_len = if matches!(cmd, VisionCommand::Continue) {
            vision_padding_len(data.len(), self.seen_tls, &mut self.rng)
        } else {
            0
        };
        let frame = encode_vision_frame(self.first_frame, &self.uuid, cmd, data, padding_len);
        self.first_frame = false;
        frame
    }
}

// ---------- 配置与 Adapter ----------

/// VLESS 出站配置。
#[derive(Debug, Clone)]
pub struct VlessConfig {
    /// 出站 tag。
    pub tag: String,
    /// 服务端 locator（如 `example.com:443`）。
    pub locator: String,
    /// 用户 UUID。
    pub uuid: VlessUuid,
    /// flow（`""` 或 `xtls-rprx-vision`）。
    pub flow: VlessFlow,
    /// 是否启用 TLS（Vision 要求 true）。
    pub tls: bool,
    /// Vision direct 模式（写侧 splice 直通；默认 false）。
    pub vision_direct: bool,
}

impl VlessConfig {
    /// 校验配置门禁。
    ///
    /// # Errors
    ///
    /// `flow=xtls-rprx-vision` 但 `tls=false` → [`VlessError::VisionRequiresTls`]
    ///（§5 坑 #3：无加密传输时拒绝启用 Vision）。
    pub fn validate(&self) -> Result<(), VlessError> {
        if self.flow == VlessFlow::XtlsRprxVision && !self.tls {
            return Err(VlessError::VisionRequiresTls);
        }
        Ok(())
    }
}

/// VLESS 出站 adapter（`OutboundAdapter` 实现，`kind = "vless"`）。
///
/// 领域中立接缝：只暴露出站标识与离线交接语义；真实建连/传输链装配由
/// Composition Root 完成（传输链是 nexus-proxy-transport 的职责）。
pub struct VlessAdapter {
    tag: String,
    locator: String,
    uuid: VlessUuid,
    flow: VlessFlow,
}

impl VlessAdapter {
    /// 构造 adapter。
    #[must_use]
    pub fn new(
        tag: impl Into<String>,
        locator: impl Into<String>,
        uuid: VlessUuid,
        flow: VlessFlow,
    ) -> Self {
        Self {
            tag: tag.into(),
            locator: locator.into(),
            uuid,
            flow,
        }
    }

    /// 从配置构造（含 Vision/TLS 门禁校验）。
    ///
    /// # Errors
    ///
    /// 配置门禁不通过 → [`VlessError`]。
    pub fn from_config(config: &VlessConfig) -> Result<Self, VlessError> {
        config.validate()?;
        Ok(Self::new(
            config.tag.clone(),
            config.locator.clone(),
            config.uuid,
            config.flow,
        ))
    }

    /// 配置的服务端 locator。
    #[must_use]
    pub fn locator(&self) -> &str {
        &self.locator
    }

    /// 用户 UUID（二进制）。
    #[must_use]
    pub fn uuid(&self) -> &VlessUuid {
        &self.uuid
    }

    /// flow。
    #[must_use]
    pub fn flow(&self) -> VlessFlow {
        self.flow
    }
}

impl OutboundAdapter for VlessAdapter {
    fn outbound_kind(&self) -> &'static str {
        "vless"
    }

    fn tag(&self) -> &str {
        &self.tag
    }

    fn handoff(&self, locator: &str) -> Result<OutboundHandoff, OutboundHandoffError> {
        Ok(OutboundHandoff {
            kind: self.outbound_kind().to_string(),
            tag: self.tag.clone(),
            locator: locator.to_string(),
        })
    }
}

// ---------- 单元测试 ----------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};

    fn test_uuid() -> VlessUuid {
        VlessUuid::parse("123e4567-e89b-12d3-a456-426614174000").unwrap()
    }

    // ----- UUID -----

    #[test]
    fn uuid_text_to_binary_roundtrip() {
        let text = "123e4567-e89b-12d3-a456-426614174000";
        let uuid = VlessUuid::parse(text).unwrap();
        assert_eq!(
            uuid.as_bytes(),
            &[
                0x12, 0x3e, 0x45, 0x67, 0xe8, 0x9b, 0x12, 0xd3, 0xa4, 0x56, 0x42, 0x66, 0x14, 0x17,
                0x40, 0x00
            ]
        );
        assert_eq!(uuid.to_text(), text);
    }

    #[test]
    fn uuid_plain_32hex_accepted_and_case_insensitive() {
        let a = VlessUuid::parse("123E4567E89B12D3A456426614174000").unwrap();
        let b = VlessUuid::parse("123e4567-e89b-12d3-a456-426614174000").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn uuid_invalid_inputs_rejected() {
        // 长度不对
        assert_eq!(
            VlessError::InvalidUuid,
            VlessUuid::parse("123e4567").unwrap_err()
        );
        // 非法 hex 字符
        assert_eq!(
            VlessError::InvalidUuid,
            VlessUuid::parse("123e4567-e89b-12d3-a456-42661417400g").unwrap_err()
        );
        // 连字符位置错误
        assert_eq!(
            VlessError::InvalidUuid,
            VlessUuid::parse("123e4567e89b-12d3-a456-426614174000").unwrap_err()
        );
        // 错误信息不回显输入
        let err = VlessUuid::parse("secret-uuid-input")
            .unwrap_err()
            .to_string();
        assert!(!err.contains("secret"));
    }

    // ----- Addon -----

    #[test]
    fn addon_empty_flow_encodes_to_empty() {
        assert!(VlessFlow::None.addon_bytes().is_empty());
    }

    #[test]
    fn addon_vision_encodes_protobuf_field1_len16() {
        let addon = VlessFlow::XtlsRprxVision.addon_bytes();
        assert_eq!(addon.len(), 18);
        assert_eq!(&addon[..2], &[0x0A, 0x10]);
        assert_eq!(&addon[2..], b"xtls-rprx-vision");
    }

    #[test]
    fn flow_parse_rejects_unknown() {
        assert_eq!(VlessFlow::parse("").unwrap(), VlessFlow::None);
        assert_eq!(
            VlessFlow::parse("xtls-rprx-vision").unwrap(),
            VlessFlow::XtlsRprxVision
        );
        // 旧废弃 flow 同样拒绝
        assert_eq!(
            VlessError::UnsupportedFlow,
            VlessFlow::parse("xtls-rprx-direct").unwrap_err()
        );
        assert_eq!(
            VlessError::UnsupportedFlow,
            VlessFlow::parse("xtls-rprx-vision-udp443").unwrap_err()
        );
    }

    // ----- 请求头 -----

    #[test]
    fn request_header_roundtrip_tcp_ipv4() {
        let req = VlessRequest {
            uuid: test_uuid(),
            flow: VlessFlow::None,
            command: VlessCommand::Tcp,
            port: 443,
            target: Some(VlessTarget::Ipv4(Ipv4Addr::new(1, 2, 3, 4))),
        };
        let bytes = encode_request(&req).unwrap();
        let (decoded, consumed) = decode_request(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(decoded, req);
    }

    #[test]
    fn request_header_roundtrip_udp_domain_vision() {
        let req = VlessRequest {
            uuid: test_uuid(),
            flow: VlessFlow::XtlsRprxVision,
            command: VlessCommand::Udp,
            port: 53,
            target: Some(VlessTarget::Domain("dns.example.com".to_string())),
        };
        let bytes = encode_request(&req).unwrap();
        let (decoded, consumed) = decode_request(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(decoded, req);
    }

    #[test]
    fn request_header_roundtrip_ipv6() {
        let req = VlessRequest {
            uuid: test_uuid(),
            flow: VlessFlow::None,
            command: VlessCommand::Tcp,
            port: 80,
            target: Some(VlessTarget::Ipv6(Ipv6Addr::LOCALHOST)),
        };
        let bytes = encode_request(&req).unwrap();
        let (decoded, _) = decode_request(&bytes).unwrap();
        assert_eq!(decoded, req);
    }

    #[test]
    fn request_header_port_comes_before_addr_type() {
        // 关键顺序回归测试：port(2 BE) 必须在 addr_type(1) 之前（§2.1 强调）。
        let req = VlessRequest {
            uuid: test_uuid(),
            flow: VlessFlow::None,
            command: VlessCommand::Tcp,
            port: 0x1234,
            target: Some(VlessTarget::Ipv4(Ipv4Addr::new(9, 9, 9, 9))),
        };
        let bytes = encode_request(&req).unwrap();
        // 布局：version(1) + uuid(16) + addon_len(1)=0 + command(1) = 19 字节前缀
        assert_eq!(bytes[0], VLESS_VERSION);
        assert_eq!(bytes[17], 0x00); // addon_len
        assert_eq!(bytes[18], 0x01); // command = TCP
        assert_eq!(&bytes[19..21], &[0x12, 0x34]); // port BE
        assert_eq!(bytes[21], 0x01); // addr_type = IPv4
        assert_eq!(&bytes[22..26], &[9, 9, 9, 9]);
        assert_eq!(bytes.len(), 26);
    }

    #[test]
    fn request_header_mux_carries_no_address() {
        let req = VlessRequest {
            uuid: test_uuid(),
            flow: VlessFlow::None,
            command: VlessCommand::Mux,
            port: 0,
            target: None,
        };
        let bytes = encode_request(&req).unwrap();
        // version(1) + uuid(16) + addon_len(1) + command(1) = 19，无 port/address。
        assert_eq!(bytes.len(), 19);
        assert_eq!(bytes[18], 0x03);
        let (decoded, consumed) = decode_request(&bytes).unwrap();
        assert_eq!(consumed, 19);
        assert_eq!(decoded.command, VlessCommand::Mux);
        assert_eq!(decoded.target, None);
    }

    #[test]
    fn request_header_rejects_bad_inputs() {
        // version 错误
        let mut bad = encode_request(&VlessRequest {
            uuid: test_uuid(),
            flow: VlessFlow::None,
            command: VlessCommand::Tcp,
            port: 80,
            target: Some(VlessTarget::Ipv4(Ipv4Addr::LOCALHOST)),
        })
        .unwrap();
        bad[0] = 0x01;
        assert!(matches!(
            decode_request(&bad),
            Err(VlessError::InvalidVersion { version: 0x01 })
        ));
        // 截断（用未篡改 version 的新编码）
        let full = encode_request(&VlessRequest {
            uuid: test_uuid(),
            flow: VlessFlow::None,
            command: VlessCommand::Tcp,
            port: 80,
            target: Some(VlessTarget::Ipv4(Ipv4Addr::LOCALHOST)),
        })
        .unwrap();
        let short = &full[..10];
        assert_eq!(
            VlessError::TruncatedHeader,
            decode_request(short).unwrap_err()
        );
        // 未知 command
        let mut bad_cmd = encode_request(&VlessRequest {
            uuid: test_uuid(),
            flow: VlessFlow::None,
            command: VlessCommand::Tcp,
            port: 80,
            target: Some(VlessTarget::Ipv4(Ipv4Addr::LOCALHOST)),
        })
        .unwrap();
        bad_cmd[18] = 0x09;
        assert!(matches!(
            decode_request(&bad_cmd),
            Err(VlessError::InvalidCommand { cmd: 0x09 })
        ));
        // TCP 缺目标
        assert_eq!(
            VlessError::MissingTarget,
            encode_request(&VlessRequest {
                uuid: test_uuid(),
                flow: VlessFlow::None,
                command: VlessCommand::Tcp,
                port: 80,
                target: None,
            })
            .unwrap_err()
        );
        // 空域名
        assert_eq!(
            VlessError::InvalidDomain,
            encode_request(&VlessRequest {
                uuid: test_uuid(),
                flow: VlessFlow::None,
                command: VlessCommand::Tcp,
                port: 80,
                target: Some(VlessTarget::Domain(String::new())),
            })
            .unwrap_err()
        );
    }

    // ----- 响应头惰性读 -----

    #[test]
    fn response_header_roundtrip() {
        let resp = VlessResponse {
            version: VLESS_VERSION,
            addon: vec![],
        };
        let bytes = encode_response(&resp);
        assert_eq!(bytes, vec![0x00, 0x00]);
        let mut cursor = std::io::Cursor::new(bytes);
        let decoded = read_response(&mut cursor).unwrap();
        assert_eq!(decoded, resp);
    }

    #[test]
    fn response_header_with_addon_is_consumed_and_discarded() {
        let resp = VlessResponse {
            version: VLESS_VERSION,
            addon: vec![0xAA, 0xBB],
        };
        let mut data = encode_response(&resp);
        data.extend_from_slice(b"PAYLOAD");
        let mut cursor = std::io::Cursor::new(data);
        let decoded = read_response(&mut cursor).unwrap();
        assert_eq!(decoded.addon, vec![0xAA, 0xBB]);
        // 响应头之后紧跟载荷：惰性消费不能多读/少读。
        let mut rest = Vec::new();
        cursor.read_to_end(&mut rest).unwrap();
        assert_eq!(rest, b"PAYLOAD");
    }

    #[test]
    fn response_bad_version_rejected() {
        let mut cursor = std::io::Cursor::new(vec![0x01, 0x00]);
        assert!(matches!(
            read_response(&mut cursor),
            Err(VlessError::InvalidVersion { version: 0x01 })
        ));
    }

    // ----- UDP-over-TCP -----

    #[test]
    fn udp_datagram_roundtrip() {
        let payloads: Vec<Vec<u8>> = vec![
            b"hello".to_vec(),
            vec![],
            (0..300u16).map(|i| (i % 251) as u8).collect(),
        ];
        let mut stream = Vec::new();
        for p in &payloads {
            stream.extend_from_slice(&encode_udp_datagram(p).unwrap());
        }
        // 逐包读
        let mut cursor = std::io::Cursor::new(&stream);
        for expected in &payloads {
            assert_eq!(&read_udp_datagram(&mut cursor).unwrap(), expected);
        }
        // 整体切分
        assert_eq!(decode_udp_datagrams(&stream).unwrap(), payloads);
    }

    #[test]
    fn udp_datagram_truncated_tail_rejected() {
        let mut stream = encode_udp_datagram(b"abc").unwrap();
        stream.extend_from_slice(&[0x00]); // 半个长度前缀
        assert_eq!(
            VlessError::TruncatedDatagram,
            decode_udp_datagrams(&stream).unwrap_err()
        );
        let mut stream2 = encode_udp_datagram(b"abcdef").unwrap();
        stream2.truncate(stream2.len() - 2); // 包体缺 2 字节
        assert_eq!(
            VlessError::TruncatedDatagram,
            decode_udp_datagrams(&stream2).unwrap_err()
        );
    }

    #[test]
    fn udp_datagram_too_large_rejected() {
        let big = vec![0u8; 65536];
        assert!(matches!(
            encode_udp_datagram(&big),
            Err(VlessError::DatagramTooLarge { len: 65536 })
        ));
    }

    // ----- Vision 帧 -----

    #[test]
    fn vision_frame_roundtrip_first_and_subsequent() {
        let uuid = *test_uuid().as_bytes();
        let content = b"inner tls bytes";
        // 首帧：21 字节头（含 UUID）
        let first = encode_vision_frame(true, &uuid, VisionCommand::Continue, content, 37);
        assert_eq!(first.len(), 21 + content.len() + 37);
        assert_eq!(&first[..16], &uuid);
        assert_eq!(first[16], 0x00); // CONTINUE
        assert_eq!(&first[17..19], &(content.len() as u16).to_be_bytes());
        assert_eq!(&first[19..21], &37u16.to_be_bytes());
        assert!(first[21 + content.len()..].iter().all(|b| *b == 0));
        // 后续帧：5 字节头（无 UUID）
        let next = encode_vision_frame(false, &uuid, VisionCommand::Continue, content, 0);
        assert_eq!(next.len(), 5 + content.len());
        assert_eq!(next[0], 0x00);
        // 解码器对称还原
        let mut reader = VisionReader::new();
        let mut stream = Vec::new();
        stream.extend_from_slice(&first);
        stream.extend_from_slice(&next);
        let mut cursor = std::io::Cursor::new(stream);
        let (cmd1, c1) = reader.read_frame(&mut cursor, &uuid).unwrap();
        assert_eq!(
            (cmd1, c1.as_slice()),
            (VisionCommand::Continue, &content[..])
        );
        let (cmd2, c2) = reader.read_frame(&mut cursor, &uuid).unwrap();
        assert_eq!(
            (cmd2, c2.as_slice()),
            (VisionCommand::Continue, &content[..])
        );
        assert!(!reader.is_ended());
    }

    #[test]
    fn vision_frame_end_and_direct_terminate_reader() {
        let uuid = *test_uuid().as_bytes();
        for cmd in [VisionCommand::End, VisionCommand::Direct] {
            let mut reader = VisionReader::new();
            let frame = encode_vision_frame(true, &uuid, cmd, b"tail", 0);
            let mut cursor = std::io::Cursor::new(frame);
            let (got, content) = reader.read_frame(&mut cursor, &uuid).unwrap();
            assert_eq!(got, cmd);
            assert_eq!(content, b"tail");
            assert!(reader.is_ended());
            // END 后再读帧 → 错误
            let frame2 = encode_vision_frame(false, &uuid, VisionCommand::Continue, b"x", 0);
            let mut cursor2 = std::io::Cursor::new(frame2);
            assert_eq!(
                VlessError::VisionAlreadyEnded,
                reader.read_frame(&mut cursor2, &uuid).unwrap_err()
            );
        }
    }

    #[test]
    fn vision_frame_uuid_mismatch_rejected() {
        let uuid = *test_uuid().as_bytes();
        let other = [0xFFu8; 16];
        let frame = encode_vision_frame(true, &other, VisionCommand::Continue, b"x", 0);
        let mut reader = VisionReader::new();
        let mut cursor = std::io::Cursor::new(frame);
        let err = reader.read_frame(&mut cursor, &uuid).unwrap_err();
        assert_eq!(VlessError::VisionUuidMismatch, err);
        // 错误信息不泄露 UUID
        assert!(!err.to_string().contains("ff"));
    }

    #[test]
    fn vision_frame_unknown_command_rejected() {
        let uuid = *test_uuid().as_bytes();
        let mut reader = VisionReader::new();
        // 先消费一个合法首帧，进入后续帧模式（5 字节头）。
        let first = encode_vision_frame(true, &uuid, VisionCommand::Continue, b"x", 0);
        let mut c0 = std::io::Cursor::new(first);
        reader.read_frame(&mut c0, &uuid).unwrap();
        // 后续帧头 command 非法 → fail-closed。
        let mut frame = encode_vision_frame(false, &uuid, VisionCommand::Continue, b"x", 0);
        frame[0] = 0x07;
        let mut cursor = std::io::Cursor::new(frame);
        assert_eq!(
            VlessError::InvalidVisionFrame,
            reader.read_frame(&mut cursor, &uuid).unwrap_err()
        );
    }

    // ----- Vision 写状态机 -----

    /// 最小 TLS ClientHello 记录：`0x16 0x03 0x01 | len | 0x01 ...`。
    fn client_hello_chunk() -> Vec<u8> {
        let mut v = vec![0x16, 0x03, 0x01, 0x00, 0x20, 0x01];
        v.extend(std::iter::repeat_n(0xABu8, 32));
        v
    }

    /// 最小 TLS Application Data 记录头。
    fn app_data_chunk() -> Vec<u8> {
        let mut v = vec![0x17, 0x03, 0x03, 0x00, 0x10];
        v.extend(std::iter::repeat_n(0xCDu8, 16));
        v
    }

    #[test]
    fn vision_write_state_machine_hello_then_appdata_ends() {
        let uuid = *test_uuid().as_bytes();
        let mut w = VisionWriter::new(uuid, false, 42);
        assert_eq!(w.phase(), VisionWritePhase::Padding);
        assert!(!w.seen_tls());

        // ClientHello → CONTINUE 帧（带 padding），标记 seen_tls
        let out1 = w.write_chunk(&client_hello_chunk());
        assert!(w.seen_tls());
        assert_eq!(w.phase(), VisionWritePhase::Padding);
        assert_eq!(&out1[..16], &uuid); // 首帧带 UUID
        assert_eq!(out1[16], VisionCommand::Continue.as_u8());
        let content_len = u16::from_be_bytes([out1[17], out1[18]]) as usize;
        assert_eq!(content_len, client_hello_chunk().len());
        let padding_len = u16::from_be_bytes([out1[19], out1[20]]) as usize;
        // 见过 TLS：padding 补到约 900~1400
        assert!((900 - content_len..1400 - content_len).contains(&padding_len));

        // 第二个握手包（无 AppData）→ 仍然 CONTINUE
        let out2 = w.write_chunk(&[0x16, 0x03, 0x03, 0x00, 0x05, 0x14, 1, 2, 3, 4, 5]);
        assert_eq!(out2[0], VisionCommand::Continue.as_u8()); // 后续帧无 UUID
        assert_eq!(w.phase(), VisionWritePhase::Padding);

        // Application Data → END 帧（含剩余数据），之后透传
        let app = app_data_chunk();
        let out3 = w.write_chunk(&app);
        assert_eq!(out3[0], VisionCommand::End.as_u8());
        let content_len3 = u16::from_be_bytes([out3[1], out3[2]]) as usize;
        assert_eq!(content_len3, app.len());
        assert_eq!(&out3[5..5 + app.len()], &app[..]);
        assert_eq!(w.phase(), VisionWritePhase::Passthrough);

        // 之后写块原样透传
        let raw = b"raw after end";
        assert_eq!(w.write_chunk(raw), raw);
    }

    #[test]
    fn vision_write_state_machine_direct_mode() {
        let uuid = *test_uuid().as_bytes();
        let mut w = VisionWriter::new(uuid, true, 7);
        let hello_out = w.write_chunk(&client_hello_chunk());
        let out = w.write_chunk(&app_data_chunk());
        assert_eq!(out[0], VisionCommand::Direct.as_u8());
        assert_eq!(w.phase(), VisionWritePhase::Passthrough);
        // 读侧语义由 VisionReader 保证：先消费首帧，再读 DIRECT 帧
        let mut reader = VisionReader::new();
        let mut c0 = std::io::Cursor::new(hello_out);
        let (cmd0, _) = reader.read_frame(&mut c0, &uuid).unwrap();
        assert_eq!(cmd0, VisionCommand::Continue);
        let mut cursor = std::io::Cursor::new(out);
        let (cmd, _) = reader.read_frame(&mut cursor, &uuid).unwrap();
        assert_eq!(cmd, VisionCommand::Direct);
        assert!(reader.is_ended());
    }

    #[test]
    fn vision_write_state_machine_non_tls_ends_immediately() {
        // 非 TLS 内层流量（首个写块无 ClientHello）→ 直接 END，不做多余填充。
        let uuid = *test_uuid().as_bytes();
        let mut w = VisionWriter::new(uuid, false, 99);
        let http = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let out = w.write_chunk(http);
        assert!(!w.seen_tls());
        assert_eq!(out[16], VisionCommand::End.as_u8());
        let padding_len = u16::from_be_bytes([out[19], out[20]]) as usize;
        assert_eq!(padding_len, 0);
        assert_eq!(w.phase(), VisionWritePhase::Passthrough);
    }

    #[test]
    fn vision_padding_strategy_ranges() {
        let mut rng = XorShift64::new(1234);
        // 见过 TLS：900~1400 区间
        for _ in 0..50 {
            let p = vision_padding_len(100, true, &mut rng);
            assert!((800..1300).contains(&p), "padding {p} out of range");
        }
        // 未见过 TLS：0~255
        for _ in 0..50 {
            let p = vision_padding_len(100, false, &mut rng);
            assert!(p < 256, "padding {p} out of range");
        }
        // >= 900：不填充
        assert_eq!(vision_padding_len(900, true, &mut rng), 0);
        assert_eq!(vision_padding_len(1500, false, &mut rng), 0);
        // 确定性：同一种子产生同一序列
        let mut r1 = XorShift64::new(5);
        let mut r2 = XorShift64::new(5);
        for _ in 0..10 {
            assert_eq!(
                vision_padding_len(10, true, &mut r1),
                vision_padding_len(10, true, &mut r2)
            );
        }
    }

    // ----- client↔server 最小握手（loopback TCP duplex） -----

    fn loopback_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).unwrap();
        let (server, _) = listener.accept().unwrap();
        (client, server)
    }

    #[test]
    fn client_server_minimal_handshake_with_lazy_response() {
        let uuid = test_uuid();
        let req = VlessRequest {
            uuid,
            flow: VlessFlow::None,
            command: VlessCommand::Tcp,
            port: 443,
            target: Some(VlessTarget::Domain("example.com".to_string())),
        };
        let (client_sock, server_sock) = loopback_pair();

        // server 线程：读请求头 → 读首个载荷字节（证明 client 没在握手时等响应）→
        // 写响应头 → 回显载荷。
        let server = std::thread::spawn(move || {
            let mut server_sock = server_sock;
            // 先读请求头：需要知道读多少字节——用 decode_request 的 consumed 语义，
            // 这里简化：读固定 1+16+1+0+1+2+1+1+11 = 34 字节后解析。
            let mut head = vec![0u8; 34];
            server_sock.read_exact(&mut head).unwrap();
            let (parsed, consumed) = decode_request(&head).unwrap();
            assert_eq!(consumed, 34);
            assert_eq!(parsed.command, VlessCommand::Tcp);
            assert_eq!(parsed.port, 443);
            assert_eq!(
                parsed.target,
                Some(VlessTarget::Domain("example.com".to_string()))
            );
            // 读 client 紧跟请求头写出的载荷（client 未阻塞等响应，证明惰性读无死锁）
            let mut one = [0u8; 1];
            server_sock.read_exact(&mut one).unwrap();
            assert_eq!(one, [0xAB]);
            // 现在才写响应头
            server_sock
                .write_all(&encode_response(&VlessResponse {
                    version: VLESS_VERSION,
                    addon: vec![],
                }))
                .unwrap();
            // 回显
            server_sock.write_all(&one).unwrap();
            server_sock.flush().unwrap();
        });

        // client：握手只写请求头 → 立刻写载荷（不等响应）→ 首次 read 惰性消费响应头。
        let mut conn = VlessConn::new(client_sock);
        conn.handshake(&req).unwrap();
        assert!(conn.response_pending());
        conn.write_all(&[0xABu8]).unwrap();
        conn.flush().unwrap();
        // 首次 read：先消费 2 字节响应头，再返回 server 回显
        let mut buf = [0u8; 8];
        let n = conn.read(&mut buf).unwrap();
        assert!(!conn.response_pending());
        assert_eq!(n, 1);
        assert_eq!(buf[0], 0xAB);
        server.join().unwrap();
    }

    #[test]
    fn vless_conn_passthrough_after_response_consumed() {
        let (client_sock, server_sock) = loopback_pair();
        let server = std::thread::spawn(move || {
            let mut s = server_sock;
            let mut buf = [0u8; 4];
            s.read_exact(&mut buf).unwrap();
            s.write_all(&[0x00, 0x00]).unwrap(); // 响应头
            s.write_all(b"echo").unwrap();
            s.flush().unwrap();
        });
        let mut conn = VlessConn::new(client_sock);
        conn.write_all(b"ping").unwrap();
        conn.flush().unwrap();
        // 手动标记 response_pending（绕过 handshake，直接测惰性读路径）
        conn.response_pending = true;
        let mut buf = [0u8; 4];
        conn.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"echo");
        assert!(!conn.response_pending());
        server.join().unwrap();
    }

    // ----- 配置门禁与 Adapter -----

    #[test]
    fn config_rejects_vision_without_tls() {
        let cfg = VlessConfig {
            tag: "v".to_string(),
            locator: "example.com:443".to_string(),
            uuid: test_uuid(),
            flow: VlessFlow::XtlsRprxVision,
            tls: false,
            vision_direct: false,
        };
        assert_eq!(VlessError::VisionRequiresTls, cfg.validate().unwrap_err());
        let cfg_tls = VlessConfig { tls: true, ..cfg };
        assert!(cfg_tls.validate().is_ok());
    }

    #[test]
    fn adapter_kind_tag_handoff() {
        let adapter = VlessAdapter::new(
            "vless-out",
            "example.com:443",
            test_uuid(),
            VlessFlow::XtlsRprxVision,
        );
        assert_eq!(adapter.outbound_kind(), "vless");
        assert_eq!(adapter.tag(), "vless-out");
        assert_eq!(adapter.locator(), "example.com:443");
        assert_eq!(adapter.flow(), VlessFlow::XtlsRprxVision);
        let handoff = adapter.handoff("example.com:443").unwrap();
        assert_eq!(handoff.kind, "vless");
        assert_eq!(handoff.tag, "vless-out");
        assert_eq!(handoff.locator, "example.com:443");
    }

    #[test]
    fn adapter_from_config_applies_gate() {
        let bad = VlessConfig {
            tag: "v".to_string(),
            locator: "example.com:443".to_string(),
            uuid: test_uuid(),
            flow: VlessFlow::XtlsRprxVision,
            tls: false,
            vision_direct: false,
        };
        assert!(VlessAdapter::from_config(&bad).is_err());
    }
}

#[cfg(test)]
mod warn2_failure_path_tests {
    use super::*;

    // WARN2: 非法 UUID → 握手拒绝（fail-closed，不回显输入）。
    #[test]
    fn invalid_uuid_rejected() {
        for bad in [
            "",
            "not-a-uuid",
            "12345678-1234-1234-1234-12345678901",   // 35 chars
            "12345678-1234-1234-1234-1234567890123", // 37 chars
            "zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz",  // non-hex
        ] {
            let err = VlessUuid::parse(bad).unwrap_err();
            assert_eq!(err, VlessError::InvalidUuid, "input: {bad}");
            // 不回显输入原文（空字符串跳过）。
            if !bad.is_empty() {
                assert!(!format!("{err}").contains(bad));
            }
        }
    }
}
