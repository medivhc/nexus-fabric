//! nexus-outbound-anytls
//!
//! AnyTLS 出站 adapter：实现 `nexus-connectivity::OutboundAdapter`，在一条 TLS
//! 连接（rustls 0.23 + ring）上承载 AnyTLS v2 会话层多路复用。
//!
//! 协议语义见 `docs/protocols/anytls.md`（clean-room 实现，不拷贝任何既有代码）。
//! 本 crate 覆盖协议中已确认的部分：
//!
//! - 认证帧：`SHA256(password)(32) + u16BE(padding0_len) + padding0`，**拼成一个
//!   buffer 一次 `write`**（§5 坑 #1：官方实现单次 `ReadOnceFrom` 读认证；rustls
//!   一次 `write_all` 对应一个 TLS record，分开写会导致对端读 padding 长度时 EOF）。
//! - 7 字节会话帧头：`cmd(1) + stream_id(u32 BE) + data_len(u16 BE)`，命令 0~10。
//! - Settings 文本（`v/client/padding-md5`）与 ServerSettings / UpdatePaddingScheme。
//! - 默认 padding scheme 数据结构与 `padding-md5`（MD5 小写 hex）计算。
//! - SOCKS5 地址编码（首个 PSH 用）。
//! - UDP-over-TCP（sing-box v2）：魔法地址、eager Connect 载荷、`u16 BE` 长度前缀分包。
//! - server 侧最小握手（测试用）：一次读认证、校验 SHA256、Settings 前收到 SYN 则
//!   发 Alert 并拒绝、回 ServerSettings。
//!
//! 未确认的细节（如 UoT 包内分片）按文档已确认部分实现，注释中标 `// 未确认：`。
//!
//! 离线确定性 E4：rcgen 动态自签证书，客户端把该唯一证书作为唯一信任根（公钥 pin），
//! loopback 127.0.0.1 同一进程内 TLS server+client；不连公网。

#![forbid(unsafe_code)]

use std::io::{Read, Write};

use nexus_proxy_config::outbound_seam::{OutboundAdapter, OutboundHandoff, OutboundHandoffError};
use sha2::{Digest, Sha256};

// ---------- 结构化错误 ----------

/// AnyTLS 出站结构化错误（不以日志文本代替类型）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnyTlsError {
    /// 认证 hash 不匹配（不泄露密码/hash）。
    AuthDenied,
    /// 帧头/帧体长度或布局非法。
    InvalidFrame,
    /// Settings 文本解析失败。
    InvalidSettings,
    /// padding scheme 文本解析失败（附行号，0 起）。
    InvalidPaddingScheme { line: usize },
    /// SOCKS5 地址编码/解码失败。
    InvalidAddress,
    /// 收到协议不允许的命令（如 Settings 之前收到 SYN、握手阶段收到未知方向帧）。
    UnexpectedCommand { cmd: u8, stream_id: u32 },
    /// 服务器 SYNACK 带错误文本，stream 打开被拒绝。
    StreamRejected { stream_id: u32, reason: String },
    /// 服务器下发新 padding scheme（cmd=6）：调用方应切换 scheme 后重建 session。
    PaddingSchemeUpdated { scheme: Vec<u8> },
    /// TLS 配置或握手失败。
    Tls,
    /// 底层 I/O 失败。
    Io,
}

impl core::fmt::Display for AnyTlsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::AuthDenied => write!(f, "anytls auth denied"),
            Self::InvalidFrame => write!(f, "anytls invalid frame"),
            Self::InvalidSettings => write!(f, "anytls invalid settings"),
            Self::InvalidPaddingScheme { line } => {
                write!(f, "anytls invalid padding scheme at line {line}")
            }
            Self::InvalidAddress => write!(f, "anytls invalid address"),
            Self::UnexpectedCommand { cmd, stream_id } => {
                write!(f, "anytls unexpected command {cmd} on stream {stream_id}")
            }
            Self::StreamRejected { stream_id, reason } => {
                write!(f, "anytls stream {stream_id} rejected: {reason}")
            }
            Self::PaddingSchemeUpdated { .. } => {
                write!(f, "anytls server requested padding scheme update")
            }
            Self::Tls => write!(f, "anytls tls error"),
            Self::Io => write!(f, "anytls io error"),
        }
    }
}

impl std::error::Error for AnyTlsError {}

impl From<std::io::Error> for AnyTlsError {
    fn from(_: std::io::Error) -> Self {
        Self::Io
    }
}

// ---------- 命令表（§3.3） ----------

/// AnyTLS 会话层命令（u8）。
///
/// 未知命令值按 `Waste` 处理（协议建议：对协议扩展友好；注意这也可能掩盖对端 bug）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AnyTlsCommand {
    /// 0：填充；收到后完整读出 data 并静默丢弃。
    Waste = 0,
    /// 1：C→S，打开新 stream。
    Syn = 1,
    /// 2：双向，承载 stream 数据；首个 PSH 的 data 以 SOCKS5 地址开头。
    Psh = 2,
    /// 3：双向，关闭 stream（EOF 标记）。
    Fin = 3,
    /// 4：C→S，客户端设置；每个新 session 必须立即发送。
    Settings = 4,
    /// 5：S→C，服务器警告文本；双方随后关闭 session。
    Alert = 5,
    /// 6：S→C，下发新 padding scheme（原始 scheme 文本）。
    UpdatePaddingScheme = 6,
    /// 7：S→C，v2+；stream 打开确认，无 data=成功，带 data=错误文本。
    SynAck = 7,
    /// 8：双向，keep-alive 请求。
    HeartRequest = 8,
    /// 9：双向，keep-alive 响应。
    HeartResponse = 9,
    /// 10：S→C，v2+；服务器设置（`v=2`）。
    ServerSettings = 10,
}

impl AnyTlsCommand {
    /// 从 u8 解析；未知值按 `Waste` 处理（§3.3 建议）。
    #[must_use]
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Waste,
            1 => Self::Syn,
            2 => Self::Psh,
            3 => Self::Fin,
            4 => Self::Settings,
            5 => Self::Alert,
            6 => Self::UpdatePaddingScheme,
            7 => Self::SynAck,
            8 => Self::HeartRequest,
            9 => Self::HeartResponse,
            10 => Self::ServerSettings,
            _ => Self::Waste,
        }
    }

    /// 命令字节值。
    #[must_use]
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

// ---------- 7 字节帧头编解码（§3.2） ----------

/// 会话帧头长度（字节）。
pub const FRAME_HEADER_LEN: usize = 7;
/// 单帧 data 最大长度（u16 上限）。
pub const MAX_FRAME_DATA_LEN: usize = u16::MAX as usize;

/// AnyTLS 会话层帧。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnyTlsFrame {
    /// 命令。
    pub cmd: AnyTlsCommand,
    /// 大端 u32；控制帧（Settings/心跳等）用 0。
    pub stream_id: u32,
    /// 命令负载。
    pub data: Vec<u8>,
}

/// 编码一帧：7 字节头 + data。
///
/// # Errors
///
/// `data` 超过 65535 字节返回 `InvalidFrame`。
pub fn encode_frame(
    cmd: AnyTlsCommand,
    stream_id: u32,
    data: &[u8],
) -> Result<Vec<u8>, AnyTlsError> {
    if data.len() > MAX_FRAME_DATA_LEN {
        return Err(AnyTlsError::InvalidFrame);
    }
    let mut out = Vec::with_capacity(FRAME_HEADER_LEN + data.len());
    out.push(cmd.as_u8());
    out.extend_from_slice(&stream_id.to_be_bytes());
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
    Ok(out)
}

/// 从字节缓冲解码一帧，返回（帧，消耗字节数）。
///
/// # Errors
///
/// 缓冲不足或布局非法返回 `InvalidFrame`。
pub fn decode_frame_bytes(buf: &[u8]) -> Result<(AnyTlsFrame, usize), AnyTlsError> {
    if buf.len() < FRAME_HEADER_LEN {
        return Err(AnyTlsError::InvalidFrame);
    }
    let cmd = AnyTlsCommand::from_u8(buf[0]);
    let stream_id = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
    let data_len = u16::from_be_bytes([buf[5], buf[6]]) as usize;
    if buf.len() < FRAME_HEADER_LEN + data_len {
        return Err(AnyTlsError::InvalidFrame);
    }
    let data = buf[FRAME_HEADER_LEN..FRAME_HEADER_LEN + data_len].to_vec();
    Ok((
        AnyTlsFrame {
            cmd,
            stream_id,
            data,
        },
        FRAME_HEADER_LEN + data_len,
    ))
}

/// 从流读出一帧（先读 7 字节头，再按长度读 data；cmdWaste 的 data 由此一并读出丢弃）。
///
/// # Errors
///
/// I/O 失败或帧非法返回 `Io`/`InvalidFrame`。
pub fn read_frame<R: Read>(reader: &mut R) -> Result<AnyTlsFrame, AnyTlsError> {
    let mut header = [0u8; FRAME_HEADER_LEN];
    reader.read_exact(&mut header)?;
    let cmd = AnyTlsCommand::from_u8(header[0]);
    let stream_id = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);
    let data_len = u16::from_be_bytes([header[5], header[6]]) as usize;
    let mut data = vec![0u8; data_len];
    reader.read_exact(&mut data)?;
    Ok(AnyTlsFrame {
        cmd,
        stream_id,
        data,
    })
}

/// 向流写入一帧。
///
/// # Errors
///
/// `data` 超长或 I/O 失败返回 `InvalidFrame`/`Io`。
pub fn write_frame<W: Write>(
    writer: &mut W,
    cmd: AnyTlsCommand,
    stream_id: u32,
    data: &[u8],
) -> Result<(), AnyTlsError> {
    let buf = encode_frame(cmd, stream_id, data)?;
    writer.write_all(&buf)?;
    writer.flush()?;
    Ok(())
}

// ---------- 认证帧（§3.1） ----------

/// `SHA256(password)` 长度（字节）。
pub const AUTH_HASH_LEN: usize = 32;
/// 认证固定开销：32 字节 hash + 2 字节 padding0 长度。
pub const AUTH_OVERHEAD: usize = AUTH_HASH_LEN + 2;

/// 计算 `SHA256(password)`（password 取 UTF-8 字节原文）。
#[must_use]
pub fn auth_digest(password: &str) -> [u8; AUTH_HASH_LEN] {
    let digest = Sha256::digest(password.as_bytes());
    let mut out = [0u8; AUTH_HASH_LEN];
    out.copy_from_slice(&digest);
    out
}

/// 构造认证请求字节：`SHA256(password) + u16BE(padding0_len) + padding0`。
///
/// padding0 填零（文档建议）。返回的 buffer 应**一次 `write`** 发出（§5 坑 #1）。
///
/// # Errors
///
/// `padding0_len` 超出 u16 范围返回 `InvalidFrame`。
#[must_use]
pub fn encode_auth(password: &str, padding0_len: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(AUTH_OVERHEAD + padding0_len as usize);
    out.extend_from_slice(&auth_digest(password));
    out.extend_from_slice(&padding0_len.to_be_bytes());
    out.resize(AUTH_OVERHEAD + padding0_len as usize, 0);
    out
}

/// 一次写发送认证请求（client 侧）。
///
/// 32+2+padding0 拼成一个 buffer 后单次 `write_all`：rustls 下一次 `write_all`
/// 对应一个 TLS record；若分三次写，官方实现单次读只拿到第一个 record，读
/// padding 长度时 EOF（§5 坑 #1）。
///
/// # Errors
///
/// I/O 失败返回 `Io`。
pub fn send_auth<W: Write>(
    writer: &mut W,
    password: &str,
    padding0_len: u16,
) -> Result<(), AnyTlsError> {
    let buf = encode_auth(password, padding0_len);
    writer.write_all(&buf)?;
    writer.flush()?;
    Ok(())
}

/// 校验完整认证缓冲（server 侧纯函数）：hash 不匹配 → `AuthDenied`（不泄露 hash）；
/// 长度不符 → `InvalidFrame`。返回 padding0 长度。
///
/// # Errors
///
/// 认证失败返回 `AuthDenied`；缓冲长度非法返回 `InvalidFrame`。
pub fn parse_auth(password: &str, buf: &[u8]) -> Result<u16, AnyTlsError> {
    if buf.len() < AUTH_OVERHEAD {
        return Err(AnyTlsError::InvalidFrame);
    }
    let padding0_len = u16::from_be_bytes([buf[32], buf[33]]);
    if buf.len() != AUTH_OVERHEAD + padding0_len as usize {
        return Err(AnyTlsError::InvalidFrame);
    }
    let expected = auth_digest(password);
    if !constant_time_eq(&buf[..AUTH_HASH_LEN], &expected) {
        return Err(AnyTlsError::AuthDenied);
    }
    Ok(padding0_len)
}

/// 定长比较（避免把 hash 内容带进错误/日志）。
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// server 侧一次读认证：读 34 字节头 → 校验 SHA256 → 完整读出 padding0 并丢弃。
///
/// 失败（hash 不符）则返回 `AuthDenied`，调用方应关闭连接（或 fallback 到 HTTP，
/// 本 crate 不实现 fallback）。
///
/// # Errors
///
/// 认证失败返回 `AuthDenied`；I/O 失败返回 `Io`。
pub fn recv_auth<R: Read>(reader: &mut R, password: &str) -> Result<(), AnyTlsError> {
    let mut head = [0u8; AUTH_OVERHEAD];
    reader.read_exact(&mut head)?;
    let padding0_len = u16::from_be_bytes([head[32], head[33]]);
    let expected = auth_digest(password);
    if !constant_time_eq(&head[..AUTH_HASH_LEN], &expected) {
        // 注意：不把 hash 内容写进错误。
        return Err(AnyTlsError::AuthDenied);
    }
    // 完整读出 padding0 并丢弃。
    let mut padding0 = vec![0u8; padding0_len as usize];
    reader.read_exact(&mut padding0)?;
    Ok(())
}

// ---------- Settings 文本（§3.4） ----------

/// 协议版本号（v2）。
pub const PROTOCOL_VERSION: u32 = 2;
/// 默认客户端标识（第三方实现应填真实名）。
pub const CLIENT_IDENT: &str = "nexus-anytls/0.1.0";

/// Settings 键值（client→server 含 v/client/padding-md5；server→client 仅 v）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    /// 协议版本。
    pub v: u32,
    /// client→server：客户端实现名。
    pub client: Option<String>,
    /// client→server：当前 padding scheme 原始字节的 MD5（小写 hex）。
    pub padding_md5: Option<String>,
}

/// 编码 client Settings 文本：`v=2\nclient=<name>\npadding-md5=<hex>`。
///
/// # Errors
///
/// `client` 含换行（会破坏 `key=value` 行格式）返回 `InvalidSettings`。
pub fn encode_settings(client: &str, padding_md5_hex: &str) -> Result<Vec<u8>, AnyTlsError> {
    if client.contains('\n') || client.contains('\r') {
        return Err(AnyTlsError::InvalidSettings);
    }
    Ok(
        format!("v={PROTOCOL_VERSION}\nclient={client}\npadding-md5={padding_md5_hex}")
            .into_bytes(),
    )
}

/// 编码 server Settings 文本：`v=2`。
#[must_use]
pub fn encode_server_settings() -> Vec<u8> {
    format!("v={PROTOCOL_VERSION}").into_bytes()
}

/// 解析 Settings 文本（`key=value` 行，`\n` 分隔；未知键忽略以向前兼容）。
///
/// # Errors
///
/// 非 UTF-8、无 `=` 的行、`v` 非数字返回 `InvalidSettings`。
pub fn parse_settings(data: &[u8]) -> Result<Settings, AnyTlsError> {
    let text = core::str::from_utf8(data).map_err(|_| AnyTlsError::InvalidSettings)?;
    let mut v: Option<u32> = None;
    let mut client: Option<String> = None;
    let mut padding_md5: Option<String> = None;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let (key, value) = line.split_once('=').ok_or(AnyTlsError::InvalidSettings)?;
        match key.trim() {
            "v" => {
                v = Some(
                    value
                        .trim()
                        .parse::<u32>()
                        .map_err(|_| AnyTlsError::InvalidSettings)?,
                );
            }
            "client" => client = Some(value.trim().to_string()),
            "padding-md5" => padding_md5 = Some(value.trim().to_string()),
            _ => {} // 未知键忽略（协议扩展友好）。
        }
    }
    Ok(Settings {
        v: v.ok_or(AnyTlsError::InvalidSettings)?,
        client,
        padding_md5,
    })
}

// ---------- Padding scheme（§4.1） ----------

/// 默认 padding scheme 原始文本（§4.1；`padding-md5` 即此文本原始字节的 MD5）。
///
/// 注意：md5 计算口径取**此常量文本的原始字节**（无末尾换行）；与对端协商时双方
/// 必须用同一口径。本 crate 的 client/server 握手均用同一常量，口径一致。
pub const DEFAULT_PADDING_SCHEME: &str = "\
stop=8
0=30-30
1=100-400
2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000
3=9-9,500-1000
4=500-1000
5=500-1000
6=500-1000
7=500-1000";

/// Padding 策略中的一个分段。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaddingSegment {
    /// 目标尺寸区间（**TLS PlainText 尺寸**，不计 TLS 加密开销）。
    SizeRange {
        /// 区间下限（字节）。
        min: u32,
        /// 区间上限（字节）。
        max: u32,
    },
    /// 检查点：若上一个分包发完后用户数据已无剩余，则直接返回、不再发后续填充包。
    Checkpoint,
}

/// 第 k 个 TLS 写包的目标尺寸策略。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketPaddingPolicy {
    /// 包序号（第 0 包 = 认证包，不支持分包）。
    pub packet_index: u8,
    /// 分段序列。
    pub segments: Vec<PaddingSegment>,
}

/// Padding scheme 数据结构。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaddingScheme {
    /// 只对第 0~stop-1 个 TLS 写包做 padding/分包，之后的包直接发送。
    pub stop: u8,
    /// 各包策略（按文本出现顺序）。
    pub policies: Vec<PacketPaddingPolicy>,
}

/// 解析 padding scheme 文本（`stop=N` / `k=min-max[,c,...]`）。
///
/// # Errors
///
/// 行格式非法、数字解析失败、`min > max` 返回 `InvalidPaddingScheme`（附行号）。
pub fn parse_padding_scheme(text: &str) -> Result<PaddingScheme, AnyTlsError> {
    let mut stop: Option<u8> = None;
    let mut policies = Vec::new();
    for (line_no, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let invalid = || AnyTlsError::InvalidPaddingScheme { line: line_no };
        let (key, value) = line.split_once('=').ok_or_else(invalid)?;
        if key.trim() == "stop" {
            stop = Some(value.trim().parse::<u8>().map_err(|_| invalid())?);
            continue;
        }
        let packet_index = key.trim().parse::<u8>().map_err(|_| invalid())?;
        let mut segments = Vec::new();
        for part in value.split(',') {
            let part = part.trim();
            if part == "c" {
                segments.push(PaddingSegment::Checkpoint);
            } else if let Some((min_s, max_s)) = part.split_once('-') {
                let min = min_s.trim().parse::<u32>().map_err(|_| invalid())?;
                let max = max_s.trim().parse::<u32>().map_err(|_| invalid())?;
                if min > max {
                    return Err(invalid());
                }
                segments.push(PaddingSegment::SizeRange { min, max });
            } else {
                return Err(invalid());
            }
        }
        if segments.is_empty() {
            return Err(invalid());
        }
        policies.push(PacketPaddingPolicy {
            packet_index,
            segments,
        });
    }
    Ok(PaddingScheme {
        stop: stop.ok_or(AnyTlsError::InvalidPaddingScheme { line: 0 })?,
        policies,
    })
}

/// 计算 padding scheme 原始字节的 MD5（小写 hex），即 Settings 中的 `padding-md5`。
///
/// MD5 在此仅作 scheme 一致性指纹，不承担安全职责。
#[must_use]
pub fn padding_md5_hex(scheme_text: &str) -> String {
    format!("{:x}", md5::compute(scheme_text.as_bytes()))
}

/// 解析默认 padding scheme（§4.1）。
///
/// # Errors
///
/// 常量文本格式损坏（理论上不可能）返回 `InvalidPaddingScheme`。
pub fn default_padding_scheme() -> Result<PaddingScheme, AnyTlsError> {
    parse_padding_scheme(DEFAULT_PADDING_SCHEME)
}

// ---------- SOCKS5 地址编码（首个 PSH 用） ----------

/// AnyTLS 目标地址（SOCKS5 ATYP 子集）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnyTlsTarget {
    /// ATYP=0x01 IPv4。
    Ipv4([u8; 4], u16),
    /// ATYP=0x04 IPv6。
    Ipv6([u8; 16], u16),
    /// ATYP=0x03 domain（长度 1 字节）。
    Domain(String, u16),
}

impl AnyTlsTarget {
    /// 稳定 host 标签（观测/断言用）。
    #[must_use]
    pub fn host_label(&self) -> String {
        match self {
            Self::Ipv4(oct, _) => oct.iter().map(u8::to_string).collect::<Vec<_>>().join("."),
            Self::Ipv6(seg, _) => seg
                .chunks(2)
                .map(|c| format!("{:02x}{:02x}", c[0], c[1]))
                .collect::<Vec<_>>()
                .join(":"),
            Self::Domain(d, _) => d.clone(),
        }
    }

    /// 端口。
    #[must_use]
    pub fn port(&self) -> u16 {
        match self {
            Self::Ipv4(_, p) | Self::Ipv6(_, p) | Self::Domain(_, p) => *p,
        }
    }
}

/// 编码 SOCKS5 地址：`ATYP + 地址 + port(u16 BE)`。
///
/// # Errors
///
/// 域名超过 255 字节返回 `InvalidAddress`。
pub fn encode_socks5_addr(target: &AnyTlsTarget) -> Result<Vec<u8>, AnyTlsError> {
    let mut out = Vec::new();
    match target {
        AnyTlsTarget::Ipv4(oct, port) => {
            out.push(0x01);
            out.extend_from_slice(oct);
            out.extend_from_slice(&port.to_be_bytes());
        }
        AnyTlsTarget::Ipv6(seg, port) => {
            out.push(0x04);
            out.extend_from_slice(seg);
            out.extend_from_slice(&port.to_be_bytes());
        }
        AnyTlsTarget::Domain(host, port) => {
            let bytes = host.as_bytes();
            if bytes.len() > 255 {
                return Err(AnyTlsError::InvalidAddress);
            }
            out.push(0x03);
            out.push(bytes.len() as u8);
            out.extend_from_slice(bytes);
            out.extend_from_slice(&port.to_be_bytes());
        }
    }
    Ok(out)
}

/// 解码 SOCKS5 地址，返回（目标，消耗字节数）；首个 PSH 的 data 可能在地址后紧跟
/// 用户数据，故不要求缓冲恰好耗尽。
///
/// # Errors
///
/// 缓冲不足、ATYP 未知、域名非 UTF-8 返回 `InvalidAddress`。
pub fn decode_socks5_addr(buf: &[u8]) -> Result<(AnyTlsTarget, usize), AnyTlsError> {
    if buf.is_empty() {
        return Err(AnyTlsError::InvalidAddress);
    }
    match buf[0] {
        0x01 => {
            if buf.len() < 1 + 4 + 2 {
                return Err(AnyTlsError::InvalidAddress);
            }
            let mut oct = [0u8; 4];
            oct.copy_from_slice(&buf[1..5]);
            let port = u16::from_be_bytes([buf[5], buf[6]]);
            Ok((AnyTlsTarget::Ipv4(oct, port), 7))
        }
        0x04 => {
            if buf.len() < 1 + 16 + 2 {
                return Err(AnyTlsError::InvalidAddress);
            }
            let mut seg = [0u8; 16];
            seg.copy_from_slice(&buf[1..17]);
            let port = u16::from_be_bytes([buf[17], buf[18]]);
            Ok((AnyTlsTarget::Ipv6(seg, port), 19))
        }
        0x03 => {
            if buf.len() < 2 {
                return Err(AnyTlsError::InvalidAddress);
            }
            let dlen = buf[1] as usize;
            if buf.len() < 2 + dlen + 2 {
                return Err(AnyTlsError::InvalidAddress);
            }
            let host = core::str::from_utf8(&buf[2..2 + dlen])
                .map_err(|_| AnyTlsError::InvalidAddress)?
                .to_string();
            let port = u16::from_be_bytes([buf[2 + dlen], buf[2 + dlen + 1]]);
            Ok((AnyTlsTarget::Domain(host, port), 2 + dlen + 2))
        }
        _ => Err(AnyTlsError::InvalidAddress),
    }
}

// ---------- UDP-over-TCP（§2.4，sing-box udp-over-tcp v2） ----------

/// UoT 魔法域名。
pub const UOT_MAGIC_DOMAIN: &str = "sp.v2.udp-over-tcp.arpa";
/// UoT 魔法端口（固定 0）。
pub const UOT_MAGIC_PORT: u16 = 0;

/// UoT 魔法目标：`sp.v2.udp-over-tcp.arpa:0`（开一条普通 stream，流程同 §2.3）。
#[must_use]
pub fn uot_magic_target() -> AnyTlsTarget {
    AnyTlsTarget::Domain(UOT_MAGIC_DOMAIN.to_string(), UOT_MAGIC_PORT)
}

/// UoT eager payload（Connect 格式）：`0x01 + SOCKS5地址`。
///
/// 必须在 SYNACK 等待**之前**先写，否则与 sing-box inbound 死锁（server 等 request
/// 才报 SYNACK，client 等 SYNACK 才写 request）。见 `client_open_stream_with_payload`。
///
/// # Errors
///
/// 地址编码失败返回 `InvalidAddress`。
pub fn encode_uot_connect(target: &AnyTlsTarget) -> Result<Vec<u8>, AnyTlsError> {
    let mut out = Vec::with_capacity(1 + 19);
    out.push(0x01); // isConnect
    out.extend_from_slice(&encode_socks5_addr(target)?);
    Ok(out)
}

/// UoT 数据包编码：`长度(u16 BE) + 包内容`。
///
/// # Errors
///
/// 包超过 65535 字节返回 `InvalidFrame`。
// 未确认：sing-box 文档中 UoT 包内分片细节未在语义文档展开；此处只实现已确认的
// u16 长度前缀分包。
pub fn encode_uot_datagram(payload: &[u8]) -> Result<Vec<u8>, AnyTlsError> {
    if payload.len() > MAX_FRAME_DATA_LEN {
        return Err(AnyTlsError::InvalidFrame);
    }
    let mut out = Vec::with_capacity(2 + payload.len());
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// UoT 数据包解码：按 `u16 BE` 长度前缀切分缓冲。
///
/// # Errors
///
/// 尾部残缺（长度头不全或包体不全）返回 `InvalidFrame`。
// 未确认：同上，包内分片细节未确认，只实现已确认的长度前缀分包。
pub fn decode_uot_datagrams(buf: &[u8]) -> Result<Vec<Vec<u8>>, AnyTlsError> {
    let mut out = Vec::new();
    let mut rest = buf;
    while !rest.is_empty() {
        if rest.len() < 2 {
            return Err(AnyTlsError::InvalidFrame);
        }
        let len = u16::from_be_bytes([rest[0], rest[1]]) as usize;
        if rest.len() < 2 + len {
            return Err(AnyTlsError::InvalidFrame);
        }
        out.push(rest[2..2 + len].to_vec());
        rest = &rest[2 + len..];
    }
    Ok(out)
}

// ---------- client 会话 ----------

/// client 握手后的会话状态（stream_id 分配器）。
#[derive(Debug, Clone)]
pub struct ClientHandshake {
    /// 下一个可用的 stream_id（控制帧占用 0，stream 从 1 开始单调递增）。
    pub next_stream_id: u32,
}

/// client 握手（已建立 TLS 之上）：认证（一次写）→ Settings → 等 ServerSettings。
///
/// 若服务器下发 UpdatePaddingScheme（md5 不一致），返回
/// `PaddingSchemeUpdated{scheme}`，调用方应切换 scheme 后**重建** session。
///
/// # Errors
///
/// 认证/SYNACK 之外的 I/O 失败返回 `Io`；服务器回包不符合预期返回
/// `UnexpectedCommand`；Settings 非法返回 `InvalidSettings`。
pub fn client_handshake<S: Read + Write>(
    stream: &mut S,
    password: &str,
    padding0_len: u16,
    client_name: &str,
    padding_md5_hex: &str,
) -> Result<ClientHandshake, AnyTlsError> {
    // 1. 认证：32+2+padding0 一次写（§5 坑 #1）。
    send_auth(stream, password, padding0_len)?;
    // 2. Settings 帧（cmd=4, stream_id=0）。
    let settings = encode_settings(client_name, padding_md5_hex)?;
    write_frame(stream, AnyTlsCommand::Settings, 0, &settings)?;
    // 3. 等服务器响应。
    let frame = read_frame(stream)?;
    match frame.cmd {
        AnyTlsCommand::ServerSettings => {
            let server_settings = parse_settings(&frame.data)?;
            if server_settings.v < PROTOCOL_VERSION {
                return Err(AnyTlsError::UnexpectedCommand {
                    cmd: frame.cmd.as_u8(),
                    stream_id: frame.stream_id,
                });
            }
        }
        AnyTlsCommand::UpdatePaddingScheme => {
            return Err(AnyTlsError::PaddingSchemeUpdated { scheme: frame.data });
        }
        other => {
            return Err(AnyTlsError::UnexpectedCommand {
                cmd: other.as_u8(),
                stream_id: frame.stream_id,
            });
        }
    }
    Ok(ClientHandshake { next_stream_id: 1 })
}

/// client 开 stream：SYN → 首个 PSH（`first_payload`）→ 等 SYNACK（v2）。
///
/// UoT 用此函数并把 `first_payload` 设为 eager Connect 载荷（`encode_uot_connect`），
/// 以规避 sing-box 死锁（§2.4）：eager 载荷在 SYNACK 等待**之前**写出。
/// 普通 TCP stream 的 `first_payload` 为 `encode_socks5_addr(target)`，其后可继续
/// 用 PSH 传用户数据。
///
/// # Errors
///
/// 地址/载荷编码失败、SYNACK 缺失或带错误文本、I/O 失败分别返回对应错误。
pub fn client_open_stream_with_payload<S: Read + Write>(
    stream: &mut S,
    handshake: &mut ClientHandshake,
    first_payload: &[u8],
) -> Result<u32, AnyTlsError> {
    let stream_id = handshake.next_stream_id;
    handshake.next_stream_id = handshake.next_stream_id.wrapping_add(1);
    if handshake.next_stream_id == 0 {
        // stream_id 回绕到 0（控制帧保留值）：协议未定义，fail-closed。
        return Err(AnyTlsError::InvalidFrame);
    }
    write_frame(stream, AnyTlsCommand::Syn, stream_id, &[])?;
    // 首个 PSH（含目标地址或 eager 载荷）：在等 SYNACK 之前写出。
    write_frame(stream, AnyTlsCommand::Psh, stream_id, first_payload)?;
    // 等 SYNACK（v2；服务器若架构上无法回报出站状态，也允许收到 SYN 即回）。
    let frame = read_frame(stream)?;
    if frame.cmd != AnyTlsCommand::SynAck || frame.stream_id != stream_id {
        return Err(AnyTlsError::UnexpectedCommand {
            cmd: frame.cmd.as_u8(),
            stream_id: frame.stream_id,
        });
    }
    if !frame.data.is_empty() {
        let reason = String::from_utf8_lossy(&frame.data).into_owned();
        return Err(AnyTlsError::StreamRejected { stream_id, reason });
    }
    Ok(stream_id)
}

/// client 开一条代理 TCP stream（目标地址编码进首个 PSH）。
///
/// # Errors
///
/// 同 `client_open_stream_with_payload`；地址编码失败返回 `InvalidAddress`。
pub fn client_open_stream<S: Read + Write>(
    stream: &mut S,
    handshake: &mut ClientHandshake,
    target: &AnyTlsTarget,
) -> Result<u32, AnyTlsError> {
    let first = encode_socks5_addr(target)?;
    client_open_stream_with_payload(stream, handshake, &first)
}

/// client 开一条 UDP-over-TCP stream（魔法域名 + eager Connect 载荷）。
///
/// # Errors
///
/// 同 `client_open_stream_with_payload`。
pub fn client_open_uot_stream<S: Read + Write>(
    stream: &mut S,
    handshake: &mut ClientHandshake,
    target: &AnyTlsTarget,
) -> Result<u32, AnyTlsError> {
    // 先开魔法 stream（地址行用魔法域名，端口 0），再写 eager Connect 载荷。
    let magic = uot_magic_target();
    let stream_id = handshake.next_stream_id;
    handshake.next_stream_id = handshake.next_stream_id.wrapping_add(1);
    if handshake.next_stream_id == 0 {
        return Err(AnyTlsError::InvalidFrame);
    }
    write_frame(stream, AnyTlsCommand::Syn, stream_id, &[])?;
    write_frame(
        stream,
        AnyTlsCommand::Psh,
        stream_id,
        &encode_socks5_addr(&magic)?,
    )?;
    // eager payload：在 SYNACK 等待之前写出（§2.4 死锁规避）。
    write_frame(
        stream,
        AnyTlsCommand::Psh,
        stream_id,
        &encode_uot_connect(target)?,
    )?;
    let frame = read_frame(stream)?;
    if frame.cmd != AnyTlsCommand::SynAck || frame.stream_id != stream_id {
        return Err(AnyTlsError::UnexpectedCommand {
            cmd: frame.cmd.as_u8(),
            stream_id: frame.stream_id,
        });
    }
    if !frame.data.is_empty() {
        let reason = String::from_utf8_lossy(&frame.data).into_owned();
        return Err(AnyTlsError::StreamRejected { stream_id, reason });
    }
    Ok(stream_id)
}

// ---------- server 最小握手（测试用） ----------

/// server 侧最小握手（已建立 TLS 之上）：一次读认证 → 校验 SHA256 → 读掉 padding0 →
/// 读帧直到 Settings → 校验 `padding-md5`（不一致则下发 UpdatePaddingScheme）→
/// `v>=2` 回 ServerSettings。
///
/// **关键规则**（§2.2）：Settings 之前收到 SYN → 先发 Alert 说明原因，再以
/// `UnexpectedCommand` 拒绝整个 session。
///
/// # Errors
///
/// 认证失败返回 `AuthDenied`；SYN 先于 Settings 返回 `UnexpectedCommand`；
/// I/O 失败返回 `Io`。
pub fn server_handshake<S: Read + Write>(
    stream: &mut S,
    password: &str,
    scheme_text: &str,
) -> Result<Settings, AnyTlsError> {
    recv_auth(stream, password)?;
    loop {
        let frame = read_frame(stream)?;
        match frame.cmd {
            AnyTlsCommand::Settings if frame.stream_id == 0 => {
                let settings = parse_settings(&frame.data)?;
                let ours = padding_md5_hex(scheme_text);
                if settings.padding_md5.as_deref() != Some(ours.as_str()) {
                    // md5 不一致：下发服务器的 scheme（客户端应切换后重建 session）。
                    write_frame(
                        stream,
                        AnyTlsCommand::UpdatePaddingScheme,
                        0,
                        scheme_text.as_bytes(),
                    )?;
                }
                if settings.v >= PROTOCOL_VERSION {
                    write_frame(
                        stream,
                        AnyTlsCommand::ServerSettings,
                        0,
                        &encode_server_settings(),
                    )?;
                }
                return Ok(settings);
            }
            AnyTlsCommand::Syn => {
                // §2.2 关键规则：Settings 之前收到 SYN 必须拒绝 session。
                let msg = b"settings required before SYN";
                write_frame(stream, AnyTlsCommand::Alert, 0, msg)?;
                return Err(AnyTlsError::UnexpectedCommand {
                    cmd: frame.cmd.as_u8(),
                    stream_id: frame.stream_id,
                });
            }
            // Waste：read_frame 已完整读出 data，此处静默丢弃（§3.3）。
            // HeartRequest/HeartResponse 等未知阶段帧：最小实现直接拒绝，避免语义漂移。
            AnyTlsCommand::Waste => {}
            other => {
                return Err(AnyTlsError::UnexpectedCommand {
                    cmd: other.as_u8(),
                    stream_id: frame.stream_id,
                });
            }
        }
    }
}

// ---------- adapter ----------

/// AnyTLS 出站 adapter（离线交接；真实 TLS 会话在上层装配）。
pub struct AnyTlsAdapter {
    tag: String,
    locator: String,
    password: String,
    client_name: String,
}

impl AnyTlsAdapter {
    /// 构造 adapter（`client_name` 取默认 `CLIENT_IDENT`）。
    #[must_use]
    pub fn new(
        tag: impl Into<String>,
        locator: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        Self {
            tag: tag.into(),
            locator: locator.into(),
            password: password.into(),
            client_name: CLIENT_IDENT.to_string(),
        }
    }

    /// 指定客户端标识构造（Settings 的 `client=` 字段应填真实实现名）。
    #[must_use]
    pub fn with_client_name(
        tag: impl Into<String>,
        locator: impl Into<String>,
        password: impl Into<String>,
        client_name: impl Into<String>,
    ) -> Self {
        Self {
            tag: tag.into(),
            locator: locator.into(),
            password: password.into(),
            client_name: client_name.into(),
        }
    }

    /// 配置的服务端 locator。
    #[must_use]
    pub fn locator(&self) -> &str {
        &self.locator
    }

    /// 认证密码（仅内部握手使用，不进入错误/日志）。
    #[must_use]
    pub fn password(&self) -> &str {
        &self.password
    }

    /// 客户端标识。
    #[must_use]
    pub fn client_name(&self) -> &str {
        &self.client_name
    }
}

impl OutboundAdapter for AnyTlsAdapter {
    fn outbound_kind(&self) -> &'static str {
        "anytls"
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

// ---------- loopback TLS 材料（rcgen 自签 + 公钥 pin） ----------

use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use rustls::{ClientConfig, ServerConfig};

/// 自签证书材料（cert DER + PKCS8 key DER）。
pub struct LoopbackIdentity {
    /// 服务端证书 DER（同时作为客户端唯一信任根，即公钥 pin）。
    pub cert_der: Vec<u8>,
    /// 服务端私钥 PKCS8 DER。
    pub key_der: Vec<u8>,
}

/// 用 rcgen 生成一张自签证书（CN/SAN = localhost），离线、确定性可复现。
///
/// # Errors
///
/// rcgen 生成失败返回 `Tls`。
pub fn generate_loopback_identity() -> Result<LoopbackIdentity, AnyTlsError> {
    let key_pair = rcgen::KeyPair::generate().map_err(|_| AnyTlsError::Tls)?;
    let params = rcgen::CertificateParams::new(vec!["localhost".to_string()])
        .map_err(|_| AnyTlsError::Tls)?;
    let cert = params
        .self_signed(&key_pair)
        .map_err(|_| AnyTlsError::Tls)?;
    let key_der = key_pair.serialize_der();
    let cert_der = cert.der().to_vec();
    Ok(LoopbackIdentity { cert_der, key_der })
}

fn ring_provider() -> std::sync::Arc<rustls::crypto::CryptoProvider> {
    std::sync::Arc::new(rustls::crypto::ring::default_provider())
}

/// 构造服务端 TLS 配置（仅持有自签证书）。
///
/// # Errors
///
/// 证书/key 解析失败返回 `Tls`。
pub fn server_config(identity: &LoopbackIdentity) -> Result<ServerConfig, AnyTlsError> {
    let cert = CertificateDer::from(identity.cert_der.clone());
    let key = PrivatePkcs8KeyDer::from(identity.key_der.clone());
    let config = ServerConfig::builder_with_provider(ring_provider())
        .with_safe_default_protocol_versions()
        .map_err(|_| AnyTlsError::Tls)?
        .with_no_client_auth()
        .with_single_cert(vec![cert], key.into())
        .map_err(|_| AnyTlsError::Tls)?;
    Ok(config)
}

/// 构造客户端 TLS 配置：把自签证书作为**唯一**信任根（公钥 pin，不依赖系统根）。
///
/// # Errors
///
/// 证书加入 root store 失败返回 `Tls`。
pub fn client_config(identity: &LoopbackIdentity) -> Result<ClientConfig, AnyTlsError> {
    let cert = CertificateDer::from(identity.cert_der.clone());
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert).map_err(|_| AnyTlsError::Tls)?;
    let config = ClientConfig::builder_with_provider(ring_provider())
        .with_safe_default_protocol_versions()
        .map_err(|_| AnyTlsError::Tls)?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    // ---------- 认证帧 ----------

    #[test]
    fn auth_frame_roundtrip() {
        let buf = encode_auth("s3cret", 0);
        assert_eq!(buf.len(), AUTH_OVERHEAD);
        assert_eq!(&buf[..32], &auth_digest("s3cret"));
        assert_eq!(&buf[32..34], &[0x00, 0x00]);
        assert_eq!(parse_auth("s3cret", &buf).unwrap(), 0);

        let buf = encode_auth("s3cret", 16);
        assert_eq!(buf.len(), AUTH_OVERHEAD + 16);
        assert!(buf[AUTH_OVERHEAD..].iter().all(|&b| b == 0)); // padding0 填零
        assert_eq!(parse_auth("s3cret", &buf).unwrap(), 16);
    }

    #[test]
    fn auth_wrong_password_is_denied() {
        let buf = encode_auth("correct", 4);
        // 不泄露密码/hash：错误里不带任何秘密材料。
        assert_eq!(parse_auth("wrong", &buf), Err(AnyTlsError::AuthDenied));
        assert!(!format!("{}", AnyTlsError::AuthDenied).contains("correct"));
    }

    #[test]
    fn auth_truncated_or_oversized_is_invalid_frame() {
        assert_eq!(parse_auth("pw", &[0u8; 10]), Err(AnyTlsError::InvalidFrame));
        let mut buf = encode_auth("pw", 3);
        buf.push(0x00); // 多出一字节
        assert_eq!(parse_auth("pw", &buf), Err(AnyTlsError::InvalidFrame));
    }

    // ---------- 7 字节帧头 ----------

    #[test]
    fn frame_header_roundtrip_all_commands() {
        let cmds = [
            AnyTlsCommand::Waste,
            AnyTlsCommand::Syn,
            AnyTlsCommand::Psh,
            AnyTlsCommand::Fin,
            AnyTlsCommand::Settings,
            AnyTlsCommand::Alert,
            AnyTlsCommand::UpdatePaddingScheme,
            AnyTlsCommand::SynAck,
            AnyTlsCommand::HeartRequest,
            AnyTlsCommand::HeartResponse,
            AnyTlsCommand::ServerSettings,
        ];
        for (i, cmd) in cmds.iter().enumerate() {
            assert_eq!(cmd.as_u8(), i as u8);
            let data = vec![i as u8; i * 7];
            let raw = encode_frame(*cmd, 0x0102_0304, &data).unwrap();
            assert_eq!(raw.len(), FRAME_HEADER_LEN + data.len());
            let (frame, consumed) = decode_frame_bytes(&raw).unwrap();
            assert_eq!(consumed, raw.len());
            assert_eq!(frame.cmd, *cmd);
            assert_eq!(frame.stream_id, 0x0102_0304);
            assert_eq!(frame.data, data);
        }
    }

    #[test]
    fn frame_unknown_command_maps_to_waste() {
        let raw = encode_frame(AnyTlsCommand::Waste, 0, b"pad").unwrap();
        let mut raw_unknown = raw.clone();
        raw_unknown[0] = 255;
        let (frame, _) = decode_frame_bytes(&raw_unknown).unwrap();
        assert_eq!(frame.cmd, AnyTlsCommand::Waste);
        assert_eq!(frame.data, b"pad");
    }

    #[test]
    fn frame_data_too_long_rejected() {
        let big = vec![0u8; MAX_FRAME_DATA_LEN + 1];
        assert_eq!(
            encode_frame(AnyTlsCommand::Psh, 1, &big),
            Err(AnyTlsError::InvalidFrame)
        );
        // 边界：恰好 65535 通过。
        let max = vec![0u8; MAX_FRAME_DATA_LEN];
        assert!(encode_frame(AnyTlsCommand::Psh, 1, &max).is_ok());
    }

    #[test]
    fn frame_short_buffer_rejected() {
        assert_eq!(
            decode_frame_bytes(&[1, 2, 3]),
            Err(AnyTlsError::InvalidFrame)
        );
        let mut raw = encode_frame(AnyTlsCommand::Psh, 9, b"hello").unwrap();
        raw.truncate(raw.len() - 2); // data 被截断
        assert_eq!(decode_frame_bytes(&raw), Err(AnyTlsError::InvalidFrame));
    }

    // ---------- Settings ----------

    #[test]
    fn settings_roundtrip() {
        let md5 = padding_md5_hex(DEFAULT_PADDING_SCHEME);
        let raw = encode_settings("nexus-anytls/0.1.0", &md5).unwrap();
        assert_eq!(
            raw,
            format!("v=2\nclient=nexus-anytls/0.1.0\npadding-md5={md5}").into_bytes()
        );
        let s = parse_settings(&raw).unwrap();
        assert_eq!(s.v, 2);
        assert_eq!(s.client.as_deref(), Some("nexus-anytls/0.1.0"));
        assert_eq!(s.padding_md5.as_deref(), Some(md5.as_str()));

        let srv = parse_settings(&encode_server_settings()).unwrap();
        assert_eq!(srv.v, 2);
        assert!(srv.client.is_none());
        assert!(srv.padding_md5.is_none());
    }

    #[test]
    fn settings_malformed_rejected() {
        assert_eq!(
            parse_settings(b"no-equals-here"),
            Err(AnyTlsError::InvalidSettings)
        );
        assert_eq!(parse_settings(b"v=abc"), Err(AnyTlsError::InvalidSettings));
        assert_eq!(
            parse_settings(b"client=x"),
            Err(AnyTlsError::InvalidSettings)
        ); // 缺 v
        assert_eq!(
            parse_settings(&[0xff, 0xfe]),
            Err(AnyTlsError::InvalidSettings)
        ); // 非 UTF-8
        assert!(encode_settings("bad\nname", "abc").is_err());
    }

    // ---------- Padding scheme ----------

    #[test]
    fn default_padding_scheme_parses() {
        let scheme = default_padding_scheme().unwrap();
        assert_eq!(scheme.stop, 8);
        assert_eq!(scheme.policies.len(), 8);
        // 第 0 包：30-30 单区间。
        assert_eq!(scheme.policies[0].packet_index, 0);
        assert_eq!(
            scheme.policies[0].segments,
            vec![PaddingSegment::SizeRange { min: 30, max: 30 }]
        );
        // 第 2 包：含 4 个检查点。
        let checkpoints = scheme.policies[2]
            .segments
            .iter()
            .filter(|s| **s == PaddingSegment::Checkpoint)
            .count();
        assert_eq!(checkpoints, 4);
        assert_eq!(
            scheme.policies[2].segments[0],
            PaddingSegment::SizeRange { min: 400, max: 500 }
        );
    }

    #[test]
    fn padding_scheme_malformed_rejected() {
        assert!(parse_padding_scheme("0=30-30").is_err()); // 缺 stop
        assert!(parse_padding_scheme("stop=x\n0=30-30").is_err());
        assert!(parse_padding_scheme("stop=8\n0=500-30").is_err()); // min > max
        assert!(parse_padding_scheme("stop=8\n0=bogus").is_err());
    }

    #[test]
    fn padding_md5_is_deterministic() {
        let a = padding_md5_hex(DEFAULT_PADDING_SCHEME);
        let b = padding_md5_hex(DEFAULT_PADDING_SCHEME);
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
        assert!(
            a.bytes()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
        let c = padding_md5_hex("stop=1\n0=1-1");
        assert_ne!(a, c);
    }

    // ---------- SOCKS5 地址 ----------

    #[test]
    fn socks5_addr_roundtrip() {
        let targets = [
            AnyTlsTarget::Ipv4([192, 168, 1, 7], 443),
            AnyTlsTarget::Ipv6(
                [
                    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
                ],
                80,
            ),
            AnyTlsTarget::Domain("example.internal".to_string(), 8443),
        ];
        for t in &targets {
            let raw = encode_socks5_addr(t).unwrap();
            let (decoded, consumed) = decode_socks5_addr(&raw).unwrap();
            assert_eq!(&decoded, t);
            assert_eq!(consumed, raw.len());
        }
        // 首个 PSH 的 data 可在地址后紧跟用户数据。
        let t = AnyTlsTarget::Ipv4([10, 0, 0, 1], 1080);
        let mut raw = encode_socks5_addr(&t).unwrap();
        raw.extend_from_slice(b"userdata");
        let (decoded, consumed) = decode_socks5_addr(&raw).unwrap();
        assert_eq!(decoded, t);
        assert_eq!(&raw[consumed..], b"userdata");
    }

    #[test]
    fn socks5_addr_atyp_bytes() {
        assert_eq!(
            encode_socks5_addr(&AnyTlsTarget::Ipv4([1, 2, 3, 4], 0x1234)).unwrap()[0],
            0x01
        );
        assert_eq!(
            encode_socks5_addr(&AnyTlsTarget::Domain("h".into(), 1)).unwrap()[0],
            0x03
        );
        let long = "x".repeat(256);
        assert_eq!(
            encode_socks5_addr(&AnyTlsTarget::Domain(long, 1)),
            Err(AnyTlsError::InvalidAddress)
        );
        assert_eq!(
            decode_socks5_addr(&[0x02, 0, 0]),
            Err(AnyTlsError::InvalidAddress)
        );
        assert_eq!(decode_socks5_addr(&[]), Err(AnyTlsError::InvalidAddress));
    }

    // ---------- UoT ----------

    #[test]
    fn uot_connect_and_datagrams_roundtrip() {
        let magic = uot_magic_target();
        assert_eq!(magic.host_label(), UOT_MAGIC_DOMAIN);
        assert_eq!(magic.port(), 0);

        let dst = AnyTlsTarget::Domain("dns.example".to_string(), 53);
        let eager = encode_uot_connect(&dst).unwrap();
        assert_eq!(eager[0], 0x01); // isConnect
        let (decoded, consumed) = decode_socks5_addr(&eager[1..]).unwrap();
        assert_eq!(decoded, dst);
        assert_eq!(consumed, eager.len() - 1);

        let p1 = encode_uot_datagram(b"query-bytes").unwrap();
        let p2 = encode_uot_datagram(b"").unwrap(); // 空包合法
        let mut wire = Vec::new();
        wire.extend_from_slice(&p1);
        wire.extend_from_slice(&p2);
        assert_eq!(
            decode_uot_datagrams(&wire).unwrap(),
            vec![b"query-bytes".to_vec(), b"".to_vec()]
        );
        assert!(decode_uot_datagrams(&[]).unwrap().is_empty());
        assert_eq!(
            decode_uot_datagrams(&[0x00]),
            Err(AnyTlsError::InvalidFrame)
        );
        assert_eq!(
            decode_uot_datagrams(&[0x00, 0x05, 0x01]),
            Err(AnyTlsError::InvalidFrame)
        );
    }

    // ---------- loopback TLS 握手 ----------

    /// client/server 握手往返：server 收到 Settings（含 client 名与 md5）。
    #[test]
    fn loopback_handshake_ok() {
        let identity = generate_loopback_identity().unwrap();
        let server_cfg = std::sync::Arc::new(server_config(&identity).unwrap());
        let client_cfg = std::sync::Arc::new(client_config(&identity).unwrap());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = mpsc::channel();
        let handle = thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            sock.set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let conn = rustls::ServerConnection::new(server_cfg).unwrap();
            let mut tls = rustls::StreamOwned::new(conn, sock);
            let res = server_handshake(&mut tls, "test-password", DEFAULT_PADDING_SCHEME);
            tx.send(res).unwrap();
        });
        let sock = TcpStream::connect(addr).unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let conn = rustls::ClientConnection::new(client_cfg, server_name).unwrap();
        let mut tls = rustls::StreamOwned::new(conn, sock);
        let md5 = padding_md5_hex(DEFAULT_PADDING_SCHEME);
        let hs = client_handshake(&mut tls, "test-password", 8, CLIENT_IDENT, &md5).unwrap();
        assert_eq!(hs.next_stream_id, 1);
        let settings = rx.recv_timeout(Duration::from_secs(10)).unwrap().unwrap();
        assert_eq!(settings.v, 2);
        assert_eq!(settings.client.as_deref(), Some(CLIENT_IDENT));
        assert_eq!(settings.padding_md5.as_deref(), Some(md5.as_str()));
        handle.join().unwrap();
    }

    #[test]
    fn loopback_handshake_wrong_password() {
        let identity = generate_loopback_identity().unwrap();
        let server_cfg = std::sync::Arc::new(server_config(&identity).unwrap());
        let client_cfg = std::sync::Arc::new(client_config(&identity).unwrap());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = mpsc::channel();
        let handle = thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            sock.set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let conn = rustls::ServerConnection::new(server_cfg).unwrap();
            let mut tls = rustls::StreamOwned::new(conn, sock);
            let res = server_handshake(&mut tls, "server-secret", DEFAULT_PADDING_SCHEME);
            tx.send(res).unwrap();
        });
        let sock = TcpStream::connect(addr).unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let conn = rustls::ClientConnection::new(client_cfg, server_name).unwrap();
        let mut tls = rustls::StreamOwned::new(conn, sock);
        let md5 = padding_md5_hex(DEFAULT_PADDING_SCHEME);
        // 密码不对：server 侧 AuthDenied 并关闭；client 侧读到 EOF → Io。
        let res = client_handshake(&mut tls, "wrong-secret", 0, CLIENT_IDENT, &md5);
        assert!(matches!(res, Err(AnyTlsError::Io)));
        let server_res = rx.recv_timeout(Duration::from_secs(10)).unwrap();
        assert_eq!(server_res, Err(AnyTlsError::AuthDenied));
        handle.join().unwrap();
    }

    #[test]
    fn loopback_padding_scheme_update() {
        let identity = generate_loopback_identity().unwrap();
        let server_cfg = std::sync::Arc::new(server_config(&identity).unwrap());
        let client_cfg = std::sync::Arc::new(client_config(&identity).unwrap());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = mpsc::channel();
        let handle = thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            sock.set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let conn = rustls::ServerConnection::new(server_cfg).unwrap();
            let mut tls = rustls::StreamOwned::new(conn, sock);
            let res = server_handshake(&mut tls, "pw", DEFAULT_PADDING_SCHEME);
            tx.send(res).unwrap();
        });
        let sock = TcpStream::connect(addr).unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let conn = rustls::ClientConnection::new(client_cfg, server_name).unwrap();
        let mut tls = rustls::StreamOwned::new(conn, sock);
        // client 上报错误的 padding-md5 → 服务器下发 UpdatePaddingScheme。
        let res = client_handshake(&mut tls, "pw", 0, CLIENT_IDENT, "deadbeef");
        match res {
            Err(AnyTlsError::PaddingSchemeUpdated { scheme }) => {
                assert_eq!(scheme, DEFAULT_PADDING_SCHEME.as_bytes());
            }
            other => panic!("expected PaddingSchemeUpdated, got {other:?}"),
        }
        let settings = rx.recv_timeout(Duration::from_secs(10)).unwrap().unwrap();
        assert_eq!(settings.padding_md5.as_deref(), Some("deadbeef"));
        handle.join().unwrap();
    }

    /// stream 开/关帧序列：SYN → PSH(地址) → SYNACK → PSH(数据) → FIN。
    #[test]
    fn loopback_stream_open_close_sequence() {
        let identity = generate_loopback_identity().unwrap();
        let server_cfg = std::sync::Arc::new(server_config(&identity).unwrap());
        let client_cfg = std::sync::Arc::new(client_config(&identity).unwrap());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = mpsc::channel();
        let handle = thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            sock.set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let conn = rustls::ServerConnection::new(server_cfg).unwrap();
            let mut tls = rustls::StreamOwned::new(conn, sock);
            server_handshake(&mut tls, "pw", DEFAULT_PADDING_SCHEME).unwrap();
            // 读 SYN。
            let syn = read_frame(&mut tls).unwrap();
            assert_eq!(syn.cmd, AnyTlsCommand::Syn);
            assert!(syn.data.is_empty());
            // 读首个 PSH：目标地址。
            let psh_addr = read_frame(&mut tls).unwrap();
            assert_eq!(psh_addr.cmd, AnyTlsCommand::Psh);
            assert_eq!(psh_addr.stream_id, syn.stream_id);
            let (target, _) = decode_socks5_addr(&psh_addr.data).unwrap();
            // 回 SYNACK（空 data = 成功）。
            write_frame(&mut tls, AnyTlsCommand::SynAck, syn.stream_id, &[]).unwrap();
            // 读数据 PSH 与 FIN。
            let psh_data = read_frame(&mut tls).unwrap();
            assert_eq!(psh_data.cmd, AnyTlsCommand::Psh);
            let fin = read_frame(&mut tls).unwrap();
            assert_eq!(fin.cmd, AnyTlsCommand::Fin);
            assert_eq!(fin.stream_id, syn.stream_id);
            tx.send((target, psh_data.data)).unwrap();
        });
        let sock = TcpStream::connect(addr).unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let conn = rustls::ClientConnection::new(client_cfg, server_name).unwrap();
        let mut tls = rustls::StreamOwned::new(conn, sock);
        let md5 = padding_md5_hex(DEFAULT_PADDING_SCHEME);
        let mut hs = client_handshake(&mut tls, "pw", 0, CLIENT_IDENT, &md5).unwrap();
        let target = AnyTlsTarget::Ipv4([203, 0, 113, 9], 8080);
        let stream_id = client_open_stream(&mut tls, &mut hs, &target).unwrap();
        assert_eq!(stream_id, 1);
        assert_eq!(hs.next_stream_id, 2);
        write_frame(&mut tls, AnyTlsCommand::Psh, stream_id, b"hello-anytls").unwrap();
        write_frame(&mut tls, AnyTlsCommand::Fin, stream_id, &[]).unwrap();
        let (got_target, got_data) = rx.recv_timeout(Duration::from_secs(10)).unwrap();
        assert_eq!(got_target, target);
        assert_eq!(got_data, b"hello-anytls");
        handle.join().unwrap();
    }

    /// SYN 先于 Settings → 服务器发 Alert 并拒绝 session。
    #[test]
    fn loopback_syn_before_settings_rejected() {
        let identity = generate_loopback_identity().unwrap();
        let server_cfg = std::sync::Arc::new(server_config(&identity).unwrap());
        let client_cfg = std::sync::Arc::new(client_config(&identity).unwrap());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = mpsc::channel();
        let handle = thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            sock.set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let conn = rustls::ServerConnection::new(server_cfg).unwrap();
            let mut tls = rustls::StreamOwned::new(conn, sock);
            let res = server_handshake(&mut tls, "pw", DEFAULT_PADDING_SCHEME);
            tx.send(res).unwrap();
        });
        let sock = TcpStream::connect(addr).unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let conn = rustls::ClientConnection::new(client_cfg, server_name).unwrap();
        let mut tls = rustls::StreamOwned::new(conn, sock);
        // 违规顺序：认证后直接发 SYN。
        send_auth(&mut tls, "pw", 0).unwrap();
        write_frame(&mut tls, AnyTlsCommand::Syn, 1, &[]).unwrap();
        // 应收到 Alert（cmd=5, stream 0），随后 session 关闭。
        let alert = read_frame(&mut tls).unwrap();
        assert_eq!(alert.cmd, AnyTlsCommand::Alert);
        assert_eq!(alert.stream_id, 0);
        assert!(!alert.data.is_empty());
        let server_res = rx.recv_timeout(Duration::from_secs(10)).unwrap();
        assert_eq!(
            server_res,
            Err(AnyTlsError::UnexpectedCommand {
                cmd: 1,
                stream_id: 1
            })
        );
        handle.join().unwrap();
    }

    /// UoT：魔法 stream + eager Connect 载荷（SYNACK 等待之前写出）。
    #[test]
    fn loopback_uot_eager_payload() {
        let identity = generate_loopback_identity().unwrap();
        let server_cfg = std::sync::Arc::new(server_config(&identity).unwrap());
        let client_cfg = std::sync::Arc::new(client_config(&identity).unwrap());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = mpsc::channel();
        let handle = thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            sock.set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let conn = rustls::ServerConnection::new(server_cfg).unwrap();
            let mut tls = rustls::StreamOwned::new(conn, sock);
            server_handshake(&mut tls, "pw", DEFAULT_PADDING_SCHEME).unwrap();
            let syn = read_frame(&mut tls).unwrap();
            assert_eq!(syn.cmd, AnyTlsCommand::Syn);
            // 首个 PSH：魔法地址 sp.v2.udp-over-tcp.arpa:0。
            let magic_psh = read_frame(&mut tls).unwrap();
            let (magic_target, _) = decode_socks5_addr(&magic_psh.data).unwrap();
            assert_eq!(magic_target, uot_magic_target());
            // eager payload（在 SYNACK 之前到达）：0x01 + 真实目标。
            let eager = read_frame(&mut tls).unwrap();
            assert_eq!(eager.cmd, AnyTlsCommand::Psh);
            assert_eq!(eager.data[0], 0x01);
            let (real_target, _) = decode_socks5_addr(&eager.data[1..]).unwrap();
            write_frame(&mut tls, AnyTlsCommand::SynAck, syn.stream_id, &[]).unwrap();
            // 后续 UDP 包：u16 长度前缀。
            let pkt = read_frame(&mut tls).unwrap();
            let datagrams = decode_uot_datagrams(&pkt.data).unwrap();
            tx.send((magic_target, real_target, datagrams)).unwrap();
        });
        let sock = TcpStream::connect(addr).unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let conn = rustls::ClientConnection::new(client_cfg, server_name).unwrap();
        let mut tls = rustls::StreamOwned::new(conn, sock);
        let md5 = padding_md5_hex(DEFAULT_PADDING_SCHEME);
        let mut hs = client_handshake(&mut tls, "pw", 0, CLIENT_IDENT, &md5).unwrap();
        let dst = AnyTlsTarget::Domain("dns.example".to_string(), 53);
        let stream_id = client_open_uot_stream(&mut tls, &mut hs, &dst).unwrap();
        write_frame(
            &mut tls,
            AnyTlsCommand::Psh,
            stream_id,
            &encode_uot_datagram(b"dns-query").unwrap(),
        )
        .unwrap();
        let (magic_target, real_target, datagrams) =
            rx.recv_timeout(Duration::from_secs(10)).unwrap();
        assert_eq!(magic_target, uot_magic_target());
        assert_eq!(real_target, dst);
        assert_eq!(datagrams, vec![b"dns-query".to_vec()]);
        handle.join().unwrap();
    }

    // ---------- adapter ----------

    #[test]
    fn adapter_kind_and_handoff() {
        let a = AnyTlsAdapter::new("anytls-out", "anytls.example:443", "pw");
        assert_eq!(a.outbound_kind(), "anytls");
        assert_eq!(a.tag(), "anytls-out");
        assert_eq!(a.locator(), "anytls.example:443");
        assert_eq!(a.client_name(), CLIENT_IDENT);
        let h = a.handoff("10.0.0.1:443").unwrap();
        assert_eq!(h.kind, "anytls");
        assert_eq!(h.tag, "anytls-out");
        assert_eq!(h.locator, "10.0.0.1:443");
    }

    #[test]
    fn loopback_identity_generates() {
        let id = generate_loopback_identity().unwrap();
        assert!(!id.cert_der.is_empty());
        assert!(!id.key_der.is_empty());
        server_config(&id).unwrap();
        client_config(&id).unwrap();
    }
}
