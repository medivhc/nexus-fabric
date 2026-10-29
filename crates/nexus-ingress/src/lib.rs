//! nexus-ingress
//!
//! 系统级、可移植的输入组件：提供 SOCKS5/HTTP 代理协议状态机与 Packet/Stream
//! 解码后的 Flow Classification 与中立 `FlowContext` 构造。
//!
//! 边界（ARCHITECTURE §2 / §10）：
//! - 只产出中立 `FlowContext` 并提交给 SessionManager / Application Layer；
//! - 不直接调用 Core Planner，不是 nexus-network 的私有子模块；
//! - 不持有平台专有透明拦截实现（那属于 nexus-platform-*）。
//!
//! 本 crate 是 Portable Core：纯函数、零 I/O、零第三方依赖，可编译到 WASI。
//! 详细边界见同目录 `MODULE.md`。

#![forbid(unsafe_code)]

use nexus_domain::{FlowContext, FlowOrigin, ResourceId};

/// §11.18 TUN 透明入站：原始 IPv4 包纯函数解码（零 I/O）。
pub mod ip_packet;

/// InternetAccess 对应的 Network Resource 标识。
pub const INTERNET_ACCESS_RESOURCE: &str = "internet-access";

/// 由指定来源构造一个中立 FlowContext（内部统一构造点，保证字段一致）。
#[must_use]
fn classify(origin: FlowOrigin, destination: &str, profile: &str) -> FlowContext {
    FlowContext {
        origin,
        resource: ResourceId(INTERNET_ACCESS_RESOURCE.into()),
        destination: destination.to_string(),
        profile: profile.to_string(),
        egress_hint: None,
    }
}

/// 来自 SOCKS5 协议状态机的流。
#[must_use]
pub fn from_socks5(destination: &str, profile: &str) -> FlowContext {
    classify(FlowOrigin::Socks5, destination, profile)
}

/// 来自 HTTP 代理协议状态机的流。
#[must_use]
pub fn from_http(destination: &str, profile: &str) -> FlowContext {
    classify(FlowOrigin::Http, destination, profile)
}

/// 来自虚拟包接口（VPI）的包/流；平台拦截实现在 nexus-platform-*。
#[must_use]
pub fn from_virtual_packet_interface(destination: &str, profile: &str) -> FlowContext {
    classify(FlowOrigin::VirtualPacketInterface, destination, profile)
}

/// 来自进程内 Native API 的直接提交。
#[must_use]
pub fn from_native_api(destination: &str, profile: &str) -> FlowContext {
    classify(FlowOrigin::NativeApi, destination, profile)
}

/// 已 accept 的透明 socket（TPROXY / TUN 前端）产生的流。
#[must_use]
pub fn from_transparent_socket(destination: &str, profile: &str) -> FlowContext {
    classify(FlowOrigin::TransparentSocket, destination, profile)
}

// ---------- SOCKS5 有状态握手状态机（RFC 1928 + RFC 1929，sing-box 吸收） ----------

/// SOCKS5 协议版本号。
pub const SOCKS5_VERSION: u8 = 0x05;

/// 结构化 SOCKS5 协议错误（非文本日志）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Socks5Error {
    /// 问候/请求版本不是 0x05。
    BadVersion { got: u8 },
    /// 问候中 NMETHODS == 0。
    BadMethodCount { count: u8 },
    /// 客户端未提供可接受的认证方法（服务端不支持其全部方法）。
    NoAcceptableMethod,
    /// RFC 1929 子协商版本不是 0x01。
    BadAuthVersion { got: u8 },
    /// RFC 1929 凭据格式非法（长度字段越界）。
    AuthFailed,
    /// 请求段版本不是 0x05。
    BadRequestVersion { got: u8 },
    /// 命令不受支持（本状态机支持 CONNECT/UDP ASSOCIATE；仅 BIND/未知命令显式拒绝）。
    UnsupportedCommand { cmd: u8 },
    /// 地址类型不受支持（仅 ATYP 1/3/4）。
    UnsupportedAddressType { atyp: u8 },
    /// 地址长度非法（如空域名）。
    InvalidAddress,
}

impl core::fmt::Display for Socks5Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadVersion { got } => write!(f, "socks5 bad version {got}"),
            Self::BadMethodCount { count } => {
                write!(f, "socks5 bad method count {count}")
            }
            Self::NoAcceptableMethod => write!(f, "socks5 no acceptable method"),
            Self::BadAuthVersion { got } => write!(f, "socks5 bad auth version {got}"),
            Self::AuthFailed => write!(f, "socks5 auth failed"),
            Self::BadRequestVersion { got } => {
                write!(f, "socks5 bad request version {got}")
            }
            Self::UnsupportedCommand { cmd } => {
                write!(f, "socks5 unsupported command {cmd:#04x}")
            }
            Self::UnsupportedAddressType { atyp } => {
                write!(f, "socks5 unsupported address type {atyp:#04x}")
            }
            Self::InvalidAddress => write!(f, "socks5 invalid address"),
        }
    }
}

impl std::error::Error for Socks5Error {}

/// SOCKS5 目标/绑定地址（RFC 1928 ATYP 三型）。
///
/// 用数组/String 表示，不依赖 `std::net`，保持 portable（WASI 可检查）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Socks5Address {
    /// ATYP=0x01：IPv4 + 端口。
    Ipv4 { addr: [u8; 4], port: u16 },
    /// ATYP=0x03：域名 + 端口。
    Domain { host: String, port: u16 },
    /// ATYP=0x04：IPv6 + 端口。
    Ipv6 { addr: [u8; 16], port: u16 },
}

impl Socks5Address {
    /// 端口。
    #[must_use]
    pub fn port(&self) -> u16 {
        match self {
            Self::Ipv4 { port, .. } | Self::Domain { port, .. } | Self::Ipv6 { port, .. } => *port,
        }
    }

    /// 既有 `FlowContext` destination 格式：`host:port` / `1.2.3.4:port` / `[v6]:port`。
    #[must_use]
    pub fn to_destination_string(&self) -> String {
        match self {
            Self::Ipv4 { addr, port } => {
                format!("{}.{}.{}.{}:{}", addr[0], addr[1], addr[2], addr[3], port)
            }
            Self::Domain { host, port } => format!("{host}:{port}"),
            Self::Ipv6 { addr, port } => format!("{}:{}", format_ipv6(addr), port),
        }
    }

    /// 是否为 unspecified（`0.0.0.0:0` / `[::]:0`）。
    #[must_use]
    pub fn is_unspecified(&self) -> bool {
        match self {
            Self::Ipv4 { addr, port } => addr == &[0, 0, 0, 0] && *port == 0,
            Self::Ipv6 { addr, port } => addr == &[0u8; 16] && *port == 0,
            Self::Domain { .. } => false,
        }
    }
}

/// 握手完成后解析出的 SOCKS5 命令。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Socks5Command {
    /// CMD=0x01：连接目标。
    Connect { target: Socks5Address },
    /// CMD=0x03：UDP 关联；`client_endpoint` 为请求里的 DST（unspecified → None）。
    UdpAssociate {
        client_endpoint: Option<Socks5Address>,
    },
}

/// 解析后的 SOCKS5 UDP 数据报（RSV RSV FRAG ATYP ADDR PORT DATA）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Socks5UdpDatagram {
    /// FRAG 字段；本状态机只做解析，非 0 由上层策略丢弃（不做重组）。
    pub fragment: u8,
    /// 请求方向为 DST.ADDR/DST.PORT；回包方向为源地址。
    pub address: Socks5Address,
    /// 载荷。
    pub payload: Vec<u8>,
}

/// SOCKS5 UDP 数据报编解码错误（结构化，非文本日志）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Socks5UdpError {
    /// 长度不足（无法容纳固定头 / 地址 / 端口）。
    TooShort { len: usize },
    /// RSV 非 0。
    BadReserved { rsv: u8 },
    /// ATYP 非 0x01/0x03/0x04。
    UnsupportedAddressType { atyp: u8 },
    /// 域名为空或超过 255 字节。
    InvalidAddress,
    /// 编码后超过上限（IPv4 UDP 最大载荷 65507）。
    DatagramTooLarge { len: usize, limit: usize },
}

impl core::fmt::Display for Socks5UdpError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooShort { len } => write!(f, "socks5 udp datagram too short ({len} bytes)"),
            Self::BadReserved { rsv } => {
                write!(f, "socks5 udp reserved bytes not zero ({rsv:#04x})")
            }
            Self::UnsupportedAddressType { atyp } => {
                write!(f, "socks5 udp unsupported address type {atyp:#04x}")
            }
            Self::InvalidAddress => write!(f, "socks5 udp invalid address"),
            Self::DatagramTooLarge { len, limit } => {
                write!(f, "socks5 udp datagram too large ({len} > {limit})")
            }
        }
    }
}

impl std::error::Error for Socks5UdpError {}

/// SOCKS5 握手阶段（有状态 enum 状态机）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Socks5State {
    /// 等待问候（VER NMETHODS METHODS）。
    Greeting,
    /// 已选择认证方法，等待 CONNECT 请求。
    MethodSelected,
    /// RFC 1929 用户名/密码认证等待。
    UserPassAuth,
    /// 握手完成，可进入数据面。
    Established,
    /// 握手失败（结构化原因）。
    Failed(Socks5Error),
}

/// `feed` 的单步产物。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Socks5Step {
    /// 推进后的状态。
    pub state: Socks5State,
    /// 需要向对端发送的响应字节（空表示无需发送）。
    pub response: Vec<u8>,
    /// 握手完成时产出的中立 FlowContext（仅 `Established` 时 `Some`）。
    pub flow: Option<FlowContext>,
    /// 已收到合法前缀但输入不足，等待更多字节。
    pub needs_more: bool,
}

/// SOCKS5 有状态握手状态机。
///
/// 纯函数、零 I/O、可增量喂入：`feed` 可能一次跨多个阶段（如问候+请求同帧），
/// 内部循环推进直到需要更多数据、完成或失败。握手完成前不产出 `FlowContext`。
pub struct Socks5Handshake {
    state: Socks5State,
    buf: Vec<u8>,
    /// `Established` 时解析出的命令（调用方用 `command()` 区分 CONNECT / UDP ASSOCIATE）。
    command: Option<Socks5Command>,
}

/// 内部解析结果：需要更多输入 / 完成（消费长度+载荷） / 协议错误。
enum Parse<T> {
    NeedMore,
    Done(usize, T),
    Err(Socks5Error),
}

impl Socks5Handshake {
    /// 新建握手状态机（起始 `Greeting`）。
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Socks5State::Greeting,
            buf: Vec::new(),
            command: None,
        }
    }

    /// 当前状态。
    #[must_use]
    pub fn state(&self) -> &Socks5State {
        &self.state
    }

    /// 已 `Established` 时返回解析出的命令；未完成 → `None`。
    ///
    /// `Established` 同时用于 CONNECT 与 UDP ASSOCIATE，调用方必须用本方法区分。
    #[must_use]
    pub fn command(&self) -> Option<&Socks5Command> {
        self.command.as_ref()
    }

    /// 取出握手完成后剩余的数据面字节（仅在 `Established` 后有意义）。
    #[must_use]
    pub fn take_data(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.buf)
    }

    /// 喂入字节并推进状态机。
    pub fn feed(&mut self, bytes: &[u8]) -> Socks5Step {
        self.buf.extend_from_slice(bytes);
        let mut response = Vec::new();
        let mut flow = None;
        loop {
            match self.state {
                Socks5State::Greeting => match parse_greeting(&self.buf) {
                    Parse::NeedMore => break,
                    Parse::Err(e) => {
                        self.state = Socks5State::Failed(e);
                        break;
                    }
                    Parse::Done(consumed, method) => {
                        self.buf.drain(..consumed);
                        response = [SOCKS5_VERSION, method].to_vec();
                        match method {
                            // NO AUTHENTICATION REQUIRED
                            0x00 => self.state = Socks5State::MethodSelected,
                            // USERNAME/PASSWORD (RFC 1929)
                            0x02 => self.state = Socks5State::UserPassAuth,
                            _ => {
                                self.state = Socks5State::Failed(Socks5Error::NoAcceptableMethod);
                                break;
                            }
                        }
                    }
                },
                Socks5State::UserPassAuth => match parse_user_pass(&self.buf) {
                    Parse::NeedMore => break,
                    Parse::Err(e) => {
                        response = [0x01, 0x01].to_vec();
                        self.state = Socks5State::Failed(e);
                        break;
                    }
                    Parse::Done(consumed, ()) => {
                        self.buf.drain(..consumed);
                        // 状态机只校验帧格式；凭据授权由上层策略决定。
                        response = [0x01, 0x00].to_vec();
                        self.state = Socks5State::MethodSelected;
                    }
                },
                Socks5State::MethodSelected => match parse_request(&self.buf) {
                    Parse::NeedMore => break,
                    Parse::Err(e) => {
                        let rep = socks5_failure_rep(&e);
                        response = [SOCKS5_VERSION, rep, 0x00].to_vec();
                        self.state = Socks5State::Failed(e);
                        break;
                    }
                    Parse::Done(consumed, (cmd, address)) => {
                        self.buf.drain(..consumed);
                        match cmd {
                            // CONNECT：建立成功响应（BND.ADDR=0.0.0.0:0）。
                            0x01 => {
                                response =
                                    [SOCKS5_VERSION, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0].to_vec();
                                flow = Some(classify(
                                    FlowOrigin::Socks5,
                                    &address.to_destination_string(),
                                    "",
                                ));
                                self.command = Some(Socks5Command::Connect { target: address });
                                self.state = Socks5State::Established;
                            }
                            // UDP ASSOCIATE：状态机不知道实际 bind 地址，响应留空；
                            // 调用方必须用 `encode_udp_associate_reply` 发送真实 BND。
                            0x03 => {
                                self.command = Some(Socks5Command::UdpAssociate {
                                    client_endpoint: if address.is_unspecified() {
                                        None
                                    } else {
                                        Some(address)
                                    },
                                });
                                self.state = Socks5State::Established;
                            }
                            // BIND / 未知命令：显式 command-not-supported。
                            _ => {
                                response = [SOCKS5_VERSION, 0x07, 0x00].to_vec();
                                self.state =
                                    Socks5State::Failed(Socks5Error::UnsupportedCommand { cmd });
                                break;
                            }
                        }
                    }
                },
                Socks5State::Established | Socks5State::Failed(_) => break,
            }
        }
        let needs_more = matches!(
            self.state,
            Socks5State::Greeting | Socks5State::MethodSelected | Socks5State::UserPassAuth
        ) && !self.buf.is_empty();
        Socks5Step {
            state: self.state.clone(),
            response,
            flow,
            needs_more,
        }
    }
}

impl Default for Socks5Handshake {
    fn default() -> Self {
        Self::new()
    }
}

/// 解析问候段：VER NMETHODS METHODS。返回消费长度与所选方法（NO-AUTH 优先）。
fn parse_greeting(buf: &[u8]) -> Parse<u8> {
    if buf.len() < 2 {
        return Parse::NeedMore;
    }
    let version = buf[0];
    let methods = buf[1];
    if version != SOCKS5_VERSION {
        return Parse::Err(Socks5Error::BadVersion { got: version });
    }
    if methods == 0 {
        return Parse::Err(Socks5Error::BadMethodCount { count: 0 });
    }
    if buf.len() < 2 + usize::from(methods) {
        return Parse::NeedMore;
    }
    let mut no_auth = false;
    let mut user_pass = false;
    for &m in &buf[2..2 + usize::from(methods)] {
        match m {
            0x00 => no_auth = true,
            0x02 => user_pass = true,
            _ => {}
        }
    }
    // 优先 NO-AUTH（与服务端能力一致），其次 USER/PASS。
    let method = if no_auth {
        0x00
    } else if user_pass {
        0x02
    } else {
        0xFF
    };
    Parse::Done(2 + usize::from(methods), method)
}

/// 解析 RFC 1929 认证段：VER ULEN UNAME PLEN PASSWD。
fn parse_user_pass(buf: &[u8]) -> Parse<()> {
    if buf.len() < 2 {
        return Parse::NeedMore;
    }
    let version = buf[0];
    let ulen = buf[1];
    if version != 0x01 {
        return Parse::Err(Socks5Error::BadAuthVersion { got: version });
    }
    if buf.len() < 2 + usize::from(ulen) + 1 {
        return Parse::NeedMore;
    }
    let plen = buf[2 + usize::from(ulen)];
    if buf.len() < 2 + usize::from(ulen) + 1 + usize::from(plen) {
        return Parse::NeedMore;
    }
    Parse::Done(2 + usize::from(ulen) + 1 + usize::from(plen), ())
}

/// 解析请求段：VER CMD RSV ATYP DST.ADDR DST.PORT。返回 (cmd, address)。
fn parse_request(buf: &[u8]) -> Parse<(u8, Socks5Address)> {
    if buf.len() < 4 {
        return Parse::NeedMore;
    }
    let version = buf[0];
    let cmd = buf[1];
    let atyp = buf[3];
    if version != SOCKS5_VERSION {
        return Parse::Err(Socks5Error::BadRequestVersion { got: version });
    }
    let (address, addr_len) = match atyp {
        0x01 => {
            if buf.len() < 4 + 4 + 2 {
                return Parse::NeedMore;
            }
            let mut addr = [0u8; 4];
            addr.copy_from_slice(&buf[4..8]);
            let port = u16::from_be_bytes([buf[8], buf[9]]);
            (Socks5Address::Ipv4 { addr, port }, 4)
        }
        0x03 => {
            if buf.len() < 5 {
                return Parse::NeedMore;
            }
            let name_len = usize::from(buf[4]);
            if name_len == 0 {
                return Parse::Err(Socks5Error::InvalidAddress);
            }
            if buf.len() < 5 + name_len + 2 {
                return Parse::NeedMore;
            }
            let host = String::from_utf8_lossy(&buf[5..5 + name_len]).into_owned();
            let port = u16::from_be_bytes([buf[5 + name_len], buf[5 + name_len + 1]]);
            (Socks5Address::Domain { host, port }, name_len + 1)
        }
        0x04 => {
            if buf.len() < 4 + 16 + 2 {
                return Parse::NeedMore;
            }
            let mut addr = [0u8; 16];
            addr.copy_from_slice(&buf[4..20]);
            let port = u16::from_be_bytes([buf[20], buf[21]]);
            (Socks5Address::Ipv6 { addr, port }, 16)
        }
        _ => return Parse::Err(Socks5Error::UnsupportedAddressType { atyp }),
    };
    Parse::Done(4 + addr_len + 2, (cmd, address))
}

/// 编码一个 SOCKS5 地址（ATYP + ADDR + PORT）。
///
/// 域名长度由调用方校验（1..=255）；本函数只负责字节布局。
fn encode_address(out: &mut Vec<u8>, address: &Socks5Address) {
    match address {
        Socks5Address::Ipv4 { addr, port } => {
            out.push(0x01);
            out.extend_from_slice(addr);
            out.extend_from_slice(&port.to_be_bytes());
        }
        Socks5Address::Domain { host, port } => {
            out.push(0x03);
            out.push(host.len() as u8);
            out.extend_from_slice(host.as_bytes());
            out.extend_from_slice(&port.to_be_bytes());
        }
        Socks5Address::Ipv6 { addr, port } => {
            out.push(0x04);
            out.extend_from_slice(addr);
            out.extend_from_slice(&port.to_be_bytes());
        }
    }
}

/// 构造任意命令应答：`VER=5 | REP | RSV=0 | ATYP | BND.ADDR | BND.PORT`。
#[must_use]
pub fn encode_command_reply(rep: u8, bind: &Socks5Address) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 19);
    out.extend_from_slice(&[SOCKS5_VERSION, rep, 0x00]);
    encode_address(&mut out, bind);
    out
}

/// 构造 UDP ASSOCIATE 成功应答（`VER=5, REP=0, RSV=0` + BND.ADDR/PORT）。
#[must_use]
pub fn encode_udp_associate_reply(bind: &Socks5Address) -> Vec<u8> {
    encode_command_reply(0x00, bind)
}

/// 解析 SOCKS5 UDP 数据报：`RSV(2B=0) | FRAG | ATYP | ADDR | PORT | DATA`。
///
/// `TooShort` 只在不足固定头（4B）或按 ATYP 声明长度不足时报出；IPv4/IPv6 的最小
/// 合法长度分别为 10/22 字节，域名型按声明长度判定（短域名 + 空载荷合法）。
///
/// # Errors
///
/// 见 [`Socks5UdpError`]；FRAG != 0 不是结构错误（由上层策略丢弃）。
pub fn decode_udp_datagram(buf: &[u8]) -> Result<Socks5UdpDatagram, Socks5UdpError> {
    if buf.len() < 4 {
        return Err(Socks5UdpError::TooShort { len: buf.len() });
    }
    if buf[0] != 0 {
        return Err(Socks5UdpError::BadReserved { rsv: buf[0] });
    }
    if buf[1] != 0 {
        return Err(Socks5UdpError::BadReserved { rsv: buf[1] });
    }
    let fragment = buf[2];
    let atyp = buf[3];
    let (address, header_len) = match atyp {
        0x01 => {
            if buf.len() < 4 + 4 + 2 {
                return Err(Socks5UdpError::TooShort { len: buf.len() });
            }
            let mut addr = [0u8; 4];
            addr.copy_from_slice(&buf[4..8]);
            let port = u16::from_be_bytes([buf[8], buf[9]]);
            (Socks5Address::Ipv4 { addr, port }, 10)
        }
        0x03 => {
            if buf.len() < 5 {
                return Err(Socks5UdpError::TooShort { len: buf.len() });
            }
            let name_len = usize::from(buf[4]);
            if name_len == 0 {
                return Err(Socks5UdpError::InvalidAddress);
            }
            if buf.len() < 5 + name_len + 2 {
                return Err(Socks5UdpError::TooShort { len: buf.len() });
            }
            let host = String::from_utf8_lossy(&buf[5..5 + name_len]).into_owned();
            let port = u16::from_be_bytes([buf[5 + name_len], buf[5 + name_len + 1]]);
            (Socks5Address::Domain { host, port }, 5 + name_len + 2)
        }
        0x04 => {
            if buf.len() < 4 + 16 + 2 {
                return Err(Socks5UdpError::TooShort { len: buf.len() });
            }
            let mut addr = [0u8; 16];
            addr.copy_from_slice(&buf[4..20]);
            let port = u16::from_be_bytes([buf[20], buf[21]]);
            (Socks5Address::Ipv6 { addr, port }, 22)
        }
        _ => return Err(Socks5UdpError::UnsupportedAddressType { atyp }),
    };
    Ok(Socks5UdpDatagram {
        fragment,
        address,
        payload: buf[header_len..].to_vec(),
    })
}

/// 编码 SOCKS5 UDP 数据报（`RSV=0, FRAG=0`）。
///
/// # Errors
///
/// 域名为空/超过 255 字节 → [`Socks5UdpError::InvalidAddress`]；
/// 编码后超过 65507 字节 → [`Socks5UdpError::DatagramTooLarge`]。
pub fn encode_udp_datagram(
    address: &Socks5Address,
    payload: &[u8],
) -> Result<Vec<u8>, Socks5UdpError> {
    const MAX_UDP_DATAGRAM_BYTES: usize = 65507;
    if let Socks5Address::Domain { host, .. } = address
        && (host.is_empty() || host.len() > 255)
    {
        return Err(Socks5UdpError::InvalidAddress);
    }
    let mut out = Vec::with_capacity(4 + 19 + payload.len());
    out.extend_from_slice(&[0x00, 0x00, 0x00]);
    encode_address(&mut out, address);
    out.extend_from_slice(payload);
    if out.len() > MAX_UDP_DATAGRAM_BYTES {
        return Err(Socks5UdpError::DatagramTooLarge {
            len: out.len(),
            limit: MAX_UDP_DATAGRAM_BYTES,
        });
    }
    Ok(out)
}

/// 16 字节 IPv6 → 未压缩十六进制段格式（portable，无 std::net 依赖）。
fn format_ipv6(addr: &[u8; 16]) -> String {
    let mut parts = Vec::with_capacity(8);
    for chunk in addr.chunks(2) {
        let v = u16::from_be_bytes([chunk[0], chunk[1]]);
        parts.push(format!("{v:x}"));
    }
    format!("[{}]", parts.join(":"))
}

/// 结构化错误 → SOCKS5 REP 码。
fn socks5_failure_rep(e: &Socks5Error) -> u8 {
    match e {
        Socks5Error::BadVersion { .. } | Socks5Error::BadRequestVersion { .. } => 0x01,
        Socks5Error::UnsupportedCommand { .. } => 0x07,
        Socks5Error::UnsupportedAddressType { .. } => 0x08,
        Socks5Error::BadMethodCount { .. }
        | Socks5Error::NoAcceptableMethod
        | Socks5Error::BadAuthVersion { .. }
        | Socks5Error::AuthFailed
        | Socks5Error::InvalidAddress => 0x01,
    }
}

// ---------- HTTP 代理有状态握手状态机（RFC 7230 请求行 / CONNECT，§11.19） ----------

/// 结构化 HTTP 代理协议错误（非文本日志）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpProxyError {
    /// 请求行不是 `METHOD SP request-target SP HTTP/x.y` 三段。
    BadRequestLine,
    /// 方法既非 CONNECT 也非可转发方法。
    UnknownMethod { method: String },
    /// 非 CONNECT 但 request-target 是 origin-form（`/path`，无 scheme），代理要求绝对形式。
    OriginFormNotAllowed,
    /// 绝对形式 URL scheme 不是 `http://`（本期不支持 `https://` 绝对形式）。
    UnsupportedScheme,
    /// authority（host[:port]）无法解析。
    InvalidAuthority,
}

impl core::fmt::Display for HttpProxyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadRequestLine => write!(f, "http-proxy bad request line"),
            Self::UnknownMethod { method } => write!(f, "http-proxy unknown method {method}"),
            Self::OriginFormNotAllowed => {
                write!(f, "http-proxy origin-form target requires absolute-form")
            }
            Self::UnsupportedScheme => write!(f, "http-proxy only supports http:// absolute-form"),
            Self::InvalidAuthority => write!(f, "http-proxy invalid authority"),
        }
    }
}

impl std::error::Error for HttpProxyError {}

/// HTTP 代理握手阶段。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpProxyState {
    /// 等待请求行结束（`\r\n`）。
    RequestLine,
    /// 已解析请求行，等待请求头结束（`\r\n\r\n`）。
    Headers,
    /// 握手完成，可进入数据面。
    Established,
    /// 握手失败（结构化原因）。
    Failed(HttpProxyError),
}

/// `feed` 的单步产物。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpProxyStep {
    /// 推进后的状态。
    pub state: HttpProxyState,
    /// 需要向客户端发送的响应字节（CONNECT=200；错误=400；转发型为空）。
    pub response: Vec<u8>,
    /// 握手完成时产出的中立 FlowContext（仅 `Established` 时 `Some`）。
    pub flow: Option<FlowContext>,
    /// 已收到合法前缀但输入不足，等待更多字节。
    pub needs_more: bool,
    /// 转发型握手：应先写上给上游的字节（改写后的 origin-form 请求行 + 已收请求头）。
    /// CONNECT 隧道为空（先回 200 再裸中继）。
    pub upstream_prefix: Vec<u8>,
}

/// HTTP 代理有状态握手状态机（portable 纯函数，零 I/O）。
///
/// 与 `Socks5Handshake` 同构：增量 `feed`，内部缓冲直到请求头结束（`\r\n\r\n`）。
/// CONNECT 回 200 后裸中继；绝对形式 GET/POST 把请求行改写为 origin-form 并随请求头
/// 作为 `upstream_prefix` 先写上给上游。
pub struct HttpProxyHandshake {
    state: HttpProxyState,
    buf: Vec<u8>,
    // 请求行解析后、等待请求头阶段携带的中间结果。
    is_connect: bool,
    destination: String,
    /// 请求行结束后的偏移（请求头起始），用于切片已收请求头。
    headers_start: usize,
    /// 转发型：改写后的 origin-form 请求行（含结尾 `\r\n`）。
    rewritten_line: Vec<u8>,
}

impl HttpProxyHandshake {
    /// 新建握手状态机（起始 `RequestLine`）。
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: HttpProxyState::RequestLine,
            buf: Vec::new(),
            is_connect: false,
            destination: String::new(),
            headers_start: 0,
            rewritten_line: Vec::new(),
        }
    }

    /// 当前状态。
    #[must_use]
    pub fn state(&self) -> &HttpProxyState {
        &self.state
    }

    /// 取出握手完成后剩余的数据面字节（仅在 `Established` 后有意义）。
    #[must_use]
    pub fn take_data(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.buf)
    }

    /// 喂入字节并推进状态机。
    pub fn feed(&mut self, bytes: &[u8]) -> HttpProxyStep {
        self.buf.extend_from_slice(bytes);
        let mut response = Vec::new();
        let mut flow = None;
        let mut upstream_prefix = Vec::new();
        loop {
            match self.state.clone() {
                HttpProxyState::RequestLine => {
                    // 找请求行结束（第一个 \r\n）。
                    let line_end = match find_subsequence(&self.buf, b"\r\n") {
                        Some(i) => i,
                        None => break,
                    };
                    let line = &self.buf[..line_end];
                    match parse_request_line(line) {
                        Ok((method, target, version)) => {
                            self.headers_start = line_end + 2;
                            if method == "CONNECT" {
                                // CONNECT host:port —— target 即 authority。
                                match parse_authority(target) {
                                    Ok(dest) => {
                                        self.is_connect = true;
                                        self.destination = dest;
                                        self.rewritten_line.clear();
                                        self.state = HttpProxyState::Headers;
                                    }
                                    Err(e) => {
                                        response = bad_request();
                                        self.state = HttpProxyState::Failed(e);
                                        break;
                                    }
                                }
                            } else {
                                // 转发型：origin-form（/path）直接拒绝；否则要求绝对形式 http://。
                                if target.starts_with('/') {
                                    response = bad_request();
                                    self.state = HttpProxyState::Failed(
                                        HttpProxyError::OriginFormNotAllowed,
                                    );
                                    break;
                                }
                                match parse_absolute_url(target) {
                                    Ok((dest, path_target)) => {
                                        self.is_connect = false;
                                        self.destination = dest;
                                        self.rewritten_line =
                                            format!("{method} {path_target} {version}\r\n")
                                                .into_bytes();
                                        self.state = HttpProxyState::Headers;
                                    }
                                    Err(e) => {
                                        response = bad_request();
                                        self.state = HttpProxyState::Failed(e);
                                        break;
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            response = bad_request();
                            self.state = HttpProxyState::Failed(e);
                            break;
                        }
                    }
                }
                HttpProxyState::Headers => {
                    // 找请求头结束（\r\n\r\n）。
                    let header_end = match find_subsequence(&self.buf, b"\r\n\r\n") {
                        Some(i) => i,
                        None => break,
                    };
                    let consumed = header_end + 4;
                    if self.is_connect {
                        response = b"HTTP/1.1 200 Connection Established\r\n\r\n".to_vec();
                        flow = Some(classify(FlowOrigin::Http, &self.destination, ""));
                    } else {
                        // upstream_prefix = 改写后的 origin-form 请求行 + 已收请求头（含结尾 \r\n\r\n）。
                        upstream_prefix = self.rewritten_line.clone();
                        upstream_prefix.extend_from_slice(&self.buf[self.headers_start..consumed]);
                        flow = Some(classify(FlowOrigin::Http, &self.destination, ""));
                    }
                    self.buf.drain(..consumed);
                    self.state = HttpProxyState::Established;
                    break;
                }
                HttpProxyState::Established | HttpProxyState::Failed(_) => break,
            }
        }
        let needs_more = matches!(
            self.state,
            HttpProxyState::RequestLine | HttpProxyState::Headers
        ) && !self.buf.is_empty();
        HttpProxyStep {
            state: self.state.clone(),
            response,
            flow,
            needs_more,
            upstream_prefix,
        }
    }
}

impl Default for HttpProxyHandshake {
    fn default() -> Self {
        Self::new()
    }
}

/// 结构化 400 响应体。
fn bad_request() -> Vec<u8> {
    b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n".to_vec()
}

/// 在 haystack 中找 needle 的起始下标（纯字节搜索，portable）。
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// 解析请求行：`METHOD SP request-target SP HTTP/x.y`。返回 (method, target, version)。
fn parse_request_line(line: &[u8]) -> Result<(&str, &str, &str), HttpProxyError> {
    let text = core::str::from_utf8(line).map_err(|_| HttpProxyError::BadRequestLine)?;
    let mut parts = text.split_whitespace();
    let method = parts.next().ok_or(HttpProxyError::BadRequestLine)?;
    let target = parts.next().ok_or(HttpProxyError::BadRequestLine)?;
    let version = parts.next().ok_or(HttpProxyError::BadRequestLine)?;
    if parts.next().is_some() {
        return Err(HttpProxyError::BadRequestLine);
    }
    if method.is_empty() || target.is_empty() || version.is_empty() {
        return Err(HttpProxyError::BadRequestLine);
    }
    if !version.starts_with("HTTP/") {
        return Err(HttpProxyError::BadRequestLine);
    }
    // 可转发方法白名单：CONNECT 单独处理；其余常见安全方法放行。
    const FORWARDABLE: [&str; 6] = ["GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS"];
    if method != "CONNECT" && !FORWARDABLE.contains(&method) {
        return Err(HttpProxyError::UnknownMethod {
            method: method.to_string(),
        });
    }
    Ok((method, target, version))
}

/// 解析 CONNECT authority：`host:port` 或 `[ipv6]:port`。缺省端口 443。
fn parse_authority(target: &str) -> Result<String, HttpProxyError> {
    let (host, port) = split_host_port(target).map_err(|_| HttpProxyError::InvalidAuthority)?;
    if host.is_empty() {
        return Err(HttpProxyError::InvalidAuthority);
    }
    Ok(format!("{host}:{port}"))
}

/// 解析绝对形式 URL：`http://host[:port]/path?query`。返回 (destination, path?query)。
fn parse_absolute_url(target: &str) -> Result<(String, String), HttpProxyError> {
    let rest = target
        .strip_prefix("http://")
        .ok_or(HttpProxyError::UnsupportedScheme)?;
    // 拆 authority 与 path。
    let (authority, path_query) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    // 剥离 userinfo（@ 之后才是 host）。
    let authority = match authority.rfind('@') {
        Some(at) => &authority[at + 1..],
        None => authority,
    };
    if authority.is_empty() {
        return Err(HttpProxyError::InvalidAuthority);
    }
    // 缺省端口 80（HTTP 绝对形式）。
    let (host, port) = split_host_port_or_default(authority, 80)?;
    Ok((format!("{host}:{port}"), path_query.to_string()))
}

/// 拆 `host:port` / `[ipv6]:port`；无端口时用 default_port。
fn split_host_port_or_default(
    authority: &str,
    default_port: u16,
) -> Result<(String, u16), HttpProxyError> {
    if let Some(rest) = authority.strip_prefix('[') {
        let close = rest.find(']').ok_or(HttpProxyError::InvalidAuthority)?;
        let host = rest[..close].to_string();
        let tail = &rest[close + 1..];
        let port = match tail.strip_prefix(':') {
            Some(p) => p.parse().map_err(|_| HttpProxyError::InvalidAuthority)?,
            None => default_port,
        };
        return Ok((host, port));
    }
    match authority.rfind(':') {
        Some(i) => {
            let host = authority[..i].to_string();
            let port = authority[i + 1..]
                .parse()
                .map_err(|_| HttpProxyError::InvalidAuthority)?;
            Ok((host, port))
        }
        None => Ok((authority.to_string(), default_port)),
    }
}

/// 拆 `host:port`（必须有端口），用于 CONNECT target。
fn split_host_port(target: &str) -> Result<(String, u16), HttpProxyError> {
    if let Some(rest) = target.strip_prefix('[') {
        let close = rest.find(']').ok_or(HttpProxyError::InvalidAuthority)?;
        let host = rest[..close].to_string();
        let tail = &rest[close + 1..];
        let port = tail
            .strip_prefix(':')
            .and_then(|p| p.parse().ok())
            .ok_or(HttpProxyError::InvalidAuthority)?;
        return Ok((host, port));
    }
    let i = target.rfind(':').ok_or(HttpProxyError::InvalidAuthority)?;
    let host = target[..i].to_string();
    let port = target[i + 1..]
        .parse()
        .map_err(|_| HttpProxyError::InvalidAuthority)?;
    Ok((host, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_by_origin_and_stays_neutral() {
        let f = from_socks5("example.invalid:443", "Balanced");
        assert_eq!(f.origin, FlowOrigin::Socks5);
        assert_eq!(f.resource, ResourceId(INTERNET_ACCESS_RESOURCE.into()));
        assert_eq!(f.destination, "example.invalid:443");
        assert_eq!(from_http("h", "p").origin, FlowOrigin::Http);
        assert_eq!(
            from_virtual_packet_interface("h", "p").origin,
            FlowOrigin::VirtualPacketInterface
        );
        assert_eq!(from_native_api("h", "p").origin, FlowOrigin::NativeApi);
    }

    #[test]
    fn ingress_does_not_carry_path_or_provider() {
        let f = from_native_api("h", "p");
        // 中立上下文只含 resource/destination/profile，编译期即无 Path/Provider 字段可设。
        assert_eq!(f.profile, "p");
    }

    // ---------- SOCKS5 有状态握手状态机 ----------

    #[test]
    fn greeting_no_auth_selects_method() {
        let mut hs = Socks5Handshake::new();
        let step = hs.feed(&[0x05, 0x01, 0x00]);
        assert_eq!(step.state, Socks5State::MethodSelected);
        assert_eq!(step.response, [0x05, 0x00]);
        assert!(step.flow.is_none());
        assert!(!step.needs_more);
    }

    #[test]
    fn greeting_user_pass_enters_auth_state() {
        let mut hs = Socks5Handshake::new();
        let step = hs.feed(&[0x05, 0x01, 0x02]);
        assert_eq!(step.state, Socks5State::UserPassAuth);
        assert_eq!(step.response, [0x05, 0x02]);
    }

    #[test]
    fn greeting_bad_version_fails_structured() {
        let mut hs = Socks5Handshake::new();
        let step = hs.feed(&[0x04, 0x01, 0x00]);
        assert_eq!(
            step.state,
            Socks5State::Failed(Socks5Error::BadVersion { got: 0x04 })
        );
    }

    #[test]
    fn greeting_zero_methods_fails() {
        let mut hs = Socks5Handshake::new();
        let step = hs.feed(&[0x05, 0x00]);
        assert!(matches!(
            step.state,
            Socks5State::Failed(Socks5Error::BadMethodCount { count: 0 })
        ));
    }

    #[test]
    fn greeting_no_acceptable_method_fails() {
        let mut hs = Socks5Handshake::new();
        let step = hs.feed(&[0x05, 0x01, 0x01]);
        assert_eq!(
            step.state,
            Socks5State::Failed(Socks5Error::NoAcceptableMethod)
        );
    }

    #[test]
    fn truncated_greeting_waits_for_more() {
        let mut hs = Socks5Handshake::new();
        let step = hs.feed(&[0x05, 0x02]);
        assert_eq!(step.state, Socks5State::Greeting);
        assert!(step.needs_more);
        let step = hs.feed(&[0x00, 0x00]);
        assert_eq!(step.state, Socks5State::MethodSelected);
        assert_eq!(step.response, [0x05, 0x00]);
    }

    #[test]
    fn full_handshake_connect_domain_establishes_flow() {
        let mut hs = Socks5Handshake::new();
        // 一次喂入全部（问候 + CONNECT example.com:443）。
        let mut bytes = vec![0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x03, 0x0b];
        bytes.extend_from_slice(b"example.com");
        bytes.extend_from_slice(&[0x01, 0xbb]);
        let step = hs.feed(&bytes);
        assert_eq!(step.state, Socks5State::Established);
        assert_eq!(step.response, [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
        let flow = step.flow.expect("flow produced on established");
        assert_eq!(flow.origin, FlowOrigin::Socks5);
        assert_eq!(flow.destination, "example.com:443");
    }

    #[test]
    fn full_handshake_connect_ipv4_and_ipv6() {
        let mut hs = Socks5Handshake::new();
        hs.feed(&[0x05, 0x01, 0x00]);
        let step = hs.feed(&[0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x1f, 0x90]);
        assert_eq!(step.flow.unwrap().destination, "127.0.0.1:8080");

        let mut hs6 = Socks5Handshake::new();
        hs6.feed(&[0x05, 0x01, 0x00]);
        let mut req = vec![0x05, 0x01, 0x00, 0x04];
        req.extend_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x2a,
        ]);
        req.extend_from_slice(&[0x00, 0x35]);
        let step = hs6.feed(&req);
        assert_eq!(step.flow.unwrap().destination, "[2001:db8:0:0:0:0:0:2a]:53");
    }

    #[test]
    fn request_bad_version_fails_with_rep() {
        let mut hs = Socks5Handshake::new();
        hs.feed(&[0x05, 0x01, 0x00]);
        let step = hs.feed(&[0x04, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0, 80]);
        assert!(matches!(
            step.state,
            Socks5State::Failed(Socks5Error::BadRequestVersion { got: 0x04 })
        ));
        // REP=general failure (0x01)。
        assert_eq!(step.response, [0x05, 0x01, 0x00]);
    }

    #[test]
    fn unsupported_command_returns_command_not_supported() {
        let mut hs = Socks5Handshake::new();
        hs.feed(&[0x05, 0x01, 0x00]);
        // BIND (0x02)。
        let step = hs.feed(&[0x05, 0x02, 0x00, 0x01, 127, 0, 0, 1, 0, 80]);
        assert_eq!(
            step.state,
            Socks5State::Failed(Socks5Error::UnsupportedCommand { cmd: 0x02 })
        );
        assert_eq!(step.response, [0x05, 0x07, 0x00]);
    }

    #[test]
    fn unsupported_address_type_fails() {
        let mut hs = Socks5Handshake::new();
        hs.feed(&[0x05, 0x01, 0x00]);
        let step = hs.feed(&[0x05, 0x01, 0x00, 0x09, 1, 2, 3, 0, 80]);
        assert!(matches!(
            step.state,
            Socks5State::Failed(Socks5Error::UnsupportedAddressType { atyp: 0x09 })
        ));
    }

    #[test]
    fn user_pass_auth_roundtrip() {
        let mut hs = Socks5Handshake::new();
        hs.feed(&[0x05, 0x01, 0x02]);
        let step = hs.feed(&[0x01, 0x03, b'u', b's', b'r', 0x03, b'p', b'w', b'd']);
        assert_eq!(step.state, Socks5State::MethodSelected);
        assert_eq!(step.response, [0x01, 0x00]);
        // 继续 CONNECT。
        let step = hs.feed(&[0x05, 0x01, 0x00, 0x03, 0x03, b'a', b'b', b'c', 0x00, 0x50]);
        assert_eq!(step.state, Socks5State::Established);
        assert_eq!(step.flow.unwrap().destination, "abc:80");
    }

    #[test]
    fn user_pass_bad_auth_version_fails() {
        let mut hs = Socks5Handshake::new();
        hs.feed(&[0x05, 0x01, 0x02]);
        let step = hs.feed(&[0x02, 0x01, b'x', 0x01, b'y']);
        assert_eq!(
            step.state,
            Socks5State::Failed(Socks5Error::BadAuthVersion { got: 0x02 })
        );
        assert_eq!(step.response, [0x01, 0x01]);
    }

    #[test]
    fn established_take_data_exposes_payload() {
        let mut hs = Socks5Handshake::new();
        let mut bytes = vec![
            0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x01, 8, 8, 8, 8, 0x00, 0x35,
        ];
        bytes.extend_from_slice(b"GET / HTTP/1.1\r\n");
        let step = hs.feed(&bytes);
        assert_eq!(step.state, Socks5State::Established);
        assert_eq!(hs.take_data(), b"GET / HTTP/1.1\r\n");
    }

    #[test]
    fn empty_domain_is_invalid_address() {
        let mut hs = Socks5Handshake::new();
        hs.feed(&[0x05, 0x01, 0x00]);
        let step = hs.feed(&[0x05, 0x01, 0x00, 0x03, 0x00, 0x00, 0x50]);
        assert_eq!(step.state, Socks5State::Failed(Socks5Error::InvalidAddress));
    }

    // ---------- SOCKS5 UDP ASSOCIATE（§3.7） ----------

    #[test]
    fn command_is_none_before_established() {
        let mut hs = Socks5Handshake::new();
        hs.feed(&[0x05, 0x01, 0x00]);
        assert!(hs.command().is_none());
    }

    #[test]
    fn connect_exposes_target_command() {
        let mut hs = Socks5Handshake::new();
        let mut bytes = vec![0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x03, 0x0b];
        bytes.extend_from_slice(b"example.com");
        bytes.extend_from_slice(&[0x01, 0xbb]);
        let step = hs.feed(&bytes);
        assert_eq!(step.state, Socks5State::Established);
        assert_eq!(
            hs.command(),
            Some(&Socks5Command::Connect {
                target: Socks5Address::Domain {
                    host: "example.com".into(),
                    port: 443,
                },
            })
        );
    }

    #[test]
    fn udp_associate_unspecified_endpoint_establishes_without_response() {
        let mut hs = Socks5Handshake::new();
        hs.feed(&[0x05, 0x01, 0x00]);
        let step = hs.feed(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
        assert_eq!(step.state, Socks5State::Established);
        // 状态机不知道真实 bind 地址：响应必须为空，由调用方 encode_udp_associate_reply。
        assert!(step.response.is_empty());
        assert!(step.flow.is_none());
        assert!(!step.needs_more);
        assert_eq!(
            hs.command(),
            Some(&Socks5Command::UdpAssociate {
                client_endpoint: None
            })
        );
        assert!(hs.take_data().is_empty());
    }

    #[test]
    fn udp_associate_concrete_endpoint_is_kept_as_hint() {
        let mut hs = Socks5Handshake::new();
        hs.feed(&[0x05, 0x01, 0x00]);
        let step = hs.feed(&[0x05, 0x03, 0x00, 0x01, 127, 0, 0, 1, 0x1f, 0x90]);
        assert_eq!(step.state, Socks5State::Established);
        assert_eq!(
            hs.command(),
            Some(&Socks5Command::UdpAssociate {
                client_endpoint: Some(Socks5Address::Ipv4 {
                    addr: [127, 0, 0, 1],
                    port: 8080,
                }),
            })
        );
    }

    #[test]
    fn udp_associate_domain_endpoint_and_zero_port_is_not_unspecified() {
        let mut hs = Socks5Handshake::new();
        hs.feed(&[0x05, 0x01, 0x00]);
        let mut req = vec![0x05, 0x03, 0x00, 0x03, 0x03];
        req.extend_from_slice(b"abc");
        req.extend_from_slice(&[0x00, 0x00]);
        let step = hs.feed(&req);
        assert_eq!(step.state, Socks5State::Established);
        assert_eq!(
            hs.command(),
            Some(&Socks5Command::UdpAssociate {
                client_endpoint: Some(Socks5Address::Domain {
                    host: "abc".into(),
                    port: 0,
                }),
            })
        );
    }

    #[test]
    fn bind_is_still_command_not_supported() {
        let mut hs = Socks5Handshake::new();
        hs.feed(&[0x05, 0x01, 0x00]);
        let step = hs.feed(&[0x05, 0x02, 0x00, 0x01, 127, 0, 0, 1, 0, 80]);
        assert_eq!(
            step.state,
            Socks5State::Failed(Socks5Error::UnsupportedCommand { cmd: 0x02 })
        );
        assert_eq!(step.response, [0x05, 0x07, 0x00]);
        assert!(hs.command().is_none());
    }

    #[test]
    fn udp_associate_unknown_command_still_rejected() {
        let mut hs = Socks5Handshake::new();
        hs.feed(&[0x05, 0x01, 0x00]);
        let step = hs.feed(&[0x05, 0x09, 0x00, 0x01, 127, 0, 0, 1, 0, 80]);
        assert_eq!(
            step.state,
            Socks5State::Failed(Socks5Error::UnsupportedCommand { cmd: 0x09 })
        );
        assert_eq!(step.response, [0x05, 0x07, 0x00]);
    }

    #[test]
    fn address_helpers_destination_and_unspecified() {
        let v4 = Socks5Address::Ipv4 {
            addr: [8, 8, 8, 8],
            port: 53,
        };
        assert_eq!(v4.port(), 53);
        assert_eq!(v4.to_destination_string(), "8.8.8.8:53");
        assert!(!v4.is_unspecified());

        let domain = Socks5Address::Domain {
            host: "example.com".into(),
            port: 443,
        };
        assert_eq!(domain.to_destination_string(), "example.com:443");
        assert!(!domain.is_unspecified());

        let v6 = Socks5Address::Ipv6 {
            addr: [
                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x2a,
            ],
            port: 53,
        };
        assert_eq!(v6.to_destination_string(), "[2001:db8:0:0:0:0:0:2a]:53");
        assert!(!v6.is_unspecified());

        assert!(
            Socks5Address::Ipv4 {
                addr: [0, 0, 0, 0],
                port: 0
            }
            .is_unspecified()
        );
        assert!(
            Socks5Address::Ipv6 {
                addr: [0; 16],
                port: 0
            }
            .is_unspecified()
        );
        // 未指定地址但端口非 0：不是 unspecified（端口锁定 hint 有意义）。
        assert!(
            !Socks5Address::Ipv4 {
                addr: [0, 0, 0, 0],
                port: 9000
            }
            .is_unspecified()
        );
    }

    #[test]
    fn encode_udp_associate_reply_uses_bind_address() {
        let bind = Socks5Address::Ipv4 {
            addr: [127, 0, 0, 1],
            port: 31,
        };
        let reply = encode_udp_associate_reply(&bind);
        assert_eq!(reply, [0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x1f]);
        assert_eq!(reply.len(), 10);

        let v6 = Socks5Address::Ipv6 {
            addr: [0; 16],
            port: 1080,
        };
        let reply = encode_command_reply(0x01, &v6);
        assert_eq!(reply.len(), 22);
        assert_eq!(&reply[..4], &[0x05, 0x01, 0x00, 0x04]);
        assert_eq!(&reply[20..], &1080u16.to_be_bytes());
    }

    #[test]
    fn udp_datagram_roundtrip_ipv4() {
        let address = Socks5Address::Ipv4 {
            addr: [127, 0, 0, 1],
            port: 5353,
        };
        let bytes = encode_udp_datagram(&address, b"hello").expect("encode");
        assert_eq!(&bytes[..4], &[0x00, 0x00, 0x00, 0x01]);
        let datagram = decode_udp_datagram(&bytes).expect("decode");
        assert_eq!(datagram.fragment, 0);
        assert_eq!(datagram.address, address);
        assert_eq!(datagram.payload, b"hello");
    }

    #[test]
    fn udp_datagram_roundtrip_domain_and_ipv6() {
        let domain = Socks5Address::Domain {
            host: "example.com".into(),
            port: 443,
        };
        let bytes = encode_udp_datagram(&domain, b"x").expect("encode");
        let datagram = decode_udp_datagram(&bytes).expect("decode");
        assert_eq!(datagram.address, domain);
        assert_eq!(datagram.payload, b"x");

        let v6 = Socks5Address::Ipv6 {
            addr: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            port: 53,
        };
        let bytes = encode_udp_datagram(&v6, b"dns").expect("encode");
        let datagram = decode_udp_datagram(&bytes).expect("decode");
        assert_eq!(datagram.address, v6);
        assert_eq!(datagram.payload, b"dns");
    }

    #[test]
    fn udp_datagram_short_domain_with_empty_payload_is_accepted() {
        // 域名为 1 字节、空载荷：编码后 8 字节（< IPv4 最小 10B）。
        let domain = Socks5Address::Domain {
            host: "a".into(),
            port: 7,
        };
        let bytes = encode_udp_datagram(&domain, b"").expect("encode");
        assert_eq!(bytes.len(), 8);
        let datagram = decode_udp_datagram(&bytes).expect("decode");
        assert_eq!(datagram.address, domain);
        assert!(datagram.payload.is_empty());
    }

    #[test]
    fn udp_datagram_fragment_is_preserved_not_rejected() {
        let address = Socks5Address::Ipv4 {
            addr: [1, 2, 3, 4],
            port: 9,
        };
        let mut bytes = encode_udp_datagram(&address, b"p").expect("encode");
        bytes[2] = 1; // FRAG=1
        let datagram = decode_udp_datagram(&bytes).expect("decode");
        assert_eq!(datagram.fragment, 1);
    }

    #[test]
    fn udp_datagram_rejects_malformed_headers() {
        // 固定头不足。
        assert_eq!(
            decode_udp_datagram(&[0x00, 0x00, 0x00]),
            Err(Socks5UdpError::TooShort { len: 3 })
        );
        // RSV 非 0。
        assert_eq!(
            decode_udp_datagram(&[0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]),
            Err(Socks5UdpError::BadReserved { rsv: 0x01 })
        );
        // ATYP 非 1/3/4。
        assert_eq!(
            decode_udp_datagram(&[0x00, 0x00, 0x00, 0x09, 0, 0, 0, 0, 0, 0]),
            Err(Socks5UdpError::UnsupportedAddressType { atyp: 0x09 })
        );
        // 域名为空。
        assert_eq!(
            decode_udp_datagram(&[0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x50]),
            Err(Socks5UdpError::InvalidAddress)
        );
        // 域名声明长度超出缓冲。
        assert_eq!(
            decode_udp_datagram(&[0x00, 0x00, 0x00, 0x03, 0x05, b'a']),
            Err(Socks5UdpError::TooShort { len: 6 })
        );
        // IPv4 少 1 字节。
        assert_eq!(
            decode_udp_datagram(&[0x00, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0]),
            Err(Socks5UdpError::TooShort { len: 9 })
        );
    }

    #[test]
    fn encode_udp_datagram_enforces_size_and_domain_limits() {
        let address = Socks5Address::Ipv4 {
            addr: [1, 2, 3, 4],
            port: 9,
        };
        // 4 + 6 + 65497 = 65507：恰好允许。
        let payload = vec![0u8; 65497];
        assert_eq!(
            encode_udp_datagram(&address, &payload)
                .expect("encode")
                .len(),
            65507
        );
        // 多 1 字节 → 超限。
        let payload = vec![0u8; 65498];
        assert_eq!(
            encode_udp_datagram(&address, &payload),
            Err(Socks5UdpError::DatagramTooLarge {
                len: 65508,
                limit: 65507,
            })
        );
        // 空域名。
        let bad_domain = Socks5Address::Domain {
            host: String::new(),
            port: 1,
        };
        assert_eq!(
            encode_udp_datagram(&bad_domain, b""),
            Err(Socks5UdpError::InvalidAddress)
        );
        // 超长域名。
        let bad_domain = Socks5Address::Domain {
            host: "a".repeat(256),
            port: 1,
        };
        assert_eq!(
            encode_udp_datagram(&bad_domain, b""),
            Err(Socks5UdpError::InvalidAddress)
        );
    }

    // ---------- HTTP 代理有状态握手状态机（§11.19） ----------

    #[test]
    fn http_connect_replies_200_and_establishes_flow() {
        let mut hs = HttpProxyHandshake::new();
        let step = hs.feed(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n");
        assert_eq!(step.state, HttpProxyState::Established);
        assert_eq!(
            step.response,
            b"HTTP/1.1 200 Connection Established\r\n\r\n".to_vec()
        );
        assert!(step.upstream_prefix.is_empty());
        let flow = step.flow.expect("flow");
        assert_eq!(flow.origin, FlowOrigin::Http);
        assert_eq!(flow.destination, "example.com:443");
    }

    #[test]
    fn http_absolute_get_rewrites_origin_form_prefix() {
        let mut hs = HttpProxyHandshake::new();
        let step =
            hs.feed(b"GET http://example.com/path?x=1 HTTP/1.1\r\nHost: example.com\r\n\r\n");
        assert_eq!(step.state, HttpProxyState::Established);
        assert!(step.response.is_empty());
        assert_eq!(step.flow.unwrap().destination, "example.com:80");
        // 改写后的 origin-form 请求行 + 原请求头。
        assert_eq!(
            step.upstream_prefix,
            b"GET /path?x=1 HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec()
        );
    }

    #[test]
    fn http_absolute_get_explicit_port_preserved() {
        let mut hs = HttpProxyHandshake::new();
        let step = hs.feed(b"GET http://example.com:8080/ HTTP/1.1\r\n\r\n");
        assert_eq!(step.state, HttpProxyState::Established);
        assert_eq!(step.flow.unwrap().destination, "example.com:8080");
        assert_eq!(step.upstream_prefix, b"GET / HTTP/1.1\r\n\r\n".to_vec());
    }

    #[test]
    fn http_truncated_request_line_waits_for_more() {
        let mut hs = HttpProxyHandshake::new();
        let step = hs.feed(b"GET http://exa");
        assert_eq!(step.state, HttpProxyState::RequestLine);
        assert!(step.needs_more);
        let step = hs.feed(b"mple.com/ HTTP/1.1\r\n\r\n");
        assert_eq!(step.state, HttpProxyState::Established);
        assert_eq!(step.flow.unwrap().destination, "example.com:80");
    }

    #[test]
    fn http_origin_form_get_is_rejected() {
        let mut hs = HttpProxyHandshake::new();
        let step = hs.feed(b"GET /path HTTP/1.1\r\nHost: x\r\n\r\n");
        assert_eq!(
            step.state,
            HttpProxyState::Failed(HttpProxyError::OriginFormNotAllowed)
        );
        assert!(step.response.starts_with(b"HTTP/1.1 400 Bad Request"));
    }

    #[test]
    fn http_unknown_scheme_is_rejected() {
        let mut hs = HttpProxyHandshake::new();
        let step = hs.feed(b"GET https://example.com/ HTTP/1.1\r\n\r\n");
        assert_eq!(
            step.state,
            HttpProxyState::Failed(HttpProxyError::UnsupportedScheme)
        );
    }

    #[test]
    fn http_bad_request_line_is_400() {
        let mut hs = HttpProxyHandshake::new();
        let step = hs.feed(b"garbage line here\r\n\r\n");
        assert!(matches!(
            step.state,
            HttpProxyState::Failed(HttpProxyError::BadRequestLine)
        ));
    }

    #[test]
    fn http_connect_missing_port_is_invalid() {
        let mut hs = HttpProxyHandshake::new();
        let step = hs.feed(b"CONNECT example.com HTTP/1.1\r\n\r\n");
        assert_eq!(
            step.state,
            HttpProxyState::Failed(HttpProxyError::InvalidAuthority)
        );
    }

    #[test]
    fn http_established_take_data_exposes_pipelined_bytes() {
        let mut hs = HttpProxyHandshake::new();
        let mut bytes = b"CONNECT example.com:443 HTTP/1.1\r\n\r\n".to_vec();
        bytes.extend_from_slice(b"GET /secret HTTP/1.1\r\n");
        let step = hs.feed(&bytes);
        assert_eq!(step.state, HttpProxyState::Established);
        assert_eq!(hs.take_data(), b"GET /secret HTTP/1.1\r\n".to_vec());
    }
}
