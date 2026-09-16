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

/// 稳定模块标识；业务实现应通过公开类型/trait 增量加入，而不是扩大隐式全局状态。
pub const NEXUS_INGRESS_MODULE: &str = "nexus-ingress";

/// InternetAccess 对应的 Network Resource 标识。
pub const INTERNET_ACCESS_RESOURCE: &str = "internet-access";

/// 返回模块的人类可读职责摘要。
#[must_use]
pub const fn module_summary() -> &'static str {
    "便携 Flow Classification 与中立 FlowContext 构造（不调用 Planner、不做平台拦截）。"
}

/// 由指定来源构造一个中立 FlowContext（内部统一构造点，保证字段一致）。
#[must_use]
fn classify(origin: FlowOrigin, destination: &str, profile: &str) -> FlowContext {
    FlowContext {
        origin,
        resource: ResourceId(INTERNET_ACCESS_RESOURCE.into()),
        destination: destination.to_string(),
        profile: profile.to_string(),
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
    /// 命令不受支持（本状态机仅 CONNECT；BIND/UDP ASSOCIATE 显式拒绝）。
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
        }
    }

    /// 当前状态。
    #[must_use]
    pub fn state(&self) -> &Socks5State {
        &self.state
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
                    Parse::Done(consumed, (cmd, destination)) => {
                        self.buf.drain(..consumed);
                        match cmd {
                            // CONNECT：建立成功响应（BND.ADDR=0.0.0.0:0）。
                            0x01 => {
                                response =
                                    [SOCKS5_VERSION, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0].to_vec();
                                flow = Some(classify(FlowOrigin::Socks5, &destination, ""));
                                self.state = Socks5State::Established;
                            }
                            // BIND / UDP ASSOCIATE：显式 command-not-supported。
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

/// 解析请求段：VER CMD RSV ATYP DST.ADDR DST.PORT。返回 (cmd, destination)。
fn parse_request(buf: &[u8]) -> Parse<(u8, String)> {
    if buf.len() < 4 {
        return Parse::NeedMore;
    }
    let version = buf[0];
    let cmd = buf[1];
    let atyp = buf[3];
    if version != SOCKS5_VERSION {
        return Parse::Err(Socks5Error::BadRequestVersion { got: version });
    }
    let (host, addr_len) = match atyp {
        0x01 => {
            if buf.len() < 4 + 4 + 2 {
                return Parse::NeedMore;
            }
            (format!("{}.{}.{}.{}", buf[4], buf[5], buf[6], buf[7]), 4)
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
            let name = &buf[5..5 + name_len];
            let host = String::from_utf8_lossy(name).into_owned();
            (host, name_len + 1)
        }
        0x04 => {
            if buf.len() < 4 + 16 + 2 {
                return Parse::NeedMore;
            }
            let mut addr = [0u8; 16];
            addr.copy_from_slice(&buf[4..20]);
            (format_ipv6(&addr), 16)
        }
        _ => return Parse::Err(Socks5Error::UnsupportedAddressType { atyp }),
    };
    let port = u16::from_be_bytes([buf[4 + addr_len], buf[4 + addr_len + 1]]);
    Parse::Done(4 + addr_len + 2, (cmd, format!("{host}:{port}")))
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
}
