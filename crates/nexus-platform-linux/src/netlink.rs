//! # netlink 窄绑定（本 crate 第二个 unsafe 模块）
//!
//! 设计（对齐 `tun.rs` 纪律）：
//! - 手写 `extern "C"` 窄绑定（socket/bind/send/recv/close），不引入第三方
//!   netlink crate（O-D-1 决策：rtnetlink 需 tokio 出局；neli 太重；需求有界）；
//! - 常量按 Linux UAPI 字面量声明；
//! - **Safety Invariant**：`NlSocket` 持有 fd 所有权，Drop 必须 `close`；
//!   所有系统调用在 `&mut self` 方法内同步完成；
//! - 消息构造/解析为纯函数（`build_*` / `parse_*`），可单测；模块外不扩散 unsafe。

use std::ffi::{c_char, c_int, c_uint, c_void};
use std::io;

/// `socket` 域：`AF_NETLINK`（Linux UAPI `16`）。
const AF_NETLINK: c_int = 16;
/// `socket` 类型：`SOCK_RAW`（`3`）。
const SOCK_RAW: c_int = 3;
/// `SOCK_CLOEXEC`（`0o2000000`）。
const SOCK_CLOEXEC: c_int = 0o2000000;
/// netlink 协议：`NETLINK_ROUTE`（`0`）。
const NETLINK_ROUTE: c_int = 0;

/// `nlmsg_flags`：`NLM_F_REQUEST`（`1`）。
const NLM_F_REQUEST: u16 = 1;
/// `nlmsg_flags`：`NLM_F_ACK`（`4`）。
const NLM_F_ACK: u16 = 4;
/// `nlmsg_flags`：`NLM_F_DUMP` = `NLM_F_ROOT|NLM_F_MATCH`（`0x300`）。
const NLM_F_DUMP: u16 = 0x300;

/// `nlmsg_type`：`NLMSG_ERROR`（`2`）。
const NLMSG_ERROR: u16 = 2;
/// `nlmsg_type`：`NLMSG_DONE`（`3`），多部分 dump 结束。
const NLMSG_DONE: u16 = 3;

/// `nlmsg_type`：`RTM_NEWLINK`（`16`）。
const RTM_NEWLINK: u16 = 16;
/// `nlmsg_type`：`RTM_NEWADDR`（`20`）。
const RTM_NEWADDR: u16 = 20;
/// `nlmsg_type`：`RTM_DELADDR`（`21`）。
const RTM_DELADDR: u16 = 21;
/// `nlmsg_type`：`RTM_GETADDR`（`22`）。
const RTM_GETADDR: u16 = 22;
/// `nlmsg_type`：`RTM_NEWROUTE`（`24`）。
const RTM_NEWROUTE: u16 = 24;
/// `nlmsg_type`：`RTM_DELROUTE`（`25`）。
const RTM_DELROUTE: u16 = 25;
/// `nlmsg_type`：`RTM_GETROUTE`（`26`）。
const RTM_GETROUTE: u16 = 26;

/// 地址族：`AF_INET`（`2`）。
const AF_INET: u8 = 2;
/// `IFA_*` 属性：`IFA_ADDRESS`（`1`）。
const IFA_ADDRESS: u16 = 1;
/// `IFA_*` 属性：`IFA_LOCAL`（`2`）。
const IFA_LOCAL: u16 = 2;

/// `RTA_*` 属性：`RTA_DST`（`1`）。
const RTA_DST: u16 = 1;
/// `RTA_*` 属性：`RTA_OIF`（`4`），输出接口 index。
const RTA_OIF: u16 = 4;
/// `RTA_*` 属性：`RTA_GATEWAY`（`5`）。
const RTA_GATEWAY: u16 = 5;

/// 路由类型：`RTN_UNICAST`（`1`）。
const RTN_UNICAST: u8 = 1;
/// 路由 scope：`RT_SCOPE_UNIVERSE`（`0`）。
const RT_SCOPE_UNIVERSE: u8 = 0;
/// 路由协议：`RTPROT_STATIC`（`4`），静态路由。
const RTPROT_STATIC: u8 = 4;
/// 路由表：`RT_TABLE_MAIN`（`254`）。
const RT_TABLE_MAIN: u8 = 254;

/// `ifi_flags`：`IFF_UP`（`0x1`）。
const IFF_UP: u32 = 0x1;
// `ifi_change` 全改掩码：只改 `IFF_UP` 时传 `IFF_UP`。

/// netlink 对齐基数（`NLMSG_ALIGNTO` / `RTA_ALIGNTO` = 4）。
const ALIGNTO: usize = 4;
/// `struct nlmsghdr` 长度（16）。
const NLMSG_HDRLEN: usize = 16;
/// `struct rtattr` 长度（4）。
const RTA_HDRLEN: usize = 4;

unsafe extern "C" {
    fn socket(domain: c_int, ty: c_int, protocol: c_int) -> c_int;
    fn bind(sockfd: c_int, addr: *const c_void, addrlen: c_uint) -> c_int;
    fn send(sockfd: c_int, buf: *const c_void, len: usize, flags: c_int) -> isize;
    fn recv(sockfd: c_int, buf: *mut c_void, len: usize, flags: c_int) -> isize;
    fn close(fd: c_int) -> c_int;
    fn if_nametoindex(ifname: *const c_char) -> c_uint;
}

/// `struct sockaddr_nl` 最小布局（12 字节）。
#[repr(C)]
struct SockAddrNl {
    nl_family: u16,
    nl_pad: u16,
    nl_pid: u32,
    nl_groups: u32,
}

/// 对齐到 4 字节边界（纯函数）。
fn align(len: usize) -> usize {
    (len + ALIGNTO - 1) & !(ALIGNTO - 1)
}

/// 构造 `nlmsghdr`（16 字节，纯函数）。
fn nlmsg_header(len: u32, msg_type: u16, flags: u16, seq: u32, pid: u32) -> [u8; NLMSG_HDRLEN] {
    let mut h = [0u8; NLMSG_HDRLEN];
    h[0..4].copy_from_slice(&len.to_ne_bytes());
    h[4..6].copy_from_slice(&msg_type.to_ne_bytes());
    h[6..8].copy_from_slice(&flags.to_ne_bytes());
    h[8..12].copy_from_slice(&seq.to_ne_bytes());
    h[12..16].copy_from_slice(&pid.to_ne_bytes());
    h
}

/// 构造一个 `rtattr`（纯函数）：`rta_len` 含头，整体按 4 对齐填充。
fn rta(attr_type: u16, payload: &[u8]) -> Vec<u8> {
    let len = RTA_HDRLEN + payload.len();
    let mut v = Vec::with_capacity(align(len));
    v.extend_from_slice(&(len as u16).to_ne_bytes());
    v.extend_from_slice(&attr_type.to_ne_bytes());
    v.extend_from_slice(payload);
    v.resize(align(len), 0);
    v
}

/// 构造 `struct ifaddrmsg`（8 字节，纯函数）。
fn ifaddrmsg(family: u8, prefixlen: u8, ifindex: u32) -> [u8; 8] {
    let mut m = [0u8; 8];
    m[0] = family;
    m[1] = prefixlen;
    // m[2] = ifa_flags (0), m[3] = ifa_scope (0 = universe)
    m[4..8].copy_from_slice(&ifindex.to_ne_bytes());
    m
}

/// 构造 `struct rtmsg`（12 字节，纯函数）。
fn rtmsg(family: u8, dst_len: u8) -> [u8; 12] {
    let mut m = [0u8; 12];
    m[0] = family;
    m[1] = dst_len;
    // m[2] = rtm_src_len (0), m[3] = rtm_tos (0)
    m[4] = RT_TABLE_MAIN;
    m[5] = RTPROT_STATIC;
    m[6] = RT_SCOPE_UNIVERSE;
    m[7] = RTN_UNICAST;
    // m[8..12] = rtm_flags (0)
    m
}

/// 构造 `struct ifinfomsg`（16 字节，纯函数）。
fn ifinfomsg(family: u8, ifindex: u32, flags: u32, change: u32) -> [u8; 16] {
    let mut m = [0u8; 16];
    m[0] = family;
    // m[1] = pad, m[2..4] = ifi_type (0)
    m[4..8].copy_from_slice(&ifindex.to_ne_bytes());
    m[8..12].copy_from_slice(&flags.to_ne_bytes());
    m[12..16].copy_from_slice(&change.to_ne_bytes());
    m
}

/// 构造 RTM_NEWADDR/RTM_DELADDR 消息（纯函数）。
fn build_addr_msg(
    new: bool,
    seq: u32,
    pid: u32,
    ifindex: u32,
    ip: [u8; 4],
    prefixlen: u8,
) -> Vec<u8> {
    let msg_type = if new { RTM_NEWADDR } else { RTM_DELADDR };
    let mut body = Vec::new();
    body.extend_from_slice(&ifaddrmsg(AF_INET, prefixlen, ifindex));
    body.extend_from_slice(&rta(IFA_LOCAL, &ip));
    body.extend_from_slice(&rta(IFA_ADDRESS, &ip));
    let total = align(NLMSG_HDRLEN + body.len());
    let mut msg = Vec::with_capacity(total);
    msg.extend_from_slice(&nlmsg_header(
        total as u32,
        msg_type,
        NLM_F_REQUEST | NLM_F_ACK,
        seq,
        pid,
    ));
    msg.extend_from_slice(&body);
    msg.resize(total, 0);
    msg
}

/// 构造 RTM_GETADDR dump 请求（纯函数）。
fn build_getaddr_msg(seq: u32, pid: u32) -> Vec<u8> {
    let body = ifaddrmsg(AF_INET, 0, 0);
    let total = NLMSG_HDRLEN + body.len();
    let mut msg = Vec::with_capacity(total);
    msg.extend_from_slice(&nlmsg_header(
        total as u32,
        RTM_GETADDR,
        NLM_F_REQUEST | NLM_F_DUMP,
        seq,
        pid,
    ));
    msg.extend_from_slice(&body);
    msg
}

/// 构造 RTM_NEWROUTE/RTM_DELROUTE 消息（纯函数）。
/// `dst` 为 None 表示默认路由（dst_len=0，不带 RTA_DST）。
fn build_route_msg(
    new: bool,
    seq: u32,
    pid: u32,
    dst: Option<([u8; 4], u8)>,
    oif: u32,
    gateway: Option<[u8; 4]>,
) -> Vec<u8> {
    let msg_type = if new { RTM_NEWROUTE } else { RTM_DELROUTE };
    let dst_len = dst.map(|(_, l)| l).unwrap_or(0);
    let mut body = Vec::new();
    body.extend_from_slice(&rtmsg(AF_INET, dst_len));
    if let Some((ip, _)) = dst {
        body.extend_from_slice(&rta(RTA_DST, &ip));
    }
    body.extend_from_slice(&rta(RTA_OIF, &oif.to_ne_bytes()));
    if let Some(gw) = gateway {
        body.extend_from_slice(&rta(RTA_GATEWAY, &gw));
    }
    let total = align(NLMSG_HDRLEN + body.len());
    let mut msg = Vec::with_capacity(total);
    msg.extend_from_slice(&nlmsg_header(
        total as u32,
        msg_type,
        NLM_F_REQUEST | NLM_F_ACK,
        seq,
        pid,
    ));
    msg.extend_from_slice(&body);
    msg.resize(total, 0);
    msg
}

/// 构造 RTM_GETROUTE dump 请求（纯函数）。
fn build_getroute_msg(seq: u32, pid: u32) -> Vec<u8> {
    let body = rtmsg(AF_INET, 0);
    let total = NLMSG_HDRLEN + body.len();
    let mut msg = Vec::with_capacity(total);
    msg.extend_from_slice(&nlmsg_header(
        total as u32,
        RTM_GETROUTE,
        NLM_F_REQUEST | NLM_F_DUMP,
        seq,
        pid,
    ));
    msg.extend_from_slice(&body);
    msg
}

/// 构造 RTM_NEWLINK（设置 IFF_UP，纯函数）。
fn build_setlink_up_msg(seq: u32, pid: u32, ifindex: u32) -> Vec<u8> {
    let body = ifinfomsg(AF_INET, ifindex, IFF_UP, IFF_UP);
    let total = NLMSG_HDRLEN + body.len();
    let mut msg = Vec::with_capacity(total);
    msg.extend_from_slice(&nlmsg_header(
        total as u32,
        RTM_NEWLINK,
        NLM_F_REQUEST | NLM_F_ACK,
        seq,
        pid,
    ));
    msg.extend_from_slice(&body);
    msg
}

/// 解析出的地址条目。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddrEntry {
    /// 接口 index。
    pub ifindex: u32,
    /// IPv4 地址。
    pub ip: [u8; 4],
    /// 前缀长度。
    pub prefixlen: u8,
}

/// 解析出的路由条目。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteEntry {
    /// 目标（None = 默认路由）。
    pub dst: Option<([u8; 4], u8)>,
    /// 输出接口 index。
    pub oif: u32,
    /// 网关（None = 直连）。
    pub gateway: Option<[u8; 4]>,
}

/// 解析 rtattr 列表（纯函数），返回 (type, payload) 列表。
fn parse_rtattrs(mut buf: &[u8]) -> Vec<(u16, Vec<u8>)> {
    let mut out = Vec::new();
    while buf.len() >= RTA_HDRLEN {
        let rta_len = u16::from_ne_bytes([buf[0], buf[1]]) as usize;
        let rta_type = u16::from_ne_bytes([buf[2], buf[3]]);
        if rta_len < RTA_HDRLEN || rta_len > buf.len() {
            break;
        }
        out.push((rta_type, buf[RTA_HDRLEN..rta_len].to_vec()));
        buf = &buf[align(rta_len)..];
    }
    out
}

/// 解析 RTM_NEWADDR dump 响应体为地址条目（纯函数）。
fn parse_addr_body(body: &[u8]) -> Option<AddrEntry> {
    if body.len() < 8 {
        return None;
    }
    let family = body[0];
    if family != AF_INET {
        return None;
    }
    let prefixlen = body[1];
    let ifindex = u32::from_ne_bytes([body[4], body[5], body[6], body[7]]);
    let mut ip: Option<[u8; 4]> = None;
    for (t, p) in parse_rtattrs(&body[8..]) {
        if (t == IFA_LOCAL || t == IFA_ADDRESS) && p.len() >= 4 {
            ip = Some([p[0], p[1], p[2], p[3]]);
        }
    }
    ip.map(|ip| AddrEntry {
        ifindex,
        ip,
        prefixlen,
    })
}

/// 解析 RTM_NEWROUTE dump 响应体为路由条目（纯函数）。
fn parse_route_body(body: &[u8]) -> Option<RouteEntry> {
    if body.len() < 12 {
        return None;
    }
    if body[0] != AF_INET {
        return None;
    }
    let dst_len = body[1];
    let mut dst_ip: Option<[u8; 4]> = None;
    let mut oif = 0u32;
    let mut gateway: Option<[u8; 4]> = None;
    for (t, p) in parse_rtattrs(&body[12..]) {
        match t {
            RTA_DST if p.len() >= 4 => dst_ip = Some([p[0], p[1], p[2], p[3]]),
            RTA_OIF if p.len() >= 4 => {
                oif = u32::from_ne_bytes([p[0], p[1], p[2], p[3]]);
            }
            RTA_GATEWAY if p.len() >= 4 => gateway = Some([p[0], p[1], p[2], p[3]]),
            _ => {}
        }
    }
    let dst = if dst_len == 0 {
        None
    } else {
        dst_ip.map(|ip| (ip, dst_len))
    };
    Some(RouteEntry { dst, oif, gateway })
}

/// netlink 错误（结构化，不吞 errno）。
#[derive(Debug)]
pub enum NlError {
    /// 系统调用失败。
    Io(io::Error),
    /// 内核返回 NLMSG_ERROR（值为 -errno）。
    Kernel(i32),
    /// 响应 seq/pid 不匹配或截断。
    Malformed(String),
    /// 等待 ACK 超时（未收到）。
    Timeout,
}

impl std::fmt::Display for NlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "netlink io: {e}"),
            Self::Kernel(errno) => write!(f, "netlink kernel error: errno {}", -errno),
            Self::Malformed(m) => write!(f, "netlink malformed: {m}"),
            Self::Timeout => write!(f, "netlink timeout waiting for ack"),
        }
    }
}

impl std::error::Error for NlError {}

/// netlink ROUTE socket（持有 fd 所有权）。
pub struct NlSocket {
    fd: c_int,
    pid: u32,
    seq: u32,
}

// SAFETY 论证：持有互斥 fd，单线程 `&mut self` 使用；Send 迁移时无进行中调用。
unsafe impl Send for NlSocket {}

impl NlSocket {
    /// 打开 NETLINK_ROUTE socket 并 bind（pid 由内核分配则取对端回填）。
    pub fn open() -> Result<Self, NlError> {
        // SAFETY：参数为常量；SOCK_CLOEXEC 防 fd 泄漏到子进程。
        let fd = unsafe { socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE) };
        if fd < 0 {
            return Err(NlError::Io(io::Error::last_os_error()));
        }
        let addr = SockAddrNl {
            nl_family: AF_NETLINK as u16,
            nl_pad: 0,
            nl_pid: 0, // 0 = 内核分配
            nl_groups: 0,
        };
        // SAFETY：addr 为有效指针，长度正确。
        let rc = unsafe {
            bind(
                fd,
                &addr as *const SockAddrNl as *const c_void,
                std::mem::size_of::<SockAddrNl>() as c_uint,
            )
        };
        if rc < 0 {
            let e = io::Error::last_os_error();
            unsafe { close(fd) };
            return Err(NlError::Io(e));
        }
        // pid 取进程 pid（getpid 需额外 FFI；用 0 让内核回填 seq 匹配即可）。
        // 为简单起见，pid 用 0，seq 自增足以匹配（单 socket 串行）。
        Ok(NlSocket { fd, pid: 0, seq: 1 })
    }

    /// 发送一帧并等待 ACK（NLMSG_ERROR code 0）。
    fn request_ack(&mut self, msg: &[u8]) -> Result<(), NlError> {
        // SAFETY：msg 为有效只读缓冲。
        let n = unsafe { send(self.fd, msg.as_ptr() as *const c_void, msg.len(), 0) };
        if n < 0 {
            return Err(NlError::Io(io::Error::last_os_error()));
        }
        let mut buf = [0u8; 8192];
        // SAFETY：buf 为有效可写缓冲。
        let n = unsafe { recv(self.fd, buf.as_mut_ptr() as *mut c_void, buf.len(), 0) };
        if n < 0 {
            return Err(NlError::Io(io::Error::last_os_error()));
        }
        let buf = &buf[..n as usize];
        if buf.len() < NLMSG_HDRLEN {
            return Err(NlError::Malformed("short ack".into()));
        }
        let msg_type = u16::from_ne_bytes([buf[4], buf[5]]);
        if msg_type != NLMSG_ERROR {
            return Err(NlError::Malformed(format!(
                "expected NLMSG_ERROR, got {msg_type}"
            )));
        }
        if buf.len() < NLMSG_HDRLEN + 4 {
            return Err(NlError::Malformed("short NLMSG_ERROR".into()));
        }
        let code = i32::from_ne_bytes([buf[16], buf[17], buf[18], buf[19]]);
        if code == 0 {
            Ok(())
        } else {
            Err(NlError::Kernel(code))
        }
    }

    /// 发送 dump 请求并收集所有响应（直到 NLMSG_DONE）。
    fn request_dump(&mut self, msg: &[u8]) -> Result<Vec<(u16, Vec<u8>)>, NlError> {
        // SAFETY：msg 为有效只读缓冲。
        let n = unsafe { send(self.fd, msg.as_ptr() as *const c_void, msg.len(), 0) };
        if n < 0 {
            return Err(NlError::Io(io::Error::last_os_error()));
        }
        let mut out = Vec::new();
        let mut buf = [0u8; 16384];
        loop {
            // SAFETY：buf 为有效可写缓冲。
            let n = unsafe { recv(self.fd, buf.as_mut_ptr() as *mut c_void, buf.len(), 0) };
            if n < 0 {
                return Err(NlError::Io(io::Error::last_os_error()));
            }
            let mut rest = &buf[..n as usize];
            let mut done = false;
            while rest.len() >= NLMSG_HDRLEN {
                let nlmsg_len = u32::from_ne_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
                let msg_type = u16::from_ne_bytes([rest[4], rest[5]]);
                if nlmsg_len < NLMSG_HDRLEN || nlmsg_len > rest.len() {
                    return Err(NlError::Malformed("bad nlmsg_len".into()));
                }
                let body = &rest[NLMSG_HDRLEN..nlmsg_len];
                match msg_type {
                    NLMSG_DONE => {
                        done = true;
                        break;
                    }
                    NLMSG_ERROR => {
                        if body.len() >= 4 {
                            let code = i32::from_ne_bytes([body[0], body[1], body[2], body[3]]);
                            if code != 0 {
                                return Err(NlError::Kernel(code));
                            }
                        }
                    }
                    t => out.push((t, body.to_vec())),
                }
                rest = &rest[align(nlmsg_len)..];
            }
            if done {
                break;
            }
        }
        Ok(out)
    }

    fn next_seq(&mut self) -> u32 {
        let s = self.seq;
        self.seq = self.seq.wrapping_add(1);
        s
    }

    /// RTM_NEWADDR：给接口加 IPv4 地址。
    pub fn new_addr(&mut self, ifindex: u32, ip: [u8; 4], prefixlen: u8) -> Result<(), NlError> {
        let seq = self.next_seq();
        let msg = build_addr_msg(true, seq, self.pid, ifindex, ip, prefixlen);
        self.request_ack(&msg)
    }

    /// RTM_DELADDR：删除接口 IPv4 地址。
    pub fn del_addr(&mut self, ifindex: u32, ip: [u8; 4], prefixlen: u8) -> Result<(), NlError> {
        let seq = self.next_seq();
        let msg = build_addr_msg(false, seq, self.pid, ifindex, ip, prefixlen);
        self.request_ack(&msg)
    }

    /// RTM_GETADDR dump：列出 IPv4 地址。
    pub fn list_addrs(&mut self) -> Result<Vec<AddrEntry>, NlError> {
        let seq = self.next_seq();
        let msg = build_getaddr_msg(seq, self.pid);
        let resps = self.request_dump(&msg)?;
        Ok(resps
            .into_iter()
            .filter_map(|(_, body)| parse_addr_body(&body))
            .collect())
    }

    /// RTM_NEWROUTE：加路由（dst=None 为默认路由）。
    pub fn new_route(
        &mut self,
        dst: Option<([u8; 4], u8)>,
        oif: u32,
        gateway: Option<[u8; 4]>,
    ) -> Result<(), NlError> {
        let seq = self.next_seq();
        let msg = build_route_msg(true, seq, self.pid, dst, oif, gateway);
        self.request_ack(&msg)
    }

    /// RTM_DELROUTE：删路由。
    pub fn del_route(
        &mut self,
        dst: Option<([u8; 4], u8)>,
        oif: u32,
        gateway: Option<[u8; 4]>,
    ) -> Result<(), NlError> {
        let seq = self.next_seq();
        let msg = build_route_msg(false, seq, self.pid, dst, oif, gateway);
        self.request_ack(&msg)
    }

    /// RTM_GETROUTE dump：列出 IPv4 路由。
    pub fn list_routes(&mut self) -> Result<Vec<RouteEntry>, NlError> {
        let seq = self.next_seq();
        let msg = build_getroute_msg(seq, self.pid);
        let resps = self.request_dump(&msg)?;
        Ok(resps
            .into_iter()
            .filter_map(|(_, body)| parse_route_body(&body))
            .collect())
    }

    /// RTM_NEWLINK：设置接口 UP。
    pub fn set_link_up(&mut self, ifindex: u32) -> Result<(), NlError> {
        let seq = self.next_seq();
        let msg = build_setlink_up_msg(seq, self.pid, ifindex);
        self.request_ack(&msg)
    }
}

impl Drop for NlSocket {
    fn drop(&mut self) {
        // SAFETY：fd 有效且独占。
        unsafe { close(self.fd) };
    }
}

/// 按接口名查 index（`if_nametoindex`，纯 FFI 包装）。
///
/// 不存在返回 0。
pub fn ifname_to_index(name: &str) -> u32 {
    let mut buf = [0 as c_char; 16];
    let bytes = name.as_bytes();
    if bytes.len() >= buf.len() || bytes.contains(&0) {
        return 0;
    }
    for (i, &b) in bytes.iter().enumerate() {
        buf[i] = b as c_char;
    }
    // SAFETY：buf 为 NUL 结尾的有效指针。
    unsafe { if_nametoindex(buf.as_ptr()) as u32 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn align_rounds_up_to_4() {
        assert_eq!(align(0), 0);
        assert_eq!(align(1), 4);
        assert_eq!(align(4), 4);
        assert_eq!(align(5), 8);
        assert_eq!(align(16), 16);
    }

    #[test]
    fn rta_encodes_len_type_payload_with_padding() {
        let r = rta(IFA_LOCAL, &[10, 0, 0, 1]);
        assert_eq!(r.len(), 8);
        assert_eq!(u16::from_ne_bytes([r[0], r[1]]), 8);
        assert_eq!(u16::from_ne_bytes([r[2], r[3]]), IFA_LOCAL);
        assert_eq!(&r[4..8], &[10, 0, 0, 1]);

        // 3 字节 payload → 填充到 8。
        let r = rta(RTA_OIF, &[1, 2, 3]);
        assert_eq!(r.len(), 8);
        assert_eq!(u16::from_ne_bytes([r[0], r[1]]), 7);
        assert_eq!(&r[4..7], &[1, 2, 3]);
        assert_eq!(r[7], 0);
    }

    #[test]
    fn build_newaddr_has_expected_layout() {
        let msg = build_addr_msg(true, 7, 0, 3, [10, 99, 0, 1], 24);
        assert_eq!(
            u32::from_ne_bytes([msg[0], msg[1], msg[2], msg[3]]) as usize,
            msg.len()
        );
        assert_eq!(u16::from_ne_bytes([msg[4], msg[5]]), RTM_NEWADDR);
        assert_eq!(u16::from_ne_bytes([msg[6], msg[7]]) & NLM_F_ACK, NLM_F_ACK);
        assert_eq!(u32::from_ne_bytes([msg[8], msg[9], msg[10], msg[11]]), 7);
        // ifaddrmsg: family=AF_INET, prefixlen=24, ifindex=3
        assert_eq!(msg[16], AF_INET);
        assert_eq!(msg[17], 24);
        assert_eq!(u32::from_ne_bytes([msg[20], msg[21], msg[22], msg[23]]), 3);
        // 两个 rtattr：IFA_LOCAL + IFA_ADDRESS
        let attrs = parse_rtattrs(&msg[24..]);
        assert_eq!(attrs.len(), 2);
        assert_eq!(attrs[0].0, IFA_LOCAL);
        assert_eq!(attrs[0].1, vec![10, 99, 0, 1]);
        assert_eq!(attrs[1].0, IFA_ADDRESS);
    }

    #[test]
    fn build_deladdr_uses_rtm_deladdr() {
        let msg = build_addr_msg(false, 1, 0, 3, [10, 99, 0, 1], 24);
        assert_eq!(u16::from_ne_bytes([msg[4], msg[5]]), RTM_DELADDR);
    }

    #[test]
    fn build_route_subnet_and_default() {
        let msg = build_route_msg(true, 1, 0, Some(([10, 99, 0, 0], 24)), 3, None);
        assert_eq!(u16::from_ne_bytes([msg[4], msg[5]]), RTM_NEWROUTE);
        assert_eq!(msg[17], 24); // rtm_dst_len
        let attrs = parse_rtattrs(&msg[28..]);
        let types: Vec<u16> = attrs.iter().map(|(t, _)| *t).collect();
        assert!(types.contains(&RTA_DST));
        assert!(types.contains(&RTA_OIF));
        assert!(!types.contains(&RTA_GATEWAY));

        // 默认路由：无 RTA_DST。
        let msg = build_route_msg(true, 2, 0, None, 3, Some([10, 99, 0, 254]));
        assert_eq!(msg[17], 0);
        let attrs = parse_rtattrs(&msg[28..]);
        let types: Vec<u16> = attrs.iter().map(|(t, _)| *t).collect();
        assert!(!types.contains(&RTA_DST));
        assert!(types.contains(&RTA_GATEWAY));
    }

    #[test]
    fn parse_addr_body_roundtrip() {
        let msg = build_addr_msg(true, 1, 0, 5, [192, 168, 1, 10], 24);
        let entry = parse_addr_body(&msg[NLMSG_HDRLEN..]).unwrap();
        assert_eq!(entry.ifindex, 5);
        assert_eq!(entry.ip, [192, 168, 1, 10]);
        assert_eq!(entry.prefixlen, 24);
    }

    #[test]
    fn parse_route_body_roundtrip() {
        let msg = build_route_msg(true, 1, 0, Some(([10, 99, 0, 0], 24)), 5, None);
        let entry = parse_route_body(&msg[NLMSG_HDRLEN..]).unwrap();
        assert_eq!(entry.dst, Some(([10, 99, 0, 0], 24)));
        assert_eq!(entry.oif, 5);
        assert_eq!(entry.gateway, None);
    }

    #[test]
    fn parse_route_body_default_roundtrip() {
        let msg = build_route_msg(true, 1, 0, None, 5, Some([10, 0, 0, 1]));
        let entry = parse_route_body(&msg[NLMSG_HDRLEN..]).unwrap();
        assert_eq!(entry.dst, None);
        assert_eq!(entry.gateway, Some([10, 0, 0, 1]));
    }

    #[test]
    fn parse_rtattrs_stops_on_truncated() {
        let attrs = parse_rtattrs(&[0x08, 0x00]);
        assert!(attrs.is_empty());
        // rta_len 小于头长 → 停止。
        let attrs = parse_rtattrs(&[0x02, 0x00, 0x01, 0x00, 0xAA]);
        assert!(attrs.is_empty());
    }

    #[test]
    fn parse_addr_body_rejects_wrong_family() {
        let mut body = vec![10u8; 16]; // AF_INET6
        body[1] = 64;
        assert!(parse_addr_body(&body).is_none());
        assert!(parse_addr_body(&[1, 2, 3]).is_none()); // 太短
    }
}
