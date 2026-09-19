//! NAT 打洞核心逻辑：STUN 协议 + UDP 打洞。
//!
//! 支持：
//! - STUN Binding Request/Response
//! - NAT 类型检测（Full Cone / Restricted Cone / Port Restricted / Symmetric）
//! - UDP 打洞建连

use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

/// STUN 消息类型：Binding Request
const STUN_BINDING_REQUEST: u16 = 0x0001;
/// STUN 消息类型：Binding Response
const STUN_BINDING_RESPONSE: u16 = 0x0101;
/// STUN Magic Cookie
const STUN_MAGIC_COOKIE: u32 = 0x2112A442;

/// NAT 类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatType {
    /// 完全锥型：任何外部主机都能发包到映射端口
    FullCone,
    /// 限制锥型：只有目标 IP 允许的主机能发包
    RestrictedCone,
    /// 端口限制锥型：只有目标 IP:Port 允许的主机能发包
    PortRestrictedCone,
    /// 对称型：每个目标都分配不同端口
    Symmetric,
    /// 未知
    Unknown,
}

/// STUN 映射结果
#[derive(Debug, Clone)]
pub struct StunMapping {
    /// 本地地址
    pub local: SocketAddr,
    /// 公网映射地址
    pub public: SocketAddr,
}

/// STUN 客户端
pub struct StunClient {
    socket: UdpSocket,
}

impl StunClient {
    /// 创建 STUN 客户端，绑定到指定本地端口
    pub fn new(local_addr: SocketAddr) -> Result<Self, std::io::Error> {
        let socket = UdpSocket::bind(local_addr)?;
        socket.set_read_timeout(Some(Duration::from_secs(3)))?;
        Ok(Self { socket })
    }

    /// 发送 Binding Request，获取公网映射
    pub fn get_mapping(&self, stun_server: SocketAddr) -> Result<StunMapping, NatError> {
        // 构造 STUN Binding Request
        let request = build_stun_binding_request();
        self.socket.send_to(&request, stun_server)?;

        // 接收响应
        let mut buf = [0u8; 1024];
        let (n, _) = self.socket.recv_from(&mut buf)?;

        // 解析响应
        let public = parse_stun_binding_response(&buf[..n])?;
        let local = self.socket.local_addr()?;

        Ok(StunMapping { local, public })
    }

    /// 检测 NAT 类型
    pub fn detect_nat_type(
        &self,
        stun_server1: SocketAddr,
        stun_server2: SocketAddr,
    ) -> Result<NatType, NatError> {
        // 第一步：从第一个 STUN 服务器获取映射
        let mapping1 = self.get_mapping(stun_server1)?;

        // 第二步：从第二个 STUN 服务器获取映射
        let mapping2 = self.get_mapping(stun_server2)?;

        // 如果两个映射不同，说明是对称 NAT
        if mapping1.public != mapping2.public {
            return Ok(NatType::Symmetric);
        }

        // TODO: 进一步检测 FullCone / RestrictedCone / PortRestrictedCone
        // 简化实现：先返回 RestrictedCone
        Ok(NatType::RestrictedCone)
    }

    /// 本地 socket
    pub fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
        self.socket.local_addr()
    }
}

/// UDP 打洞器
pub struct HolePuncher {
    socket: UdpSocket,
}

impl HolePuncher {
    /// 创建打洞器，绑定到指定本地地址
    pub fn new(local_addr: SocketAddr) -> Result<Self, std::io::Error> {
        let socket = UdpSocket::bind(local_addr)?;
        socket.set_read_timeout(Some(Duration::from_secs(5)))?;
        Ok(Self { socket })
    }

    /// 执行打洞：向目标地址发包，尝试打通 NAT
    pub fn punch(&self, target: SocketAddr) -> Result<bool, NatError> {
        let start = Instant::now();
        let hello = b"punch-hello";

        // 连续发包打洞
        for _ in 0..10 {
            self.socket.send_to(hello, target)?;

            // 等待响应
            let mut buf = [0u8; 1024];
            match self.socket.recv_from(&mut buf) {
                Ok((n, from)) => {
                    if from == target && &buf[..n] == b"punch-hello-ack" {
                        return Ok(true);
                    }
                }
                Err(_) => {
                    // 超时，继续重试
                }
            }

            if start.elapsed() > Duration::from_secs(5) {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }

        Ok(false)
    }

    /// 响应打洞请求
    pub fn respond_punch(&self, target: SocketAddr) -> Result<(), NatError> {
        let ack = b"punch-hello-ack";
        self.socket.send_to(ack, target)?;
        Ok(())
    }

    /// 测量 RTT
    pub fn measure_rtt(&self, target: SocketAddr) -> Result<Duration, NatError> {
        let start = Instant::now();
        let ping = b"ping";
        self.socket.send_to(ping, target)?;

        let mut buf = [0u8; 1024];
        let (n, _) = self.socket.recv_from(&mut buf)?;
        if &buf[..n] == b"pong" {
            Ok(start.elapsed())
        } else {
            Err(NatError::InvalidResponse)
        }
    }
}

/// NAT 错误类型
#[derive(Debug)]
pub enum NatError {
    /// IO 错误
    Io(std::io::Error),
    /// STUN 解析错误
    StunParse(String),
    /// 无效响应
    InvalidResponse,
    /// 超时
    Timeout,
}

impl std::fmt::Display for NatError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NatError::Io(e) => write!(f, "IO error: {}", e),
            NatError::StunParse(s) => write!(f, "STUN parse error: {}", s),
            NatError::InvalidResponse => write!(f, "invalid response"),
            NatError::Timeout => write!(f, "timeout"),
        }
    }
}

impl std::error::Error for NatError {}

impl From<std::io::Error> for NatError {
    fn from(e: std::io::Error) -> Self {
        NatError::Io(e)
    }
}

/// 构造 STUN Binding Request
fn build_stun_binding_request() -> Vec<u8> {
    let mut msg = Vec::with_capacity(20);

    // Message Type: Binding Request (0x0001)
    msg.extend_from_slice(&STUN_BINDING_REQUEST.to_be_bytes());

    // Message Length: 0（无属性）
    msg.extend_from_slice(&0u16.to_be_bytes());

    // Magic Cookie
    msg.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());

    // Transaction ID（12 字节，随机）
    msg.extend_from_slice(&[
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44,
    ]);

    msg
}

/// 解析 STUN Binding Response，提取 XOR-MAPPED-ADDRESS
fn parse_stun_binding_response(buf: &[u8]) -> Result<SocketAddr, NatError> {
    if buf.len() < 20 {
        return Err(NatError::StunParse("message too short".to_string()));
    }

    // 检查消息类型
    let msg_type = u16::from_be_bytes([buf[0], buf[1]]);
    if msg_type != STUN_BINDING_RESPONSE {
        return Err(NatError::StunParse(format!(
            "unexpected type: 0x{:04x}",
            msg_type
        )));
    }

    // 检查 Magic Cookie
    let cookie = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    if cookie != STUN_MAGIC_COOKIE {
        return Err(NatError::StunParse("invalid magic cookie".to_string()));
    }

    // 解析属性
    let mut offset = 20;
    while offset + 4 <= buf.len() {
        let attr_type = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        let attr_len = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]) as usize;
        offset += 4;

        if offset + attr_len > buf.len() {
            break;
        }

        // XOR-MAPPED-ADDRESS (0x0020)
        if attr_type == 0x0020 {
            let family = buf[offset + 1];
            if family != 0x01 {
                return Err(NatError::StunParse("only IPv4 supported".to_string()));
            }

            let port = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]])
                ^ (STUN_MAGIC_COOKIE >> 16) as u16;
            let ip = u32::from_be_bytes([
                buf[offset + 4],
                buf[offset + 5],
                buf[offset + 6],
                buf[offset + 7],
            ]) ^ STUN_MAGIC_COOKIE;

            let addr = SocketAddr::from((std::net::Ipv4Addr::from(ip), port));
            return Ok(addr);
        }

        // 对齐到 4 字节
        offset += (attr_len + 3) & !3;
    }

    Err(NatError::StunParse(
        "XOR-MAPPED-ADDRESS not found".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stun_request_build() {
        let req = build_stun_binding_request();
        assert_eq!(req.len(), 20);
        assert_eq!(&req[0..2], &STUN_BINDING_REQUEST.to_be_bytes());
    }

    #[test]
    fn test_nat_type_debug() {
        assert_eq!(format!("{:?}", NatType::FullCone), "FullCone");
    }
}
