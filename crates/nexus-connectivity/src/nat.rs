//! NAT 打洞核心逻辑：STUN 协议 + UDP 打洞。
//!
//! 支持：
//! - STUN Binding Request/Response
//! - NAT 类型检测（Full Cone / Restricted Cone / Port Restricted / Symmetric）
//! - UDP 打洞建连
//! - 结构化事件输出（支持 replay / 调试）

use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

/// STUN 消息类型：Binding Request
const STUN_BINDING_REQUEST: u16 = 0x0001;
/// STUN 消息类型：Binding Response
const STUN_BINDING_RESPONSE: u16 = 0x0101;
/// STUN Magic Cookie
const STUN_MAGIC_COOKIE: u32 = 0x2112A442;

/// NAT 事件（结构化日志，支持 replay）
#[derive(Debug, Clone)]
pub enum NatEvent {
    /// STUN 请求已发送
    StunRequestSent {
        /// STUN 服务器地址
        server: SocketAddr,
        /// 事务 ID
        transaction_id: [u8; 12],
    },
    /// STUN 响应已接收
    StunResponseReceived {
        /// STUN 服务器地址
        server: SocketAddr,
        /// 公网映射地址
        public_mapping: SocketAddr,
        /// RTT
        rtt_ms: u64,
    },
    /// NAT 类型检测完成
    NatTypeDetected {
        /// 检测到的 NAT 类型
        nat_type: NatType,
    },
    /// 打洞开始
    HolePunchStarted {
        /// 目标 peer 地址
        target: SocketAddr,
    },
    /// 打洞成功
    HolePunchSuccess {
        /// 目标 peer 地址
        target: SocketAddr,
        /// RTT
        rtt_ms: u64,
    },
    /// 打洞失败
    HolePunchFailed {
        /// 目标 peer 地址
        target: SocketAddr,
        /// 失败原因
        reason: String,
    },
}

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

/// 路径决策（P4.2 §12.9.4，NAT 类型驱动路径选择的输出）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathDecision {
    /// 打洞直连。
    Direct,
    /// 走 relay（TURN 中继，§12.9.2）。
    Relay,
}

/// NAT 类型驱动的路径决策表（P4.2 §12.9.4）。
///
/// FullCone/RestrictedCone/PortRestrictedCone → Direct（打洞可通）；
/// Symmetric → Relay（打洞不可通，直达 relay）；Unknown → Direct（保守尝试
/// 打洞，失败自动 fallback relay，保底路径不变）。
#[must_use]
pub fn nat_path_decision(nat_type: NatType) -> PathDecision {
    match nat_type {
        NatType::Symmetric => PathDecision::Relay,
        NatType::FullCone
        | NatType::RestrictedCone
        | NatType::PortRestrictedCone
        | NatType::Unknown => PathDecision::Direct,
    }
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
    events: Vec<NatEvent>,
}

impl StunClient {
    /// 创建 STUN 客户端，绑定到指定本地端口
    pub fn new(local_addr: SocketAddr) -> Result<Self, std::io::Error> {
        let socket = UdpSocket::bind(local_addr)?;
        socket.set_read_timeout(Some(Duration::from_secs(3)))?;
        Ok(Self {
            socket,
            events: Vec::new(),
        })
    }

    /// 发送 Binding Request，获取公网映射
    pub fn get_mapping(&mut self, stun_server: SocketAddr) -> Result<StunMapping, NatError> {
        let start = Instant::now();

        // 构造 STUN Binding Request（随机 Transaction ID）
        let transaction_id = random_transaction_id();
        let request = build_stun_binding_request(&transaction_id);

        self.events.push(NatEvent::StunRequestSent {
            server: stun_server,
            transaction_id,
        });

        self.socket.send_to(&request, stun_server)?;

        // 接收响应
        let mut buf = [0u8; 1024];
        let (n, _) = self.socket.recv_from(&mut buf)?;

        // 解析响应
        let public = parse_stun_binding_response(&buf[..n])?;
        let local = self.socket.local_addr()?;

        let rtt_ms = start.elapsed().as_millis() as u64;
        self.events.push(NatEvent::StunResponseReceived {
            server: stun_server,
            public_mapping: public,
            rtt_ms,
        });

        Ok(StunMapping { local, public })
    }

    /// 检测 NAT 类型
    pub fn detect_nat_type(
        &mut self,
        stun_server1: SocketAddr,
        stun_server2: SocketAddr,
    ) -> Result<NatType, NatError> {
        // 第一步：从第一个 STUN 服务器获取映射
        let mapping1 = self.get_mapping(stun_server1)?;

        // 第二步：从第二个 STUN 服务器获取映射
        let mapping2 = self.get_mapping(stun_server2)?;

        // 如果两个映射不同，说明是对称 NAT
        let nat_type = if mapping1.public != mapping2.public {
            NatType::Symmetric
        } else {
            // TODO: 进一步检测 FullCone / RestrictedCone / PortRestrictedCone
            NatType::RestrictedCone
        };

        self.events.push(NatEvent::NatTypeDetected { nat_type });

        Ok(nat_type)
    }

    /// 获取事件收集
    pub fn events(&self) -> &[NatEvent] {
        &self.events
    }

    /// 清空事件收集
    pub fn clear_events(&mut self) {
        self.events.clear();
    }

    /// 本地 socket
    pub fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
        self.socket.local_addr()
    }
}

/// UDP 打洞器
pub struct HolePuncher {
    socket: UdpSocket,
    events: Vec<NatEvent>,
}

impl HolePuncher {
    /// 创建打洞器，绑定到指定本地地址
    pub fn new(local_addr: SocketAddr) -> Result<Self, std::io::Error> {
        let socket = UdpSocket::bind(local_addr)?;
        socket.set_read_timeout(Some(Duration::from_secs(5)))?;
        Ok(Self {
            socket,
            events: Vec::new(),
        })
    }

    /// 执行打洞：向目标地址发包，尝试打通 NAT
    pub fn punch(&mut self, target: SocketAddr) -> Result<bool, NatError> {
        let start = Instant::now();
        let hello = b"punch-hello";

        self.events.push(NatEvent::HolePunchStarted { target });

        // 连续发包打洞
        for _ in 0..10 {
            self.socket.send_to(hello, target)?;

            // 等待响应
            let mut buf = [0u8; 1024];
            match self.socket.recv_from(&mut buf) {
                Ok((n, from)) => {
                    if from == target && &buf[..n] == b"punch-hello-ack" {
                        let rtt_ms = start.elapsed().as_millis() as u64;
                        self.events
                            .push(NatEvent::HolePunchSuccess { target, rtt_ms });
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

        self.events.push(NatEvent::HolePunchFailed {
            target,
            reason: "timeout".to_string(),
        });

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

    /// 获取事件收集
    pub fn events(&self) -> &[NatEvent] {
        &self.events
    }

    /// 清空事件收集
    pub fn clear_events(&mut self) {
        self.events.clear();
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
}

impl std::fmt::Display for NatError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NatError::Io(e) => write!(f, "IO error: {}", e),
            NatError::StunParse(s) => write!(f, "STUN parse error: {}", s),
            NatError::InvalidResponse => write!(f, "invalid response"),
        }
    }
}

impl std::error::Error for NatError {}

impl From<std::io::Error> for NatError {
    fn from(e: std::io::Error) -> Self {
        NatError::Io(e)
    }
}

/// 生成随机 Transaction ID
fn random_transaction_id() -> [u8; 12] {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    let mut id = [0u8; 12];
    id[0..8].copy_from_slice(&(nanos as u64).to_be_bytes());
    id[8..12].copy_from_slice(&(nanos as u32).wrapping_mul(0x9e3779b9).to_be_bytes());
    id
}

/// 构造 STUN Binding Request
fn build_stun_binding_request(transaction_id: &[u8; 12]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(20);

    // Message Type: Binding Request (0x0001)
    msg.extend_from_slice(&STUN_BINDING_REQUEST.to_be_bytes());

    // Message Length: 0（无属性）
    msg.extend_from_slice(&0u16.to_be_bytes());

    // Magic Cookie
    msg.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());

    // Transaction ID（12 字节，随机）
    msg.extend_from_slice(transaction_id);

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

/// STUN 离线编解码自检（确定性、零网络）。
///
/// 构造一个带已知 XOR-MAPPED-ADDRESS 的合成 Binding Response 并经
/// `parse_stun_binding_response` 解析，同时校验 `build_stun_binding_request` 长度。
/// 供 E4 场景驱动（example）与 harness 在**无真实 STUN 服务器**时确认编解码正确性，
/// 不伪造公网映射。返回 `(request_len, parsed_public_addr)`。
pub fn codec_self_test() -> Result<(usize, SocketAddr), NatError> {
    let txn = [0xAB; 12];
    let request = build_stun_binding_request(&txn);

    // 合成一个指向 1.2.3.4:54321 的 XOR-MAPPED-ADDRESS 响应。
    let mut buf = Vec::new();
    buf.extend_from_slice(&STUN_BINDING_RESPONSE.to_be_bytes());
    buf.extend_from_slice(&8u16.to_be_bytes());
    buf.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    buf.extend_from_slice(&txn);
    buf.extend_from_slice(&0x0020u16.to_be_bytes());
    buf.extend_from_slice(&8u16.to_be_bytes());
    buf.extend_from_slice(&[0x00, 0x01]);
    let port = 54321u16;
    buf.extend_from_slice(&(port ^ (STUN_MAGIC_COOKIE >> 16) as u16).to_be_bytes());
    let ip = u32::from_be_bytes([1, 2, 3, 4]);
    buf.extend_from_slice(&(ip ^ STUN_MAGIC_COOKIE).to_be_bytes());

    let parsed = parse_stun_binding_response(&buf)?;
    if parsed.port() != port || parsed.ip().to_string() != "1.2.3.4" {
        return Err(NatError::StunParse(
            "codec self-test: parsed address mismatch".to_string(),
        ));
    }
    Ok((request.len(), parsed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stun_request_build() {
        let txn_id = [0x12; 12];
        let req = build_stun_binding_request(&txn_id);
        assert_eq!(req.len(), 20);
        assert_eq!(&req[0..2], &STUN_BINDING_REQUEST.to_be_bytes());
        assert_eq!(&req[8..20], &txn_id);
    }

    #[test]
    fn test_random_transaction_id() {
        let id1 = random_transaction_id();
        let id2 = random_transaction_id();
        // 两次调用应该不同（时间不同）
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_parse_stun_response_success() {
        // 构造一个模拟的 STUN Binding Response
        let mut buf = Vec::new();

        // Message Type: Binding Response
        buf.extend_from_slice(&STUN_BINDING_RESPONSE.to_be_bytes());

        // Message Length: 8（XOR-MAPPED-ADDRESS 8 字节）
        buf.extend_from_slice(&8u16.to_be_bytes());

        // Magic Cookie
        buf.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());

        // Transaction ID
        buf.extend_from_slice(&[0x12; 12]);

        // XOR-MAPPED-ADDRESS attribute
        // Type: 0x0020
        buf.extend_from_slice(&0x0020u16.to_be_bytes());
        // Length: 8
        buf.extend_from_slice(&8u16.to_be_bytes());
        // Reserved: 0, Family: 0x01 (IPv4)
        buf.extend_from_slice(&[0x00, 0x01]);

        // XOR Port (假设公网端口是 54321)
        let port = 54321u16;
        let xor_port = port ^ (STUN_MAGIC_COOKIE >> 16) as u16;
        buf.extend_from_slice(&xor_port.to_be_bytes());

        // XOR IP (假设公网 IP 是 1.2.3.4)
        let ip = u32::from_be_bytes([1, 2, 3, 4]);
        let xor_ip = ip ^ STUN_MAGIC_COOKIE;
        buf.extend_from_slice(&xor_ip.to_be_bytes());

        let result = parse_stun_binding_response(&buf).unwrap();
        assert_eq!(result.port(), 54321);
        assert_eq!(result.ip().to_string(), "1.2.3.4");
    }

    #[test]
    fn test_parse_stun_response_too_short() {
        let buf = [0u8; 10];
        let result = parse_stun_binding_response(&buf);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_stun_response_wrong_type() {
        let mut buf = vec![0u8; 20];
        // 错误的消息类型
        buf[0] = 0x00;
        buf[1] = 0x00;
        let result = parse_stun_binding_response(&buf);
        assert!(result.is_err());
    }

    #[test]
    fn test_nat_type_debug() {
        assert_eq!(format!("{:?}", NatType::FullCone), "FullCone");
    }

    #[test]
    fn test_nat_event_debug() {
        let event = NatEvent::NatTypeDetected {
            nat_type: NatType::RestrictedCone,
        };
        let s = format!("{:?}", event);
        assert!(s.contains("NatTypeDetected"));
    }

    // ---------- P4.2 §12.9.4 NAT 类型驱动的路径决策表 ----------

    #[test]
    fn test_nat_path_decision_full_table() {
        // FullCone/RestrictedCone/PortRestrictedCone → Direct（可打洞）；
        // Symmetric → Relay（直达中继）；Unknown → Direct（保守打洞）。
        assert_eq!(nat_path_decision(NatType::FullCone), PathDecision::Direct);
        assert_eq!(
            nat_path_decision(NatType::RestrictedCone),
            PathDecision::Direct
        );
        assert_eq!(
            nat_path_decision(NatType::PortRestrictedCone),
            PathDecision::Direct
        );
        assert_eq!(nat_path_decision(NatType::Symmetric), PathDecision::Relay);
        assert_eq!(nat_path_decision(NatType::Unknown), PathDecision::Direct);
    }

    #[test]
    fn test_path_decision_debug() {
        assert_eq!(format!("{:?}", PathDecision::Relay), "Relay");
    }
}
// test
