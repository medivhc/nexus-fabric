//! STUN 探测与 NAT 类型分支（NAT switching daemon activation，AC4）。
//!
//! 职责：
//! - 单次 STUN Binding 探测（默认 2s 超时，经注入的 `StunTransport` 零网络可测）；
//! - NAT 类型检测（双服务器公网映射对比：对称 vs 锥型，与
//!   `nexus_connectivity::nat::StunClient::detect_nat_type` 同口径）；
//! - 基于 NAT 类型的打洞分支决策（`should_punch`）；
//! - 输出 `PortSample` 供 `PunchManager` 的有界端口预测（±16/3s）使用。
//!
//! 5 分钟重采样由调用方（`main.rs`）驱动：本模块只声明 `STUN_REFRESH_INTERVAL`
//! 节奏，不自行创建长期任务（§13 结构化并发：Worker 由组合根拥有）。
//!
//! # 临时说明（BLOCKED）
//! `main.rs` 的完整 NAT 接线依赖 `nat_turn.rs`（TURN 客户端依赖尚未获批，
//! 见实现报告的 BLOCKED 依赖缺口）。本模块已就绪并通过单测，但生产路径
//! 尚未实例化 `StunProber`，故暂以 `#![allow(dead_code)]` 抑制 dead_code；
//! 依赖决策后接线时会移除该属性。

#![allow(dead_code)]

use std::fmt;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use nexus_connectivity::nat::{NatType, StunMapping};
use nexus_nat_traversal::PortSample;

/// 单次 STUN 探测超时（AC4：2s）。
pub const STUN_PROBE_TIMEOUT: Duration = Duration::from_secs(2);
/// STUN 重采样/刷新节奏（AC4：5min；调用方驱动）。
pub const STUN_REFRESH_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// STUN Binding Request 消息类型（RFC 5389）。
const STUN_BINDING_REQUEST: u16 = 0x0001;
/// STUN Binding Success Response 消息类型。
const STUN_BINDING_RESPONSE: u16 = 0x0101;
/// STUN Magic Cookie。
const STUN_MAGIC_COOKIE: u32 = 0x2112_A442;
/// XOR-MAPPED-ADDRESS 属性类型。
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

/// STUN 探测错误（类型化，不 panic）。
#[derive(Debug)]
pub enum StunError {
    /// 底层 I/O 错误。
    Io(io::Error),
    /// 探测超时（未在指定时间内收到响应）。
    Timeout,
    /// 响应字节无法解析 / 语义非法。
    Parse(String),
}

impl fmt::Display for StunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StunError::Io(e) => write!(f, "stun io error: {e}"),
            StunError::Timeout => write!(f, "stun probe timed out"),
            StunError::Parse(s) => write!(f, "stun parse error: {s}"),
        }
    }
}

impl std::error::Error for StunError {}

impl From<io::Error> for StunError {
    fn from(e: io::Error) -> Self {
        StunError::Io(e)
    }
}

/// STUN 传输接缝（真实 UDP 与测试替身构成独立变化维度）。
///
/// Deletion Test：`UdpStunTransport` 需要真实网络，而单测/E4 需要离线确定性
/// 回环；trait 分离两个维度，与 `nexus_connectivity::turn::TurnTransport` 同构。
pub trait StunTransport: Send {
    /// 发送请求并等待响应；`timeout` 内无响应 → `StunError::Timeout`。
    fn send_recv(
        &mut self,
        request: &[u8],
        server: SocketAddr,
        timeout: Duration,
    ) -> Result<Vec<u8>, StunError>;
    /// 本地 socket 地址（供 `StunMapping.local`）。
    fn local_addr(&self) -> Result<SocketAddr, StunError>;
}

/// 真实 UDP STUN 传输（绑定本地地址，逐请求设置读超时）。
pub struct UdpStunTransport {
    socket: UdpSocket,
}

impl UdpStunTransport {
    /// 绑定到 `local_addr`（如 `0.0.0.0:0`）。
    pub fn new(local_addr: SocketAddr) -> Result<Self, io::Error> {
        let socket = UdpSocket::bind(local_addr)?;
        Ok(Self { socket })
    }
}

impl StunTransport for UdpStunTransport {
    fn send_recv(
        &mut self,
        request: &[u8],
        server: SocketAddr,
        timeout: Duration,
    ) -> Result<Vec<u8>, StunError> {
        self.socket.set_read_timeout(Some(timeout))?;
        self.socket.send_to(request, server)?;
        let mut buf = [0u8; 1024];
        loop {
            match self.socket.recv_from(&mut buf) {
                // 只接受来自目标服务器的响应（丢弃脏包/迟到包，继续等）。
                Ok((n, from)) if from == server => return Ok(buf[..n].to_vec()),
                Ok((_, _)) => continue,
                Err(e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::TimedOut =>
                {
                    return Err(StunError::Timeout);
                }
                Err(e) => return Err(StunError::Io(e)),
            }
        }
    }

    fn local_addr(&self) -> Result<SocketAddr, StunError> {
        Ok(self.socket.local_addr()?)
    }
}

/// STUN 探测器：Binding 探测 → 公网映射 → NAT 类型分支。
///
/// 组合根创建一次，按 `STUN_REFRESH_INTERVAL` 周期性调用 `sample` /
/// `detect_nat_type` 并把样本喂给 `NatSwitching::set_local`。
pub struct StunProber {
    transport: Box<dyn StunTransport>,
}

impl StunProber {
    /// 构造探测器（传输实现由组合根注入）。
    pub fn new(transport: Box<dyn StunTransport>) -> Self {
        Self { transport }
    }

    /// 单次 STUN Binding 探测，返回本地地址与公网映射。
    ///
    /// `timeout` 为单次探测超时（规格默认 `STUN_PROBE_TIMEOUT` = 2s）。
    pub fn probe_once(
        &mut self,
        server: SocketAddr,
        timeout: Duration,
    ) -> Result<StunMapping, StunError> {
        let txid = random_transaction_id();
        let request = build_binding_request(&txid);
        let response = self.transport.send_recv(&request, server, timeout)?;
        let public = parse_binding_response(&response, &txid)?;
        let local = self.transport.local_addr()?;
        Ok(StunMapping { local, public })
    }

    /// NAT 类型检测：对比两个 STUN 服务器的公网映射。
    ///
    /// 映射不同 → `Symmetric`；相同 → `RestrictedCone`（无法区分
    /// Full/Restricted/PortRestricted，保守取 RestrictedCone，与
    /// `nexus_connectivity::nat` 同口径）。
    pub fn detect_nat_type(
        &mut self,
        server1: SocketAddr,
        server2: SocketAddr,
    ) -> Result<NatType, StunError> {
        let m1 = self.probe_once(server1, STUN_PROBE_TIMEOUT)?;
        let m2 = self.probe_once(server2, STUN_PROBE_TIMEOUT)?;
        Ok(if m1.public != m2.public {
            NatType::Symmetric
        } else {
            NatType::RestrictedCone
        })
    }

    /// 采集一个端口样本（供 `PunchManager` 有界预测）。
    pub fn sample(&mut self, server: SocketAddr) -> Result<PortSample, StunError> {
        let m = self.probe_once(server, STUN_PROBE_TIMEOUT)?;
        Ok(PortSample {
            port: m.public.port(),
            at_ms: unix_ms(),
        })
    }
}

/// 基于 NAT 类型的打洞分支（AC4：symmetric/Cone 分支）。
///
/// Symmetric → 不打洞（走 relay）；Cone（及 Unknown）→ 打洞直连。
/// 与 `nexus_connectivity::nat::nat_path_decision` 的路径语义一致，
/// 但作为 daemon 侧是否启用打洞的布尔分支。
pub fn should_punch(nat_type: NatType) -> bool {
    match nat_type {
        NatType::Symmetric => false,
        NatType::FullCone
        | NatType::RestrictedCone
        | NatType::PortRestrictedCone
        | NatType::Unknown => true,
    }
}

/// 当前 unix 毫秒（PortSample 时间戳）。
fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// 生成随机 Transaction ID（12 字节）。
fn random_transaction_id() -> [u8; 12] {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let mut id = [0u8; 12];
    id[0..8].copy_from_slice(&nanos.to_be_bytes());
    id[8..12].copy_from_slice(&(nanos as u32).wrapping_mul(0x9e37_79b9).to_be_bytes());
    id
}

/// 构造 STUN Binding Request（20 字节，无属性）。
fn build_binding_request(txid: &[u8; 12]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(20);
    msg.extend_from_slice(&STUN_BINDING_REQUEST.to_be_bytes());
    msg.extend_from_slice(&0u16.to_be_bytes());
    msg.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    msg.extend_from_slice(txid);
    msg
}

/// 解析 STUN Binding Success Response，提取 XOR-MAPPED-ADDRESS。
///
/// 校验消息类型、Magic Cookie 与事务 ID（拒绝脏包/迟到包）。
fn parse_binding_response(buf: &[u8], txid: &[u8; 12]) -> Result<SocketAddr, StunError> {
    if buf.len() < 20 {
        return Err(StunError::Parse("message too short".into()));
    }
    let msg_type = u16::from_be_bytes([buf[0], buf[1]]);
    if msg_type != STUN_BINDING_RESPONSE {
        return Err(StunError::Parse(format!(
            "unexpected message type: 0x{msg_type:04x}"
        )));
    }
    let cookie = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    if cookie != STUN_MAGIC_COOKIE {
        return Err(StunError::Parse("invalid magic cookie".into()));
    }
    if &buf[8..20] != txid {
        return Err(StunError::Parse("transaction id mismatch".into()));
    }

    let mut offset = 20;
    while offset + 4 <= buf.len() {
        let attr_type = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        let attr_len = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]) as usize;
        offset += 4;
        if offset + attr_len > buf.len() {
            break;
        }
        if attr_type == ATTR_XOR_MAPPED_ADDRESS {
            if attr_len < 8 {
                return Err(StunError::Parse("xor-mapped-address too short".into()));
            }
            let family = buf[offset + 1];
            if family != 0x01 {
                return Err(StunError::Parse(
                    "only IPv4 xor-mapped-address supported".into(),
                ));
            }
            let port = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]])
                ^ (STUN_MAGIC_COOKIE >> 16) as u16;
            let ip = u32::from_be_bytes([
                buf[offset + 4],
                buf[offset + 5],
                buf[offset + 6],
                buf[offset + 7],
            ]) ^ STUN_MAGIC_COOKIE;
            return Ok(SocketAddr::from((Ipv4Addr::from(ip), port)));
        }
        offset += (attr_len + 3) & !3;
    }
    Err(StunError::Parse("xor-mapped-address not found".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 测试用 STUN 传输替身：回显 txid，按顺序返回可配置的公网映射。
    struct MockStunTransport {
        local: SocketAddr,
        responses: Vec<SocketAddr>,
        next: usize,
        requests: Vec<Vec<u8>>,
    }

    impl MockStunTransport {
        fn new(local: SocketAddr, responses: Vec<SocketAddr>) -> Self {
            Self {
                local,
                responses,
                next: 0,
                requests: Vec::new(),
            }
        }
    }

    impl StunTransport for MockStunTransport {
        fn send_recv(
            &mut self,
            request: &[u8],
            _server: SocketAddr,
            _timeout: Duration,
        ) -> Result<Vec<u8>, StunError> {
            self.requests.push(request.to_vec());
            if request.len() < 20 {
                return Err(StunError::Parse("request too short".into()));
            }
            let public = self.responses[self.next % self.responses.len()];
            self.next += 1;
            let txid: [u8; 12] = request[8..20].try_into().expect("12-byte txid");
            Ok(synthetic_binding_response(&txid, public))
        }

        fn local_addr(&self) -> Result<SocketAddr, StunError> {
            Ok(self.local)
        }
    }

    /// 构造指向 `public` 的合成 Binding Success Response（XOR-MAPPED-ADDRESS）。
    fn synthetic_binding_response(txid: &[u8; 12], public: SocketAddr) -> Vec<u8> {
        let ip = match public.ip() {
            std::net::IpAddr::V4(v4) => u32::from(v4),
            std::net::IpAddr::V6(_) => u32::from(std::net::Ipv4Addr::new(192, 0, 2, 1)),
        };
        let mut buf = Vec::new();
        buf.extend_from_slice(&STUN_BINDING_RESPONSE.to_be_bytes());
        buf.extend_from_slice(&8u16.to_be_bytes());
        buf.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        buf.extend_from_slice(txid);
        buf.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        buf.extend_from_slice(&8u16.to_be_bytes());
        buf.extend_from_slice(&[0x00, 0x01]); // reserved + family IPv4
        let port = public.port() ^ ((STUN_MAGIC_COOKIE >> 16) as u16);
        buf.extend_from_slice(&port.to_be_bytes());
        buf.extend_from_slice(&(ip ^ STUN_MAGIC_COOKIE).to_be_bytes());
        buf
    }

    #[test]
    fn binding_request_is_20_bytes() {
        let txid = [0x12; 12];
        let req = build_binding_request(&txid);
        assert_eq!(req.len(), 20);
        assert_eq!(&req[0..2], &STUN_BINDING_REQUEST.to_be_bytes());
        assert_eq!(&req[8..20], &txid);
    }

    #[test]
    fn parse_binding_response_roundtrip() {
        let txid = [0xab; 12];
        let public = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 7), 54321));
        let buf = synthetic_binding_response(&txid, public);
        let parsed = parse_binding_response(&buf, &txid).unwrap();
        assert_eq!(parsed, public);
    }

    #[test]
    fn parse_binding_response_rejects_bad_input() {
        let txid = [0x01; 12];
        let public = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 7), 54321));
        let good = synthetic_binding_response(&txid, public);
        // 太短。
        assert!(parse_binding_response(&good[..10], &txid).is_err());
        // 错误消息类型。
        let mut wrong_type = good.clone();
        wrong_type[0] = 0x00;
        wrong_type[1] = 0x00;
        assert!(parse_binding_response(&wrong_type, &txid).is_err());
        // 错误 magic cookie。
        let mut wrong_cookie = good.clone();
        wrong_cookie[5] ^= 0xff;
        assert!(parse_binding_response(&wrong_cookie, &txid).is_err());
        // 事务 ID 不匹配。
        let other_txid = [0x02; 12];
        assert!(parse_binding_response(&good, &other_txid).is_err());
    }

    #[test]
    fn probe_once_returns_mapping() {
        let local = SocketAddr::from((Ipv4Addr::LOCALHOST, 40000));
        let public = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 7), 54321));
        let mut prober = StunProber::new(Box::new(MockStunTransport::new(local, vec![public])));
        let server = SocketAddr::from((Ipv4Addr::LOCALHOST, 3478));
        let m = prober.probe_once(server, STUN_PROBE_TIMEOUT).unwrap();
        assert_eq!(m.local, local);
        assert_eq!(m.public, public);
    }

    #[test]
    fn detect_nat_type_branches_symmetric_vs_cone() {
        let local = SocketAddr::from((Ipv4Addr::LOCALHOST, 40000));
        let server1 = SocketAddr::from((Ipv4Addr::LOCALHOST, 3478));
        let server2 = SocketAddr::from((Ipv4Addr::LOCALHOST, 3479));

        // 两个服务器返回相同映射 → 非对称（保守 RestrictedCone）。
        let same = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 7), 54321));
        let mut cone = StunProber::new(Box::new(MockStunTransport::new(local, vec![same, same])));
        assert_eq!(
            cone.detect_nat_type(server1, server2).unwrap(),
            NatType::RestrictedCone
        );

        // 第二个服务器返回不同映射 → Symmetric。
        let second = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 7), 54322));
        let mut sym = StunProber::new(Box::new(MockStunTransport::new(local, vec![same, second])));
        assert_eq!(
            sym.detect_nat_type(server1, server2).unwrap(),
            NatType::Symmetric
        );
    }

    #[test]
    fn sample_returns_port_sample() {
        let local = SocketAddr::from((Ipv4Addr::LOCALHOST, 40000));
        let public = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 7), 54321));
        let mut prober = StunProber::new(Box::new(MockStunTransport::new(local, vec![public])));
        let server = SocketAddr::from((Ipv4Addr::LOCALHOST, 3478));
        let s = prober.sample(server).unwrap();
        assert_eq!(s.port, 54321);
        assert!(s.at_ms > 0);
    }

    #[test]
    fn should_punch_branches() {
        // Symmetric → 不打洞（走 relay）；Cone/Unknown → 打洞。
        assert!(!should_punch(NatType::Symmetric));
        assert!(should_punch(NatType::FullCone));
        assert!(should_punch(NatType::RestrictedCone));
        assert!(should_punch(NatType::PortRestrictedCone));
        assert!(should_punch(NatType::Unknown));
    }
}
