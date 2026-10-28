//! STUN 探测与 NAT 类型分支（NAT switching daemon activation，AC4）。
//!
//! 职责：
//! - 单次 STUN Binding 探测（默认 2s 超时，经注入的 `StunTransport` 零网络可测）；
//! - NAT 类型检测（双服务器公网映射对比：对称 vs 锥型）；STUN 消息
//!   编解码经 `nexus-turn::stun` 归一（codec 单一来源）；
//! - 基于 NAT 类型的打洞分支决策（`should_punch`）；
//! - 输出 `PortSample` 供 `PunchManager` 的有界端口预测（±16/3s）使用。
//!
//! 5 分钟重采样由调用方（`main.rs`）驱动：本模块只声明 `STUN_REFRESH_INTERVAL`
//! 节奏，不自行创建长期任务（§13 结构化并发：Worker 由组合根拥有）。

//! Tech debt (W-1)：`unix_ms` / 事务 ID 熵 / `UdpStunTransport` 累计超时直接使用
//! `SystemTime`/`Instant`。DESIGN.md §11 决议 6 的时钟注入约束针对协议 core
//! crate；本模块是 daemon-edge 的 STUN 探测（端口样本时间戳仅用于 Δ 排序，
//! 无需虚拟时间确定性）。工作区统一 `Clock` 抽象落地后随之迁移。
//!

#![allow(dead_code)]

use std::fmt;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use nexus_domain::nat::{NatType, StunMapping};
use nexus_nat_traversal::{DefaultPredictor, PortSample, Predictability, PunchPredictor};
use nexus_turn::stun::{self, Attribute, StunMessage};

/// 单次 STUN 探测超时（AC4：2s）。
pub const STUN_PROBE_TIMEOUT: Duration = Duration::from_secs(2);
/// STUN 重采样/刷新节奏（AC4：5min；调用方驱动）。
pub const STUN_REFRESH_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// D2 有界端口预测：端口窗口半径（±16）。
pub const BOUNDED_PUNCH_PORT_RADIUS: u16 = 16;
/// D2 有界端口预测：时间盒（3s）。
pub const BOUNDED_PUNCH_TIME_WINDOW: Duration = Duration::from_secs(3);

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
/// 回环；trait 分离两个维度（传输接缝的设计意图：真实实现与测试替身可独立变化）。
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
        // W-4：累计超时——`set_read_timeout` 是每 syscall 重启计时的，公网脏包
        // flood 会让总耗时远超 `timeout`；循环外记录起点，累计超时即返回。
        // （时间源说明见 W-1 tech-debt 注释。）
        let start = std::time::Instant::now();
        loop {
            match self.socket.recv_from(&mut buf) {
                // 只接受来自目标服务器的响应（丢弃脏包/迟到包，继续等）。
                Ok((n, from)) if from == server => return Ok(buf[..n].to_vec()),
                Ok((_, _)) => {
                    if start.elapsed() >= timeout {
                        return Err(StunError::Timeout);
                    }
                    continue;
                }
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
        let request = StunMessage {
            msg_type: 0x0001, // STUN Binding Request; nexus-turn 未导出该常量
            txn: txid,
            attrs: vec![],
        }
        .encode();
        let response = self.transport.send_recv(&request, server, timeout)?;
        let public = parse_binding_response(&response, &txid)?;
        let local = self.transport.local_addr()?;
        Ok(StunMapping { local, public })
    }

    /// NAT 类型检测：对比两个 STUN 服务器的公网映射。
    ///
    /// 映射不同 → `Symmetric`；相同 → `RestrictedCone`（无法区分
    /// Full/Restricted/PortRestricted，保守取 RestrictedCone，与
    /// `nexus_domain::nat` 同口径）。
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

    /// 同一 transport（生产上即 punch driver socket）连续探测两个目标。
    ///
    /// 返回两条 mapping + NAT 类型；任一 probe 失败即返回该错误，不返回半成品。
    /// 双样本是 `DefaultPredictor` 的 `distinct_targets >= 2` 前提。
    pub fn probe_pair(
        &mut self,
        server1: SocketAddr,
        server2: SocketAddr,
    ) -> Result<(StunMapping, StunMapping, NatType), StunError> {
        let m1 = self.probe_once(server1, STUN_PROBE_TIMEOUT)?;
        let m2 = self.probe_once(server2, STUN_PROBE_TIMEOUT)?;
        let nat_type = if m1.public != m2.public {
            NatType::Symmetric
        } else {
            NatType::RestrictedCone
        };
        Ok((m1, m2, nat_type))
    }

    /// 双服务器探测：返回 server1 的公网映射 + 双映射对比的 NAT 类型。
    ///
    /// 一次调用只做两次 Binding 探测（调用方不再需要额外的 `probe_once`），
    /// 适合 5min 刷新循环直接取映射与类型。
    pub fn probe_and_detect(
        &mut self,
        server1: SocketAddr,
        server2: SocketAddr,
    ) -> Result<(StunMapping, NatType), StunError> {
        let (m1, _m2, nat_type) = self.probe_pair(server1, server2)?;
        Ok((m1, nat_type))
    }

    /// 采集一个端口样本（供 `PunchManager` 有界预测）。
    pub fn sample(&mut self, server: SocketAddr) -> Result<PortSample, StunError> {
        let m = self.probe_once(server, STUN_PROBE_TIMEOUT)?;
        Ok(PortSample {
            port: m.public.port(),
            at_ms: unix_ms(),
            target: server,
            observed_from: m.local,
        })
    }
}

/// Production STUN transport on the punch driver's UDP socket.
///
/// Installs the additive fabric STUN tap and correlates responses by
/// transaction id over an mpsc channel. `local_addr()` is the driver socket,
/// so `PortSample.observed_from` proves same-socket provenance (AC-1/G1).
pub struct DriverStunTransport {
    driver: Arc<nexus_fabric::Driver>,
    inbox: std::sync::Mutex<std::sync::mpsc::Receiver<nexus_fabric::StunResponse>>,
}

struct TapSink {
    tx: std::sync::mpsc::Sender<nexus_fabric::StunResponse>,
}

impl nexus_fabric::StunSink for TapSink {
    fn on_stun_response(&self, response: nexus_fabric::StunResponse) {
        let _ = self.tx.send(response);
    }
}

impl DriverStunTransport {
    pub fn new(driver: Arc<nexus_fabric::Driver>) -> Result<Self, io::Error> {
        let (tx, rx) = std::sync::mpsc::channel();
        driver
            .install_stun_tap(Arc::new(TapSink { tx }))
            .map_err(|e| io::Error::other(format!("install_stun_tap: {e:?}")))?;
        Ok(Self {
            driver,
            inbox: std::sync::Mutex::new(rx),
        })
    }
}

impl StunTransport for DriverStunTransport {
    fn send_recv(
        &mut self,
        request: &[u8],
        server: SocketAddr,
        timeout: Duration,
    ) -> Result<Vec<u8>, StunError> {
        let txn = self
            .driver
            .send_stun_request(server, request.to_vec())
            .map_err(|e| StunError::Io(io::Error::other(format!("send_stun_request: {e:?}"))))?;
        let deadline = std::time::Instant::now() + timeout;
        let inbox = self
            .inbox
            .lock()
            .map_err(|_| StunError::Io(io::Error::other("stun inbox poisoned")))?;
        loop {
            let remain = deadline.saturating_duration_since(std::time::Instant::now());
            if remain.is_zero() {
                return Err(StunError::Timeout);
            }
            match inbox.recv_timeout(remain) {
                // 只接受本事务且来自目标服务器的响应（与 UdpStunTransport 同口径）。
                Ok(r) if r.transaction_id == txn && r.from == server => return Ok(r.bytes),
                Ok(_) => continue,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => return Err(StunError::Timeout),
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(StunError::Io(io::Error::other("stun tap closed")));
                }
            }
        }
    }

    fn local_addr(&self) -> Result<SocketAddr, StunError> {
        // 实时读取 driver socket 地址（rebind 后不返回构造期缓存）。
        let local = self
            .driver
            .shared()
            .local_addr
            .lock()
            .map_err(|_| StunError::Io(io::Error::other("driver local_addr poisoned")))?;
        Ok(*local)
    }
}

/// 打洞分支决策（AC4 + D2 有界端口预测决议）。
///
/// - 本地 Cone / Unknown → 常规打洞（`Punch`）；
/// - 本地 Symmetric：仅当端口增量 Δ 稳定（≥3 样本、连续两两 Δ 相等，
///   复用 `nexus_nat_traversal::DefaultPredictor` 的冻结判定逻辑）且对端为
///   Cone 时，触发 D2 有界预测打洞（±16 端口窗口，3s 时间盒，只打对端单一 IP）；
///   Δ 不规律、样本不足、STUN 超时或对端同为 Symmetric/Unknown → `NoPunch`，
///   稳定维持 Relay 路径。
pub fn should_punch(local: NatType, peer: NatType, samples: &[PortSample]) -> PunchDecision {
    let delta_stable = matches!(
        DefaultPredictor.assess(samples),
        Predictability::Predictable { .. }
    );
    match (local, peer) {
        // Symmetric–symmetric: mathematically unreachable under the frozen
        // spray semantics; never send.
        (NatType::Symmetric, NatType::Symmetric) => PunchDecision::NoPunch,
        // Local symmetric -> cone: bounded mapping probes + prediction.
        (NatType::Symmetric, p) if is_cone(p) => {
            if delta_stable {
                PunchDecision::BoundedPunch {
                    port_radius: BOUNDED_PUNCH_PORT_RADIUS,
                    time_window: BOUNDED_PUNCH_TIME_WINDOW,
                }
            } else {
                PunchDecision::NoPunch
            }
        }
        // Local symmetric with a non-cone peer (Unknown included): relay.
        (NatType::Symmetric, _) => PunchDecision::NoPunch,
        // Cone -> remote symmetric: attempt; the hint gate lives in run().
        (l, NatType::Symmetric) if is_cone(l) => PunchDecision::Punch,
        _ => PunchDecision::Punch,
    }
}

/// 打洞分支决策（AC4 + D2）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PunchDecision {
    /// Cone/Unknown NAT：常规打洞。
    Punch,
    /// 本地 Symmetric + Δ 稳定 + 对端 Cone：D2 有界预测打洞
    /// （±16 端口窗口，3s 时间盒，只打对端单一 IP）。
    BoundedPunch {
        port_radius: u16,
        time_window: Duration,
    },
    /// 其余情况：维持 Relay，不打洞。
    NoPunch,
}

/// 是否为锥型 NAT（Full / Restricted / PortRestricted）。
fn is_cone(t: NatType) -> bool {
    matches!(
        t,
        NatType::FullCone | NatType::RestrictedCone | NatType::PortRestrictedCone
    )
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

/// 解析 STUN Binding Success Response，提取 XOR-MAPPED-ADDRESS。
///
/// 经 `nexus-turn::stun` 解码；校验消息类型、Magic Cookie 与事务 ID
/// （拒绝脏包/迟到包）。`stun::decode` 本身不校验 `msg_type`，此处自查
/// 以保留旧行为；Magic Cookie 由 decode 校验（`DecodeError::BadMagic`→`Parse`）。
fn parse_binding_response(buf: &[u8], txid: &[u8; 12]) -> Result<SocketAddr, StunError> {
    let msg = stun::decode(buf).map_err(|e| StunError::Parse(format!("stun decode: {e:?}")))?;
    // STUN Binding Success Response（RFC 5389 §7.3.1）；字面量因
    // nexus-turn 未导出该常量。
    if msg.msg_type != 0x0101 {
        return Err(StunError::Parse(format!(
            "unexpected message type: 0x{:04x}",
            msg.msg_type
        )));
    }
    if msg.txn != *txid {
        return Err(StunError::Parse("transaction id mismatch".into()));
    }
    for attr in &msg.attrs {
        if let Attribute::XorMappedAddress(addr) = attr {
            // 旧 codec 只接受 IPv4（family 0x01）；保持行为一致。
            if !addr.is_ipv4() {
                return Err(StunError::Parse(
                    "only IPv4 xor-mapped-address supported".into(),
                ));
            }
            return Ok(*addr);
        }
    }
    Err(StunError::Parse("xor-mapped-address not found".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

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
        buf.extend_from_slice(&0x0101u16.to_be_bytes()); // Binding Success Response
        buf.extend_from_slice(&12u16.to_be_bytes()); // msg len = attr block (2+2+8); old codec ignored this field
        buf.extend_from_slice(&stun::MAGIC_COOKIE.to_be_bytes());
        buf.extend_from_slice(txid);
        buf.extend_from_slice(&0x0020u16.to_be_bytes()); // XOR-MAPPED-ADDRESS
        buf.extend_from_slice(&8u16.to_be_bytes());
        buf.extend_from_slice(&[0x00, 0x01]); // reserved + family IPv4
        let port = public.port() ^ ((stun::MAGIC_COOKIE >> 16) as u16);
        buf.extend_from_slice(&port.to_be_bytes());
        buf.extend_from_slice(&(ip ^ stun::MAGIC_COOKIE).to_be_bytes());
        buf
    }

    #[test]
    fn binding_request_is_20_bytes() {
        let txid = [0x12; 12];
        let req = StunMessage {
            msg_type: 0x0001, // STUN Binding Request
            txn: txid,
            attrs: vec![],
        }
        .encode();
        assert_eq!(req.len(), 20);
        assert_eq!(&req[0..2], &0x0001u16.to_be_bytes());
        assert_eq!(&req[8..20], &txid);
    }

    /// AC1 回归门：`nexus-turn::stun` 编码输出必须与退役前的私有 codec
    /// 逐字节一致（3 组固定 txid 的 golden vector，删前抓取）。
    #[test]
    fn stun_codec_byte_equivalence() {
        const GOLDEN: [([u8; 12], &str); 3] = [
            ([0x01; 12], "000100002112a442010101010101010101010101"),
            ([0xab; 12], "000100002112a442abababababababababababab"),
            ([0x5c; 12], "000100002112a4425c5c5c5c5c5c5c5c5c5c5c5c"),
        ];
        for (txid, hex) in GOLDEN {
            let got = StunMessage {
                msg_type: 0x0001,
                txn: txid,
                attrs: vec![],
            }
            .encode();
            let want: Vec<u8> = (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                .collect();
            assert_eq!(got, want, "golden mismatch for txid {txid:02x?}");
        }
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
    fn probe_pair_returns_two_mappings_and_type() {
        let local = SocketAddr::from((Ipv4Addr::LOCALHOST, 40000));
        let server1 = SocketAddr::from((Ipv4Addr::LOCALHOST, 3478));
        let server2 = SocketAddr::from((Ipv4Addr::LOCALHOST, 3479));
        let same = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 7), 54321));

        // 双服务器返回相同映射 → RestrictedCone；两次请求。
        let transport = MockStunTransport::new(local, vec![same, same]);
        let mut cone = StunProber::new(Box::new(transport));
        let (m1, m2, nat) = cone.probe_pair(server1, server2).unwrap();
        assert_eq!(m1.public, same);
        assert_eq!(m2.public, same);
        assert_eq!(m1.local, local);
        assert_eq!(m2.local, local);
        assert_eq!(nat, NatType::RestrictedCone);

        // 第二个服务器返回不同映射 → Symmetric；仍只有两次请求。
        let second = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 7), 54322));
        let transport = MockStunTransport::new(local, vec![same, second]);
        let mut sym = StunProber::new(Box::new(transport));
        let (m1, m2, nat) = sym.probe_pair(server1, server2).unwrap();
        assert_eq!(m1.public, same);
        assert_eq!(m2.public, second);
        assert_eq!(nat, NatType::Symmetric);

        // 投影保持既有签名/语义（丢弃 m2）。
        let transport = MockStunTransport::new(local, vec![same, second]);
        let mut projected = StunProber::new(Box::new(transport));
        let (m1, nat) = projected.probe_and_detect(server1, server2).unwrap();
        assert_eq!(m1.public, same);
        assert_eq!(nat, NatType::Symmetric);
    }

    /// 顺序分配公网端口的 mock：每次响应 +1（从 40000 起）。
    fn sequential_ip_responses(count: usize) -> Vec<SocketAddr> {
        (0..count)
            .map(|i| {
                SocketAddr::from((
                    Ipv4Addr::new(203, 0, 113, 7),
                    40_000u16.wrapping_add(i as u16),
                ))
            })
            .collect()
    }

    /// 按采样轮次顺序（每轮 s1,s2）把 `probe_pair` 的映射压成端口样本。
    fn sample_pair_series(
        prober: &mut StunProber,
        server1: SocketAddr,
        server2: SocketAddr,
        rounds: usize,
        samples: &mut Vec<PortSample>,
    ) -> (StunMapping, NatType) {
        let mut last_m1 = None;
        let mut last_nat = NatType::Unknown;
        for round in 0..rounds {
            let (m1, m2, nat) = prober.probe_pair(server1, server2).unwrap();
            for (mapping, target) in [(&m1, server1), (&m2, server2)] {
                samples.push(PortSample {
                    port: mapping.public.port(),
                    at_ms: 1_000_000 + (round * 2) as u64 * 100,
                    target,
                    observed_from: mapping.local,
                });
            }
            last_m1 = Some(m1);
            last_nat = nat;
        }
        (last_m1.expect("at least one round"), last_nat)
    }

    #[test]
    fn sample_series_is_predictable() {
        let local = SocketAddr::from((Ipv4Addr::LOCALHOST, 40000));
        let server1 = SocketAddr::from((Ipv4Addr::LOCALHOST, 3478));
        let server2 = SocketAddr::from((Ipv4Addr::LOCALHOST, 3479));
        let mut prober = StunProber::new(Box::new(MockStunTransport::new(
            local,
            sequential_ip_responses(6),
        )));

        let mut samples = Vec::new();
        sample_pair_series(&mut prober, server1, server2, 3, &mut samples);
        assert_eq!(samples.len(), 6, "3 rounds x 2 targets");
        let first_observed = samples[0].observed_from;
        assert!(samples.iter().all(|s| s.observed_from == first_observed));
        let mut targets: Vec<SocketAddr> = samples.iter().map(|s| s.target).collect();
        targets.sort();
        targets.dedup();
        assert_eq!(targets.len(), 2, "two distinct targets per round");

        let ports: Vec<u16> = samples.iter().map(|s| s.port).collect();
        assert_eq!(ports, vec![40000, 40001, 40002, 40003, 40004, 40005]);
        assert_eq!(
            DefaultPredictor.assess(&samples),
            Predictability::Predictable {
                base_port: 40005,
                delta: 1,
            }
        );
    }

    #[test]
    fn p1_ac2_candidates_projection() {
        use crate::nat_gather::CandidateGatherer;

        let local = SocketAddr::from((Ipv4Addr::LOCALHOST, 40000));
        let server1 = SocketAddr::from((Ipv4Addr::LOCALHOST, 3478));
        let server2 = SocketAddr::from((Ipv4Addr::LOCALHOST, 3479));
        let stun = StunProber::new(Box::new(MockStunTransport::new(
            local,
            sequential_ip_responses(6),
        )));
        let mut gatherer = CandidateGatherer::new(stun, local);
        let mut samples = Vec::new();
        let (last_m1, nat) =
            sample_pair_series(gatherer.stun_prober(), server1, server2, 3, &mut samples);
        gatherer.set_nat_type(nat);

        // 组合根投影（Wave B 的 sample_round 规则；Wave A 在测试内复刻）：
        // srflx = 最后一轮 s1 的 XOR-MAPPED，srflx_stun = Some(s1)。
        let mut candidates = gatherer
            .gather(None, false, &mut samples)
            .expect("host candidate present");
        candidates.srflx = Some(last_m1.public);
        candidates.srflx_stun = Some(server1);

        assert_eq!(candidates.srflx, Some(last_m1.public));
        assert_eq!(candidates.srflx_stun, Some(server1));
        assert_eq!(candidates.srflx_turn, None);
        assert_eq!(candidates.nat_type, nat);
        assert_eq!(samples.len(), 6);
    }

    fn port_samples(ports: &[u16]) -> Vec<PortSample> {
        ports
            .iter()
            .enumerate()
            .map(|(i, &port)| PortSample {
                port,
                at_ms: 1_000_000 + i as u64 * 100,
                target: if i % 2 == 0 {
                    "192.0.2.1:3478".parse().unwrap()
                } else {
                    "192.0.2.2:3478".parse().unwrap()
                },
                observed_from: "10.0.0.2:5000".parse().unwrap(),
            })
            .collect()
    }

    #[test]
    fn should_punch_branches() {
        let no_samples: Vec<PortSample> = vec![];
        // Cone / Unknown → 常规打洞。
        assert_eq!(
            should_punch(NatType::FullCone, NatType::Symmetric, &no_samples),
            PunchDecision::Punch
        );
        assert_eq!(
            should_punch(NatType::RestrictedCone, NatType::FullCone, &no_samples),
            PunchDecision::Punch
        );
        assert_eq!(
            should_punch(NatType::PortRestrictedCone, NatType::Unknown, &no_samples),
            PunchDecision::Punch
        );
        assert_eq!(
            should_punch(NatType::Unknown, NatType::Symmetric, &no_samples),
            PunchDecision::Punch
        );
        // Symmetric 本地 + 无样本 → 不打洞（维持 Relay）。
        assert_eq!(
            should_punch(NatType::Symmetric, NatType::FullCone, &no_samples),
            PunchDecision::NoPunch
        );
    }

    #[test]
    fn d2_bounded_punch_on_stable_delta() {
        // 本地 Symmetric + Δ 稳定（10000→10002→10004，Δ=2）+ 对端 Cone
        // → D2 有界预测打洞（±16 端口，3s 时间盒）。
        let samples = port_samples(&[10000, 10002, 10004]);
        assert_eq!(
            should_punch(NatType::Symmetric, NatType::FullCone, &samples),
            PunchDecision::BoundedPunch {
                port_radius: BOUNDED_PUNCH_PORT_RADIUS,
                time_window: BOUNDED_PUNCH_TIME_WINDOW,
            }
        );
        assert_eq!(
            should_punch(NatType::Symmetric, NatType::PortRestrictedCone, &samples),
            PunchDecision::BoundedPunch {
                port_radius: 16,
                time_window: Duration::from_secs(3),
            }
        );
    }

    #[test]
    fn d2_no_punch_on_unstable_delta() {
        // Δ 不规律（10000→10005→10003）→ 不打洞。
        let samples = port_samples(&[10000, 10005, 10003]);
        assert_eq!(
            should_punch(NatType::Symmetric, NatType::FullCone, &samples),
            PunchDecision::NoPunch
        );
    }

    #[test]
    fn d2_no_punch_when_peer_not_cone() {
        // 对端同为 Symmetric → 不打洞；对端 Unknown → 不打洞（无法确认 Cone）。
        let samples = port_samples(&[10000, 10002, 10004]);
        assert_eq!(
            should_punch(NatType::Symmetric, NatType::Symmetric, &samples),
            PunchDecision::NoPunch
        );
        assert_eq!(
            should_punch(NatType::Symmetric, NatType::Unknown, &samples),
            PunchDecision::NoPunch
        );
    }

    #[test]
    fn d2_no_punch_on_too_few_samples() {
        // 样本不足 3 个 → Δ 无法判定 → 不打洞。
        let samples = port_samples(&[10000, 10002]);
        assert_eq!(
            should_punch(NatType::Symmetric, NatType::FullCone, &samples),
            PunchDecision::NoPunch
        );
    }
}

#[cfg(test)]
mod gap_tests {
    use super::*;
    use nexus_fabric::Driver;
    use std::net::UdpSocket;
    use std::thread;

    fn binding_request(txn: [u8; 12]) -> Vec<u8> {
        StunMessage {
            msg_type: 0x0001, // STUN Binding Request
            txn,
            attrs: vec![],
        }
        .encode()
    }

    fn binding_response(txn: [u8; 12], public: SocketAddr) -> Vec<u8> {
        StunMessage {
            msg_type: 0x0101, // Binding Success Response
            txn,
            attrs: vec![Attribute::XorMappedAddress(public)],
        }
        .encode()
    }

    #[test]
    fn g1_stun_samples_share_punch_socket() {
        let driver = Driver::new_server("127.0.0.1:0".parse().unwrap()).expect("bind driver");
        let local = *driver.shared().local_addr.lock().unwrap();
        let transport = DriverStunTransport::new(driver.clone()).expect("install tap");
        assert_eq!(
            transport.local_addr().unwrap(),
            local,
            "STUN must be observed on the punch driver socket"
        );
    }

    /// S1/AC-1：`local_addr()` 跟随 driver 实时地址，不返回构造期缓存。
    #[test]
    fn tap_local_addr_is_live_driver_addr() {
        let driver = Driver::new_server("127.0.0.1:0".parse().unwrap()).expect("bind driver");
        let transport = DriverStunTransport::new(driver.clone()).expect("install tap");
        let rebound: SocketAddr = "127.0.0.1:54321".parse().unwrap();
        // D-3：没有服务端级 rebind API；测试直接改 driver 的共享 local_addr
        // （无 traffic，安全），以证明 transport 不再缓存构造期值。
        *driver.shared().local_addr.lock().unwrap() = rebound;
        assert_eq!(
            transport.local_addr().unwrap(),
            rebound,
            "driver local_addr must be read live (rebind-safe)"
        );
    }

    /// S2/AC-1：伪造同 txn 的错误源响应必须先被丢弃。
    ///
    /// D-1（ANCHOR-DRIFT）：fabric tap 在第一个 txn 命中时就把 pending 消费掉
    /// （不论源地址），因此正确源的后到响应不会再进 sink。本测试断言：
    /// 伪造先到 → `Timeout`；干净路径 → `Ok`。目标（不接受错误源）不变。
    #[test]
    fn send_recv_rejects_wrong_source() {
        let driver = Driver::new_server("127.0.0.1:0".parse().unwrap()).expect("bind driver");
        let driver_addr = *driver.shared().local_addr.lock().unwrap();
        let mut transport = DriverStunTransport::new(driver.clone()).expect("install tap");

        let legit = UdpSocket::bind("127.0.0.1:0").expect("bind legit responder");
        let legit_addr = legit.local_addr().expect("legit addr");
        let attacker = UdpSocket::bind("127.0.0.1:0").expect("bind attacker");

        // 第 1 轮：等 driver 的请求到达 legit（证明 txn 已注册），attacker
        // 立即发伪造响应，legit 50ms 后发正确响应 → Timeout（D-1）。
        let txn1 = [0x31u8; 12];
        let forged_public: SocketAddr = "203.0.113.9:50000".parse().unwrap();
        let legit_public: SocketAddr = "198.51.100.7:41000".parse().unwrap();
        let forged = binding_response(txn1, forged_public);
        let legit_response = binding_response(txn1, legit_public);
        let coordinator = {
            let legit = legit.try_clone().expect("clone legit");
            let attacker = attacker.try_clone().expect("clone attacker");
            thread::spawn(move || {
                let mut buf = [0u8; 1500];
                legit
                    .set_read_timeout(Some(Duration::from_millis(500)))
                    .expect("set legit read timeout");
                let _ = legit.recv_from(&mut buf).expect("probe request arrives");
                let _ = attacker.send_to(&forged, driver_addr);
                thread::sleep(Duration::from_millis(50));
                let _ = legit.send_to(&legit_response, driver_addr);
            })
        };
        let err = transport
            .send_recv(
                &binding_request(txn1),
                legit_addr,
                Duration::from_millis(400),
            )
            .expect_err("forged response must never be accepted");
        assert!(
            matches!(err, StunError::Timeout),
            "forged-first must yield Timeout, got {err:?}"
        );
        coordinator.join().unwrap();

        // 第 2 轮：干净路径（正确源）→ Ok，字节可解析为同一映射。
        let txn2 = [0x32u8; 12];
        let clean_response = binding_response(txn2, legit_public);
        let clean_sender = {
            let sock = legit.try_clone().expect("clone legit");
            thread::spawn(move || {
                let mut buf = [0u8; 1500];
                sock.set_read_timeout(Some(Duration::from_millis(500)))
                    .expect("set legit read timeout");
                let _ = sock.recv_from(&mut buf).expect("probe request arrives");
                let _ = sock.send_to(&clean_response, driver_addr);
            })
        };
        let bytes = transport
            .send_recv(
                &binding_request(txn2),
                legit_addr,
                Duration::from_millis(400),
            )
            .expect("clean source response must be accepted");
        clean_sender.join().unwrap();
        assert_eq!(
            parse_binding_response(&bytes, &txn2).expect("parse clean response"),
            legit_public
        );
    }
}
