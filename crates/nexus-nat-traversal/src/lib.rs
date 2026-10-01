//! NAT 穿透打洞编排核心（portable core，std-only）。
//!
//! 冻结合同：`docs/foundation/NAT-TRAVERSAL-CONTRACT.md`
//! （contract hash `6ab671a04d061b16`）。
//!
//! 本 crate 只做编排：候选地址（P1）、信令编解码（P2）、
//! 打洞状态机（P4）、可观测（P7）。真实的 QUIC 迁移、
//! 三类路径竞速、多路径由组合根经注入 trait 装配；
//! 各轨道不得碰 `driver.rs` / `nexusd`。

pub mod candidate;
pub mod predict;
pub mod race;
pub mod signal;

pub use candidate::{CandidateKind, LocalCandidates, PunchCandidate, punch_targets};
pub use predict::DefaultPredictor;
pub use race::{path_score, select_path};
pub use signal::{
    MAX_CANDIDATES, PunchAnswer, PunchOffer, SIGNAL_VERSION, SignalError, decode_answer,
    decode_offer, encode_answer, encode_offer,
};

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use nexus_connectivity::nat::NatType;

// ---------------------------------------------------------------------------
// P4 相关类型
// ---------------------------------------------------------------------------

/// 对端身份。与 `nexus-fabric::PeerId` 同表示（`[u8; 32]` ed25519 公钥）。
///
/// 本 crate 按合同只依赖 `nexus-connectivity`（std-only portable core），
/// 故在此本地定义；组合根接线时做 `From` 转换（表示相同，无信息损失）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PeerId(pub [u8; 32]);

/// 打洞编排阶段（冻结的状态转换见 `PunchSession::run`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PunchPhase {
    #[default]
    Idle,
    OfferSent,
    Coordinated,
    Punching,
    Validating,
    Migrated,
    Failed(PunchFailReason),
}

/// 打洞失败原因（冻结）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PunchFailReason {
    /// 任一步超时。
    Timeout,
    /// 任一端 Symmetric 且 predictor 不可预测。
    UnpredictableSymmetric,
    /// 无可用候选（本地或对端）。
    NoCandidates,
    /// 信令通道关闭/异常。
    ChannelClosed,
}

/// 信令通道（P4）：承载 offer/answer 的可靠通道。
///
/// 生产实现 = 中继 FabricConn 上的一条控制流（已认证加密）；
/// 测试用内存替身。
pub trait PunchChannel: Send + Sync {
    fn send_offer(&self, offer: &PunchOffer) -> io::Result<()>;
    /// 等待 answer；超时 → `Err` 且 kind 为 `TimedOut`。
    fn recv_answer(&self, timeout: Duration) -> io::Result<PunchAnswer>;
}

/// 打洞 socket（P4）：**必须**是 QUIC 连接所在的同一个 UDP socket
///（NAT 映射绑定本地 4 元组，换 socket 打洞无效）。
///
/// 生产实现由组合根注入（driver 的 socket）；测试用真实 UDP 替身。
pub trait PunchSocket: Send + Sync {
    /// 从同一 UDP socket 向目标发打洞负载。
    ///
    /// 负载语义：生产环境应为 QUIC 包（由组合根构造）；本核心发送
    /// 内部标记负载，冻结的是"同一 socket + 目标地址"语义——
    /// 生产 `PunchSocket` 实现拥有 socket，可在此处替换为真实
    /// QUIC Initial/PING 字节。
    fn send_punch(&self, target: SocketAddr, payload: &[u8]) -> io::Result<()>;
    /// 等待对端打洞包/路径验证完成，返回验证通过的直连地址；
    /// 超时 → `Err` 且 kind 为 `TimedOut`。
    fn await_direct(&self, timeout: Duration) -> io::Result<SocketAddr>;
}

/// 打洞配置（冻结字段与默认值）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PunchConfig {
    /// 打洞/等 answer 超时。默认 5s。
    pub punch_timeout: Duration,
    /// 协同开打时间窗（offer.start_at 相对发送时刻的偏移）。默认 200ms。
    pub coord_skew_ms: u64,
    /// spray 半径 K。默认 16，上限 32（构造时钳制）。
    pub spray_k: u8,
    /// spray 限速间隔。默认 50ms。
    pub spray_interval_ms: u64,
    /// 后台重打洞间隔。默认 5min。
    pub repunch_interval: Duration,
}

impl Default for PunchConfig {
    fn default() -> Self {
        Self {
            punch_timeout: Duration::from_secs(5),
            coord_skew_ms: 200,
            spray_k: 16,
            spray_interval_ms: 50,
            repunch_interval: Duration::from_secs(5 * 60),
        }
    }
}

/// `run()` 的终态结果（Exactly-One Terminal Outcome）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PunchResult {
    /// 打洞成功：连接可迁移到 `addr`（迁移本身由组合根驱动 driver）。
    Migrated { addr: SocketAddr },
    /// 留在中继上（打洞失败/放弃）。
    StayedOnRelay { reason: PunchFailReason },
}

// ---------------------------------------------------------------------------
// P3 可预测性检测（trait 由 Track A 定义，实现由 Track B 提供）
// ---------------------------------------------------------------------------

/// STUN 端口采样。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortSample {
    pub port: u16,
    pub at_ms: u64,
}

/// 可预测性判定（冻结规则见合同 §P3）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Predictability {
    Predictable { base_port: u16, delta: i32 },
    Unpredictable,
}

/// 有界 spray 计划。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SprayPlan {
    pub target_ip: IpAddr,
    pub ports: Vec<u16>,
}

/// 端口预测器（注入 trait）。
///
/// 样本采集是组合根的责任：组合根可提供预载了 STUN 样本的
/// 有状态实现；本核心调用 `assess(&[])`，实现可忽略该参数
/// 而使用内部样本（`NoopPredictor` 恒返回 `Unpredictable`）。
pub trait PunchPredictor: Send + Sync {
    /// 至少 3 个样本；Δ 不稳定 → `Unpredictable`。
    fn assess(&self, samples: &[PortSample]) -> Predictability;
    /// 有界：`ports.len() <= 2*K+1`，K = `config.spray_k`（上限 32）。
    fn plan(&self, p: &Predictability, target_ip: IpAddr, k: u8) -> Option<SprayPlan>;
}

/// 空预测器：恒 `Unpredictable`（Track A 自身测试用）。
#[derive(Debug, Default)]
pub struct NoopPredictor;

impl PunchPredictor for NoopPredictor {
    fn assess(&self, _samples: &[PortSample]) -> Predictability {
        Predictability::Unpredictable
    }

    fn plan(&self, _p: &Predictability, _target_ip: IpAddr, _k: u8) -> Option<SprayPlan> {
        None
    }
}

// ---------------------------------------------------------------------------
// P5 三类路径竞速（类型由 Track A 定义，实现由 Track C 提供）
// ---------------------------------------------------------------------------

/// 路径类别（冻结）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RaceClass {
    DirectP2P,
    TurnRelay,
    PeerRelay,
}

/// 带打分的路径候选。
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ScoredPath {
    pub class: RaceClass,
    pub rtt_ms: u64,
    /// 0.0–1.0。
    pub loss_01: f64,
}

/// 打洞成功后向路径层登记 direct 候选（Track C 实现；
///
/// Track A 只定义 trait，测试用 `NoopFeed`）。
pub trait PunchRaceFeed: Send + Sync {
    fn report_direct_candidate(&self, peer: PeerId, addr: SocketAddr, rtt_ms: u64, loss_01: f64);
}

/// 空登记器（Track A 自身测试用）。
#[derive(Debug, Default)]
pub struct NoopFeed;

impl PunchRaceFeed for NoopFeed {
    fn report_direct_candidate(
        &self,
        _peer: PeerId,
        _addr: SocketAddr,
        _rtt_ms: u64,
        _loss_01: f64,
    ) {
    }
}

// ---------------------------------------------------------------------------
// P7 可观测
// ---------------------------------------------------------------------------

/// 打洞统计（`PunchSession::stats()`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PunchStats {
    pub attempts: u64,
    pub migrated: u64,
    pub failed_timeout: u64,
    pub failed_unpredictable: u64,
    pub last_phase: PunchPhase,
}

// ---------------------------------------------------------------------------
// P4 打洞编排状态机
// ---------------------------------------------------------------------------

/// 打洞负载魔数（portable core 内部标记；生产实现可在
/// `PunchSocket::send_punch` 处替换为真实 QUIC 字节）。
const PUNCH_MAGIC: [u8; 8] = *b"NXPNCH01";

static NONCE_COUNTER: AtomicU64 = AtomicU64::new(1);

fn fresh_nonce() -> u64 {
    let t = unix_ms();
    let c = NONCE_COUNTER.fetch_add(1, Ordering::Relaxed);
    t.wrapping_mul(0x9E3779B97F4A7C15).wrapping_add(c)
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn punch_payload(nonce: u64) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[..8].copy_from_slice(&PUNCH_MAGIC);
    b[8..].copy_from_slice(&nonce.to_be_bytes());
    b
}

/// 对端打洞目标 IP：优先 Srflx 候选，否则首个候选。
fn remote_punch_ip(answer: &PunchAnswer) -> Option<IpAddr> {
    answer
        .candidates
        .iter()
        .find(|c| c.kind == CandidateKind::Srflx)
        .or_else(|| answer.candidates.first())
        .map(|c| c.addr.ip())
}

/// 打洞编排会话（发起方）。
///
/// 状态转换（冻结）：
/// `Idle →(send offer) OfferSent →(answer nonce 匹配) Coordinated
/// →(start_at 到达) Punching →(await_direct 成功) Validating
/// →(确认迁移) Migrated`；任一步超时/失败 → `Failed(reason)`。
///
/// `run()` 不直接做 QUIC 迁移：返回 `Migrated{addr}` 由组合根
/// 驱动 driver 路径迁移。
pub struct PunchSession {
    peer: PeerId,
    local: LocalCandidates,
    remote_nat: NatType,
    config: PunchConfig,
    channel: Arc<dyn PunchChannel>,
    socket: Arc<dyn PunchSocket>,
    predictor: Arc<dyn PunchPredictor>,
    nonce: u64,
    phase: PunchPhase,
    stats: PunchStats,
}

impl PunchSession {
    pub fn new(
        peer: PeerId,
        local: LocalCandidates,
        remote_nat: NatType,
        config: PunchConfig,
        channel: Arc<dyn PunchChannel>,
        socket: Arc<dyn PunchSocket>,
        predictor: Arc<dyn PunchPredictor>,
    ) -> Self {
        let mut config = config;
        config.spray_k = config.spray_k.min(32); // 冻结上限
        Self {
            peer,
            local,
            remote_nat,
            config,
            channel,
            socket,
            predictor,
            nonce: fresh_nonce(),
            phase: PunchPhase::Idle,
            stats: PunchStats::default(),
        }
    }

    /// 当前阶段。
    pub fn phase(&self) -> PunchPhase {
        self.phase
    }

    /// 对端身份。
    pub fn peer(&self) -> PeerId {
        self.peer
    }

    /// 累计统计（P7）。
    pub fn stats(&self) -> PunchStats {
        self.stats
    }

    /// 阻塞执行完整编排：offer → answer → 协同开打 → 等待直连/超时。
    ///
    /// 任一端 Symmetric 且 predictor 不可预测 → 直接
    /// `StayedOnRelay(UnpredictableSymmetric)`（不发打洞包）。
    pub fn run(&mut self) -> PunchResult {
        self.stats.attempts = self.stats.attempts.saturating_add(1);

        // P1：至少 1 个可打洞候选。
        if !self.local.has_punchable() {
            return self.fail(PunchFailReason::NoCandidates);
        }

        // Idle → OfferSent
        let offer = PunchOffer {
            version: SIGNAL_VERSION,
            nonce: self.nonce,
            candidates: self.local.ordered(),
            nat_type: self.local.nat_type,
            start_at_ms: unix_ms().saturating_add(self.config.coord_skew_ms),
        };
        if self.channel.send_offer(&offer).is_err() {
            return self.fail(PunchFailReason::ChannelClosed);
        }
        self.set_phase(PunchPhase::OfferSent);

        // OfferSent → Coordinated：nonce 不匹配的 answer 直接丢弃，
        // 状态机不推进，在整体超时内继续等。
        let deadline = Instant::now() + self.config.punch_timeout;
        let answer = loop {
            let remain = deadline.saturating_duration_since(Instant::now());
            if remain.is_zero() {
                return self.fail(PunchFailReason::Timeout);
            }
            match self.channel.recv_answer(remain) {
                Ok(a) if a.nonce == offer.nonce => break a,
                Ok(_) => continue,
                Err(e) if e.kind() == io::ErrorKind::TimedOut => {
                    return self.fail(PunchFailReason::Timeout);
                }
                Err(_) => return self.fail(PunchFailReason::ChannelClosed),
            }
        };
        self.set_phase(PunchPhase::Coordinated);

        // P4：任一端 Symmetric → 咨询 predictor。
        // 样本采集是组合根的责任（有状态 predictor 预载 STUN 样本）；
        // 不可预测 → 直接 StayedOnRelay，不发一个打洞包。
        let symmetric =
            self.local.nat_type == NatType::Symmetric || self.remote_nat == NatType::Symmetric;
        let spray_plan: Option<SprayPlan> = if symmetric {
            match self.predictor.assess(&[]) {
                Predictability::Unpredictable => {
                    return self.fail(PunchFailReason::UnpredictableSymmetric);
                }
                p @ Predictability::Predictable { .. } => match remote_punch_ip(&answer) {
                    Some(ip) => self.predictor.plan(&p, ip, self.config.spray_k),
                    None => None,
                },
            }
        } else {
            None
        };

        // 打洞目标：spray 计划 或 对端候选（Srflx > Host，Relay 排除）。
        let targets: Vec<SocketAddr> = match &spray_plan {
            Some(plan) => plan
                .ports
                .iter()
                .map(|p| SocketAddr::new(plan.target_ip, *p))
                .collect(),
            None => punch_targets(&answer.candidates),
        };
        if targets.is_empty() {
            return self.fail(PunchFailReason::NoCandidates);
        }

        // Coordinated →(start_at 到达) Punching：协同开打，保证双向
        // 发包时间窗重叠。
        let wait_ms = offer.start_at_ms.saturating_sub(unix_ms());
        if wait_ms > 0 {
            std::thread::sleep(Duration::from_millis(wait_ms));
        }
        self.set_phase(PunchPhase::Punching);
        let payload = punch_payload(self.nonce);
        for (i, t) in targets.iter().enumerate() {
            if spray_plan.is_some() && i > 0 {
                // spray 限速：避免扫描行为。
                std::thread::sleep(Duration::from_millis(self.config.spray_interval_ms));
            }
            // 尽力而为：单个目标发送失败不中断整体。
            let _ = self.socket.send_punch(*t, &payload);
        }

        // Punching →(await_direct 成功) Validating →(确认迁移) Migrated。
        // await_direct 的成功即视为路径验证完成；本编排直接确认，
        // 真实 QUIC 路径验证由 driver 完成，迁移由组合根驱动。
        match self.socket.await_direct(self.config.punch_timeout) {
            Ok(addr) => {
                self.set_phase(PunchPhase::Validating);
                self.set_phase(PunchPhase::Migrated);
                self.stats.migrated = self.stats.migrated.saturating_add(1);
                PunchResult::Migrated { addr }
            }
            Err(e) if e.kind() == io::ErrorKind::TimedOut => self.fail(PunchFailReason::Timeout),
            Err(_) => self.fail(PunchFailReason::ChannelClosed),
        }
    }

    fn set_phase(&mut self, phase: PunchPhase) {
        self.phase = phase;
        self.stats.last_phase = phase;
    }

    fn fail(&mut self, reason: PunchFailReason) -> PunchResult {
        self.set_phase(PunchPhase::Failed(reason));
        match reason {
            PunchFailReason::Timeout => {
                self.stats.failed_timeout = self.stats.failed_timeout.saturating_add(1)
            }
            PunchFailReason::UnpredictableSymmetric => {
                self.stats.failed_unpredictable = self.stats.failed_unpredictable.saturating_add(1)
            }
            PunchFailReason::NoCandidates | PunchFailReason::ChannelClosed => {}
        }
        PunchResult::StayedOnRelay { reason }
    }
}
