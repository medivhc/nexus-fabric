//! NAT 穿透打洞编排核心（portable core，std-only）。
//!
//! 冻结合同：`docs/foundation/NAT-TRAVERSAL-CONTRACT.md` v1.1。
//!
//! 本 crate 只做编排：候选地址（P1）、信令 v1/v2 编解码（P2）、
//! 打洞状态机（P4）、可观测（P7）。真实 QUIC 建连、路径选路由
//! 组合根经注入 trait 装配；时间一律由 `PunchClock` 注入。

pub mod candidate;
pub mod predict;
pub mod signal;

pub use candidate::{CandidateKind, LocalCandidates, PunchCandidate, punch_targets};
pub use predict::{DefaultPredictor, PredictionPlan, default_plan};
pub use signal::{
    MAX_CANDIDATES, PredictionHint, PunchAnswer, PunchOffer, SIGNAL_VERSION, SignalError,
    decode_answer, decode_answer_v1, decode_offer, decode_offer_v1, encode_answer,
    encode_answer_v1, encode_offer, encode_offer_v1,
};

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::Duration;

use nexus_connectivity::nat::NatType;

// ---------------------------------------------------------------------------
// P4 相关类型
// ---------------------------------------------------------------------------

/// 对端身份。与 `nexus-fabric::PeerId` 同表示（`[u8; 32]` ed25519 公钥）。
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

impl PunchPhase {
    pub fn as_str(&self) -> &'static str {
        match self {
            PunchPhase::Idle => "idle",
            PunchPhase::OfferSent => "offer_sent",
            PunchPhase::Coordinated => "coordinated",
            PunchPhase::Punching => "punching",
            PunchPhase::Validating => "validating",
            PunchPhase::Migrated => "migrated",
            PunchPhase::Failed(reason) => reason.as_str(),
        }
    }
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

impl PunchFailReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            PunchFailReason::Timeout => "timeout",
            PunchFailReason::UnpredictableSymmetric => "unpredictable_symmetric",
            PunchFailReason::NoCandidates => "no_candidates",
            PunchFailReason::ChannelClosed => "channel_closed",
        }
    }
}

/// 注入时钟：core 不直接读系统时间。
pub trait PunchClock: Send + Sync {
    /// 单调毫秒；只用于时长/超时。
    fn now_ms(&self) -> u64;
    /// 墙钟毫秒（Unix epoch）；只用于 `start_at_ms` 诊断。
    fn wall_ms(&self) -> u64;
    /// 阻塞到 `deadline_ms`（虚拟时钟可立即推进并返回）。
    fn sleep_until_ms(&self, deadline_ms: u64);
    /// 阻塞 `ms` 毫秒（虚拟时钟可立即推进）。
    fn sleep_ms(&self, ms: u64);
}

/// 信令通道（P4）：承载 offer/answer 的可靠通道。
pub trait PunchChannel: Send + Sync {
    fn send_offer(&self, offer: &PunchOffer) -> io::Result<()>;
    /// 等待 answer；超时 → `Err` 且 kind 为 `TimedOut`。
    fn recv_answer(&self, timeout: Duration) -> io::Result<PunchAnswer>;
}

/// 打洞 socket（P4）：**必须**是 QUIC 连接所在的同一个 UDP socket。
pub trait PunchSocket: Send + Sync {
    /// 从同一 UDP socket 向目标发打洞负载（生产 payload 被忽略，
    /// 真正打洞包是 `Driver::connect` 的 QUIC Initial）。
    fn send_punch(&self, target: SocketAddr, payload: &[u8]) -> io::Result<()>;
    /// 等待路径验证完成，返回验证通过的直连地址；超时 → `Err(TimedOut)`。
    fn await_direct(&self, timeout: Duration) -> io::Result<SocketAddr>;
}

/// 打洞配置（v1.1 冻结字段与默认值）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PunchConfig {
    pub punch_timeout: Duration,
    pub coord_skew_ms: u64,
    pub spray_k: u8,
    pub spray_interval_ms: u64,
    pub spray_time_budget: Duration,
    pub repunch_interval: Duration,
    pub repunch_jitter: Duration,
    pub prediction_samples: u8,
    pub max_sample_age: Duration,
    pub max_stable_delta: u16,
    pub mapping_probe_count: u8,
    pub mapping_probe_interval_ms: u64,
}

impl Default for PunchConfig {
    fn default() -> Self {
        Self {
            punch_timeout: Duration::from_secs(5),
            coord_skew_ms: 200,
            spray_k: 16,
            spray_interval_ms: 50,
            spray_time_budget: Duration::from_secs(3),
            repunch_interval: Duration::from_secs(300),
            repunch_jitter: Duration::ZERO,
            prediction_samples: 3,
            max_sample_age: Duration::from_secs(900),
            max_stable_delta: 8,
            mapping_probe_count: 3,
            mapping_probe_interval_ms: 50,
        }
    }
}

impl PunchConfig {
    /// Internal test-only config (production goes through `PunchSection::validate`).
    #[cfg(any(test, feature = "test-config"))]
    pub fn new_test_config() -> Self {
        Self {
            repunch_interval: Duration::from_secs(2),
            ..Self::default()
        }
    }

    pub fn validate(&self) -> Result<(), PunchConfigError> {
        let ranges: [(&'static str, i64, i64, i64); 12] = [
            (
                "punch_timeout_ms",
                self.punch_timeout.as_millis() as i64,
                500,
                30_000,
            ),
            ("coord_skew_ms", self.coord_skew_ms as i64, 0, 2_000),
            ("spray_k", i64::from(self.spray_k), 1, 32),
            ("spray_interval_ms", self.spray_interval_ms as i64, 10, 500),
            (
                "spray_time_budget_ms",
                self.spray_time_budget.as_millis() as i64,
                500,
                10_000,
            ),
            (
                "repunch_interval_sec",
                self.repunch_interval.as_secs() as i64,
                60,
                3_600,
            ),
            (
                "repunch_jitter_sec",
                self.repunch_jitter.as_secs() as i64,
                0,
                60,
            ),
            (
                "prediction_samples",
                i64::from(self.prediction_samples),
                3,
                8,
            ),
            (
                "max_sample_age_sec",
                self.max_sample_age.as_secs() as i64,
                60,
                3_600,
            ),
            ("max_stable_delta", i64::from(self.max_stable_delta), 1, 64),
            (
                "mapping_probe_count",
                i64::from(self.mapping_probe_count),
                1,
                5,
            ),
            (
                "mapping_probe_interval_ms",
                self.mapping_probe_interval_ms as i64,
                10,
                500,
            ),
        ];
        for (field, value, min, max) in ranges {
            if value < min || value > max {
                return Err(PunchConfigError::OutOfRange {
                    field,
                    value,
                    min,
                    max,
                });
            }
        }
        let spray_window = 2 * u64::from(self.spray_k) * self.spray_interval_ms;
        if self.spray_time_budget.as_millis() as u64 > self.punch_timeout.as_millis() as u64 {
            return Err(PunchConfigError::InvalidCombination {
                field: "spray_time_budget_ms",
                reason: "spray time budget cannot exceed punch_timeout_ms",
            });
        }
        if spray_window > self.spray_time_budget.as_millis() as u64 {
            return Err(PunchConfigError::InvalidCombination {
                field: "spray_interval_ms",
                reason: "spray window cannot fit in spray_time_budget_ms",
            });
        }
        Ok(())
    }
}

/// 配置校验错误（edge 配置映射）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PunchConfigError {
    OutOfRange {
        field: &'static str,
        value: i64,
        min: i64,
        max: i64,
    },
    InvalidCombination {
        field: &'static str,
        reason: &'static str,
    },
}

impl std::fmt::Display for PunchConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PunchConfigError::OutOfRange {
                field,
                value,
                min,
                max,
            } => write!(f, "{field}={value} out of range [{min}, {max}]"),
            PunchConfigError::InvalidCombination { field, reason } => {
                write!(f, "invalid combination at {field}: {reason}")
            }
        }
    }
}

impl std::error::Error for PunchConfigError {}

/// `run()` 的终态结果（Exactly-One Terminal Outcome）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PunchResult {
    /// 打洞成功：**新直连**握手完成（组合根负责登记/选路；CID 可变）。
    Migrated { addr: SocketAddr },
    /// 留在中继上（打洞失败/放弃）。
    StayedOnRelay { reason: PunchFailReason },
}

// ---------------------------------------------------------------------------
// P3 可预测性检测
// ---------------------------------------------------------------------------

/// STUN 端口采样（带 provenance）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortSample {
    pub port: u16,
    pub at_ms: u64,
    pub target: SocketAddr,
    pub observed_from: SocketAddr,
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
pub trait PunchPredictor: Send + Sync {
    /// 至少 3 个样本；Δ 不稳定 → `Unpredictable`。
    fn assess(&self, samples: &[PortSample]) -> Predictability;
    /// 有界：`ports.len() <= 2*K+1`，K = `config.spray_k`（上限 32）。
    fn plan(&self, p: &Predictability, target_ip: IpAddr, k: u8) -> Option<SprayPlan>;
}

/// 空预测器：恒 `Unpredictable`（自身测试用）。
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
// P5 三类路径竞速（SUPERSEDED；仅保留类型与可观测钩子）
// ---------------------------------------------------------------------------

/// 路径类别（冻结；映射到 `nexus-path::PathKind`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RaceClass {
    DirectP2P,
    TurnRelay,
    PeerRelay,
}

/// 打洞成功后向路径层上报候选（**可观测钩子**；不参与选路）。
pub trait PunchRaceFeed: Send + Sync {
    fn report_direct_candidate(&self, peer: PeerId, addr: SocketAddr, rtt_ms: u64, loss_01: f64);
}

/// 空登记器。
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

/// 打洞统计（`PunchSession::stats()`，v1.1 12 字段）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PunchStats {
    pub attempts: u64,
    pub migrated: u64,
    pub failed_timeout: u64,
    pub failed_unpredictable: u64,
    pub failed_no_candidates: u64,
    pub failed_channel_closed: u64,
    pub spray_sends: u64,
    pub spray_skipped: u64,
    pub mapping_probe_sends: u64,
    pub prediction_hints_sent: u64,
    pub prediction_hints_recv: u64,
    pub last_phase: PunchPhase,
}

// ---------------------------------------------------------------------------
// P4 打洞编排状态机
// ---------------------------------------------------------------------------

/// 打洞负载标记（test-only；production `PunchSocket` 忽略 payload）。
const PUNCH_MAGIC: [u8; 8] = *b"NXPNCH01";

static NONCE_COUNTER: AtomicU64 = AtomicU64::new(1);

fn fresh_nonce(now_ms: u64) -> u64 {
    let c = NONCE_COUNTER.fetch_add(1, Ordering::Relaxed);
    now_ms.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(c)
}

fn punch_payload(nonce: u64) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[..8].copy_from_slice(&PUNCH_MAGIC);
    b[8..].copy_from_slice(&nonce.to_be_bytes());
    b
}

/// 对端候选中的首个 Srflx 地址。
fn remote_reflexive(answer: &PunchAnswer) -> Option<SocketAddr> {
    answer
        .candidates
        .iter()
        .find(|c| c.kind == CandidateKind::Srflx)
        .or_else(|| answer.candidates.first())
        .map(|c| c.addr)
}

/// 打洞编排会话（发起方）。
pub struct PunchSession {
    peer: PeerId,
    local: LocalCandidates,
    remote_nat: NatType,
    samples: Vec<PortSample>,
    config: PunchConfig,
    channel: Arc<dyn PunchChannel>,
    socket: Arc<dyn PunchSocket>,
    predictor: Arc<dyn PunchPredictor>,
    clock: Arc<dyn PunchClock>,
    nonce: u64,
    phase: PunchPhase,
    stats: PunchStats,
}

impl PunchSession {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        peer: PeerId,
        local: LocalCandidates,
        remote_nat: NatType,
        samples: Vec<PortSample>,
        config: PunchConfig,
        channel: Arc<dyn PunchChannel>,
        socket: Arc<dyn PunchSocket>,
        predictor: Arc<dyn PunchPredictor>,
        clock: Arc<dyn PunchClock>,
    ) -> Self {
        let mut config = config;
        if config.spray_k > 32 {
            // m-4 (review): previously a silent clamp; the daemon log now
            // carries the event on the [nat-punch] channel (stderr, like
            // the other [nat-*] daemon logs). Diagnostic only: it does
            // not touch the data path, time, or randomness.
            eprintln!(
                "[nat-punch] WARN: config_clamped spray_k {} -> 32",
                config.spray_k
            );
        }
        config.spray_k = config.spray_k.min(32);
        let nonce = fresh_nonce(clock.now_ms());
        Self {
            peer,
            local,
            remote_nat,
            samples,
            config,
            channel,
            socket,
            predictor,
            clock,
            nonce,
            phase: PunchPhase::Idle,
            stats: PunchStats::default(),
        }
    }

    pub fn phase(&self) -> PunchPhase {
        self.phase
    }

    /// Effective config (post-clamp); used by the m-4 regression test.
    pub fn config(&self) -> &PunchConfig {
        &self.config
    }
    pub fn peer(&self) -> PeerId {
        self.peer
    }
    pub fn stats(&self) -> PunchStats {
        self.stats
    }

    pub fn set_local(&mut self, local: LocalCandidates, samples: Vec<PortSample>) {
        self.local = local;
        self.samples = samples;
    }

    pub fn set_samples(&mut self, samples: Vec<PortSample>) {
        self.samples = samples;
    }

    fn remaining(&self, deadline_ms: u64) -> u64 {
        deadline_ms.saturating_sub(self.clock.now_ms())
    }

    /// 过滤过期/端口 0 样本后才交给 predictor；同一 `observed_from` 由组合根保证。
    fn usable_samples(&self) -> Vec<PortSample> {
        let now = self.clock.now_ms();
        let max_age = self.config.max_sample_age.as_millis() as u64;
        self.samples
            .iter()
            .copied()
            .filter(|s| s.port != 0 && now.saturating_sub(s.at_ms) <= max_age)
            .collect()
    }

    fn prediction_hint(
        &self,
        verdict: &Predictability,
        sample_count: usize,
    ) -> Option<PredictionHint> {
        match *verdict {
            Predictability::Predictable { base_port, delta }
                if sample_count >= usize::from(self.config.prediction_samples) =>
            {
                Some(PredictionHint {
                    base_port,
                    delta,
                    samples: sample_count.min(8) as u8,
                })
            }
            _ => None,
        }
    }

    /// 阻塞执行完整编排。
    pub fn run(&mut self) -> PunchResult {
        self.stats.attempts = self.stats.attempts.saturating_add(1);
        let deadline = self
            .clock
            .now_ms()
            .saturating_add(self.config.punch_timeout.as_millis() as u64);

        if !self.local.has_punchable() {
            return self.fail(PunchFailReason::NoCandidates);
        }

        let usable = self.usable_samples();
        // One `assess` per run: the same verdict feeds the offer hint and the
        // local-symmetry gate (two calls could disagree).
        let verdict = self.predictor.assess(&usable);
        let prediction = self.prediction_hint(&verdict, usable.len());
        let offer = PunchOffer {
            version: SIGNAL_VERSION,
            nonce: self.nonce,
            candidates: self.local.ordered(),
            nat_type: self.local.nat_type,
            start_at_ms: self
                .clock
                .wall_ms()
                .saturating_add(self.config.coord_skew_ms),
            prediction,
        };
        if prediction.is_some() {
            self.stats.prediction_hints_sent = self.stats.prediction_hints_sent.saturating_add(1);
        }
        if self.channel.send_offer(&offer).is_err() {
            return self.fail(PunchFailReason::ChannelClosed);
        }
        self.set_phase(PunchPhase::OfferSent);

        let answer = loop {
            let remain = self.remaining(deadline);
            if remain == 0 {
                return self.fail(PunchFailReason::Timeout);
            }
            match self.channel.recv_answer(Duration::from_millis(remain)) {
                Ok(a) if a.nonce == offer.nonce => break a,
                Ok(_) => continue,
                Err(e) if e.kind() == io::ErrorKind::TimedOut => {
                    return self.fail(PunchFailReason::Timeout);
                }
                Err(_) => return self.fail(PunchFailReason::ChannelClosed),
            }
        };
        if answer.prediction.is_some() {
            self.stats.prediction_hints_recv = self.stats.prediction_hints_recv.saturating_add(1);
        }
        self.set_phase(PunchPhase::Coordinated);

        let local_sym = self.local.nat_type == NatType::Symmetric;
        let remote_sym = self.remote_nat == NatType::Symmetric;

        if local_sym && remote_sym {
            return self.fail(PunchFailReason::UnpredictableSymmetric);
        }

        let plan = if local_sym {
            // F-V5-1 (R2-1): symmetric -> cone is only worth probing when the
            // local mapping is predictable. Otherwise the cone side has no
            // usable hint, the probes cannot open a path, and AC-5 requires
            // zero punch traffic. Fail closed before building `SendPlan`.
            if !matches!(verdict, Predictability::Predictable { .. }) {
                return self.fail(PunchFailReason::UnpredictableSymmetric);
            }
            // symmetric -> cone: bounded mapping probes, never spray.
            let Some(target) = remote_reflexive(&answer) else {
                return self.fail(PunchFailReason::NoCandidates);
            };
            SendPlan::Probes {
                target,
                count: self.config.mapping_probe_count.max(1),
                interval_ms: self.config.mapping_probe_interval_ms,
            }
        } else if remote_sym {
            // cone -> symmetric: only with a hint; single reflexive IP spray.
            let Some(hint) = answer.prediction else {
                return self.fail(PunchFailReason::UnpredictableSymmetric);
            };
            let Some(target) = remote_reflexive(&answer) else {
                return self.fail(PunchFailReason::NoCandidates);
            };
            let p = Predictability::Predictable {
                base_port: hint.base_port,
                delta: hint.delta,
            };
            match self.predictor.plan(&p, target.ip(), self.config.spray_k) {
                Some(spray) => SendPlan::Spray {
                    target_ip: spray.target_ip,
                    ports: spray.ports,
                },
                None => return self.fail(PunchFailReason::UnpredictableSymmetric),
            }
        } else {
            let targets = punch_targets(&answer.candidates);
            if targets.is_empty() {
                return self.fail(PunchFailReason::NoCandidates);
            }
            SendPlan::Normal { targets }
        };

        // Coordinated -> Punching：协调等待（不使用 start_at_ms 做等待）。
        let coord_deadline = self
            .clock
            .now_ms()
            .saturating_add(self.config.coord_skew_ms);
        self.clock.sleep_until_ms(coord_deadline);
        self.set_phase(PunchPhase::Punching);

        let payload = punch_payload(self.nonce);
        match plan {
            SendPlan::Normal { targets } => {
                for t in targets {
                    let _ = self.socket.send_punch(t, &payload);
                }
            }
            SendPlan::Probes {
                target,
                count,
                interval_ms,
            } => {
                for i in 0..count {
                    if i > 0 {
                        self.clock.sleep_ms(interval_ms);
                    }
                    if self.socket.send_punch(target, &payload).is_ok() {
                        self.stats.mapping_probe_sends =
                            self.stats.mapping_probe_sends.saturating_add(1);
                    }
                }
            }
            SendPlan::Spray { target_ip, ports } => {
                let spray_budget = self
                    .config
                    .spray_time_budget
                    .as_millis()
                    .min(self.remaining(deadline).into()) as u64;
                let spray_deadline = self.clock.now_ms().saturating_add(spray_budget);
                let total = ports.len() as u64;
                let mut sent = 0u64;
                for (i, port) in ports.iter().enumerate() {
                    if i > 0 {
                        let next = self
                            .clock
                            .now_ms()
                            .saturating_add(self.config.spray_interval_ms);
                        if next > spray_deadline {
                            break;
                        }
                        self.clock.sleep_ms(self.config.spray_interval_ms);
                    }
                    let addr = SocketAddr::new(target_ip, *port);
                    if self.socket.send_punch(addr, &payload).is_ok() {
                        sent += 1;
                        self.stats.spray_sends = self.stats.spray_sends.saturating_add(1);
                    }
                }
                self.stats.spray_skipped = self
                    .stats
                    .spray_skipped
                    .saturating_add(total.saturating_sub(sent));
            }
        }

        let remain = self.remaining(deadline);
        if remain == 0 {
            return self.fail(PunchFailReason::Timeout);
        }
        match self.socket.await_direct(Duration::from_millis(remain)) {
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
            PunchFailReason::NoCandidates => {
                self.stats.failed_no_candidates = self.stats.failed_no_candidates.saturating_add(1)
            }
            PunchFailReason::ChannelClosed => {
                self.stats.failed_channel_closed =
                    self.stats.failed_channel_closed.saturating_add(1)
            }
        }
        PunchResult::StayedOnRelay { reason }
    }
}

enum SendPlan {
    Normal {
        targets: Vec<SocketAddr>,
    },
    Probes {
        target: SocketAddr,
        count: u8,
        interval_ms: u64,
    },
    Spray {
        target_ip: IpAddr,
        ports: Vec<u16>,
    },
}
