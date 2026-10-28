//! 节点优雅退出（内存骨架，注入逻辑时钟）。
//!
//! 本模块是 v9 CLI 产品线运行时（frozen）的节点下线状态机骨架：
//! - **配置**：`ExitConfig` 持有宽限期 / 是否通知对端 / 是否等待流量排空；
//! - **状态**：`ExitState` 四态（Active / Draining / Exiting / Exited）；
//! - **协调器**：`GracefulExit` 维护当前状态与已通知对端列表，按注入时间推进状态机；
//! - **转移规则**：
//!   - `Active --begin_draining--> Draining`（记录 drain 起始时间）；
//!   - `Draining --wait_for_drain 且仍有连接且未到宽限期--> 仍 Draining`；
//!   - `Draining --连接排空或宽限期超时--> Exiting`；
//!   - `Exiting --advance--> Exited`。
//!
//! 边界（PRODUCT §12-graceful-exit 冻结）：
//! - 纯内存、纯同步、纯函数骨架；时间由调用方经 `now_ms` 注入，本模块不读真实墙钟；
//! - 状态推进只看注入的 `active_connections` 与 `now_ms`，不真实等待 I/O；
//! - 已进入终态（Exiting / Exited）后不再回退；
//! - 真实网络通知对端 / 真实 drain 等待线程留 TODO。
//!
//! TODO（真实下线集成，非本骨架范围）：
//! - 按 `grace_period_ms` 起一个有 Owner 的定时任务（CancellationToken + JoinSet）；
//! - 用真实 I/O 向对端发送再见帧（peer 下线通知），并等待对端 ACK；
//! - 阻塞新会话接入，等待既有连接自然排空或超时强制关闭；
//! - 把最终 Exited 事件反馈给多跳路由 / 健康检查，摘除本节点。
//!
//! 错误面独立：`GracefulExitError` 是本模块自有类型化 enum，不以 panic / 日志代替。

use std::fmt;

// ---------- 错误 ----------

/// 优雅退出相关结构化错误（delivery 层自有错误面，类型化）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GracefulExitError {
    /// 配置非法（如 grace_period_ms=0）。
    InvalidConfig(String),
    /// 再见帧 wire 格式非法（截断 / 魔错 / 长度不符 / UTF-8 解码失败）。
    InvalidFrame(String),
}

impl fmt::Display for GracefulExitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(msg) => {
                write!(f, "GRACEFUL_EXIT_INVALID_CONFIG: {msg}")
            }
            Self::InvalidFrame(msg) => {
                write!(f, "GRACEFUL_EXIT_INVALID_FRAME: {msg}")
            }
        }
    }
}

impl std::error::Error for GracefulExitError {}

// ---------- 退出状态 ----------

/// 节点退出四态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitState {
    /// 正常服务中，未开始下线。
    Active,
    /// 正在排空：不再接受新会话，等待既有流量结束。
    Draining,
    /// 即将退出：流量已排空或宽限期已到，正在做收尾。
    Exiting,
    /// 已退出：终态，不再接受任何工作。
    Exited,
}

impl ExitState {
    /// 返回稳定的小写字符串标识（供 JSON / 日志 / 断言使用）。
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Draining => "draining",
            Self::Exiting => "exiting",
            Self::Exited => "exited",
        }
    }
}

impl fmt::Display for ExitState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------- 配置 ----------

/// 优雅退出配置。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitConfig {
    /// 排空宽限期（毫秒，逻辑时钟；必须 > 0）。
    pub grace_period_ms: u64,
    /// 是否在进入 Draining 时通知对端 peer。
    pub notify_peers: bool,
    /// 是否等待连接排空（false 时进入 Draining 后立即推进到 Exiting）。
    pub wait_for_drain: bool,
}

impl ExitConfig {
    /// 构造配置并校验不变量。
    ///
    /// 校验：
    /// - `grace_period_ms > 0`。
    ///
    /// 非法返回 `GracefulExitError::InvalidConfig`。
    pub fn new(
        grace_period_ms: u64,
        notify_peers: bool,
        wait_for_drain: bool,
    ) -> Result<Self, GracefulExitError> {
        if grace_period_ms == 0 {
            return Err(GracefulExitError::InvalidConfig(
                "grace_period_ms must be > 0".to_string(),
            ));
        }
        Ok(Self {
            grace_period_ms,
            notify_peers,
            wait_for_drain,
        })
    }
}

// ---------- 协调器 ----------

/// 节点优雅退出协调器：维护退出状态机与已通知对端列表。
///
/// 纯内存、纯同步；时间由调用方经 `now_ms` 注入，便于单测与确定性 replay。
pub struct GracefulExit {
    cfg: ExitConfig,
    state: ExitState,
    /// 进入 Draining 时的注入逻辑时间（仅在 Draining 态有意义）。
    drain_start_ms: u64,
    /// 已通知过的对端 peer 名（仅当 `notify_peers=true` 时记录）。
    notified: Vec<String>,
}

impl GracefulExit {
    /// 用给定配置构造处于 `Active` 态的协调器。
    #[must_use]
    pub fn new(cfg: ExitConfig) -> Self {
        Self {
            cfg,
            state: ExitState::Active,
            drain_start_ms: 0,
            notified: Vec::new(),
        }
    }

    /// 开始排空：`Active -> Draining`，记录 drain 起始时间。
    ///
    /// 幂等：若已不在 `Active`（例如重复调用），保持当前状态不变。
    pub fn begin_draining(&mut self, now_ms: u64) -> ExitState {
        if self.state == ExitState::Active {
            self.state = ExitState::Draining;
            self.drain_start_ms = now_ms;
        }
        self.state
    }

    /// 通知一批对端 peer 本节点即将下线。
    ///
    /// 仅当配置 `notify_peers=true` 时才把 peer 名记入已通知列表并返回它们；
    /// 配置关闭时不记录、返回空列表（真实网络发送留 TODO）。
    pub fn notify_peers(&mut self, peers: &[&str]) -> Vec<String> {
        if !self.cfg.notify_peers {
            return Vec::new();
        }
        let mut recorded = Vec::new();
        for p in peers {
            let p = p.to_string();
            self.notified.push(p.clone());
            recorded.push(p);
        }
        recorded
    }

    /// 推进退出状态机，返回推进后的状态。
    ///
    /// 转移规则：
    /// - `Draining` 且 `wait_for_drain=true` 且 `active_connections > 0`
    ///   且尚未超过宽限期 → 仍为 `Draining`；
    /// - `Draining`：连接已排空（`active_connections == 0`）或宽限期已到 → `Exiting`；
    /// - `Exiting` → `Exited`；
    /// - 其它态（`Active` / `Exited`）保持不变。
    pub fn advance(&mut self, active_connections: u32, now_ms: u64) -> ExitState {
        match self.state {
            ExitState::Draining => {
                let within_grace =
                    now_ms.saturating_sub(self.drain_start_ms) < self.cfg.grace_period_ms;
                let still_busy = self.cfg.wait_for_drain && active_connections > 0;
                if still_busy && within_grace {
                    self.state
                } else {
                    self.state = ExitState::Exiting;
                    self.state
                }
            }
            ExitState::Exiting => {
                self.state = ExitState::Exited;
                self.state
            }
            ExitState::Active | ExitState::Exited => self.state,
        }
    }

    /// 当前退出状态（只读）。
    #[must_use]
    pub fn state(&self) -> ExitState {
        self.state
    }

    /// 已通知过的对端 peer 数量（只读快照）。
    #[must_use]
    pub fn notified_peer_count(&self) -> usize {
        self.notified.len()
    }
}

// === 12.40.5 再见帧 wire codec + 真实墙钟宽限期 drain ==========================

use std::thread;
use std::time::{Duration, Instant};

/// 再见帧类型标签线字节（ASCII 'G'）。
pub const GOODBYE_FRAME_TYPE: u8 = b'G';
/// 再见帧线格式版本。
pub const GOODBYE_FRAME_VERSION: u8 = 1;

/// 节点下线再见帧（版本化确定线格式）。
///
/// 线格式：`[version u8=1][type u8=0x47 'G'][peer_len u16 BE][peer_id utf8]
/// [reason_len u16 BE][reason utf8]`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoodbyeFrame {
    /// 线格式版本（当前恒为 1）。
    pub version: u8,
    /// 发送方 peer 标识。
    pub peer_id: String,
    /// 人可读下线原因。
    pub reason: String,
}

impl GoodbyeFrame {
    /// 用 peer_id / reason 构造版本 1 再见帧。
    #[must_use]
    pub fn new(peer_id: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            version: GOODBYE_FRAME_VERSION,
            peer_id: peer_id.into(),
            reason: reason.into(),
        }
    }

    /// 编码为确定线格式字节。
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let peer = self.peer_id.as_bytes();
        let reason = self.reason.as_bytes();
        let mut out = Vec::with_capacity(4 + peer.len() + 2 + reason.len());
        out.push(self.version);
        out.push(GOODBYE_FRAME_TYPE);
        out.extend_from_slice(&(peer.len() as u16).to_be_bytes());
        out.extend_from_slice(peer);
        out.extend_from_slice(&(reason.len() as u16).to_be_bytes());
        out.extend_from_slice(reason);
        out
    }
}

/// 解码再见帧；截断 / 魔错 / 长度不符 / 非 UTF-8 / 尾字节均报 `InvalidFrame`。
pub fn decode_goodbye(buf: &[u8]) -> Result<GoodbyeFrame, GracefulExitError> {
    if buf.len() < 4 {
        return Err(GracefulExitError::InvalidFrame(format!(
            "frame too short: {} bytes",
            buf.len()
        )));
    }
    let version = buf[0];
    if buf[1] != GOODBYE_FRAME_TYPE {
        return Err(GracefulExitError::InvalidFrame(format!(
            "bad type byte: 0x{:02x}",
            buf[1]
        )));
    }
    let peer_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    let mut idx = 4usize;
    if buf.len() < idx + peer_len + 2 {
        return Err(GracefulExitError::InvalidFrame(
            "truncated peer id".to_string(),
        ));
    }
    let peer = std::str::from_utf8(&buf[idx..idx + peer_len])
        .map_err(|_| GracefulExitError::InvalidFrame("peer id not utf-8".to_string()))?;
    idx += peer_len;
    let reason_len = u16::from_be_bytes([buf[idx], buf[idx + 1]]) as usize;
    idx += 2;
    if buf.len() < idx + reason_len {
        return Err(GracefulExitError::InvalidFrame(
            "truncated reason".to_string(),
        ));
    }
    let reason = std::str::from_utf8(&buf[idx..idx + reason_len])
        .map_err(|_| GracefulExitError::InvalidFrame("reason not utf-8".to_string()))?;
    idx += reason_len;
    if idx != buf.len() {
        return Err(GracefulExitError::InvalidFrame(format!(
            "trailing {} bytes",
            buf.len() - idx
        )));
    }
    Ok(GoodbyeFrame {
        version,
        peer_id: peer.to_string(),
        reason: reason.to_string(),
    })
}

impl GracefulExit {
    /// 真实墙钟宽限期 drain（PRODUCT §12.40.5）。
    ///
    /// 调用前应已 `begin_draining(0)`；本方法按约 20ms 轮询 `active()` 取活跃连接数，
    /// 喂给既有 `advance(active, now_ms)`：连接排空或超过 `grace_period_ms` 即推进到
    /// `Exiting`。返回最终状态（`Exiting` / `Exited`）。
    pub fn drain_real<F: Fn() -> u32>(&mut self, active: F) -> ExitState {
        let start = Instant::now();
        loop {
            let a = active();
            let now_ms = start.elapsed().as_millis() as u64;
            let st = self.advance(a, now_ms);
            if st != ExitState::Draining {
                return st;
            }
            if start.elapsed() >= Duration::from_millis(self.cfg.grace_period_ms) {
                // 宽限期已到：强制推进一次（now 远超 drain_start）。
                return self.advance(a, self.cfg.grace_period_ms + 1);
            }
            thread::sleep(Duration::from_millis(20));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(grace: u64, notify: bool, wait: bool) -> ExitConfig {
        ExitConfig::new(grace, notify, wait).expect("valid config")
    }

    #[test]
    fn config_accepts_valid_values() {
        let c = ExitConfig::new(1_000, true, true).expect("valid");
        assert_eq!(c.grace_period_ms, 1_000);
        assert!(c.notify_peers);
        assert!(c.wait_for_drain);
    }

    #[test]
    fn config_rejects_zero_grace() {
        let err = ExitConfig::new(0, true, true).expect_err("grace must be > 0");
        assert!(matches!(err, GracefulExitError::InvalidConfig(_)));
    }

    #[test]
    fn starts_active() {
        let g = GracefulExit::new(cfg(1_000, true, true));
        assert_eq!(g.state(), ExitState::Active);
    }

    #[test]
    fn begin_draining_moves_to_draining() {
        let mut g = GracefulExit::new(cfg(1_000, true, true));
        assert_eq!(g.begin_draining(0), ExitState::Draining);
        assert_eq!(g.state(), ExitState::Draining);
    }

    #[test]
    fn begin_draining_is_idempotent_when_already_draining() {
        let mut g = GracefulExit::new(cfg(1_000, true, true));
        g.begin_draining(0);
        // 重复 begin_draining 不应重置 drain_start。
        assert_eq!(g.begin_draining(500), ExitState::Draining);
        // 仍以 t=0 为 drain_start：t=999 仍在宽限期内。
        let s = g.advance(5, 999);
        assert_eq!(s, ExitState::Draining);
    }

    #[test]
    fn stays_draining_while_busy_within_grace() {
        let mut g = GracefulExit::new(cfg(1_000, true, true));
        g.begin_draining(0);
        let s = g.advance(5, 500);
        assert_eq!(s, ExitState::Draining);
    }

    #[test]
    fn moves_to_exiting_when_drained() {
        let mut g = GracefulExit::new(cfg(1_000, true, true));
        g.begin_draining(0);
        let s = g.advance(0, 500);
        assert_eq!(s, ExitState::Exiting);
    }

    #[test]
    fn timeout_forces_exiting_even_if_busy() {
        let mut g = GracefulExit::new(cfg(1_000, true, true));
        g.begin_draining(0);
        // 仍有连接，但已超过宽限期 → 强制 Exiting。
        let s = g.advance(5, 2_000);
        assert_eq!(s, ExitState::Exiting);
    }

    #[test]
    fn exiting_advances_to_exited() {
        let mut g = GracefulExit::new(cfg(1_000, true, true));
        g.begin_draining(0);
        g.advance(0, 100);
        let s = g.advance(0, 200);
        assert_eq!(s, ExitState::Exited);
        assert_eq!(g.state(), ExitState::Exited);
    }

    #[test]
    fn exited_is_terminal() {
        let mut g = GracefulExit::new(cfg(1_000, true, true));
        g.begin_draining(0);
        g.advance(0, 100);
        g.advance(0, 200);
        let s = g.advance(0, 300);
        assert_eq!(s, ExitState::Exited);
    }

    #[test]
    fn wait_for_drain_false_skips_drain_wait() {
        let mut g = GracefulExit::new(cfg(1_000, true, false));
        g.begin_draining(0);
        // 即使仍有连接且在宽限期内，也立即 Exiting。
        let s = g.advance(9, 10);
        assert_eq!(s, ExitState::Exiting);
    }

    #[test]
    fn notify_peers_records_when_enabled() {
        let mut g = GracefulExit::new(cfg(1_000, true, true));
        let recorded = g.notify_peers(&["peer-a", "peer-b"]);
        assert_eq!(recorded, vec!["peer-a".to_string(), "peer-b".to_string()]);
        assert_eq!(g.notified_peer_count(), 2);
    }

    #[test]
    fn notify_peers_skipped_when_disabled() {
        let mut g = GracefulExit::new(cfg(1_000, false, true));
        let recorded = g.notify_peers(&["peer-a", "peer-b"]);
        assert!(recorded.is_empty());
        assert_eq!(g.notified_peer_count(), 0);
    }

    #[test]
    fn full_transition_active_to_exited() {
        let mut g = GracefulExit::new(cfg(1_000, true, true));
        assert_eq!(g.state(), ExitState::Active);
        g.begin_draining(0);
        assert_eq!(g.advance(3, 100), ExitState::Draining);
        assert_eq!(g.advance(0, 200), ExitState::Exiting);
        assert_eq!(g.advance(0, 300), ExitState::Exited);
    }

    #[test]
    fn exit_state_as_str_and_display() {
        assert_eq!(ExitState::Active.as_str(), "active");
        assert_eq!(ExitState::Draining.as_str(), "draining");
        assert_eq!(ExitState::Exiting.as_str(), "exiting");
        assert_eq!(ExitState::Exited.as_str(), "exited");
        assert_eq!(ExitState::Exited.to_string(), "exited");
    }

    #[test]
    fn error_display_is_structured() {
        let e = GracefulExitError::InvalidConfig("bad grace".into());
        assert!(e.to_string().contains("bad grace"));
    }

    fn valid_frame() -> Vec<u8> {
        GoodbyeFrame::new("peer-a", "shutting-down").encode()
    }

    #[test]
    fn goodbye_roundtrip() {
        let frame = GoodbyeFrame::new("peer-a", "shutting-down");
        let decoded = decode_goodbye(&frame.encode()).expect("decode");
        assert_eq!(decoded, frame);
        assert_eq!(decoded.version, 1);
    }

    #[test]
    fn decode_goodbye_error_matrix() {
        let base = valid_frame();
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("empty", vec![]),
            ("too-short-3", vec![1, b'G', 0x00]),
            ("bad-type", {
                let mut b = base.clone();
                b[1] = b'X';
                b
            }),
            ("truncated-peer", base[..6].to_vec()),
            ("truncated-reason", base[..(base.len() - 3)].to_vec()),
            ("trailing-bytes", {
                let mut b = base.clone();
                b.push(0x00);
                b
            }),
        ];
        for (name, buf) in cases {
            let err = decode_goodbye(&buf).expect_err(&format!("{name} should err"));
            assert!(
                matches!(err, GracefulExitError::InvalidFrame(_)),
                "{name}: expected InvalidFrame, got {err:?}"
            );
        }
    }

    #[test]
    fn decode_goodbye_non_utf8_peer() {
        // version=1, type='G', peer_len=2, peer=[0xff,0xfe] (invalid utf8)
        let buf = [1u8, b'G', 0x00, 0x02, 0xff, 0xfe, 0x00, 0x00];
        let err = decode_goodbye(&buf).expect_err("non-utf8 peer");
        assert!(matches!(err, GracefulExitError::InvalidFrame(_)));
    }

    #[test]
    fn decode_goodbye_non_utf8_reason() {
        // peer="a", reason=[0xff]
        let buf = [1u8, b'G', 0x00, 0x01, b'a', 0x00, 0x01, 0xff];
        let err = decode_goodbye(&buf).expect_err("non-utf8 reason");
        assert!(matches!(err, GracefulExitError::InvalidFrame(_)));
    }
}
