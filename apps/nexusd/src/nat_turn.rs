//! TURN 分配生命周期管理（NAT switching daemon activation，AC1/AC3）。
//!
//! daemon 侧把 `nexus_turn::client::TurnClient` 包装成有状态的生命周期对象：
//!
//! - 懒初始化 Allocate（401 质询由 `TurnClient` 内部处理；失败 → WARN + `Disabled`
//!   降级，回退 Peer Relay，中继照常工作）；
//! - 按配置的 `refresh_interval_sec` 在 LIFETIME 过期前 60s 发送 Refresh 保活，
//!   把 TURN 分配保留为 warm backup（D4：打洞迁移后不立即释放）；
//! - 收到 438 Stale Nonce 时自动重试（重新 Allocate 获取新 Nonce）；
//! - 连续 3 次 Refresh 失败 → 判定 warm backup 死亡，释放 Allocation 资源，
//!   记录 WARN，流量保持在当前路径；
//! - 状态机：`Disabled → Allocating → Active → Refreshing → Expired → Disabled`。
//!
//! 可测试性：`TurnHandle` trait 把真实 `TurnClient` 与测试替身分成两个独立变化
//! 维度（Deletion Test：真实 TURN 服务器与离线 mock 都需要被策略层驱动）。

//! Tech debt (W-1)：本模块直接使用 `std::time::Instant::now()` 做 Refresh
//! 节奏调度。DESIGN.md §11 决议 6 的时钟注入约束针对协议 core crate；本模块是
//! daemon-edge 的生命周期管理（非协议 core），且时间为单调时钟（无墙钟语义）。
//! 若工作区后续统一引入 `Clock` trait（已分流为待决策项），本模块随之迁移。

#![allow(dead_code)]

use std::io;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use nexus_turn::client::{TurnClient, TurnCredentials};

use crate::config::TurnSection;

/// LIFETIME 过期前多少秒触发 Refresh（AC3）。
pub const REFRESH_MARGIN: Duration = Duration::from_secs(60);
/// 连续多少次 Refresh 失败判定 warm backup 死亡（AC3）。
pub const MAX_REFRESH_FAILURES: u32 = 3;
/// Refresh 失败后的重试间隔（非 438 错误，快速重试）。
const REFRESH_RETRY_DELAY: Duration = Duration::from_secs(1);
/// 默认分配生命周期（`nexus_turn` 请求的 LIFETIME）。
const DEFAULT_LIFETIME: Duration = Duration::from_secs(600);

/// TURN 生命周期状态（AC3 状态机）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TurnState {
    /// TURN 功能禁用（未配置，或 Allocate 认证失败/超时后降级）。
    Disabled,
    /// Allocate 进行中（或等待首次分配）。
    Allocating,
    /// Allocation 有效，作为 warm backup 保活中。
    Active,
    /// 正在发送 Refresh。
    Refreshing,
    /// 连续 3 次 Refresh 失败，warm backup 已判定死亡，资源已释放。
    Expired,
}

impl std::fmt::Display for TurnState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TurnState::Disabled => f.write_str("disabled"),
            TurnState::Allocating => f.write_str("allocating"),
            TurnState::Active => f.write_str("active"),
            TurnState::Refreshing => f.write_str("refreshing"),
            TurnState::Expired => f.write_str("expired"),
        }
    }
}

/// 运维可见的 TURN 健康态（内部 `TurnState` 的投影；区分「未配置」与「降级」）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TurnHealth {
    /// 无 `[network.turn]`。
    Unconfigured,
    /// 已配置，尚未完成首次分配。
    Allocating,
    /// 分配有效（含 Refreshing）。
    Active,
    /// 3-strike 后 warm backup 死亡。
    Expired,
    /// 已配置但分配失败（bind/allocate/server 非法）。
    Degraded,
}

impl TurnHealth {
    pub fn as_str(self) -> &'static str {
        match self {
            TurnHealth::Unconfigured => "unconfigured",
            TurnHealth::Allocating => "allocating",
            TurnHealth::Active => "active",
            TurnHealth::Expired => "expired",
            TurnHealth::Degraded => "degraded",
        }
    }
}

/// 降级原因（仅 `health() == Degraded` 时非 None；值域固定）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TurnFailure {
    /// bind 失败（`AddrNotAvailable|AddrInUse|PermissionDenied|InvalidInput`）。
    Bind,
    /// 其余 allocate/refresh 网络错误。
    Allocate,
    /// `[network.turn].server` 不可解析（构造期）。
    Server,
}

impl TurnFailure {
    pub fn as_str(self) -> &'static str {
        match self {
            TurnFailure::Bind => "bind_failed",
            TurnFailure::Allocate => "allocate_failed",
            TurnFailure::Server => "server_invalid",
        }
    }
}

/// `refresh_if_needed` 的结果（可观测）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshOutcome {
    /// 未到刷新时间（或状态不允许）。
    NotDue,
    /// 已成功刷新（warm backup 续租）。
    Refreshed,
    /// 收到 438 Stale Nonce，已携带新 Nonce 自动重试成功。
    StaleNonceRetried,
    /// 438 重试中的重新 Allocate 失败 → 已走分配失败路径（Disabled 降级）。
    ReallocateFailed,
    /// 刷新失败（参数为当前连续失败次数）。
    Failed(u32),
    /// 管理器处于非活动状态（Disabled/Expired/未分配）。
    Inactive,
}

/// TURN 管理器错误（类型化，不 panic）。
#[derive(Debug)]
pub enum TurnError {
    /// TURN 未配置或已降级禁用。
    Unconfigured,
    /// 配置无效（如 server 地址不可解析）。
    InvalidConfig(String),
    /// Allocate / Refresh 底层 I/O 错误。
    Io(io::Error),
}

impl std::fmt::Display for TurnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TurnError::Unconfigured => f.write_str("turn unconfigured"),
            TurnError::InvalidConfig(s) => write!(f, "turn invalid config: {s}"),
            TurnError::Io(e) => write!(f, "turn io error: {e}"),
        }
    }
}

impl std::error::Error for TurnError {}

/// TURN 客户端句柄抽象（真实 `TurnClient` 与测试替身）。
///
/// 覆盖策略层需要的操作；`as_turn_client` 让组合根在需要数据面
/// （`TurnSocket`）时取回具体 client（mock 返回 `None`）。
pub trait TurnHandle: Send {
    /// 发送 Refresh 续租。
    fn refresh(&self) -> io::Result<()>;
    /// 显式释放 TURN Allocation（RFC 5766 LIFETIME=0）；best-effort。
    fn release(&mut self) -> io::Result<()>;
    /// 中继分配地址。
    fn relayed_addr(&self) -> SocketAddr;
    /// 服务器观察到的 reflexive 地址（打洞候选）。
    fn mapped_addr(&self) -> Option<SocketAddr>;
    /// 分配是否已过期。
    fn is_expired(&self) -> bool;
    /// 取回具体 `TurnClient`（数据面用）；mock 返回 `None`。
    fn as_turn_client(&self) -> Option<TurnClient>;
}

impl TurnHandle for TurnClient {
    fn refresh(&self) -> io::Result<()> {
        TurnClient::refresh(self)
    }

    fn release(&mut self) -> io::Result<()> {
        TurnClient::deallocate(self)
    }

    fn relayed_addr(&self) -> SocketAddr {
        TurnClient::relayed_addr(self)
    }

    fn mapped_addr(&self) -> Option<SocketAddr> {
        TurnClient::mapped_addr(self)
    }

    fn is_expired(&self) -> bool {
        TurnClient::is_expired(self)
    }

    fn as_turn_client(&self) -> Option<TurnClient> {
        Some(self.clone())
    }
}

/// 创建真实 `TurnClient` 的工厂（组合根注入，测试可替换）。
type TurnFactory = Box<dyn Fn() -> io::Result<Box<dyn TurnHandle>> + Send>;

/// 构造指向 `server` 的真实 TURN client 工厂。
///
/// `bind` 来自 `[network.turn].bind_addr`：`Some` → `allocate_bound`；
/// `None`（仅手写 `TurnSection` 的测试可达；配置加载已拒绝非法值）→
/// `InvalidInput`，不 panic、不静默换地址。
fn real_factory(
    server: SocketAddr,
    creds: TurnCredentials,
    bind: Option<SocketAddr>,
) -> TurnFactory {
    Box::new(move || match bind {
        Some(local_bind) => TurnClient::allocate_bound(server, creds.clone(), local_bind)
            .map(|c| Box::new(c) as Box<dyn TurnHandle>),
        None => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "turn bind_addr invalid",
        )),
    })
}

/// TURN 分配生命周期管理器（AC1/AC3）。
///
/// 所有权：`TurnManager` 由组合根（`main.rs`）创建并持有；worker 线程是唯一
/// 调用方（单写入者）。`refresh_if_needed` 必须在同一线程按节奏调用。
pub struct TurnManager {
    /// 原始配置（`None` = 未配置，子系统禁用）。
    config: Option<TurnSection>,
    /// TURN 服务器地址（配置解析失败时为 `None`）。
    server: Option<SocketAddr>,
    /// 生命周期状态。
    state: TurnState,
    /// 当前分配（`Some` 表示持有资源）。
    client: Option<Box<dyn TurnHandle>>,
    /// 分配/重试工厂。
    factory: TurnFactory,
    /// `[network.turn].bind_addr` 解析结果（TURN client 的本地 socket 绑定）。
    bind: Option<SocketAddr>,
    /// 连续 Refresh 失败次数（AC3 3-strike）。
    consecutive_refresh_failures: u32,
    /// 本轮 438 Stale Nonce 是否已重试过（C-3：单次 Refresh 周期最多重试 1 次，
    /// 防恶意/故障服务端 438 死循环；仅在干净 Refresh 成功后复位）。
    stale_nonce_retried: bool,
    /// 下次 Refresh 时间点。
    next_refresh_at: Option<Instant>,
    /// 分配的保活间隔（来自配置的 refresh_interval_sec）。
    refresh_interval: Duration,
    /// 最近一次失败原因（仅 `health() == Degraded` 时对外可见）。
    last_failure: Option<TurnFailure>,
}

impl TurnManager {
    /// 从配置构造管理器。无 `[network.turn]` 配置 → `Disabled` 状态。
    ///
    /// `server` 解析失败时记录 WARN 并进入 `Disabled`（不阻断进程启动）。
    pub fn new(config: Option<TurnSection>) -> Self {
        match config {
            None => Self {
                config: None,
                server: None,
                state: TurnState::Disabled,
                client: None,
                factory: Box::new(|| {
                    Err(io::Error::new(io::ErrorKind::NotFound, "turn unconfigured"))
                }),
                bind: None,
                consecutive_refresh_failures: 0,
                stale_nonce_retried: false,
                next_refresh_at: None,
                refresh_interval: Duration::from_secs(300),
                last_failure: None,
            },
            Some(section) => {
                let refresh_interval = Duration::from_secs(section.refresh_interval_sec);
                // 只在构造期解析一次；两个生产 manager 都经此路径覆盖。
                let bind = section.bind_addr.parse::<SocketAddr>().ok();
                // P3-Q1：bind 解析失败（生产不可达；config 已拒绝）预置 Server。
                let bind_failure = if bind.is_none() {
                    Some(TurnFailure::Server)
                } else {
                    None
                };
                match section.server.parse::<SocketAddr>() {
                    Ok(server) => {
                        let creds = TurnCredentials {
                            username: section.username.clone(),
                            password: section.password.clone(),
                            realm: section.realm.clone(),
                        };
                        Self {
                            config: Some(section),
                            server: Some(server),
                            state: TurnState::Allocating,
                            client: None,
                            factory: real_factory(server, creds, bind),
                            bind,
                            consecutive_refresh_failures: 0,
                            stale_nonce_retried: false,
                            next_refresh_at: None,
                            refresh_interval,
                            last_failure: bind_failure,
                        }
                    }
                    Err(e) => {
                        eprintln!(
                            "[nat-switch] WARN: turn configured but server {:?} is invalid ({e}); turn disabled, punch disabled",
                            section.server
                        );
                        Self {
                            config: Some(section),
                            server: None,
                            state: TurnState::Disabled,
                            client: None,
                            factory: Box::new(|| {
                                Err(io::Error::new(
                                    io::ErrorKind::InvalidInput,
                                    "turn server invalid",
                                ))
                            }),
                            bind,
                            consecutive_refresh_failures: 0,
                            stale_nonce_retried: false,
                            next_refresh_at: None,
                            refresh_interval,
                            last_failure: Some(TurnFailure::Server),
                        }
                    }
                }
            }
        }
    }

    /// 测试钩子：注入自定义工厂。
    #[cfg(test)]
    fn with_factory(config: Option<TurnSection>, factory: TurnFactory) -> Self {
        let refresh_interval = config
            .as_ref()
            .map(|c| Duration::from_secs(c.refresh_interval_sec))
            .unwrap_or_else(|| Duration::from_secs(300));
        let initial_state = if config.is_some() {
            TurnState::Allocating
        } else {
            TurnState::Disabled
        };
        let bind = config
            .as_ref()
            .and_then(|c| c.bind_addr.parse::<SocketAddr>().ok());
        Self {
            config,
            server: None,
            state: initial_state,
            client: None,
            factory,
            bind,
            consecutive_refresh_failures: 0,
            stale_nonce_retried: false,
            next_refresh_at: None,
            refresh_interval,
            last_failure: None,
        }
    }

    /// 当前状态。
    pub fn state(&self) -> TurnState {
        self.state
    }

    /// 是否处于活动状态（有有效 Allocation）。
    pub fn is_active(&self) -> bool {
        self.state == TurnState::Active && self.client.is_some()
    }

    /// 运维可见的健康态（`TurnState` + config 的投影）。
    ///
    /// 注意：装配侧的 `not_started` 是伪值，**不经**本方法（Wave B）。
    pub fn health(&self) -> TurnHealth {
        if self.config.is_none() {
            return TurnHealth::Unconfigured;
        }
        match self.state {
            TurnState::Allocating => TurnHealth::Allocating,
            TurnState::Active | TurnState::Refreshing => TurnHealth::Active,
            TurnState::Expired => TurnHealth::Expired,
            TurnState::Disabled => TurnHealth::Degraded,
        }
    }

    /// 降级原因：仅 `health() == Degraded` 时返回。
    pub fn last_failure(&self) -> Option<TurnFailure> {
        if self.health() == TurnHealth::Degraded {
            self.last_failure
        } else {
            None
        }
    }

    /// 配置里的 `bind_addr` 原文（未配置时为 `None`）。
    pub fn bind_addr_text(&self) -> Option<&str> {
        self.config.as_ref().map(|c| c.bind_addr.as_str())
    }

    /// 连续 Refresh 失败次数（可观测）。
    pub fn consecutive_refresh_failures(&self) -> u32 {
        self.consecutive_refresh_failures
    }

    /// 中继分配地址（未分配时为 `None`）。
    pub fn relayed_addr(&self) -> Option<SocketAddr> {
        self.client.as_ref().map(|c| c.relayed_addr())
    }

    /// 服务器观察到的 reflexive 地址（打洞候选；未分配时为 `None`）。
    pub fn mapped_addr(&self) -> Option<SocketAddr> {
        self.client.as_ref().and_then(|c| c.mapped_addr())
    }

    /// 取回具体 `TurnClient`（数据面 `TurnSocket` 用）；mock/未分配为 `None`。
    pub fn client(&self) -> Option<TurnClient> {
        self.client.as_ref().and_then(|c| c.as_turn_client())
    }

    /// 懒初始化 Allocate（AC1）。
    ///
    /// - 成功：状态 → `Active`，返回中继地址。
    /// - 失败（401/438/超时等）：记录 WARN，状态 → `Disabled`，回退 Peer Relay。
    pub fn ensure_allocated(&mut self) -> Result<SocketAddr, TurnError> {
        // 已分配且有效：直接返回。
        if self.is_active() {
            if let Some(c) = &self.client {
                return Ok(c.relayed_addr());
            }
        }
        if self.state == TurnState::Disabled {
            return Err(TurnError::Unconfigured);
        }

        self.state = TurnState::Allocating;
        match (self.factory)() {
            Ok(client) => Ok(self.activate(client, true)),
            Err(e) => {
                self.handle_auth_failure(&e);
                Err(TurnError::Io(e))
            }
        }
    }

    /// 统一「激活分配」路径：置 `Active`、清失败计数、排下次刷新、打印分配行。
    ///
    /// `reset_stale_nonce`：`ensure_allocated` 传 `true`；438 重分配传 `false`
    /// （C-3：单次 Refresh 周期最多重分配一次）。
    fn activate(&mut self, client: Box<dyn TurnHandle>, reset_stale_nonce: bool) -> SocketAddr {
        // mapped 必须在 client move 进 self.client 之前读取。
        let relayed = client.relayed_addr();
        let mapped = client.mapped_addr();
        self.client = Some(client);
        self.state = TurnState::Active;
        self.consecutive_refresh_failures = 0;
        self.last_failure = None;
        if reset_stale_nonce {
            self.stale_nonce_retried = false;
        }
        self.next_refresh_at = self.schedule_next_refresh();
        eprintln!(
            "[nat-switch] TURN allocation active: relayed={relayed} mapped={} bind={} refresh_in={}s",
            mapped
                .map(|addr| addr.to_string())
                .unwrap_or_else(|| "none".to_string()),
            self.bind_for_log(),
            self.refresh_interval.as_secs()
        );
        relayed
    }

    /// 分配行/失败行里的 `bind=` 文本：解析成功用 `SocketAddr`，否则用配置原文。
    fn bind_for_log(&self) -> String {
        match self.bind {
            Some(addr) => addr.to_string(),
            None => self
                .config
                .as_ref()
                .map(|c| c.bind_addr.clone())
                .unwrap_or_else(|| "none".to_string()),
        }
    }

    /// 按节奏检查并发送 Refresh（AC3）。
    ///
    /// 仅在到达刷新时间点时执行；未到期返回 `NotDue`。
    /// 438 Stale Nonce → 重新 Allocate（新 Nonce）自动重试。
    /// 连续 3 次失败 → 释放 Allocation，状态 → `Expired`。
    pub fn refresh_if_needed(&mut self) -> RefreshOutcome {
        if !self.is_active() {
            return RefreshOutcome::Inactive;
        }
        let Some(next) = self.next_refresh_at else {
            return RefreshOutcome::Inactive;
        };
        if Instant::now() < next {
            return RefreshOutcome::NotDue;
        }

        self.state = TurnState::Refreshing;
        let Some(client) = &self.client else {
            self.state = TurnState::Expired;
            return RefreshOutcome::Inactive;
        };

        match client.refresh() {
            Ok(()) => {
                let relayed = client.relayed_addr();
                self.state = TurnState::Active;
                self.consecutive_refresh_failures = 0;
                self.last_failure = None;
                self.stale_nonce_retried = false;
                self.next_refresh_at = self.schedule_next_refresh();
                eprintln!("[nat-switch] TURN refresh ok relayed={relayed}");
                RefreshOutcome::Refreshed
            }
            Err(e) if is_stale_nonce(&e) => {
                // C-3：单次 Refresh 周期内 438 只重试 1 次；已重试过则按普通
                // Refresh 失败处理（计入 3-strike），防 438 死循环。
                if self.stale_nonce_retried {
                    eprintln!(
                        "[nat-switch] TURN refresh got 438 Stale Nonce again after retry; treating as ordinary refresh failure"
                    );
                    self.handle_refresh_failure(&e)
                } else {
                    self.stale_nonce_retried = true;
                    eprintln!(
                        "[nat-switch] TURN refresh got 438 Stale Nonce; re-allocating with fresh nonce"
                    );
                    self.retry_stale_nonce()
                }
            }
            Err(e) => self.handle_refresh_failure(&e),
        }
    }

    /// 438 Stale Nonce：重新 Allocate 获取新 Nonce（单次 Refresh 周期最多 1 次）。
    ///
    /// 重试成功 → Active；重试失败说明分配本身不可达/认证失败，走分配失败
    /// 路径（`handle_auth_failure` → Disabled），绝不回退到 Active（C-3）。
    /// 注意：成功时不复位 `stale_nonce_retried`——若服务端持续返回 438，
    /// 后续 438 会流入普通 Refresh 失败（3-strike），避免每周期泄漏一个
    /// 服务端 allocation；仅干净 Refresh 成功才复位。
    fn retry_stale_nonce(&mut self) -> RefreshOutcome {
        // D-5：必须真正 drop（命名绑定会活到作用域末），否则固定端口重分配
        // 时旧 UDP socket 仍占位 → EADDRINUSE。
        drop(self.client.take());
        match (self.factory)() {
            Ok(new_client) => {
                // 复位参数为 false：本 Refresh 周期内不得再次重分配（C-3）。
                self.activate(new_client, false);
                RefreshOutcome::StaleNonceRetried
            }
            Err(e) => {
                self.handle_auth_failure(&e);
                RefreshOutcome::ReallocateFailed
            }
        }
    }

    /// 记录一次 Refresh 失败。连续 `MAX_REFRESH_FAILURES` 次 → 释放资源。
    fn handle_refresh_failure(&mut self, e: &io::Error) -> RefreshOutcome {
        self.consecutive_refresh_failures += 1;
        let n = self.consecutive_refresh_failures;
        if n >= MAX_REFRESH_FAILURES {
            eprintln!(
                "[nat-switch] WARN: TURN refresh failed {n} consecutive times ({e}); warm backup dead, releasing allocation"
            );
            // C2：显式 Deallocate（RFC 5766 §7.3：Refresh LIFETIME=0），best-effort。
            // `take()` 已把 `self.client` 置为 `None`；失败时服务端也会在自身计时器到期后
            // 过期该 allocation，因此这里只记录 WARN，不阻断降级。
            if let Some(mut c) = self.client.take() {
                if let Err(e) = c.release() {
                    eprintln!(
                        "[nat-switch] WARN: TURN deallocate (LIFETIME=0) failed ({e}); server-side allocation will expire on its own timer"
                    );
                }
            }
            self.state = TurnState::Expired;
            self.next_refresh_at = None;
            self.last_failure = None;
        } else {
            eprintln!(
                "[nat-switch] WARN: TURN refresh failed ({e}); retry {n}/{}",
                MAX_REFRESH_FAILURES
            );
            self.state = TurnState::Active;
            self.next_refresh_at = Some(Instant::now() + REFRESH_RETRY_DELAY);
        }
        RefreshOutcome::Failed(n)
    }

    /// Allocate 认证失败/超时（AC1 异常）：WARN + Disabled 降级，回退 Peer Relay。
    fn handle_auth_failure(&mut self, e: &io::Error) {
        eprintln!(
            "[nat-switch] WARN: TURN allocate failed bind={} err={e}; disabling turn, falling back to peer relay",
            self.bind_for_log()
        );
        // P3-Q1：构造期已预置的失败原因优先（bind 解析失败 → server_invalid）。
        if self.last_failure.is_none() {
            self.last_failure = Some(classify_failure(e));
        }
        self.state = TurnState::Disabled;
        self.client = None;
        self.consecutive_refresh_failures = 0;
        self.next_refresh_at = None;
    }

    /// 计算下次 Refresh 时间：`refresh_interval - REFRESH_MARGIN` 后。
    fn schedule_next_refresh(&self) -> Option<Instant> {
        Some(Instant::now() + self.refresh_interval.saturating_sub(REFRESH_MARGIN))
    }

    /// 释放 TURN 资源并进入 `Disabled`（退出路径，幂等）。
    pub fn shutdown(&mut self) {
        // C2：显式 Deallocate（RFC 5766 LIFETIME=0），best-effort。
        if let Some(mut c) = self.client.take() {
            if let Err(e) = c.release() {
                eprintln!(
                    "[nat-switch] WARN: TURN deallocate (LIFETIME=0) failed ({e}); server-side allocation will expire on its own timer"
                );
            }
        }
        self.state = TurnState::Disabled;
        self.consecutive_refresh_failures = 0;
        self.next_refresh_at = None;
        eprintln!("[nat-switch] TURN manager shut down");
    }
}

/// 判断 Refresh 错误是否为 438 Stale Nonce。
///
/// W-5：不用裸 `contains("438")`（会误命中如端口 1438 之类的数字），而是匹配
/// 完整词组 `"438 Stale Nonce"`。依据的格式契约：`nexus_turn::client` 的
/// `unexpected()` 把错误响应格式化为
/// `"turn {op}: unexpected response 0x{msg:04x} {class}{num:02} {reason}"`，
/// 其中 438 的 reason 为 RFC 5389 标准词组 "Stale Nonce"。
/// 完全类型化的 `TurnError::StaleNonce` 需要把 `TurnClient::refresh` 的公开
/// `io::Result` 签名改掉——超出本次范围，记为后续工作。
fn is_stale_nonce(e: &io::Error) -> bool {
    e.to_string().contains("438 Stale Nonce")
}

/// 把分配失败分类为对外可见的降级原因。
fn classify_failure(e: &io::Error) -> TurnFailure {
    match e.kind() {
        io::ErrorKind::AddrNotAvailable
        | io::ErrorKind::AddrInUse
        | io::ErrorKind::PermissionDenied
        | io::ErrorKind::InvalidInput => TurnFailure::Bind,
        _ => TurnFailure::Allocate,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_turn::client::TurnCredentials;
    use nexus_turn::server::TurnServer;
    use std::net::UdpSocket;
    use std::sync::Arc;
    use std::sync::atomic::Ordering;

    fn creds() -> TurnCredentials {
        TurnCredentials {
            username: "nexus".into(),
            password: "test-secret".into(),
            realm: "nexus".into(),
        }
    }

    fn section(server: SocketAddr, refresh_interval_sec: u64) -> TurnSection {
        TurnSection {
            server: server.to_string(),
            realm: "nexus".into(),
            username: "nexus".into(),
            password: "test-secret".into(),
            refresh_interval_sec,
            stun_server: None,
            stun_server2: None,
            bind_addr: "0.0.0.0:0".into(),
        }
    }

    fn bind_available(addr: &str) -> bool {
        UdpSocket::bind(addr).is_ok()
    }

    /// P3-AC1：`bind_addr` 被工厂消费（mapped IP == 配置 IP）。
    #[test]
    fn bind_addr_is_honored() {
        if !bind_available("127.0.0.2:0") {
            eprintln!("SKIP: 127.0.0.2 not bindable in this environment");
            return;
        }
        let server = TurnServer::bind("127.0.0.1:0".parse().unwrap(), creds()).unwrap();
        let mut cfg = section(server.main_addr(), 300);
        cfg.bind_addr = "127.0.0.2:0".into();
        let mut mgr = TurnManager::new(Some(cfg));
        let relayed = mgr.ensure_allocated().expect("allocate with 127.0.0.2");
        assert!(relayed.port() > 0);
        assert_eq!(
            mgr.mapped_addr().map(|addr| addr.ip()),
            Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 2))),
            "TURN client socket must bind the configured bind_addr"
        );
    }

    /// P3-AC2(i)：同一 `TurnSection` 构造的两个 manager 都绑配置 IP。
    #[test]
    fn factory_covers_both_managers() {
        if !bind_available("127.0.0.2:0") {
            eprintln!("SKIP: 127.0.0.2 not bindable in this environment");
            return;
        }
        let server = TurnServer::bind("127.0.0.1:0".parse().unwrap(), creds()).unwrap();
        let mut cfg = section(server.main_addr(), 300);
        cfg.bind_addr = "127.0.0.2:0".into();
        let mut warm_backup = TurnManager::new(Some(cfg.clone()));
        let mut provider = TurnManager::new(Some(cfg));

        warm_backup
            .ensure_allocated()
            .expect("warm backup allocate");
        provider.ensure_allocated().expect("provider allocate");
        let expected = Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 2)));
        assert_eq!(warm_backup.mapped_addr().map(|a| a.ip()), expected);
        assert_eq!(provider.mapped_addr().map(|a| a.ip()), expected);
    }

    /// 真实 TURN server 往返：allocate → refresh 保活。
    #[test]
    fn allocate_then_refresh_keeps_warm() {
        let server = TurnServer::bind("127.0.0.1:0".parse().unwrap(), creds()).unwrap();
        let cfg = section(server.main_addr(), 300);
        let mut mgr = TurnManager::new(Some(cfg));
        let relayed = mgr.ensure_allocated().expect("allocate should succeed");
        assert!(relayed.port() > 0);
        assert_eq!(mgr.state(), TurnState::Active);
        assert!(mgr.is_active());
        assert!(mgr.relayed_addr().is_some());

        // 强制立即刷新。
        mgr.next_refresh_at = Some(Instant::now());
        let outcome = mgr.refresh_if_needed();
        assert_eq!(outcome, RefreshOutcome::Refreshed);
        assert_eq!(mgr.consecutive_refresh_failures(), 0);
        assert!(mgr.is_active());
    }

    /// P3-AC5（manager 级）：非本地 `bind_addr` → Disabled + Degraded + Bind。
    #[test]
    fn non_local_bind_disables() {
        if bind_available("192.0.2.1:0") {
            eprintln!("SKIP: 192.0.2.1 unexpectedly bindable in this environment");
            return;
        }
        let mut cfg = section("127.0.0.1:3478".parse().unwrap(), 300);
        cfg.bind_addr = "192.0.2.1:0".into();
        let mut mgr = TurnManager::new(Some(cfg));
        assert!(
            mgr.ensure_allocated().is_err(),
            "non-local bind must fail allocation"
        );
        assert_eq!(mgr.state(), TurnState::Disabled);
        assert_eq!(mgr.health(), TurnHealth::Degraded);
        assert_eq!(mgr.last_failure(), Some(TurnFailure::Bind));
    }

    /// P3-AC1/§4.7-3：固定端口 438 重分配前必须 drop 旧 socket（否则 EADDRINUSE）。
    #[test]
    fn fixed_port_reallocate_drops_old_socket() {
        let port = {
            let probe = UdpSocket::bind("127.0.0.1:0").expect("probe bind");
            probe.local_addr().unwrap().port()
        };
        struct FixedPortHandle {
            sock: UdpSocket,
            stale: bool,
        }
        impl TurnHandle for FixedPortHandle {
            fn refresh(&self) -> io::Result<()> {
                if self.stale {
                    Err(io::Error::other(
                        "turn refresh: unexpected response 0x0113 438 Stale Nonce",
                    ))
                } else {
                    Ok(())
                }
            }
            fn release(&mut self) -> io::Result<()> {
                Ok(())
            }
            fn relayed_addr(&self) -> SocketAddr {
                self.sock.local_addr().unwrap()
            }
            fn mapped_addr(&self) -> Option<SocketAddr> {
                None
            }
            fn is_expired(&self) -> bool {
                false
            }
            fn as_turn_client(&self) -> Option<TurnClient> {
                None
            }
        }

        let calls = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let calls_for_factory = calls.clone();
        let factory: TurnFactory = Box::new(move || {
            let call = calls_for_factory.fetch_add(1, Ordering::Relaxed);
            let sock = UdpSocket::bind(("127.0.0.1", port)).map_err(|e| {
                io::Error::new(e.kind(), format!("bind fixed port {port} failed: {e}"))
            })?;
            Ok(Box::new(FixedPortHandle {
                sock,
                stale: call == 0,
            }))
        });
        let cfg = section("127.0.0.1:3478".parse().unwrap(), 300);
        let mut mgr = TurnManager::with_factory(Some(cfg), factory);
        mgr.ensure_allocated().expect("first allocate");
        assert_eq!(calls.load(Ordering::Relaxed), 1);

        mgr.next_refresh_at = Some(Instant::now());
        assert_eq!(mgr.refresh_if_needed(), RefreshOutcome::StaleNonceRetried);
        assert_eq!(
            calls.load(Ordering::Relaxed),
            2,
            "stale-nonce reallocation must bind the same fixed port"
        );
        assert!(mgr.is_active());
        assert_eq!(mgr.health(), TurnHealth::Active);
        assert!(
            mgr.stale_nonce_retried,
            "successful 438 reallocation must not reset the per-cycle latch"
        );
    }

    /// §4.5 五行映射 + `not_started` 不经 `TurnHealth` 的边界说明。
    #[test]
    fn health_mapping_table() {
        // 1) 未配置。
        let mgr = TurnManager::new(None);
        assert_eq!(mgr.health(), TurnHealth::Unconfigured);
        assert_eq!(mgr.health().as_str(), "unconfigured");
        assert_eq!(mgr.last_failure(), None);
        assert_eq!(mgr.bind_addr_text(), None);

        // 2) 已配置、尚未分配 → Allocating（与 Degraded 不同）。
        let cfg = section("127.0.0.1:3478".parse().unwrap(), 300);
        let mgr = TurnManager::new(Some(cfg));
        assert_eq!(mgr.health(), TurnHealth::Allocating);
        assert_eq!(mgr.health().as_str(), "allocating");
        assert_eq!(mgr.bind_addr_text(), Some("0.0.0.0:0"));

        // 3) 分配成功 → Active。
        let server = TurnServer::bind("127.0.0.1:0".parse().unwrap(), creds()).unwrap();
        let mut mgr = TurnManager::new(Some(section(server.main_addr(), 300)));
        mgr.ensure_allocated().expect("allocate");
        assert_eq!(mgr.health(), TurnHealth::Active);
        assert_eq!(mgr.health().as_str(), "active");
        assert_eq!(mgr.last_failure(), None);

        // 4) 3-strike → Expired，last_failure 为 None（health 已表达）。
        struct AlwaysFailing;
        impl TurnHandle for AlwaysFailing {
            fn refresh(&self) -> io::Result<()> {
                Err(io::Error::other("turn server unreachable"))
            }
            fn release(&mut self) -> io::Result<()> {
                Ok(())
            }
            fn relayed_addr(&self) -> SocketAddr {
                "192.0.2.1:54320".parse().unwrap()
            }
            fn mapped_addr(&self) -> Option<SocketAddr> {
                None
            }
            fn is_expired(&self) -> bool {
                true
            }
            fn as_turn_client(&self) -> Option<TurnClient> {
                None
            }
        }
        let factory: TurnFactory = Box::new(|| Ok(Box::new(AlwaysFailing)));
        let mut mgr = TurnManager::with_factory(
            Some(section("127.0.0.1:3478".parse().unwrap(), 300)),
            factory,
        );
        mgr.ensure_allocated().expect("allocate");
        for expected in 1..=3 {
            mgr.next_refresh_at = Some(Instant::now());
            assert_eq!(mgr.refresh_if_needed(), RefreshOutcome::Failed(expected));
        }
        assert_eq!(mgr.health(), TurnHealth::Expired);
        assert_eq!(mgr.health().as_str(), "expired");
        assert_eq!(mgr.last_failure(), None);

        // 5) 分配失败降级 → Degraded + Allocate。
        let factory: TurnFactory = Box::new(|| Err(io::Error::other("network unreachable")));
        let mut mgr = TurnManager::with_factory(
            Some(section("127.0.0.1:3478".parse().unwrap(), 300)),
            factory,
        );
        assert!(mgr.ensure_allocated().is_err());
        assert_eq!(mgr.health(), TurnHealth::Degraded);
        assert_eq!(mgr.health().as_str(), "degraded");
        assert_eq!(mgr.last_failure(), Some(TurnFailure::Allocate));
        assert_eq!(
            mgr.last_failure().map(TurnFailure::as_str),
            Some("allocate_failed")
        );

        // 值域逐字（装配侧 not_started 不经 TurnHealth）。
        assert_eq!(TurnFailure::Bind.as_str(), "bind_failed");
        assert_eq!(TurnFailure::Server.as_str(), "server_invalid");
    }

    /// 未配置 → Disabled，ensure_allocated 返回 Unconfigured。
    #[test]
    fn unconfigured_is_disabled() {
        let mut mgr = TurnManager::new(None);
        assert_eq!(mgr.state(), TurnState::Disabled);
        assert!(!mgr.is_active());
        assert!(matches!(
            mgr.ensure_allocated(),
            Err(TurnError::Unconfigured)
        ));
        assert_eq!(mgr.refresh_if_needed(), RefreshOutcome::Inactive);
    }

    /// 3-strike：连续 3 次 Refresh 失败 → Expired，释放资源。
    #[test]
    fn three_refresh_failures_release_allocation() {
        struct FailingHandle;
        impl TurnHandle for FailingHandle {
            fn refresh(&self) -> io::Result<()> {
                Err(io::Error::other("turn server unreachable"))
            }
            fn release(&mut self) -> io::Result<()> {
                Ok(())
            }
            fn relayed_addr(&self) -> SocketAddr {
                "192.0.2.1:54320".parse().unwrap()
            }
            fn mapped_addr(&self) -> Option<SocketAddr> {
                None
            }
            fn is_expired(&self) -> bool {
                true
            }
            fn as_turn_client(&self) -> Option<TurnClient> {
                None
            }
        }

        let cfg = section("127.0.0.1:3478".parse().unwrap(), 300);
        let factory: TurnFactory = Box::new(|| Ok(Box::new(FailingHandle)));
        let mut mgr = TurnManager::with_factory(Some(cfg), factory);
        mgr.ensure_allocated().expect("allocate should succeed");
        assert!(mgr.is_active());

        mgr.next_refresh_at = Some(Instant::now());
        assert_eq!(mgr.refresh_if_needed(), RefreshOutcome::Failed(1));
        assert!(mgr.is_active(), "still warm backup after 1st failure");

        mgr.next_refresh_at = Some(Instant::now());
        assert_eq!(mgr.refresh_if_needed(), RefreshOutcome::Failed(2));
        assert!(mgr.is_active(), "still warm backup after 2nd failure");

        mgr.next_refresh_at = Some(Instant::now());
        assert_eq!(mgr.refresh_if_needed(), RefreshOutcome::Failed(3));
        assert_eq!(mgr.state(), TurnState::Expired);
        assert!(!mgr.is_active());
        assert!(mgr.client.is_none(), "allocation must be released");
        assert_eq!(mgr.refresh_if_needed(), RefreshOutcome::Inactive);
    }

    /// 438 Stale Nonce → 重新 Allocate（新 Nonce）自动重试成功。
    #[test]
    fn stale_nonce_triggers_reallocate() {
        // 第一次 refresh 返回 438 风格错误；工厂随后返回新 client。
        struct StaleNonceThenOk {
            calls: std::sync::atomic::AtomicU32,
        }
        impl TurnHandle for StaleNonceThenOk {
            fn refresh(&self) -> io::Result<()> {
                Err(io::Error::other(
                    "turn refresh: unexpected response 0x0113 438 Stale Nonce",
                ))
            }
            fn release(&mut self) -> io::Result<()> {
                Ok(())
            }
            fn relayed_addr(&self) -> SocketAddr {
                "192.0.2.1:54320".parse().unwrap()
            }
            fn mapped_addr(&self) -> Option<SocketAddr> {
                None
            }
            fn is_expired(&self) -> bool {
                true
            }
            fn as_turn_client(&self) -> Option<TurnClient> {
                None
            }
        }

        let cfg = section("127.0.0.1:3478".parse().unwrap(), 300);
        let factory: TurnFactory = Box::new(|| {
            Ok(Box::new(StaleNonceThenOk {
                calls: Default::default(),
            }))
        });
        let mut mgr = TurnManager::with_factory(Some(cfg), factory);
        mgr.ensure_allocated().expect("allocate should succeed");

        mgr.next_refresh_at = Some(Instant::now());
        let outcome = mgr.refresh_if_needed();
        assert_eq!(outcome, RefreshOutcome::StaleNonceRetried);
        assert!(mgr.is_active());
        assert_eq!(mgr.consecutive_refresh_failures(), 0);
    }

    /// 配置的 server 非法 → Disabled（不 panic）。
    #[test]
    fn invalid_server_is_disabled() {
        let cfg = TurnSection {
            server: "not-an-addr".into(),
            realm: "nexus".into(),
            username: "nexus".into(),
            password: "secret".into(),
            refresh_interval_sec: 300,
            stun_server: None,
            stun_server2: None,
            bind_addr: "0.0.0.0:0".into(),
        };
        let mgr = TurnManager::new(Some(cfg));
        assert_eq!(mgr.state(), TurnState::Disabled);
        assert!(!mgr.is_active());
    }

    /// C-3：438 重试中重新 Allocate 失败 → 走分配失败路径（Disabled），
    /// 绝不回退到 Active；outcome 为 ReallocateFailed。
    #[test]
    fn stale_nonce_retry_failure_disables() {
        struct AlwaysStale;
        impl TurnHandle for AlwaysStale {
            fn refresh(&self) -> io::Result<()> {
                Err(io::Error::other(
                    "turn refresh: unexpected response 0x0113 438 Stale Nonce",
                ))
            }
            fn release(&mut self) -> io::Result<()> {
                Ok(())
            }
            fn relayed_addr(&self) -> SocketAddr {
                "192.0.2.1:54320".parse().unwrap()
            }
            fn mapped_addr(&self) -> Option<SocketAddr> {
                None
            }
            fn is_expired(&self) -> bool {
                true
            }
            fn as_turn_client(&self) -> Option<TurnClient> {
                None
            }
        }

        let cfg = section("127.0.0.1:3478".parse().unwrap(), 300);
        // allocate 成功（拿到旧 client），但后续 factory（重分配）恒失败。
        let factory: TurnFactory = Box::new({
            let n = std::sync::atomic::AtomicU32::new(0);
            move || {
                let c = n.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if c == 0 {
                    Ok(Box::new(AlwaysStale) as Box<dyn TurnHandle>)
                } else {
                    Err(io::Error::other("turn allocate: network unreachable"))
                }
            }
        });
        let mut mgr = TurnManager::with_factory(Some(cfg), factory);
        mgr.ensure_allocated().expect("allocate should succeed");
        assert!(mgr.is_active());

        mgr.next_refresh_at = Some(Instant::now());
        let outcome = mgr.refresh_if_needed();
        assert_eq!(outcome, RefreshOutcome::ReallocateFailed);
        assert_eq!(
            mgr.state(),
            TurnState::Disabled,
            "re-allocate failure must go to Disabled, never back to Active"
        );
        assert!(!mgr.is_active());
        assert!(mgr.client.is_none());
    }

    /// C-3：单次 Refresh 周期内 438 只重试 1 次；第二次 438 走普通失败路径，
    /// 工厂只被调用一次（无 438 死循环）。
    #[test]
    fn stale_nonce_second_438_is_ordinary_failure() {
        struct AlwaysStale;
        impl TurnHandle for AlwaysStale {
            fn refresh(&self) -> io::Result<()> {
                Err(io::Error::other(
                    "turn refresh: unexpected response 0x0113 438 Stale Nonce",
                ))
            }
            fn release(&mut self) -> io::Result<()> {
                Ok(())
            }
            fn relayed_addr(&self) -> SocketAddr {
                "192.0.2.1:54320".parse().unwrap()
            }
            fn mapped_addr(&self) -> Option<SocketAddr> {
                None
            }
            fn is_expired(&self) -> bool {
                true
            }
            fn as_turn_client(&self) -> Option<TurnClient> {
                None
            }
        }

        let factory_calls = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let factory_calls2 = factory_calls.clone();
        let factory: TurnFactory = Box::new(move || {
            factory_calls2.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(Box::new(AlwaysStale) as Box<dyn TurnHandle>)
        });
        let cfg = section("127.0.0.1:3478".parse().unwrap(), 300);
        let mut mgr = TurnManager::with_factory(Some(cfg), factory);
        mgr.ensure_allocated().expect("allocate should succeed");
        assert_eq!(factory_calls.load(std::sync::atomic::Ordering::Relaxed), 1);

        // 第一次 438 → 重试一次，成功。
        mgr.next_refresh_at = Some(Instant::now());
        assert_eq!(mgr.refresh_if_needed(), RefreshOutcome::StaleNonceRetried);
        assert!(mgr.is_active());
        assert_eq!(factory_calls.load(std::sync::atomic::Ordering::Relaxed), 2);

        // 新 client 的 refresh 同样 438 → 不再重分配，走普通失败路径。
        mgr.next_refresh_at = Some(Instant::now());
        assert_eq!(mgr.refresh_if_needed(), RefreshOutcome::Failed(1));
        assert_eq!(
            factory_calls.load(std::sync::atomic::Ordering::Relaxed),
            2,
            "no second re-allocate within the 438 episode"
        );
        assert!(
            mgr.is_active(),
            "still warm backup after 1st ordinary failure"
        );
    }

    /// 认证失败（工厂返回 401 风格错误）→ Disabled 降级。
    #[test]
    fn auth_failure_disables_turn() {
        let factory: TurnFactory = Box::new(|| {
            Err(io::Error::other(
                "turn allocate: unexpected response 0x0113 401 Unauthorized",
            ))
        });
        let cfg = section("127.0.0.1:3478".parse().unwrap(), 300);
        let mut mgr = TurnManager::with_factory(Some(cfg), factory);
        assert!(mgr.ensure_allocated().is_err());
        assert_eq!(mgr.state(), TurnState::Disabled);
        assert!(!mgr.is_active());
        assert_eq!(mgr.refresh_if_needed(), RefreshOutcome::Inactive);
    }

    /// C2：`shutdown()` 显式释放 Allocation（LIFETIME=0 Deallocate），状态 → Disabled。
    #[test]
    fn shutdown_releases_allocation() {
        struct RecordingHandle {
            released: Arc<std::sync::atomic::AtomicBool>,
        }
        impl TurnHandle for RecordingHandle {
            fn refresh(&self) -> io::Result<()> {
                Ok(())
            }
            fn release(&mut self) -> io::Result<()> {
                self.released.store(true, Ordering::Relaxed);
                Ok(())
            }
            fn relayed_addr(&self) -> SocketAddr {
                "192.0.2.1:54320".parse().unwrap()
            }
            fn mapped_addr(&self) -> Option<SocketAddr> {
                None
            }
            fn is_expired(&self) -> bool {
                false
            }
            fn as_turn_client(&self) -> Option<TurnClient> {
                None
            }
        }

        let released = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let released_for_factory = released.clone();
        let factory: TurnFactory = Box::new(move || {
            Ok(Box::new(RecordingHandle {
                released: released_for_factory.clone(),
            }))
        });
        let cfg = section("127.0.0.1:3478".parse().unwrap(), 300);
        let mut mgr = TurnManager::with_factory(Some(cfg), factory);
        mgr.ensure_allocated().expect("allocate should succeed");
        assert!(mgr.is_active());

        mgr.shutdown();
        assert!(
            released.load(Ordering::Relaxed),
            "shutdown must send LIFETIME=0 Deallocate"
        );
        assert_eq!(mgr.state(), TurnState::Disabled);
        assert!(!mgr.is_active());
    }

    /// C2：3-strike 死亡判定时显式释放 Allocation（LIFETIME=0 Deallocate）。
    #[test]
    fn three_strikes_send_deallocate() {
        struct FailingHandle {
            released: Arc<std::sync::atomic::AtomicBool>,
        }
        impl TurnHandle for FailingHandle {
            fn refresh(&self) -> io::Result<()> {
                Err(io::Error::other("turn server unreachable"))
            }
            fn release(&mut self) -> io::Result<()> {
                self.released.store(true, Ordering::Relaxed);
                Ok(())
            }
            fn relayed_addr(&self) -> SocketAddr {
                "192.0.2.1:54320".parse().unwrap()
            }
            fn mapped_addr(&self) -> Option<SocketAddr> {
                None
            }
            fn is_expired(&self) -> bool {
                true
            }
            fn as_turn_client(&self) -> Option<TurnClient> {
                None
            }
        }

        let released = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let released_for_factory = released.clone();
        let factory: TurnFactory = Box::new(move || {
            Ok(Box::new(FailingHandle {
                released: released_for_factory.clone(),
            }))
        });
        let cfg = section("127.0.0.1:3478".parse().unwrap(), 300);
        let mut mgr = TurnManager::with_factory(Some(cfg), factory);
        mgr.ensure_allocated().expect("allocate should succeed");
        assert!(mgr.is_active());

        mgr.next_refresh_at = Some(Instant::now());
        assert_eq!(mgr.refresh_if_needed(), RefreshOutcome::Failed(1));
        assert!(mgr.is_active(), "still warm backup after 1st failure");

        mgr.next_refresh_at = Some(Instant::now());
        assert_eq!(mgr.refresh_if_needed(), RefreshOutcome::Failed(2));
        assert!(mgr.is_active(), "still warm backup after 2nd failure");

        mgr.next_refresh_at = Some(Instant::now());
        assert_eq!(mgr.refresh_if_needed(), RefreshOutcome::Failed(3));
        assert_eq!(mgr.state(), TurnState::Expired);
        assert!(!mgr.is_active());
        assert!(mgr.client.is_none(), "allocation must be released");
        assert!(
            released.load(Ordering::Relaxed),
            "3-strike path must send LIFETIME=0 Deallocate"
        );
        assert_eq!(mgr.refresh_if_needed(), RefreshOutcome::Inactive);
    }
}
