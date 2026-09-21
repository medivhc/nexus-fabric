//! nexus-connectivity
//!
//! 提供 Connectivity Evaluation、Link Establishment、NAT Traversal、Hole Punching、
//! Assisted/Relay Fallback 与 Link State。
//!
//! 本 crate 是 **delivery 层共享底座**（ARCHITECTURE §11 Delivery Infrastructure）：
//! - 保持领域中立：不依赖 `nexus-domain`，不持有 Plan/Session/Provider 等业务对象，
//!   只处理 locator / endpoint / 认证门控等传输语义；
//! - 拒绝反向依赖 Workspace / Compute / Service 业务逻辑；
//! - 规划（Plan）由 Planner 产出，本层只负责"按 locator 建连"并返回状态机结果。
//!
//! 最小闭环（吸收开源标杆 WireGuard 的 W12：认证后才允许建连/改 Locator）：
//! - `establish` 为确定性纯函数，相同输入必然相同输出；
//! - `require_authenticated` 时未认证即失败，不产生任何 Established 状态；
//! - 每次尝试输出结构化事件序列，供 Owner 状态机消费（Worker 只发事件）。
//!
//! 双 trait 解耦（吸收点 W2/W7）：
//! - `ConnectivityRuntime` 注入 `VirtualPacketInterface`（IP 包）与
//!   `PacketCarrier`（承载帧）两个独立 trait，本层只做编排不实现任何一方；
//! - `send_frame` 在 `authenticated=false` 时直接拒绝（W7：未认证前不发送
//!   流量、不改 Locator），且完全不触碰 carrier。
//!
//! 详细边界见同目录 `MODULE.md`。

#![forbid(unsafe_code)]

/// 稳定模块标识；业务实现应通过公开类型/trait 增量加入，而不是扩大隐式全局状态。
pub const NEXUS_CONNECTIVITY_MODULE: &str = "nexus-connectivity";

/// 返回模块的人类可读职责摘要。
#[must_use]
pub const fn module_summary() -> &'static str {
    "提供 Connectivity Evaluation、Link Establishment、NAT Traversal、Hole Punching、Assisted/Relay Fallback 与 Link State。"
}

// ---------- 虚拟子网组网（Virtual Subnet Networking） ----------

pub mod coord;
pub mod nat;
pub mod virtual_subnet;

// ---------- 中继通道（Relay Fallback Channel） ----------

pub mod relay;

// ---------- 链路加密（WireGuard 风格 X25519 + ChaCha20Poly1305） ----------

pub mod encryption;

// ---------- 多跳动态路由（Distance Vector，PRODUCT §12.6） ----------

pub mod routing;

// ---------- Mesh DNS（域名注册与解析） ----------

pub mod mesh_dns;

// ---------- Mesh 防火墙规则匹配引擎（E4：product.firewall-rules） ----------

pub mod firewall;

// ---------- 带宽控制 / QoS 令牌桶限流（E4：product.bandwidth-qos） ----------

pub mod qos;

// ---------- 自动断线重连（指数退避状态机，E4：product.auto-reconnect） ----------

pub mod reconnect;

// ---------- 节点分组标签（打标 + 过滤 + 路由选择，E4：product.node-tags） ----------

pub mod node_tags;

// ---------- 批次2：健康检查 / 节点优先级 / 连接复用（纯逻辑骨架） ----------

/// 连接复用池（idle 复用 + max_total 上限 + idle 超时回收）。
pub mod connection_pool;
/// 节点健康检查（探针状态机：Healthy/Degraded/Unhealthy）。
pub mod health_check;
/// 节点优先级选择器（priority 升序 -> latency 升序 -> bandwidth 降序）。
pub mod node_priority;

// ---------- 结构化错误（不以日志文本代替错误类型） ----------

/// Connectivity 层的结构化错误（delivery 层自有错误面，不依赖领域错误）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectivityError {
    /// 要求认证后才能建立链路（W12：未认证前不发送流量、不改 Locator）。
    AuthenticationRequired {
        /// 目标 locator。
        locator: String,
    },
    /// 目标 locator 无效/为空。
    InvalidLocator { locator: String },
    /// 底层平台/承载 I/O 失败（由 `PlatformError` 映射）。
    Io {
        /// 失败操作名。
        operation: String,
        /// 可诊断原因。
        message: String,
    },
    /// 输入无效（承载/平台层校验失败）。
    Invalid { message: String },
    /// 所有候选链路均不可达（不替换业务 Provider，由 Core Planner 生成替代 Plan）。
    NoLinkAvailable {
        /// 已尝试的候选类型（按激活顺序）。
        attempted: Vec<LinkKind>,
    },
}

impl core::fmt::Display for ConnectivityError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::AuthenticationRequired { locator } => {
                write!(
                    f,
                    "authentication required before establishing link to {locator}"
                )
            }
            Self::InvalidLocator { locator } => {
                write!(f, "invalid locator: {locator:?}")
            }
            Self::Io { operation, message } => {
                write!(f, "connectivity io error during {operation}: {message}")
            }
            Self::Invalid { message } => write!(f, "connectivity invalid input: {message}"),
            Self::NoLinkAvailable { attempted } => write!(
                f,
                "no link available after attempting: {}",
                attempted
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }
    }
}

impl std::error::Error for ConnectivityError {}

// ---------- 状态机与事件 ----------

/// Connectivity 链路状态（每 Session 一份，由 Owner/编排层持有）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectivityState {
    /// 尚未尝试建连。
    NotAttempted,
    /// 建连进行中。
    Establishing,
    /// 已建立（认证完成时为 `true`）。
    Established {
        /// 是否已完成认证（W12：认证后才允许流量/改 Locator）。
        authenticated: bool,
    },
    /// 建连失败（结构化原因）。
    Failed {
        /// 失败原因。
        error: ConnectivityError,
    },
}

/// 建连请求（领域中立：仅含关联标识、locator 与认证门控）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EstablishmentRequest {
    /// 关联标识（编排层传入 SessionId 的字符串形式，用于事件关联）。
    pub session_tag: String,
    /// 目标出口 locator（对应 Plan.path 的 locator）。
    pub locator: String,
    /// 是否要求认证后才允许建连。
    pub require_authenticated: bool,
    /// 当前认证状态（由编排层/平台注入事实）。
    pub authenticated: bool,
}

impl EstablishmentRequest {
    /// 构造建连请求。
    #[must_use]
    pub fn new(
        session_tag: impl Into<String>,
        locator: impl Into<String>,
        require_authenticated: bool,
        authenticated: bool,
    ) -> Self {
        Self {
            session_tag: session_tag.into(),
            locator: locator.into(),
            require_authenticated,
            authenticated,
        }
    }
}

/// 建连过程的结构化事件（Worker 只发事件，不直接改 Owner Outcome）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectivityEvent {
    /// 开始尝试建连。
    Establishing {
        session_tag: String,
        locator: String,
    },
    /// 认证通过。
    Authenticated {
        session_tag: String,
        locator: String,
    },
    /// 链路建立成功。
    Established {
        session_tag: String,
        locator: String,
    },
    /// 建连失败。
    Failed {
        session_tag: String,
        locator: String,
        error: ConnectivityError,
    },
}

/// 建连结果：最终状态 + 完整事件序列（可重放、可 explain）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EstablishmentResult {
    /// 最终链路状态。
    pub state: ConnectivityState,
    /// 完整事件序列。
    pub events: Vec<ConnectivityEvent>,
}

// ---------- 确定性建连（吸收点 W12） ----------

/// 对给定请求执行确定性建连评估（纯函数，零 I/O）。
///
/// 规则：
/// 1. locator 为空 → `Failed(InvalidLocator)`；
/// 2. `require_authenticated` 且未认证 → `Failed(AuthenticationRequired)`
///    （W12：未认证前不发送流量、不改 Locator，绝不进入 Established）；
/// 3. 认证满足（或无需认证）→ 按序产出 Establishing →（Authenticated）→ Established。
#[must_use]
pub fn establish(request: &EstablishmentRequest) -> EstablishmentResult {
    let tag = request.session_tag.clone();
    let loc = request.locator.clone();

    if loc.is_empty() {
        let error = ConnectivityError::InvalidLocator {
            locator: loc.clone(),
        };
        return EstablishmentResult {
            state: ConnectivityState::Failed {
                error: error.clone(),
            },
            events: vec![ConnectivityEvent::Failed {
                session_tag: tag,
                locator: loc,
                error,
            }],
        };
    }

    let mut events = vec![ConnectivityEvent::Establishing {
        session_tag: tag.clone(),
        locator: loc.clone(),
    }];

    if request.require_authenticated && !request.authenticated {
        let error = ConnectivityError::AuthenticationRequired {
            locator: loc.clone(),
        };
        events.push(ConnectivityEvent::Failed {
            session_tag: tag,
            locator: loc,
            error: error.clone(),
        });
        return EstablishmentResult {
            state: ConnectivityState::Failed { error },
            events,
        };
    }

    if request.authenticated {
        events.push(ConnectivityEvent::Authenticated {
            session_tag: tag.clone(),
            locator: loc.clone(),
        });
    }
    events.push(ConnectivityEvent::Established {
        session_tag: tag.clone(),
        locator: loc.clone(),
    });
    EstablishmentResult {
        state: ConnectivityState::Established {
            authenticated: request.authenticated,
        },
        events,
    }
}

// ---------- 双 trait 编排（吸收点 W2/W7） ----------

use nexus_platform::{PacketCarrier, PlatformError, VirtualPacketInterface};

/// 双 trait 注入的 Connectivity 编排器。
///
/// W2（WireGuard `tun.Device` / `conn.Bind` 解耦）：
/// - `vpi` 只负责 IP 包读/写（`VirtualPacketInterface`）；
/// - `carrier` 只负责封装帧收发（`PacketCarrier`）；
/// - 本类型只做编排与门控，不实现任何一方。
///
/// W7（认证后才允许触碰对端）：
/// - `send_frame(..., authenticated=false)` 直接返回 `AuthenticationRequired`，
///   且**不调用** carrier 的 `send_to`（未认证流量零发送）。
pub struct ConnectivityRuntime {
    vpi: Box<dyn VirtualPacketInterface>,
    carrier: Box<dyn PacketCarrier>,
}

impl ConnectivityRuntime {
    /// 注入 VPI 与 Carrier（两者解耦，可独立替换/测试替身）。
    #[must_use]
    pub fn new(vpi: Box<dyn VirtualPacketInterface>, carrier: Box<dyn PacketCarrier>) -> Self {
        Self { vpi, carrier }
    }

    /// 只读访问注入的 VPI（不转移所有权）。
    pub fn vpi(&mut self) -> &mut dyn VirtualPacketInterface {
        self.vpi.as_mut()
    }

    /// 只读访问注入的 Carrier（不转移所有权）。
    pub fn carrier(&mut self) -> &mut dyn PacketCarrier {
        self.carrier.as_mut()
    }

    /// 绑定承载本地地址/端口；返回本地 locator。
    pub fn bind_local(&mut self, local_locator: &str) -> Result<String, ConnectivityError> {
        self.carrier.bind(local_locator).map_err(map_platform_error)
    }

    /// 仅认证通过后向对端发送一帧封装数据（W7 门控）。
    ///
    /// `authenticated=false` 时返回 `AuthenticationRequired`，不触碰 carrier。
    pub fn send_frame(
        &mut self,
        peer_locator: &str,
        frame: &[u8],
        authenticated: bool,
    ) -> Result<(), ConnectivityError> {
        if !authenticated {
            return Err(ConnectivityError::AuthenticationRequired {
                locator: peer_locator.to_string(),
            });
        }
        if peer_locator.is_empty() {
            return Err(ConnectivityError::InvalidLocator {
                locator: String::new(),
            });
        }
        self.carrier
            .send_to(peer_locator, frame)
            .map_err(map_platform_error)
    }

    /// 接收一帧封装数据（委托 carrier；无数据返回 `Ok(0)`）。
    pub fn receive_frame(&mut self, output: &mut [u8]) -> Result<usize, ConnectivityError> {
        self.carrier
            .receive_into(output)
            .map_err(map_platform_error)
    }

    /// 从 VPI 读取一个 IP 包（委托 vpi；不含加密/建连）。
    pub fn read_ip_packet(&mut self, output: &mut [u8]) -> Result<usize, ConnectivityError> {
        self.vpi.receive(output).map_err(map_platform_error)
    }

    /// 向 VPI 写入一个 IP 包（委托 vpi）。
    pub fn write_ip_packet(&mut self, packet: &[u8]) -> Result<(), ConnectivityError> {
        self.vpi.send(packet).map_err(map_platform_error)
    }

    /// 当前承载本地 locator。
    #[must_use]
    pub fn local_locator(&self) -> Option<String> {
        self.carrier.local_locator()
    }
}

/// `PlatformError` → `ConnectivityError` 映射（结构化、保留可诊断原因）。
fn map_platform_error(e: PlatformError) -> ConnectivityError {
    match e {
        PlatformError::Io { operation, message } => ConnectivityError::Io { operation, message },
        PlatformError::Invalid { message } => ConnectivityError::Invalid { message },
        PlatformError::Unavailable { capability } => ConnectivityError::Io {
            operation: "capability".to_string(),
            message: format!("unavailable: {capability}"),
        },
        PlatformError::NotFound { key } => ConnectivityError::Io {
            operation: "lookup".to_string(),
            message: format!("not found: {key}"),
        },
    }
}

// ---------- 链路激活：Direct -> Relay Fallback（v9 §239/§243 P0 子集） ----------

/// 候选链路类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LinkKind {
    /// 直连（LAN / IPv6 / Public Endpoint）。
    Direct,
    /// 经中继（DERP 类）。NAT 场景回退路径。
    Relay,
}

impl core::fmt::Display for LinkKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Direct => f.write_str("direct"),
            Self::Relay => f.write_str("relay"),
        }
    }
}

/// 领域中立候选链路（激活顺序输入，v9 §239：成本/可达性用于选择）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkCandidate {
    /// 候选类型。
    pub kind: LinkKind,
    /// 出口 locator。
    pub locator: String,
    /// 预估建连成本（毫秒；由 Evaluation 输入，激活器只做顺序决策）。
    pub setup_cost_ms: u64,
}

impl LinkCandidate {
    /// 构造候选链路。
    #[must_use]
    pub fn new(kind: LinkKind, locator: impl Into<String>, setup_cost_ms: u64) -> Self {
        Self {
            kind,
            locator: locator.into(),
            setup_cost_ms,
        }
    }
}

/// 候选可达性探测（由 Composition Root 以真实 I/O 实现；Connectivity 只做策略编排，零 I/O）。
pub trait LinkProbe {
    /// 探测候选可达性；`Ok(())` 表示可达，`Err(reason)` 保留失败原因。
    fn probe(&self, candidate: &LinkCandidate) -> Result<(), String>;
}

/// 链路激活过程事件（Worker 只发事件，不直接修改 Owner Outcome）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkActivationEvent {
    /// 开始尝试某类候选。
    Attempting { kind: LinkKind, locator: String },
    /// 该候选不可达（保留原因，供 explain/replay）。
    AttemptFailed {
        kind: LinkKind,
        locator: String,
        reason: String,
    },
    /// 选中并建立某类链路。
    Established { kind: LinkKind, locator: String },
}

/// 链路激活结果：选中链路 + 完整事件序列（可重放、可 explain）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkSelection {
    /// 最终选中链路类型。
    pub kind: LinkKind,
    /// 选中链路的 locator（物理建连目标）。
    pub locator: String,
    /// 完整激活事件序列。
    pub events: Vec<LinkActivationEvent>,
}

/// 链路激活器：按 v9 §243 激活顺序（Direct -> Relay Fallback）决策。
///
/// 规则：
/// 1. 认证门控（W12）：`require_authenticated` 且未认证 -> `AuthenticationRequired`，
///    在任何探测之前拦截（未认证零探测、零发送）；
/// 2. Direct 探测成功 -> 选中 Direct；
/// 3. Direct 失败且提供 Relay 候选 -> 尝试 Relay；成功 -> 选中 Relay；
/// 4. 全部失败 -> `NoLinkAvailable { attempted }`（不替换业务 Provider）。
pub struct LinkActivator<P: LinkProbe> {
    probe: P,
}

impl<P: LinkProbe> LinkActivator<P> {
    /// 注入可达性探测（真实 I/O 由组合根提供）。
    #[must_use]
    pub fn new(probe: P) -> Self {
        Self { probe }
    }

    /// 按序激活候选链路并返回选中结果。
    ///
    /// `direct` 必须存在；`relay` 为可选回退候选（NAT 场景提供）。
    pub fn activate(
        &self,
        direct: &LinkCandidate,
        relay: Option<&LinkCandidate>,
        require_authenticated: bool,
        authenticated: bool,
    ) -> Result<LinkSelection, ConnectivityError> {
        if require_authenticated && !authenticated {
            return Err(ConnectivityError::AuthenticationRequired {
                locator: direct.locator.clone(),
            });
        }

        let mut events = Vec::new();

        // 1) Direct
        events.push(LinkActivationEvent::Attempting {
            kind: LinkKind::Direct,
            locator: direct.locator.clone(),
        });
        match self.probe.probe(direct) {
            Ok(()) => {
                events.push(LinkActivationEvent::Established {
                    kind: LinkKind::Direct,
                    locator: direct.locator.clone(),
                });
                return Ok(LinkSelection {
                    kind: LinkKind::Direct,
                    locator: direct.locator.clone(),
                    events,
                });
            }
            Err(reason) => {
                events.push(LinkActivationEvent::AttemptFailed {
                    kind: LinkKind::Direct,
                    locator: direct.locator.clone(),
                    reason,
                });
            }
        }

        // 2) Relay fallback
        let mut attempted = vec![LinkKind::Direct];
        if let Some(relay) = relay {
            events.push(LinkActivationEvent::Attempting {
                kind: LinkKind::Relay,
                locator: relay.locator.clone(),
            });
            match self.probe.probe(relay) {
                Ok(()) => {
                    events.push(LinkActivationEvent::Established {
                        kind: LinkKind::Relay,
                        locator: relay.locator.clone(),
                    });
                    return Ok(LinkSelection {
                        kind: LinkKind::Relay,
                        locator: relay.locator.clone(),
                        events,
                    });
                }
                Err(reason) => {
                    attempted.push(LinkKind::Relay);
                    events.push(LinkActivationEvent::AttemptFailed {
                        kind: LinkKind::Relay,
                        locator: relay.locator.clone(),
                        reason,
                    });
                }
            }
        }

        Err(ConnectivityError::NoLinkAvailable { attempted })
    }
}

// ---------- OutboundAdapter 接缝（PRODUCT §11.6） ----------

/// 出站交接结果（离线 DTO，零真实网络）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundHandoff {
    /// 出站 kind 标签（"direct" / "relay" / "shadowsocks"）。
    pub kind: String,
    /// 出站 tag。
    pub tag: String,
    /// 物理目标 locator。
    pub locator: String,
}

/// 出站 adapter：一种真实的出站协议实现（Direct / Relay / Shadowsocks）。
///
/// 领域中立接缝：只暴露出站标识与离线交接语义；真实加密/建连由各实现与
/// Composition Root 完成。Deletion Test（AGENTS.md §12）：Shadowsocks 是首个带
/// 真实 AEAD 加解密的出站，与仅做可达性探测的 Direct/Relay 构成独立变化维度。
pub trait OutboundAdapter {
    /// 稳定出站 kind 标签。
    fn outbound_kind(&self) -> &'static str;
    /// 出站标识 tag。
    fn tag(&self) -> &str;
    /// 离线交接：确认该 adapter 可承接目标 locator（不发起真实网络）。
    fn handoff(&self, locator: &str) -> Result<OutboundHandoff, ConnectivityError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authenticated_link_establishes_with_event_sequence() {
        let req = EstablishmentRequest::new("s1", "edge-a.exit", true, true);
        let out = establish(&req);
        assert_eq!(
            out.state,
            ConnectivityState::Established {
                authenticated: true
            }
        );
        assert_eq!(out.events.len(), 3);
        assert!(matches!(
            &out.events[0],
            ConnectivityEvent::Establishing { locator, .. } if locator == "edge-a.exit"
        ));
        assert!(matches!(
            &out.events[1],
            ConnectivityEvent::Authenticated { .. }
        ));
        assert!(matches!(
            &out.events[2],
            ConnectivityEvent::Established { .. }
        ));
    }

    #[test]
    fn unauthenticated_required_link_fails_before_established() {
        let req = EstablishmentRequest::new("s2", "relay-b.exit", true, false);
        let out = establish(&req);
        assert!(matches!(
            out.state,
            ConnectivityState::Failed {
                error: ConnectivityError::AuthenticationRequired { .. }
            }
        ));
        // 绝不进入 Established；失败事件位于序列末尾。
        assert!(
            out.events
                .iter()
                .all(|e| !matches!(e, ConnectivityEvent::Established { .. }))
        );
        assert!(matches!(
            out.events.last(),
            Some(ConnectivityEvent::Failed { .. })
        ));
    }

    #[test]
    fn no_auth_requirement_establishes_without_authenticated_event() {
        let req = EstablishmentRequest::new("s3", "edge-a.exit", false, false);
        let out = establish(&req);
        assert_eq!(
            out.state,
            ConnectivityState::Established {
                authenticated: false
            }
        );
        assert_eq!(out.events.len(), 2); // Establishing + Established
        assert!(
            out.events
                .iter()
                .all(|e| !matches!(e, ConnectivityEvent::Authenticated { .. }))
        );
    }

    #[test]
    fn empty_locator_fails_with_invalid_locator() {
        let req = EstablishmentRequest::new("s4", "", true, true);
        let out = establish(&req);
        assert!(matches!(
            out.state,
            ConnectivityState::Failed {
                error: ConnectivityError::InvalidLocator { .. }
            }
        ));
        assert_eq!(out.events.len(), 1);
    }

    #[test]
    fn establishment_is_deterministic() {
        let req = EstablishmentRequest::new("s5", "edge-a.exit", true, true);
        assert_eq!(establish(&req), establish(&req));
    }

    #[test]
    fn display_is_structured_not_panic_text() {
        let err = ConnectivityError::AuthenticationRequired {
            locator: "x.exit".into(),
        };
        assert!(err.to_string().contains("authentication required"));
    }

    // ---------- ConnectivityRuntime 双 trait 编排（W2/W7） ----------

    use std::sync::{Arc, Mutex};

    /// 已发送帧的共享记录（peer, frame）。
    type SentFrames = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

    /// 内存 mock VPI：写进 buffer 的包可被读回（共享状态供断言）。
    struct MockVpi {
        packets: Vec<Vec<u8>>,
        written: Arc<Mutex<usize>>,
    }

    impl MockVpi {
        fn new() -> Self {
            Self {
                packets: Vec::new(),
                written: Arc::new(Mutex::new(0)),
            }
        }
    }

    impl VirtualPacketInterface for MockVpi {
        fn receive(&mut self, output: &mut [u8]) -> Result<usize, PlatformError> {
            match self.packets.pop() {
                Some(p) if p.len() <= output.len() => {
                    output[..p.len()].copy_from_slice(&p);
                    Ok(p.len())
                }
                Some(_) => Err(PlatformError::Invalid {
                    message: "mock buffer too small".into(),
                }),
                None => Ok(0),
            }
        }
        fn send(&mut self, packet: &[u8]) -> Result<(), PlatformError> {
            *self.written.lock().unwrap() += 1;
            self.packets.push(packet.to_vec());
            Ok(())
        }
    }

    /// 内存 mock carrier：记录帧与本地 locator（共享状态供断言）。
    struct MockCarrier {
        local: Arc<Mutex<Option<String>>>,
        sent: SentFrames,
        inbound: Vec<Vec<u8>>,
    }

    impl MockCarrier {
        fn new() -> Self {
            Self {
                local: Arc::new(Mutex::new(None)),
                sent: Arc::new(Mutex::new(Vec::new())),
                inbound: Vec::new(),
            }
        }
    }

    impl PacketCarrier for MockCarrier {
        fn bind(&mut self, local: &str) -> Result<String, PlatformError> {
            *self.local.lock().unwrap() = Some(local.to_string());
            Ok(local.to_string())
        }
        fn send_to(&mut self, peer: &str, frame: &[u8]) -> Result<(), PlatformError> {
            self.sent
                .lock()
                .unwrap()
                .push((peer.to_string(), frame.to_vec()));
            Ok(())
        }
        fn receive_into(&mut self, output: &mut [u8]) -> Result<usize, PlatformError> {
            match self.inbound.pop() {
                Some(f) if f.len() <= output.len() => {
                    output[..f.len()].copy_from_slice(&f);
                    Ok(f.len())
                }
                Some(_) => Err(PlatformError::Invalid {
                    message: "mock inbound too large".into(),
                }),
                None => Ok(0),
            }
        }
        fn local_locator(&self) -> Option<String> {
            self.local.lock().unwrap().clone()
        }
    }

    #[test]
    fn runtime_binds_local_and_reports_locator() {
        let mut rt =
            ConnectivityRuntime::new(Box::new(MockVpi::new()), Box::new(MockCarrier::new()));
        let loc = rt.bind_local("0.0.0.0:51820").unwrap();
        assert_eq!(loc, "0.0.0.0:51820");
        assert_eq!(rt.local_locator().as_deref(), Some("0.0.0.0:51820"));
    }

    #[test]
    fn send_frame_blocks_unauthenticated_without_touching_carrier() {
        let carrier = MockCarrier::new();
        let sent = Arc::clone(&carrier.sent);
        let mut rt = ConnectivityRuntime::new(Box::new(MockVpi::new()), Box::new(carrier));
        let err = rt.send_frame("peer.exit", b"handshake", false).unwrap_err();
        assert!(matches!(
            err,
            ConnectivityError::AuthenticationRequired { .. }
        ));
        // W7：未认证不触碰 carrier（零发送）。
        assert_eq!(sent.lock().unwrap().len(), 0);
    }

    #[test]
    fn send_frame_authenticated_reaches_carrier() {
        let carrier = MockCarrier::new();
        let sent = Arc::clone(&carrier.sent);
        let mut rt = ConnectivityRuntime::new(Box::new(MockVpi::new()), Box::new(carrier));
        rt.send_frame("peer.exit", b"encrypted-frame", true)
            .unwrap();
        let sent = sent.lock().unwrap();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0, "peer.exit");
        assert_eq!(sent[0].1, b"encrypted-frame");
    }

    #[test]
    fn send_frame_empty_peer_fails_invalid_locator() {
        let carrier = MockCarrier::new();
        let sent = Arc::clone(&carrier.sent);
        let mut rt = ConnectivityRuntime::new(Box::new(MockVpi::new()), Box::new(carrier));
        let err = rt.send_frame("", b"x", true).unwrap_err();
        assert!(matches!(err, ConnectivityError::InvalidLocator { .. }));
        assert_eq!(sent.lock().unwrap().len(), 0);
    }

    #[test]
    fn vpi_and_carrier_roundtrip_are_independent() {
        let carrier = MockCarrier::new();
        let sent = Arc::clone(&carrier.sent);
        let mut rt = ConnectivityRuntime::new(Box::new(MockVpi::new()), Box::new(carrier));
        // IP 包走 VPI（不经过 carrier）。
        rt.write_ip_packet(&[0x45, 0x00, 0x00, 0x14]).unwrap();
        let mut ip = [0u8; 32];
        let n = rt.read_ip_packet(&mut ip).unwrap();
        assert_eq!(&ip[..n], &[0x45, 0x00, 0x00, 0x14]);
        // 承载帧走 carrier（不经过 VPI）。
        rt.send_frame("peer.exit", b"frame", true).unwrap();
        assert_eq!(sent.lock().unwrap().len(), 1);
    }

    #[test]
    fn platform_io_error_maps_to_connectivity_io() {
        let err = map_platform_error(PlatformError::Io {
            operation: "send_to".into(),
            message: "network unreachable".into(),
        });
        match err {
            ConnectivityError::Io { operation, message } => {
                assert_eq!(operation, "send_to");
                assert_eq!(message, "network unreachable");
            }
            other => panic!("expected Io, got {other:?}"),
        }
    }

    #[test]
    fn platform_invalid_maps_to_connectivity_invalid() {
        let err = map_platform_error(PlatformError::Invalid {
            message: "bad frame".into(),
        });
        assert!(matches!(err, ConnectivityError::Invalid { .. }));
    }
    // ---------- Link Activator ----------

    /// 可编程探测替身：按候选类型返回预置结果。
    struct MockProbe {
        results: std::collections::HashMap<LinkKind, Result<(), String>>,
    }

    impl MockProbe {
        fn new(results: std::collections::HashMap<LinkKind, Result<(), String>>) -> Self {
            Self { results }
        }
    }

    impl LinkProbe for MockProbe {
        fn probe(&self, candidate: &LinkCandidate) -> Result<(), String> {
            self.results
                .get(&candidate.kind)
                .cloned()
                .unwrap_or_else(|| Err("no result configured".into()))
        }
    }

    fn candidate(kind: LinkKind, locator: &str) -> LinkCandidate {
        LinkCandidate::new(kind, locator, 10)
    }

    #[test]
    fn direct_ok_selects_direct_without_probing_relay() {
        let mut results = std::collections::HashMap::new();
        results.insert(LinkKind::Direct, Ok(()));
        // Relay 无结果配置：若被探测将失败，用于验证未被触碰。
        let activator = LinkActivator::new(MockProbe::new(results));
        let direct = candidate(LinkKind::Direct, "edge-a.exit");
        let relay = candidate(LinkKind::Relay, "relay-a.exit");
        let sel = activator
            .activate(&direct, Some(&relay), false, false)
            .expect("direct ok");
        assert_eq!(sel.kind, LinkKind::Direct);
        assert_eq!(sel.locator, "edge-a.exit");
        assert_eq!(sel.events.len(), 2); // Attempting + Established
        assert!(matches!(
            sel.events.last(),
            Some(LinkActivationEvent::Established {
                kind: LinkKind::Direct,
                ..
            })
        ));
    }

    #[test]
    fn direct_fail_relay_ok_selects_relay() {
        let mut results = std::collections::HashMap::new();
        results.insert(LinkKind::Direct, Err("nat unreachable".into()));
        results.insert(LinkKind::Relay, Ok(()));
        let activator = LinkActivator::new(MockProbe::new(results));
        let direct = candidate(LinkKind::Direct, "10.0.0.5:4242");
        let relay = candidate(LinkKind::Relay, "relay-a.exit");
        let sel = activator
            .activate(&direct, Some(&relay), false, false)
            .expect("relay ok");
        assert_eq!(sel.kind, LinkKind::Relay);
        assert_eq!(sel.locator, "relay-a.exit");
        // Attempting Direct, AttemptFailed Direct, Attempting Relay, Established Relay
        assert_eq!(sel.events.len(), 4);
        assert!(matches!(
            sel.events[1],
            LinkActivationEvent::AttemptFailed { kind: LinkKind::Direct, ref reason, .. } if reason == "nat unreachable"
        ));
        assert!(matches!(
            sel.events.last(),
            Some(LinkActivationEvent::Established {
                kind: LinkKind::Relay,
                ..
            })
        ));
    }

    #[test]
    fn direct_fail_no_relay_is_no_link_available() {
        let mut results = std::collections::HashMap::new();
        results.insert(LinkKind::Direct, Err("connection refused".into()));
        let activator = LinkActivator::new(MockProbe::new(results));
        let direct = candidate(LinkKind::Direct, "10.0.0.5:4242");
        let err = activator
            .activate(&direct, None, false, false)
            .expect_err("must fail");
        match err {
            ConnectivityError::NoLinkAvailable { attempted } => {
                assert_eq!(attempted, vec![LinkKind::Direct]);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn both_fail_is_no_link_available_with_full_attempt_list() {
        let mut results = std::collections::HashMap::new();
        results.insert(LinkKind::Direct, Err("nat unreachable".into()));
        results.insert(LinkKind::Relay, Err("relay down".into()));
        let activator = LinkActivator::new(MockProbe::new(results));
        let direct = candidate(LinkKind::Direct, "10.0.0.5:4242");
        let relay = candidate(LinkKind::Relay, "relay-a.exit");
        let err = activator
            .activate(&direct, Some(&relay), false, false)
            .expect_err("must fail");
        match err {
            ConnectivityError::NoLinkAvailable { attempted } => {
                assert_eq!(attempted, vec![LinkKind::Direct, LinkKind::Relay]);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn auth_gate_blocks_before_any_probe() {
        let mut results = std::collections::HashMap::new();
        results.insert(LinkKind::Direct, Ok(()));
        let activator = LinkActivator::new(MockProbe::new(results));
        let direct = candidate(LinkKind::Direct, "edge-a.exit");
        let relay = candidate(LinkKind::Relay, "relay-a.exit");
        let err = activator
            .activate(&direct, Some(&relay), true, false)
            .expect_err("auth must gate");
        assert!(matches!(
            err,
            ConnectivityError::AuthenticationRequired { ref locator } if locator == "edge-a.exit"
        ));
    }
}
