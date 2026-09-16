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
}
