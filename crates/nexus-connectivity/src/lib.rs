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
}
