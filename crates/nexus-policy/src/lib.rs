//! nexus-policy
//!
//! 把 Flow / Resource Context 展开为 Intent + Constraint。
//! Policy != Path：本 crate 不选择协议、Path 或最终 Provider，也不执行 I/O。
//! 未知画像/主体必须显式表达，不伪造默认身份。
//!
//! 求值模型（吸收开源标杆 sing-box 的"动作化有序管线"）：
//! - 策略是**有序动作链**：规则按序匹配，**首匹配即终止**，规则顺序即语义；
//! - 非终态动作（`AddConstraint` / `EnrichMetadata`）边执行边累积副作用；
//! - 终态动作（`SelectProvider` / `Reject`）执行后立即终止，产出终局决策；
//! - 每次求值记录完整 trace，可重放、可 explain。
//!
//! 本 crate 是 Portable Core：纯函数、零 I/O、零第三方依赖，可编译到 WASI。
//! 详细边界见同目录 `MODULE.md`。

#![forbid(unsafe_code)]

use nexus_domain::{Constraint, FlowContext, Intent};

/// 稳定模块标识；业务实现应通过公开类型/trait 增量加入，而不是扩大隐式全局状态。
pub const NEXUS_POLICY_MODULE: &str = "nexus-policy";

/// 返回模块的人类可读职责摘要。
#[must_use]
pub const fn module_summary() -> &'static str {
    "把 Flow/Resource Context 展开为 Intent 与 Constraint（不选择 Path/Provider）。"
}

/// 资源要求 Provider 必须广告的能力约束键。
pub const CONSTRAINT_CAPABILITY: &str = "capability";
/// Exit-DNS Binding 约束键（NetworkPlanExtension 消费）。
pub const CONSTRAINT_EXIT_DNS: &str = "exit-dns";
/// 显式授权约束键（PRODUCT §3：非 loopback 监听必须显式授权）。
pub const CONSTRAINT_AUTHORIZATION: &str = "authorization";
/// InternetAccess 能力值。
pub const CAPABILITY_INTERNET_ACCESS: &str = "internet-access";
/// Nexus-aware Service Session 能力值。
pub const CAPABILITY_SERVICE_SESSION: &str = "service-session";
/// 远程 Compute Job 执行能力值（PRODUCT §6，remote P0 扩展）。
pub const CAPABILITY_COMPUTE_JOB: &str = "compute-job";
// ---------- 动作化有序链（吸收点 S1/S2/S7） ----------

/// 策略动作。
///
/// - 非终态动作执行后继续同一规则的后续动作；
/// - 终态动作（`SelectProvider` / `Reject`）执行后立即终止规则链（后续规则不再尝试）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyAction {
    /// 非终态：追加一条硬约束（进入决策的 constraints）。
    AddConstraint { key: String, value: String },
    /// 非终态：附加结构化元数据（如 S7 sniff 补全的域名；不进 Planner 约束集）。
    EnrichMetadata { key: String, value: String },
    /// 终态：选择 Provider 必须具备的能力（可选 Exit-DNS 绑定）。
    SelectProvider {
        capability: String,
        exit_dns: Option<String>,
    },
    /// 终态：拒绝该流量，记录结构化原因。
    Reject { reason: String },
}

impl PolicyAction {
    /// 是否终态动作（终态动作执行后规则链终止）。
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::SelectProvider { .. } | Self::Reject { .. })
    }
}

/// 规则匹配条件：所有字段均为可选约束，`None` 表示该维度不限制。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PolicyMatch {
    /// 画像精确匹配。
    pub profile_eq: Option<String>,
    /// 目标前缀匹配（如 `https://`）。
    pub destination_prefix: Option<String>,
}

impl PolicyMatch {
    /// 是否匹配该 Flow。
    #[must_use]
    pub fn matches(&self, flow: &FlowContext) -> bool {
        self.profile_eq.as_ref().is_none_or(|p| flow.profile == *p)
            && self
                .destination_prefix
                .as_ref()
                .is_none_or(|d| flow.destination.starts_with(d))
    }
}

/// 单条策略规则：匹配条件 + 有序动作列表。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRule {
    /// 规则标识（用于 explain/trace）。
    pub id: String,
    /// 匹配条件。
    pub match_: PolicyMatch,
    /// 按序执行的动作链。
    pub actions: Vec<PolicyAction>,
}

/// 决策轨迹条目：记录命中的规则与已执行动作（支持 explain / replay）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyTraceEntry {
    /// 命中的规则索引（0-based）。
    pub rule_index: usize,
    /// 动作在规则内的索引。
    pub action_index: usize,
    /// 已执行的动作。
    pub action: PolicyAction,
}

/// 策略求值结果：决策 + 轨迹；`rejected` 为 `Some` 时表示终态拒绝。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyResult {
    /// 决策（intent + 有序 constraints + 元数据）。
    pub decision: PolicyDecision,
    /// 完整决策轨迹。
    pub trace: Vec<PolicyTraceEntry>,
    /// 终态拒绝原因；`None` 表示未被拒绝。
    pub rejected: Option<String>,
}

// ---------- 决策产物 ----------

/// Policy 决策产物：意图 + 约束集（交给唯一 Core Planner 求解）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyDecision {
    /// 展开后的意图（携带使用画像）。
    pub intent: Intent,
    /// 约束的有序集合（顺序确定，便于重放）。
    pub constraints: Vec<Constraint>,
    /// 非终态动作累积的结构化元数据（如 sniff 补全的域名）。
    pub metadata: Vec<(String, String)>,
}

// ---------- 引擎 ----------

/// 动作化策略引擎：有序规则列表，首匹配即终止，产出确定性决策 + trace。
#[derive(Debug, Clone, Default)]
pub struct PolicyEngine {
    rules: Vec<PolicyRule>,
}

impl PolicyEngine {
    /// 使用显式规则列表构造引擎。
    #[must_use]
    pub fn new(rules: Vec<PolicyRule>) -> Self {
        Self { rules }
    }

    /// 默认 Network 策略：任何 Flow 要求 `internet-access` 能力 + Exit-DNS 绑定。
    #[must_use]
    pub fn default_network() -> Self {
        Self::new(vec![PolicyRule {
            id: "default-network".into(),
            match_: PolicyMatch::default(),
            actions: vec![PolicyAction::SelectProvider {
                capability: CAPABILITY_INTERNET_ACCESS.into(),
                exit_dns: Some("bound".into()),
            }],
        }])
    }

    /// 默认 Service 策略：要求 `service-session` 能力 + 显式授权（PRODUCT §3）。
    ///
    /// 动作顺序即产出顺序：先累积 `authorization` 约束，再以终态动作选择 Provider。
    #[must_use]
    pub fn default_service() -> Self {
        Self::new(vec![PolicyRule {
            id: "default-service".into(),
            match_: PolicyMatch::default(),
            actions: vec![
                PolicyAction::AddConstraint {
                    key: CONSTRAINT_AUTHORIZATION.into(),
                    value: "explicit".into(),
                },
                PolicyAction::SelectProvider {
                    capability: CAPABILITY_SERVICE_SESSION.into(),
                    exit_dns: None,
                },
            ],
        }])
    }

    /// 默认 Compute 策略：要求 `compute-job` 能力 + 显式授权（PRODUCT §2/§6，remote P0 扩展）。
    ///
    /// 动作顺序即产出顺序：先累积 `authorization` 约束，再以终态动作选择远程执行器。
    #[must_use]
    pub fn default_compute() -> Self {
        Self::new(vec![PolicyRule {
            id: "default-compute".into(),
            match_: PolicyMatch::default(),
            actions: vec![
                PolicyAction::AddConstraint {
                    key: CONSTRAINT_AUTHORIZATION.into(),
                    value: "explicit".into(),
                },
                PolicyAction::SelectProvider {
                    capability: CAPABILITY_COMPUTE_JOB.into(),
                    exit_dns: None,
                },
            ],
        }])
    }

    /// 求值：首条命中规则执行其动作链；终态动作后立即终止。
    ///
    /// 纯函数：相同输入必然得到相同输出（可重放）。
    #[must_use]
    pub fn evaluate(&self, flow: &FlowContext) -> PolicyResult {
        let mut constraints: Vec<Constraint> = Vec::new();
        let mut metadata: Vec<(String, String)> = Vec::new();
        let mut trace: Vec<PolicyTraceEntry> = Vec::new();
        let mut rejected: Option<String> = None;

        for (rule_index, rule) in self.rules.iter().enumerate() {
            if !rule.match_.matches(flow) {
                continue;
            }
            for (action_index, action) in rule.actions.iter().enumerate() {
                let entry = PolicyTraceEntry {
                    rule_index,
                    action_index,
                    action: action.clone(),
                };
                match action {
                    PolicyAction::AddConstraint { key, value } => {
                        constraints.push(Constraint {
                            key: key.clone(),
                            value: value.clone(),
                        });
                        trace.push(entry);
                    }
                    PolicyAction::EnrichMetadata { key, value } => {
                        metadata.push((key.clone(), value.clone()));
                        trace.push(entry);
                    }
                    PolicyAction::SelectProvider {
                        capability,
                        exit_dns,
                    } => {
                        constraints.push(Constraint {
                            key: CONSTRAINT_CAPABILITY.into(),
                            value: capability.clone(),
                        });
                        if let Some(dns) = exit_dns {
                            constraints.push(Constraint {
                                key: CONSTRAINT_EXIT_DNS.into(),
                                value: dns.clone(),
                            });
                        }
                        trace.push(entry);
                        return PolicyResult {
                            decision: Self::decision(flow, constraints, metadata),
                            trace,
                            rejected: None,
                        };
                    }
                    PolicyAction::Reject { reason } => {
                        trace.push(entry);
                        rejected = Some(reason.clone());
                        return PolicyResult {
                            decision: Self::decision(flow, constraints, metadata),
                            trace,
                            rejected,
                        };
                    }
                }
            }
            // 命中规则执行完毕（无终态动作）：首匹配即终止，不继续后续规则。
            return PolicyResult {
                decision: Self::decision(flow, constraints, metadata),
                trace,
                rejected,
            };
        }

        // 无规则命中：返回空约束决策（不伪造默认选择）。
        PolicyResult {
            decision: Self::decision(flow, constraints, metadata),
            trace,
            rejected,
        }
    }

    fn decision(
        flow: &FlowContext,
        constraints: Vec<Constraint>,
        metadata: Vec<(String, String)>,
    ) -> PolicyDecision {
        PolicyDecision {
            intent: Intent {
                profile: flow.profile.clone(),
            },
            constraints,
            metadata,
        }
    }
}

// ---------- 便捷求值入口（兼容既有调用方，语义与默认引擎一致） ----------

/// 对一个中立 Network FlowContext 求值，产出确定性的 Intent + Constraints。
///
/// 等价于 `PolicyEngine::default_network().evaluate(flow).decision`。
#[must_use]
pub fn evaluate(flow: &FlowContext) -> PolicyDecision {
    PolicyEngine::default_network().evaluate(flow).decision
}

/// 对一个 Service FlowContext 求值：要求 service-session 能力与显式授权。
///
/// 等价于 `PolicyEngine::default_service().evaluate(flow).decision`。
#[must_use]
pub fn evaluate_service(flow: &FlowContext) -> PolicyDecision {
    PolicyEngine::default_service().evaluate(flow).decision
}

/// 从 destination 提取主机名（S7 sniff 补全域名的简化实现）。
///
/// 去掉 `scheme://` 后取到首个 `/` 或 `:` 为止；返回 `(key, value)` 形式元数据，
/// 供 `EnrichMetadata` 动作使用。提取失败返回 `None`（不伪造）。
#[must_use]
pub fn host_metadata_from_destination(destination: &str) -> Option<(String, String)> {
    let rest = destination
        .strip_prefix("https://")
        .or_else(|| destination.strip_prefix("http://"))
        .unwrap_or(destination);
    let host = rest.split(['/', ':']).next().unwrap_or(rest);
    if host.is_empty() {
        None
    } else {
        Some(("sniffed-host".into(), host.into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_domain::{FlowOrigin, ResourceId};

    fn flow_with(profile: &str, destination: &str) -> FlowContext {
        FlowContext {
            origin: FlowOrigin::NativeApi,
            resource: ResourceId("internet-access".into()),
            destination: destination.into(),
            profile: profile.into(),
        }
    }

    fn flow(profile: &str) -> FlowContext {
        flow_with(profile, "https://example.invalid/")
    }

    // ---- 兼容性：便捷求值入口语义不变 ----

    #[test]
    fn evaluates_to_intent_and_constraints_without_path() {
        let d = evaluate(&flow("Balanced"));
        assert_eq!(d.intent.profile, "Balanced");
        let keys: Vec<&str> = d.constraints.iter().map(|c| c.key.as_str()).collect();
        assert_eq!(keys, vec!["capability", "exit-dns"]);
        // 决策中不允许出现 Path/Provider 选择。
        assert!(d.constraints.iter().all(|c| c.key != "path"));
    }

    #[test]
    fn unknown_profile_is_preserved_not_fabricated() {
        let d = evaluate(&flow("Something-New"));
        assert_eq!(d.intent.profile, "Something-New");
        assert_eq!(d.constraints.len(), 2);
    }

    #[test]
    fn evaluation_is_deterministic() {
        assert_eq!(evaluate(&flow("Balanced")), evaluate(&flow("Balanced")));
    }

    #[test]
    fn service_policy_requires_capability_and_explicit_authorization() {
        let d = evaluate_service(&flow("Default"));
        let caps: Vec<(&str, &str)> = d
            .constraints
            .iter()
            .map(|c| (c.key.as_str(), c.value.as_str()))
            .collect();
        assert_eq!(
            caps,
            vec![
                ("authorization", "explicit"),
                ("capability", "service-session")
            ]
        );
    }

    // ---- 动作化有序链（S1/S2） ----

    #[test]
    fn first_match_wins_and_terminal_action_stops_chain() {
        let engine = PolicyEngine::new(vec![
            PolicyRule {
                id: "corp-vip".into(),
                match_: PolicyMatch {
                    profile_eq: Some("Corp-VIP".into()),
                    destination_prefix: None,
                },
                actions: vec![PolicyAction::SelectProvider {
                    capability: CAPABILITY_INTERNET_ACCESS.into(),
                    exit_dns: Some("corp-dns".into()),
                }],
            },
            PolicyRule {
                id: "fallback".into(),
                match_: PolicyMatch::default(),
                actions: vec![PolicyAction::Reject {
                    reason: "no matching policy".into(),
                }],
            },
        ]);

        let result = engine.evaluate(&flow_with("Corp-VIP", "https://x.example/"));
        assert!(result.rejected.is_none());
        // 首条规则命中即终止：fallback 规则不得执行。
        assert_eq!(result.trace.len(), 1);
        assert_eq!(result.trace[0].rule_index, 0);
        let keys: Vec<&str> = result
            .decision
            .constraints
            .iter()
            .map(|c| c.key.as_str())
            .collect();
        assert_eq!(keys, vec!["capability", "exit-dns"]);
    }

    #[test]
    fn unmatched_flow_reaches_later_rule() {
        let engine = PolicyEngine::new(vec![
            PolicyRule {
                id: "vip-only".into(),
                match_: PolicyMatch {
                    profile_eq: Some("Corp-VIP".into()),
                    destination_prefix: None,
                },
                actions: vec![PolicyAction::SelectProvider {
                    capability: CAPABILITY_INTERNET_ACCESS.into(),
                    exit_dns: None,
                }],
            },
            PolicyRule {
                id: "fallback".into(),
                match_: PolicyMatch::default(),
                actions: vec![PolicyAction::Reject {
                    reason: "profile not permitted".into(),
                }],
            },
        ]);

        let result = engine.evaluate(&flow("Guest"));
        assert_eq!(result.rejected.as_deref(), Some("profile not permitted"));
        // 第一条规则不匹配被跳过，第二条（fallback）命中并拒绝。
        assert_eq!(result.trace.len(), 1);
        assert_eq!(result.trace[0].rule_index, 1);
    }

    #[test]
    fn destination_prefix_is_ordered_first_match() {
        let engine = PolicyEngine::new(vec![
            PolicyRule {
                id: "block-internal".into(),
                match_: PolicyMatch {
                    profile_eq: None,
                    destination_prefix: Some("http://10.".into()),
                },
                actions: vec![PolicyAction::Reject {
                    reason: "internal network denied".into(),
                }],
            },
            PolicyRule {
                id: "default".into(),
                match_: PolicyMatch::default(),
                actions: vec![PolicyAction::SelectProvider {
                    capability: CAPABILITY_INTERNET_ACCESS.into(),
                    exit_dns: Some("bound".into()),
                }],
            },
        ]);

        let blocked = engine.evaluate(&flow_with("Any", "http://10.0.0.1/"));
        assert_eq!(blocked.rejected.as_deref(), Some("internal network denied"));

        let allowed = engine.evaluate(&flow_with("Any", "https://public.example/"));
        assert!(allowed.rejected.is_none());
        assert_eq!(allowed.trace[0].rule_index, 1);
    }

    #[test]
    fn non_terminal_actions_accumulate_side_effects_then_select() {
        let engine = PolicyEngine::new(vec![PolicyRule {
            id: "enrich-then-select".into(),
            match_: PolicyMatch::default(),
            actions: vec![
                PolicyAction::EnrichMetadata {
                    key: "sniffed-host".into(),
                    value: "example.invalid".into(),
                },
                PolicyAction::AddConstraint {
                    key: CONSTRAINT_AUTHORIZATION.into(),
                    value: "explicit".into(),
                },
                PolicyAction::SelectProvider {
                    capability: CAPABILITY_INTERNET_ACCESS.into(),
                    exit_dns: None,
                },
            ],
        }]);

        let result = engine.evaluate(&flow("Balanced"));
        assert!(result.rejected.is_none());
        assert_eq!(result.trace.len(), 3);
        // 元数据进 decision.metadata（不进 constraints）。
        assert_eq!(
            result.decision.metadata,
            vec![("sniffed-host".into(), "example.invalid".into())]
        );
        let keys: Vec<&str> = result
            .decision
            .constraints
            .iter()
            .map(|c| c.key.as_str())
            .collect();
        assert_eq!(keys, vec!["authorization", "capability"]);
    }

    #[test]
    fn no_rule_match_yields_empty_decision_not_fabrication() {
        let engine = PolicyEngine::new(vec![PolicyRule {
            id: "never-matches".into(),
            match_: PolicyMatch {
                profile_eq: Some("Nope".into()),
                destination_prefix: None,
            },
            actions: vec![PolicyAction::Reject { reason: "x".into() }],
        }]);
        let result = engine.evaluate(&flow("Balanced"));
        assert!(result.rejected.is_none());
        assert!(result.decision.constraints.is_empty());
        assert!(result.trace.is_empty());
    }

    #[test]
    fn default_engines_match_legacy_entrypoints() {
        let flow = flow("Balanced");
        assert_eq!(
            PolicyEngine::default_network().evaluate(&flow).decision,
            evaluate(&flow)
        );
        assert_eq!(
            PolicyEngine::default_service().evaluate(&flow).decision,
            evaluate_service(&flow)
        );
    }

    #[test]
    fn host_metadata_extraction() {
        assert_eq!(
            host_metadata_from_destination("https://example.invalid:443/path"),
            Some(("sniffed-host".into(), "example.invalid".into()))
        );
        assert_eq!(
            host_metadata_from_destination("http://10.0.0.1/"),
            Some(("sniffed-host".into(), "10.0.0.1".into()))
        );
        assert_eq!(host_metadata_from_destination(""), None);
    }
}
