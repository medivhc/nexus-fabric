//! v9 §8.1 Connectivity Evaluation：规划期低成本连通性评估。
//!
//! 纯函数（零 I/O、无隐藏状态、确定性）：同等输入必然产出同等输出。
//! 不建立业务 Link；输出 [`ConnectivityEvaluation`] 作为 Core Planner 的
//! Connectivity Feasibility 输入（见 `nexus-planner::connectivity_gate`）。
//!
//! 判定语义（保守优先，宁可低估不可高估）：
//! - `DirectLikely`：有候选 Locator + UDP 可用 + 本端 FullCone（任意外端可直达
//!   映射端口）+ 对端非 Symmetric（其 advertised locator 稳定）；
//! - `PunchingLikely`：复用冻结 NAT 合同的可达性语义——cone–cone、cone–symmetric
//!   可达，symmetric–symmetric 不可达；任一端 NAT 未知时退到历史成功率
//!   （≥50% 判 likely，无历史则保守为 false）；
//! - `EstimatedSetupCost`：取可用路径的最小估计（existing 0ms / direct 取实测
//!   RTT 或 100ms / punch 3000ms=有界预测 3s 时间盒 / relay 500ms）；无可行
//!   路径时为 `None`；
//! - `Confidence`：输入完备度（100 起扣，饱和减），不是业务分数。
//!
//! 数值全部使用整数（避免浮点不确定性），与 `nexus-measurement` 约定一致。

#![forbid(unsafe_code)]

use std::net::SocketAddr;

use nexus_domain::ConnectivityEvaluation;
use nexus_measurement::LinkMeasurement;

use crate::nat::NatType;

/// 平台网络能力（Evaluation 输入的最小集合；按需扩展）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlatformNetworkCapability {
    /// 是否可收发 UDP（直连/打洞的前提；QUIC 基于 UDP）。
    pub udp_supported: bool,
    /// 是否有 IPv6 可用（影响直连候选）。
    pub ipv6_supported: bool,
}

/// Connectivity Evaluation 输入（v9 §8.1）。
///
/// 由 Composition Root 采集（Known Locators、NAT 观测、历史成功率、最近测量、
/// 中继可用性、已有链路、平台能力）；本函数只做纯计算。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluationInput {
    /// 已知 Locator（候选直连地址）。
    pub known_locators: Vec<SocketAddr>,
    /// 本端 NAT 类型观测。
    pub local_nat: NatType,
    /// 对端 NAT 类型观测。
    pub remote_nat: NatType,
    /// 历史打洞成功率（万分比 0..=10000；`None` = 无历史）。
    pub punch_success_permyriad: Option<u32>,
    /// 最近链路测量（RTT/Loss；`None` = 无测量）。
    pub recent: Option<LinkMeasurement>,
    /// 中继可用性（TURN / peer-relay，由 Composition Root 判定）。
    pub relay_available: bool,
    /// 已有可用链路（可复用）。
    pub existing_link: bool,
    /// 平台网络能力。
    pub platform: PlatformNetworkCapability,
}

/// 直连默认建连成本（毫秒）：QUIC 握手约 1 个 RTT 量级，无测量时的保守估计。
const COST_DIRECT_DEFAULT_MS: u32 = 100;
/// 打洞建连成本（毫秒）：有界端口预测 3 秒时间盒（冻结 NAT 合同）。
const COST_PUNCH_MS: u32 = 3_000;
/// 中继建连成本（毫秒）：TURN 分配 + 握手估计。
const COST_RELAY_MS: u32 = 500;
/// 复用已有链路：零建连成本。
const COST_EXISTING_MS: u32 = 0;

/// 历史成功率门限（万分比）：NAT 未知时 ≥50% 才判打洞可能。
const HISTORY_LIKELY_THRESHOLD_PERMYRIAD: u32 = 5_000;

/// v9 §8.1 纯函数：Connectivity Evaluation。
///
/// 确定性：同等输入必然产出同等输出。零 I/O，不建立业务 Link。
#[must_use]
pub fn evaluate_connectivity(input: &EvaluationInput) -> ConnectivityEvaluation {
    let udp = input.platform.udp_supported;
    let has_locators = !input.known_locators.is_empty();

    // DirectLikely：保守——本端 FullCone 且对端非 Symmetric 时，
    // 对端 advertised locator 稳定，直连可能成功。未知 NAT 不判 likely。
    let direct_likely = udp
        && has_locators
        && matches!(input.local_nat, NatType::FullCone)
        && !matches!(input.remote_nat, NatType::Symmetric);

    // PunchingLikely：冻结 NAT 合同的可达性语义。
    let punching_likely = udp
        && has_locators
        && match (input.local_nat, input.remote_nat) {
            // symmetric–symmetric 在冻结 spray 语义下不可达。
            (NatType::Symmetric, NatType::Symmetric) => false,
            // 任一端未知：退到历史成功率，无历史则保守为 false。
            (NatType::Unknown, _) | (_, NatType::Unknown) => input
                .punch_success_permyriad
                .is_some_and(|r| r >= HISTORY_LIKELY_THRESHOLD_PERMYRIAD),
            // 其余组合（cone–cone、cone–symmetric、FullCone 参与）可达。
            _ => true,
        };

    let relay_available = input.relay_available;
    let existing_link_available = input.existing_link;

    // EstimatedSetupCost：取可用路径的最小估计；无可行路径时为 None。
    let mut cost: Option<u32> = None;
    let mut take = |c: u32| {
        cost = Some(cost.map_or(c, |prev: u32| prev.min(c)));
    };
    if existing_link_available {
        take(COST_EXISTING_MS);
    }
    if direct_likely {
        take(
            input
                .recent
                .as_ref()
                .and_then(|m| m.rtt_ms)
                .unwrap_or(COST_DIRECT_DEFAULT_MS),
        );
    }
    if punching_likely {
        take(COST_PUNCH_MS);
    }
    if relay_available {
        take(COST_RELAY_MS);
    }

    // Confidence：输入完备度（100 起扣，饱和减）。
    let mut confidence: u16 = 100;
    if matches!(input.local_nat, NatType::Unknown) {
        confidence = confidence.saturating_sub(25);
    }
    if matches!(input.remote_nat, NatType::Unknown) {
        confidence = confidence.saturating_sub(25);
    }
    if input.punch_success_permyriad.is_none() {
        confidence = confidence.saturating_sub(10);
    }
    if input.recent.is_none() {
        confidence = confidence.saturating_sub(10);
    }
    if !has_locators {
        confidence = confidence.saturating_sub(15);
    }

    ConnectivityEvaluation {
        version: ConnectivityEvaluation::VERSION,
        direct_likely,
        punching_likely,
        relay_available,
        existing_link_available,
        estimated_setup_cost_ms: cost,
        confidence_percent: confidence.min(100) as u8,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr() -> SocketAddr {
        "203.0.113.7:54321".parse().unwrap()
    }

    fn base_input() -> EvaluationInput {
        EvaluationInput {
            known_locators: vec![addr()],
            local_nat: NatType::RestrictedCone,
            remote_nat: NatType::PortRestrictedCone,
            punch_success_permyriad: Some(8_500),
            recent: Some(LinkMeasurement {
                rtt_ms: Some(42),
                confidence_percent: 90,
                ..Default::default()
            }),
            relay_available: false,
            existing_link: false,
            platform: PlatformNetworkCapability {
                udp_supported: true,
                ipv6_supported: false,
            },
        }
    }

    #[test]
    fn cone_cone_punching_likely() {
        let ev = evaluate_connectivity(&base_input());
        assert!(ev.punching_likely);
        assert!(!ev.direct_likely); // 本端非 FullCone，直连不判 likely
        assert!(ev.has_feasible_path());
        assert_eq!(ev.estimated_setup_cost_ms, Some(COST_PUNCH_MS));
        assert_eq!(ev.confidence_percent, 100);
        assert_eq!(ev.version, ConnectivityEvaluation::VERSION);
    }

    #[test]
    fn symmetric_symmetric_unreachable_without_relay() {
        let mut input = base_input();
        input.local_nat = NatType::Symmetric;
        input.remote_nat = NatType::Symmetric;
        input.punch_success_permyriad = None;
        input.recent = None;
        let ev = evaluate_connectivity(&input);
        assert!(!ev.punching_likely);
        assert!(!ev.direct_likely);
        assert!(!ev.has_feasible_path());
        assert_eq!(ev.estimated_setup_cost_ms, None);
        // 100 - 10（无历史） - 10（无测量） = 80
        assert_eq!(ev.confidence_percent, 80);
    }

    #[test]
    fn symmetric_symmetric_with_relay_is_feasible() {
        let mut input = base_input();
        input.local_nat = NatType::Symmetric;
        input.remote_nat = NatType::Symmetric;
        input.relay_available = true;
        let ev = evaluate_connectivity(&input);
        assert!(ev.relay_available);
        assert!(ev.has_feasible_path());
        assert_eq!(ev.estimated_setup_cost_ms, Some(COST_RELAY_MS));
    }

    #[test]
    fn unknown_nat_falls_back_to_history() {
        let mut input = base_input();
        input.local_nat = NatType::Unknown;
        input.remote_nat = NatType::Unknown;
        input.punch_success_permyriad = None;
        input.recent = None;
        let ev = evaluate_connectivity(&input);
        assert!(!ev.punching_likely); // 无历史 → 保守 false
        // 100 - 25 - 25 - 10 - 10 = 30
        assert_eq!(ev.confidence_percent, 30);

        // 有历史且 ≥50% → likely
        input.punch_success_permyriad = Some(6_000);
        let ev = evaluate_connectivity(&input);
        assert!(ev.punching_likely);
    }

    #[test]
    fn fullcone_local_direct_likely_and_uses_measured_rtt() {
        let mut input = base_input();
        input.local_nat = NatType::FullCone;
        let ev = evaluate_connectivity(&input);
        assert!(ev.direct_likely);
        // 建连成本取实测 RTT（42），而非默认 100
        assert_eq!(ev.estimated_setup_cost_ms, Some(42));
    }

    #[test]
    fn fullcone_local_but_symmetric_remote_not_direct_likely() {
        let mut input = base_input();
        input.local_nat = NatType::FullCone;
        input.remote_nat = NatType::Symmetric;
        let ev = evaluate_connectivity(&input);
        assert!(!ev.direct_likely); // 对端 Symmetric：advertised locator 不稳定
        assert!(ev.punching_likely); // 但打洞可达（cone–symmetric）
    }

    #[test]
    fn no_udp_means_nothing_likely() {
        let mut input = base_input();
        input.platform.udp_supported = false;
        let ev = evaluate_connectivity(&input);
        assert!(!ev.direct_likely);
        assert!(!ev.punching_likely);
        assert!(!ev.has_feasible_path());
    }

    #[test]
    fn no_locators_means_nothing_likely() {
        let mut input = base_input();
        input.known_locators.clear();
        let ev = evaluate_connectivity(&input);
        assert!(!ev.direct_likely);
        assert!(!ev.punching_likely);
        // 100 - 15（无 locator） = 85（历史/测量仍在）
        assert_eq!(ev.confidence_percent, 85);
    }

    #[test]
    fn existing_link_costs_zero_and_wins() {
        let mut input = base_input();
        input.existing_link = true;
        let ev = evaluate_connectivity(&input);
        assert!(ev.existing_link_available);
        assert_eq!(ev.estimated_setup_cost_ms, Some(COST_EXISTING_MS));
    }

    #[test]
    fn evaluation_is_deterministic() {
        let input = base_input();
        assert_eq!(evaluate_connectivity(&input), evaluate_connectivity(&input));
    }
}
