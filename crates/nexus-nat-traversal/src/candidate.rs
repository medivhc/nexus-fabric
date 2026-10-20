//! P1 候选地址（冻结合同 §P1）。
//!
//! 候选按优先级排序：Srflx > Host；Relay 候选已是中继地址，
//! 不参与打洞。

use std::net::SocketAddr;

use nexus_connectivity::nat::NatType;

/// 候选地址类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateKind {
    /// 本机接口地址。
    Host,
    /// Server-reflexive（TURN Allocate 的 XOR-MAPPED / STUN 自测）。
    Srflx,
    /// 中继地址（不参与打洞，仅用于信令 completeness）。
    Relay,
}

/// 单个打洞候选。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PunchCandidate {
    pub addr: SocketAddr,
    pub kind: CandidateKind,
}

/// 本端候选集合。
#[derive(Debug, Clone)]
pub struct LocalCandidates {
    /// 本机各接口地址（可空）。
    pub host: Vec<SocketAddr>,
    /// TURN Allocate 的 XOR-MAPPED（优先）。
    pub srflx: Option<SocketAddr>,
    /// STUN 自测 reflexive（校验用，可空；同样可打）。
    pub srflx_stun: Option<SocketAddr>,
    /// 本端自测 NAT 类型。
    pub nat_type: NatType,
}

impl LocalCandidates {
    /// 是否至少有 1 个可打洞候选（srflx 或 host）。
    pub fn has_punchable(&self) -> bool {
        !self.ordered().is_empty()
    }

    /// 打洞候选，排序 Srflx > Host；Relay 不参与；去重。
    pub fn ordered(&self) -> Vec<PunchCandidate> {
        let mut out = Vec::new();
        let mut push = |addr: SocketAddr, kind: CandidateKind| {
            if !out.iter().any(|c: &PunchCandidate| c.addr == addr) {
                out.push(PunchCandidate { addr, kind });
            }
        };
        if let Some(a) = self.srflx {
            push(a, CandidateKind::Srflx);
        }
        if let Some(a) = self.srflx_stun {
            push(a, CandidateKind::Srflx);
        }
        for a in &self.host {
            push(*a, CandidateKind::Host);
        }
        out
    }
}

/// 对端候选的打洞目标：Srflx 优先，排除 Relay，去重。
pub fn punch_targets(cands: &[PunchCandidate]) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    for kind in [CandidateKind::Srflx, CandidateKind::Host] {
        for c in cands {
            if c.kind == kind && !out.contains(&c.addr) {
                out.push(c.addr);
            }
        }
    }
    out
}
