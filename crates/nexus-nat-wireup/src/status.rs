//! Per-peer punch registry (observability; LocalAPI JSON source).

use nexus_connectivity::nat::NatType;
use nexus_fabric::PeerId as FabricPeerId;
use nexus_nat_traversal::{PunchFailReason, PunchPhase, PunchResult};

/// Transport currently carrying production traffic for a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TunnelProto {
    Direct,
    Turn,
    PeerRelay,
    #[default]
    None,
}

impl TunnelProto {
    pub fn as_str(&self) -> &'static str {
        match self {
            TunnelProto::Direct => "direct",
            TunnelProto::Turn => "turn",
            TunnelProto::PeerRelay => "peer_relay",
            TunnelProto::None => "none",
        }
    }
}

/// Where the relay leg comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelaySource {
    Turn,
    Mesh,
}

impl RelaySource {
    pub fn as_str(&self) -> &'static str {
        match self {
            RelaySource::Turn => "turn",
            RelaySource::Mesh => "mesh",
        }
    }
}

/// High-level punch state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PunchState {
    #[default]
    NotAttempted,
    InProgress,
    Succeeded,
    Failed,
    Disabled,
}

impl PunchState {
    pub fn as_str(&self) -> &'static str {
        match self {
            PunchState::NotAttempted => "not_attempted",
            PunchState::InProgress => "in_progress",
            PunchState::Succeeded => "succeeded",
            PunchState::Failed => "failed",
            PunchState::Disabled => "disabled",
        }
    }
}

/// Automatic repunch trigger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepunchTrigger {
    Periodic,
    ReflexiveChanged,
    RelayDegraded,
}

impl RepunchTrigger {
    pub fn as_str(&self) -> &'static str {
        match self {
            RepunchTrigger::Periodic => "periodic",
            RepunchTrigger::ReflexiveChanged => "reflexive_changed",
            RepunchTrigger::RelayDegraded => "relay_degraded",
        }
    }
}

/// Per-peer status: 12 counter projections + lifecycle facts.
#[derive(Debug, Clone)]
pub struct PunchPeerStatus {
    pub peer: FabricPeerId,
    pub phase: PunchPhase,
    pub state: PunchState,
    pub last_result: Option<PunchResult>,
    pub fail_reason: Option<PunchFailReason>,
    pub last_attempt_ms: Option<u64>,
    pub last_success_ms: Option<u64>,
    pub attempts_total: u64,
    pub migrated_total: u64,
    pub failed_timeout_total: u64,
    pub failed_unpredictable_total: u64,
    pub failed_no_candidates_total: u64,
    pub failed_channel_closed_total: u64,
    pub spray_sends_total: u64,
    pub spray_skipped_total: u64,
    pub mapping_probe_sends_total: u64,
    pub prediction_hints_sent_total: u64,
    pub prediction_hints_recv_total: u64,
    pub signal_decode_errors_total: u64,
    pub turn_mapped_loopback: bool,
    pub last_direct_addr: Option<std::net::SocketAddr>,
    pub direct_conn_id: Option<u64>,
    pub nat_type_local: NatType,
    pub nat_type_remote: NatType,
    pub tunnel_proto: TunnelProto,
    pub relay_source: Option<RelaySource>,
}

impl PunchPeerStatus {
    pub fn new(peer: FabricPeerId) -> Self {
        Self {
            peer,
            phase: PunchPhase::Idle,
            state: PunchState::NotAttempted,
            last_result: None,
            fail_reason: None,
            last_attempt_ms: None,
            last_success_ms: None,
            attempts_total: 0,
            migrated_total: 0,
            failed_timeout_total: 0,
            failed_unpredictable_total: 0,
            failed_no_candidates_total: 0,
            failed_channel_closed_total: 0,
            spray_sends_total: 0,
            spray_skipped_total: 0,
            mapping_probe_sends_total: 0,
            prediction_hints_sent_total: 0,
            prediction_hints_recv_total: 0,
            signal_decode_errors_total: 0,
            turn_mapped_loopback: false,
            last_direct_addr: None,
            direct_conn_id: None,
            nat_type_local: NatType::Unknown,
            nat_type_remote: NatType::Unknown,
            tunnel_proto: TunnelProto::None,
            relay_source: None,
        }
    }
}
