//! NAT connectivity snapshot (`GET /localapi/v0/connectivity/nat`).
//!
//! Reads an in-memory publisher (no per-request probing). With no publisher
//! the route still returns 200 with `runtime=disabled` and `peers=[]`.

use std::sync::OnceLock;

use nexus_connectivity::nat::NatType;
use nexus_domain::NexusError;
use nexus_nat_wireup::{PunchPeerStatus, RelaySource, TunnelProto};
use serde_json::{Value, json};

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatRuntimeState {
    Enabled,
    Disabled,
}

impl NatRuntimeState {
    pub fn as_str(&self) -> &'static str {
        match self {
            NatRuntimeState::Enabled => "enabled",
            NatRuntimeState::Disabled => "disabled",
        }
    }
}

#[derive(Debug, Clone)]
pub struct PathStatusView {
    pub kind: String,
    pub remote_addr: String,
    pub rtt_ms: Option<u64>,
    pub loss_01: Option<f64>,
    pub score: Option<f64>,
    pub active: bool,
    pub cost: f64,
}

#[derive(Debug, Clone)]
pub struct PeerNatStatus {
    pub peer_id: String,
    pub tunnel_proto: TunnelProto,
    pub nat_type_local: NatType,
    pub nat_type_remote: NatType,
    pub relay_source: Option<RelaySource>,
    pub punch: PunchPeerStatus,
    pub paths: Vec<PathStatusView>,
}

#[derive(Debug, Clone)]
pub struct NatStatusSnapshot {
    pub schema_version: u32,
    pub runtime: NatRuntimeState,
    pub generated_at_ms: u64,
    pub peers: Vec<PeerNatStatus>,
}

/// Source of an in-memory snapshot (published once at assembly).
pub trait NatStatusSource: Send + Sync {
    fn peers(&self) -> Vec<PunchPeerStatus>;
}

impl<T: NatStatusSource + ?Sized> NatStatusSource for std::sync::Arc<T> {
    fn peers(&self) -> Vec<PunchPeerStatus> {
        (**self).peers()
    }
}

static SOURCE: OnceLock<Box<dyn NatStatusSource>> = OnceLock::new();

pub fn publish_nat_status_source(source: Box<dyn NatStatusSource>) {
    let _ = SOURCE.set(source);
}

pub fn nat_type_label(t: NatType) -> &'static str {
    match t {
        NatType::FullCone => "full_cone",
        NatType::RestrictedCone => "restricted_cone",
        NatType::PortRestrictedCone => "port_restricted_cone",
        NatType::Symmetric => "symmetric",
        NatType::Unknown => "unknown",
    }
}

pub fn tunnel_proto_label(p: TunnelProto) -> &'static str {
    p.as_str()
}

fn counter(v: u64) -> Value {
    json!(v)
}

fn peer_json(st: &PunchPeerStatus) -> Value {
    json!({
        "peer_id": hex32(&st.peer.0),
        "tunnel_proto": tunnel_proto_label(st.tunnel_proto),
        "nat_type_local": nat_type_label(st.nat_type_local),
        "nat_type_remote": nat_type_label(st.nat_type_remote),
        "relay_source": st.relay_source.map(|r| r.as_str()),
        "punch": {
            "phase": st.phase.as_str(),
            "state": st.state.as_str(),
            "last_result": st.last_result.map(|r| match r {
                nexus_nat_traversal::PunchResult::Migrated { .. } => "migrated",
                nexus_nat_traversal::PunchResult::StayedOnRelay { .. } => "stayed_on_relay",
            }),
            "fail_reason": st.fail_reason.map(|r| r.as_str()),
            "last_attempt_ms": st.last_attempt_ms,
            "last_success_ms": st.last_success_ms,
            "attempts_total": counter(st.attempts_total),
            "migrated_total": counter(st.migrated_total),
            "failed_timeout_total": counter(st.failed_timeout_total),
            "failed_unpredictable_total": counter(st.failed_unpredictable_total),
            "failed_no_candidates_total": counter(st.failed_no_candidates_total),
            "failed_channel_closed_total": counter(st.failed_channel_closed_total),
            "spray_sends_total": counter(st.spray_sends_total),
            "spray_skipped_total": counter(st.spray_skipped_total),
            "mapping_probe_sends_total": counter(st.mapping_probe_sends_total),
            "prediction_hints_sent_total": counter(st.prediction_hints_sent_total),
            "prediction_hints_recv_total": counter(st.prediction_hints_recv_total),
            "signal_decode_errors_total": counter(st.signal_decode_errors_total),
            "turn_mapped_loopback": st.turn_mapped_loopback,
            "last_direct_addr": st.last_direct_addr.map(|a| a.to_string()),
            "direct_conn_id": st.direct_conn_id,
        },
        "paths": [],
    })
}

fn hex32(id: &[u8; 32]) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn connectivity_nat() -> Result<Value, NexusError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    match SOURCE.get() {
        Some(src) => {
            let peers: Vec<Value> = src.peers().iter().map(peer_json).collect();
            Ok(json!({
                "schema_version": SCHEMA_VERSION,
                "runtime": NatRuntimeState::Enabled.as_str(),
                "generated_at_ms": now,
                "peers": peers,
            }))
        }
        None => Ok(json!({
            "schema_version": SCHEMA_VERSION,
            "runtime": NatRuntimeState::Disabled.as_str(),
            "generated_at_ms": now,
            "peers": [],
        })),
    }
}
