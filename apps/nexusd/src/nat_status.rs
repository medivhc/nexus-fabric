//! NAT connectivity snapshot (`GET /localapi/v0/connectivity/nat`).
//!
//! Reads an in-memory publisher (no per-request probing). With no publisher
//! the route still returns 200 with `runtime=disabled` and `peers=[]`.

use std::sync::OnceLock;

use nexus_connectivity::nat::NatType;
use nexus_domain::NexusError;
use nexus_nat_wireup::{PunchPeerStatus, RelaySource, TunnelProto};
use serde_json::{Value, json};

pub const SCHEMA_VERSION: u32 = 2;

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

static PEER_SOURCE: OnceLock<std::sync::Arc<crate::peer_source::PeerSourceStatus>> =
    OnceLock::new();
static DISCOVERY: OnceLock<std::sync::Arc<crate::discovery_runtime::DiscoveryPumpStatus>> =
    OnceLock::new();
/// OQ-2 ruling (a): the hub is registered separately so the frozen pump
/// snapshot keeps its shape; metrics are read through `hub.metrics()`.
static DISCOVERY_HUB: OnceLock<std::sync::Arc<nexus_discovery::hub::DiscoveryHub>> =
    OnceLock::new();

/// Register the peer-source status (first registration wins, like `SOURCE`).
pub fn publish_peer_source_status(status: std::sync::Arc<crate::peer_source::PeerSourceStatus>) {
    let _ = PEER_SOURCE.set(status);
}

/// Register the discovery pump status.
pub fn publish_discovery_status(
    status: std::sync::Arc<crate::discovery_runtime::DiscoveryPumpStatus>,
) {
    let _ = DISCOVERY.set(status);
}

/// Register the discovery hub (read-only metrics source for the JSON block).
pub fn publish_discovery_hub(hub: std::sync::Arc<nexus_discovery::hub::DiscoveryHub>) {
    let _ = DISCOVERY_HUB.set(hub);
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

/// `peer_source` block (spec §4.12.1).
fn peer_source_json() -> Value {
    let snap = PEER_SOURCE
        .get()
        .map(|s| s.snapshot())
        .unwrap_or_else(|| crate::peer_source::PeerSourceStatus::default().snapshot());
    json!({
        "state": snap.state,
        "enabled": snap.enabled,
        "subscribed_peers": snap.subscribed_peers,
        "sources": {
            "static": snap.sources_static,
            "paired": snap.sources_paired,
            "lsa": snap.sources_lsa,
            "mdns": snap.sources_mdns,
            "n1": snap.sources_n1,
        },
        "invalid_peer_id_total": counter(snap.invalid_peer_id_total),
        "subscribe_refused_total": counter(snap.subscribe_refused_total),
        "trigger_attempts_total": counter(snap.trigger_attempts_total),
        "trigger_ok_total": counter(snap.trigger_ok_total),
        "trigger_fail_total": counter(snap.trigger_fail_total),
        "trigger_capacity_parked_total": counter(snap.trigger_capacity_parked_total),
        "trigger_parked_peers": snap.trigger_parked_peers,
        "trigger_parked_max_failures": snap.trigger_parked_max_failures,
        "trigger_parked_capacity": snap.trigger_parked_capacity,
        "trigger_inflight_peers": snap.trigger_inflight_peers,
        "book_entries": snap.book_entries,
        "subscribed_peers_without_book_addr": snap.subscribed_peers_without_book_addr,
        "book_reloads_total": counter(snap.book_reloads_total),
        "book_errors_total": counter(snap.book_errors_total),
        "book_last_success_ms": counter(snap.book_last_success_ms),
        "last_error": snap.last_error,
    })
}

/// `discovery` block (spec §4.12.1); read independently of the NAT source so a
/// pump without a NAT stack still reports real values.
fn discovery_json() -> Value {
    let snap = DISCOVERY.get().map(|s| s.snapshot()).unwrap_or_default();
    let metrics = DISCOVERY_HUB
        .get()
        .map(|hub| hub.metrics())
        .unwrap_or_default();
    json!({
        "mdns": snap.mdns,
        "lsa": snap.lsa,
        "mdns_cached_peers": snap.mdns_cached_peers,
        "lsa_lsdb_entries": snap.lsa_lsdb_entries,
        "lsa_fresh_peers": snap.lsa_fresh_peers,
        "mdns_queries_sent": counter(snap.mdns_queries_sent),
        "mdns_announces_sent": counter(snap.mdns_announces_sent),
        "lsa_hellos_sent": counter(snap.lsa_hellos_sent),
        "lsa_adverts_sent": counter(snap.lsa_adverts_sent),
        "lsa_adverts_recv": counter(snap.lsa_adverts_recv),
        "lsa_floods_sent": counter(snap.lsa_floods_sent),
        "lsa_floods_suppressed": counter(snap.lsa_floods_suppressed),
        "lsa_decode_errors": counter(snap.lsa_decode_errors),
        "lsa_frame_too_large": counter(snap.lsa_frame_too_large),
        "discovery_metrics": {
            "hits_paired": counter(metrics.hits_paired),
            "hits_static": counter(metrics.hits_static),
            "hits_lsa": counter(metrics.hits_lsa),
            "hits_mdns": counter(metrics.hits_mdns),
            "miss": counter(metrics.miss),
        },
        "last_error": snap.last_error,
    })
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
                "peer_source": peer_source_json(),
                "discovery": discovery_json(),
            }))
        }
        None => Ok(json!({
            "schema_version": SCHEMA_VERSION,
            "runtime": NatRuntimeState::Disabled.as_str(),
            "generated_at_ms": now,
            "peers": [],
            // No NAT stack: the state row is `disabled:no-turn`, counters are
            // all zero, and the discovery block still reports the real pump.
            "peer_source": {
                "state": "disabled:no-turn",
                "enabled": false,
                "subscribed_peers": 0,
                "sources": { "static": 0, "paired": 0, "lsa": 0, "mdns": 0, "n1": 0 },
                "invalid_peer_id_total": 0,
                "subscribe_refused_total": 0,
                "trigger_attempts_total": 0,
                "trigger_ok_total": 0,
                "trigger_fail_total": 0,
                "trigger_capacity_parked_total": 0,
                "trigger_parked_peers": 0,
                "trigger_parked_max_failures": 0,
                "trigger_parked_capacity": 0,
                "trigger_inflight_peers": 0,
                "book_entries": Value::Null,
                "subscribed_peers_without_book_addr": 0,
                "book_reloads_total": 0,
                "book_errors_total": 0,
                "book_last_success_ms": 0,
                "last_error": Value::Null,
            },
            "discovery": discovery_json(),
        })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer_source::{PeerSourceStateInputs, decide_state};

    fn inputs(
        enabled: bool,
        feed: bool,
        nat: bool,
        provider: bool,
        hub: bool,
        sessions: bool,
    ) -> PeerSourceStateInputs {
        PeerSourceStateInputs {
            enabled,
            feed,
            has_nat_switch: nat,
            has_provider: provider,
            has_hub: hub,
            has_sessions: sessions,
        }
    }

    /// AC7: the six rows of §4.11.1, asserted exactly and in judgment order.
    #[test]
    fn peer_source_state_table() {
        // 1. config off (enabled=false, then feed=false; both outrank no-turn).
        assert_eq!(
            decide_state(inputs(false, true, false, false, false, false)),
            "disabled:config"
        );
        assert_eq!(
            decide_state(inputs(true, false, false, false, false, false)),
            "disabled:config"
        );
        // 2..5: the remaining disabled reasons, in order.
        assert_eq!(
            decide_state(inputs(true, true, false, true, true, true)),
            "disabled:no-turn"
        );
        assert_eq!(
            decide_state(inputs(true, true, true, false, true, true)),
            "disabled:no-provider"
        );
        assert_eq!(
            decide_state(inputs(true, true, true, true, false, false)),
            "disabled:no-discovery"
        );
        assert_eq!(
            decide_state(inputs(true, true, true, true, true, false)),
            "disabled:no-sessions"
        );
        // 6. all preconditions met.
        assert_eq!(
            decide_state(inputs(true, true, true, true, true, true)),
            "running"
        );
    }

    #[test]
    fn connectivity_nat_keeps_both_blocks_without_a_source() {
        // No NatSwitching registered in this process.
        let v = connectivity_nat().expect("snapshot");
        assert_eq!(v["schema_version"], 2);
        assert_eq!(v["peer_source"]["state"], "disabled:no-turn");
        assert_eq!(v["peer_source"]["enabled"], false);
        assert!(v["peer_source"]["last_error"].is_null());
        // Discovery block is present and shaped even when the pump never ran.
        assert!(v["discovery"]["mdns"].is_string());
        assert_eq!(v["discovery"]["discovery_metrics"]["miss"], 0);
        assert!(v["peers"].as_array().expect("peers array").is_empty());
    }
}
