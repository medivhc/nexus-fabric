//! Local egress: minimal rule engine + UDP NAT (DESIGN.md §6.4).
//!
//! - [`SimpleRuleEngine`]: P0 rule engine — ordered CIDR rules, first match
//!   wins, no match → `Drop`. P1+ (domain/geoip/process) replaces this type
//!   behind the same [`RuleEngine`] trait.
//! - [`EgressNat`]: connection-tracked UDP NAT for `Egress{self}`.
//!   The table is protocol-agnostic (keyed by 5-tuple), so TCP reuses it
//!   once §6.1 phase 2 (L4 relay) lands. P0 simplifies: the source IP is NOT
//!   rewritten, only the mapping is recorded; E4 validates the mapping logic
//!   with a mock.

use nexus_domain::{RouteRequest, RouteTarget, RuleEngine};
use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::routing::{Cidr, parse_ipv4_dst};

/// A single CIDR → [`RouteTarget`] rule. First match wins.
#[derive(Debug, Clone)]
pub struct Rule {
    pub cidr: Cidr,
    pub target: RouteTarget,
}

/// P0 minimal rule engine: ordered CIDR rules over the packet's IPv4
/// destination. First match wins; no match (or unparsable packet) → `Drop`.
pub struct SimpleRuleEngine {
    rules: Vec<Rule>,
}

impl SimpleRuleEngine {
    pub fn new(rules: Vec<Rule>) -> Self {
        Self { rules }
    }

    /// Number of rules (observability).
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

impl RuleEngine for SimpleRuleEngine {
    fn decide(&self, req: &RouteRequest) -> RouteTarget {
        let dst = match parse_ipv4_dst(req.packet) {
            Some(d) => d,
            None => return RouteTarget::Drop,
        };
        for r in &self.rules {
            if r.cidr.contains(dst) {
                return r.target.clone();
            }
        }
        RouteTarget::Drop
    }
}

/// 5-tuple flow key. Protocol-agnostic: UDP today, TCP reuses the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
}

impl FlowKey {
    /// Parse from an IPv4/UDP or IPv4/TCP packet. Returns `None` for
    /// non-IPv4, truncated, or non-TCP/UDP packets.
    pub fn parse(packet: &[u8]) -> Option<Self> {
        if packet.len() < 20 || packet[0] >> 4 != 4 {
            return None;
        }
        let ihl = ((packet[0] & 0x0F) as usize) * 4;
        if ihl < 20 || packet.len() < ihl + 4 {
            return None;
        }
        let proto = packet[9];
        if proto != 6 && proto != 17 {
            return None; // TCP or UDP only
        }
        let src_ip = u32::from_be_bytes([packet[12], packet[13], packet[14], packet[15]]);
        let dst_ip = u32::from_be_bytes([packet[16], packet[17], packet[18], packet[19]]);
        let src_port = u16::from_be_bytes([packet[ihl], packet[ihl + 1]]);
        let dst_port = u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]);
        Some(Self {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            proto,
        })
    }

    /// Reverse direction, for matching a reply packet against the stored
    /// outbound key.
    pub fn reversed(&self) -> Self {
        Self {
            src_ip: self.dst_ip,
            dst_ip: self.src_ip,
            src_port: self.dst_port,
            dst_port: self.src_port,
            proto: self.proto,
        }
    }
}

/// A tracked egress flow.
#[derive(Debug, Clone)]
pub struct NatEntry {
    /// Originating peer (`"self"` or a peer id). Used by the caller to
    /// route the reply back.
    pub peer: String,
    pub last_seen: Instant,
}

/// NAT counters (S8/S11: honest, only successful translations counted).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct NatStats {
    /// Outbound packets recorded.
    pub egress_handled: u64,
    /// Inbound replies matched to a tracked flow.
    pub reply_received: u64,
    /// Inbound packets with no matching flow (dropped).
    pub reply_dropped: u64,
    /// Entries evicted by timeout.
    pub evicted: u64,
    /// Entries evicted by capacity bound (S14).
    pub capacity_evicted: u64,
    /// Current tracked flows (WARN-6: observable snapshot).
    pub current_flows: usize,
}

/// Default NAT table capacity (S14).
pub const DEFAULT_MAX_NAT_ENTRIES: usize = 65536;

/// Connection-tracked UDP NAT for `Egress{self}` (S11).
///
/// P0 simplification: packets are recorded, NOT rewritten (no SNAT).
/// E4 validates the mapping logic with a mock "internet".
///
/// S14: the table is bounded by `max_entries`; when full, the oldest
/// (least-recently-seen) entry is evicted to make room.
pub struct EgressNat {
    table: HashMap<FlowKey, NatEntry>,
    max_entries: usize,
    stats: NatStats,
}

impl EgressNat {
    pub fn new(max_entries: usize) -> Self {
        Self {
            table: HashMap::new(),
            max_entries,
            stats: NatStats::default(),
        }
    }

    /// Outbound: record the flow. Returns the (unmodified, P0) packet,
    /// or `None` if the packet is unparsable.
    ///
    /// S14: if the table is full, evict the oldest entry first.
    pub fn translate_outbound(&mut self, packet: &[u8], peer: &str) -> Option<Vec<u8>> {
        let key = FlowKey::parse(packet)?;
        if !self.table.contains_key(&key) && self.table.len() >= self.max_entries {
            self.evict_oldest();
        }
        self.table.insert(
            key,
            NatEntry {
                peer: peer.to_string(),
                last_seen: Instant::now(),
            },
        );
        self.stats.egress_handled += 1;
        self.stats.current_flows = self.table.len();
        Some(packet.to_vec())
    }

    /// Inbound reply: reverse-lookup the flow. Returns the packet and the
    /// originating peer, or `None` (counted in `reply_dropped`).
    pub fn translate_inbound(&mut self, packet: &[u8]) -> Option<(Vec<u8>, String)> {
        let reply_key = FlowKey::parse(packet)?;
        let orig_key = reply_key.reversed();
        match self.table.get_mut(&orig_key) {
            Some(entry) => {
                entry.last_seen = Instant::now();
                self.stats.reply_received += 1;
                Some((packet.to_vec(), entry.peer.clone()))
            }
            None => {
                self.stats.reply_dropped += 1;
                None
            }
        }
    }

    /// Drop entries idle longer than `timeout`. Returns the evicted count.
    pub fn evict_expired(&mut self, timeout: Duration) -> usize {
        let now = Instant::now();
        let before = self.table.len();
        self.table
            .retain(|_, e| now.duration_since(e.last_seen) <= timeout);
        let n = before - self.table.len();
        self.stats.evicted += n as u64;
        self.stats.current_flows = self.table.len();
        n
    }

    /// Evict the single oldest entry (S14 capacity bound).
    fn evict_oldest(&mut self) {
        let oldest = self
            .table
            .iter()
            .min_by_key(|(_, e)| e.last_seen)
            .map(|(k, _)| *k);
        if let Some(k) = oldest {
            self.table.remove(&k);
            self.stats.capacity_evicted += 1;
        }
    }

    /// Non-counting reply lookup (for the downlink fast path): does this
    /// packet match a tracked outbound flow? Returns the origin peer.
    pub fn peek_reply(&self, packet: &[u8]) -> Option<String> {
        let reply_key = FlowKey::parse(packet)?;
        let orig_key = reply_key.reversed();
        self.table.get(&orig_key).map(|e| e.peer.clone())
    }

    /// Number of tracked flows.
    pub fn flow_count(&self) -> usize {
        self.table.len()
    }

    pub fn stats(&self) -> NatStats {
        self.stats
    }
}

impl Default for EgressNat {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_NAT_ENTRIES)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// UDP packet: 20B IPv4 + 8B UDP header + payload.
    fn udp_packet(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16) -> Vec<u8> {
        let mut pkt = vec![0u8; 28 + 4];
        pkt[0] = 0x45;
        pkt[9] = 17; // UDP
        pkt[12..16].copy_from_slice(&src);
        pkt[16..20].copy_from_slice(&dst);
        pkt[20..22].copy_from_slice(&sport.to_be_bytes());
        pkt[22..24].copy_from_slice(&dport.to_be_bytes());
        pkt[28..].copy_from_slice(&[1, 2, 3, 4]);
        pkt
    }

    #[test]
    fn simple_rule_engine_first_match_wins() {
        let e = SimpleRuleEngine::new(vec![
            Rule {
                cidr: "1.2.3.0/24".parse().unwrap(),
                target: RouteTarget::Drop,
            },
            Rule {
                cidr: "0.0.0.0/0".parse().unwrap(),
                target: RouteTarget::Egress {
                    peer: "self".to_string(),
                },
            },
        ]);
        // Need owned packets because RouteRequest borrows.
        let p1 = udp_packet([10, 0, 0, 1], [1, 2, 3, 4], 1234, 53);
        let p2 = udp_packet([10, 0, 0, 1], [8, 8, 8, 8], 1234, 53);
        assert_eq!(
            e.decide(&RouteRequest {
                packet: &p1,
                domain: None
            }),
            RouteTarget::Drop
        );
        assert_eq!(
            e.decide(&RouteRequest {
                packet: &p2,
                domain: None
            }),
            RouteTarget::Egress {
                peer: "self".to_string()
            }
        );
    }

    #[test]
    fn s11_nat_reply_roundtrip() {
        let mut nat = EgressNat::default();
        let out = udp_packet([10, 0, 0, 1], [8, 8, 8, 8], 1234, 53);
        let sent = nat.translate_outbound(&out, "self").expect("recorded");
        assert_eq!(sent, out); // P0: unmodified
        assert_eq!(nat.stats().egress_handled, 1);

        // Mock internet reply: reversed 5-tuple.
        let reply = udp_packet([8, 8, 8, 8], [10, 0, 0, 1], 53, 1234);
        let (got, peer) = nat.translate_inbound(&reply).expect("matched");
        assert_eq!(got, reply);
        assert_eq!(peer, "self");
        assert_eq!(nat.stats().reply_received, 1);
    }

    #[test]
    fn s11_nat_unknown_reply_dropped_and_counted() {
        let mut nat = EgressNat::default();
        let reply = udp_packet([8, 8, 8, 8], [10, 0, 0, 1], 53, 9999);
        assert!(nat.translate_inbound(&reply).is_none());
        assert_eq!(nat.stats().reply_dropped, 1);
        assert_eq!(nat.stats().reply_received, 0);
    }

    #[test]
    fn s11_nat_evict_expired() {
        let mut nat = EgressNat::default();
        let out = udp_packet([10, 0, 0, 1], [8, 8, 8, 8], 1234, 53);
        nat.translate_outbound(&out, "self");
        assert_eq!(nat.flow_count(), 1);
        // Zero timeout evicts everything idle.
        let n = nat.evict_expired(Duration::ZERO);
        assert_eq!(n, 1);
        assert_eq!(nat.flow_count(), 0);
        assert_eq!(nat.stats().evicted, 1);
        // Generous timeout keeps flows.
        nat.translate_outbound(&out, "self");
        let n = nat.evict_expired(Duration::from_secs(120));
        assert_eq!(n, 0);
    }

    #[test]
    fn flow_key_rejects_garbage() {
        assert!(FlowKey::parse(&[0x45, 0x00]).is_none()); // truncated
        let mut pkt = udp_packet([10, 0, 0, 1], [8, 8, 8, 8], 1, 2);
        pkt[0] = 0x60; // IPv6 nibble
        assert!(FlowKey::parse(&pkt).is_none());
        let mut pkt = udp_packet([10, 0, 0, 1], [8, 8, 8, 8], 1, 2);
        pkt[9] = 1; // ICMP, not TCP/UDP
        assert!(FlowKey::parse(&pkt).is_none());
    }

    #[test]
    fn s14_capacity_evicts_oldest() {
        let mut nat = EgressNat::new(3);
        // Fill to capacity with distinct flows.
        for i in 0..3u16 {
            let pkt = udp_packet([10, 0, 0, 1], [8, 8, 8, 8], 1000 + i, 53);
            nat.translate_outbound(&pkt, "self");
        }
        assert_eq!(nat.flow_count(), 3);
        assert_eq!(nat.stats().current_flows, 3);
        assert_eq!(nat.stats().capacity_evicted, 0);

        // One more: oldest (sport 1000) evicted, newest kept.
        let pkt = udp_packet([10, 0, 0, 1], [8, 8, 8, 8], 2000, 53);
        nat.translate_outbound(&pkt, "self");
        assert_eq!(nat.flow_count(), 3);
        assert_eq!(nat.stats().capacity_evicted, 1);
        assert_eq!(nat.stats().current_flows, 3);

        // Oldest flow's reply no longer matches.
        let old_reply = udp_packet([8, 8, 8, 8], [10, 0, 0, 1], 53, 1000);
        assert!(nat.translate_inbound(&old_reply).is_none());
        // Newest flow's reply matches.
        let new_reply = udp_packet([8, 8, 8, 8], [10, 0, 0, 1], 53, 2000);
        assert!(nat.translate_inbound(&new_reply).is_some());
    }

    #[test]
    fn s14_reinsert_same_flow_no_evict() {
        // Re-recording an existing flow must not trigger eviction.
        let mut nat = EgressNat::new(2);
        let p1 = udp_packet([10, 0, 0, 1], [8, 8, 8, 8], 1000, 53);
        let p2 = udp_packet([10, 0, 0, 1], [8, 8, 8, 8], 1001, 53);
        nat.translate_outbound(&p1, "self");
        nat.translate_outbound(&p2, "self");
        nat.translate_outbound(&p1, "self"); // refresh, not new
        assert_eq!(nat.flow_count(), 2);
        assert_eq!(nat.stats().capacity_evicted, 0);
    }

    #[test]
    fn peek_reply_does_not_count() {
        let mut nat = EgressNat::default();
        let out = udp_packet([10, 0, 0, 1], [8, 8, 8, 8], 1234, 53);
        nat.translate_outbound(&out, "peer-x");
        let reply = udp_packet([8, 8, 8, 8], [10, 0, 0, 1], 53, 1234);
        assert_eq!(nat.peek_reply(&reply), Some("peer-x".to_string()));
        // Peek is non-counting.
        assert_eq!(nat.stats().reply_received, 0);
        assert_eq!(nat.stats().reply_dropped, 0);
        let unknown = udp_packet([8, 8, 8, 8], [10, 0, 0, 1], 53, 9999);
        assert_eq!(nat.peek_reply(&unknown), None);
    }
}
