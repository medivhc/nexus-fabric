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
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::routing::{Cidr, parse_ipv4_dst};

/// Lock helper that tolerates poisoning (a panicked thread must not
/// permanently break the egress path).
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// A single CIDR → [`RouteTarget`] rule. First match wins.
#[derive(Debug, Clone)]
pub struct Rule {
    pub cidr: Cidr,
    pub target: RouteTarget,
}

/// Domain match kind (3b-3, S16).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainMatch {
    /// Exact hostname, e.g. `ads.example.com`.
    Exact(String),
    /// Suffix, e.g. `example.com` matches `www.example.com` and itself.
    Suffix(String),
    /// Substring, e.g. `ads` matches `ads-tracker.example.com`.
    Keyword(String),
}

/// A domain → [`RouteTarget`] rule. Checked before IP rules (S16):
/// exact > suffix > keyword; first added wins within a kind.
#[derive(Debug, Clone)]
pub struct DomainRule {
    pub matcher: DomainMatch,
    pub target: RouteTarget,
}

/// Normalize a domain for comparison: lowercase, no trailing dot.
fn normalize_domain(d: &str) -> String {
    d.trim().trim_end_matches('.').to_lowercase()
}

impl DomainMatch {
    /// Does this matcher hit the (already normalized) domain?
    fn matches(&self, domain: &str) -> bool {
        match self {
            DomainMatch::Exact(e) => domain == e,
            DomainMatch::Suffix(s) => domain == s || domain.ends_with(&format!(".{s}")),
            DomainMatch::Keyword(k) => domain.contains(k),
        }
    }

    /// Priority rank for S16 ordering (lower = checked first).
    fn rank(&self) -> u8 {
        match self {
            DomainMatch::Exact(_) => 0,
            DomainMatch::Suffix(_) => 1,
            DomainMatch::Keyword(_) => 2,
        }
    }
}

/// P0 minimal rule engine: ordered CIDR rules over the packet's IPv4
/// destination. First match wins; no match (or unparsable packet) → `Drop`.
///
/// 3b-3: domain rules (`Exact`/`Suffix`/`Keyword`). When `req.domain` is
/// `Some`, domain rules are consulted first (exact > suffix > keyword,
/// S16); a domain miss falls back to the IP rules.
pub struct SimpleRuleEngine {
    rules: Vec<Rule>,
    domain_rules: Vec<DomainRule>,
}

impl SimpleRuleEngine {
    pub fn new(rules: Vec<Rule>) -> Self {
        Self {
            rules,
            domain_rules: Vec::new(),
        }
    }

    /// Number of rules (observability).
    pub fn rule_count(&self) -> usize {
        self.rules.len() + self.domain_rules.len()
    }

    /// Add a DOMAIN-SUFFIX rule (normalized; empty suffixes are ignored).
    pub fn add_domain_suffix_rule(&mut self, suffix: &str, target: RouteTarget) {
        let s = normalize_domain(suffix);
        if s.is_empty() {
            return;
        }
        self.domain_rules.push(DomainRule {
            matcher: DomainMatch::Suffix(s),
            target,
        });
    }

    /// Add a DOMAIN (exact) rule.
    pub fn add_domain_exact_rule(&mut self, domain: &str, target: RouteTarget) {
        let d = normalize_domain(domain);
        if d.is_empty() {
            return;
        }
        self.domain_rules.push(DomainRule {
            matcher: DomainMatch::Exact(d),
            target,
        });
    }

    /// Add a DOMAIN-KEYWORD rule.
    pub fn add_domain_keyword_rule(&mut self, keyword: &str, target: RouteTarget) {
        let k = normalize_domain(keyword);
        if k.is_empty() {
            return;
        }
        self.domain_rules.push(DomainRule {
            matcher: DomainMatch::Keyword(k),
            target,
        });
    }

    /// Number of domain rules (observability).
    pub fn domain_rule_count(&self) -> usize {
        self.domain_rules.len()
    }

    /// Match domain rules only (S16 ordering). Returns `None` on miss.
    fn match_domain(&self, domain: &str) -> Option<RouteTarget> {
        let domain = normalize_domain(domain);
        if domain.is_empty() {
            return None;
        }
        for rank in 0..=2u8 {
            for r in &self.domain_rules {
                if r.matcher.rank() == rank && r.matcher.matches(&domain) {
                    return Some(r.target.clone());
                }
            }
        }
        None
    }
}

impl RuleEngine for SimpleRuleEngine {
    fn decide(&self, req: &RouteRequest) -> RouteTarget {
        // S16: domain rules take priority over IP rules.
        if let Some(domain) = req.domain {
            if let Some(target) = self.match_domain(domain) {
                return target;
            }
            // Miss: fall through to IP rules.
        }
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
    /// Original outbound 5-tuple (S19). For the mock path this equals the
    /// table key; for the real-socket path the key is the *translated*
    /// tuple (socket address) and `orig` is needed to rebuild the reply
    /// IP packet for the originator.
    pub orig: FlowKey,
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
    /// Entries evicted (timeout + capacity bound, S14).
    pub evicted: u64,
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
        self.record_flow(key, key, peer);
        Some(packet.to_vec())
    }

    /// Record a flow under an explicit key (S18/S19).
    ///
    /// The mock path records under the packet's own 5-tuple (`key == orig`).
    /// The real-socket path records under the *translated* key (the flow
    /// socket's address) with `orig` = the original 5-tuple, so socket
    /// replies reverse-lookup correctly.
    ///
    /// S14: if the table is full, evict the oldest entry first.
    pub fn record_flow(&mut self, key: FlowKey, orig: FlowKey, peer: &str) {
        if !self.table.contains_key(&key) && self.table.len() >= self.max_entries {
            self.evict_oldest();
        }
        self.table.insert(
            key,
            NatEntry {
                peer: peer.to_string(),
                last_seen: Instant::now(),
                orig,
            },
        );
        self.stats.egress_handled += 1;
        self.stats.current_flows = self.table.len();
    }

    /// Inbound reply: reverse-lookup the flow. Returns the packet and the
    /// originating peer, or `None` (counted in `reply_dropped`).
    pub fn translate_inbound(&mut self, packet: &[u8]) -> Option<(Vec<u8>, String)> {
        let reply_key = FlowKey::parse(packet)?;
        let (_, peer) = self.lookup_reply(&reply_key)?;
        Some((packet.to_vec(), peer))
    }

    /// Reverse-lookup by explicit reply key (S19).
    ///
    /// Returns the recorded original 5-tuple and the origin peer, or `None`
    /// (counted in `reply_dropped`). Refreshes `last_seen` on hit, mirroring
    /// [`EgressNat::translate_inbound`].
    pub fn lookup_reply(&mut self, reply_key: &FlowKey) -> Option<(FlowKey, String)> {
        let orig_key = reply_key.reversed();
        match self.table.get_mut(&orig_key) {
            Some(entry) => {
                entry.last_seen = Instant::now();
                self.stats.reply_received += 1;
                Some((entry.orig, entry.peer.clone()))
            }
            None => {
                self.stats.reply_dropped += 1;
                None
            }
        }
    }

    /// Does the table contain `key`? Used to prune dead flow sockets (S20).
    pub fn contains(&self, key: &FlowKey) -> bool {
        self.table.contains_key(key)
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
            self.stats.evicted += 1;
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

/// Counters for the real UDP egress path (S18/S19).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RealEgressStats {
    /// Packets forwarded via the real socket (S18).
    pub real_sent: u64,
    /// Socket send failures (counted, never panics, S18).
    pub egress_send_failed: u64,
    /// Non-UDP packets dropped (P0 is UDP-only, S18).
    pub egress_tcp_dropped: u64,
    /// Replies reverse-NAT-matched and handed back (S19).
    pub reply_routed: u64,
    /// Replies with no NAT mapping dropped (S19).
    pub unmapped_dropped: u64,
}

/// Split an IPv4/UDP packet into (udp_payload, flow_key).
/// `None` for non-UDP or malformed packets (S18: P0 is UDP-only).
fn udp_payload(packet: &[u8]) -> Option<(&[u8], FlowKey)> {
    let key = FlowKey::parse(packet)?;
    if key.proto != 17 {
        return None;
    }
    let ihl = ((packet[0] & 0x0F) as usize) * 4;
    if packet.len() < ihl + 8 {
        return None;
    }
    Some((&packet[ihl + 8..], key))
}

/// Translated NAT key for a flow socket: `{src: bound_addr, dst: orig.dst}`.
///
/// The socket is bound to `0.0.0.0:ephemeral`; the wildcard is used verbatim
/// on both record and reply lookup, so the keys match. The ephemeral port is
/// unique per flow socket, which is what demultiplexes replies.
fn translated_key(sock: &UdpSocket, orig: &FlowKey) -> Option<FlowKey> {
    let local = sock.local_addr().ok()?;
    let src_ip = match local.ip() {
        IpAddr::V4(v) => u32::from_be_bytes(v.octets()),
        IpAddr::V6(_) => return None, // P0: IPv4 only
    };
    Some(FlowKey {
        src_ip,
        src_port: local.port(),
        dst_ip: orig.dst_ip,
        dst_port: orig.dst_port,
        proto: 17,
    })
}

/// IPv4 header checksum (one's complement).
fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in header.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]]) as u32
        } else {
            (chunk[0] as u32) << 8
        };
        sum += word;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Rebuild a full IPv4/UDP packet for a reply (S19).
///
/// `orig` is the recorded original 5-tuple: the reply's source is the
/// original destination and vice versa. The originator's downlink parses
/// this packet for NAT validation (S11), so it must be well-formed.
fn build_reply_packet(orig: &FlowKey, payload: &[u8]) -> Vec<u8> {
    let mut pkt = vec![0u8; 20 + 8 + payload.len()];
    let total_len = pkt.len() as u16;
    pkt[0] = 0x45; // v4, IHL 5
    pkt[2..4].copy_from_slice(&total_len.to_be_bytes());
    pkt[8] = 64; // TTL
    pkt[9] = 17; // UDP
    pkt[12..16].copy_from_slice(&orig.dst_ip.to_be_bytes()); // src = orig dst
    pkt[16..20].copy_from_slice(&orig.src_ip.to_be_bytes()); // dst = orig src
    let csum = ipv4_checksum(&pkt[..20]);
    pkt[10..12].copy_from_slice(&csum.to_be_bytes());
    pkt[20..22].copy_from_slice(&orig.dst_port.to_be_bytes());
    pkt[22..24].copy_from_slice(&orig.src_port.to_be_bytes());
    pkt[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    // UDP checksum 0 = not computed (valid for IPv4).
    pkt[28..].copy_from_slice(payload);
    pkt
}

/// Real UDP egress: forwards egress-intent packets via OS sockets (S18/S19/S20).
///
/// P0 design:
/// - One `UdpSocket` per flow (bound `0.0.0.0:0`, non-blocking). A single
///   socket cannot demultiplex concurrent flows to the same destination
///   (every reply would share the source port), so per-flow sockets are the
///   correct userspace NAT. The fd cost is bounded by NAT eviction (S14);
///   a socket pool is P1 work, not hidden here.
/// - The NAT table is keyed by the *translated* 5-tuple
///   (`translated_key`); replies reverse-lookup to the origin peer and the
///   recorded original 5-tuple, from which a full IP packet is rebuilt.
/// - Unmapped replies are dropped and counted, never forwarded blindly.
///
/// Zero Tokio; std-only. Shared with `Projection` via `Arc`; the
/// `egress-recv` thread polls [`RealUdpEgress::recv_reply`].
pub struct RealUdpEgress {
    nat: Arc<Mutex<EgressNat>>,
    /// Original FlowKey -> flow socket.
    sockets: Mutex<HashMap<FlowKey, UdpSocket>>,
    stats: Mutex<RealEgressStats>,
}

impl RealUdpEgress {
    /// Create with the shared NAT table. The probe bind fails fast when UDP
    /// is unavailable (e.g. sandboxed), so callers can SKIP instead of FAIL.
    pub fn new(nat: Arc<Mutex<EgressNat>>) -> io::Result<Self> {
        let probe = UdpSocket::bind("0.0.0.0:0")?;
        drop(probe);
        Ok(Self {
            nat,
            sockets: Mutex::new(HashMap::new()),
            stats: Mutex::new(RealEgressStats::default()),
        })
    }

    /// Forward one egress packet via the real socket (S18).
    ///
    /// Records the flow under the translated key, then sends the UDP payload
    /// to the packet's destination. Non-UDP packets are dropped and counted
    /// (`egress_tcp_dropped`). Send failures are counted
    /// (`egress_send_failed`); the NAT record is retained so a retransmit can
    /// still match the reply. Never panics; returns `false` on drop.
    pub fn send(&self, packet: &[u8], peer: &str) -> bool {
        let (payload, orig) = match udp_payload(packet) {
            Some(x) => x,
            None => {
                lock(&self.stats).egress_tcp_dropped += 1;
                return false;
            }
        };
        // Lock order (sockets -> nat) is the same in `recv_reply`.
        let mut sockets = lock(&self.sockets);
        // Prune sockets whose NAT entry is gone (evicted/expired, S20).
        {
            let nat = lock(&self.nat);
            sockets.retain(|o, s| {
                translated_key(s, o)
                    .map(|t| nat.contains(&t))
                    .unwrap_or(false)
            });
        }
        // Get-or-create the flow socket; retransmits reuse it (S18).
        if !sockets.contains_key(&orig) {
            match UdpSocket::bind("0.0.0.0:0") {
                Ok(s) => {
                    let _ = s.set_nonblocking(true);
                    sockets.insert(orig, s);
                }
                Err(_) => {
                    lock(&self.stats).egress_send_failed += 1;
                    return false;
                }
            }
        }
        let sock = &sockets[&orig];
        let trans = match translated_key(sock, &orig) {
            Some(t) => t,
            None => {
                lock(&self.stats).egress_send_failed += 1;
                return false;
            }
        };
        let dst = SocketAddr::from((Ipv4Addr::from(orig.dst_ip), orig.dst_port));
        // Record before send: the mapping survives a send failure (S18).
        lock(&self.nat).record_flow(trans, orig, peer);
        match sock.send_to(payload, dst) {
            Ok(_) => {
                lock(&self.stats).real_sent += 1;
                true
            }
            Err(_) => {
                lock(&self.stats).egress_send_failed += 1;
                false
            }
        }
    }

    /// Poll all flow sockets for a reply (non-blocking, S19).
    ///
    /// Returns the reply rebuilt as a full IP packet plus the origin peer,
    /// or `None` when no reply is ready. Unmapped replies are dropped and
    /// counted (`unmapped_dropped`); a dead flow's socket is pruned, but a
    /// junk probe on a *live* flow never kills it.
    pub fn recv_reply(&self) -> Option<(Vec<u8>, String)> {
        // Phase 1: poll sockets (sockets lock only).
        let hit: Option<(FlowKey, FlowKey, Vec<u8>, SocketAddr)> = {
            let sockets = lock(&self.sockets);
            let mut out = None;
            for (orig, sock) in sockets.iter() {
                let mut buf = [0u8; 65535];
                match sock.recv_from(&mut buf) {
                    Ok((n, src)) => {
                        if let Some(trans) = translated_key(sock, orig) {
                            out = Some((*orig, trans, buf[..n].to_vec(), src));
                            break;
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                    Err(_) => continue, // broken socket: pruned on next send
                }
            }
            out
        };
        let (orig, trans, payload, src) = hit?;
        // Phase 2: NAT reverse lookup (nat lock only).
        let src_ip = match src.ip() {
            IpAddr::V4(v) => u32::from_be_bytes(v.octets()),
            IpAddr::V6(_) => {
                lock(&self.stats).unmapped_dropped += 1;
                return None;
            }
        };
        let reply_key = FlowKey {
            src_ip,
            src_port: src.port(),
            dst_ip: trans.src_ip,
            dst_port: trans.src_port,
            proto: 17,
        };
        let mut nat = lock(&self.nat);
        match nat.lookup_reply(&reply_key) {
            Some((orig_key, peer)) => {
                let pkt = build_reply_packet(&orig_key, &payload);
                lock(&self.stats).reply_routed += 1;
                Some((pkt, peer))
            }
            None => {
                lock(&self.stats).unmapped_dropped += 1;
                // Prune only when the flow itself is gone; a junk probe on
                // a live flow must not kill it.
                if !nat.contains(&trans) {
                    drop(nat);
                    lock(&self.sockets).remove(&orig);
                }
                None
            }
        }
    }

    /// Bound addresses of live flow sockets (observability / E4 probing).
    pub fn socket_addrs(&self) -> Vec<SocketAddr> {
        lock(&self.sockets)
            .values()
            .filter_map(|s| s.local_addr().ok())
            .collect()
    }

    /// Number of live flow sockets.
    pub fn socket_count(&self) -> usize {
        lock(&self.sockets).len()
    }

    /// Egress counters (S18/S19).
    pub fn stats(&self) -> RealEgressStats {
        *lock(&self.stats)
    }

    /// Drop all flow sockets (S20). Idempotent; a polling recv thread
    /// observes the empty set and exits so the owner can join it.
    pub fn shutdown_sockets(&self) {
        lock(&self.sockets).clear();
    }

    /// Consuming close: drop sockets, release resources (S20).
    pub fn close(self) {
        self.shutdown_sockets();
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
        assert_eq!(nat.stats().evicted, 0);

        // One more: oldest (sport 1000) evicted, newest kept.
        let pkt = udp_packet([10, 0, 0, 1], [8, 8, 8, 8], 2000, 53);
        nat.translate_outbound(&pkt, "self");
        assert_eq!(nat.flow_count(), 3);
        assert_eq!(nat.stats().evicted, 1);
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
        assert_eq!(nat.stats().evicted, 0);
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

    /// Engine with a domain suffix rule plus IP rules (S16 test fixture).
    fn domain_engine() -> SimpleRuleEngine {
        let mut e = SimpleRuleEngine::new(vec![
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
        e.add_domain_suffix_rule(
            "blocked.example",
            RouteTarget::Egress {
                peer: "B".to_string(),
            },
        );
        e
    }

    #[test]
    fn s16_domain_suffix_beats_ip_rule() {
        // dst 1.2.3.4 would Drop by IP rule, but the domain rule wins (S16).
        let e = domain_engine();
        let pkt = udp_packet([10, 0, 0, 1], [1, 2, 3, 4], 1234, 80);
        let req = RouteRequest {
            packet: &pkt,
            domain: Some("www.blocked.example"),
        };
        assert_eq!(
            e.decide(&req),
            RouteTarget::Egress {
                peer: "B".to_string()
            }
        );
        // Suffix also matches the bare domain itself.
        let req = RouteRequest {
            packet: &pkt,
            domain: Some("blocked.example"),
        };
        assert_eq!(
            e.decide(&req),
            RouteTarget::Egress {
                peer: "B".to_string()
            }
        );
        // ...but not a lookalike that merely shares a tail.
        let req = RouteRequest {
            packet: &pkt,
            domain: Some("notblocked.example"),
        };
        assert_eq!(e.decide(&req), RouteTarget::Drop);
    }

    #[test]
    fn s16_domain_no_match_falls_back_to_ip() {
        let e = domain_engine();
        // No domain rule for this host: IP rules decide (S16 fallback).
        let pkt = udp_packet([10, 0, 0, 1], [8, 8, 8, 8], 1234, 80);
        let req = RouteRequest {
            packet: &pkt,
            domain: Some("www.allowed.example"),
        };
        assert_eq!(
            e.decide(&req),
            RouteTarget::Egress {
                peer: "self".to_string()
            }
        );
        // domain=None behaves exactly like the old IP-only engine.
        let req = RouteRequest {
            packet: &pkt,
            domain: None,
        };
        assert_eq!(
            e.decide(&req),
            RouteTarget::Egress {
                peer: "self".to_string()
            }
        );
    }

    #[test]
    fn s16_domain_kind_priority_exact_over_suffix_over_keyword() {
        let mut e = SimpleRuleEngine::new(vec![]);
        // All three kinds match www.ads.example.com; exact must win.
        e.add_domain_keyword_rule("ads", RouteTarget::Drop);
        e.add_domain_suffix_rule(
            "example.com",
            RouteTarget::Egress {
                peer: "suffix".to_string(),
            },
        );
        e.add_domain_exact_rule(
            "www.ads.example.com",
            RouteTarget::Egress {
                peer: "exact".to_string(),
            },
        );
        let pkt = udp_packet([10, 0, 0, 1], [8, 8, 8, 8], 1, 80);
        let req = RouteRequest {
            packet: &pkt,
            domain: Some("www.ads.example.com"),
        };
        assert_eq!(
            e.decide(&req),
            RouteTarget::Egress {
                peer: "exact".to_string()
            }
        );
        // Suffix beats keyword for a host with no exact rule.
        let req = RouteRequest {
            packet: &pkt,
            domain: Some("cdn.ads.example.com"),
        };
        assert_eq!(
            e.decide(&req),
            RouteTarget::Egress {
                peer: "suffix".to_string()
            }
        );
        // Keyword alone.
        let req = RouteRequest {
            packet: &pkt,
            domain: Some("ads-tracker.other.net"),
        };
        assert_eq!(e.decide(&req), RouteTarget::Drop);
    }

    #[test]
    fn s16_domain_matching_case_insensitive() {
        let mut e = SimpleRuleEngine::new(vec![]);
        e.add_domain_suffix_rule(
            "Blocked.Example.",
            RouteTarget::Egress {
                peer: "B".to_string(),
            },
        );
        assert_eq!(e.domain_rule_count(), 1);
        let pkt = udp_packet([10, 0, 0, 1], [8, 8, 8, 8], 1, 80);
        let req = RouteRequest {
            packet: &pkt,
            domain: Some("WWW.BLOCKED.EXAMPLE"),
        };
        assert_eq!(
            e.decide(&req),
            RouteTarget::Egress {
                peer: "B".to_string()
            }
        );
        // Empty matchers are ignored (never match-all).
        e.add_domain_keyword_rule("", RouteTarget::Drop);
        e.add_domain_suffix_rule(".", RouteTarget::Drop);
        assert_eq!(e.domain_rule_count(), 1);
    }

    // ---- 3b-4 real UDP egress (S18/S19/S20) ----
    // NOTE: these tests need real loopback UDP. They fail in the sandbox
    // (EPERM on sendto) and pass on xc-pc-linux; that is an environment
    // limitation, not a code defect.

    use std::net::UdpSocket as TestUdpSocket;
    use std::thread as test_thread;

    /// Bind a loopback "internet" endpoint. Panics with a clear message if
    /// UDP is unavailable (so the failure is diagnosable, not silent).
    fn fake_internet() -> TestUdpSocket {
        let s = TestUdpSocket::bind("127.0.0.1:0").expect("loopback UDP unavailable");
        s.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("set_read_timeout");
        s
    }

    fn real_egress() -> (RealUdpEgress, Arc<Mutex<EgressNat>>) {
        let nat = Arc::new(Mutex::new(EgressNat::default()));
        let re = RealUdpEgress::new(Arc::clone(&nat)).expect("RealUdpEgress::new");
        (re, nat)
    }

    /// Poll `f` until it returns `Some`, or panic after the deadline.
    fn poll_until<T>(f: impl Fn() -> Option<T>, what: &str) -> T {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(v) = f() {
                return v;
            }
            if Instant::now() > deadline {
                panic!("timed out waiting for {what}");
            }
            test_thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn real_egress_sends_via_socket() {
        // S18: the egress node forwards the UDP payload via a real socket.
        let internet = fake_internet();
        let dst_port = internet.local_addr().unwrap().port();
        let (re, nat) = real_egress();

        let pkt = udp_packet([10, 0, 0, 1], [127, 0, 0, 1], 40000, dst_port);
        assert!(re.send(&pkt, "A"));

        let st = re.stats();
        assert_eq!(st.real_sent, 1);
        assert_eq!(st.egress_send_failed, 0);
        assert_eq!(st.egress_tcp_dropped, 0);
        assert_eq!(re.socket_count(), 1);

        // The fake internet receives exactly the UDP payload.
        let mut buf = [0u8; 64];
        let (n, _src) = internet.recv_from(&mut buf).expect("recv echo request");
        assert_eq!(&buf[..n], &[1, 2, 3, 4]);

        // NAT recorded the flow (translated key).
        assert_eq!(nat.lock().unwrap().flow_count(), 1);

        // Retransmit reuses the socket (no new socket, S18).
        assert!(re.send(&pkt, "A"));
        assert_eq!(re.socket_count(), 1);
        assert_eq!(re.stats().real_sent, 2);
    }

    #[test]
    fn real_egress_send_failure_counted() {
        // S18: send failure counted, never panics, returns false — and the
        // NAT record is retained so a retransmit can still match the reply.
        let (re, nat) = real_egress();
        // Port 0 is invalid: send_to fails deterministically.
        let pkt = udp_packet([10, 0, 0, 1], [127, 0, 0, 1], 40001, 0);
        assert!(!re.send(&pkt, "A"));
        let st = re.stats();
        assert_eq!(st.egress_send_failed, 1);
        assert_eq!(st.real_sent, 0);
        assert_eq!(nat.lock().unwrap().flow_count(), 1);
    }

    #[test]
    fn real_egress_reply_reverse_nat() {
        // S19: a reply on the flow socket reverse-NATs to the origin peer,
        // rebuilt as a full IP packet the originator can validate.
        let internet = fake_internet();
        let dst_port = internet.local_addr().unwrap().port();
        let (re, _nat) = real_egress();

        let pkt = udp_packet([10, 0, 0, 1], [127, 0, 0, 1], 40002, dst_port);
        assert!(re.send(&pkt, "peer-A"));

        // Fake internet echoes the payload back to the flow socket.
        let mut buf = [0u8; 64];
        let (n, src) = internet.recv_from(&mut buf).expect("recv");
        internet.send_to(&buf[..n], src).expect("echo");

        let (ip_pkt, peer) = poll_until(|| re.recv_reply(), "egress reply");
        assert_eq!(peer, "peer-A");

        // Rebuilt IP packet: src = original dst, dst = original src.
        let key = FlowKey::parse(&ip_pkt).expect("well-formed reply packet");
        assert_eq!(key.src_ip, u32::from_be_bytes([127, 0, 0, 1]));
        assert_eq!(key.dst_ip, u32::from_be_bytes([10, 0, 0, 1]));
        assert_eq!(key.src_port, dst_port);
        assert_eq!(key.dst_port, 40002);
        assert_eq!(key.proto, 17);
        assert_eq!(&ip_pkt[28..], &[1, 2, 3, 4]); // payload intact

        let st = re.stats();
        assert_eq!(st.reply_routed, 1);
        assert_eq!(st.unmapped_dropped, 0);
    }

    #[test]
    fn real_egress_unmapped_reply_dropped() {
        // S19: a reply with no NAT mapping is dropped and counted — never
        // forwarded blindly. A junk probe on a *live* flow must not kill it.
        let internet = fake_internet();
        let dst_port = internet.local_addr().unwrap().port();
        let (re, _nat) = real_egress();

        let pkt = udp_packet([10, 0, 0, 1], [127, 0, 0, 1], 40003, dst_port);
        assert!(re.send(&pkt, "A"));
        let addrs = re.socket_addrs();
        assert_eq!(addrs.len(), 1);

        // Attacker socket (not the flow's peer) sends junk to the flow socket.
        let attacker = fake_internet();
        attacker
            .send_to(b"junk-unmapped-probe", addrs[0])
            .expect("probe send");

        poll_until(
            || {
                if re.stats().unmapped_dropped == 1 {
                    Some(())
                } else {
                    None
                }
            },
            "unmapped drop",
        );
        let st = re.stats();
        assert_eq!(st.unmapped_dropped, 1);
        assert_eq!(st.reply_routed, 0);
        // The live flow's socket survived the probe.
        assert_eq!(re.socket_count(), 1);

        // The real reply still routes afterwards.
        let mut buf = [0u8; 64];
        let (n, src) = internet.recv_from(&mut buf).expect("recv");
        internet.send_to(&buf[..n], src).expect("echo");
        let (ip_pkt, peer) = poll_until(|| re.recv_reply(), "reply after probe");
        assert_eq!(peer, "A");
        assert_eq!(FlowKey::parse(&ip_pkt).unwrap().dst_port, 40003);
    }

    #[test]
    fn real_egress_tcp_dropped() {
        // S18: P0 is UDP-only; TCP packets are dropped and counted, and no
        // socket is created for them.
        let (re, nat) = real_egress();
        let mut pkt = udp_packet([10, 0, 0, 1], [127, 0, 0, 1], 40004, 80);
        pkt[9] = 6; // TCP
        assert!(!re.send(&pkt, "A"));
        let st = re.stats();
        assert_eq!(st.egress_tcp_dropped, 1);
        assert_eq!(st.real_sent, 0);
        assert_eq!(re.socket_count(), 0);
        assert_eq!(nat.lock().unwrap().flow_count(), 0);
    }

    #[test]
    fn real_egress_close_joins_thread() {
        // S20: closing drops the sockets; a polling recv thread observes the
        // empty set and exits, so the owner can join it.
        let (re, _nat) = real_egress();
        let re = Arc::new(re);
        // Port-0 send fails but still creates the flow socket.
        let pkt = udp_packet([10, 0, 0, 1], [127, 0, 0, 1], 40005, 0);
        assert!(!re.send(&pkt, "A"));
        assert_eq!(re.socket_count(), 1);

        let re2 = Arc::clone(&re);
        let h = test_thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                if re2.socket_count() == 0 {
                    break;
                }
                let _ = re2.recv_reply();
                assert!(
                    Instant::now() < deadline,
                    "recv thread did not observe close"
                );
                test_thread::sleep(Duration::from_millis(1));
            }
        });
        test_thread::sleep(Duration::from_millis(50));
        re.shutdown_sockets();
        h.join().expect("recv thread joined after close");
        assert_eq!(re.socket_count(), 0);

        // Consuming close on an owned value.
        let (re2, _nat2) = real_egress();
        re2.close();
    }
}
