//! DNS wire-format sniffing + domain→IP cache (S15/S17).
//!
//! std-only, zero-dependency minimal DNS parser. [`UnifiedRouter`] uses it to
//! fill `RouteRequest.domain` from DNS queries and to learn domain→IP
//! mappings from DNS responses.
//!
//! S15: sniffing never modifies packets. Any parse failure (non-DNS payload,
//! truncated packet, bad compression pointers) yields "not DNS" and the
//! packet is routed by ordinary IP rules — never dropped. `sniff_failed` is
//! a debug-only counter, not an error metric.
//!
//! S37: responses are only trusted when their TXID matches a query this
//! sniffer actually saw (pending-query table, bounded + expiring). This
//! keeps stray/spoofed port-53 traffic out of the resolution cache.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Max DNS TTL honored by the cache (S17): min(dns_ttl, 300s).
pub const DNS_CACHE_TTL_CAP: Duration = Duration::from_secs(300);

/// Max cached domain→IP mappings (S17).
pub const DEFAULT_DNS_CACHE_ENTRIES: usize = 4096;

/// Max pending DNS queries tracked for TXID validation (S37).
pub const DNS_PENDING_CAP: usize = 4096;

/// Age after which a pending query no longer validates a response (S37).
/// Real resolutions complete in milliseconds; 60s is generous headroom.
pub const DNS_PENDING_TTL: Duration = Duration::from_secs(60);

/// Result of sniffing one IP packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sniffed {
    /// DNS query: the (lowercased, trailing-dot-stripped) QNAME plus the
    /// message TXID (S37: recorded in the pending table).
    Query { txid: u16, qname: String },
    /// DNS response: message TXID plus extracted (domain, ip, ttl_secs)
    /// A/AAAA records. Only produced when the TXID matches a pending
    /// query (S37); otherwise the packet is `NotDns`.
    Response {
        txid: u16,
        records: Vec<(String, IpAddr, u32)>,
    },
    /// Not a DNS packet (or sniffing failed — S15: route normally).
    NotDns,
}

fn read_u16(buf: &[u8], off: usize) -> Option<u16> {
    let b = buf.get(off..off + 2)?;
    Some(u16::from_be_bytes([b[0], b[1]]))
}

fn read_u32(buf: &[u8], off: usize) -> Option<u32> {
    let b = buf.get(off..off + 4)?;
    Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

/// Read a DNS name at `offset`, following compression pointers (0xC0..).
///
/// Returns `(decoded_name, offset_past_the_name_field)`. The name is
/// lowercased with no trailing dot. `None` on truncation, pointer loops,
/// or overlong names.
fn read_name(buf: &[u8], mut off: usize) -> Option<(String, usize)> {
    let mut out: Vec<u8> = Vec::new();
    let mut jumped = false;
    let mut end = 0usize;
    let mut jumps = 0u8;
    loop {
        let b = *buf.get(off)?;
        if b & 0xC0 == 0xC0 {
            // Compression pointer: 2 bytes, top 2 bits set.
            let lo = *buf.get(off + 1)?;
            let target = (((b & 0x3F) as usize) << 8) | usize::from(lo);
            if !jumped {
                end = off + 2;
            }
            jumped = true;
            jumps += 1;
            if jumps > 16 {
                return None; // pointer loop protection
            }
            off = target;
            continue;
        }
        if b == 0x00 {
            if !jumped {
                end = off + 1;
            }
            break;
        }
        // Plain label: length byte (top bits clear here) + bytes.
        let len = usize::from(b);
        off += 1;
        let label = buf.get(off..off + len)?;
        if !out.is_empty() {
            out.push(b'.');
        }
        out.extend_from_slice(label);
        if out.len() > 255 {
            return None; // overlong name
        }
        off += len;
    }
    let name = String::from_utf8(out).ok()?.to_lowercase();
    Some((name, end))
}

/// Parse a DNS query message (UDP payload) → the QNAME.
///
/// Requires: ≥12 bytes, QR=0 (query), QDCOUNT=1, one well-formed question.
/// Returns `None` for anything else (S15).
pub fn parse_dns_query(payload: &[u8]) -> Option<String> {
    if payload.len() < 12 {
        return None;
    }
    if payload[2] & 0x80 != 0 {
        return None; // not a query (QR set)
    }
    if read_u16(payload, 4)? != 1 {
        return None; // QDCOUNT != 1
    }
    let (qname, off) = read_name(payload, 12)?;
    // QTYPE (2) + QCLASS (2) must be present.
    payload.get(off..off + 4)?;
    Some(qname)
}

/// Parse a DNS response message (UDP payload) → A/AAAA records.
///
/// Each record is `(domain, ip, ttl_secs)` with the domain lowercased.
/// Requires the response bit (QR); returns an empty vec on any structural
/// failure or when there are no A/AAAA records (S15: never panics).
pub fn parse_dns_response(payload: &[u8]) -> Vec<(String, IpAddr, u32)> {
    let mut out = Vec::new();
    if payload.len() < 12 {
        return out;
    }
    if payload[2] & 0x80 == 0 {
        return out; // not a response (QR clear)
    }
    let qdcount = read_u16(payload, 4).unwrap_or(0);
    let ancount = read_u16(payload, 6).unwrap_or(0);
    let mut off = 12usize;

    // Skip the question section.
    for _ in 0..qdcount.min(8) {
        let (_, next) = match read_name(payload, off) {
            Some(t) => t,
            None => return out,
        };
        off = next;
        // QTYPE + QCLASS.
        if payload.get(off..off + 4).is_none() {
            return out;
        }
        off += 4;
    }

    // Answers.
    for _ in 0..ancount.min(64) {
        let (name, next) = match read_name(payload, off) {
            Some(t) => t,
            None => break,
        };
        off = next;
        let rtype = match read_u16(payload, off) {
            Some(t) => t,
            None => break,
        };
        let rclass = match read_u16(payload, off + 2) {
            Some(c) => c,
            None => break,
        };
        let ttl = match read_u32(payload, off + 4) {
            Some(t) => t,
            None => break,
        };
        let rdlen = match read_u16(payload, off + 8) {
            Some(l) => usize::from(l),
            None => break,
        };
        off += 10;
        let rdata = match payload.get(off..off + rdlen) {
            Some(r) => r,
            None => break,
        };
        off += rdlen;
        if rclass != 1 {
            continue; // IN class only
        }
        let ip: IpAddr = match (rtype, rdlen) {
            (1, 4) => IpAddr::V4(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3])),
            (28, 16) => {
                let mut b = [0u8; 16];
                b.copy_from_slice(rdata);
                IpAddr::V6(Ipv6Addr::from(b))
            }
            _ => continue,
        };
        out.push((name, ip, ttl));
    }
    out
}

/// Extract (src_port, dst_port, udp_payload) from an IPv4/UDP packet.
/// Returns `None` for non-IPv4, truncated, or non-UDP packets.
fn udp_payload(packet: &[u8]) -> Option<(u16, u16, &[u8])> {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return None;
    }
    let ihl = (usize::from(packet[0] & 0x0F)) * 4;
    if ihl < 20 || packet[9] != 17 {
        return None; // not UDP
    }
    if packet.len() < ihl + 8 {
        return None;
    }
    let sport = u16::from_be_bytes([packet[ihl], packet[ihl + 1]]);
    let dport = u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]);
    let udp_len = usize::from(u16::from_be_bytes([packet[ihl + 4], packet[ihl + 5]]));
    if udp_len < 8 {
        return None;
    }
    let end = (ihl + udp_len).min(packet.len());
    if end < ihl + 8 {
        return None;
    }
    Some((sport, dport, &packet[ihl + 8..end]))
}

/// DNS sniffer: classifies IP packets without modifying them (S15).
///
/// S37: stateful — tracks pending queries (TXID → qname) so that only
/// responses to queries we actually saw are trusted for cache learning.
/// The wire parsing itself stays pure; only the TXID correlation table is
/// kept, bounded and expiring.
pub struct DnsSniffer {
    sniff_failed: AtomicU64,
    pending: Mutex<HashMap<u16, (String, Instant)>>,
}

impl DnsSniffer {
    pub fn new() -> Self {
        Self {
            sniff_failed: AtomicU64::new(0),
            pending: Mutex::new(HashMap::new()),
        }
    }

    /// Record an outbound query's TXID (S37). Opportunistically expires
    /// stale entries and bounds the table.
    fn note_query(&self, txid: u16, qname: String) {
        let mut p = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        p.retain(|_, (_, t)| now.duration_since(*t) <= DNS_PENDING_TTL);
        if p.len() >= DNS_PENDING_CAP {
            if let Some(oldest) = p.iter().min_by_key(|(_, (_, t))| *t).map(|(k, _)| *k) {
                p.remove(&oldest);
            }
        }
        p.insert(txid, (qname, now));
    }

    /// Consume the pending query for `txid` (S37). Returns the qname iff a
    /// live (unexpired) query was recorded.
    fn take_query(&self, txid: u16) -> Option<String> {
        let mut p = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        let (qname, t) = p.remove(&txid)?;
        if Instant::now().duration_since(t) > DNS_PENDING_TTL {
            None
        } else {
            Some(qname)
        }
    }

    /// Sniff one IP packet. Never fails: unparsable input → [`Sniffed::NotDns`].
    pub fn sniff_packet(&self, packet: &[u8]) -> Sniffed {
        let (sport, dport, payload) = match udp_payload(packet) {
            Some(t) => t,
            None => return Sniffed::NotDns,
        };
        if dport == 53 {
            let txid = match read_u16(payload, 0) {
                Some(t) => t,
                None => {
                    self.sniff_failed.fetch_add(1, Ordering::Relaxed);
                    return Sniffed::NotDns;
                }
            };
            match parse_dns_query(payload) {
                Some(qname) => {
                    self.note_query(txid, qname.clone());
                    Sniffed::Query { txid, qname }
                }
                None => {
                    self.sniff_failed.fetch_add(1, Ordering::Relaxed);
                    Sniffed::NotDns
                }
            }
        } else if sport == 53 {
            let txid = match read_u16(payload, 0) {
                Some(t) => t,
                None => {
                    self.sniff_failed.fetch_add(1, Ordering::Relaxed);
                    return Sniffed::NotDns;
                }
            };
            let records = parse_dns_response(payload);
            if records.is_empty() {
                // Either not DNS or no A/AAAA records (e.g. NXDOMAIN):
                // nothing to learn; debug-count it (S15).
                self.sniff_failed.fetch_add(1, Ordering::Relaxed);
                Sniffed::NotDns
            } else if self.take_query(txid).is_none() {
                // S37: no pending query with this TXID — the response is
                // untrusted (stray/spoofed). Don't learn from it; the packet
                // itself is routed by ordinary IP rules (S15).
                self.sniff_failed.fetch_add(1, Ordering::Relaxed);
                Sniffed::NotDns
            } else {
                Sniffed::Response { txid, records }
            }
        } else {
            Sniffed::NotDns
        }
    }

    /// Debug-only counter (S15): port-53 packets that yielded nothing.
    pub fn sniff_failed(&self) -> u64 {
        self.sniff_failed.load(Ordering::Relaxed)
    }
}

impl Default for DnsSniffer {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
struct CacheEntry {
    domain: String,
    inserted: Instant,
    ttl: Duration,
}

/// Domain→IP resolution cache (S17).
///
/// Learned from DNS responses. TTL is capped at 300s; entries expire
/// lazily on lookup (and via [`DnsCache::evict_expired`]). Bounded at
/// `max_entries`; when full, the oldest entry is evicted (`evicted`
/// counts it: `dns_cache_evicted`).
pub struct DnsCache {
    entries: HashMap<IpAddr, CacheEntry>,
    max_entries: usize,
    inserted: u64,
    evicted: u64,
}

impl DnsCache {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: HashMap::new(),
            max_entries,
            inserted: 0,
            evicted: 0,
        }
    }

    /// Insert one mapping. TTL is capped at [`DNS_CACHE_TTL_CAP`] (S17).
    /// A zero TTL expires immediately.
    pub fn insert(&mut self, domain: &str, ip: IpAddr, ttl_secs: u32) {
        let ttl = Duration::from_secs(u64::from(ttl_secs)).min(DNS_CACHE_TTL_CAP);
        if !self.entries.contains_key(&ip) && self.entries.len() >= self.max_entries {
            self.evict_oldest();
        }
        self.entries.insert(
            ip,
            CacheEntry {
                domain: domain.to_string(),
                inserted: Instant::now(),
                ttl,
            },
        );
        self.inserted += 1;
    }

    /// Insert all A/AAAA records from a parsed DNS response.
    pub fn insert_response(&mut self, records: &[(String, IpAddr, u32)]) {
        for (domain, ip, ttl) in records {
            self.insert(domain, *ip, *ttl);
        }
    }

    /// Look up the cached domain for `ip`. Expired entries are dropped and
    /// reported as a miss (S17).
    pub fn lookup(&mut self, ip: &IpAddr) -> Option<String> {
        let now = Instant::now();
        match self.entries.get(ip) {
            Some(e) if e.ttl.is_zero() => {
                self.entries.remove(ip);
                None
            }
            Some(e) if now.duration_since(e.inserted) <= e.ttl => Some(e.domain.clone()),
            Some(_) => {
                self.entries.remove(ip);
                None
            }
            None => None,
        }
    }

    /// Drop all expired entries. Returns the count removed.
    pub fn evict_expired(&mut self) -> usize {
        let now = Instant::now();
        let before = self.entries.len();
        self.entries
            .retain(|_, e| !e.ttl.is_zero() && now.duration_since(e.inserted) <= e.ttl);
        before - self.entries.len()
    }

    /// Number of live entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Total insert calls (observability, E4).
    pub fn inserted(&self) -> u64 {
        self.inserted
    }

    /// Capacity evictions (`dns_cache_evicted`, S17).
    pub fn evicted(&self) -> u64 {
        self.evicted
    }

    /// Evict the single oldest entry (capacity bound).
    fn evict_oldest(&mut self) {
        let oldest = self
            .entries
            .iter()
            .min_by_key(|(_, e)| e.inserted)
            .map(|(k, _)| *k);
        if let Some(k) = oldest {
            self.entries.remove(&k);
            self.evicted += 1;
        }
    }
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new(DEFAULT_DNS_CACHE_ENTRIES)
    }
}

/// DNS observability counters (S15/S17).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DnsStats {
    /// Total cache insert calls.
    pub cache_inserted: u64,
    /// Capacity evictions (`dns_cache_evicted`).
    pub cache_evicted: u64,
    /// Debug-only: port-53 packets that yielded nothing (S15).
    pub sniff_failed: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a DNS query message for `qname` (labels, no compression).
    fn query_msg(txid: u16, qname: &str) -> Vec<u8> {
        let mut m = vec![0u8; 12];
        m[0..2].copy_from_slice(&txid.to_be_bytes());
        m[2..4].copy_from_slice(&[0x01, 0x00]); // standard query, RD
        m[4..6].copy_from_slice(&[0x00, 0x01]); // QDCOUNT=1
        for label in qname.split('.') {
            m.push(label.len() as u8);
            m.extend_from_slice(label.as_bytes());
        }
        m.push(0x00);
        m.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // QTYPE=A, QCLASS=IN
        m
    }

    /// Build a DNS response message answering `qname` with `answers`.
    /// Uses compression pointers (0xC00C) for answer names.
    fn response_msg(txid: u16, qname: &str, answers: &[(IpAddr, u32)]) -> Vec<u8> {
        let mut m = vec![0u8; 12];
        m[0..2].copy_from_slice(&txid.to_be_bytes());
        m[2..4].copy_from_slice(&[0x81, 0x80]); // response, RD+RA
        m[4..6].copy_from_slice(&[0x00, 0x01]); // QDCOUNT=1
        m[6..8].copy_from_slice(&(answers.len() as u16).to_be_bytes()); // ANCOUNT
        for label in qname.split('.') {
            m.push(label.len() as u8);
            m.extend_from_slice(label.as_bytes());
        }
        m.push(0x00);
        m.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // QTYPE=A, QCLASS=IN
        for (ip, ttl) in answers {
            m.extend_from_slice(&[0xC0, 0x0C]); // pointer to QNAME at 12
            match ip {
                IpAddr::V4(v4) => {
                    m.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // A, IN
                    m.extend_from_slice(&ttl.to_be_bytes());
                    m.extend_from_slice(&[0x00, 0x04]);
                    m.extend_from_slice(&v4.octets());
                }
                IpAddr::V6(v6) => {
                    m.extend_from_slice(&[0x00, 0x1C, 0x00, 0x01]); // AAAA, IN
                    m.extend_from_slice(&ttl.to_be_bytes());
                    m.extend_from_slice(&[0x00, 0x10]);
                    m.extend_from_slice(&v6.octets());
                }
            }
        }
        m
    }

    /// Full IPv4/UDP packet with the given payload.
    fn udp_ip_packet(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let mut pkt = vec![0u8; 20 + 8 + payload.len()];
        pkt[0] = 0x45;
        pkt[9] = 17; // UDP
        pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
        pkt[16..20].copy_from_slice(&[8, 8, 8, 8]);
        pkt[20..22].copy_from_slice(&sport.to_be_bytes());
        pkt[22..24].copy_from_slice(&dport.to_be_bytes());
        let udp_len = (8 + payload.len()) as u16;
        pkt[24..26].copy_from_slice(&udp_len.to_be_bytes());
        pkt[28..].copy_from_slice(payload);
        pkt
    }

    #[test]
    fn parse_query_extracts_qname() {
        let q = query_msg(0x1234, "www.blocked.example");
        assert_eq!(parse_dns_query(&q), Some("www.blocked.example".to_string()));
    }

    #[test]
    fn parse_query_lowercases() {
        let q = query_msg(0x1234, "WWW.Blocked.EXAMPLE");
        assert_eq!(parse_dns_query(&q), Some("www.blocked.example".to_string()));
    }

    #[test]
    fn parse_query_malformed_returns_none() {
        assert_eq!(parse_dns_query(&[]), None);
        assert_eq!(parse_dns_query(&[0x12, 0x34]), None); // truncated header
        let mut q = query_msg(0x1234, "www.example.com");
        q[2] |= 0x80; // QR set: it's a response
        assert_eq!(parse_dns_query(&q), None);
        let mut q = query_msg(0x1234, "www.example.com");
        q[4] = 0x00;
        q[5] = 0x02; // QDCOUNT=2
        assert_eq!(parse_dns_query(&q), None);
        // Truncated QNAME.
        let q = query_msg(0x1234, "www.example.com");
        assert_eq!(parse_dns_query(&q[..15]), None);
    }

    #[test]
    fn parse_query_compression_pointer() {
        // Hand-crafted query whose QNAME is a pointer to offset 12...
        // (degenerate but must not hang or panic).
        let mut q = vec![0u8; 12];
        q[0..2].copy_from_slice(&0x1234u16.to_be_bytes());
        q[2..4].copy_from_slice(&[0x01, 0x00]);
        q[4..6].copy_from_slice(&[0x00, 0x01]);
        // QNAME = pointer to 12 (points at itself): loop → None.
        q.extend_from_slice(&[0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01]);
        assert_eq!(parse_dns_query(&q), None);
    }

    #[test]
    fn parse_response_extracts_a_records() {
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let r = response_msg(0x1234, "www.blocked.example", &[(ip, 60)]);
        let recs = parse_dns_response(&r);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].0, "www.blocked.example");
        assert_eq!(recs[0].1, ip);
        assert_eq!(recs[0].2, 60);
    }

    #[test]
    fn parse_response_extracts_aaaa_and_multiple() {
        let ip4: IpAddr = "1.2.3.4".parse().unwrap();
        let ip6: IpAddr = "2001:db8::1".parse().unwrap();
        let r = response_msg(0x1234, "WWW.Example.COM", &[(ip4, 60), (ip6, 120)]);
        let recs = parse_dns_response(&r);
        assert_eq!(recs.len(), 2);
        // Domain lowercased via compression-pointer path.
        assert_eq!(recs[0].0, "www.example.com");
        assert_eq!(recs[1].0, "www.example.com");
        assert_eq!(recs[0].1, ip4);
        assert_eq!(recs[1].1, ip6);
        assert_eq!(recs[1].2, 120);
    }

    #[test]
    fn parse_response_rejects_non_responses() {
        assert!(parse_dns_response(&[]).is_empty());
        let q = query_msg(0x1234, "www.example.com");
        assert!(parse_dns_response(&q).is_empty()); // QR clear
        assert!(parse_dns_response(&[0xFF; 20]).is_empty()); // garbage
    }

    #[test]
    fn sniffer_classifies_packets() {
        let s = DnsSniffer::new();
        // Query: dport 53.
        let q = query_msg(0x1234, "www.blocked.example");
        let pkt = udp_ip_packet(40000, 53, &q);
        assert_eq!(
            s.sniff_packet(&pkt),
            Sniffed::Query {
                txid: 0x1234,
                qname: "www.blocked.example".to_string()
            }
        );
        // Response: sport 53.
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let r = response_msg(0x1234, "www.blocked.example", &[(ip, 60)]);
        let pkt = udp_ip_packet(53, 40000, &r);
        match s.sniff_packet(&pkt) {
            Sniffed::Response { txid, records } => {
                assert_eq!(txid, 0x1234);
                assert_eq!(records.len(), 1);
                assert_eq!(records[0].1, ip);
            }
            other => panic!("expected Response, got {other:?}"),
        }
        // Ordinary UDP: neither port 53.
        let pkt = udp_ip_packet(40000, 80, b"hello");
        assert_eq!(s.sniff_packet(&pkt), Sniffed::NotDns);
        // Non-UDP (TCP): NotDns.
        let mut pkt = udp_ip_packet(40000, 53, &q);
        pkt[9] = 6;
        assert_eq!(s.sniff_packet(&pkt), Sniffed::NotDns);
        // Truncated: NotDns.
        assert_eq!(s.sniff_packet(&[0x45, 0x00]), Sniffed::NotDns);
    }

    #[test]
    fn sniffer_ignores_non_dns_udp() {
        // Garbage to port 53: sniff fails, counted, NotDns (S15).
        let s = DnsSniffer::new();
        let pkt = udp_ip_packet(40000, 53, b"\xFF\xFFgarbage-not-dns");
        assert_eq!(s.sniff_packet(&pkt), Sniffed::NotDns);
        assert_eq!(s.sniff_failed(), 1);
        // Garbage from port 53: same.
        let pkt = udp_ip_packet(53, 40000, b"\x00\x01");
        assert_eq!(s.sniff_packet(&pkt), Sniffed::NotDns);
        assert_eq!(s.sniff_failed(), 2);
    }

    #[test]
    fn cache_insert_lookup_roundtrip() {
        let mut c = DnsCache::new(4096);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        c.insert("www.blocked.example", ip, 60);
        assert_eq!(c.lookup(&ip), Some("www.blocked.example".to_string()));
        assert_eq!(c.len(), 1);
        assert_eq!(c.inserted(), 1);
        // Unknown IP: miss.
        let other: IpAddr = "9.9.9.9".parse().unwrap();
        assert_eq!(c.lookup(&other), None);
    }

    #[test]
    fn cache_ttl_capped_at_300s() {
        let mut c = DnsCache::new(4096);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        c.insert("www.example.com", ip, 3600);
        // TTL capped: internal entry ttl == 300s (S17).
        let ttl = c.entries.get(&ip).unwrap().ttl;
        assert_eq!(ttl, Duration::from_secs(300));
        assert!(c.lookup(&ip).is_some());
    }

    #[test]
    fn cache_ttl_expiry() {
        let mut c = DnsCache::new(4096);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        // Zero TTL expires immediately and deterministically.
        c.insert("www.example.com", ip, 0);
        assert_eq!(c.lookup(&ip), None);
        assert_eq!(c.len(), 0);
        // evict_expired drops zero-TTL entries too.
        c.insert("www.example.com", ip, 0);
        assert_eq!(c.evict_expired(), 1);
    }

    #[test]
    fn cache_capacity_evicts_oldest() {
        let mut c = DnsCache::new(2);
        let a: IpAddr = "1.1.1.1".parse().unwrap();
        let b: IpAddr = "2.2.2.2".parse().unwrap();
        let d: IpAddr = "3.3.3.3".parse().unwrap();
        c.insert("a.example", a, 60);
        c.insert("b.example", b, 60);
        assert_eq!(c.len(), 2);
        // Full: oldest (a) evicted for the newcomer (S17).
        c.insert("d.example", d, 60);
        assert_eq!(c.len(), 2);
        assert_eq!(c.evicted(), 1);
        assert_eq!(c.lookup(&a), None);
        assert_eq!(c.lookup(&b), Some("b.example".to_string()));
        assert_eq!(c.lookup(&d), Some("d.example".to_string()));
        // Re-inserting an existing key does not evict.
        c.insert("b2.example", b, 60);
        assert_eq!(c.len(), 2);
        assert_eq!(c.evicted(), 1);
        assert_eq!(c.lookup(&b), Some("b2.example".to_string()));
    }

    #[test]
    fn cache_insert_response_batch() {
        let mut c = DnsCache::new(4096);
        let ip4: IpAddr = "1.2.3.4".parse().unwrap();
        let ip6: IpAddr = "2001:db8::1".parse().unwrap();
        let r = response_msg(0x1234, "www.example.com", &[(ip4, 60), (ip6, 120)]);
        let recs = parse_dns_response(&r);
        c.insert_response(&recs);
        assert_eq!(c.inserted(), 2);
        assert_eq!(c.lookup(&ip4), Some("www.example.com".to_string()));
        assert_eq!(c.lookup(&ip6), Some("www.example.com".to_string()));
    }

    // S37 Red tests: DNS responses must be validated against pending queries.
    #[test]
    fn sniffer_response_without_pending_query_is_not_dns() {
        // A well-formed response whose TXID was never queried: untrusted.
        let s = DnsSniffer::new();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let r = response_msg(0xBEEF, "evil.example", &[(ip, 60)]);
        let pkt = udp_ip_packet(53, 40000, &r);
        assert_eq!(s.sniff_packet(&pkt), Sniffed::NotDns);
        assert_eq!(s.sniff_failed(), 1);
    }

    #[test]
    fn sniffer_response_txid_mismatch_is_not_dns() {
        // Query with TXID A, response with TXID B: the response is not ours.
        let s = DnsSniffer::new();
        let q = query_msg(0x1111, "www.example.com");
        let qpkt = udp_ip_packet(40000, 53, &q);
        assert!(matches!(s.sniff_packet(&qpkt), Sniffed::Query { .. }));
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let r = response_msg(0x2222, "www.example.com", &[(ip, 60)]);
        let rpkt = udp_ip_packet(53, 40000, &r);
        assert_eq!(s.sniff_packet(&rpkt), Sniffed::NotDns);
    }

    #[test]
    fn sniffer_response_matching_txid_is_trusted_once() {
        let s = DnsSniffer::new();
        let q = query_msg(0x1234, "www.example.com");
        let qpkt = udp_ip_packet(40000, 53, &q);
        match s.sniff_packet(&qpkt) {
            Sniffed::Query { txid, qname } => {
                assert_eq!(txid, 0x1234);
                assert_eq!(qname, "www.example.com");
            }
            other => panic!("expected Query, got {other:?}"),
        }
        // Matching TXID → trusted.
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let r = response_msg(0x1234, "www.example.com", &[(ip, 60)]);
        let rpkt = udp_ip_packet(53, 40000, &r);
        match s.sniff_packet(&rpkt) {
            Sniffed::Response { txid, records } => {
                assert_eq!(txid, 0x1234);
                assert_eq!(records.len(), 1);
            }
            other => panic!("expected Response, got {other:?}"),
        }
        // The pending entry is consumed: a replayed response is untrusted.
        let rpkt2 = udp_ip_packet(53, 40000, &r);
        assert_eq!(s.sniff_packet(&rpkt2), Sniffed::NotDns);
    }

    #[test]
    fn sniffer_query_response_roundtrip_feeds_cache() {
        // End-to-end through the router: only the TXID-matched response
        // populates the resolution cache.
        use crate::{RouteTarget, Router, Rule, SimpleRuleEngine, UnifiedRouter};
        let engine = SimpleRuleEngine::new(vec![Rule {
            cidr: "0.0.0.0/0".parse().unwrap(),
            target: RouteTarget::Drop,
        }]);
        let router = UnifiedRouter::new(vec![], Box::new(engine));
        let ip: IpAddr = "9.9.9.9".parse().unwrap();
        // Spoofed response first (no pending query): not learned.
        let r = response_msg(0x7777, "spoofed.example", &[(ip, 60)]);
        let rpkt = udp_ip_packet(53, 40000, &r);
        router.route_packet(&rpkt);
        assert_eq!(router.dns_stats().cache_inserted, 0);
        // Real query → response: learned.
        let q = query_msg(0x1234, "real.example");
        router.route_packet(&udp_ip_packet(40000, 53, &q));
        let r2 = response_msg(0x1234, "real.example", &[(ip, 60)]);
        router.route_packet(&udp_ip_packet(53, 40000, &r2));
        assert_eq!(router.dns_stats().cache_inserted, 1);
    }
}
