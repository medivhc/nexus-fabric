//! Unified routing: virtual-subnet fast path + rule engine (DESIGN.md §6.4).
//!
//! Every TUN packet is classified to a [`RouteTarget`]:
//! - dst IP in a virtual-subnet CIDR → `MeshPeer` (S10 fast path,
//!   the rule engine is NOT consulted);
//! - otherwise → the rule engine decides (`Egress` / `Drop`).
//!
//! 3b-3: [`UnifiedRouter`] DNS-sniffs packets (S15/S17) before deciding:
//! UDP dport 53 → the query's QNAME fills `RouteRequest.domain`;
//! UDP sport 53 → A/AAAA records are learned into the domain→IP cache and
//! the response is decided by the queried domain; other packets inherit a
//! cached domain for their destination IP (S17).
//!
//! Non-IPv4 or truncated packets → `Drop` (S12; the caller counts it).

use nexus_domain::{RouteRequest, RouteTarget, RuleEngine};
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use crate::dns::{DEFAULT_DNS_CACHE_ENTRIES, DnsCache, DnsSniffer, DnsStats, Sniffed};

/// IPv4 CIDR block, std-only (no `ipnet` crate).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    /// Network address with host bits masked off.
    network: u32,
    prefix: u8,
}

impl Cidr {
    /// Build from a raw address and prefix length. Returns `None` for
    /// `prefix > 32`.
    pub fn new(addr: u32, prefix: u8) -> Option<Self> {
        if prefix > 32 {
            return None;
        }
        Some(Self {
            network: addr & mask(prefix),
            prefix,
        })
    }

    /// Does `ip` fall inside this block?
    pub fn contains(&self, ip: u32) -> bool {
        (ip & mask(self.prefix)) == self.network
    }

    /// Prefix length.
    pub fn prefix(&self) -> u8 {
        self.prefix
    }
}

/// Parse `"10.0.0.0/8"` style CIDR notation.
impl FromStr for Cidr {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        let (ip_part, prefix_part) = s.split_once('/').ok_or_else(|| "missing '/'".to_string())?;
        let prefix: u8 = prefix_part
            .parse()
            .map_err(|_| format!("bad prefix in {s:?}"))?;
        if prefix > 32 {
            return Err(format!("prefix out of range in {s:?}"));
        }
        let mut addr: u32 = 0;
        let octets: Vec<&str> = ip_part.split('.').collect();
        if octets.len() != 4 {
            return Err(format!("bad IPv4 address in {s:?}"));
        }
        for o in octets {
            let b: u8 = o.parse().map_err(|_| format!("bad octet in {s:?}"))?;
            addr = (addr << 8) | u32::from(b);
        }
        // `new` masks host bits, so "10.1.2.3/8" is accepted as 10.0.0.0/8.
        Cidr::new(addr, prefix).ok_or_else(|| format!("bad CIDR {s:?}"))
    }
}

fn mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

/// Format a u32 as dotted-decimal IPv4.
pub fn format_ipv4(ip: u32) -> String {
    format!(
        "{}.{}.{}.{}",
        (ip >> 24) & 0xFF,
        (ip >> 16) & 0xFF,
        (ip >> 8) & 0xFF,
        ip & 0xFF
    )
}

/// Parse the IPv4 destination address (header bytes 16..20).
/// Returns `None` for non-IPv4 or truncated packets.
pub fn parse_ipv4_dst(packet: &[u8]) -> Option<u32> {
    parse_ipv4_addr(packet, 16)
}

fn parse_ipv4_addr(packet: &[u8], offset: usize) -> Option<u32> {
    if packet.len() < 20 {
        return None;
    }
    if packet[0] >> 4 != 4 {
        return None; // not IPv4
    }
    let b = packet.get(offset..offset + 4)?;
    Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

/// Unified routing decision point (lives in the projection layer, §6.4).
///
/// Implementors classify a packet to a [`RouteTarget`]. The provided
/// [`UnifiedRouter`] implements the §6.4 pipeline; custom routers (tests,
/// future policy extensions) can implement this trait directly.
///
/// [`Router::route_packet`] is the packet-level entry: the default impl
/// passes `domain: None`, while [`UnifiedRouter`] overrides it to DNS-sniff
/// (S15/S17) before delegating to [`Router::route`].
pub trait Router: Send + Sync {
    fn route(&self, req: &RouteRequest) -> RouteTarget;

    /// Classify a raw IP packet. DNS-sniffing routers override this to
    /// fill `RouteRequest.domain` (and learn response mappings) first.
    fn route_packet(&self, packet: &[u8]) -> RouteTarget {
        self.route(&RouteRequest {
            packet,
            domain: None,
        })
    }
}

/// Lock helper that tolerates poisoning.
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// §6.4 decision pipeline:
///
/// ```text
/// packet → DNS sniff (S15/S17: query → QNAME, response → learn cache,
///                      else inherit cached domain for dst IP)
///   → IPv4 dst?
///   → no → Drop
///   → yes → in virtual_cidrs? → MeshPeer{peer: dst_ip}   (S10, no rule engine)
///   → no  → rules.decide(req)   (S16: domain rules first)
/// ```
pub struct UnifiedRouter {
    virtual_cidrs: Vec<Cidr>,
    rules: Box<dyn RuleEngine>,
    sniffer: DnsSniffer,
    /// Shared so the same cache is visible through clones of the router
    /// handle (E4 drivers keep a handle for `dns_stats`).
    dns_cache: Arc<Mutex<DnsCache>>,
}

impl UnifiedRouter {
    pub fn new(virtual_cidrs: Vec<Cidr>, rules: Box<dyn RuleEngine>) -> Self {
        Self {
            virtual_cidrs,
            rules,
            sniffer: DnsSniffer::new(),
            dns_cache: Arc::new(Mutex::new(DnsCache::new(DEFAULT_DNS_CACHE_ENTRIES))),
        }
    }

    /// DNS observability: cache inserts, capacity evictions, sniff failures
    /// (S15/S17).
    pub fn dns_stats(&self) -> DnsStats {
        let cache = lock(&self.dns_cache);
        DnsStats {
            cache_inserted: cache.inserted(),
            cache_evicted: cache.evicted(),
            sniff_failed: self.sniffer.sniff_failed(),
        }
    }
}

impl Router for UnifiedRouter {
    fn route(&self, req: &RouteRequest) -> RouteTarget {
        let dst = match parse_ipv4_dst(req.packet) {
            Some(d) => d,
            None => return RouteTarget::Drop,
        };
        // S10: virtual-subnet fast path — the rule engine is not consulted.
        if self.virtual_cidrs.iter().any(|c| c.contains(dst)) {
            return RouteTarget::MeshPeer {
                peer: format_ipv4(dst),
            };
        }
        self.rules.decide(req)
    }

    fn route_packet(&self, packet: &[u8]) -> RouteTarget {
        // S15/S17: DNS sniffing. Never drops the packet: on any sniff
        // failure the domain stays None and IP rules decide.
        let mut domain: Option<String> = None;
        {
            let mut cache = lock(&self.dns_cache);
            match self.sniffer.sniff_packet(packet) {
                Sniffed::Query { qname, .. } => {
                    domain = Some(qname);
                }
                Sniffed::Response { records, .. } => {
                    // S17: learn domain→IP, and decide the response itself
                    // by the queried domain (query/response path consistency).
                    domain = records.first().map(|(name, _, _)| name.clone());
                    cache.insert_response(&records);
                }
                Sniffed::NotDns => {
                    // S17: inherit a cached domain for the destination IP.
                    if let Some(dst) = parse_ipv4_dst(packet) {
                        let ip = IpAddr::V4(Ipv4Addr::from(dst));
                        domain = cache.lookup(&ip);
                    }
                }
            }
        }
        let req = RouteRequest {
            packet,
            domain: domain.as_deref(),
        };
        self.route(&req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::egress::{Rule, SimpleRuleEngine};

    fn engine() -> SimpleRuleEngine {
        SimpleRuleEngine::new(vec![
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
        ])
    }

    fn v4_packet(dst: [u8; 4]) -> Vec<u8> {
        let mut pkt = vec![0u8; 20];
        pkt[0] = 0x45;
        pkt[9] = 17; // UDP
        pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
        pkt[16..20].copy_from_slice(&dst);
        pkt
    }

    #[test]
    fn cidr_parse_and_contains() {
        let c: Cidr = "10.0.0.0/8".parse().unwrap();
        assert!(c.contains(0x0A010203));
        assert!(!c.contains(0x08080808));
        let all: Cidr = "0.0.0.0/0".parse().unwrap();
        assert!(all.contains(0x01020304));
        let single: Cidr = "1.2.3.4/32".parse().unwrap();
        assert!(single.contains(0x01020304));
        assert!(!single.contains(0x01020305));
        assert!("10.0.0.0/33".parse::<Cidr>().is_err());
        assert!("not-a-cidr".parse::<Cidr>().is_err());
    }

    #[test]
    fn s10_virtual_subnet_skips_rule_engine() {
        // Even though 0.0.0.0/0 would match, 10/8 wins via fast path
        // and the rule engine is never consulted.
        let r = UnifiedRouter::new(vec!["10.0.0.0/8".parse().unwrap()], Box::new(engine()));
        let pkt = v4_packet([10, 1, 2, 3]);
        let req = RouteRequest {
            packet: &pkt,
            domain: None,
        };
        assert_eq!(
            r.route(&req),
            RouteTarget::MeshPeer {
                peer: "10.1.2.3".to_string()
            }
        );
    }

    #[test]
    fn s9_routing_deterministic() {
        let r = UnifiedRouter::new(vec!["10.0.0.0/8".parse().unwrap()], Box::new(engine()));
        let pkt = v4_packet([8, 8, 8, 8]);
        let req = RouteRequest {
            packet: &pkt,
            domain: None,
        };
        let a = r.route(&req);
        let b = r.route(&req);
        assert_eq!(a, b);
        assert_eq!(
            a,
            RouteTarget::Egress {
                peer: "self".to_string()
            }
        );
    }

    #[test]
    fn non_ipv4_drops() {
        let r = UnifiedRouter::new(vec![], Box::new(engine()));
        // IPv6 version nibble.
        let mut pkt = v4_packet([8, 8, 8, 8]);
        pkt[0] = 0x60;
        let req = RouteRequest {
            packet: &pkt,
            domain: None,
        };
        assert_eq!(r.route(&req), RouteTarget::Drop);
        // Truncated.
        let req = RouteRequest {
            packet: &[0x45, 0x00],
            domain: None,
        };
        assert_eq!(r.route(&req), RouteTarget::Drop);
    }

    // --- 3b-3 DNS sniffing tests (S15/S16/S17) ---

    /// Router fixture: DOMAIN-SUFFIX blocked.example → Egress{B},
    /// 1.2.3.0/24 → Drop, default → Egress{self}.
    fn domain_router() -> UnifiedRouter {
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
        UnifiedRouter::new(vec![], Box::new(e))
    }

    /// IPv4/UDP packet with a raw payload.
    fn udp_payload_packet(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
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

    /// Minimal DNS query message for `qname`.
    fn dns_query_msg(qname: &str) -> Vec<u8> {
        let mut m = vec![0u8; 12];
        m[0..2].copy_from_slice(&0x1234u16.to_be_bytes());
        m[2..4].copy_from_slice(&[0x01, 0x00]);
        m[4..6].copy_from_slice(&[0x00, 0x01]);
        for label in qname.split('.') {
            m.push(label.len() as u8);
            m.extend_from_slice(label.as_bytes());
        }
        m.push(0x00);
        m.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        m
    }

    /// Minimal DNS response: `qname` → A `ip`, TTL 60, compression pointer.
    fn dns_response_msg(qname: &str, ip: [u8; 4]) -> Vec<u8> {
        let mut m = vec![0u8; 12];
        m[0..2].copy_from_slice(&0x1234u16.to_be_bytes());
        m[2..4].copy_from_slice(&[0x81, 0x80]);
        m[4..6].copy_from_slice(&[0x00, 0x01]);
        m[6..8].copy_from_slice(&[0x00, 0x01]);
        for label in qname.split('.') {
            m.push(label.len() as u8);
            m.extend_from_slice(label.as_bytes());
        }
        m.push(0x00);
        m.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        m.extend_from_slice(&[0xC0, 0x0C]); // name pointer → QNAME
        m.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // A, IN
        m.extend_from_slice(&60u32.to_be_bytes()); // TTL
        m.extend_from_slice(&[0x00, 0x04]);
        m.extend_from_slice(&ip);
        m
    }

    #[test]
    fn s16_dns_query_sniffed_to_domain_rule() {
        let r = domain_router();
        // DNS query for www.blocked.example → Egress{B} (S16).
        let q = dns_query_msg("www.blocked.example");
        let pkt = udp_payload_packet(40000, 53, &q);
        assert_eq!(
            r.route_packet(&pkt),
            RouteTarget::Egress {
                peer: "B".to_string()
            }
        );
        // Query for an unlisted domain → IP fallback → Egress{self}.
        let q = dns_query_msg("www.allowed.example");
        let pkt = udp_payload_packet(40001, 53, &q);
        assert_eq!(
            r.route_packet(&pkt),
            RouteTarget::Egress {
                peer: "self".to_string()
            }
        );
    }

    #[test]
    fn s17_response_learns_cache_and_later_packets_inherit() {
        let r = domain_router();
        // S37: the query must be seen first so the response TXID (0x1234)
        // matches a pending query; otherwise the response is untrusted.
        let q = dns_query_msg("www.blocked.example");
        let qpkt = udp_payload_packet(40000, 53, &q);
        let _ = r.route_packet(&qpkt);
        // Feed the DNS response (sport 53): learns 1.2.3.4 → www.blocked.example.
        let resp = dns_response_msg("www.blocked.example", [1, 2, 3, 4]);
        // Response packet: src=8.8.8.8:53, dst=10.0.0.1.
        let mut pkt = udp_payload_packet(53, 40000, &resp);
        pkt[12..16].copy_from_slice(&[8, 8, 8, 8]); // src = DNS server
        pkt[16..20].copy_from_slice(&[10, 0, 0, 1]); // dst = us
        // The response itself is decided by the queried domain (S17).
        assert_eq!(
            r.route_packet(&pkt),
            RouteTarget::Egress {
                peer: "B".to_string()
            }
        );
        let stats = r.dns_stats();
        assert_eq!(stats.cache_inserted, 1);

        // Later packet to the resolved IP inherits the domain decision (S17):
        // 1.2.3.4 would Drop by IP rule, but the cached domain wins.
        let data = udp_payload_packet(40002, 80, b"hello");
        let mut pkt2 = data;
        pkt2[16..20].copy_from_slice(&[1, 2, 3, 4]); // dst = resolved IP
        assert_eq!(
            r.route_packet(&pkt2),
            RouteTarget::Egress {
                peer: "B".to_string()
            }
        );
    }

    #[test]
    fn s15_malformed_dns_not_dropped() {
        let r = domain_router();
        // Garbage to port 53: sniff fails → ordinary IP rule, not Drop (S15).
        let pkt = udp_payload_packet(40000, 53, b"\xFF\xFF not dns");
        assert_eq!(
            r.route_packet(&pkt),
            RouteTarget::Egress {
                peer: "self".to_string()
            }
        );
        assert_eq!(r.dns_stats().sniff_failed, 1);
        // Truncated UDP: also fine.
        let pkt = udp_payload_packet(40000, 53, b"\x00");
        assert_eq!(
            r.route_packet(&pkt),
            RouteTarget::Egress {
                peer: "self".to_string()
            }
        );
        assert_eq!(r.dns_stats().sniff_failed, 2);
    }

    #[test]
    fn route_packet_default_trait_impl_skips_sniffing() {
        // A custom Router using the default route_packet: domain stays None.
        struct IpOnly;
        impl Router for IpOnly {
            fn route(&self, req: &RouteRequest) -> RouteTarget {
                assert!(req.domain.is_none());
                RouteTarget::Drop
            }
        }
        let q = dns_query_msg("www.blocked.example");
        let pkt = udp_payload_packet(40000, 53, &q);
        assert_eq!(IpOnly.route_packet(&pkt), RouteTarget::Drop);
    }
}
