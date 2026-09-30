//! Unified routing: virtual-subnet fast path + rule engine (DESIGN.md §6.4).
//!
//! Every TUN packet is classified to a [`RouteTarget`]:
//! - dst IP in a virtual-subnet CIDR → `MeshPeer` (S10 fast path,
//!   the rule engine is NOT consulted);
//! - otherwise → the rule engine decides (`Egress` / `Drop`).
//!
//! Non-IPv4 or truncated packets → `Drop` (S12; the caller counts it).

use nexus_domain::{RouteRequest, RouteTarget, RuleEngine};
use std::str::FromStr;

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

/// Parse the IPv4 source address (header bytes 12..16).
pub fn parse_ipv4_src(packet: &[u8]) -> Option<u32> {
    parse_ipv4_addr(packet, 12)
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
pub trait Router: Send + Sync {
    fn route(&self, req: &RouteRequest) -> RouteTarget;
}

/// §6.4 decision pipeline:
///
/// ```text
/// packet → IPv4 dst?
///   → no → Drop
///   → yes → in virtual_cidrs? → MeshPeer{peer: dst_ip}   (S10, no rule engine)
///   → no  → rules.decide(req)
/// ```
pub struct UnifiedRouter {
    virtual_cidrs: Vec<Cidr>,
    rules: Box<dyn RuleEngine>,
}

impl UnifiedRouter {
    pub fn new(virtual_cidrs: Vec<Cidr>, rules: Box<dyn RuleEngine>) -> Self {
        Self {
            virtual_cidrs,
            rules,
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
}
