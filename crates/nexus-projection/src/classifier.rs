//! 统一包分类器（S29/S30/S31）。
//!
//! TUN 前端分类器（TPROXY 前端使用 TransparentPipeline，不经过本类型）：
//!
//! - S29：分类顺序 mesh CIDR → fake-IP → bypass → 规则引擎；
//! - S30：mesh 命中时用 `boost::select_best` 做 EWMA 选路（只读）；
//! - S31：分类后生成统一 `FlowContext` 供 QoS/调度器使用。
//!
//! 纯内存、零 tokio；不接真实 TUN（接入点预留）。

use std::net::Ipv4Addr;

use nexus_domain::{FlowContext, FlowOrigin, ResourceId, RouteRequest, RouteTarget, RuleEngine};
use nexus_path::{CandidatePath, PathManager};

use crate::boost::select_best;
use crate::routing::{Cidr, parse_ipv4_dst, parse_packet_ports};

/// Fake-IP 池 CIDR（nexus-dns S-unified）：`198.18.0.0/15`。
fn fake_ip_cidr() -> Cidr {
    // 198.18.0.0 = 0xC6120000, /15
    Cidr::new(0xC612_0000, 15).expect("hardcoded fake-ip CIDR is valid")
}

/// 丢弃原因（spec §9.6；调用方按原因计数）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    /// 非 IPv4 包。
    NotIpv4,
    /// IPv4 头截断。
    Truncated,
    /// 分片包（需重组，前端不支持）。
    Fragmented,
    /// 非 TCP/UDP 协议。
    UnsupportedProtocol,
    /// 规则引擎判定 Drop（REJECT）。
    RuleRejected,
    /// 规则引擎运行期错误。
    RuleError,
    /// 规则引擎产出 MeshPeer，但本前端不支持 mesh。
    MeshUnsupported,
}

/// 分类结果（S29）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Classification {
    /// Mesh：N1 转发。`path` 为 EWMA 选出的最优路径对端地址（S30）；
    /// 全 unknown 时为 `None`（回落默认 mesh 转发，不阻塞）。
    /// `degraded` 为 true 时表示最优路径分数低于阈值（已打 warn，不自动切 proxy）。
    Mesh {
        path: Option<std::net::SocketAddr>,
        degraded: bool,
    },
    /// 代理：送 proxy 规则引擎，携带规则选定的出站 tag。
    Proxy {
        /// 规则选定的出站 tag。
        outbound: String,
    },
    /// 直连：bypass/白名单或规则 DIRECT。
    Direct,
    /// 丢弃：规则 REJECT / 不支持的类型（调用方计数）。
    Drop {
        /// 丢弃原因。
        reason: DropReason,
    },
}

/// 统一包分类器：TUN 前端的分类器（TPROXY 走 TransparentPipeline 的决策路径）。
///
/// - `manager` / `candidates` 仅用于 S30 的只读 EWMA 选路；
///   不持有写权限（single writer 仍在 `nexus-path`）。
pub struct PacketClassifier<'a> {
    mesh_cidrs: Vec<Cidr>,
    bypass_cidrs: Vec<Cidr>,
    manager: &'a PathManager,
    candidates: &'a [CandidatePath],
    degrade_threshold: f64,
    rules: &'a dyn RuleEngine,
    fake_ip_enabled: bool,
}

impl<'a> PacketClassifier<'a> {
    /// 构造分类器。
    ///
    /// - `mesh_cidrs`：mesh 网段（S10 fast path）；
    /// - `bypass_cidrs`：bypass/白名单网段（直连）；
    /// - `manager`/`candidates`：EWMA 选路输入（只读）；
    /// - `degrade_threshold`：S30 劣化阈值（分数非归一化，调用方定）。
    pub fn new(
        mesh_cidrs: Vec<Cidr>,
        bypass_cidrs: Vec<Cidr>,
        rules: &'a dyn RuleEngine,
        fake_ip_enabled: bool,
        manager: &'a PathManager,
        candidates: &'a [CandidatePath],
        degrade_threshold: f64,
    ) -> Self {
        Self {
            mesh_cidrs,
            bypass_cidrs,
            manager,
            candidates,
            degrade_threshold,
            rules,
            fake_ip_enabled,
        }
    }

    /// 分类一个 IP 包（S29 / spec §9.6）。
    ///
    /// 顺序：mesh CIDR → fake-IP（启用时）→ bypass → 注入的规则引擎。
    /// 非 IPv4 → `Drop { NotIpv4 }`；IPv4 头截断 → `Drop { Truncated }`。
    pub fn classify(&self, packet: &[u8], domain: Option<&str>) -> Classification {
        if packet.is_empty() || packet[0] >> 4 != 4 {
            return Classification::Drop {
                reason: DropReason::NotIpv4,
            };
        }
        let dst = match parse_ipv4_dst(packet) {
            Some(d) => d,
            None => {
                return Classification::Drop {
                    reason: DropReason::Truncated,
                };
            }
        };
        // 1. mesh fast path（S10）：规则引擎不介入。
        if self.mesh_cidrs.iter().any(|c| c.contains(dst)) {
            return self.classify_mesh();
        }
        // 2. fake-IP：本 run 不启用；启用时仍需经规则引擎（不吞域名规则）。
        if self.fake_ip_enabled && fake_ip_cidr().contains(dst) {
            return self.classify_rules(packet, domain);
        }
        // 3. bypass/白名单 → 直连。
        if self.bypass_cidrs.iter().any(|c| c.contains(dst)) {
            return Classification::Direct;
        }
        // 4. 其余 → 注入的规则引擎（TUN 与 TPROXY 共用同一实现）。
        self.classify_rules(packet, domain)
    }

    /// 委派规则引擎并把 `RouteTarget` 映射为分类结果（spec §9.6）。
    fn classify_rules(&self, packet: &[u8], domain: Option<&str>) -> Classification {
        let (src_port, dst_port) = parse_packet_ports(packet);
        let req = RouteRequest {
            packet,
            domain,
            src_port,
            dst_port,
            process_name: None,
        };
        match self.rules.decide(&req) {
            RouteTarget::Egress { peer } if peer == "self" => Classification::Direct,
            RouteTarget::Egress { peer } => Classification::Proxy { outbound: peer },
            RouteTarget::Drop => Classification::Drop {
                reason: DropReason::RuleRejected,
            },
            RouteTarget::MeshPeer { .. } => Classification::Drop {
                reason: DropReason::MeshUnsupported,
            },
        }
    }

    /// mesh 命中的 EWMA 选路（S30）。
    fn classify_mesh(&self) -> Classification {
        match select_best(self.manager, self.candidates, self.degrade_threshold) {
            Some(sel) => {
                if sel.degraded {
                    // S30：只 warn，不自动切 proxy（决策权在调用方）。
                    eprintln!(
                        "[classifier] warn: mesh 路径质量劣化 (score={:?} < threshold={})",
                        sel.score, self.degrade_threshold
                    );
                }
                Classification::Mesh {
                    path: sel.best.map(|c| c.remote_addr),
                    degraded: sel.degraded,
                }
            }
            // 全 unknown → 路径 None，回落默认转发，不阻塞。
            None => Classification::Mesh {
                path: None,
                degraded: false,
            },
        }
    }

    /// 分类后生成统一 `FlowContext`（S31）。
    ///
    /// - `Drop` 返回 `None`（调用方计数丢弃）；
    /// - `origin` 恒为 `FlowOrigin::VirtualPacketInterface`；
    /// - `destination` 为目的 IP 字符串；`domain` 透传（DNS 嗅探命中时由调用方填）；
    /// - `resource` 按分类映射；`profile` 透传。
    pub fn to_flow_context(
        &self,
        classification: &Classification,
        packet: &[u8],
        domain: Option<&str>,
        profile: &str,
    ) -> Option<FlowContext> {
        let dst = parse_ipv4_dst(packet)?;
        let dst_ip = Ipv4Addr::from(dst);
        let destination = domain
            .map(|d| d.to_string())
            .unwrap_or_else(|| dst_ip.to_string());
        let (resource, egress_hint) = match classification {
            Classification::Mesh { .. } => (ResourceId("mesh".to_string()), None),
            Classification::Proxy { outbound } => {
                (ResourceId("proxy".to_string()), Some(outbound.clone()))
            }
            Classification::Direct => (ResourceId("direct".to_string()), None),
            Classification::Drop { .. } => return None,
        };
        Some(FlowContext {
            origin: FlowOrigin::VirtualPacketInterface,
            resource,
            destination,
            profile: profile.to_string(),
            egress_hint,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn v4_packet(dst: [u8; 4]) -> Vec<u8> {
        let mut pkt = vec![0u8; 20];
        pkt[0] = 0x45;
        pkt[9] = 17; // UDP
        pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
        pkt[16..20].copy_from_slice(&dst);
        pkt
    }

    fn test_rules() -> &'static crate::egress::SimpleRuleEngine {
        static RULES: std::sync::OnceLock<crate::egress::SimpleRuleEngine> =
            std::sync::OnceLock::new();
        RULES.get_or_init(|| {
            crate::egress::SimpleRuleEngine::new(vec![crate::egress::Rule {
                cidr: "0.0.0.0/0".parse().unwrap(),
                target: RouteTarget::Egress {
                    peer: "p1".to_string(),
                },
            }])
        })
    }

    fn classifier<'a>(
        manager: &'a PathManager,
        candidates: &'a [CandidatePath],
    ) -> PacketClassifier<'a> {
        PacketClassifier::new(
            vec!["10.0.0.0/8".parse().unwrap()],
            vec!["192.168.0.0/16".parse().unwrap()],
            test_rules(),
            false,
            manager,
            candidates,
            50.0,
        )
    }

    #[test]
    fn s29_mesh_fast_path() {
        let m = PathManager::new(Default::default());
        let c = classifier(&m, &[]);
        // 全 unknown → Mesh { path: None }，不阻塞。
        assert_eq!(
            c.classify(&v4_packet([10, 1, 2, 3]), None),
            Classification::Mesh {
                path: None,
                degraded: false
            }
        );
    }

    #[test]
    fn s29_fake_ip_to_proxy() {
        let m = PathManager::new(Default::default());
        let c = classifier(&m, &[]);
        // fake_ip_enabled=false：198.18/15 不特殊处理，按规则走 Proxy。
        assert_eq!(
            c.classify(&v4_packet([198, 18, 0, 5]), None),
            Classification::Proxy {
                outbound: "p1".to_string()
            }
        );
        // 198.19.x.x 也在 /15 内。
        assert_eq!(
            c.classify(&v4_packet([198, 19, 1, 1]), None),
            Classification::Proxy {
                outbound: "p1".to_string()
            }
        );
        // 198.16 不在 /15 内 → 规则引擎。
        assert_eq!(
            c.classify(&v4_packet([198, 16, 0, 1]), None),
            Classification::Proxy {
                outbound: "p1".to_string()
            }
        );
    }

    #[test]
    fn s29_bypass_to_direct() {
        let m = PathManager::new(Default::default());
        let c = classifier(&m, &[]);
        assert_eq!(
            c.classify(&v4_packet([192, 168, 1, 1]), None),
            Classification::Direct
        );
    }

    #[test]
    fn s29_non_ipv4_drop() {
        let m = PathManager::new(Default::default());
        let c = classifier(&m, &[]);
        assert_eq!(
            c.classify(&[], None),
            Classification::Drop {
                reason: DropReason::NotIpv4
            }
        );
        assert_eq!(
            c.classify(&[0x60, 0, 0, 0], None),
            Classification::Drop {
                reason: DropReason::NotIpv4
            }
        ); // IPv6
    }

    #[test]
    fn s29_deterministic() {
        let m = PathManager::new(Default::default());
        let c = classifier(&m, &[]);
        let pkt = v4_packet([10, 9, 9, 9]);
        assert_eq!(c.classify(&pkt, None), c.classify(&pkt, None));
    }

    #[test]
    fn s31_flow_context() {
        let m = PathManager::new(Default::default());
        let c = classifier(&m, &[]);
        let pkt = v4_packet([10, 1, 2, 3]);
        let cl = c.classify(&pkt, None);
        let ctx = c.to_flow_context(&cl, &pkt, None, "default").unwrap();
        assert_eq!(ctx.origin, FlowOrigin::VirtualPacketInterface);
        assert_eq!(ctx.destination, "10.1.2.3");
        assert_eq!(ctx.resource, ResourceId("mesh".to_string()));
        assert_eq!(ctx.profile, "default");

        // domain 透传。
        let pkt2 = v4_packet([198, 18, 0, 5]);
        let cl2 = c.classify(&pkt2, None);
        let ctx2 = c
            .to_flow_context(&cl2, &pkt2, Some("example.com"), "p")
            .unwrap();
        assert_eq!(ctx2.destination, "example.com");
        assert_eq!(ctx2.resource, ResourceId("proxy".to_string()));

        // Drop 不生成。
        let ctx3 = c.to_flow_context(
            &Classification::Drop {
                reason: DropReason::RuleRejected,
            },
            &[],
            None,
            "p",
        );
        assert!(ctx3.is_none());
    }

    #[test]
    fn s30_ewma_select_best() {
        use nexus_path::{PathConfig, PathKind, PathStats};
        use std::net::{IpAddr, Ipv4Addr};

        let mut m = PathManager::new(PathConfig::default());
        let mk = |ip: [u8; 4]| CandidatePath {
            kind: PathKind::Direct,
            local_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 0),
            remote_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), 443),
            cost: 0.0,
        };
        let c0 = mk([10, 0, 0, 2]);
        let c1 = mk([10, 0, 0, 3]);
        m.add_candidate(c0.clone());
        m.add_candidate(c1.clone());
        let candidates = vec![c0.clone(), c1.clone()];

        // 无样本时全 unknown → Mesh { path: None }，不阻塞。
        let c = classifier(&m, &candidates);
        assert_eq!(
            c.classify(&v4_packet([10, 1, 2, 3]), None),
            Classification::Mesh {
                path: None,
                degraded: false
            }
        );

        // 喂 stats：c0 好（rtt 20ms），c1 差（rtt 200ms + 丢包）。
        m.on_stats(
            &c0.remote_addr,
            PathStats {
                rtt_ms: Some(20),
                loss_rate: Some(0.0),
                throughput_bps: Some(100_000_000),
            },
        );
        m.on_stats(
            &c1.remote_addr,
            PathStats {
                rtt_ms: Some(200),
                loss_rate: Some(0.1),
                throughput_bps: Some(10_000_000),
            },
        );

        // EWMA 选出 c0。
        let c = classifier(&m, &candidates);
        assert_eq!(
            c.classify(&v4_packet([10, 1, 2, 3]), None),
            Classification::Mesh {
                path: Some(c0.remote_addr),
                degraded: false,
            }
        );
    }

    #[test]
    fn s30_degraded_still_mesh() {
        // 劣化路径：分数低于阈值时仍选 Mesh（不自动切 proxy），degraded=true。
        use nexus_path::{PathConfig, PathKind, PathStats};
        use std::net::{IpAddr, Ipv4Addr};

        let mut m = PathManager::new(PathConfig::default());
        let mk = |ip: [u8; 4]| CandidatePath {
            kind: PathKind::Direct,
            local_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 0),
            remote_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), 443),
            cost: 0.0,
        };
        let c0 = mk([10, 0, 0, 2]);
        m.add_candidate(c0.clone());
        let candidates = vec![c0.clone()];
        // 喂极差 stats（高延迟+高丢包），分数必然低于阈值 50。
        m.on_stats(
            &c0.remote_addr,
            PathStats {
                rtt_ms: Some(5000),
                loss_rate: Some(0.9),
                throughput_bps: Some(1000),
            },
        );
        // 阈值设得很高，确保 degraded。
        let c = PacketClassifier::new(
            vec!["10.0.0.0/8".parse().unwrap()],
            vec![],
            test_rules(),
            false,
            &m,
            &candidates,
            1e9, // 极高阈值，任何真实分数都低于它
        );
        match c.classify(&v4_packet([10, 1, 2, 3]), None) {
            Classification::Mesh {
                path: Some(p),
                degraded: true,
            } => assert_eq!(p, c0.remote_addr),
            other => panic!("expected degraded Mesh, got {:?}", other),
        }
    }

    #[test]
    fn s17_rule_engine_direct_proxy_reject() {
        use crate::egress::{Rule, SimpleRuleEngine};
        let m = PathManager::new(Default::default());
        let rules = SimpleRuleEngine::new(vec![
            Rule {
                cidr: "1.2.3.0/24".parse().unwrap(),
                target: RouteTarget::Egress {
                    peer: "p1".to_string(),
                },
            },
            Rule {
                cidr: "4.4.4.0/24".parse().unwrap(),
                target: RouteTarget::Egress {
                    peer: "self".to_string(),
                },
            },
            Rule {
                cidr: "6.6.6.0/24".parse().unwrap(),
                target: RouteTarget::Drop,
            },
        ]);
        let c = PacketClassifier::new(vec![], vec![], &rules, false, &m, &[], 0.0);
        assert_eq!(
            c.classify(&v4_packet([1, 2, 3, 4]), None),
            Classification::Proxy {
                outbound: "p1".to_string()
            }
        );
        assert_eq!(
            c.classify(&v4_packet([4, 4, 4, 4]), None),
            Classification::Direct
        );
        assert_eq!(
            c.classify(&v4_packet([6, 6, 6, 6]), None),
            Classification::Drop {
                reason: DropReason::RuleRejected
            }
        );
    }

    #[test]
    fn s17_mesh_peer_target_is_unsupported_drop() {
        struct MeshEngine;
        impl RuleEngine for MeshEngine {
            fn decide(&self, _req: &RouteRequest<'_>) -> RouteTarget {
                RouteTarget::MeshPeer {
                    peer: "10.0.0.9".to_string(),
                }
            }
        }
        let m = PathManager::new(Default::default());
        let c = PacketClassifier::new(vec![], vec![], &MeshEngine, false, &m, &[], 0.0);
        assert_eq!(
            c.classify(&v4_packet([8, 8, 8, 8]), None),
            Classification::Drop {
                reason: DropReason::MeshUnsupported
            }
        );
    }

    #[test]
    fn s17_fake_ip_disabled_does_not_swallow_pool() {
        use crate::egress::{Rule, SimpleRuleEngine};
        let m = PathManager::new(Default::default());
        let rules = SimpleRuleEngine::new(vec![Rule {
            cidr: "198.18.0.0/15".parse().unwrap(),
            target: RouteTarget::Drop,
        }]);
        let c = PacketClassifier::new(vec![], vec![], &rules, false, &m, &[], 0.0);
        assert_eq!(
            c.classify(&v4_packet([198, 18, 0, 5]), None),
            Classification::Drop {
                reason: DropReason::RuleRejected
            }
        );
    }
}
