//! 统一包分类器（S29/S30/S31）。
//!
//! 单个 TUN 的唯一包分类入口（文档 §6/§11.2 数据面位置）：
//!
//! - S29：分类顺序 mesh CIDR → fake-IP → bypass → 规则引擎；
//! - S30：mesh 命中时用 `boost::select_best` 做 EWMA 选路（只读）；
//! - S31：分类后生成统一 `FlowContext` 供 QoS/调度器使用。
//!
//! 纯内存、零 tokio；不接真实 TUN（接入点预留）。

use std::net::Ipv4Addr;

use nexus_domain::{FlowContext, FlowOrigin, ResourceId};
use nexus_path::{CandidatePath, PathManager};

use crate::boost::select_best;
use crate::routing::{Cidr, parse_ipv4_dst};

/// Fake-IP 池 CIDR（nexus-dns S-unified）：`198.18.0.0/15`。
fn fake_ip_cidr() -> Cidr {
    // 198.18.0.0 = 0xC6120000, /15
    Cidr::new(0xC612_0000, 15).expect("hardcoded fake-ip CIDR is valid")
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
    /// 代理：送 proxy 规则引擎。
    Proxy,
    /// 直连：bypass/白名单。
    Direct,
    /// 丢弃：非 IPv4/截断包等（S12 可见性由调用方负责）。
    Drop,
}

/// 统一包分类器：单个 TUN 的唯一分类入口。
///
/// - `manager` / `candidates` 仅用于 S30 的只读 EWMA 选路；
///   不持有写权限（single writer 仍在 `nexus-path`）。
pub struct PacketClassifier<'a> {
    mesh_cidrs: Vec<Cidr>,
    bypass_cidrs: Vec<Cidr>,
    manager: &'a PathManager,
    candidates: &'a [CandidatePath],
    degrade_threshold: f64,
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
        }
    }

    /// 分类一个 IP 包（S29）。
    ///
    /// 顺序：mesh CIDR → fake-IP → bypass → 规则引擎（此处回落 `Proxy`，
    /// 完整规则引擎由调用方在外层接入；见 S29-4）。
    /// 非 IPv4 或截断包 → `Drop`。
    pub fn classify(&self, packet: &[u8]) -> Classification {
        let dst = match parse_ipv4_dst(packet) {
            Some(d) => d,
            None => return Classification::Drop,
        };
        // 1. mesh fast path（S10）：规则引擎不介入。
        if self.mesh_cidrs.iter().any(|c| c.contains(dst)) {
            return self.classify_mesh();
        }
        // 2. fake-IP → proxy。
        if fake_ip_cidr().contains(dst) {
            return Classification::Proxy;
        }
        // 3. bypass/白名单 → 直连。
        if self.bypass_cidrs.iter().any(|c| c.contains(dst)) {
            return Classification::Direct;
        }
        // 4. 其余 → 规则引擎（本 MVP 回落 Proxy；完整引擎由调用方接入）。
        Classification::Proxy
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
        let resource = match classification {
            Classification::Mesh { .. } => ResourceId("mesh".to_string()),
            Classification::Proxy => ResourceId("proxy".to_string()),
            Classification::Direct => ResourceId("direct".to_string()),
            Classification::Drop => return None,
        };
        Some(FlowContext {
            origin: FlowOrigin::VirtualPacketInterface,
            resource,
            destination,
            profile: profile.to_string(),
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

    fn classifier<'a>(
        manager: &'a PathManager,
        candidates: &'a [CandidatePath],
    ) -> PacketClassifier<'a> {
        PacketClassifier::new(
            vec!["10.0.0.0/8".parse().unwrap()],
            vec!["192.168.0.0/16".parse().unwrap()],
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
            c.classify(&v4_packet([10, 1, 2, 3])),
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
        assert_eq!(
            c.classify(&v4_packet([198, 18, 0, 5])),
            Classification::Proxy
        );
        // 198.19.x.x 也在 /15 内。
        assert_eq!(
            c.classify(&v4_packet([198, 19, 1, 1])),
            Classification::Proxy
        );
        // 198.16 不在 /15 内 → 回落 Proxy（规则引擎）。
        assert_eq!(
            c.classify(&v4_packet([198, 16, 0, 1])),
            Classification::Proxy
        );
    }

    #[test]
    fn s29_bypass_to_direct() {
        let m = PathManager::new(Default::default());
        let c = classifier(&m, &[]);
        assert_eq!(
            c.classify(&v4_packet([192, 168, 1, 1])),
            Classification::Direct
        );
    }

    #[test]
    fn s29_non_ipv4_drop() {
        let m = PathManager::new(Default::default());
        let c = classifier(&m, &[]);
        assert_eq!(c.classify(&[]), Classification::Drop);
        assert_eq!(c.classify(&[0x60, 0, 0, 0]), Classification::Drop); // IPv6
    }

    #[test]
    fn s29_deterministic() {
        let m = PathManager::new(Default::default());
        let c = classifier(&m, &[]);
        let pkt = v4_packet([10, 9, 9, 9]);
        assert_eq!(c.classify(&pkt), c.classify(&pkt));
    }

    #[test]
    fn s31_flow_context() {
        let m = PathManager::new(Default::default());
        let c = classifier(&m, &[]);
        let pkt = v4_packet([10, 1, 2, 3]);
        let cl = c.classify(&pkt);
        let ctx = c.to_flow_context(&cl, &pkt, None, "default").unwrap();
        assert_eq!(ctx.origin, FlowOrigin::VirtualPacketInterface);
        assert_eq!(ctx.destination, "10.1.2.3");
        assert_eq!(ctx.resource, ResourceId("mesh".to_string()));
        assert_eq!(ctx.profile, "default");

        // domain 透传。
        let pkt2 = v4_packet([198, 18, 0, 5]);
        let cl2 = c.classify(&pkt2);
        let ctx2 = c
            .to_flow_context(&cl2, &pkt2, Some("example.com"), "p")
            .unwrap();
        assert_eq!(ctx2.destination, "example.com");
        assert_eq!(ctx2.resource, ResourceId("proxy".to_string()));

        // Drop 不生成。
        let ctx3 = c.to_flow_context(&Classification::Drop, &[], None, "p");
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
            c.classify(&v4_packet([10, 1, 2, 3])),
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
            c.classify(&v4_packet([10, 1, 2, 3])),
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
            &m,
            &candidates,
            1e9, // 极高阈值，任何真实分数都低于它
        );
        match c.classify(&v4_packet([10, 1, 2, 3])) {
            Classification::Mesh {
                path: Some(p),
                degraded: true,
            } => assert_eq!(p, c0.remote_addr),
            other => panic!("expected degraded Mesh, got {:?}", other),
        }
    }
}
