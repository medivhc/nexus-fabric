//! 聚合发现（DESIGN §8.2 D5/D7）：多源合并去重 + 优先级 + 可观测。
//!
//! Portable Core：零 I/O、零第三方依赖。

use std::collections::HashSet;
use std::net::SocketAddr;

use super::lsa::{LsaDiscovery, Lsdb};
use super::mdns::MdnsDiscovery;
use super::paired::PairedDiscovery;
use super::{Discovery, DiscoveryMetrics, DiscoverySource, PeerId, ResolvedAddr, StaticDiscovery};

/// 聚合发现：配对 > 静态 > LSA > mDNS 按优先级合并去重。
///
/// `LsaDiscovery` 借用 `Lsdb`，故本类型带生命周期 `'a`。
/// 每次 [`Discovery::resolve`] 调用更新 [`DiscoveryMetrics`]（D6/D7）。
#[derive(Debug)]
pub struct AggregateDiscovery<'a> {
    paired_src: Option<PairedDiscovery>,
    static_src: StaticDiscovery,
    lsa_src: LsaDiscovery<'a>,
    mdns_src: MdnsDiscovery,
    metrics: DiscoveryMetrics,
}

impl<'a> AggregateDiscovery<'a> {
    /// 组合三源构造聚合器（D5 冻结签名；配对源用 `with_paired` 接入）。
    pub fn new(static_src: StaticDiscovery, lsdb: &'a Lsdb, mdns_src: MdnsDiscovery) -> Self {
        Self {
            paired_src: None,
            static_src,
            lsa_src: LsaDiscovery::new(lsdb),
            mdns_src,
            metrics: DiscoveryMetrics::default(),
        }
    }

    /// 接入配对源（D7；builder 加法，不破坏 D5 冻结的 `new` 签名）。
    pub fn with_paired(mut self, paired: PairedDiscovery) -> Self {
        self.paired_src = Some(paired);
        self
    }

    /// 按优先级解析，返回带来源标注的地址（同地址去重，保留最高优先级）。
    #[must_use]
    pub fn resolve_with_sources(&self, peer: &PeerId) -> Vec<ResolvedAddr> {
        merge_ranked(
            self.paired_src.as_ref().map(|p| p as &dyn Discovery),
            &self.static_src,
            &self.lsa_src,
            &self.mdns_src,
            peer,
        )
    }

    /// 可观测计数器（D6）。
    #[must_use]
    pub fn metrics(&self) -> &DiscoveryMetrics {
        &self.metrics
    }

    /// mDNS 状态机的可变访问（组合根 pump 喂包/清理用）。
    #[must_use]
    pub fn mdns_mut(&mut self) -> &mut MdnsDiscovery {
        &mut self.mdns_src
    }
}

impl Discovery for AggregateDiscovery<'_> {
    /// 聚合解析（只返回地址）；更新 D6/D7 计数器：
    /// 有产出的源 `hits_{source}++`，全空则 `miss++`。
    fn resolve(&self, peer: &PeerId) -> Vec<SocketAddr> {
        let paired_addrs = self
            .paired_src
            .as_ref()
            .map(|p| Discovery::resolve(p, peer))
            .unwrap_or_default();
        let static_addrs = Discovery::resolve(&self.static_src, peer);
        let lsa_addrs = self.lsa_src.resolve(peer);
        let mdns_addrs = Discovery::resolve(&self.mdns_src, peer);
        if !paired_addrs.is_empty() {
            self.metrics.hits_paired();
        }
        if !static_addrs.is_empty() {
            self.metrics.hits_static();
        }
        if !lsa_addrs.is_empty() {
            self.metrics.hits_lsa();
        }
        if !mdns_addrs.is_empty() {
            self.metrics.hits_mdns();
        }
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for addr in paired_addrs
            .into_iter()
            .chain(static_addrs)
            .chain(lsa_addrs)
            .chain(mdns_addrs)
        {
            if seen.insert(addr) {
                out.push(addr);
            }
        }
        if out.is_empty() {
            self.metrics.miss();
        }
        out
    }

    /// 全部源的 peer 并集（去重；不含新鲜度过滤——`AggregateDiscovery` 没有时间参数）。
    fn peers(&self) -> Vec<PeerId> {
        let mut out: Vec<PeerId> = Vec::new();
        let mut seen = HashSet::new();
        let sources: [Option<&dyn Discovery>; 4] = [
            self.paired_src.as_ref().map(|p| p as &dyn Discovery),
            Some(&self.static_src),
            Some(&self.lsa_src),
            Some(&self.mdns_src),
        ];
        for src in sources.into_iter().flatten() {
            for peer in src.peers() {
                if seen.insert(peer.0.clone()) {
                    out.push(peer);
                }
            }
        }
        out
    }
}

/// 单一优先级实现：Paired > Static > Lsa > Mdns，同地址去重保留最高优先级。
///
/// `AggregateDiscovery` 与 `DiscoveryHub` 共用本函数（不复制优先级规则）。
/// `static_src` / `lsa` / `mdns` 是必选源，`paired` 可选（D7 builder 加法）。
pub(crate) fn merge_ranked(
    paired: Option<&dyn Discovery>,
    static_src: &dyn Discovery,
    lsa: &dyn Discovery,
    mdns: &dyn Discovery,
    peer: &PeerId,
) -> Vec<ResolvedAddr> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    // 优先级：Paired > Static > Lsa > Mdns（变体声明顺序）。
    if let Some(paired) = paired {
        for addr in Discovery::resolve(paired, peer) {
            if seen.insert(addr) {
                out.push(ResolvedAddr {
                    addr,
                    source: DiscoverySource::Paired,
                });
            }
        }
    }
    let sources: [(DiscoverySource, Vec<SocketAddr>); 3] = [
        (
            DiscoverySource::Static,
            Discovery::resolve(static_src, peer),
        ),
        (DiscoverySource::Lsa, lsa.resolve(peer)),
        (DiscoverySource::Mdns, Discovery::resolve(mdns, peer)),
    ];
    for (source, addrs) in sources {
        for addr in addrs {
            if seen.insert(addr) {
                out.push(ResolvedAddr { addr, source });
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lsa::Lsa;

    fn peer(id: &str) -> PeerId {
        PeerId(id.to_string())
    }

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn lsdb_with(locator_pairs: &[(&str, Option<&str>)]) -> Lsdb {
        let mut db = Lsdb::new(peer("self"));
        for (id, locator) in locator_pairs {
            // vip 只是 LSA 结构体的占位字段，本测试不关心。
            let lsa = Lsa {
                node_id: peer(id),
                vip: "10.9.0.1".to_string(),
                incarnation: 1,
                seq: 1,
                capabilities: 0,
                locator: locator.map(str::to_string),
                neighbors: Vec::new(),
            };
            db.update(lsa);
        }
        db
    }

    fn mdns(id: &str) -> MdnsDiscovery {
        MdnsDiscovery::new(peer(id), 5000, "127.0.0.1".parse().unwrap()).unwrap()
    }

    #[test]
    fn priority_static_over_lsa() {
        let static_src = StaticDiscovery::new([(peer("n1"), addr("10.0.0.1:1111"))]);
        let db = lsdb_with(&[("n1", Some("udp://10.0.0.2:2222"))]);
        let agg = AggregateDiscovery::new(static_src, &db, mdns("self"));
        let r = agg.resolve_with_sources(&peer("n1"));
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].addr, addr("10.0.0.1:1111"));
        assert_eq!(r[0].source, DiscoverySource::Static);
        assert_eq!(r[1].addr, addr("10.0.0.2:2222"));
        assert_eq!(r[1].source, DiscoverySource::Lsa);
    }

    #[test]
    fn dedup_keeps_highest_priority_source() {
        let static_src = StaticDiscovery::new([(peer("n1"), addr("10.0.0.1:1111"))]);
        // LSA 通告了与静态表相同的地址 → 去重后只剩一条，来源标注为 Static。
        let db = lsdb_with(&[("n1", Some("udp://10.0.0.1:1111"))]);
        let agg = AggregateDiscovery::new(static_src, &db, mdns("self"));
        let r = agg.resolve_with_sources(&peer("n1"));
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].source, DiscoverySource::Static);
    }

    #[test]
    fn unknown_peer_yields_empty_and_miss() {
        let db = Lsdb::new(peer("self"));
        let agg = AggregateDiscovery::new(StaticDiscovery::default(), &db, mdns("self"));
        let r = agg.resolve_with_sources(&peer("ghost"));
        assert!(r.is_empty());
        let v = Discovery::resolve(&agg, &peer("ghost"));
        assert!(v.is_empty());
        let snap = agg.metrics().snapshot();
        assert_eq!(snap.miss, 1);
        assert_eq!(snap.hits_static, 0);
    }

    #[test]
    fn metrics_count_per_source_hit() {
        let static_src = StaticDiscovery::new([(peer("n1"), addr("10.0.0.1:1111"))]);
        let db = lsdb_with(&[
            ("n1", Some("udp://10.0.0.2:2222")),
            ("n2", Some("udp://10.0.0.3:3333")),
        ]);
        let agg = AggregateDiscovery::new(static_src, &db, mdns("self"));
        Discovery::resolve(&agg, &peer("n1")); // static + lsa
        Discovery::resolve(&agg, &peer("n2")); // lsa only
        let snap = agg.metrics().snapshot();
        assert_eq!(snap.hits_static, 1);
        assert_eq!(snap.hits_lsa, 2);
        assert_eq!(snap.hits_mdns, 0);
        assert_eq!(snap.miss, 0);
    }

    #[test]
    fn mdns_source_participates() {
        let mut m = mdns("self");
        let other = MdnsDiscovery::new(peer("n9"), 9999, "127.0.0.1".parse().unwrap()).unwrap();
        let now = std::time::Instant::now();
        m.handle_datagram(&other.encode_announce(), now);
        let db = Lsdb::new(peer("self"));
        let agg = AggregateDiscovery::new(StaticDiscovery::default(), &db, m);
        let r = agg.resolve_with_sources(&peer("n9"));
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].addr, addr("127.0.0.1:9999"));
        assert_eq!(r[0].source, DiscoverySource::Mdns);
    }

    #[test]
    fn paired_source_highest_priority() {
        use crate::paired::{PairedDiscovery, PairedPeer};
        // 配对源的地址优先于静态源（D7：Paired > Static > Lsa > Mdns）。
        let mut paired = PairedDiscovery::new();
        // 注意：PairedDiscovery 内部用 PeerId(hex(pubkey)) 做键。
        let peer_hex = "ab".repeat(32); // 64 hex chars = 32 bytes
        let peer_id_bytes = crate::paired::hex_decode(&peer_hex).unwrap();
        let mut pid = [0u8; 32];
        pid.copy_from_slice(&peer_id_bytes);
        let pp = PairedPeer {
            peer_id: pid,
            name: "test".to_string(),
            addresses: vec![addr("10.9.9.9:9999")],
            paired_at: 0,
        };
        paired.insert(&pp);
        let peer_key = peer(peer_hex.as_str());
        let static_src = StaticDiscovery::new([(peer_key.clone(), addr("10.0.0.1:1111"))]);
        let db = lsdb_with(&[(peer_hex.as_str(), Some("udp://10.0.0.2:2222"))]);
        let agg = AggregateDiscovery::new(static_src, &db, mdns("self")).with_paired(paired);
        let r = agg.resolve_with_sources(&peer_key);
        assert_eq!(r.len(), 3);
        assert_eq!(r[0].source, DiscoverySource::Paired);
        assert_eq!(r[0].addr, addr("10.9.9.9:9999"));
        assert_eq!(r[1].source, DiscoverySource::Static);
        assert_eq!(r[2].source, DiscoverySource::Lsa);
        // metrics 计数配对命中
        let v = Discovery::resolve(&agg, &peer_key);
        assert_eq!(v.len(), 3);
        let snap = agg.metrics().snapshot();
        assert_eq!(snap.hits_paired, 1);
        assert_eq!(snap.hits_static, 1);
    }

    #[test]
    fn without_paired_behaves_as_before() {
        // 未调用 with_paired 时，行为与 D5 冻结时一致（向后兼容）。
        let static_src = StaticDiscovery::new([(peer("n1"), addr("10.0.0.1:1111"))]);
        let db = Lsdb::new(peer("self"));
        let agg = AggregateDiscovery::new(static_src, &db, mdns("self"));
        let r = agg.resolve_with_sources(&peer("n1"));
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].source, DiscoverySource::Static);
        let snap = agg.metrics().snapshot();
        assert_eq!(snap.hits_paired, 0);
    }
}
