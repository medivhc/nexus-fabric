//! nexus-discovery
//!
//! 执行 Bootstrap、Peer Discovery、Endpoint/Candidate Exchange 与 Presence 建立。
//!
//! remote P0 冻结契约：静态发现表（scenarios/product/remote_service_access_flow.toml）；
//! 发现协议后置。`resolve` 只做静态表查询，不发起网络 I/O、不建立 Connectivity。
//!
//! 详细边界见同目录 `MODULE.md`。

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;

/// 稳定模块标识；业务实现应通过公开类型/trait 增量加入，而不是扩大隐式全局状态。
pub const NEXUS_DISCOVERY_MODULE: &str = "nexus-discovery";

/// 返回模块的人类可读职责摘要。
#[must_use]
pub const fn module_summary() -> &'static str {
    "执行 Bootstrap、Peer Discovery、Endpoint/Candidate Exchange 与 Presence 建立。"
}

/// 提供方节点标识。Identity != Locator：Peer 不携带 Endpoint 本身。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PeerId(pub String);

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// 发现失败（冻结契约：单变体）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoveryError {
    /// 静态表/注册中心中不存在该 Peer。
    PeerUnknown(PeerId),
    /// 该 Peer 的 Presence 已过期（动态发现，不得返回过期 Endpoint）。
    PeerExpired(PeerId),
}

impl fmt::Display for DiscoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PeerUnknown(peer) => write!(f, "peer unknown: {peer}"),
            Self::PeerExpired(peer) => write!(f, "peer presence expired: {peer}"),
        }
    }
}

impl std::error::Error for DiscoveryError {}

/// 静态发现表（remote P0；发现协议后置）。
///
/// 冻结契约：`new` 以迭代器注入 Peer/Endpoint 关系；`resolve` 只做查询。
#[derive(Debug, Clone, Default)]
pub struct StaticDiscovery {
    peers: HashMap<PeerId, SocketAddr>,
}

impl StaticDiscovery {
    /// 从 (PeerId, SocketAddr) 迭代器构造静态发现表。
    pub fn new(peers: impl IntoIterator<Item = (PeerId, SocketAddr)>) -> Self {
        Self {
            peers: peers.into_iter().collect(),
        }
    }

    /// 解析 Peer 的 Endpoint；未知 Peer 返回 `DiscoveryError::PeerUnknown`。
    pub fn resolve(&self, peer: &PeerId) -> Result<SocketAddr, DiscoveryError> {
        self.peers
            .get(peer)
            .copied()
            .ok_or_else(|| DiscoveryError::PeerUnknown(peer.clone()))
    }

    /// 注册（或覆盖）一个 Peer 的 Endpoint（P0 组合根装配用补充 API；
    /// 不改动冻结契约中的任何签名）。
    pub fn register(&mut self, peer: PeerId, addr: SocketAddr) {
        self.peers.insert(peer, addr);
    }
}

// ---------- 动态 Presence（remote P0 扩展；发现协议网络传输仍后置） ----------

/// 动态 Presence：提供方主动发布的可达性公告（AGENTS.md §15 重新发布 Provider Presence）。
#[derive(Debug, Clone)]
pub struct Presence {
    /// 提供方节点标识（Identity != Locator）。
    pub peer: PeerId,
    /// 可达 Endpoint。
    pub endpoint: SocketAddr,
    /// 生存期（秒）；过期后不可解析。
    pub ttl_secs: u64,
    announced_at: std::time::Instant,
}

impl Presence {
    /// Presence 是否已过期（过期后不得解析）。
    #[must_use]
    pub fn expired(&self) -> bool {
        self.announced_at.elapsed().as_secs() >= self.ttl_secs
    }
}

/// 进程内动态发现注册中心：announce / resolve + TTL 过期语义。
///
/// 冻结契约（scenarios/product/remote_presence_dynamic_flow.toml）：
/// `resolve` 只做注册中心查询，不发起网络 I/O、不建立 Connectivity
/// （Discovery != Connectivity Establishment）；TTL 过期后 Peer 不可解析
/// （不得返回过期 Endpoint）；`announce` 幂等刷新。
#[derive(Debug, Default)]
pub struct PresenceRegistry {
    presences: Vec<Presence>,
}

impl PresenceRegistry {
    /// 发布/刷新提供方 Presence（幂等：重复 announce 刷新记录）。
    pub fn announce(
        &mut self,
        peer: PeerId,
        endpoint: SocketAddr,
        ttl_secs: u64,
    ) -> Result<(), DiscoveryError> {
        if let Some(p) = self.presences.iter_mut().find(|p| p.peer == peer) {
            p.endpoint = endpoint;
            p.ttl_secs = ttl_secs;
            p.announced_at = std::time::Instant::now();
        } else {
            self.presences.push(Presence {
                peer,
                endpoint,
                ttl_secs,
                announced_at: std::time::Instant::now(),
            });
        }
        Ok(())
    }

    /// 动态解析：Presence 存在且未过期 -> Endpoint；
    /// 未发布 -> `PeerUnknown`；已过期 -> `PeerExpired`。
    pub fn resolve(&self, peer: &PeerId) -> Result<SocketAddr, DiscoveryError> {
        let Some(p) = self.presences.iter().find(|p| &p.peer == peer) else {
            return Err(DiscoveryError::PeerUnknown(peer.clone()));
        };
        if p.expired() {
            return Err(DiscoveryError::PeerExpired(peer.clone()));
        }
        Ok(p.endpoint)
    }

    /// 该 Peer 是否已发布 Presence（不校验过期）。
    #[must_use]
    pub fn is_announced(&self, peer: &PeerId) -> bool {
        self.presences.iter().any(|p| &p.peer == peer)
    }

    /// 该 Peer 的 Presence 是否已过期。
    #[must_use]
    pub fn is_expired(&self, peer: &PeerId) -> bool {
        self.presences
            .iter()
            .find(|p| &p.peer == peer)
            .map(Presence::expired)
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod presence_registry_tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    #[test]
    fn announce_then_resolve_ok() {
        let mut reg = PresenceRegistry::default();
        reg.announce(PeerId("node-b".into()), addr(4242), 60)
            .expect("announce ok");
        assert_eq!(
            reg.resolve(&PeerId("node-b".into())).expect("resolve ok"),
            addr(4242)
        );
        assert!(reg.is_announced(&PeerId("node-b".into())));
        assert!(!reg.is_expired(&PeerId("node-b".into())));
    }

    #[test]
    fn ttl_zero_is_expired_and_unresolvable() {
        let mut reg = PresenceRegistry::default();
        reg.announce(PeerId("node-b".into()), addr(4242), 0)
            .expect("announce ok");
        assert!(reg.is_announced(&PeerId("node-b".into())));
        assert!(reg.is_expired(&PeerId("node-b".into())));
        assert!(matches!(
            reg.resolve(&PeerId("node-b".into())),
            Err(DiscoveryError::PeerExpired(_))
        ));
    }

    #[test]
    fn never_announced_is_unknown() {
        let reg = PresenceRegistry::default();
        assert!(matches!(
            reg.resolve(&PeerId("node-b".into())),
            Err(DiscoveryError::PeerUnknown(_))
        ));
        assert!(!reg.is_announced(&PeerId("node-b".into())));
    }

    #[test]
    fn reannounce_refreshes_ttl() {
        let mut reg = PresenceRegistry::default();
        reg.announce(PeerId("node-b".into()), addr(4242), 0)
            .expect("announce ttl0");
        reg.announce(PeerId("node-b".into()), addr(9999), 60)
            .expect("announce refresh");
        assert_eq!(
            reg.resolve(&PeerId("node-b".into())).expect("resolve ok"),
            addr(9999)
        );
        assert!(!reg.is_expired(&PeerId("node-b".into())));
    }
}
