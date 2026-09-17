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
    /// 静态表中不存在该 Peer。
    PeerUnknown(PeerId),
}

impl fmt::Display for DiscoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PeerUnknown(peer) => write!(f, "peer unknown: {peer}"),
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
