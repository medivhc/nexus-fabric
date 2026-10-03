//! nexus-registry
//!
//! 维护 Resource / Provider / Node / Presence / Capability / Locator 的可查询注册视图。
//! 只保存事实与广告，不做业务评分（Measurement != Score），不负责 Bootstrap 网络发现，
//! 也不建立 Link；Node Identity 与 Locator 严格分离。
//!
//! N2 P0-2：`advertisement` 模块提供 Provider 广告类型（D2 契约三件套：
//! 双层授权字段 / 三种不可用原因 / 过期拒绝）与本地名字表；
//! `control_frame` 模块提供经 FrameStream 交换的 5 种 N2 控制帧的
//! wire 编解码与已认证通道（认证走既有门控，本模块不另起一套）。
//!
//! 本 crate 是 Portable Core：纯内存、零 I/O、零第三方依赖，可编译到 WASI。
//! 详细边界见同目录 `MODULE.md`。

#![forbid(unsafe_code)]

pub mod advertisement;
pub mod control_frame;

pub use advertisement::{
    Discoverability, LocalNameTable, ProviderAdvertisement, RegistryError, StaticProviderEntry,
    UnavailabilityReason, UsageGrant,
};
pub use control_frame::{
    AuthenticatedPeer, ChannelError, ControlChannel, ControlFrame, ControlTransport,
    FrameCodecError, GrantAnnouncement, decode_control_frame, encode_control_frame,
};

use advertisement::ProviderAdvertisement as Advertisement;
use nexus_domain::{ProviderId, ResourceId};

/// 一条 Provider 注册记录（事实，不含评分）。
///
/// 不变量：
/// - `id`（Identity）与 `locator`（Locator）是两个独立字段，禁止互相推导或合并；
/// - Registry 只记录 `present`（Presence 事实）与 `capabilities`（能力广告），
///   不记录权重、分数或选择结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderRecord {
    /// Provider 身份标识（稳定，与位置无关）。
    pub id: ProviderId,
    /// 该 Provider 能服务的 Resource。
    pub resource: ResourceId,
    /// Placement（部署位置的中立标签，如 region/zone）。
    pub placement: String,
    /// Locator（如何到达它的位置信息；Identity != Locator）。
    pub locator: String,
    /// 广告的能力标签（如 "internet-access"），供 Planner 对照 Constraint。
    pub capabilities: Vec<String>,
    /// Presence 事实：当前是否在线可候选。
    pub present: bool,
}

impl ProviderRecord {
    /// 是否广告了指定能力。
    #[must_use]
    pub fn has_capability(&self, capability: &str) -> bool {
        self.capabilities.iter().any(|c| c == capability)
    }
}

/// 纯内存注册视图。查询结果按注册顺序稳定返回（确定性，可重放）。
#[derive(Debug, Clone, Default)]
pub struct Registry {
    records: Vec<ProviderRecord>,
    pub(crate) ads: Vec<Advertisement>,
}

impl Registry {
    /// 创建空注册表。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 注册（或按 id 幂等覆盖）一条 Provider 记录。
    pub fn register(&mut self, record: ProviderRecord) {
        if let Some(existing) = self.records.iter_mut().find(|r| r.id == record.id) {
            *existing = record;
        } else {
            self.records.push(record);
        }
    }

    /// 返回服务指定 Resource 且当前在线的候选（事实集，不做排序/评分）。
    /// 返回克隆记录（调用方获得拥有态），结果按注册顺序返回，保证确定性。
    pub fn candidates(&self, resource: &ResourceId) -> Vec<ProviderRecord> {
        self.records
            .iter()
            .filter(|r| r.resource == *resource && r.present)
            .cloned()
            .collect()
    }

    /// 当前注册记录数。
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// 是否为空。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider(id: &str, caps: &[&str], present: bool) -> ProviderRecord {
        ProviderRecord {
            id: ProviderId(id.into()),
            resource: ResourceId("internet-access".into()),
            placement: format!("place-{id}"),
            locator: format!("locator-{id}"),
            capabilities: caps.iter().map(|s| (*s).to_string()).collect(),
            present,
        }
    }

    #[test]
    fn identity_is_distinct_from_locator() {
        let r = provider("p1", &["internet-access"], true);
        assert_ne!(r.id.0, r.locator);
    }

    #[test]
    fn candidates_filter_by_resource_and_presence_only() {
        let mut reg = Registry::new();
        reg.register(provider("p1", &["internet-access"], true));
        reg.register(provider("p2", &["internet-access"], false)); // 离线
        reg.register(ProviderRecord {
            resource: ResourceId("other".into()),
            ..provider("p3", &["internet-access"], true)
        });
        let ids: Vec<String> = reg
            .candidates(&ResourceId("internet-access".into()))
            .iter()
            .map(|r| r.id.0.clone())
            .collect();
        assert_eq!(ids, vec!["p1".to_string()]);
    }

    #[test]
    fn register_is_idempotent_by_id_and_order_stable() {
        let mut reg = Registry::new();
        reg.register(provider("b", &[], true));
        reg.register(provider("a", &[], true));
        reg.register(provider("b", &["x"], true)); // 覆盖，不新增
        assert_eq!(reg.len(), 2);
        let order: Vec<String> = reg.records.iter().map(|r| r.id.0.clone()).collect();
        assert_eq!(order, vec!["b".to_string(), "a".to_string()]);
    }

    #[test]
    fn capability_match() {
        let r = provider("p1", &["internet-access", "udp"], true);
        assert!(r.has_capability("udp"));
        assert!(!r.has_capability("tcp"));
    }
}
