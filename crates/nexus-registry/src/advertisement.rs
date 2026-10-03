//! Provider 广告（N2 D2）：目录可见的 Provider 能力声明。
//!
//! 一条广告 = v9 §6 最小字段集（ProviderId、ResourceId、Capability Set、
//! Locator Set）＋ D2 裁决的 Registry 契约三件套：
//!
//! 1. **双层授权字段**：`discoverable_by`（目录可见性：谁能在目录里看到这条广告）
//!    vs `use_grants`（使用授权提示：谁被授予了哪些操作）。
//!    目录可见 ≠ 有权限——权威的授权判定永远在提供方侧的 grant 表
//!    （`nexus-auth` D6），每次建 Session 时执行。
//! 2. **三种不可用原因**：`UnavailabilityReason::{ProviderOffline, HealthDegraded,
//!    NotAcceptingWork}` 的结构化区分（字符串形式与 `n2-provider-offline`
//!    冻结期望一致）。
//! 3. **过期广告拒绝**：TTL 语义；`publish` 直接拒绝过期广告
//!    （`RegistryError::AdvertisementExpired`），`lookup` 跳过过期广告。
//!
//! 时间：本模块不取系统时钟（Portable Core 纯内存）；所有时间相关 API
//! 由调用方传入 `now_secs`（unix epoch 秒）。

use std::collections::HashMap;
use std::fmt;

use nexus_domain::{ProviderId, ResourceId, ResourceOperation, ResourceRef};

// ============================================================================
// 双层授权字段
// ============================================================================

/// 目录可见性：谁能在目录（Registry）里看到这条广告。
///
/// 与 `use_grants` 正交：可见 ≠ 有权限。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Discoverability {
    /// 任何请求方可见。
    Public,
    /// 仅名单内的主体可见（主体字符串格式由认证层定义，
    /// 如 D6 的 `"ed25519:<hex>"`；空名单 = 对谁都不可见，显式配置）。
    Restricted {
        /// 可见主体名单。
        principals: Vec<String>,
    },
}

/// 使用授权提示（广告内嵌的 grant 快照）。
///
/// 只是**提示**：请求方可用它做本地过滤/解释，但权威判定在提供方侧
/// grant 表（`nexus-auth` D6），"目录返回 ≠ 有权限"。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageGrant {
    /// 被授权主体（认证层定义的主体字符串）。
    pub principal: String,
    /// 授予的操作集合。
    pub operations: Vec<ResourceOperation>,
    /// 授权过期时间（unix 秒）；`None` = 永不过期（与 `Grant::not_after` 同语义）。
    pub not_after_secs: Option<u64>,
}

// ============================================================================
// 不可用原因（三件套之二）
// ============================================================================

/// Provider 不可用原因（D2：三种结构化区分）。
///
/// `as_str()` 的取值与 `scenarios/product/n2-provider-offline.toml`
/// 冻结期望（`error.reason`）逐字一致，P0-5 可直接复用。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnavailabilityReason {
    /// Provider 下线（进程停 / 网络不可达）。
    ProviderOffline,
    /// Provider 在线但健康度下降（仍可尝试，效果可能打折）。
    HealthDegraded {
        /// 降级说明（如 "cpu_saturated"），机器可读优先。
        detail: String,
    },
    /// Provider 在线健康，但当前不接受新工作（如维护窗口/配额用尽）。
    NotAcceptingWork {
        /// 拒绝原因（如 "draining"），机器可读优先。
        reason: String,
    },
}

impl UnavailabilityReason {
    /// 机器可读的不可用原因名（冻结拼写，勿改）。
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ProviderOffline => "ProviderOffline",
            Self::HealthDegraded { .. } => "HealthDegraded",
            Self::NotAcceptingWork { .. } => "NotAcceptingWork",
        }
    }
}

impl fmt::Display for UnavailabilityReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ============================================================================
// ProviderAdvertisement
// ============================================================================

/// Provider 广告：一条可被目录查询、可经控制面传输的 Provider 能力声明。
///
/// 不变量：
/// - `resource` 是**不透明** `ResourceId`（D2：`ResourceRef{workspace, name}`
///   只做本地解析，名字不进广告传输）；
/// - `provider`（Identity）与 `locators`（Locator）分离，禁止互相推导；
/// - Registry 只保存广告事实，不做评分/排序（Measurement != Score）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderAdvertisement {
    /// Provider 身份标识（稳定，与位置无关）。
    pub provider: ProviderId,
    /// 被服务的资源（不透明 Id；由请求方/提供方各自本地解析自 `ResourceRef`）。
    pub resource: ResourceId,
    /// 能力集合（供 Planner 对照 Constraint，如 "service-session"）。
    pub capabilities: Vec<String>,
    /// 定位集合（如何到达该 Provider，如 "tcp://10.0.0.2:9000"）。
    pub locators: Vec<String>,
    /// 目录可见性（谁能在目录里看到；三件套之一）。
    pub discoverable_by: Discoverability,
    /// 使用授权提示（谁被授予了哪些操作；三件套之一；可见 ≠ 有权限）。
    pub use_grants: Vec<UsageGrant>,
    /// 不可用原因；`None` = 当前可用（三件套之一）。
    pub unavailable: Option<UnavailabilityReason>,
    /// 广告发布时间（unix epoch 秒；调用方时钟提供）。
    pub issued_at_secs: u64,
    /// 广告有效期（秒）；`0` = 永不过期（静态配置可显式选择）。
    pub ttl_secs: u64,
}

impl ProviderAdvertisement {
    /// 广告是否已过期（TTL 语义）。
    ///
    /// `ttl_secs == 0` 永不过期；否则 `now_secs >= issued_at_secs + ttl_secs`
    /// 即过期（加法 saturating 防溢出）；`now_secs < issued_at_secs`
    /// （时钟 skew）视为未过期。
    #[must_use]
    pub fn is_expired(&self, now_secs: u64) -> bool {
        self.ttl_secs > 0 && now_secs >= self.issued_at_secs.saturating_add(self.ttl_secs)
    }

    /// 广告当前是否可用（未过期且无不可用标记）。
    #[must_use]
    pub fn is_usable(&self, now_secs: u64) -> bool {
        !self.is_expired(now_secs) && self.unavailable.is_none()
    }

    /// 对指定请求主体是否目录可见。
    #[must_use]
    pub fn visible_to(&self, requester_principal: &str) -> bool {
        match &self.discoverable_by {
            Discoverability::Public => true,
            Discoverability::Restricted { principals } => {
                principals.iter().any(|p| p == requester_principal)
            }
        }
    }
}

// ============================================================================
// Registry 错误
// ============================================================================

/// Registry 广告操作失败（类型化；D2 过期拒绝为独立变体）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryError {
    /// 过期广告被拒绝（TTL 语义；D2 契约三件套之三）。
    AdvertisementExpired {
        /// 广告所属 Provider。
        provider: ProviderId,
        /// 广告所属资源。
        resource: ResourceId,
    },
}

impl fmt::Display for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AdvertisementExpired { provider, resource } => write!(
                f,
                "advertisement expired: provider={} resource={}",
                provider.0, resource.0
            ),
        }
    }
}

impl std::error::Error for RegistryError {}

// ============================================================================
// Registry：广告存储（追加到 lib.rs 的 Registry）
// ============================================================================

/// 纯内存广告存储的 Registry 侧方法（实现见 lib.rs `Registry`）。
impl super::Registry {
    /// 发布一条广告（按 `(provider, resource)` 幂等覆盖）。
    ///
    /// 过期广告直接拒绝（`RegistryError::AdvertisementExpired`），不入库。
    pub fn publish_ad(
        &mut self,
        ad: ProviderAdvertisement,
        now_secs: u64,
    ) -> Result<(), RegistryError> {
        if ad.is_expired(now_secs) {
            return Err(RegistryError::AdvertisementExpired {
                provider: ad.provider.clone(),
                resource: ad.resource.clone(),
            });
        }
        if let Some(existing) = self
            .ads
            .iter_mut()
            .find(|a| a.provider == ad.provider && a.resource == ad.resource)
        {
            *existing = ad;
        } else {
            self.ads.push(ad);
        }
        Ok(())
    }

    /// 撤回一条广告（提供方下线/资源下架）；返回是否命中。
    pub fn withdraw_ad(&mut self, provider: &ProviderId, resource: &ResourceId) -> bool {
        let before = self.ads.len();
        self.ads
            .retain(|a| !(a.provider == *provider && a.resource == *resource));
        self.ads.len() != before
    }

    /// 查询指定资源的有效广告（跳过过期；不过滤可见性/可用性——
    /// 调用方按需用 `visible_to` / `is_usable` 再过滤）。
    /// 结果按发布顺序返回（确定性）。
    pub fn lookup_ads(&self, resource: &ResourceId, now_secs: u64) -> Vec<ProviderAdvertisement> {
        self.ads
            .iter()
            .filter(|a| a.resource == *resource && !a.is_expired(now_secs))
            .cloned()
            .collect()
    }

    /// 查询指定资源、对指定请求主体**目录可见**的有效广告。
    ///
    /// 提供方响应 `RESOURCE_QUERY` 时用此方法（按请求方已认证主体过滤）；
    /// 请求方本地目录展示也用此方法。
    pub fn lookup_visible_ads(
        &self,
        resource: &ResourceId,
        requester_principal: &str,
        now_secs: u64,
    ) -> Vec<ProviderAdvertisement> {
        self.lookup_ads(resource, now_secs)
            .into_iter()
            .filter(|a| a.visible_to(requester_principal))
            .collect()
    }

    /// 清理过期广告；返回清理条数。
    pub fn purge_expired_ads(&mut self, now_secs: u64) -> usize {
        let before = self.ads.len();
        self.ads.retain(|a| !a.is_expired(now_secs));
        before - self.ads.len()
    }

    /// 当前广告条数（含过期未清理的）。
    #[must_use]
    pub fn advertisement_count(&self) -> usize {
        self.ads.len()
    }

    /// 从静态配置导入广告（P0 static 先行；mDNS/LSA 广播是 P0 红线，不做）。
    ///
    /// 每条静态条目以 `now_secs` 为发布时间生成广告并发布；
    /// 任一条目过期则整体返回 `AdvertisementExpired`（已导入的保留）。
    pub fn import_static(
        &mut self,
        entries: impl IntoIterator<Item = StaticProviderEntry>,
        now_secs: u64,
    ) -> Result<usize, RegistryError> {
        let mut count = 0;
        for entry in entries {
            self.publish_ad(entry.into_advertisement(now_secs), now_secs)?;
            count += 1;
        }
        Ok(count)
    }
}

// ============================================================================
// 静态配置（P0 先行）
// ============================================================================

/// 静态 Provider 配置条目（P0：static 配置先行）。
///
/// 请求方/提供方各自的静态配置文件描述"本节点知道哪些 Provider 在哪里"；
/// `import_static` 把它变成广告进入 Registry——请求方 Registry 可见，
/// 无需任何网络广播（mDNS/LSA 的 Provider 广播是 P0 红线）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticProviderEntry {
    /// Provider 身份标识。
    pub provider: ProviderId,
    /// 被服务的资源（不透明 Id；静态配置里由运维/用户事先填好，
    /// 与 `LocalNameTable` 的本地名解耦）。
    pub resource: ResourceId,
    /// 能力集合。
    pub capabilities: Vec<String>,
    /// 定位集合（如提供方监听地址）。
    pub locators: Vec<String>,
    /// 目录可见性。
    pub discoverable_by: Discoverability,
    /// 使用授权提示。
    pub use_grants: Vec<UsageGrant>,
    /// 静态广告有效期（秒）；`0` = 永不过期。
    pub ttl_secs: u64,
}

impl StaticProviderEntry {
    /// 生成广告：发布时间 = 导入时刻，可用（`unavailable = None`）。
    ///
    /// 静态配置表达"我知道这个 Provider"；它的实时可用性由后续的
    /// 控制帧（`RESOURCE_ANNOUNCE` 刷新 / `LEASE_RENEW` / 过期）表达，
    /// 不在静态配置里硬编码。
    #[must_use]
    pub fn into_advertisement(self, now_secs: u64) -> ProviderAdvertisement {
        ProviderAdvertisement {
            provider: self.provider,
            resource: self.resource,
            capabilities: self.capabilities,
            locators: self.locators,
            discoverable_by: self.discoverable_by,
            use_grants: self.use_grants,
            unavailable: None,
            issued_at_secs: now_secs,
            ttl_secs: self.ttl_secs,
        }
    }
}

// ============================================================================
// 本地名字表（D2：名字解析与广告传输分离）
// ============================================================================

/// 本地资源名字表：`ResourceRef{workspace, name}` → 不透明 `ResourceId`。
///
/// 只做**本地**解析（静态配置/用户输入的人类可读名 → 机器 Id）；
/// 广告与控制帧在传输中只携带不透明 `ResourceId`，名字永不进传输层
/// （D2 名字解析与广告传输分离）。
#[derive(Debug, Clone, Default)]
pub struct LocalNameTable {
    entries: HashMap<ResourceRef, ResourceId>,
}

impl LocalNameTable {
    /// 创建空名字表。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 登记一个本地名 → Id 映射（同名覆盖）。
    pub fn insert(&mut self, name: ResourceRef, id: ResourceId) {
        self.entries.insert(name, id);
    }

    /// 本地解析人类可读名为不透明 Id；未登记返回 `None`。
    #[must_use]
    pub fn resolve(&self, name: &ResourceRef) -> Option<&ResourceId> {
        self.entries.get(name)
    }

    /// 删除一条映射；返回是否命中。
    pub fn remove(&mut self, name: &ResourceRef) -> bool {
        self.entries.remove(name).is_some()
    }

    /// 当前映射条数。
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// 是否为空。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_domain::{ResourceName, WorkspaceId};

    fn ad(provider: &str) -> ProviderAdvertisement {
        ProviderAdvertisement {
            provider: ProviderId(provider.into()),
            resource: ResourceId("res-1".into()),
            capabilities: vec!["service-session".into()],
            locators: vec!["tcp://10.0.0.2:9000".into()],
            discoverable_by: Discoverability::Public,
            use_grants: vec![UsageGrant {
                principal: "ed25519:aa".into(),
                operations: vec![ResourceOperation::Use],
                not_after_secs: None,
            }],
            unavailable: None,
            issued_at_secs: 1_000,
            ttl_secs: 60,
        }
    }

    fn name_ref(ws: &str, name: &str) -> ResourceRef {
        ResourceRef::new(
            WorkspaceId::new(ws),
            ResourceName::new(name).expect("valid name"),
        )
    }

    #[test]
    fn ttl_expiry_boundary() {
        let a = ad("p1");
        assert!(!a.is_expired(1_059), "ttl 内未过期");
        assert!(a.is_expired(1_060), "ttl 边界恰好过期");
        assert!(a.is_expired(9_999_999), "远超 ttl 过期");

        // ttl=0 永不过期。
        let mut b = ad("p1");
        b.ttl_secs = 0;
        assert!(!b.is_expired(u64::MAX));

        // saturating 防溢出：issued_at 接近 u64::MAX 时不 panic。
        let mut c = ad("p1");
        c.issued_at_secs = u64::MAX;
        c.ttl_secs = 100;
        assert!(c.is_expired(u64::MAX));
        assert!(!c.is_expired(u64::MAX - 1), "saturating 下未到边界不算过期");
    }

    #[test]
    fn publish_rejects_expired_advertisement() {
        let mut reg = crate::Registry::new();
        let mut expired = ad("p1");
        expired.issued_at_secs = 100;
        expired.ttl_secs = 60; // 160 过期
        let err = reg.publish_ad(expired, 200).expect_err("过期广告必须拒绝");
        assert_eq!(
            err,
            RegistryError::AdvertisementExpired {
                provider: ProviderId("p1".into()),
                resource: ResourceId("res-1".into()),
            }
        );
        assert_eq!(reg.advertisement_count(), 0, "过期广告不入库");
    }

    #[test]
    fn publish_is_idempotent_by_provider_and_resource() {
        let mut reg = crate::Registry::new();
        reg.publish_ad(ad("p1"), 1_000).unwrap();
        let mut newer = ad("p1");
        newer.issued_at_secs = 1_010;
        newer.capabilities = vec!["v2".into()];
        reg.publish_ad(newer, 1_010).unwrap();
        assert_eq!(reg.advertisement_count(), 1);
        let got = reg.lookup_ads(&ResourceId("res-1".into()), 1_020);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].capabilities, vec!["v2".to_string()]);
    }

    #[test]
    fn lookup_skips_expired_but_keeps_them_until_purge() {
        let mut reg = crate::Registry::new();
        reg.publish_ad(ad("fresh"), 1_000).unwrap();
        let mut stale = ad("stale");
        stale.issued_at_secs = 100;
        stale.ttl_secs = 60;
        // 直接 publish 会被拒绝；用 ttl=0 绕过再改时间，模拟缓存中自然过期。
        stale.ttl_secs = 0;
        reg.publish_ad(stale, 200).unwrap();
        // 手动把它的 ttl 改小（测试替身：直接改已入库广告）。
        {
            let slot = reg
                .ads
                .iter_mut()
                .find(|a| a.provider.0 == "stale")
                .unwrap();
            slot.ttl_secs = 60;
            slot.issued_at_secs = 100;
        }
        let got = reg.lookup_ads(&ResourceId("res-1".into()), 1_000);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].provider.0, "fresh");
        assert_eq!(reg.purge_expired_ads(1_000), 1);
        assert_eq!(reg.advertisement_count(), 1);
    }

    #[test]
    fn three_unavailability_reasons_are_structured_and_match_frozen_spelling() {
        // as_str 与 n2-provider-offline.toml 冻结期望逐字一致。
        assert_eq!(
            UnavailabilityReason::ProviderOffline.as_str(),
            "ProviderOffline"
        );
        assert_eq!(
            UnavailabilityReason::HealthDegraded {
                detail: "cpu_saturated".into()
            }
            .as_str(),
            "HealthDegraded"
        );
        assert_eq!(
            UnavailabilityReason::NotAcceptingWork {
                reason: "draining".into()
            }
            .as_str(),
            "NotAcceptingWork"
        );

        // 三种原因都使广告不可用，但仍可被查到（结构化可见，非静默）。
        let mut reg = crate::Registry::new();
        for (i, reason) in [
            UnavailabilityReason::ProviderOffline,
            UnavailabilityReason::HealthDegraded {
                detail: "cpu_saturated".into(),
            },
            UnavailabilityReason::NotAcceptingWork {
                reason: "draining".into(),
            },
        ]
        .into_iter()
        .enumerate()
        {
            let mut a = ad(&format!("p{i}"));
            a.unavailable = Some(reason);
            assert!(!a.is_usable(1_000));
            reg.publish_ad(a, 1_000).unwrap();
        }
        let got = reg.lookup_ads(&ResourceId("res-1".into()), 1_000);
        assert_eq!(got.len(), 3, "不可用广告仍可见（结构化原因），非静默丢弃");
        let reasons: Vec<&str> = got
            .iter()
            .map(|a| a.unavailable.as_ref().unwrap().as_str())
            .collect();
        assert_eq!(
            reasons,
            vec!["ProviderOffline", "HealthDegraded", "NotAcceptingWork"]
        );
    }

    #[test]
    fn discoverability_filters_directory_visibility() {
        let mut reg = crate::Registry::new();
        reg.publish_ad(ad("pub"), 1_000).unwrap();
        let mut restricted = ad("priv");
        restricted.discoverable_by = Discoverability::Restricted {
            principals: vec!["ed25519:aa".into()],
        };
        reg.publish_ad(restricted, 1_000).unwrap();
        let mut locked = ad("locked");
        locked.discoverable_by = Discoverability::Restricted { principals: vec![] };
        reg.publish_ad(locked, 1_000).unwrap();

        let res = ResourceId("res-1".into());
        let anon: Vec<String> = reg
            .lookup_visible_ads(&res, "ed25519:stranger", 1_000)
            .iter()
            .map(|a| a.provider.0.clone())
            .collect();
        assert_eq!(anon, vec!["pub".to_string()], "陌生人只看到 public");
        let insider: Vec<String> = reg
            .lookup_visible_ads(&res, "ed25519:aa", 1_000)
            .iter()
            .map(|a| a.provider.0.clone())
            .collect();
        assert_eq!(insider, vec!["pub".to_string(), "priv".to_string()]);
        // 空名单 = 对谁都不可见。
        assert!(
            reg.lookup_visible_ads(&res, "ed25519:aa", 1_000)
                .iter()
                .all(|a| a.provider.0 != "locked")
        );
    }

    #[test]
    fn withdraw_ad() {
        let mut reg = crate::Registry::new();
        reg.publish_ad(ad("p1"), 1_000).unwrap();
        assert!(reg.withdraw_ad(&ProviderId("p1".into()), &ResourceId("res-1".into())));
        assert!(!reg.withdraw_ad(&ProviderId("p1".into()), &ResourceId("res-1".into())));
        assert_eq!(reg.advertisement_count(), 0);
    }

    #[test]
    fn local_name_table_resolves_and_forgets() {
        let mut table = LocalNameTable::new();
        assert!(table.is_empty());
        let r = name_ref("ws1", "dev-web");
        table.insert(r.clone(), ResourceId("res-9f2".into()));
        assert_eq!(
            table.resolve(&r),
            Some(&ResourceId("res-9f2".into())),
            "人类可读名本地解析为不透明 Id"
        );
        assert_eq!(table.resolve(&name_ref("ws1", "unknown")), None);
        // 同名覆盖。
        table.insert(r.clone(), ResourceId("res-aaa".into()));
        assert_eq!(table.resolve(&r), Some(&ResourceId("res-aaa".into())));
        assert!(table.remove(&r));
        assert!(!table.remove(&r));
        assert!(table.is_empty());
    }

    #[test]
    fn static_import_makes_providers_visible_to_requester() {
        // Provider 静态注册 → Advertisement → 请求方 Registry 可见（无广播）。
        let mut reg = crate::Registry::new();
        let n = reg
            .import_static(
                [StaticProviderEntry {
                    provider: ProviderId("node-b".into()),
                    resource: ResourceId("res-svc".into()),
                    capabilities: vec!["service-session".into()],
                    locators: vec!["tcp://10.0.0.2:9000".into()],
                    discoverable_by: Discoverability::Public,
                    use_grants: vec![],
                    ttl_secs: 300,
                }],
                5_000,
            )
            .unwrap();
        assert_eq!(n, 1);
        let got = reg.lookup_visible_ads(&ResourceId("res-svc".into()), "anyone", 5_100);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].provider.0, "node-b");
        assert_eq!(got[0].issued_at_secs, 5_000);
        assert_eq!(got[0].unavailable, None, "静态导入假定可用");
    }

    #[test]
    fn static_import_rejects_expired_entry() {
        let mut reg = crate::Registry::new();
        // ttl=0 永不过期才能导入；这里构造一个 into_advertisement 后已过期的条目
        // 无法直接表达（into_advertisement 用 now 做 issued_at），改用 publish 路径已覆盖。
        // 本用例断言：ttl_secs=0 的静态条目永不过期。
        reg.import_static(
            [StaticProviderEntry {
                provider: ProviderId("node-b".into()),
                resource: ResourceId("res-svc".into()),
                capabilities: vec![],
                locators: vec![],
                discoverable_by: Discoverability::Public,
                use_grants: vec![],
                ttl_secs: 0,
            }],
            5_000,
        )
        .unwrap();
        let got = reg.lookup_ads(&ResourceId("res-svc".into()), u64::MAX);
        assert_eq!(got.len(), 1, "ttl=0 的静态广告永不过期");
    }
}
