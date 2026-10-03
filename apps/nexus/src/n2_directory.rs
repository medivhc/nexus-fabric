//! N2 目录（P0-4）：registry-backed 资源解析。
//!
//! P0-3 的编译内置静态目录（`plan_cli::DIRECTORY`）在此替换为 registry-backed
//! 解析（D2"P0 static 配置先行"的 registry 形态）：静态种子经 P0-2 的
//! `import_static` 进入 `Registry`，`resource publish` 的持久化广告经
//! `publish_ad` 进入同一 Registry；名字经 `LocalNameTable` 本地解析
//! （名字≠定位，D2）。
//!
//! Presence 语义对齐（任务明确要求）：`Registry::candidates()` 按 P0-2 契约只
//! 返回在线候选，会吞掉 `not_present` 的解释价值；本模块的快照构造器改从
//! `lookup_ads`（全部未过期广告）取数，按 D2 三件套映射 `present`：
//! - `unavailable == None` / `HealthDegraded` → `present = true`；
//! - `ProviderOffline` / `NotAcceptingWork` → `present = false`
//!  （Planner 以 `NotPresent` 解释；完整原因由 `resource show` 展示）。
//! 静态种子中 `down-dev-1` 的离线态即用 `ProviderOffline` 表达（P0-3 的
//! `present=false` 在此语义下精确对应）。

use std::collections::HashMap;

use nexus_domain::{
    Constraint, Intent, NexusError, ProviderId, ResourceId, ResourceKind, ResourceName,
    ResourceRef, WorkspaceId,
};
use nexus_planner::{PlanningSnapshot, plan_from_snapshot};
use nexus_registry::{
    Discoverability, LocalNameTable, ProviderAdvertisement, ProviderRecord, Registry,
    StaticProviderEntry, UnavailabilityReason,
};

use crate::n2_store::{N2Store, NameEntry};

/// P0 默认 workspace（单 Workspace 单管理员；D6）。
pub const DEFAULT_WORKSPACE: &str = "default";

/// 目录标记（输出自述；P0-3 的 `static-demo` 在此被 registry 形态取代）。
pub const DIRECTORY_TAG: &str = "registry(static-seed)";

/// 静态种子条目（P0 static 先行；P0-3 `plan_cli::DIRECTORY` 的 registry 形态）。
struct SeedProvider {
    id: &'static str,
    placement: &'static str,
    locator: &'static str,
    capabilities: &'static [&'static str],
    /// 是否为请求方本地节点（白皮书原则 #4 本地优先的加成对象）。
    local: bool,
    /// D2 不可用原因；`None` = 可用。`down-dev-1` 在此表达离线。
    unavailable: Option<UnavailabilityReason>,
}

struct SeedEntry {
    name: &'static str,
    kind: ResourceKind,
    capability: &'static str,
    resource_id: &'static str,
    providers: &'static [SeedProvider],
}

const SEED: &[SeedEntry] = &[
    SeedEntry {
        name: "dev-svc",
        kind: ResourceKind::Service,
        capability: "service",
        resource_id: "res-dev-svc",
        providers: &[
            SeedProvider {
                id: "local-dev-1",
                placement: "local",
                locator: "127.0.0.1:8080",
                capabilities: &["service"],
                local: true,
                unavailable: None,
            },
            SeedProvider {
                id: "remote-dev-1",
                placement: "region-a",
                locator: "203.0.113.10:8080",
                capabilities: &["service"],
                local: false,
                unavailable: None,
            },
            // 结构化拒绝原因演示：离线（Presence 语义对齐后由 ProviderOffline 表达）。
            SeedProvider {
                id: "down-dev-1",
                placement: "region-b",
                locator: "203.0.113.11:8080",
                capabilities: &["service"],
                local: false,
                unavailable: Some(UnavailabilityReason::ProviderOffline),
            },
            // 结构化拒绝原因演示：缺能力。
            SeedProvider {
                id: "nocap-dev-1",
                placement: "region-a",
                locator: "203.0.113.12:8080",
                capabilities: &["metrics"],
                local: false,
                unavailable: None,
            },
        ],
    },
    SeedEntry {
        name: "internet-access",
        kind: ResourceKind::Network,
        capability: "internet-access",
        resource_id: "res-internet-access",
        providers: &[
            SeedProvider {
                id: "p1",
                placement: "us-east",
                locator: "203.0.113.1:51820",
                capabilities: &["internet-access"],
                local: true,
                unavailable: None,
            },
            SeedProvider {
                id: "p2",
                placement: "eu-west",
                locator: "203.0.113.2:51820",
                capabilities: &[],
                local: false,
                unavailable: None,
            },
        ],
    },
    // 授权拒绝路径夹具（`n2-grant-deny-audit`）：目录可解析，但本地 grant 表
    // 无对应授权 → `use` 必须结构化拒绝（目录可见≠有权限，D6）。
    SeedEntry {
        name: "restricted-svc",
        kind: ResourceKind::Service,
        capability: "service",
        resource_id: "res-restricted-svc",
        providers: &[SeedProvider {
            id: "restricted-prov-1",
            placement: "region-c",
            locator: "203.0.113.20:8080",
            capabilities: &["service"],
            local: false,
            unavailable: None,
        }],
    },
];

/// registry-backed 目录（组合根持有；每次 CLI 调用重建，daemon 可长期持有）。
pub struct N2Directory {
    registry: Registry,
    names: LocalNameTable,
    kinds: HashMap<String, ResourceKind>,
    capabilities: HashMap<String, String>,
    placements: HashMap<String, String>,
    local_providers: HashMap<String, ProviderId>,
    withdrawn: Vec<ResourceId>,
}

impl N2Directory {
    /// 打开目录：静态种子导入＋持久化广告/名字表叠加。
    pub fn open(node_dir: &std::path::Path, now_secs: u64) -> Result<Self, String> {
        let store = N2Store::open(node_dir)?;
        Self::open_with_store(&store, now_secs)
    }

    /// `open` 的可测试内核（store 注入）。
    pub fn open_with_store(store: &N2Store, now_secs: u64) -> Result<Self, String> {
        let mut registry = Registry::new();
        let mut names = LocalNameTable::new();
        let mut kinds = HashMap::new();
        let mut capabilities = HashMap::new();
        let mut placements = HashMap::new();
        let mut local_providers = HashMap::new();

        // 1. 静态种子 → Registry（P0 static 先行）。
        for entry in SEED {
            let resource = ResourceId(entry.resource_id.to_string());
            let static_entries = entry.providers.iter().map(|p| StaticProviderEntry {
                provider: ProviderId(p.id.to_string()),
                resource: resource.clone(),
                capabilities: p.capabilities.iter().map(|s| (*s).to_string()).collect(),
                locators: vec![p.locator.to_string()],
                discoverable_by: Discoverability::Public,
                use_grants: Vec::new(),
                ttl_secs: 0,
            });
            registry
                .import_static(static_entries, now_secs)
                .map_err(|e| format!("import static directory: {e}"))?;
            // D2 不可用原因：静态种子里标记离线的 provider，经 publish_ad
            // upsert 同一条广告的 unavailable 字段（Presence 语义对齐）。
            for p in entry.providers.iter().filter(|p| p.unavailable.is_some()) {
                let mut ads = registry.lookup_ads(&resource, now_secs);
                if let Some(pos) = ads.iter().position(|a| a.provider.0 == p.id) {
                    let mut ad = ads.remove(pos);
                    ad.unavailable = p.unavailable.clone();
                    registry
                        .publish_ad(ad, now_secs)
                        .map_err(|e| format!("mark static provider unavailable: {e}"))?;
                }
            }
            // 名字表＋目录属性。
            let rref = ResourceRef::new(
                WorkspaceId::new(DEFAULT_WORKSPACE),
                ResourceName::new(entry.name).expect("static seed name valid"),
            );
            names.insert(rref, resource.clone());
            kinds.insert(entry.name.to_string(), entry.kind);
            capabilities.insert(entry.name.to_string(), entry.capability.to_string());
            for p in entry.providers {
                placements.insert(p.id.to_string(), p.placement.to_string());
                if p.local {
                    local_providers.insert(entry.name.to_string(), ProviderId(p.id.to_string()));
                }
            }
        }

        // 2. 持久化广告叠加（`resource publish` 落盘的）。
        for ad in store.load_ads()? {
            registry
                .publish_ad(ad, now_secs)
                .map_err(|e| format!("load persisted ad: {e}"))?;
        }

        // 3. 持久化名字表叠加（`resource publish` 登记的）。
        for NameEntry {
            workspace,
            name,
            resource_id,
            kind: entry_kind,
        } in store.load_names()?
        {
            names.insert(ResourceRef::new(workspace, name.clone()), resource_id);
            // publish 时指定的 kind（`--kind`）持久化在名字表条目里。
            kinds.insert(
                name.as_str().to_string(),
                entry_kind.unwrap_or(ResourceKind::Service),
            );
        }

        // 4. 撤销 tombstone：已撤销资源不再列出（静态种子重导入后剔除）。
        let withdrawn = store.load_withdrawn()?;
        for w in &withdrawn {
            for ad in registry.lookup_ads(w, now_secs) {
                registry.withdraw_ad(&ad.provider, w);
            }
        }

        Ok(Self {
            registry,
            names,
            kinds,
            capabilities,
            placements,
            local_providers,
            withdrawn,
        })
    }

    /// resolve：人类可读名 → (`ResourceRef`, 不透明 `ResourceId`)（D2 本地解析）。
    pub fn resolve(&self, name: &str) -> Result<(ResourceRef, ResourceId), NexusError> {
        let parsed = ResourceName::new(name).map_err(|e| NexusError::NotFound {
            kind: "resource".to_string(),
            id: format!("{name} (invalid name: {e:?})"),
        })?;
        let rref = ResourceRef::new(WorkspaceId::new(DEFAULT_WORKSPACE), parsed);
        let id = self
            .names
            .resolve(&rref)
            .cloned()
            .ok_or_else(|| NexusError::NotFound {
                kind: "resource".to_string(),
                id: format!("{name} (not in N2 directory '{DIRECTORY_TAG}')"),
            })?;
        if self.withdrawn.contains(&id) {
            return Err(NexusError::NotFound {
                kind: "resource".to_string(),
                id: format!("{name} (revoked; no longer listed)"),
            });
        }
        Ok((rref, id))
    }

    /// 目录 kind 属性（`resource show` 用）。
    #[must_use]
    pub fn kind_of(&self, name: &str) -> Option<ResourceKind> {
        self.kinds.get(name).copied()
    }

    /// 为资源构造规划快照（resolve＋filter＋score 的输入；不建连）。
    ///
    /// Presence 语义对齐：从 `lookup_ads`（全部未过期广告）取数，
    /// `unavailable` 映射为 `ProviderRecord.present`（见模块文档）。
    pub fn planning_snapshot(
        &self,
        name: &str,
        resource: &ResourceId,
        now_secs: u64,
    ) -> PlanningSnapshot {
        let ads = self.registry.lookup_ads(resource, now_secs);
        let candidates: Vec<ProviderRecord> = ads
            .iter()
            .map(|ad: &ProviderAdvertisement| ProviderRecord {
                id: ad.provider.clone(),
                resource: ad.resource.clone(),
                placement: self
                    .placements
                    .get(&ad.provider.0)
                    .cloned()
                    .unwrap_or_default(),
                locator: ad.locators.first().cloned().unwrap_or_default(),
                capabilities: ad.capabilities.clone(),
                present: matches!(
                    ad.unavailable,
                    None | Some(UnavailabilityReason::HealthDegraded { .. })
                ),
            })
            .collect();
        let capability = self
            .capabilities
            .get(name)
            .cloned()
            .unwrap_or_else(|| "service".to_string());
        let constraints = vec![Constraint {
            key: "capability".to_string(),
            value: capability,
        }];
        let snapshot = PlanningSnapshot::new(candidates, constraints);
        match self.local_providers.get(name) {
            Some(local) => snapshot.with_local_provider(local.clone()),
            None => snapshot,
        }
    }

    /// 只读规划：resolve＋filter＋score（`nexus plan` 用；不建连）。
    pub fn preview(
        &self,
        name: &str,
        now_secs: u64,
    ) -> Result<(ResourceRef, ResourceId, nexus_domain::PlanSnapshot), NexusError> {
        let (rref, resource) = self.resolve(name)?;
        let snapshot = self.planning_snapshot(name, &resource, now_secs);
        let intent = Intent {
            profile: "preview".to_string(),
        };
        // P0-3 语义保留：预览无事实测量（不伪造数据；`None` = 显式未知）。
        let planned = plan_from_snapshot(&resource, &snapshot, &intent, |_| None)?;
        Ok((
            rref,
            resource,
            nexus_domain::PlanSnapshot::from_planned(planned.plan, planned.trace),
        ))
    }

    /// 目录名字集合（`resource list` 遍历用；已排序）。
    #[must_use]
    pub fn resource_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.kinds.keys().cloned().collect();
        names.sort();
        names
    }

    /// 底层 Registry（`resource list/show` 用）。
    #[must_use]
    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    /// 按不透明 ResourceId 反查人类可读名（展示用；查无 → `None`）。
    ///
    /// `LocalNameTable` 只支持 name→id；此处对 kinds 的名字集合线性反查
    /// （条目少，P0 可接受）。
    #[must_use]
    pub fn name_of_resource(&self, id: &ResourceId) -> Option<String> {
        if self.withdrawn.contains(id) {
            return None;
        }
        self.kinds
            .keys()
            .find(|n| {
                let rref = ResourceRef::new(
                    WorkspaceId::new(DEFAULT_WORKSPACE),
                    ResourceName::new(*n).expect("stored name valid"),
                );
                self.names.resolve(&rref).is_some_and(|rid| rid == id)
            })
            .cloned()
    }

    /// 名字表条目数（可观测）。
    #[must_use]
    pub fn name_count(&self) -> usize {
        self.names.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_node_dir(tag: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("n2-directory-test-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn seed_resolves_dev_svc_to_opaque_id() {
        let dir = temp_node_dir("resolve");
        let d = N2Directory::open(&dir, 1000).unwrap();
        let (rref, id) = d.resolve("dev-svc").unwrap();
        assert_eq!(rref.name.as_str(), "dev-svc");
        assert_eq!(rref.workspace.0, DEFAULT_WORKSPACE);
        // 不透明 Id：不是名字本身（D2）。
        assert_ne!(id.0, "dev-svc");
        assert_eq!(id.0, "res-dev-svc");
        assert!(d.resolve("no-such").is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn presence_maps_offline_to_not_present() {
        // Presence 语义对齐：down-dev-1（ProviderOffline）→ present=false，
        // Planner 以 not_present 解释（P0-3 行为保留）。
        let dir = temp_node_dir("presence");
        let d = N2Directory::open(&dir, 1000).unwrap();
        let (_, resource) = d.resolve("dev-svc").unwrap();
        let snapshot = d.planning_snapshot("dev-svc", &resource, 1000);
        let intent = Intent {
            profile: "test".to_string(),
        };
        let planned = plan_from_snapshot(&resource, &snapshot, &intent, |_| None).unwrap();
        let reason_of = |id: &str| {
            planned
                .trace
                .considered
                .iter()
                .find(|c| c.provider.0 == id)
                .unwrap()
                .rejected_reason
                .as_ref()
                .map(|r| r.label())
        };
        assert_eq!(reason_of("down-dev-1"), Some("not_present"));
        assert_eq!(reason_of("nocap-dev-1"), Some("missing_capability"));
        assert_eq!(reason_of("local-dev-1"), None);
        // 本地优先保留。
        assert_eq!(planned.plan.provider_id.0, "local-dev-1");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn restricted_svc_resolves_for_deny_path() {
        // n2-grant-deny-audit 前置：restricted-svc 可解析（目录返回），
        // 但无 grant（`use` 必须走到授权拒绝，而非 NotFound）。
        let dir = temp_node_dir("restricted");
        let d = N2Directory::open(&dir, 1000).unwrap();
        let (_, id) = d.resolve("restricted-svc").unwrap();
        assert_eq!(id.0, "res-restricted-svc");
        assert_eq!(d.kind_of("restricted-svc"), Some(ResourceKind::Service));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn persisted_ads_overlay_static_seed() {
        use crate::n2_store::N2Store;
        let dir = temp_node_dir("overlay");
        let store = N2Store::open(&dir).unwrap();
        // 持久化一条新广告（模拟 resource publish）。
        store
            .save_ad(&ProviderAdvertisement {
                provider: ProviderId("pub-prov-1".into()),
                resource: ResourceId("res-pub-svc".into()),
                capabilities: vec!["service".into()],
                locators: vec!["tcp://10.9.9.9:8080".into()],
                discoverable_by: Discoverability::Public,
                use_grants: Vec::new(),
                unavailable: None,
                issued_at_secs: 1000,
                ttl_secs: 0,
            })
            .unwrap();
        store
            .save_names(&[NameEntry {
                workspace: WorkspaceId::new(DEFAULT_WORKSPACE),
                name: ResourceName::new("pub-svc").unwrap(),
                resource_id: ResourceId("res-pub-svc".into()),
                kind: Some(nexus_domain::ResourceKind::Service),
            }])
            .unwrap();
        let d = N2Directory::open_with_store(&store, 1000).unwrap();
        let (_, id) = d.resolve("pub-svc").unwrap();
        assert_eq!(id.0, "res-pub-svc");
        // 静态种子不受影响。
        assert!(d.resolve("dev-svc").is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
