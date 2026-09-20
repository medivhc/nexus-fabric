//! Mesh 网络内域名注册与解析（内存骨架）。
//!
//! 本模块是 delivery 层共享底座的域名解析骨架：
//! - **域名注册**：每个节点把 `域名 -> 虚拟 IP + node_id + TTL` 注册进本地表；
//! - **本地解析**：查询命中本地表即返回 `Resolved`，未命中返回 `NotFound`；
//! - **对等学习**：通过 `learn_peer_record` 接收对端同步来的记录（自动发现集成点）；
//! - **TTL 过期**：`expire(now)` 清扫过期记录，返回被移除的 domain 列表。
//!
//! 边界（PRODUCT §12-mesh-dns 冻结）：
//! - 纯内存、纯同步、纯函数骨架；不接真实 socket、不做 DNS-over-UDP 协议解析；
//! - 跨节点转发骨架期直接返回 `NotFound`，多跳转发 / 协议细节留 TODO；
//! - 不接加密、不接 TUN，只表达"域名 -> 虚拟 IP"的映射语义。
//!
//! TODO（真实网络传播，非本骨架范围）：
//! - 通过 MeshCarrier 把本地注册通告给直连邻居；
//! - 未命中本地表时按距离矢量向对端转发查询（`DnsResolution::Forwarded` 占位）；
//! - TTL 到期前周期性续租 / 再通告。
//!
//! 错误面独立：`MeshDnsError` 是本模块自有类型化 enum，不以 panic / 日志代替。

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Mesh DNS 相关结构化错误（delivery 层自有错误面，类型化）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MeshDnsError {
    /// 域名在表中不存在（或已被 TTL 清扫）。
    NotFound {
        /// 查询的域名。
        domain: String,
    },
    /// 域名非法（空字符串等）。
    InvalidDomain {
        /// 非法域名。
        domain: String,
    },
    /// 记录已过期（调用方在过期窗口内访问；正常路径由 `expire` 清扫后返回 `NotFound`）。
    Expired {
        /// 已过期的域名。
        domain: String,
    },
}

impl core::fmt::Display for MeshDnsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotFound { domain } => write!(f, "DNS_NOT_FOUND: no record for {domain}"),
            Self::InvalidDomain { domain } => write!(f, "DNS_INVALID_DOMAIN: {domain:?}"),
            Self::Expired { domain } => write!(f, "DNS_EXPIRED: record for {domain} expired"),
        }
    }
}

impl std::error::Error for MeshDnsError {}

// ---------- 注册记录 ----------

/// 一条 Mesh DNS 注册记录：域名 -> 虚拟 IP + node_id + TTL。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRecord {
    /// 域名（如 `node-a.mesh`）。
    pub domain: String,
    /// 节点在虚拟子网中的虚拟 IP（如 `10.0.0.1`）。
    pub virtual_ip: String,
    /// 节点稳定标识（如 `node-a`）。
    pub node_id: String,
    /// TTL（秒）；从 `registered_at` 起算。
    pub ttl_secs: u32,
    /// 过期时刻（`registered_at + ttl_secs`）；由构造函数计算，便于 `expire` 比较。
    pub expires_at: Instant,
}

impl DnsRecord {
    /// 构造一条记录；`expires_at = now + ttl_secs`。
    ///
    /// `domain` 为空时返回 `InvalidDomain`。
    pub fn new(
        domain: impl Into<String>,
        virtual_ip: impl Into<String>,
        node_id: impl Into<String>,
        ttl_secs: u32,
        now: Instant,
    ) -> Result<Self, MeshDnsError> {
        let domain = domain.into();
        if domain.is_empty() {
            return Err(MeshDnsError::InvalidDomain { domain });
        }
        let expires_at = now + Duration::from_secs(u64::from(ttl_secs));
        Ok(Self {
            domain,
            virtual_ip: virtual_ip.into(),
            node_id: node_id.into(),
            ttl_secs,
            expires_at,
        })
    }

    /// 在 `now` 时刻是否已过期（`now >= expires_at`）。
    #[must_use]
    pub fn is_expired(&self, now: Instant) -> bool {
        now >= self.expires_at
    }
}

// ---------- 本地表 ----------

/// 单节点本地域名表：`domain -> DnsRecord`。
#[derive(Debug, Clone, Default)]
pub struct MeshDnsTable {
    records: HashMap<String, DnsRecord>,
}

impl MeshDnsTable {
    /// 空表。
    #[must_use]
    pub fn new() -> Self {
        Self {
            records: HashMap::new(),
        }
    }

    /// 注册/覆盖一条记录（同 domain 重复注册允许覆盖 virtual_ip/node_id/ttl）。
    ///
    /// `record.domain` 为空时返回 `InvalidDomain`。
    pub fn register(&mut self, record: DnsRecord) -> Result<(), MeshDnsError> {
        if record.domain.is_empty() {
            return Err(MeshDnsError::InvalidDomain {
                domain: record.domain.clone(),
            });
        }
        self.records.insert(record.domain.clone(), record);
        Ok(())
    }

    /// 查表；不存在返回 `NotFound`。
    ///
    /// 注意：本方法不主动判断 TTL；过期记录由 `expire` 清扫后再查即 `NotFound`。
    pub fn lookup(&self, domain: &str) -> Result<&DnsRecord, MeshDnsError> {
        self.records
            .get(domain)
            .ok_or_else(|| MeshDnsError::NotFound {
                domain: domain.to_string(),
            })
    }

    /// 清扫 `now` 时刻已过期的记录，返回被移除的 domain 列表。
    pub fn expire(&mut self, now: Instant) -> Vec<String> {
        let expired: Vec<String> = self
            .records
            .iter()
            .filter_map(|(domain, rec)| rec.is_expired(now).then_some(domain.clone()))
            .collect();
        for d in &expired {
            self.records.remove(d);
        }
        expired
    }

    /// 返回所有现存记录的快照（供 flow 断言 / 对等同步）。
    #[must_use]
    pub fn snapshot(&self) -> Vec<DnsRecord> {
        self.records.values().cloned().collect()
    }
}

// ---------- 查询与响应 ----------

/// 一条 DNS 查询（从某个节点发起）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuery {
    /// 查询标识（响应原样带回）。
    pub query_id: u64,
    /// 目标域名。
    pub domain: String,
    /// 发起查询的节点。
    pub from_node: String,
}

/// 解析结果（命中 / 未命中 / 转发）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsResolution {
    /// 命中：返回虚拟 IP、node_id 与剩余 TTL。
    Resolved {
        /// 目标虚拟 IP。
        virtual_ip: String,
        /// 目标节点。
        node_id: String,
        /// 记录 TTL（秒）。
        ttl_secs: u32,
    },
    /// 未命中（NXDOMAIN 语义）。
    NotFound,
    /// TODO（骨架期不产生）：本地未命中，经 `via_node` 转发。
    Forwarded {
        /// 转发到的对端节点。
        via_node: String,
    },
}

/// 一条 DNS 响应（query_id 与查询对齐）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsResponse {
    /// 与查询一致的标识。
    pub query_id: u64,
    /// 被查询的域名。
    pub domain: String,
    /// 解析结果。
    pub result: DnsResolution,
}

// ---------- 单节点视角 ----------

/// 单节点 Mesh DNS 视图：持有自己的 node_id / virtual_ip 与本地表。
#[derive(Debug, Clone)]
pub struct MeshDnsNode {
    /// 本节点稳定标识。
    node_id: String,
    /// 本节点虚拟 IP。
    virtual_ip: String,
    /// 本地表（自身注册 + 从对端学习）。
    table: MeshDnsTable,
}

impl MeshDnsNode {
    /// 以 `node_id` 与 `virtual_ip` 构造一个空表节点。
    #[must_use]
    pub fn new(node_id: impl Into<String>, virtual_ip: impl Into<String>) -> Self {
        Self {
            node_id: node_id.into(),
            virtual_ip: virtual_ip.into(),
            table: MeshDnsTable::new(),
        }
    }

    /// 本节点稳定标识。
    #[must_use]
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    /// 本节点虚拟 IP。
    #[must_use]
    pub fn virtual_ip(&self) -> &str {
        &self.virtual_ip
    }

    /// 把自己的域名注册进本地表（`now = Instant::now()`，TTL = `ttl_secs`）。
    pub fn register_self_domain(
        &mut self,
        domain: impl Into<String>,
        ttl_secs: u32,
    ) -> Result<(), MeshDnsError> {
        let record = DnsRecord::new(
            domain,
            self.virtual_ip.clone(),
            self.node_id.clone(),
            ttl_secs,
            Instant::now(),
        )?;
        self.table.register(record)
    }

    /// 处理一条查询：本地查表，命中返回 `Resolved`，未命中返回 `NotFound`。
    ///
    /// 跨节点转发骨架期直接返回 `NotFound`（TODO：按距离矢量向对端转发）。
    pub fn handle_query(&mut self, query: &DnsQuery, now: Instant) -> DnsResponse {
        // 先清扫过期记录，避免命中已过期条目。
        self.table.expire(now);
        let result = match self.table.lookup(&query.domain) {
            Ok(rec) => {
                if rec.is_expired(now) {
                    DnsResolution::NotFound
                } else {
                    DnsResolution::Resolved {
                        virtual_ip: rec.virtual_ip.clone(),
                        node_id: rec.node_id.clone(),
                        ttl_secs: rec.ttl_secs,
                    }
                }
            }
            Err(_) => DnsResolution::NotFound,
        };
        DnsResponse {
            query_id: query.query_id,
            domain: query.domain.clone(),
            result,
        }
    }

    /// 从对端学习一条记录写入本地表（自动发现集成点；同 domain 覆盖）。
    pub fn learn_peer_record(&mut self, record: DnsRecord) -> Result<(), MeshDnsError> {
        self.table.register(record)
    }

    /// 本地表快照（供 flow 断言 / 对等同步）。
    #[must_use]
    pub fn table_snapshot(&self) -> Vec<DnsRecord> {
        self.table.snapshot()
    }

    /// 清扫 `now` 时刻已过期记录，返回被移除的 domain 列表。
    pub fn expire_peers(&mut self, now: Instant) -> Vec<String> {
        self.table.expire(now)
    }

    /// 查表（不主动清扫；调用方一般先 `expire_peers`）。
    pub fn lookup(&self, domain: &str) -> Result<&DnsRecord, MeshDnsError> {
        self.table.lookup(domain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn query(id: u64, domain: &str, from: &str) -> DnsQuery {
        DnsQuery {
            query_id: id,
            domain: domain.to_string(),
            from_node: from.to_string(),
        }
    }

    #[test]
    fn register_then_lookup_hits() {
        let now = Instant::now();
        let rec = DnsRecord::new("a.mesh", "10.0.0.1", "node-a", 3600, now).expect("valid record");
        let mut table = MeshDnsTable::new();
        table.register(rec).expect("register ok");
        let got = table.lookup("a.mesh").expect("lookup hit");
        assert_eq!(got.virtual_ip, "10.0.0.1");
        assert_eq!(got.node_id, "node-a");
    }

    #[test]
    fn lookup_miss_is_not_found() {
        let table = MeshDnsTable::new();
        let err = table.lookup("nobody.mesh").expect_err("must miss");
        assert!(matches!(err, MeshDnsError::NotFound { .. }));
    }

    #[test]
    fn re_register_overwrites_record() {
        let now = Instant::now();
        let rec1 = DnsRecord::new("a.mesh", "10.0.0.1", "node-a", 3600, now).unwrap();
        let rec2 = DnsRecord::new("a.mesh", "10.0.0.9", "node-a-v2", 7200, now).unwrap();
        let mut table = MeshDnsTable::new();
        table.register(rec1).unwrap();
        table.register(rec2).unwrap();
        let got = table.lookup("a.mesh").unwrap();
        assert_eq!(got.virtual_ip, "10.0.0.9");
        assert_eq!(got.node_id, "node-a-v2");
        assert_eq!(got.ttl_secs, 7200);
    }

    #[test]
    fn expire_removes_only_expired_records() {
        let now = Instant::now();
        let fresh = DnsRecord::new("fresh.mesh", "10.0.0.1", "node-a", 3600, now).unwrap();
        let stale = DnsRecord::new(
            "stale.mesh",
            "10.0.0.2",
            "node-b",
            1,
            now - Duration::from_secs(10),
        )
        .unwrap();
        let mut table = MeshDnsTable::new();
        table.register(fresh).unwrap();
        table.register(stale).unwrap();
        let removed = table.expire(now);
        assert_eq!(removed, vec!["stale.mesh".to_string()]);
        assert!(table.lookup("fresh.mesh").is_ok());
        assert!(matches!(
            table.lookup("stale.mesh"),
            Err(MeshDnsError::NotFound { .. })
        ));
    }

    #[test]
    fn node_learn_peer_and_handle_query_resolves() {
        let mut a = MeshDnsNode::new("node-a", "10.0.0.1");
        a.register_self_domain("node-a.mesh", 3600).unwrap();

        let mut b = MeshDnsNode::new("node-b", "10.0.0.2");
        b.register_self_domain("node-b.mesh", 3600).unwrap();
        for rec in a.table_snapshot() {
            if rec.node_id == "node-a" {
                b.learn_peer_record(rec).unwrap();
            }
        }

        let resp = b.handle_query(&query(1, "node-a.mesh", "node-b"), Instant::now());
        match resp.result {
            DnsResolution::Resolved {
                virtual_ip,
                node_id,
                ..
            } => {
                assert_eq!(virtual_ip, "10.0.0.1");
                assert_eq!(node_id, "node-a");
            }
            other => panic!("expected Resolved, got {other:?}"),
        }

        let unknown = b.handle_query(&query(2, "nobody.mesh", "node-b"), Instant::now());
        assert!(matches!(unknown.result, DnsResolution::NotFound));
    }

    #[test]
    fn empty_domain_is_invalid() {
        let err = DnsRecord::new("", "10.0.0.1", "node-a", 1, Instant::now())
            .expect_err("empty domain invalid");
        assert!(matches!(err, MeshDnsError::InvalidDomain { .. }));
    }
}
