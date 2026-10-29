//! Mesh 节点分组标签（内存骨架）。
//!
//! 本模块是 v9 CLI 产品线运行时（frozen）的节点标签匹配骨架：
//! - **标签**：每个节点可打多个 `NodeTag`（key=value 对，如 `region:us`、`role:db`）；
//! - **节点信息**：`NodeInfo` 聚合 node_id + virtual_ip + tags；
//! - **过滤**：`TagFilter` 描述单个过滤条件（精确匹配或存在性匹配）；
//! - **匹配器**：`TagMatcher` 持有多个 `TagFilter`，按 AND 语义匹配节点；
//! - **过滤节点列表**：`filter_nodes` 按 matcher 从节点列表中筛出命中子集。
//!
//! 边界（PRODUCT §12-node-tags 冻结）：
//! - 纯内存、纯同步、纯函数骨架；不接真实网络传输；
//! - 标签字符串格式：`key=value`（`=` 分隔 key 与 value）；
//! - 存在性匹配：只指定 key、不指定 value 时，只要节点有该 key 即命中；
//! - 真实节点发现同步、持久化、CRDT 合并留 TODO。
//!
//! TODO（真实网络集成，非本骨架范围）：
//! - 在自动节点发现（`nexus-discovery::auto_discovery`）注册/心跳时携带 tags；
//! - 在多跳路由（`routing`）中按标签选择下一跳；
//! - 在 Mesh DNS（`mesh_dns`）中按标签查询域名；
//! - 在防火墙规则（`firewall`）中按标签过滤流量。
//!
//! 错误面独立：`NodeTagError` 是本模块自有类型化 enum，不以 panic / 日志代替。

use std::fmt;

// ---------- 错误 ----------

/// 节点标签相关结构化错误（delivery 层自有错误面，类型化）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeTagError {
    /// 标签字符串无法解析（如缺少 `=` 分隔符、key 或 value 为空）。
    InvalidTag {
        /// 非法标签字符串（人可读）。
        raw: String,
    },
    /// 过滤条件 key 为空。
    EmptyKey,
}

impl fmt::Display for NodeTagError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTag { raw } => write!(f, "NODE_TAG_INVALID: cannot parse {raw:?}"),
            Self::EmptyKey => write!(f, "NODE_TAG_EMPTY_KEY: tag key must not be empty"),
        }
    }
}

impl std::error::Error for NodeTagError {}

// ---------- 标签 ----------

/// 单个节点标签（key=value 对）。
///
/// 示例：`NodeTag { key: "region".into(), value: "us".into() }`
/// 表示节点位于 us 区域。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NodeTag {
    /// 标签键（如 `region`、`role`、`tier`）。
    pub key: String,
    /// 标签值（如 `us`、`db`、`edge`）。
    pub value: String,
}

impl NodeTag {
    /// 构造一个标签；key 或 value 为空返回 `EmptyKey` / `InvalidTag`。
    pub fn new(key: impl Into<String>, value: impl Into<String>) -> Result<Self, NodeTagError> {
        let key = key.into();
        let value = value.into();
        if key.is_empty() {
            return Err(NodeTagError::EmptyKey);
        }
        Ok(Self { key, value })
    }

    /// 从 `key=value` 格式字符串解析标签。
    ///
    /// 规则：
    /// 1. 必须包含 `=` 分隔符；
    /// 2. key 与 value 均不能为空；
    /// 3. 按第一个 `=` 分割（value 中可包含 `=`）。
    pub fn parse(raw: &str) -> Result<Self, NodeTagError> {
        let (key, value) = raw
            .split_once('=')
            .ok_or_else(|| NodeTagError::InvalidTag {
                raw: raw.to_string(),
            })?;
        if key.is_empty() {
            return Err(NodeTagError::InvalidTag {
                raw: raw.to_string(),
            });
        }
        if value.is_empty() {
            return Err(NodeTagError::InvalidTag {
                raw: raw.to_string(),
            });
        }
        Ok(Self {
            key: key.to_string(),
            value: value.to_string(),
        })
    }

    /// 判断此标签是否与另一个标签精确匹配（key 和 value 都相同）。
    #[must_use]
    pub fn matches(&self, other: &NodeTag) -> bool {
        self.key == other.key && self.value == other.value
    }

    /// 返回 `key=value` 格式的字符串表示。
    #[must_use]
    pub fn as_str(&self) -> String {
        format!("{}={}", self.key, self.value)
    }
}

impl fmt::Display for NodeTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}={}", self.key, self.value)
    }
}

// ---------- 节点信息 ----------

/// 已打标签的节点信息。
///
/// 聚合节点标识、虚拟 IP 与标签列表，供过滤/路由/查询使用。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeInfo {
    /// 节点唯一标识。
    pub node_id: String,
    /// 虚拟 IP（如 `10.0.0.1`）。
    pub virtual_ip: String,
    /// 该节点的标签列表。
    pub tags: Vec<NodeTag>,
}

impl NodeInfo {
    /// 构造节点信息；tags 为空 Vec 表示无标签节点。
    #[must_use]
    pub fn new(
        node_id: impl Into<String>,
        virtual_ip: impl Into<String>,
        tags: Vec<NodeTag>,
    ) -> Self {
        Self {
            node_id: node_id.into(),
            virtual_ip: virtual_ip.into(),
            tags,
        }
    }

    /// 判断节点是否拥有指定 key 的标签（存在性匹配，不限 value）。
    #[must_use]
    pub fn has_tag_key(&self, key: &str) -> bool {
        self.tags.iter().any(|t| t.key == key)
    }

    /// 判断节点是否拥有指定 key=value 的标签（精确匹配）。
    #[must_use]
    pub fn has_tag(&self, key: &str, value: &str) -> bool {
        self.tags.iter().any(|t| t.key == key && t.value == value)
    }

    /// 获取指定 key 的标签值（若存在）。
    #[must_use]
    pub fn tag_value(&self, key: &str) -> Option<&str> {
        self.tags
            .iter()
            .find(|t| t.key == key)
            .map(|t| t.value.as_str())
    }
}

// ---------- 过滤条件 ----------

/// 单个标签过滤条件。
///
/// - `value = Some(v)`：精确匹配（节点必须有 key=v 的标签）；
/// - `value = None`：存在性匹配（节点只要有 key 即命中，不限值）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TagFilter {
    /// 过滤的标签键。
    pub key: String,
    /// 期望的标签值；`None` 表示存在性匹配。
    pub value: Option<String>,
}

impl TagFilter {
    /// 构造精确匹配过滤器（key=value）。
    pub fn exact(key: impl Into<String>, value: impl Into<String>) -> Result<Self, NodeTagError> {
        let key = key.into();
        let value = value.into();
        if key.is_empty() {
            return Err(NodeTagError::EmptyKey);
        }
        Ok(Self {
            key,
            value: Some(value),
        })
    }

    /// 构造存在性匹配过滤器（只要 key 存在即命中）。
    pub fn exists(key: impl Into<String>) -> Result<Self, NodeTagError> {
        let key = key.into();
        if key.is_empty() {
            return Err(NodeTagError::EmptyKey);
        }
        Ok(Self { key, value: None })
    }

    /// 从 `key=value` 格式字符串解析精确匹配过滤器。
    ///
    /// 与 `NodeTag::parse` 一致，但返回 `TagFilter` 类型。
    pub fn parse(raw: &str) -> Result<Self, NodeTagError> {
        let tag = NodeTag::parse(raw)?;
        Ok(Self {
            key: tag.key,
            value: Some(tag.value),
        })
    }

    /// 判断单个节点是否满足此过滤条件。
    #[must_use]
    pub fn matches(&self, node: &NodeInfo) -> bool {
        match &self.value {
            Some(v) => node.has_tag(&self.key, v),
            None => node.has_tag_key(&self.key),
        }
    }
}

// ---------- 匹配器（AND 语义） ----------

/// 标签匹配器：持有多个 `TagFilter`，按 AND 语义匹配节点。
///
/// 节点必须满足所有过滤器才视为命中。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TagMatcher {
    /// 所有必须同时满足的过滤条件。
    pub all: Vec<TagFilter>,
}

impl TagMatcher {
    /// 构造空匹配器（无过滤条件，匹配所有节点）。
    #[must_use]
    pub fn empty() -> Self {
        Self { all: Vec::new() }
    }

    /// 构造匹配器；按给定过滤器列表。
    #[must_use]
    pub fn new(filters: Vec<TagFilter>) -> Self {
        Self { all: filters }
    }

    /// 判断节点是否满足所有过滤条件（AND 语义）。
    ///
    /// 空匹配器匹配所有节点（返回 `true`）。
    #[must_use]
    pub fn matches(&self, node: &NodeInfo) -> bool {
        self.all.iter().all(|f| f.matches(node))
    }

    /// 过滤节点列表，返回所有命中节点的子集。
    #[must_use]
    pub fn filter_nodes(&self, nodes: &[NodeInfo]) -> Vec<NodeInfo> {
        nodes.iter().filter(|n| self.matches(n)).cloned().collect()
    }

    /// 匹配器中的过滤条件数量。
    #[must_use]
    pub fn filter_count(&self) -> usize {
        self.all.len()
    }
}

// ---------- 便捷函数 ----------

/// 从 `key=value` 字符串列表批量解析为 `TagFilter` 列表。
///
/// 任一解析失败即返回第一个错误。
pub fn parse_filters(raw: &[&str]) -> Result<Vec<TagFilter>, NodeTagError> {
    raw.iter().map(|s| TagFilter::parse(s)).collect()
}

/// 从 `key=value` 字符串列表批量解析为 `NodeTag` 列表。
///
/// 任一解析失败即返回第一个错误。
pub fn parse_tags(raw: &[&str]) -> Result<Vec<NodeTag>, NodeTagError> {
    raw.iter().map(|s| NodeTag::parse(s)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_node(id: &str, ip: &str, tags: &[&str]) -> NodeInfo {
        let tags = parse_tags(tags).expect("valid tags");
        NodeInfo::new(id, ip, tags)
    }

    #[test]
    fn parse_tag_exact_format() {
        let tag = NodeTag::parse("region=us").expect("valid tag");
        assert_eq!(tag.key, "region");
        assert_eq!(tag.value, "us");
    }

    #[test]
    fn parse_tag_rejects_missing_equals() {
        let err = NodeTag::parse("region-us").expect_err("must fail");
        assert!(matches!(err, NodeTagError::InvalidTag { .. }));
    }

    #[test]
    fn parse_tag_rejects_empty_key() {
        let err = NodeTag::parse("=us").expect_err("must fail");
        assert!(matches!(err, NodeTagError::InvalidTag { .. }));
    }

    #[test]
    fn parse_tag_rejects_empty_value() {
        let err = NodeTag::parse("region=").expect_err("must fail");
        assert!(matches!(err, NodeTagError::InvalidTag { .. }));
    }

    #[test]
    fn parse_tag_allows_equals_in_value() {
        let tag = NodeTag::parse("path=a=b=c").expect("equals in value is fine");
        assert_eq!(tag.key, "path");
        assert_eq!(tag.value, "a=b=c");
    }

    #[test]
    fn tag_matches_exact_key_and_value() {
        let a = NodeTag::new("region", "us").unwrap();
        let b = NodeTag::new("region", "us").unwrap();
        let c = NodeTag::new("region", "eu").unwrap();
        assert!(a.matches(&b));
        assert!(!a.matches(&c));
    }

    #[test]
    fn node_has_tag_key_existence() {
        let node = make_node("n1", "10.0.0.1", &["region=us", "role=edge"]);
        assert!(node.has_tag_key("region"));
        assert!(node.has_tag_key("role"));
        assert!(!node.has_tag_key("tier"));
    }

    #[test]
    fn node_has_tag_exact() {
        let node = make_node("n1", "10.0.0.1", &["region=us", "role=edge"]);
        assert!(node.has_tag("region", "us"));
        assert!(!node.has_tag("region", "eu"));
        assert!(node.has_tag("role", "edge"));
    }

    #[test]
    fn node_tag_value_lookup() {
        let node = make_node("n1", "10.0.0.1", &["region=us", "role=edge"]);
        assert_eq!(node.tag_value("region"), Some("us"));
        assert_eq!(node.tag_value("role"), Some("edge"));
        assert_eq!(node.tag_value("tier"), None);
    }

    #[test]
    fn filter_exact_matches_node() {
        let node = make_node("n1", "10.0.0.1", &["region=us"]);
        let f = TagFilter::exact("region", "us").unwrap();
        assert!(f.matches(&node));

        let f_wrong = TagFilter::exact("region", "eu").unwrap();
        assert!(!f_wrong.matches(&node));
    }

    #[test]
    fn filter_exists_matches_key_regardless_of_value() {
        let node = make_node("n1", "10.0.0.1", &["region=us"]);
        let f = TagFilter::exists("region").unwrap();
        assert!(f.matches(&node));

        let f_missing = TagFilter::exists("tier").unwrap();
        assert!(!f_missing.matches(&node));
    }

    #[test]
    fn matcher_and_semantics_requires_all() {
        let node = make_node("n1", "10.0.0.1", &["region=us", "role=db"]);
        let filters = parse_filters(&["region=us", "role=db"]).unwrap();
        let matcher = TagMatcher::new(filters);
        assert!(matcher.matches(&node));

        let filters_wrong = parse_filters(&["region=us", "role=edge"]).unwrap();
        let matcher_wrong = TagMatcher::new(filters_wrong);
        assert!(!matcher_wrong.matches(&node));
    }

    #[test]
    fn empty_matcher_matches_all() {
        let node = make_node("n1", "10.0.0.1", &[]);
        let matcher = TagMatcher::empty();
        assert!(matcher.matches(&node));
        assert_eq!(matcher.filter_count(), 0);
    }

    #[test]
    fn filter_nodes_returns_matching_subset() {
        let nodes = vec![
            make_node("us-edge", "10.0.0.1", &["region=us", "role=edge"]),
            make_node("eu-edge", "10.0.0.2", &["region=eu", "role=edge"]),
            make_node("us-db", "10.0.0.3", &["region=us", "role=db"]),
        ];
        let matcher = TagMatcher::new(parse_filters(&["region=us"]).unwrap());
        let result = matcher.filter_nodes(&nodes);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].node_id, "us-edge");
        assert_eq!(result[1].node_id, "us-db");
    }

    #[test]
    fn parse_filters_batch() {
        let filters = parse_filters(&["region=us", "role=db"]).unwrap();
        assert_eq!(filters.len(), 2);
        assert_eq!(filters[0].key, "region");
        assert_eq!(filters[0].value, Some("us".to_string()));
        assert_eq!(filters[1].key, "role");
        assert_eq!(filters[1].value, Some("db".to_string()));
    }

    #[test]
    fn tag_display_and_as_str_roundtrip() {
        let tag = NodeTag::new("region", "us").unwrap();
        assert_eq!(tag.as_str(), "region=us");
        assert_eq!(tag.to_string(), "region=us");
        let reparsed = NodeTag::parse(&tag.as_str()).unwrap();
        assert_eq!(tag, reparsed);
    }
}
