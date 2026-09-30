//! LSA（链路状态通告）协议：Hello/Welcome 入网 + LSA 泛洪 + LSDB（P5 §12.44）。
//!
//! Portable Core：零 I/O、零第三方依赖。帧编解码确定性、可移植。
//! 泛洪的"发送"由装配层执行，本模块只提供纯决策逻辑（`SeenCache::should_flood`）
//! 与状态机（`Lsdb::update`）。
//!
//! 帧格式：`[version: u8=1][tag: u8][fields...]`；字符串 = `u16 BE` 长度前缀 +
//! UTF-8；整数 = BE；`Option<String>` = `u8` 存在位 + 字符串。

use std::collections::{HashMap, VecDeque};

use crate::{DiscoveryError, PeerId, get_str, put_str};

/// LSA 协议版本（本期 v1）。
pub const LSA_VERSION: u8 = 1;

/// 帧类型标签。
const TAG_HELLO: u8 = 1;
const TAG_WELCOME: u8 = 2;
const TAG_LSA_ADVERT: u8 = 3;

/// 链路度量（§12.44；本期发现只用占位，选路 feature 用 latency/bandwidth）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkMetrics {
    /// 延迟（毫秒）。
    pub latency_ms: u32,
    /// 丢包率（万分比，如 50 = 0.5%）。
    pub loss_pct: u16,
    /// 带宽（kbps）。
    pub bandwidth_kbps: u64,
}

/// 链路通告：邻居 + 度量（本期 `neighbors` 为空，字段保留供选路用）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkAdvert {
    /// 邻居节点 ID。
    pub neighbor: PeerId,
    /// 链路度量。
    pub metrics: LinkMetrics,
}

/// 链路状态通告（本期只负责发现；`neighbors` 为空）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lsa {
    /// 节点 ID。
    pub node_id: PeerId,
    /// 虚拟 IP（如 "10.99.0.5"）。
    pub vip: String,
    /// 世代（节点重启 +1；本期内存，持久化为后续 feature）。
    pub incarnation: u64,
    /// 序列号（单调递增）。
    pub seq: u64,
    /// 能力位图（RELAY=0x01, EXIT_NODE=0x02, TUN=0x04, …）。
    pub capabilities: u32,
    /// 可达 locator（如 "udp://host:port"，打洞用）；未知 → None。
    pub locator: Option<String>,
    /// 邻居链路（本期空）。
    pub neighbors: Vec<LinkAdvert>,
}

/// LSA 协议帧。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LsaFrame {
    /// 新节点 → bootstrap：`{ node_id, vip, capabilities, incarnation }`。
    Hello {
        node_id: PeerId,
        vip: String,
        capabilities: u32,
        incarnation: u64,
    },
    /// bootstrap → 新节点：全量 LSA 快照（仅入网时一次）。
    Welcome { lsas: Vec<Lsa> },
    /// 邻居间泛洪：单个 LSA。
    LsaAdvert { lsa: Lsa },
}

/// LSDB 更新结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateOutcome {
    /// 新节点。
    New,
    /// 已有节点，`(incarnation, seq)` 更新。
    Updated,
    /// 旧版本，拒绝。
    Stale,
    /// 本端 LSA，永不被覆盖。
    SelfIgnored,
}

/// 写入 `Option<String>`（u8 存在位 + 字符串）。
fn put_opt_str(out: &mut Vec<u8>, s: &Option<String>) -> Result<(), DiscoveryError> {
    match s {
        Some(v) => {
            out.push(1);
            put_str(out, v)?;
        }
        None => out.push(0),
    }
    Ok(())
}

/// 读取 `Option<String>`。
fn get_opt_str(buf: &[u8], pos: &mut usize) -> Result<Option<String>, DiscoveryError> {
    if *pos >= buf.len() {
        return Err(DiscoveryError::Transport("frame truncated".into()));
    }
    let present = buf[*pos];
    *pos += 1;
    match present {
        0 => Ok(None),
        1 => Ok(Some(get_str(buf, pos)?)),
        _ => Err(DiscoveryError::Transport("invalid option tag".into())),
    }
}

/// 读取 u64 BE。
fn get_u64(buf: &[u8], pos: &mut usize) -> Result<u64, DiscoveryError> {
    if *pos + 8 > buf.len() {
        return Err(DiscoveryError::Transport("frame truncated".into()));
    }
    let v = u64::from_be_bytes(buf[*pos..*pos + 8].try_into().unwrap());
    *pos += 8;
    Ok(v)
}

/// 读取 u32 BE。
fn get_u32(buf: &[u8], pos: &mut usize) -> Result<u32, DiscoveryError> {
    if *pos + 4 > buf.len() {
        return Err(DiscoveryError::Transport("frame truncated".into()));
    }
    let v = u32::from_be_bytes(buf[*pos..*pos + 4].try_into().unwrap());
    *pos += 4;
    Ok(v)
}

/// 读取 u16 BE。
fn get_u16(buf: &[u8], pos: &mut usize) -> Result<u16, DiscoveryError> {
    if *pos + 2 > buf.len() {
        return Err(DiscoveryError::Transport("frame truncated".into()));
    }
    let v = u16::from_be_bytes(buf[*pos..*pos + 2].try_into().unwrap());
    *pos += 2;
    Ok(v)
}

/// 确保帧已消费完毕（无尾随字节）。
fn expect_end(buf: &[u8], pos: usize) -> Result<(), DiscoveryError> {
    if pos != buf.len() {
        return Err(DiscoveryError::Transport("trailing bytes".into()));
    }
    Ok(())
}

/// 编码单个 LSA（不含外层 version/tag）。
fn put_lsa(out: &mut Vec<u8>, lsa: &Lsa) -> Result<(), DiscoveryError> {
    put_str(out, &lsa.node_id.0)?;
    put_str(out, &lsa.vip)?;
    out.extend_from_slice(&lsa.incarnation.to_be_bytes());
    out.extend_from_slice(&lsa.seq.to_be_bytes());
    out.extend_from_slice(&lsa.capabilities.to_be_bytes());
    put_opt_str(out, &lsa.locator)?;
    let n = u16::try_from(lsa.neighbors.len())
        .map_err(|_| DiscoveryError::Transport("too many neighbors".into()))?;
    out.extend_from_slice(&n.to_be_bytes());
    for nb in &lsa.neighbors {
        put_str(out, &nb.neighbor.0)?;
        out.extend_from_slice(&nb.metrics.latency_ms.to_be_bytes());
        out.extend_from_slice(&nb.metrics.loss_pct.to_be_bytes());
        out.extend_from_slice(&nb.metrics.bandwidth_kbps.to_be_bytes());
    }
    Ok(())
}

/// 解码单个 LSA。
fn get_lsa(buf: &[u8], pos: &mut usize) -> Result<Lsa, DiscoveryError> {
    let node_id = PeerId(get_str(buf, pos)?);
    let vip = get_str(buf, pos)?;
    let incarnation = get_u64(buf, pos)?;
    let seq = get_u64(buf, pos)?;
    let capabilities = get_u32(buf, pos)?;
    let locator = get_opt_str(buf, pos)?;
    let n = get_u16(buf, pos)? as usize;
    let mut neighbors = Vec::with_capacity(n.min(64));
    for _ in 0..n {
        let neighbor = PeerId(get_str(buf, pos)?);
        let latency_ms = get_u32(buf, pos)?;
        let loss_pct = get_u16(buf, pos)?;
        let bandwidth_kbps = get_u64(buf, pos)?;
        neighbors.push(LinkAdvert {
            neighbor,
            metrics: LinkMetrics {
                latency_ms,
                loss_pct,
                bandwidth_kbps,
            },
        });
    }
    Ok(Lsa {
        node_id,
        vip,
        incarnation,
        seq,
        capabilities,
        locator,
        neighbors,
    })
}

/// 编码 LSA 协议帧：`[version][tag][fields...]`。
pub fn encode_lsa_frame(frame: &LsaFrame) -> Result<Vec<u8>, DiscoveryError> {
    let mut out = Vec::new();
    out.push(LSA_VERSION);
    match frame {
        LsaFrame::Hello {
            node_id,
            vip,
            capabilities,
            incarnation,
        } => {
            out.push(TAG_HELLO);
            put_str(&mut out, &node_id.0)?;
            put_str(&mut out, vip)?;
            out.extend_from_slice(&capabilities.to_be_bytes());
            out.extend_from_slice(&incarnation.to_be_bytes());
        }
        LsaFrame::Welcome { lsas } => {
            out.push(TAG_WELCOME);
            let n = u16::try_from(lsas.len())
                .map_err(|_| DiscoveryError::Transport("too many lsas".into()))?;
            out.extend_from_slice(&n.to_be_bytes());
            for lsa in lsas {
                put_lsa(&mut out, lsa)?;
            }
        }
        LsaFrame::LsaAdvert { lsa } => {
            out.push(TAG_LSA_ADVERT);
            put_lsa(&mut out, lsa)?;
        }
    }
    Ok(out)
}

/// 解码 LSA 协议帧；版本不匹配 / 未知 tag / 截断 → `DiscoveryError::Transport`。
pub fn decode_lsa_frame(buf: &[u8]) -> Result<LsaFrame, DiscoveryError> {
    if buf.len() < 2 {
        return Err(DiscoveryError::Transport("frame too short".into()));
    }
    if buf[0] != LSA_VERSION {
        return Err(DiscoveryError::Transport(format!(
            "unsupported lsa version {}",
            buf[0]
        )));
    }
    let mut pos = 2;
    match buf[1] {
        TAG_HELLO => {
            let node_id = PeerId(get_str(buf, &mut pos)?);
            let vip = get_str(buf, &mut pos)?;
            let capabilities = get_u32(buf, &mut pos)?;
            let incarnation = get_u64(buf, &mut pos)?;
            expect_end(buf, pos)?;
            Ok(LsaFrame::Hello {
                node_id,
                vip,
                capabilities,
                incarnation,
            })
        }
        TAG_WELCOME => {
            let n = get_u16(buf, &mut pos)? as usize;
            let mut lsas = Vec::with_capacity(n.min(256));
            for _ in 0..n {
                lsas.push(get_lsa(buf, &mut pos)?);
            }
            expect_end(buf, pos)?;
            Ok(LsaFrame::Welcome { lsas })
        }
        TAG_LSA_ADVERT => {
            let lsa = get_lsa(buf, &mut pos)?;
            expect_end(buf, pos)?;
            Ok(LsaFrame::LsaAdvert { lsa })
        }
        other => Err(DiscoveryError::Transport(format!(
            "unknown lsa tag {other}"
        ))),
    }
}

/// 链路状态数据库（本端视角的全网拓扑）。
#[derive(Debug, Clone)]
pub struct Lsdb {
    self_id: PeerId,
    nodes: HashMap<String, Lsa>,
}

impl Lsdb {
    /// 创建空 LSDB（`self_id` 为本端节点 ID，本端 LSA 永不被覆盖）。
    #[must_use]
    pub fn new(self_id: PeerId) -> Self {
        Self {
            self_id,
            nodes: HashMap::new(),
        }
    }

    /// 本端节点 ID。
    #[must_use]
    pub fn self_id(&self) -> &PeerId {
        &self.self_id
    }

    /// 更新 LSA：以 `(incarnation, seq)` 比新旧。
    ///
    /// - `lsa.node_id == self_id` → `SelfIgnored`（本端 LSA 永不被远端覆盖；
    ///   本端发布用 [`Lsdb::update_local`]）。
    /// - 新节点 → `New`；`(incarnation, seq)` 更新 → `Updated`；否则 → `Stale`。
    pub fn update(&mut self, lsa: Lsa) -> UpdateOutcome {
        if lsa.node_id.0 == self.self_id.0 {
            return UpdateOutcome::SelfIgnored;
        }
        match self.nodes.get(&lsa.node_id.0) {
            Some(cur) => {
                if (lsa.incarnation, lsa.seq) > (cur.incarnation, cur.seq) {
                    self.nodes.insert(lsa.node_id.0.clone(), lsa);
                    UpdateOutcome::Updated
                } else {
                    UpdateOutcome::Stale
                }
            }
            None => {
                self.nodes.insert(lsa.node_id.0.clone(), lsa);
                UpdateOutcome::New
            }
        }
    }

    /// 本端发布自己的 LSA（seq/incarnation 必须前进，否则 `Stale`）。
    ///
    /// # Panics
    ///
    /// `lsa.node_id != self_id` 时 panic（编程错误，非业务失败）。
    pub fn update_local(&mut self, lsa: Lsa) -> UpdateOutcome {
        assert_eq!(
            lsa.node_id.0, self.self_id.0,
            "update_local called with foreign node_id"
        );
        match self.nodes.get(&lsa.node_id.0) {
            Some(cur) => {
                if (lsa.incarnation, lsa.seq) > (cur.incarnation, cur.seq) {
                    self.nodes.insert(lsa.node_id.0.clone(), lsa);
                    UpdateOutcome::Updated
                } else {
                    UpdateOutcome::Stale
                }
            }
            None => {
                self.nodes.insert(lsa.node_id.0.clone(), lsa);
                UpdateOutcome::New
            }
        }
    }

    /// 查询节点 LSA。
    #[must_use]
    pub fn get(&self, node_id: &PeerId) -> Option<&Lsa> {
        self.nodes.get(&node_id.0)
    }

    /// 是否包含节点。
    #[must_use]
    pub fn contains(&self, node_id: &PeerId) -> bool {
        self.nodes.contains_key(&node_id.0)
    }

    /// 全部 LSA（快照，供 Welcome 用）。
    #[must_use]
    pub fn all(&self) -> Vec<&Lsa> {
        self.nodes.values().collect()
    }

    /// 节点数。
    #[must_use]
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// 是否为空。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
}

/// 泛洪去重缓存（有界，防内存无限增长）。
#[derive(Debug)]
pub struct SeenCache {
    capacity: usize,
    seen: HashMap<(String, u64, u64), ()>,
    order: VecDeque<(String, u64, u64)>,
}

impl SeenCache {
    /// 创建去重缓存（`capacity` 为最大条目数）。
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            seen: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    /// 是否应该泛洪：未见过的 `(node_id, incarnation, seq)` → true 并记录；
    /// 见过 → false。超容时淘汰最旧条目（FIFO）。
    pub fn should_flood(&mut self, node_id: &PeerId, incarnation: u64, seq: u64) -> bool {
        let key = (node_id.0.clone(), incarnation, seq);
        if self.seen.contains_key(&key) {
            return false;
        }
        if self.seen.len() >= self.capacity {
            if let Some(old) = self.order.pop_front() {
                self.seen.remove(&old);
            }
        }
        self.seen.insert(key.clone(), ());
        self.order.push_back(key);
        true
    }

    /// 缓存条目数。
    #[must_use]
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// 是否为空。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

// ---------- LSA 发现源（DESIGN §8.2 D4） ----------

/// LSA 发现源：从 LSDB 只读提取 peer → 可达地址。
///
/// 读取本已随 LSA 泛洪扩散的 `Lsa.locator` 字段（P5 冻结），**无线协议扩展**。
/// locator 为 `"udp://host:port"` 字面量形式；不可解析的 locator 被跳过
/// （该源对该 peer 无地址，不报错——见 [`Discovery`](super::Discovery) 语义）。
#[derive(Debug)]
pub struct LsaDiscovery<'a> {
    lsdb: &'a Lsdb,
}

impl<'a> LsaDiscovery<'a> {
    /// 借用 LSDB 构造（只读，不拷贝）。
    #[must_use]
    pub fn new(lsdb: &'a Lsdb) -> Self {
        Self { lsdb }
    }

    /// 解析 LSA locator 字符串为 SocketAddr。
    ///
    /// 仅接受 `udp://host:port`（host 为 IP 字面量）；其他 scheme / 主机名 /
    /// 非法格式返回 `None`（诚实跳过，不 panic）。
    #[must_use]
    pub fn parse_locator(locator: &str) -> Option<std::net::SocketAddr> {
        let rest = locator.strip_prefix("udp://")?;
        rest.parse::<std::net::SocketAddr>().ok()
    }
}

impl super::Discovery for LsaDiscovery<'_> {
    fn resolve(&self, peer: &super::PeerId) -> Vec<std::net::SocketAddr> {
        self.lsdb
            .get(peer)
            .and_then(|lsa| lsa.locator.as_deref())
            .and_then(Self::parse_locator)
            .into_iter()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_lsa(id: &str, seq: u64) -> Lsa {
        Lsa {
            node_id: PeerId(id.to_string()),
            vip: "10.99.0.1".to_string(),
            incarnation: 1,
            seq,
            capabilities: 0,
            locator: Some("udp://127.0.0.1:11010".to_string()),
            neighbors: Vec::new(),
        }
    }

    #[test]
    fn hello_codec_roundtrip() {
        let f = LsaFrame::Hello {
            node_id: PeerId("n1".to_string()),
            vip: "10.99.0.1".to_string(),
            capabilities: 3,
            incarnation: 7,
        };
        let bytes = encode_lsa_frame(&f).unwrap();
        assert_eq!(bytes[0], LSA_VERSION);
        assert_eq!(decode_lsa_frame(&bytes).unwrap(), f);
    }

    #[test]
    fn welcome_codec_roundtrip() {
        let f = LsaFrame::Welcome {
            lsas: vec![test_lsa("n1", 1), test_lsa("n2", 2)],
        };
        let bytes = encode_lsa_frame(&f).unwrap();
        assert_eq!(decode_lsa_frame(&bytes).unwrap(), f);
    }

    #[test]
    fn advert_codec_roundtrip() {
        let f = LsaFrame::LsaAdvert {
            lsa: test_lsa("n1", 5),
        };
        let bytes = encode_lsa_frame(&f).unwrap();
        assert_eq!(decode_lsa_frame(&bytes).unwrap(), f);
    }

    #[test]
    fn decode_rejects_bad_version_and_tag() {
        let mut bad = encode_lsa_frame(&LsaFrame::Hello {
            node_id: PeerId("n1".to_string()),
            vip: "10.99.0.1".to_string(),
            capabilities: 0,
            incarnation: 1,
        })
        .unwrap();
        bad[0] = 99;
        assert!(decode_lsa_frame(&bad).is_err());
        let mut bad_tag = encode_lsa_frame(&LsaFrame::Hello {
            node_id: PeerId("n1".to_string()),
            vip: "10.99.0.1".to_string(),
            capabilities: 0,
            incarnation: 1,
        })
        .unwrap();
        bad_tag[1] = 99;
        assert!(decode_lsa_frame(&bad_tag).is_err());
    }

    #[test]
    fn decode_rejects_truncated_frames() {
        // 截断：逐字节缩短，全部应返回 Transport 错误而非 panic。
        let full = encode_lsa_frame(&LsaFrame::Welcome {
            lsas: vec![test_lsa("n1", 1), test_lsa("n2", 2)],
        })
        .unwrap();
        for cut in 1..full.len() {
            assert!(
                decode_lsa_frame(&full[..cut]).is_err(),
                "truncated at {cut} should fail"
            );
        }
        // 空帧。
        assert!(decode_lsa_frame(&[]).is_err());
        // 尾随字节。
        let mut trailing = encode_lsa_frame(&LsaFrame::Hello {
            node_id: PeerId("n1".to_string()),
            vip: "10.99.0.1".to_string(),
            capabilities: 0,
            incarnation: 1,
        })
        .unwrap();
        trailing.push(0xFF);
        assert!(decode_lsa_frame(&trailing).is_err());
    }

    #[test]
    fn lsdb_update_ordering() {
        let mut db = Lsdb::new(PeerId("self".to_string()));
        assert_eq!(db.update(test_lsa("n1", 1)), UpdateOutcome::New);
        assert_eq!(db.update(test_lsa("n1", 1)), UpdateOutcome::Stale);
        assert_eq!(db.update(test_lsa("n1", 2)), UpdateOutcome::Updated);
        // incarnation 提升优先于 seq。
        let mut newer = test_lsa("n1", 1);
        newer.incarnation = 2;
        assert_eq!(db.update(newer), UpdateOutcome::Updated);
    }

    #[test]
    fn lsdb_self_never_overwritten_by_foreign() {
        let mut db = Lsdb::new(PeerId("self".to_string()));
        // 本端通过 update_local 发布。
        assert_eq!(db.update_local(test_lsa("self", 1)), UpdateOutcome::New);
        assert_eq!(db.update_local(test_lsa("self", 2)), UpdateOutcome::Updated);
        // 远端冒充本端 LSA 经 update → SelfIgnored，内容不变。
        let mut fake = test_lsa("self", 99);
        fake.vip = "10.99.0.99".to_string();
        assert_eq!(db.update(fake), UpdateOutcome::SelfIgnored);
        assert_eq!(
            db.get(&PeerId("self".to_string())).unwrap().vip,
            "10.99.0.1"
        );
        // 注：真正的冒充防御靠 PSK + 握手认证；此处仅保证 LSDB 不被远端覆盖。
    }

    #[test]
    fn seen_cache_dedup_and_bound() {
        let mut c = SeenCache::new(2);
        let id = PeerId("n1".to_string());
        assert!(c.should_flood(&id, 1, 1));
        assert!(!c.should_flood(&id, 1, 1));
        assert!(c.should_flood(&id, 1, 2));
        // 超容淘汰最旧 (n1,1,1)。
        assert!(c.should_flood(&id, 1, 3));
        assert_eq!(c.len(), 2);
        // (n1,1,1) 已被淘汰，再次出现视为新。
        assert!(c.should_flood(&id, 1, 1));
    }
}
