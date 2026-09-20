//! 自动节点发现：引导注册 + 对等节点发现 + 心跳保活（纯内存/无 I/O 骨架，
//! 真实网络传输留 TODO，由 Composition Root 注入）。

use crate::{DiscoveryError, PeerId, get_str, put_str};

/// 自动发现配置（纯标识/内存骨架；真实部署为网络地址）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryConfig {
    /// 引导节点地址列表（真实部署为网络地址；此处为标识串）。
    pub bootstrap_nodes: Vec<String>,
    /// 本节点标识。
    pub node_id: String,
}

/// 自动发现状态机（全部同步、无 tokio、无 spawn）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryState {
    /// 初始：尚未注册到引导。
    Idle,
    /// 已注册/已发起发现，等待对等节点列表或建连。
    Discovering,
    /// 已与至少一个 peer 建连成功。
    Connected,
    /// 引导不可用/长时间无心跳，离线。
    Offline,
}

impl DiscoveryState {
    /// 返回小写字符串："idle"/"discovering"/"connected"/"offline"（JSON 输出用）。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Discovering => "discovering",
            Self::Connected => "connected",
            Self::Offline => "offline",
        }
    }
}

/// 已发现的对等节点（Identity != Locator；virtual_ip/locator 为标识串）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredNode {
    /// 节点标识。
    pub node_id: String,
    /// 虚拟 IP 标识（此处为字符串，真实部署由网络层分配）。
    pub virtual_ip: String,
    /// 定位标识（Locator；真实部署为网络地址）。
    pub locator: String,
    /// 最近一次心跳/注册的时间（秒，由调用方注入，便于确定性测试）。
    pub last_seen: u64,
}

/// 引导注册中心（服务端侧，纯内存、无 I/O；模拟 bootstrap/registry 角色）。
#[derive(Debug, Default)]
pub struct BootstrapRegistry {
    peers: Vec<DiscoveredNode>,
}

impl BootstrapRegistry {
    /// 创建空的引导注册中心。
    pub fn new() -> Self {
        Self::default()
    }

    /// 注册/刷新一个节点（按 node_id 幂等 upsert；同时刷新 last_seen）。
    pub fn register(&mut self, node: DiscoveredNode) {
        if let Some(existing) = self.peers.iter_mut().find(|p| p.node_id == node.node_id) {
            existing.virtual_ip = node.virtual_ip;
            existing.locator = node.locator;
            existing.last_seen = node.last_seen;
        } else {
            self.peers.push(node);
        }
    }

    /// 查询对等节点列表（排除 exclude 指定的 self node_id），按 node_id 升序返回以保证确定性。
    pub fn get_peers(&self, exclude: &str) -> Vec<DiscoveredNode> {
        let mut peers: Vec<DiscoveredNode> = self
            .peers
            .iter()
            .filter(|p| p.node_id != exclude)
            .cloned()
            .collect();
        peers.sort_by(|a, b| a.node_id.cmp(&b.node_id));
        peers
    }

    /// 心跳刷新 last_seen；未知节点返回 `DiscoveryError::PeerUnknown(PeerId(node_id.into()))`。
    pub fn heartbeat(&mut self, node_id: &str, now: u64) -> Result<(), DiscoveryError> {
        let Some(existing) = self.peers.iter_mut().find(|p| p.node_id == node_id) else {
            return Err(DiscoveryError::PeerUnknown(PeerId(node_id.to_owned())));
        };
        existing.last_seen = now;
        Ok(())
    }

    /// 当前注册节点总数（含 self）。
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }
}

/// 自动发现状态机（客户端侧；全部同步、无 tokio、无 spawn；
/// 心跳由 Owner 周期性调用 `heartbeat()` 驱动）。
#[derive(Debug)]
pub struct AutoDiscovery {
    config: DiscoveryConfig,
    state: DiscoveryState,
    known_peers: Vec<DiscoveredNode>,
}

impl AutoDiscovery {
    /// 以配置创建自动发现状态机（初始状态 `Idle`）。
    pub fn new(config: DiscoveryConfig) -> Self {
        Self {
            config,
            state: DiscoveryState::Idle,
            known_peers: Vec::new(),
        }
    }

    /// 当前发现状态。
    pub fn state(&self) -> DiscoveryState {
        self.state
    }

    /// 发现配置引用。
    pub fn config(&self) -> &DiscoveryConfig {
        &self.config
    }

    /// 已知对等节点（拉取自引导注册中心的快照）。
    pub fn known_peers(&self) -> &[DiscoveredNode] {
        &self.known_peers
    }

    /// 向 bootstrap 注册本节点：把 `(config.node_id, virtual_ip, locator, now)` upsert 进 registry；
    /// state: `Idle -> Discovering`；成功后返回 `Ok(())`。
    pub fn register(
        &mut self,
        registry: &mut BootstrapRegistry,
        virtual_ip: &str,
        locator: &str,
        now: u64,
    ) -> Result<(), DiscoveryError> {
        registry.register(DiscoveredNode {
            node_id: self.config.node_id.clone(),
            virtual_ip: virtual_ip.to_owned(),
            locator: locator.to_owned(),
            last_seen: now,
        });
        self.state = DiscoveryState::Discovering;
        Ok(())
    }

    /// 从 registry 拉取对等节点：`get_peers(exclude=self)`，更新 `known_peers`；
    /// 拉到至少一个 peer 时 state 保持 `Discovering`（由调用方在成功建连后 `mark_connected`）；
    /// 返回拉到的 peers 副本。
    pub fn discover_peers(
        &mut self,
        registry: &BootstrapRegistry,
    ) -> Result<Vec<DiscoveredNode>, DiscoveryError> {
        let peers = registry.get_peers(&self.config.node_id);
        self.known_peers = peers.clone();
        if !peers.is_empty() && self.state == DiscoveryState::Idle {
            self.state = DiscoveryState::Discovering;
        }
        Ok(peers)
    }

    /// 向 registry 发送心跳（`registry.heartbeat(self.node_id, now)`），透传错误。
    pub fn heartbeat(
        &mut self,
        registry: &mut BootstrapRegistry,
        now: u64,
    ) -> Result<(), DiscoveryError> {
        registry.heartbeat(&self.config.node_id, now)
    }

    /// 与至少一个 peer 建连成功后调用：state -> `Connected`。
    pub fn mark_connected(&mut self) {
        self.state = DiscoveryState::Connected;
    }

    /// 引导不可用/长时间无心跳：state -> `Offline`。
    pub fn mark_offline(&mut self) {
        self.state = DiscoveryState::Offline;
    }
}

// ---------- 自动发现协议帧（Register/GetPeers/Heartbeat） ----------

/// 自动发现协议帧类型标签。
const AUTO_FRAME_REGISTER: u8 = 11;
const AUTO_FRAME_GET_PEERS: u8 = 12;
const AUTO_FRAME_PEER_LIST: u8 = 13;
const AUTO_FRAME_HEARTBEAT: u8 = 14;

/// 自动发现协议帧（Register/GetPeers/Heartbeat；独立于既有 `DiscoveryFrame`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AutoDiscoveryFrame {
    /// 节点 -> bootstrap：注册/刷新本节点标识与定位。
    Register {
        node_id: String,
        virtual_ip: String,
        locator: String,
    },
    /// 节点 -> bootstrap：拉取对等节点列表（exclude=self）。
    GetPeers { node_id: String },
    /// bootstrap -> 节点：对等节点列表。
    PeerList { peers: Vec<DiscoveredNode> },
    /// 节点 -> bootstrap：心跳保活。
    Heartbeat { node_id: String, now: u64 },
}

/// 写入一个 u64（大端 8 字节）。
fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_be_bytes());
}

/// 读取一个 u64（大端 8 字节）；越界返回 `Transport` 错误。
fn get_u64(buf: &[u8], pos: &mut usize) -> Result<u64, DiscoveryError> {
    if *pos + 8 > buf.len() {
        return Err(DiscoveryError::Transport("frame truncated".into()));
    }
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&buf[*pos..*pos + 8]);
    *pos += 8;
    Ok(u64::from_be_bytes(bytes))
}

/// 写入一个 `DiscoveredNode`（三个字符串 + last_seen u64）。
fn put_node(out: &mut Vec<u8>, node: &DiscoveredNode) -> Result<(), DiscoveryError> {
    put_str(out, &node.node_id)?;
    put_str(out, &node.virtual_ip)?;
    put_str(out, &node.locator)?;
    put_u64(out, node.last_seen);
    Ok(())
}

/// 读取一个 `DiscoveredNode`。
fn get_node(buf: &[u8], pos: &mut usize) -> Result<DiscoveredNode, DiscoveryError> {
    let node_id = get_str(buf, pos)?;
    let virtual_ip = get_str(buf, pos)?;
    let locator = get_str(buf, pos)?;
    let last_seen = get_u64(buf, pos)?;
    Ok(DiscoveredNode {
        node_id,
        virtual_ip,
        locator,
        last_seen,
    })
}

/// 校验解码已消费全部字节。
fn expect_frame_end(payload: &[u8], pos: usize) -> Result<(), DiscoveryError> {
    if pos != payload.len() {
        return Err(DiscoveryError::Transport("trailing bytes".into()));
    }
    Ok(())
}

/// 编码自动发现帧：type tag (u8) + 字段；字符串为 u16 BE 长度前缀 + UTF-8，
/// u64 为大端 8 字节，PeerList 节点数量为 u16 BE 前缀。确定性、可移植、无新依赖。
pub fn encode_auto_frame(frame: &AutoDiscoveryFrame) -> Result<Vec<u8>, DiscoveryError> {
    let mut out = Vec::new();
    match frame {
        AutoDiscoveryFrame::Register {
            node_id,
            virtual_ip,
            locator,
        } => {
            out.push(AUTO_FRAME_REGISTER);
            put_str(&mut out, node_id)?;
            put_str(&mut out, virtual_ip)?;
            put_str(&mut out, locator)?;
        }
        AutoDiscoveryFrame::GetPeers { node_id } => {
            out.push(AUTO_FRAME_GET_PEERS);
            put_str(&mut out, node_id)?;
        }
        AutoDiscoveryFrame::PeerList { peers } => {
            out.push(AUTO_FRAME_PEER_LIST);
            let count = u16::try_from(peers.len())
                .map_err(|_| DiscoveryError::Transport("peer list too long".into()))?;
            out.extend_from_slice(&count.to_be_bytes());
            for node in peers {
                put_node(&mut out, node)?;
            }
        }
        AutoDiscoveryFrame::Heartbeat { node_id, now } => {
            out.push(AUTO_FRAME_HEARTBEAT);
            put_str(&mut out, node_id)?;
            put_u64(&mut out, *now);
        }
    }
    Ok(out)
}

/// 解码自动发现帧；空帧 / 未知 type tag / 截断 / 非法 utf8 / 越界一律返回
/// `DiscoveryError::Transport(String)`。
pub fn decode_auto_frame(payload: &[u8]) -> Result<AutoDiscoveryFrame, DiscoveryError> {
    let Some(&tag) = payload.first() else {
        return Err(DiscoveryError::Transport("empty frame".into()));
    };
    let mut pos = 1;
    match tag {
        AUTO_FRAME_REGISTER => {
            let node_id = get_str(payload, &mut pos)?;
            let virtual_ip = get_str(payload, &mut pos)?;
            let locator = get_str(payload, &mut pos)?;
            expect_frame_end(payload, pos)?;
            Ok(AutoDiscoveryFrame::Register {
                node_id,
                virtual_ip,
                locator,
            })
        }
        AUTO_FRAME_GET_PEERS => {
            let node_id = get_str(payload, &mut pos)?;
            expect_frame_end(payload, pos)?;
            Ok(AutoDiscoveryFrame::GetPeers { node_id })
        }
        AUTO_FRAME_PEER_LIST => {
            if pos + 2 > payload.len() {
                return Err(DiscoveryError::Transport("frame truncated".into()));
            }
            let count = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
            pos += 2;
            let mut peers = Vec::with_capacity(count);
            for _ in 0..count {
                peers.push(get_node(payload, &mut pos)?);
            }
            expect_frame_end(payload, pos)?;
            Ok(AutoDiscoveryFrame::PeerList { peers })
        }
        AUTO_FRAME_HEARTBEAT => {
            let node_id = get_str(payload, &mut pos)?;
            let now = get_u64(payload, &mut pos)?;
            expect_frame_end(payload, pos)?;
            Ok(AutoDiscoveryFrame::Heartbeat { node_id, now })
        }
        other => Err(DiscoveryError::Transport(format!(
            "unknown auto frame type: {other}"
        ))),
    }
}

#[cfg(test)]
mod auto_discovery_tests {
    use super::*;

    fn node(id: &str, last_seen: u64) -> DiscoveredNode {
        DiscoveredNode {
            node_id: id.to_owned(),
            virtual_ip: format!("10.0.0.{id}"),
            locator: format!("locator-{id}"),
            last_seen,
        }
    }

    #[test]
    fn register_is_idempotent_upsert() {
        let mut reg = BootstrapRegistry::new();
        reg.register(node("a", 100));
        reg.register(node("b", 100));
        assert_eq!(reg.peer_count(), 2);
        // 重复注册同 node_id：刷新 last_seen，不新增。
        reg.register(node("a", 200));
        assert_eq!(reg.peer_count(), 2);
        let peers = reg.get_peers("self");
        let a = peers.iter().find(|p| p.node_id == "a").expect("a exists");
        assert_eq!(a.last_seen, 200);
    }

    #[test]
    fn get_peers_excludes_self_and_sorts() {
        let mut reg = BootstrapRegistry::new();
        reg.register(node("carol", 1));
        reg.register(node("self", 1));
        reg.register(node("alice", 1));
        reg.register(node("bob", 1));
        let peers = reg.get_peers("self");
        let ids: Vec<&str> = peers.iter().map(|p| p.node_id.as_str()).collect();
        assert_eq!(ids, vec!["alice", "bob", "carol"]);
    }

    #[test]
    fn heartbeat_unknown_node_errors() {
        let mut reg = BootstrapRegistry::new();
        reg.register(node("a", 100));
        assert!(matches!(
            reg.heartbeat("ghost", 200),
            Err(DiscoveryError::PeerUnknown(_))
        ));
        // 已知节点心跳刷新 last_seen。
        reg.heartbeat("a", 300).expect("heartbeat ok");
        let a = reg
            .get_peers("self")
            .into_iter()
            .find(|p| p.node_id == "a")
            .expect("a");
        assert_eq!(a.last_seen, 300);
    }

    #[test]
    fn discover_peers_updates_known_peers() {
        let mut reg = BootstrapRegistry::new();
        reg.register(node("peer-1", 1));
        reg.register(node("peer-2", 1));

        let cfg = DiscoveryConfig {
            bootstrap_nodes: vec!["b1".into()],
            node_id: "self".into(),
        };
        let mut ad = AutoDiscovery::new(cfg);
        assert!(ad.known_peers().is_empty());

        let peers = ad.discover_peers(&reg).expect("discover ok");
        assert_eq!(peers.len(), 2);
        assert_eq!(ad.known_peers().len(), 2);
        // 拉到 peer 后由 Idle -> Discovering。
        assert_eq!(ad.state(), DiscoveryState::Discovering);
    }

    #[test]
    fn state_machine_idle_discovering_connected_offline() {
        let cfg = DiscoveryConfig {
            bootstrap_nodes: vec!["b1".into()],
            node_id: "self".into(),
        };
        let mut ad = AutoDiscovery::new(cfg);
        assert_eq!(ad.state(), DiscoveryState::Idle);
        assert_eq!(ad.state().as_str(), "idle");

        let mut reg = BootstrapRegistry::new();
        ad.register(&mut reg, "10.0.0.1", "locator-self", 100)
            .expect("register ok");
        assert_eq!(ad.state(), DiscoveryState::Discovering);
        assert_eq!(ad.state().as_str(), "discovering");

        ad.mark_connected();
        assert_eq!(ad.state(), DiscoveryState::Connected);
        assert_eq!(ad.state().as_str(), "connected");

        ad.mark_offline();
        assert_eq!(ad.state(), DiscoveryState::Offline);
        assert_eq!(ad.state().as_str(), "offline");
    }

    #[test]
    fn client_heartbeat_passes_through_registry() {
        let mut reg = BootstrapRegistry::new();
        let cfg = DiscoveryConfig {
            bootstrap_nodes: vec![],
            node_id: "self".into(),
        };
        let mut ad = AutoDiscovery::new(cfg);
        ad.register(&mut reg, "10.0.0.1", "locator-self", 100)
            .expect("register ok");
        ad.heartbeat(&mut reg, 500).expect("heartbeat ok");
        let me = reg
            .get_peers("nobody")
            .into_iter()
            .find(|p| p.node_id == "self")
            .expect("self");
        assert_eq!(me.last_seen, 500);
    }

    #[test]
    fn auto_frame_roundtrip_all_variants() {
        let frames = vec![
            AutoDiscoveryFrame::Register {
                node_id: "self".into(),
                virtual_ip: "10.0.0.1".into(),
                locator: "locator-self".into(),
            },
            AutoDiscoveryFrame::GetPeers {
                node_id: "self".into(),
            },
            AutoDiscoveryFrame::PeerList {
                peers: vec![node("a", 1), node("b", 2)],
            },
            AutoDiscoveryFrame::Heartbeat {
                node_id: "self".into(),
                now: 123456789,
            },
        ];
        for f in &frames {
            let enc = encode_auto_frame(f).expect("encode ok");
            assert_eq!(decode_auto_frame(&enc).expect("decode ok"), *f);
        }
    }

    #[test]
    fn decode_rejects_empty_unknown_tag_and_truncated() {
        // 空帧。
        assert!(matches!(
            decode_auto_frame(b""),
            Err(DiscoveryError::Transport(_))
        ));
        // 未知 tag。
        assert!(matches!(
            decode_auto_frame(&[99, 0, 1, b'x']),
            Err(DiscoveryError::Transport(_))
        ));
        // 截断的 Register（声明字符串长度 5 但字节不足）。
        assert!(matches!(
            decode_auto_frame(&[AUTO_FRAME_REGISTER, 0, 5, b'a', b'b']),
            Err(DiscoveryError::Transport(_))
        ));
        // 截断的 Heartbeat（字符串后缺 u64）。
        assert!(matches!(
            decode_auto_frame(&[AUTO_FRAME_HEARTBEAT, 0, 1, b'a', 0, 0]),
            Err(DiscoveryError::Transport(_))
        ));
        // PeerList 节点数量前缀截断。
        assert!(matches!(
            decode_auto_frame(&[AUTO_FRAME_PEER_LIST, 0, 2]),
            Err(DiscoveryError::Transport(_))
        ));
    }

    #[test]
    fn encode_peer_list_over_u16_count_errors() {
        // 节点数量超过 u16::MAX -> u16::try_from 失败 -> encode 返回 Transport 错误。
        let too_many = u16::MAX as usize + 1;
        let peers: Vec<DiscoveredNode> = (0..too_many)
            .map(|i| DiscoveredNode {
                node_id: format!("n{i}"),
                virtual_ip: String::new(),
                locator: String::new(),
                last_seen: 0,
            })
            .collect();
        assert_eq!(peers.len(), 65536);
        let frame = AutoDiscoveryFrame::PeerList { peers };
        assert!(matches!(
            encode_auto_frame(&frame),
            Err(DiscoveryError::Transport(_))
        ));
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        // 合法 Register 帧后追加 1 字节 -> expect_frame_end 报 trailing bytes。
        let frame = AutoDiscoveryFrame::Register {
            node_id: "self".into(),
            virtual_ip: "10.0.0.1".into(),
            locator: "locator-self".into(),
        };
        let mut bytes = encode_auto_frame(&frame).expect("encode ok");
        bytes.push(0xff);
        assert!(matches!(
            decode_auto_frame(&bytes),
            Err(DiscoveryError::Transport(_))
        ));
    }

    #[test]
    fn discover_peers_on_empty_registry_keeps_idle() {
        let cfg = DiscoveryConfig {
            bootstrap_nodes: vec!["b1".into()],
            node_id: "self".into(),
        };
        let mut ad = AutoDiscovery::new(cfg);

        // 空注册中心：拉到空，state 保持初始 Idle。
        let reg = BootstrapRegistry::new();
        let peers = ad.discover_peers(&reg).expect("discover ok");
        assert!(peers.is_empty());
        assert!(ad.known_peers().is_empty());
        assert_eq!(ad.state(), DiscoveryState::Idle);

        // 注册中心只有 self 自己（被 exclude）：同样拉空，state 仍 Idle。
        let mut reg2 = BootstrapRegistry::new();
        reg2.register(node("self", 1));
        let peers2 = ad.discover_peers(&reg2).expect("discover ok");
        assert!(peers2.is_empty());
        assert!(ad.known_peers().is_empty());
        assert_eq!(ad.state(), DiscoveryState::Idle);
    }
}
