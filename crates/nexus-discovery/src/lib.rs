//! nexus-discovery
//!
//! 执行 Bootstrap、Peer Discovery、Endpoint/Candidate Exchange 与 Presence 建立。
//!
//! remote P0 冻结契约：静态发现表（scenarios/product/remote_service_access_flow.toml）；
//! 发现协议后置。`resolve` 只做静态表查询，不发起网络 I/O、不建立 Connectivity。
//!
//! 详细边界见同目录 `MODULE.md`。

#![forbid(unsafe_code)]

pub mod lsa;

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
    /// 发现协议传输失败（发送/接收/解码失败，携带原因）。
    Transport(String),
}

impl fmt::Display for DiscoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PeerUnknown(peer) => write!(f, "peer unknown: {peer}"),
            Self::PeerExpired(peer) => write!(f, "peer presence expired: {peer}"),
            Self::Transport(reason) => write!(f, "discovery transport: {reason}"),
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

    /// 查询该 Peer 的 Presence 记录（含过期记录，是否过期由调用方判定；网络发现协议 Server 用）。
    pub fn presence(&self, peer: &PeerId) -> Option<&Presence> {
        self.presences.iter().find(|p| &p.peer == peer)
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

// ---------- 网络发现协议（remote P0 扩展；发现协议网络传输） ----------

/// 发现协议帧（Discover/Announce/PeerUnknown/PeerExpired）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoveryFrame {
    /// 请求方 -> 提供方：查询某 Peer 的动态 Presence。
    Discover(PeerId),
    /// 提供方 -> 请求方：该 Peer 的动态 Presence（未过期）。
    Announce {
        peer: PeerId,
        endpoint: SocketAddr,
        ttl_secs: u64,
    },
    /// 提供方 -> 请求方：该 Peer 未发布 Presence。
    PeerUnknown(PeerId),
    /// 提供方 -> 请求方：该 Peer 的 Presence 已过期。
    PeerExpired(PeerId),
}

/// 帧类型标签（编解码用）。
const FRAME_DISCOVER: u8 = 1;
const FRAME_ANNOUNCE: u8 = 2;
const FRAME_PEER_UNKNOWN: u8 = 3;
const FRAME_PEER_EXPIRED: u8 = 4;

/// 写入长度前缀字符串（u16 BE + UTF-8）。
pub(crate) fn put_str(out: &mut Vec<u8>, s: &str) -> Result<(), DiscoveryError> {
    let len =
        u16::try_from(s.len()).map_err(|_| DiscoveryError::Transport("string too long".into()))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(s.as_bytes());
    Ok(())
}

/// 读取长度前缀字符串（u16 BE + UTF-8）。
pub(crate) fn get_str(buf: &[u8], pos: &mut usize) -> Result<String, DiscoveryError> {
    if *pos + 2 > buf.len() {
        return Err(DiscoveryError::Transport("frame truncated".into()));
    }
    let len = u16::from_be_bytes([buf[*pos], buf[*pos + 1]]) as usize;
    *pos += 2;
    if *pos + len > buf.len() {
        return Err(DiscoveryError::Transport("frame truncated".into()));
    }
    let s = std::str::from_utf8(&buf[*pos..*pos + len])
        .map_err(|e| DiscoveryError::Transport(format!("invalid utf8: {e}")))?;
    *pos += len;
    Ok(s.to_owned())
}

/// 编码一帧：type tag (u8) + 字段（字符串 = u16 BE 长度前缀 + UTF-8；
/// endpoint = 地址字符串；ttl = u64 BE）。确定性、可移植、无新依赖。
pub fn encode_frame(frame: &DiscoveryFrame) -> Result<Vec<u8>, DiscoveryError> {
    let mut out = Vec::new();
    match frame {
        DiscoveryFrame::Discover(peer) => {
            out.push(FRAME_DISCOVER);
            put_str(&mut out, &peer.0)?;
        }
        DiscoveryFrame::Announce {
            peer,
            endpoint,
            ttl_secs,
        } => {
            out.push(FRAME_ANNOUNCE);
            put_str(&mut out, &peer.0)?;
            put_str(&mut out, &endpoint.to_string())?;
            out.extend_from_slice(&ttl_secs.to_be_bytes());
        }
        DiscoveryFrame::PeerUnknown(peer) => {
            out.push(FRAME_PEER_UNKNOWN);
            put_str(&mut out, &peer.0)?;
        }
        DiscoveryFrame::PeerExpired(peer) => {
            out.push(FRAME_PEER_EXPIRED);
            put_str(&mut out, &peer.0)?;
        }
    }
    Ok(out)
}

/// 解码一帧；空帧 / 未知 type tag / 截断 / 非法编码返回 `DiscoveryError::Transport`。
pub fn decode_frame(payload: &[u8]) -> Result<DiscoveryFrame, DiscoveryError> {
    let Some(&tag) = payload.first() else {
        return Err(DiscoveryError::Transport("empty frame".into()));
    };
    let mut pos = 1;
    match tag {
        FRAME_DISCOVER => {
            let peer = PeerId(get_str(payload, &mut pos)?);
            expect_frame_end(payload, pos)?;
            Ok(DiscoveryFrame::Discover(peer))
        }
        FRAME_ANNOUNCE => {
            let peer = PeerId(get_str(payload, &mut pos)?);
            let endpoint = get_str(payload, &mut pos)?
                .parse::<SocketAddr>()
                .map_err(|e| DiscoveryError::Transport(format!("invalid endpoint: {e}")))?;
            if pos + 8 > payload.len() {
                return Err(DiscoveryError::Transport("frame truncated".into()));
            }
            let ttl_secs = u64::from_be_bytes(payload[pos..pos + 8].try_into().unwrap());
            pos += 8;
            expect_frame_end(payload, pos)?;
            Ok(DiscoveryFrame::Announce {
                peer,
                endpoint,
                ttl_secs,
            })
        }
        FRAME_PEER_UNKNOWN => {
            let peer = PeerId(get_str(payload, &mut pos)?);
            expect_frame_end(payload, pos)?;
            Ok(DiscoveryFrame::PeerUnknown(peer))
        }
        FRAME_PEER_EXPIRED => {
            let peer = PeerId(get_str(payload, &mut pos)?);
            expect_frame_end(payload, pos)?;
            Ok(DiscoveryFrame::PeerExpired(peer))
        }
        other => Err(DiscoveryError::Transport(format!(
            "unknown frame type: {other}"
        ))),
    }
}

/// 校验解码已消费全部字节。
fn expect_frame_end(payload: &[u8], pos: usize) -> Result<(), DiscoveryError> {
    if pos != payload.len() {
        return Err(DiscoveryError::Transport("trailing bytes".into()));
    }
    Ok(())
}

/// 发现协议传输抽象：一次请求-响应往返（实现由 Composition Root 注入，
/// Discovery 层零 I/O）。
pub trait DiscoveryTransport {
    /// 发送请求并接收响应；失败返回 `DiscoveryError::Transport`。
    fn exchange(&mut self, request: &[u8]) -> Result<Vec<u8>, DiscoveryError>;
}

/// 请求方侧网络发现客户端：经发现协议拉取远端 Presence 并本地缓存。
#[derive(Debug, Default)]
pub struct PresenceClient {
    registry: PresenceRegistry,
}

impl PresenceClient {
    /// 以本地缓存注册中心构造客户端（可携带既有公告）。
    pub fn new(registry: PresenceRegistry) -> Self {
        Self { registry }
    }

    /// 经发现协议拉取远端 Presence：编码 `Discover` 请求帧 -> exchange -> 解码响应；
    /// `Announce` 缓存入本地注册中心并返回；`PeerUnknown`/`PeerExpired` 原样返回
    /// （不得缓存、不得使用）。
    pub fn discover(
        &mut self,
        transport: &mut impl DiscoveryTransport,
        peer: &PeerId,
    ) -> Result<Presence, DiscoveryError> {
        let request = encode_frame(&DiscoveryFrame::Discover(peer.clone()))?;
        let response = transport.exchange(&request)?;
        match decode_frame(&response)? {
            DiscoveryFrame::Announce {
                peer: p,
                endpoint,
                ttl_secs,
            } => {
                self.registry.announce(p.clone(), endpoint, ttl_secs)?;
                Ok(Presence {
                    peer: p,
                    endpoint,
                    ttl_secs,
                    announced_at: std::time::Instant::now(),
                })
            }
            DiscoveryFrame::PeerUnknown(p) => Err(DiscoveryError::PeerUnknown(p)),
            DiscoveryFrame::PeerExpired(p) => Err(DiscoveryError::PeerExpired(p)),
            DiscoveryFrame::Discover(_) => Err(DiscoveryError::Transport(
                "unexpected discover frame".into(),
            )),
        }
    }

    /// 查本地缓存（代理 `PresenceRegistry::resolve`）。
    pub fn resolve_local(&self, peer: &PeerId) -> Result<SocketAddr, DiscoveryError> {
        self.registry.resolve(peer)
    }

    /// 本地缓存是否已公告该 Peer（不校验过期）。
    #[must_use]
    pub fn is_announced(&self, peer: &PeerId) -> bool {
        self.registry.is_announced(peer)
    }
}

/// 提供方侧无状态发现协议处理器：只做 registry 查询与帧编解码，不发起 I/O。
#[derive(Debug, Clone, Copy, Default)]
pub struct PresenceServer;

impl PresenceServer {
    /// 解码 `Discover` -> `registry` 查询 -> 编码响应帧；
    /// 已发布且未过期 -> `Announce`，未发布 -> `PeerUnknown`，已过期 -> `PeerExpired`；
    /// 非法/非 Discover 请求返回空响应（由传输层体现为协议拒绝）。
    pub fn handle(&self, registry: &PresenceRegistry, request: &[u8]) -> Vec<u8> {
        let Ok(DiscoveryFrame::Discover(peer)) = decode_frame(request) else {
            return Vec::new();
        };
        let frame = match registry.presence(&peer) {
            Some(p) if !p.expired() => DiscoveryFrame::Announce {
                peer,
                endpoint: p.endpoint,
                ttl_secs: p.ttl_secs,
            },
            Some(_) => DiscoveryFrame::PeerExpired(peer),
            None => DiscoveryFrame::PeerUnknown(peer),
        };
        encode_frame(&frame).unwrap_or_default()
    }
}

#[cfg(test)]
mod network_discovery_tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    struct EchoTransport {
        response: Vec<u8>,
    }

    impl DiscoveryTransport for EchoTransport {
        fn exchange(&mut self, _request: &[u8]) -> Result<Vec<u8>, DiscoveryError> {
            Ok(self.response.clone())
        }
    }

    #[test]
    fn frame_roundtrip_all_variants() {
        let frames = vec![
            DiscoveryFrame::Discover(PeerId("node-b".into())),
            DiscoveryFrame::Announce {
                peer: PeerId("node-b".into()),
                endpoint: addr(4242),
                ttl_secs: 60,
            },
            DiscoveryFrame::PeerUnknown(PeerId("node-x".into())),
            DiscoveryFrame::PeerExpired(PeerId("node-b".into())),
        ];
        for f in &frames {
            let enc = encode_frame(f).expect("encode ok");
            assert_eq!(decode_frame(&enc).expect("decode ok"), *f);
        }
    }

    #[test]
    fn decode_rejects_truncated_and_unknown() {
        assert!(matches!(
            decode_frame(b""),
            Err(DiscoveryError::Transport(_))
        ));
        assert!(matches!(
            decode_frame(&[7, 0, 1, b'x']),
            Err(DiscoveryError::Transport(_))
        ));
        assert!(matches!(
            decode_frame(&[FRAME_DISCOVER, 0, 5, 110, 111, 100, 101, 98, 0]),
            Err(DiscoveryError::Transport(_))
        ));
    }

    #[test]
    fn client_discover_announce_caches_locally() {
        let mut client = PresenceClient::default();
        let resp = encode_frame(&DiscoveryFrame::Announce {
            peer: PeerId("node-b".into()),
            endpoint: addr(4242),
            ttl_secs: 60,
        })
        .expect("encode ok");
        let p = client
            .discover(
                &mut EchoTransport { response: resp },
                &PeerId("node-b".into()),
            )
            .expect("discover ok");
        assert_eq!(p.endpoint, addr(4242));
        assert!(client.is_announced(&PeerId("node-b".into())));
        assert_eq!(
            client
                .resolve_local(&PeerId("node-b".into()))
                .expect("resolve ok"),
            addr(4242)
        );
    }

    #[test]
    fn client_discover_peer_unknown_not_cached() {
        let mut client = PresenceClient::default();
        let resp =
            encode_frame(&DiscoveryFrame::PeerUnknown(PeerId("node-x".into()))).expect("encode ok");
        assert!(matches!(
            client.discover(
                &mut EchoTransport { response: resp },
                &PeerId("node-x".into())
            ),
            Err(DiscoveryError::PeerUnknown(_))
        ));
        assert!(!client.is_announced(&PeerId("node-x".into())));
    }

    #[test]
    fn server_handles_announce_unknown_expired() {
        let mut registry = PresenceRegistry::default();
        registry
            .announce(PeerId("node-b".into()), addr(4242), 60)
            .expect("announce ok");
        registry
            .announce(PeerId("node-old".into()), addr(9999), 0)
            .expect("announce ttl0");
        let server = PresenceServer;

        let ok = server.handle(
            &registry,
            &encode_frame(&DiscoveryFrame::Discover(PeerId("node-b".into()))).unwrap(),
        );
        assert_eq!(
            decode_frame(&ok).expect("decode ok"),
            DiscoveryFrame::Announce {
                peer: PeerId("node-b".into()),
                endpoint: addr(4242),
                ttl_secs: 60,
            }
        );

        let unknown = server.handle(
            &registry,
            &encode_frame(&DiscoveryFrame::Discover(PeerId("node-x".into()))).unwrap(),
        );
        assert_eq!(
            decode_frame(&unknown).expect("decode ok"),
            DiscoveryFrame::PeerUnknown(PeerId("node-x".into()))
        );

        let expired = server.handle(
            &registry,
            &encode_frame(&DiscoveryFrame::Discover(PeerId("node-old".into()))).unwrap(),
        );
        assert_eq!(
            decode_frame(&expired).expect("decode ok"),
            DiscoveryFrame::PeerExpired(PeerId("node-old".into()))
        );
    }
}

// ---------- 自动节点发现（引导注册 + 对等发现 + 心跳保活；纯内存骨架） ----------

pub mod auto_discovery;
