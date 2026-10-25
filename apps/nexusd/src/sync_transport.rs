//! C2: workspace sync over fabric QUIC bi-stream（Composition Root 适配器）。
//!
//! 本模块是 `nexus_workspace::WorkspaceTransport` 的 fabric 实现，
//! 放在 nexusd（Composition Root）侧，`nexus-workspace` 不新增对 fabric 的依赖（D2）。
//!
//! 帧格式：复用 wireup 的 `frame_msg`（`u8 type | u32 BE len | payload`），
//! type 固定为 [`STREAM_TYPE_WORKSPACE_SYNC`] (0x03, D3)。
//!
//! ## 回迁点（D1）
//!
//! 连接获取在**调用方**（`NatSwitching::active_conn(peer)`），不在本适配器。
//! `nexus-delivery` 已于 2026-10-26 删除（dual-stack-convergence run；
//! 零实现占位 crate）。若日后重建 delivery 层，只需把调用方的
//! `active_conn` 换成标准 `ResourceDeliveryRequest → Planner` 路径，
//! 本适配器（`open(conn)` 签名）不需要改。
//!
//! ## 被动端路由
//!
//! - relay 连接：`PunchManager` 是唯一 acceptor，非 punch 流经
//!   `take_unclaimed()` 交出 `(type, StreamShared)`；调用方按 type 0x03
//!   路由到 [`serve_sync_authorized`]。
//! - direct 连接：调用方 `accept_bi()` 后用 [`peek_sync_type`] 判定。

#![forbid(unsafe_code)]

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use nexus_fabric::{
    ConnShared, FabricError, PeerId, RecvStream, SendStream, StreamShared, split_stream,
};
use nexus_nat_wireup::{STREAM_TYPE_WORKSPACE_SYNC, frame_msg};
use nexus_storage::ContentStore;
use nexus_workspace::{SyncServedReport, Workspace, WorkspaceError, WorkspaceTransport};

/// 单帧 sanity 上限（64KB；与 wireup 的 MAX_FRAME 一致）。
pub const MAX_FRAME: usize = 64 * 1024;
/// 默认接收 deadline（单帧）。`RecvStream::read` 无超时，
/// 对端 hang 会卡死 sync 线程，适配器必须自加（P1）。
pub const DEFAULT_RECV_DEADLINE: Duration = Duration::from_secs(30);

/// 适配器错误（typed，映射到 `WorkspaceError::Transport`）。
#[derive(Debug)]
pub enum SyncTransportError {
    Fabric(FabricError),
    UnexpectedStreamType { got: u8 },
    FrameTooLarge { len: usize },
    UnexpectedEof,
    RecvTimeout,
}

impl std::fmt::Display for SyncTransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Fabric(e) => write!(f, "fabric: {e:?}"),
            Self::UnexpectedStreamType { got } => {
                write!(f, "expected stream type 0x03, got {got:#04x}")
            }
            Self::FrameTooLarge { len } => write!(f, "frame too large: {len}"),
            Self::UnexpectedEof => write!(f, "unexpected EOF"),
            Self::RecvTimeout => write!(f, "recv deadline exceeded"),
        }
    }
}

impl From<FabricError> for SyncTransportError {
    fn from(e: FabricError) -> Self {
        Self::Fabric(e)
    }
}

impl From<SyncTransportError> for WorkspaceError {
    fn from(e: SyncTransportError) -> Self {
        WorkspaceError::Transport {
            reason: e.to_string(),
        }
    }
}

fn peer_hex_of(peer: &PeerId) -> String {
    peer.0.iter().map(|b| format!("{b:02x}")).collect()
}

/// fabric bi-stream 上的 `WorkspaceTransport` 实现。
pub struct FabricSyncTransport {
    send: SendStream,
    recv: RecvStream,
    peer_hex: String,
    recv_deadline: Duration,
}

impl FabricSyncTransport {
    /// 主动端：在**已有连接**上开 bi-stream（D1：复用 active_conn，不另建连接）。
    pub fn open(
        conn: &Arc<ConnShared>,
        recv_deadline: Duration,
    ) -> Result<Self, SyncTransportError> {
        let sh = conn.open_stream()?;
        let (send, recv) = split_stream(sh);
        Ok(Self {
            send,
            recv,
            peer_hex: peer_hex_of(&conn.peer),
            recv_deadline,
        })
    }

    /// 被动端：从已 accept 的流构造（type 在首帧校验）。
    pub fn from_accepted(
        send: SendStream,
        recv: RecvStream,
        peer: &PeerId,
        recv_deadline: Duration,
    ) -> Self {
        Self {
            send,
            recv,
            peer_hex: peer_hex_of(peer),
            recv_deadline,
        }
    }

    /// 被动端：从 `take_unclaimed()` 交出的 `StreamShared` 构造。
    pub fn from_shared(sh: Arc<StreamShared>, peer: &PeerId, recv_deadline: Duration) -> Self {
        let (send, recv) = split_stream(sh);
        Self::from_accepted(send, recv, peer, recv_deadline)
    }

    /// 对端 PeerId（hex），用于成员授权（D4）。
    #[must_use]
    pub fn peer_hex(&self) -> &str {
        &self.peer_hex
    }

    /// 结束发送（FIN）。sync 会话结束时调用。
    pub fn finish(&mut self) -> Result<(), SyncTransportError> {
        self.send.finish()?;
        Ok(())
    }

    fn read_exact(&mut self, buf: &mut [u8], deadline: Instant) -> Result<(), SyncTransportError> {
        let mut filled = 0usize;
        while filled < buf.len() {
            match self.recv.read_deadline(&mut buf[filled..], deadline) {
                Ok(0) => return Err(SyncTransportError::UnexpectedEof),
                Ok(n) => filled += n,
                Err(FabricError::Timeout) => return Err(SyncTransportError::RecvTimeout),
                Err(e) => return Err(SyncTransportError::Fabric(e)),
            }
        }
        Ok(())
    }

    fn read_frame(&mut self) -> Result<Vec<u8>, SyncTransportError> {
        let deadline = Instant::now() + self.recv_deadline;
        let mut hdr = [0u8; 5];
        self.read_exact(&mut hdr, deadline)?;
        let ty = hdr[0];
        if ty != STREAM_TYPE_WORKSPACE_SYNC {
            return Err(SyncTransportError::UnexpectedStreamType { got: ty });
        }
        let len = u32::from_be_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]) as usize;
        if len > MAX_FRAME {
            return Err(SyncTransportError::FrameTooLarge { len });
        }
        let mut payload = vec![0u8; len];
        self.read_exact(&mut payload, deadline)?;
        Ok(payload)
    }
}

impl WorkspaceTransport for FabricSyncTransport {
    fn send_frame(&mut self, payload: &[u8]) -> Result<(), WorkspaceError> {
        let framed = frame_msg(STREAM_TYPE_WORKSPACE_SYNC, payload);
        let mut written = 0usize;
        while written < framed.len() {
            let n = self
                .send
                .write(&framed[written..])
                .map_err(SyncTransportError::from)?;
            written += n;
        }
        Ok(())
    }

    fn recv_frame(&mut self) -> Result<Vec<u8>, WorkspaceError> {
        self.read_frame().map_err(WorkspaceError::from)
    }
}

/// 静态成员列表（D4 第一版；后续接正式成员服务）。
///
/// P0 诚实声明：fabric 当前仅做单向认证（client 验证 server），**server 侧拿不到
/// client 的 PeerId**（`ConnShared::peer` 在 P0 为 zeroed，见 nexus-fabric driver）。
/// 因此生产环境被动端的 peer 身份不可信；`SyncAuthorizer` 当前为"机制就绪、
/// 强制执行待 client-auth"状态。E4 用显式注入的测试 ID 验证机制正确性，
/// 不代表生产安全属性已成立。client-auth 补齐后，本检查即转为强制执行。
/// （"他有没有资格读这个 Workspace"；白皮书要求每个 Workspace 有明确的成员与
/// 策略权威来源；纯 Relay 转发不自动获得成员身份。）
#[derive(Debug, Clone, Default)]
pub struct SyncAuthorizer {
    members: HashSet<String>,
}

impl SyncAuthorizer {
    /// `members` 为 hex PeerId 集合。
    #[must_use]
    pub fn new(members: HashSet<String>) -> Self {
        Self { members }
    }

    /// 对端是否在成员列表中。
    #[must_use]
    pub fn is_member(&self, peer_hex: &str) -> bool {
        self.members.contains(peer_hex)
    }
}

/// 被动 serve 结果：正常服务 vs 明确拒绝（D4）。
#[derive(Debug)]
pub enum SyncServeOutcome {
    Served(SyncServedReport),
    /// 未授权：已发送 `REJECTED:not-a-member` 帧，零数据发送。
    Rejected {
        peer_hex: String,
        reason: String,
    },
}

/// 带成员授权的被动 serve（D4）。
///
/// - 非成员：发送 `REJECTED:not-a-member` 帧后直接返回，不调用
///   `serve_sync`，不泄露任何 commit/object；拒绝记审计日志。
/// - 成员：正常 `serve_sync`。
pub fn serve_sync_authorized<S: ContentStore>(
    workspace: &mut Workspace<S>,
    transport: &mut FabricSyncTransport,
    authorizer: &SyncAuthorizer,
) -> Result<SyncServeOutcome, WorkspaceError> {
    let peer_hex = transport.peer_hex().to_string();
    if !authorizer.is_member(&peer_hex) {
        transport.send_frame(b"REJECTED:not-a-member")?;
        transport.finish().map_err(WorkspaceError::from)?;
        eprintln!("[sync] rejected non-member peer {peer_hex} (authz)");
        return Ok(SyncServeOutcome::Rejected {
            peer_hex,
            reason: "not-a-member".to_string(),
        });
    }
    let report = workspace.serve_sync(transport)?;
    Ok(SyncServeOutcome::Served(report))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorizer_allows_member_denies_other() {
        let mut members = HashSet::new();
        members.insert("ab".to_string());
        let auth = SyncAuthorizer::new(members);
        assert!(auth.is_member("ab"));
        assert!(!auth.is_member("cd"));
    }

    #[test]
    fn peer_hex_is_lowercase_hex_64() {
        let peer = PeerId([0xabu8; 32]);
        let hex = peer_hex_of(&peer);
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(&hex[0..2], "ab");
    }
}
