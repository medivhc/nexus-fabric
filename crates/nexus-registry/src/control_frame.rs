//! N2 控制面帧协议（D8）：经 FrameStream 交换的 5 种控制帧。
//!
//! 帧格式（NAT wireup T3 教训）：payload 首字节为**显式**帧类型标签，
//! 不靠首字节内容猜测类型；字段编码沿用仓库既有约定——
//! 字符串 = u16 BE 长度前缀 + UTF-8，u64 = 大端 8 字节，
//! 集合 = u16 BE 计数前缀，Option = u8 标志位。
//! 解码拒绝：空帧 / 未知标签 / 截断 / 非法 UTF-8 / 非法名字 / 未知判别值 / 尾部多余字节。
//!
//! 认证：本模块**不实现认证**。控制帧只能在**已通过既有认证门控**的通道上
//! 交换——remote P0 用 `nexus_auth::verify_token`，N2 用 D6 ed25519 身份校验；
//! `ControlChannel::established` 要求调用方传入已认证对端（`AuthenticatedPeer`），
//! 不制造第二套认证路径（mimo 的品味点）。
//!
//! 传输：`ControlTransport` trait 由组合根以 `nexus_transport::FrameStream`
//! 适配装配，避免 registry → transport 依赖边（架构策略；
//! 同 `nexus_service::ServiceTransport` 模式）。

use std::fmt;

use nexus_domain::{NodeId, ProviderId, ResourceId, ResourceName, ResourceOperation, ResourceRef};

use super::advertisement::{
    Discoverability, ProviderAdvertisement, UnavailabilityReason, UsageGrant,
};

// ============================================================================
// 帧类型标签（显式前缀；0x2x 段，避免与 discovery 0x01-0x0E 碰撞）
// ============================================================================

const FRAME_RESOURCE_ANNOUNCE: u8 = 0x21;
const FRAME_RESOURCE_QUERY: u8 = 0x22;
const FRAME_AUTH_GRANT: u8 = 0x23;
const FRAME_AUTH_REVOKE: u8 = 0x24;
const FRAME_LEASE_RENEW: u8 = 0x25;

// 字段判别值（wire 稳定；扩展需走 requirement-change）。
const DISC_PUBLIC: u8 = 0;
const DISC_RESTRICTED: u8 = 1;
const UNAV_OFFLINE: u8 = 0;
const UNAV_DEGRADED: u8 = 1;
const UNAV_NOT_ACCEPTING: u8 = 2;
const OP_USE: u8 = 0;
const OP_MANAGE: u8 = 1;

// ============================================================================
// 控制帧
// ============================================================================

/// 授权公告（wire DTO）：`nexus-auth` Grant 的传输形态。
///
/// 字段与 `Grant{resource, principal, operations, not_after}` 一一对应；
/// `principal` / `operations` / `not_after` 由内嵌的 `UsageGrant` 承载，
/// 避免 `principal` 在 wire 上重复序列化；
/// 权威的授权判定仍在提供方侧 grant 表，**公告 ≠ 授权**。
///
/// D2 例外（P0-4 复核，见 MODULE.md"契約張力裁决"）：`resource` 为
/// `ResourceRef{workspace, name}`（人类可读名进传输）。
/// 这**不是** D2"人类可读名不出传输层"的违反——该规则约束的是**寻址/查询路径**
/// （请求方不得把人类可读名当地址发出去做解析；`ResourceQuery` 因此只带不透明
/// `ResourceId`）。而 AUTH_GRANT/AUTH_REVOKE 是**提供方→请求方**的授权状态公告，
/// 其中的 `ResourceRef` 是提供方**自己命名空间**内的 grant 表键
/// （`{workspace, name}`，人类可运维），不是地址解析键；请求方收到后
/// 用自己本地解析的 `ResourceId`（经广告通道已持有的映射）做关联，
/// 永不把收到的名字当地址用。改用 `ResourceId` 的替代方案被否决：
/// 提供方 grant 表本就以 `ResourceRef` 为键，强行换 Id 需要提供方维护
/// 一套它没有的反向映射，且会把人类可运维的 grant 管理与线上传告割裂。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantAnnouncement {
    /// 授权目标资源（提供方本地命名）。
    pub resource: ResourceRef,
    /// 授予详情：`principal` / `operations` / `not_after` 由内嵌
    /// `UsageGrant` 承载（避免 `principal` 在 wire 上重复序列化）。
    pub grant: UsageGrant,
}

/// N2 控制面帧（D8 列出的 5 种，经 FrameStream 交换）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlFrame {
    /// 提供方 → 请求方：发布/刷新一条 Provider 广告。
    ResourceAnnounce {
        /// 广告（`resource` 为不透明 `ResourceId`，名字不进传输）。
        ad: ProviderAdvertisement,
    },
    /// 请求方 → 提供方：按不透明资源 Id 查询广告。
    ///
    /// D2：`ResourceRef{workspace, name}` 由请求方**本地**解析为 `ResourceId`
    /// 后再发起查询；人类可读名不出传输层。
    ResourceQuery {
        /// 查询方节点（已认证主体对应的节点标识；可观测字段）。
        requester: NodeId,
        /// 被查询资源（不透明 Id）。
        resource: ResourceId,
    },
    /// 提供方 → 请求方：授权授予公告（grant 表变更推送）。
    ///
    /// D2 例外（P0-4 复核）：`announcement.resource` 为提供方命名空间内的
    /// `ResourceRef`（见 `GrantAnnouncement` 文档）；请求方只做本地关联，
    /// 不做地址解析。
    AuthGrant {
        /// 授权公告。
        announcement: GrantAnnouncement,
    },
    /// 提供方 → 请求方：授权撤销公告。
    ///
    /// D2 例外（P0-4 复核）：`resource` 为提供方命名空间内的 `ResourceRef`
    ///（同 `AuthGrant`）；请求方只做本地关联，不做地址解析。
    AuthRevoke {
        /// 撤销目标资源（提供方本地命名）。
        resource: ResourceRef,
        /// 被撤销主体。
        principal: String,
    },
    /// 提供方 → 请求方：广告租约续期（刷新请求方缓存的 issued_at/ttl）。
    LeaseRenew {
        /// 广告所属 Provider。
        provider: ProviderId,
        /// 广告所属资源（不透明 Id）。
        resource: ResourceId,
        /// 新的发布时间（unix 秒）。
        issued_at_secs: u64,
        /// 新的有效期（秒）；0 = 永不过期。
        ttl_secs: u64,
    },
}

// ============================================================================
// 编解码错误（类型化）
// ============================================================================

/// 控制帧编解码失败。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameCodecError {
    /// 空帧（至少需要 1 字节类型标签）。
    EmptyFrame,
    /// 未知的帧类型标签。
    UnknownFrameType(u8),
    /// 帧截断（字段未读完）。
    Truncated,
    /// 非法 UTF-8。
    InvalidUtf8,
    /// 解码后还有多余字节（帧格式违规）。
    TrailingBytes,
    /// 值超长（字符串 > u16::MAX / 集合元素 > u16::MAX）。
    ValueTooLong,
    /// 非法的资源名（违反 `ResourceName` 字符集）。
    InvalidResourceName,
    /// 未知的枚举判别值。
    UnknownDiscriminant {
        /// 字段名（"discoverability" / "unavailability" / "operation"）。
        field: &'static str,
        /// 收到的判别值。
        value: u8,
    },
}

impl fmt::Display for FrameCodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyFrame => f.write_str("empty control frame"),
            Self::UnknownFrameType(t) => write!(f, "unknown control frame type: {t:#04x}"),
            Self::Truncated => f.write_str("control frame truncated"),
            Self::InvalidUtf8 => f.write_str("control frame invalid utf8"),
            Self::TrailingBytes => f.write_str("control frame trailing bytes"),
            Self::ValueTooLong => f.write_str("control frame value too long"),
            Self::InvalidResourceName => f.write_str("control frame invalid resource name"),
            Self::UnknownDiscriminant { field, value } => {
                write!(f, "control frame unknown discriminant: {field}={value}")
            }
        }
    }
}

impl std::error::Error for FrameCodecError {}

// ============================================================================
// wire 原语（u8 tag + BE 字段；与 nexus-discovery 同风格）
// ============================================================================

fn put_u8(out: &mut Vec<u8>, v: u8) {
    out.push(v);
}

fn put_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn put_str(out: &mut Vec<u8>, s: &str) -> Result<(), FrameCodecError> {
    let len = u16::try_from(s.len()).map_err(|_| FrameCodecError::ValueTooLong)?;
    put_u16(out, len);
    out.extend_from_slice(s.as_bytes());
    Ok(())
}

fn put_opt_u64(out: &mut Vec<u8>, v: Option<u64>) {
    match v {
        None => put_u8(out, 0),
        Some(x) => {
            put_u8(out, 1);
            put_u64(out, x);
        }
    }
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn get_u8(&mut self) -> Result<u8, FrameCodecError> {
        if self.pos + 1 > self.buf.len() {
            return Err(FrameCodecError::Truncated);
        }
        let v = self.buf[self.pos];
        self.pos += 1;
        Ok(v)
    }

    fn get_u16(&mut self) -> Result<u16, FrameCodecError> {
        if self.pos + 2 > self.buf.len() {
            return Err(FrameCodecError::Truncated);
        }
        let mut b = [0u8; 2];
        b.copy_from_slice(&self.buf[self.pos..self.pos + 2]);
        self.pos += 2;
        Ok(u16::from_be_bytes(b))
    }

    fn get_u64(&mut self) -> Result<u64, FrameCodecError> {
        if self.pos + 8 > self.buf.len() {
            return Err(FrameCodecError::Truncated);
        }
        let mut b = [0u8; 8];
        b.copy_from_slice(&self.buf[self.pos..self.pos + 8]);
        self.pos += 8;
        Ok(u64::from_be_bytes(b))
    }

    fn get_str(&mut self) -> Result<String, FrameCodecError> {
        let len = self.get_u16()? as usize;
        if self.pos + len > self.buf.len() {
            return Err(FrameCodecError::Truncated);
        }
        let s = std::str::from_utf8(&self.buf[self.pos..self.pos + len])
            .map_err(|_| FrameCodecError::InvalidUtf8)?;
        self.pos += len;
        Ok(s.to_owned())
    }

    fn get_opt_u64(&mut self) -> Result<Option<u64>, FrameCodecError> {
        match self.get_u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.get_u64()?)),
            v => Err(FrameCodecError::UnknownDiscriminant {
                field: "option",
                value: v,
            }),
        }
    }

    fn end(&self) -> Result<(), FrameCodecError> {
        if self.pos != self.buf.len() {
            return Err(FrameCodecError::TrailingBytes);
        }
        Ok(())
    }
}

fn put_operation(out: &mut Vec<u8>, op: ResourceOperation) {
    put_u8(
        out,
        match op {
            ResourceOperation::Use => OP_USE,
            ResourceOperation::Manage => OP_MANAGE,
        },
    );
}

fn get_operation(r: &mut Reader<'_>) -> Result<ResourceOperation, FrameCodecError> {
    match r.get_u8()? {
        OP_USE => Ok(ResourceOperation::Use),
        OP_MANAGE => Ok(ResourceOperation::Manage),
        v => Err(FrameCodecError::UnknownDiscriminant {
            field: "operation",
            value: v,
        }),
    }
}

fn put_grant(out: &mut Vec<u8>, g: &UsageGrant) -> Result<(), FrameCodecError> {
    put_str(out, &g.principal)?;
    let n = u16::try_from(g.operations.len()).map_err(|_| FrameCodecError::ValueTooLong)?;
    put_u16(out, n);
    for op in &g.operations {
        put_operation(out, *op);
    }
    put_opt_u64(out, g.not_after_secs);
    Ok(())
}

fn get_grant(r: &mut Reader<'_>) -> Result<UsageGrant, FrameCodecError> {
    let principal = r.get_str()?;
    let n = r.get_u16()? as usize;
    let mut operations = Vec::with_capacity(n);
    for _ in 0..n {
        operations.push(get_operation(r)?);
    }
    let not_after_secs = r.get_opt_u64()?;
    Ok(UsageGrant {
        principal,
        operations,
        not_after_secs,
    })
}

fn put_resource_ref(out: &mut Vec<u8>, rr: &ResourceRef) -> Result<(), FrameCodecError> {
    put_str(out, &rr.workspace.0)?;
    put_str(out, rr.name.as_str())
}

fn get_resource_ref(r: &mut Reader<'_>) -> Result<ResourceRef, FrameCodecError> {
    use nexus_domain::WorkspaceId;
    let workspace = WorkspaceId::new(r.get_str()?);
    let name = ResourceName::new(r.get_str()?).map_err(|_| FrameCodecError::InvalidResourceName)?;
    Ok(ResourceRef::new(workspace, name))
}

fn put_discoverability(out: &mut Vec<u8>, d: &Discoverability) -> Result<(), FrameCodecError> {
    match d {
        Discoverability::Public => put_u8(out, DISC_PUBLIC),
        Discoverability::Restricted { principals } => {
            put_u8(out, DISC_RESTRICTED);
            let n = u16::try_from(principals.len()).map_err(|_| FrameCodecError::ValueTooLong)?;
            put_u16(out, n);
            for p in principals {
                put_str(out, p)?;
            }
        }
    }
    Ok(())
}

fn get_discoverability(r: &mut Reader<'_>) -> Result<Discoverability, FrameCodecError> {
    match r.get_u8()? {
        DISC_PUBLIC => Ok(Discoverability::Public),
        DISC_RESTRICTED => {
            let n = r.get_u16()? as usize;
            let mut principals = Vec::with_capacity(n);
            for _ in 0..n {
                principals.push(r.get_str()?);
            }
            Ok(Discoverability::Restricted { principals })
        }
        v => Err(FrameCodecError::UnknownDiscriminant {
            field: "discoverability",
            value: v,
        }),
    }
}

fn put_unavailability(
    out: &mut Vec<u8>,
    u: &Option<UnavailabilityReason>,
) -> Result<(), FrameCodecError> {
    match u {
        None => put_u8(out, 0),
        Some(reason) => {
            put_u8(out, 1);
            match reason {
                UnavailabilityReason::ProviderOffline => {
                    put_u8(out, UNAV_OFFLINE);
                    put_str(out, "")?;
                }
                UnavailabilityReason::HealthDegraded { detail } => {
                    put_u8(out, UNAV_DEGRADED);
                    put_str(out, detail)?;
                }
                UnavailabilityReason::NotAcceptingWork { reason } => {
                    put_u8(out, UNAV_NOT_ACCEPTING);
                    put_str(out, reason)?;
                }
            }
        }
    }
    Ok(())
}

fn get_unavailability(r: &mut Reader<'_>) -> Result<Option<UnavailabilityReason>, FrameCodecError> {
    match r.get_u8()? {
        0 => Ok(None),
        1 => {
            let reason = match r.get_u8()? {
                UNAV_OFFLINE => {
                    let _ = r.get_str()?; // 保留字段（恒空），向前兼容
                    UnavailabilityReason::ProviderOffline
                }
                UNAV_DEGRADED => UnavailabilityReason::HealthDegraded {
                    detail: r.get_str()?,
                },
                UNAV_NOT_ACCEPTING => UnavailabilityReason::NotAcceptingWork {
                    reason: r.get_str()?,
                },
                v => {
                    return Err(FrameCodecError::UnknownDiscriminant {
                        field: "unavailability",
                        value: v,
                    });
                }
            };
            Ok(Some(reason))
        }
        _ => Err(FrameCodecError::Truncated),
    }
}

fn put_ad(out: &mut Vec<u8>, ad: &ProviderAdvertisement) -> Result<(), FrameCodecError> {
    put_str(out, &ad.provider.0)?;
    put_str(out, &ad.resource.0)?;
    let n = u16::try_from(ad.capabilities.len()).map_err(|_| FrameCodecError::ValueTooLong)?;
    put_u16(out, n);
    for c in &ad.capabilities {
        put_str(out, c)?;
    }
    let n = u16::try_from(ad.locators.len()).map_err(|_| FrameCodecError::ValueTooLong)?;
    put_u16(out, n);
    for l in &ad.locators {
        put_str(out, l)?;
    }
    put_discoverability(out, &ad.discoverable_by)?;
    let n = u16::try_from(ad.use_grants.len()).map_err(|_| FrameCodecError::ValueTooLong)?;
    put_u16(out, n);
    for g in &ad.use_grants {
        put_grant(out, g)?;
    }
    put_unavailability(out, &ad.unavailable)?;
    put_u64(out, ad.issued_at_secs);
    put_u64(out, ad.ttl_secs);
    Ok(())
}

fn get_ad(r: &mut Reader<'_>) -> Result<ProviderAdvertisement, FrameCodecError> {
    let provider = ProviderId(r.get_str()?);
    let resource = ResourceId(r.get_str()?);
    let n = r.get_u16()? as usize;
    let mut capabilities = Vec::with_capacity(n);
    for _ in 0..n {
        capabilities.push(r.get_str()?);
    }
    let n = r.get_u16()? as usize;
    let mut locators = Vec::with_capacity(n);
    for _ in 0..n {
        locators.push(r.get_str()?);
    }
    let discoverable_by = get_discoverability(r)?;
    let n = r.get_u16()? as usize;
    let mut use_grants = Vec::with_capacity(n);
    for _ in 0..n {
        use_grants.push(get_grant(r)?);
    }
    let unavailable = get_unavailability(r)?;
    let issued_at_secs = r.get_u64()?;
    let ttl_secs = r.get_u64()?;
    Ok(ProviderAdvertisement {
        provider,
        resource,
        capabilities,
        locators,
        discoverable_by,
        use_grants,
        unavailable,
        issued_at_secs,
        ttl_secs,
    })
}

// ============================================================================
// 编解码入口
// ============================================================================

/// 编码控制帧：`u8 帧类型标签` + 字段（确定性、可移植、无新依赖）。
pub fn encode_control_frame(frame: &ControlFrame) -> Result<Vec<u8>, FrameCodecError> {
    let mut out = Vec::new();
    match frame {
        ControlFrame::ResourceAnnounce { ad } => {
            put_u8(&mut out, FRAME_RESOURCE_ANNOUNCE);
            put_ad(&mut out, ad)?;
        }
        ControlFrame::ResourceQuery {
            requester,
            resource,
        } => {
            put_u8(&mut out, FRAME_RESOURCE_QUERY);
            put_str(&mut out, &requester.0)?;
            put_str(&mut out, &resource.0)?;
        }
        ControlFrame::AuthGrant { announcement } => {
            put_u8(&mut out, FRAME_AUTH_GRANT);
            put_resource_ref(&mut out, &announcement.resource)?;
            put_grant(&mut out, &announcement.grant)?;
        }
        ControlFrame::AuthRevoke {
            resource,
            principal,
        } => {
            put_u8(&mut out, FRAME_AUTH_REVOKE);
            put_resource_ref(&mut out, resource)?;
            put_str(&mut out, principal)?;
        }
        ControlFrame::LeaseRenew {
            provider,
            resource,
            issued_at_secs,
            ttl_secs,
        } => {
            put_u8(&mut out, FRAME_LEASE_RENEW);
            put_str(&mut out, &provider.0)?;
            put_str(&mut out, &resource.0)?;
            put_u64(&mut out, *issued_at_secs);
            put_u64(&mut out, *ttl_secs);
        }
    }
    Ok(out)
}

/// 解码控制帧；空帧 / 未知标签 / 截断 / 非法 UTF-8 / 非法名字 /
/// 未知判别值 / 尾部多余字节一律返回类型化错误。
pub fn decode_control_frame(payload: &[u8]) -> Result<ControlFrame, FrameCodecError> {
    let Some(&tag) = payload.first() else {
        return Err(FrameCodecError::EmptyFrame);
    };
    let mut r = Reader::new(&payload[1..]);
    let frame = match tag {
        FRAME_RESOURCE_ANNOUNCE => ControlFrame::ResourceAnnounce {
            ad: get_ad(&mut r)?,
        },
        FRAME_RESOURCE_QUERY => {
            let requester = NodeId(r.get_str()?);
            let resource = ResourceId(r.get_str()?);
            ControlFrame::ResourceQuery {
                requester,
                resource,
            }
        }
        FRAME_AUTH_GRANT => {
            let resource = get_resource_ref(&mut r)?;
            let grant = get_grant(&mut r)?;
            ControlFrame::AuthGrant {
                announcement: GrantAnnouncement { resource, grant },
            }
        }
        FRAME_AUTH_REVOKE => {
            let resource = get_resource_ref(&mut r)?;
            let principal = r.get_str()?;
            ControlFrame::AuthRevoke {
                resource,
                principal,
            }
        }
        FRAME_LEASE_RENEW => {
            let provider = ProviderId(r.get_str()?);
            let resource = ResourceId(r.get_str()?);
            let issued_at_secs = r.get_u64()?;
            let ttl_secs = r.get_u64()?;
            ControlFrame::LeaseRenew {
                provider,
                resource,
                issued_at_secs,
                ttl_secs,
            }
        }
        other => return Err(FrameCodecError::UnknownFrameType(other)),
    };
    // 全部消费：尾部多余字节即帧格式违规。
    r.end()?;
    Ok(frame)
}

// ============================================================================
// 已认证通道（同一认证路径；不制造第二套认证）
// ============================================================================

/// 帧通道抽象（传输无关）：原始字节帧的收发。
///
/// 由组合根以 `nexus_transport::FrameStream` 适配装配，避免 registry →
/// transport 依赖边（架构策略；同 `nexus_service::ServiceTransport` 模式）。
pub trait ControlTransport {
    /// 发送一帧原始字节（调用方保证已通过认证门控）。
    fn send_bytes(&mut self, payload: &[u8]) -> Result<(), ChannelError>;
    /// 接收一帧原始字节。
    fn recv_bytes(&mut self) -> Result<Vec<u8>, ChannelError>;
}

/// 通道失败（类型化）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelError {
    /// 通道已关闭（对端断开 / 读写失败）。
    Closed,
    /// 控制帧编解码失败。
    Codec(FrameCodecError),
}

impl fmt::Display for ChannelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed => f.write_str("control channel closed"),
            Self::Codec(e) => write!(f, "control frame codec: {e}"),
        }
    }
}

impl std::error::Error for ChannelError {}

/// 已通过认证的对端（不透明证明）。
///
/// 构造前置条件：调用方必须先走**既有**认证门控——remote P0 用
/// `nexus_auth::verify_token`，N2 用 D6 ed25519 身份校验——并以校验出的
/// 主体字符串构造本类型。本模块不做认证、不定义第二套认证协议。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedPeer {
    principal: String,
}

impl AuthenticatedPeer {
    /// 以既有认证门控校验出的主体构造。
    #[must_use]
    pub fn new(principal: impl Into<String>) -> Self {
        Self {
            principal: principal.into(),
        }
    }

    /// 已认证主体（认证层定义的主体字符串，如 `"ed25519:<hex>"`）。
    #[must_use]
    pub fn principal(&self) -> &str {
        &self.principal
    }
}

/// 已认证的 N2 控制面通道：`ControlFrame` 的类型化收发。
///
/// 只能经 [`ControlChannel::established`] 构造——构造即要求
/// [`AuthenticatedPeer`]，类型层面不存在"未认证的控制通道"。
/// 认证本身发生在构造之前、调用方的既有门控里（见 `AuthenticatedPeer`）。
pub struct ControlChannel {
    transport: Box<dyn ControlTransport>,
    peer: AuthenticatedPeer,
}

impl ControlChannel {
    /// 在已通过既有认证门控的通道上建立控制面（`peer` 来自该门控的校验结果）。
    #[must_use]
    pub fn established(transport: Box<dyn ControlTransport>, peer: AuthenticatedPeer) -> Self {
        Self { transport, peer }
    }

    /// 对端已认证主体。
    #[must_use]
    pub fn peer(&self) -> &AuthenticatedPeer {
        &self.peer
    }

    /// 发送一帧控制帧（编码后经底层通道发送）。
    pub fn send_frame(&mut self, frame: &ControlFrame) -> Result<(), ChannelError> {
        let bytes = encode_control_frame(frame).map_err(ChannelError::Codec)?;
        self.transport.send_bytes(&bytes)
    }

    /// 接收并解码一帧控制帧。
    pub fn recv_frame(&mut self) -> Result<ControlFrame, ChannelError> {
        let bytes = self.transport.recv_bytes()?;
        decode_control_frame(&bytes).map_err(ChannelError::Codec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Registry;
    use nexus_domain::{ResourceName, WorkspaceId};
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::rc::Rc;

    fn rich_ad() -> ProviderAdvertisement {
        ProviderAdvertisement {
            provider: ProviderId("node-b".into()),
            resource: ResourceId("res-svc".into()),
            capabilities: vec!["service-session".into(), "exec".into()],
            locators: vec!["tcp://10.0.0.2:9000".into()],
            discoverable_by: Discoverability::Restricted {
                principals: vec!["ed25519:aa".into(), "ed25519:bb".into()],
            },
            use_grants: vec![
                UsageGrant {
                    principal: "ed25519:aa".into(),
                    operations: vec![ResourceOperation::Use, ResourceOperation::Manage],
                    not_after_secs: Some(9_999_999),
                },
                UsageGrant {
                    principal: "ed25519:bb".into(),
                    operations: vec![],
                    not_after_secs: None,
                },
            ],
            unavailable: Some(UnavailabilityReason::HealthDegraded {
                detail: "cpu_saturated".into(),
            }),
            issued_at_secs: 5_000,
            ttl_secs: 300,
        }
    }

    fn name_ref() -> ResourceRef {
        ResourceRef::new(
            WorkspaceId::new("ws1"),
            ResourceName::new("dev-web").unwrap(),
        )
    }

    #[test]
    fn roundtrip_all_five_frame_types() {
        let frames = [
            ControlFrame::ResourceAnnounce { ad: rich_ad() },
            ControlFrame::ResourceQuery {
                requester: NodeId("node-a".into()),
                resource: ResourceId("res-svc".into()),
            },
            ControlFrame::AuthGrant {
                announcement: GrantAnnouncement {
                    resource: name_ref(),
                    grant: UsageGrant {
                        principal: "ed25519:cc".into(),
                        operations: vec![ResourceOperation::Use],
                        not_after_secs: Some(7_777),
                    },
                },
            },
            ControlFrame::AuthRevoke {
                resource: name_ref(),
                principal: "ed25519:cc".into(),
            },
            ControlFrame::LeaseRenew {
                provider: ProviderId("node-b".into()),
                resource: ResourceId("res-svc".into()),
                issued_at_secs: 5_300,
                ttl_secs: 300,
            },
        ];
        for frame in &frames {
            let bytes = encode_control_frame(frame).expect("encode ok");
            // 显式类型前缀：首字节即帧类型标签（不靠内容猜）。
            assert!(bytes[0] >= 0x21 && bytes[0] <= 0x25, "tag in 0x21..=0x25");
            let back = decode_control_frame(&bytes).expect("decode ok");
            assert_eq!(&back, frame, "round-trip");
        }
        // 三种不可用原因各自 round-trip。
        for reason in [
            UnavailabilityReason::ProviderOffline,
            UnavailabilityReason::HealthDegraded { detail: "x".into() },
            UnavailabilityReason::NotAcceptingWork { reason: "y".into() },
        ] {
            let mut ad = rich_ad();
            ad.unavailable = Some(reason.clone());
            let f = ControlFrame::ResourceAnnounce { ad };
            let back = decode_control_frame(&encode_control_frame(&f).unwrap()).unwrap();
            assert_eq!(back, f);
        }
        // discoverable_by 两种形态 round-trip。
        for d in [
            Discoverability::Public,
            Discoverability::Restricted { principals: vec![] },
        ] {
            let mut ad = rich_ad();
            ad.discoverable_by = d;
            let f = ControlFrame::ResourceAnnounce { ad };
            assert_eq!(
                decode_control_frame(&encode_control_frame(&f).unwrap()).unwrap(),
                f
            );
        }
    }

    #[test]
    fn decode_rejects_malformed_frames() {
        assert_eq!(decode_control_frame(&[]), Err(FrameCodecError::EmptyFrame));
        assert_eq!(
            decode_control_frame(&[0x99]),
            Err(FrameCodecError::UnknownFrameType(0x99))
        );
        // 截断：合法帧砍掉最后一个字节。
        let full = encode_control_frame(&ControlFrame::LeaseRenew {
            provider: ProviderId("p".into()),
            resource: ResourceId("r".into()),
            issued_at_secs: 1,
            ttl_secs: 2,
        })
        .unwrap();
        assert_eq!(
            decode_control_frame(&full[..full.len() - 1]),
            Err(FrameCodecError::Truncated)
        );
        // 尾部多余字节。
        let mut trailing = full.clone();
        trailing.push(0x00);
        assert_eq!(
            decode_control_frame(&trailing),
            Err(FrameCodecError::TrailingBytes)
        );
        // 非法 UTF-8：QUERY 帧的 requester 字段塞入非法字节。
        let mut bad_utf8 = vec![FRAME_RESOURCE_QUERY, 0, 1, 0xFF];
        bad_utf8.extend_from_slice(&[0, 1, b'x']);
        assert_eq!(
            decode_control_frame(&bad_utf8),
            Err(FrameCodecError::InvalidUtf8)
        );
        // 未知判别值：ANNOUNCE 帧的 discoverability 字段写非法值。
        // 构造最小 ANNOUNCE：tag + provider("") + resource("") + caps(0) + locators(0)
        // + discoverability(0x7F 非法)。
        let mut bad_disc = vec![FRAME_RESOURCE_ANNOUNCE];
        for _ in 0..4 {
            bad_disc.extend_from_slice(&[0, 0]);
        }
        bad_disc.push(0x7F);
        assert_eq!(
            decode_control_frame(&bad_disc),
            Err(FrameCodecError::UnknownDiscriminant {
                field: "discoverability",
                value: 0x7F
            })
        );
        // 非法资源名：AUTH_REVOKE 的 name 含空格（ResourceName 字符集拒绝）。
        let mut bad_name = vec![FRAME_AUTH_REVOKE];
        bad_name.extend_from_slice(&[0, 3, b'w', b's', b'1']); // workspace
        bad_name.extend_from_slice(&[0, 8, b'b', b'a', b'd', b' ', b'n', b'a', b'm', b'e']); // name
        bad_name.extend_from_slice(&[0, 1, b'p']); // principal
        assert_eq!(
            decode_control_frame(&bad_name),
            Err(FrameCodecError::InvalidResourceName)
        );
    }

    #[test]
    fn human_readable_name_never_goes_on_wire() {
        // D2：名字解析与广告传输分离——QUERY 帧只带不透明 Id。
        let frame = ControlFrame::ResourceQuery {
            requester: NodeId("node-a".into()),
            resource: ResourceId("res-9f2".into()),
        };
        let bytes = encode_control_frame(&frame).unwrap();
        let as_lossy = String::from_utf8_lossy(&bytes);
        assert!(
            !as_lossy.contains("dev-web"),
            "人类可读名不得出现在传输字节里"
        );
        assert!(as_lossy.contains("res-9f2"), "不透明 Id 在传输字节里");
    }

    #[test]
    fn auth_revoke_carries_provider_namespaced_ref_exception() {
        // P0-4 D2 例外：AUTH_REVOKE 的 ResourceRef 是提供方命名空间内的
        // grant 表键（人类可运维），不是地址解析键——名字在此帧是合法的。
        // 与 human_readable_name_never_goes_on_wire 的边界：QUERY 不得带名
        //（寻址路径），REVOKE 可带名（授权公告路径，请求方只做本地关联）。
        let frame = ControlFrame::AuthRevoke {
            resource: name_ref(),
            principal: "ed25519:abc".into(),
        };
        let bytes = encode_control_frame(&frame).unwrap();
        let as_lossy = String::from_utf8_lossy(&bytes);
        // name_ref() 的 workspace/name 出现在字节里（例外，非违反）。
        assert!(
            as_lossy.contains("ws1"),
            "provider 命名空间 workspace 在帧里"
        );
        assert!(
            as_lossy.contains("dev-web"),
            "provider 命名空间 name 在帧里"
        );
        // roundtrip：解码回的仍是 ResourceRef（非不透明 Id）。
        match decode_control_frame(&bytes).unwrap() {
            ControlFrame::AuthRevoke {
                resource,
                principal,
            } => {
                assert_eq!(resource, name_ref());
                assert_eq!(principal, "ed25519:abc");
            }
            other => panic!("expected AuthRevoke, got {other:?}"),
        }
    }

    // ---------- 内存双工通道（测试替身；portable crate 内无 I/O） ----------

    #[derive(Clone)]
    struct MemChannel {
        inbox: Rc<RefCell<VecDeque<Vec<u8>>>>,
        peer_inbox: Rc<RefCell<VecDeque<Vec<u8>>>>,
        closed: Rc<RefCell<bool>>,
    }

    impl MemChannel {
        fn close(&self) {
            *self.closed.borrow_mut() = true;
        }
    }

    fn channel_pair() -> (MemChannel, MemChannel) {
        let a_in = Rc::new(RefCell::new(VecDeque::new()));
        let b_in = Rc::new(RefCell::new(VecDeque::new()));
        let closed = Rc::new(RefCell::new(false));
        (
            MemChannel {
                inbox: Rc::clone(&a_in),
                peer_inbox: Rc::clone(&b_in),
                closed: Rc::clone(&closed),
            },
            MemChannel {
                inbox: b_in,
                peer_inbox: a_in,
                closed,
            },
        )
    }

    impl ControlTransport for MemChannel {
        fn send_bytes(&mut self, payload: &[u8]) -> Result<(), ChannelError> {
            if *self.closed.borrow() {
                return Err(ChannelError::Closed);
            }
            self.peer_inbox.borrow_mut().push_back(payload.to_vec());
            Ok(())
        }

        fn recv_bytes(&mut self) -> Result<Vec<u8>, ChannelError> {
            self.inbox
                .borrow_mut()
                .pop_front()
                .ok_or(ChannelError::Closed)
        }
    }

    #[test]
    fn query_announce_exchange_over_authenticated_channel() {
        // 请求方：本地名 → Id（本地解析），经已认证通道查询。
        let (client_t, server_t) = channel_pair();
        let mut client =
            ControlChannel::established(Box::new(client_t), AuthenticatedPeer::new("ed25519:aa"));
        let mut server =
            ControlChannel::established(Box::new(server_t), AuthenticatedPeer::new("ed25519:aa"));
        assert_eq!(client.peer().principal(), "ed25519:aa");

        client
            .send_frame(&ControlFrame::ResourceQuery {
                requester: NodeId("node-a".into()),
                resource: ResourceId("res-svc".into()),
            })
            .unwrap();

        // 提供方：收到查询，按请求方主体过滤可见广告后回公告。
        let mut provider_registry = Registry::new();
        provider_registry.publish_ad(rich_ad(), 5_000).unwrap();
        match server.recv_frame().unwrap() {
            ControlFrame::ResourceQuery {
                requester,
                resource,
            } => {
                assert_eq!(requester.0, "node-a");
                for ad in provider_registry.lookup_visible_ads(
                    &resource,
                    server.peer().principal(),
                    5_100,
                ) {
                    server
                        .send_frame(&ControlFrame::ResourceAnnounce { ad })
                        .unwrap();
                }
            }
            other => panic!("unexpected frame: {other:?}"),
        }

        // 请求方：收到公告，缓存进本地 Registry（TTL 由广告携带）。
        let mut requester_registry = Registry::new();
        match client.recv_frame().unwrap() {
            ControlFrame::ResourceAnnounce { ad } => {
                requester_registry.publish_ad(ad, 5_100).unwrap();
            }
            other => panic!("unexpected frame: {other:?}"),
        }
        let got = requester_registry.lookup_visible_ads(
            &ResourceId("res-svc".into()),
            "ed25519:aa",
            5_100,
        );
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].provider.0, "node-b");
        assert_eq!(
            got[0].unavailable.as_ref().unwrap().as_str(),
            "HealthDegraded"
        );
    }

    #[test]
    fn lease_renew_refreshes_cached_advertisement() {
        let (client_t, server_t) = channel_pair();
        let mut client =
            ControlChannel::established(Box::new(client_t), AuthenticatedPeer::new("ed25519:aa"));
        let mut server =
            ControlChannel::established(Box::new(server_t), AuthenticatedPeer::new("ed25519:aa"));

        let mut cache = Registry::new();
        cache.publish_ad(rich_ad(), 5_000).unwrap(); // ttl=300 → 5300 过期

        // 续期帧到达前：5300 已过期。
        assert!(
            cache
                .lookup_ads(&ResourceId("res-svc".into()), 5_300)
                .is_empty()
        );

        server
            .send_frame(&ControlFrame::LeaseRenew {
                provider: ProviderId("node-b".into()),
                resource: ResourceId("res-svc".into()),
                issued_at_secs: 5_250,
                ttl_secs: 300,
            })
            .unwrap();
        match client.recv_frame().unwrap() {
            ControlFrame::LeaseRenew {
                provider,
                resource,
                issued_at_secs,
                ttl_secs,
            } => {
                // 请求方用续期刷新缓存广告的 issued_at/ttl（幂等覆盖）。
                let mut ads = cache.lookup_ads(&resource, 0); // now=0：取全部再按 key 找
                let slot = ads
                    .iter_mut()
                    .find(|a| a.provider == provider)
                    .expect("cached ad");
                slot.issued_at_secs = issued_at_secs;
                slot.ttl_secs = ttl_secs;
                cache.publish_ad(slot.clone(), issued_at_secs).unwrap();
            }
            other => panic!("unexpected frame: {other:?}"),
        }
        assert_eq!(
            cache.lookup_ads(&ResourceId("res-svc".into()), 5_300).len(),
            1,
            "续期后 5300 仍有效（新 ttl 到 5550）"
        );
    }

    #[test]
    fn channel_propagates_codec_error_and_closed() {
        let (client_t, mut server_t) = channel_pair();
        // 服务端直接塞非法字节（未认证的垃圾 / 损坏帧）。
        server_t.send_bytes(&[0x99]).unwrap();
        let mut client = ControlChannel::established(
            Box::new(client_t.clone()),
            AuthenticatedPeer::new("ed25519:aa"),
        );
        assert_eq!(
            client.recv_frame(),
            Err(ChannelError::Codec(FrameCodecError::UnknownFrameType(0x99)))
        );
        // 通道关闭透出 Closed。
        client_t.close();
        let mut client2 =
            ControlChannel::established(Box::new(client_t), AuthenticatedPeer::new("ed25519:aa"));
        assert_eq!(client2.recv_frame(), Err(ChannelError::Closed));
    }
}
