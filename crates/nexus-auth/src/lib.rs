//! nexus-auth
//!
//! 定义 Resource Authorization、Principal 与类型化权限判定。
//!
//! remote P0 冻结契约：预共享 Token 门控（scenarios/product/remote_service_access_flow.toml）；
//! 认证门控发生在业务帧转发之前（W7：未认证帧不得进入业务处理）。
//! 本模块纯校验、无 I/O、保持 portable（harness.toml `[portable_core]` WASI check 覆盖）。
//!
//! N2 P0（D6，PRODUCT §16.5）：双向身份（ed25519）＋本地 grant 表。
//! - `Principal` 由握手验证过的 ed25519 公钥内容派生
//!   （[`Principal::from_ed25519_public_key`]），**不接受请求方自称**（硬约束）；
//! - 授权判定在 provider 侧每次建 Session 时执行，"目录返回≠有权限"；
//! - **拒绝 PSK**：N2 授权路径不接受预共享秘密；`verify_token` 仅服务于冻结的
//!   N1 remote-host 场景（`daemon-real-host-*`），不得用于 N2 资源授权；
//! - TOFU 显式化：[`TrustStore::check`] 对未知节点返回 `UnknownFirstSeen`，
//!   永不静默学习（与 `nexus-connectivity` 的 N1 静默 TOFU 区分）；
//! - 每次判定 exactly-once 写审计记录（[`AuditSink`]）。
//!
//! 详细边界见同目录 `MODULE.md`。

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::fmt;

use nexus_domain::{
    AuthorizationDecision, DenyReason, NodeId, ResourceOperation, ResourceRef, WorkspaceId,
};
use sha2::{Digest, Sha256};

/// 预共享令牌（remote P0 门控；完整握手后置）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreSharedToken(pub String);

/// 认证通过后的主体标识。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal(pub String);

/// 认证失败（冻结契约：单变体）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    /// 令牌不匹配。
    Unauthorized,
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unauthorized => f.write_str("authorization denied: token mismatch"),
        }
    }
}

impl std::error::Error for AuthError {}

/// 校验预共享令牌（冻结契约）。
///
/// 使用常量时间比较（长度 XOR + 逐字节 XOR，不因前缀/长度差异提前返回），
/// 避免时序侧信道泄露令牌信息；失败结构化返回 `AuthError::Unauthorized`。
///
/// P0 为单主体语义：通过校验即视为持有预共享令牌的可信主体；
/// 多主体映射与完整握手后置。
pub fn verify_token(
    token: &PreSharedToken,
    expected: &PreSharedToken,
) -> Result<Principal, AuthError> {
    let a = token.0.as_bytes();
    let b = expected.0.as_bytes();
    let mut diff = a.len() ^ b.len();
    let n = a.len().max(b.len());
    for i in 0..n {
        diff |= usize::from(a.get(i).copied().unwrap_or(0) ^ b.get(i).copied().unwrap_or(0));
    }
    if diff == 0 {
        Ok(Principal("authenticated".to_string()))
    } else {
        Err(AuthError::Unauthorized)
    }
}

// ============================================================================
// N2 P0（D6）：ed25519 双向身份 ＋ 本地 grant 表
// ============================================================================

/// Principal 派生方案标识（审计 / 日志前缀）。
pub const PRINCIPAL_SCHEME: &str = "ed25519";

/// 由 ed25519 公钥内容派生 [`Principal`]。
///
/// 方案：`ed25519:<hex(SHA-256(pubkey)[..16])>`，与
/// `IdentityManager::peer_id_of` 同构（不引入注册中心，D6）。
/// 调用方必须传入**握手已验证**的公钥；本函数不做签名校验，
/// "不接受请求方自称"由调用链保证（provider 侧握手层）。
fn derive_principal(ed25519_public_key: &[u8; 32]) -> Principal {
    let mut hasher = Sha256::new();
    hasher.update(ed25519_public_key);
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(32);
    for b in &digest[..16] {
        use fmt::Write;
        let _ = write!(hex, "{b:02x}");
    }
    Principal(format!("{PRINCIPAL_SCHEME}:{hex}"))
}

impl Principal {
    /// 由握手验证过的 ed25519 公钥派生主体标识（D6 硬约束入口）。
    #[must_use]
    pub fn from_ed25519_public_key(public_key: &[u8; 32]) -> Self {
        derive_principal(public_key)
    }
}

/// 授权请求（provider 侧每次建 Session 时构造；principal 来自握手密钥）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthRequest {
    /// 请求发生的 workspace 上下文。
    pub workspace: WorkspaceId,
    /// 目标资源引用。
    pub resource: ResourceRef,
    /// 握手派生的主体（非自称）。
    pub principal: Principal,
    /// 请求的操作。
    pub operation: ResourceOperation,
}

/// 本地授权表条目（D6）：`{resource, principal, operations, not_after}`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    pub resource: ResourceRef,
    pub principal: Principal,
    pub operations: Vec<ResourceOperation>,
    /// 过期时间（unix 秒）；`None` = 永不过期。
    pub not_after: Option<u64>,
    /// 显式撤销标记（tombstone：撤销后仍可区分 `Revoked` 与 `NoSuchGrant`）。
    pub revoked: bool,
}

impl Grant {
    #[must_use]
    pub fn new(
        resource: ResourceRef,
        principal: Principal,
        operations: Vec<ResourceOperation>,
        not_after: Option<u64>,
    ) -> Self {
        Self {
            resource,
            principal,
            operations,
            not_after,
            revoked: false,
        }
    }
}

/// 单次授权判定的审计记录（每次判定 exactly-once 写入）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecord {
    /// 判定时间（unix 秒，由调用方时钟提供；本模块无 I/O/时钟）。
    pub at_unix: u64,
    pub workspace: WorkspaceId,
    pub resource: ResourceRef,
    pub principal: Principal,
    pub operation: ResourceOperation,
    pub decision: AuthorizationDecision,
}

/// 审计落点抽象（Deletion Test：内存测试替身 vs daemon 文件落盘实现
/// ——P0-4 经 `FileKvStore::journal_append` 落盘，为两个独立变化维度）。
pub trait AuditSink {
    /// 记录一次判定（exactly-once；实现必须同步落盘或同步入队）。
    fn record(&mut self, record: AuditRecord);
}

/// 内存审计槽（测试 / 嵌入式调用方）。
#[derive(Debug, Default)]
pub struct VecAuditSink {
    pub records: Vec<AuditRecord>,
}

impl VecAuditSink {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl AuditSink for VecAuditSink {
    fn record(&mut self, record: AuditRecord) {
        self.records.push(record);
    }
}

/// 本地 grant 表（内存态；持久化由组合根经 `FileKvStore` 负责，本模块无 I/O）。
#[derive(Debug, Default)]
pub struct GrantTable {
    grants: Vec<Grant>,
}

impl GrantTable {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 插入/覆盖（以 `(resource, principal)` 为键的 upsert）。
    pub fn upsert(&mut self, grant: Grant) {
        if let Some(slot) = self
            .grants
            .iter_mut()
            .find(|g| g.resource == grant.resource && g.principal == grant.principal)
        {
            *slot = grant;
        } else {
            self.grants.push(grant);
        }
    }

    /// 显式撤销（tombstone；返回是否命中）。
    pub fn revoke(&mut self, resource: &ResourceRef, principal: &Principal) -> bool {
        if let Some(g) = self
            .grants
            .iter_mut()
            .find(|g| &g.resource == resource && &g.principal == principal)
        {
            g.revoked = true;
            true
        } else {
            false
        }
    }

    /// 授权判定（D6）：provider 侧每次建 Session 时调用。
    ///
    /// 判定顺序固定（拒绝原因精确化）：
    /// 1. 无 `(resource, principal)` grant → `NoSuchGrant`；
    /// 2. grant.workspace ≠ 请求 workspace → `WrongWorkspace`；
    /// 3. grant 被撤销 → `Revoked`；
    /// 4. `not_after` 已过 → `Expired`；
    /// 5. operation ∉ grant.operations → `OperationNotGranted`；
    /// 6. 否则 `Allow`。
    ///
    /// 无论 Allow/Deny 都向 `sink` 写 exactly-once 审计记录。
    pub fn authorize(
        &self,
        req: &AuthRequest,
        now_unix: u64,
        sink: &mut dyn AuditSink,
    ) -> AuthorizationDecision {
        let decision = self.decide(req, now_unix);
        sink.record(AuditRecord {
            at_unix: now_unix,
            workspace: req.workspace.clone(),
            resource: req.resource.clone(),
            principal: req.principal.clone(),
            operation: req.operation,
            decision: decision.clone(),
        });
        decision
    }

    /// 判定内核（纯函数，无 I/O）。
    fn decide(&self, req: &AuthRequest, now_unix: u64) -> AuthorizationDecision {
        // P1-17：`ResourceRef` 的 `PartialEq` 含 workspace，若直接按
        // `g.resource == req.resource` 查找，跨 workspace 请求会在 find 阶段
        // 就落成 `NoSuchGrant`，`WrongWorkspace` 变成死路径。先按
        // `(name, principal)` 找，同名不同 workspace 显式比出 `WrongWorkspace`；
        // 存在精确匹配时行为与旧实现完全一致（按 `(resource, principal)` 命中优先）。
        let exact = self
            .grants
            .iter()
            .find(|g| g.resource == req.resource && g.principal == req.principal);
        let grant = match exact.or_else(|| {
            self.grants
                .iter()
                .find(|g| g.resource.name == req.resource.name && g.principal == req.principal)
        }) {
            Some(g) => g,
            None => return AuthorizationDecision::Deny(DenyReason::NoSuchGrant),
        };
        if grant.resource.workspace != req.workspace {
            return AuthorizationDecision::Deny(DenyReason::WrongWorkspace {
                expected: grant.resource.workspace.clone(),
                actual: req.workspace.clone(),
            });
        }
        if grant.revoked {
            return AuthorizationDecision::Deny(DenyReason::Revoked);
        }
        if let Some(not_after) = grant.not_after {
            if now_unix >= not_after {
                return AuthorizationDecision::Deny(DenyReason::Expired {
                    not_after,
                    now: now_unix,
                });
            }
        }
        if !grant.operations.contains(&req.operation) {
            return AuthorizationDecision::Deny(DenyReason::OperationNotGranted {
                operation: req.operation,
            });
        }
        AuthorizationDecision::Allow
    }
}

/// 显式 TOFU 判定（D6：首次见未知节点提示用户确认，不静默）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustVerdict {
    /// 已知且公钥一致。
    Trusted,
    /// 首次见到该 NodeId：调用方必须提示用户确认后方可 `trust`。
    UnknownFirstSeen { node_id: NodeId },
    /// 公钥与已信任记录不一致（可能的中间人/顶替）：拒绝。
    IdentityChanged,
}

/// 节点信任表（内存态；`check` 永不自动学习，学习必须经显式 `trust`）。
#[derive(Debug, Default)]
pub struct TrustStore {
    peers: HashMap<String, Vec<u8>>,
}

impl TrustStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 校验节点身份：已知→比对；未知→`UnknownFirstSeen`（不学习）。
    pub fn check(&self, node_id: &NodeId, public_key: &[u8]) -> TrustVerdict {
        match self.peers.get(&node_id.0) {
            None => TrustVerdict::UnknownFirstSeen {
                node_id: node_id.clone(),
            },
            Some(known) if known.as_slice() == public_key => TrustVerdict::Trusted,
            Some(_) => TrustVerdict::IdentityChanged,
        }
    }

    /// 显式信任（用户确认后调用；覆盖旧记录即轮换）。
    pub fn trust(&mut self, node_id: NodeId, public_key: Vec<u8>) {
        self.peers.insert(node_id.0, public_key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_domain::ResourceName;

    fn wid(s: &str) -> WorkspaceId {
        WorkspaceId::new(s)
    }

    fn rref(ws: &str, name: &str) -> ResourceRef {
        ResourceRef::new(wid(ws), ResourceName::new(name).unwrap())
    }

    fn principal(byte: u8) -> Principal {
        Principal::from_ed25519_public_key(&[byte; 32])
    }

    fn req(ws: &str, name: &str, p: Principal, op: ResourceOperation) -> AuthRequest {
        AuthRequest {
            workspace: wid(ws),
            resource: rref(ws, name),
            principal: p,
            operation: op,
        }
    }

    #[test]
    fn principal_derivation_is_stable_and_schemed() {
        let a = Principal::from_ed25519_public_key(&[7u8; 32]);
        let b = Principal::from_ed25519_public_key(&[7u8; 32]);
        let c = Principal::from_ed25519_public_key(&[8u8; 32]);
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert!(a.0.starts_with("ed25519:"));
        // 32 hex 字符（SHA-256 前 16 字节），与 peer_id_of 同构。
        assert_eq!(a.0.len(), "ed25519:".len() + 32);
    }

    #[test]
    fn authorize_allow_and_audit_written() {
        let mut table = GrantTable::new();
        let p = principal(1);
        table.upsert(Grant::new(
            rref("default", "svc"),
            p.clone(),
            vec![ResourceOperation::Use],
            None,
        ));
        let mut sink = VecAuditSink::new();
        let d = table.authorize(
            &req("default", "svc", p.clone(), ResourceOperation::Use),
            1000,
            &mut sink,
        );
        assert_eq!(d, AuthorizationDecision::Allow);
        assert_eq!(sink.records.len(), 1);
        let rec = &sink.records[0];
        assert_eq!(rec.decision, AuthorizationDecision::Allow);
        assert_eq!(rec.principal, p);
        assert_eq!(rec.at_unix, 1000);
    }

    #[test]
    fn authorize_no_such_grant() {
        let table = GrantTable::new();
        let mut sink = VecAuditSink::new();
        let d = table.authorize(
            &req("default", "svc", principal(9), ResourceOperation::Use),
            1000,
            &mut sink,
        );
        assert_eq!(d, AuthorizationDecision::Deny(DenyReason::NoSuchGrant));
        assert_eq!(sink.records.len(), 1);
        assert_eq!(
            sink.records[0].decision,
            AuthorizationDecision::Deny(DenyReason::NoSuchGrant)
        );
    }

    #[test]
    fn authorize_wrong_workspace() {
        let mut table = GrantTable::new();
        let p = principal(2);
        table.upsert(Grant::new(
            rref("ws-a", "svc"),
            p.clone(),
            vec![ResourceOperation::Use],
            None,
        ));
        let mut sink = VecAuditSink::new();
        // 请求 workspace 与 grant 的 workspace 不一致。
        let mut r = req("ws-a", "svc", p, ResourceOperation::Use);
        r.workspace = wid("ws-b");
        let d = table.authorize(&r, 1000, &mut sink);
        assert!(matches!(
            d,
            AuthorizationDecision::Deny(DenyReason::WrongWorkspace { .. })
        ));
        assert_eq!(sink.records.len(), 1);
    }

    #[test]
    fn wrong_workspace_is_reachable_when_resource_ref_differs_in_workspace() {
        // P1-17 回归：`ResourceRef` 的 `PartialEq` 含 workspace，旧实现用
        // `g.resource == req.resource` 查找 → 跨 workspace 请求在 find 阶段
        // 就落成 NoSuchGrant，`WrongWorkspace` 是死路径。这里请求的
        // `req.resource.workspace` 与 `req.workspace` 都不同于 grant，验证
        // 生产可达的分支。
        let mut table = GrantTable::new();
        let p = principal(21);
        table.upsert(Grant::new(
            rref("ws-a", "svc"),
            p.clone(),
            vec![ResourceOperation::Use],
            None,
        ));
        let mut sink = VecAuditSink::new();
        let r = AuthRequest {
            workspace: wid("ws-b"),
            resource: rref("ws-b", "svc"),
            principal: p,
            operation: ResourceOperation::Use,
        };
        let d = table.authorize(&r, 1000, &mut sink);
        match d {
            AuthorizationDecision::Deny(DenyReason::WrongWorkspace { expected, actual }) => {
                assert_eq!(expected, wid("ws-a"));
                assert_eq!(actual, wid("ws-b"));
            }
            other => panic!("expected WrongWorkspace, got {other:?}"),
        }
        assert_eq!(sink.records.len(), 1);
    }

    #[test]
    fn exact_workspace_match_still_wins_over_cross_workspace_grant() {
        // P1-17：精确匹配优先——同名同 principal 在两个 workspace 各有一条时，
        // 请求哪个就用哪个，不被另一条挤成 WrongWorkspace。
        let mut table = GrantTable::new();
        let p = principal(22);
        table.upsert(Grant::new(
            rref("ws-a", "svc"),
            p.clone(),
            vec![ResourceOperation::Manage],
            None,
        ));
        table.upsert(Grant::new(
            rref("ws-b", "svc"),
            p.clone(),
            vec![ResourceOperation::Use],
            None,
        ));
        let mut sink = VecAuditSink::new();
        assert_eq!(
            table.authorize(
                &req("ws-a", "svc", p.clone(), ResourceOperation::Manage),
                1000,
                &mut sink
            ),
            AuthorizationDecision::Allow
        );
        assert_eq!(
            table.authorize(
                &req("ws-b", "svc", p, ResourceOperation::Use),
                1000,
                &mut sink
            ),
            AuthorizationDecision::Allow
        );
        // 第三个 workspace：存在同名同 principal 的 grant 但不在该 workspace →
        // WrongWorkspace（而非 NoSuchGrant）。
        let r = AuthRequest {
            workspace: wid("ws-c"),
            resource: rref("ws-c", "svc"),
            principal: principal(22),
            operation: ResourceOperation::Use,
        };
        assert!(matches!(
            table.authorize(&r, 1000, &mut sink),
            AuthorizationDecision::Deny(DenyReason::WrongWorkspace {
                expected,
                ..
            }) if expected == wid("ws-a")
        ));
    }

    #[test]
    fn revoked_is_produced_after_explicit_revoke() {
        // P1-14：`Grant.revoked` tombstone 是 `DenyReason::Revoked` 的唯一
        // 生产来源（`nexus grant revoke`）。撤销后判定必须是 Revoked 而非
        // NoSuchGrant——否则审计里"撤销"与"从未授权"不可区分。
        let mut table = GrantTable::new();
        let p = principal(31);
        table.upsert(Grant::new(
            rref("default", "svc"),
            p.clone(),
            vec![ResourceOperation::Use],
            None,
        ));
        let mut sink = VecAuditSink::new();
        assert!(table.revoke(&rref("default", "svc"), &p));
        assert_eq!(
            table.authorize(
                &req("default", "svc", p, ResourceOperation::Use),
                1000,
                &mut sink
            ),
            AuthorizationDecision::Deny(DenyReason::Revoked)
        );
        assert_eq!(
            sink.records[0].decision,
            AuthorizationDecision::Deny(DenyReason::Revoked)
        );
    }

    #[test]
    fn authorize_expired_and_revoked() {
        let mut table = GrantTable::new();
        let p = principal(3);
        table.upsert(Grant::new(
            rref("default", "svc"),
            p.clone(),
            vec![ResourceOperation::Use],
            Some(100),
        ));
        let mut sink = VecAuditSink::new();
        let d = table.authorize(
            &req("default", "svc", p.clone(), ResourceOperation::Use),
            200,
            &mut sink,
        );
        assert!(matches!(
            d,
            AuthorizationDecision::Deny(DenyReason::Expired { .. })
        ));
        // 未过期则放行。
        let d = table.authorize(
            &req("default", "svc", p.clone(), ResourceOperation::Use),
            50,
            &mut sink,
        );
        assert_eq!(d, AuthorizationDecision::Allow);
        // 显式撤销后为 Revoked（非 NoSuchGrant）。
        assert!(table.revoke(&rref("default", "svc"), &p));
        let d = table.authorize(
            &req("default", "svc", p, ResourceOperation::Use),
            50,
            &mut sink,
        );
        assert_eq!(d, AuthorizationDecision::Deny(DenyReason::Revoked));
        assert_eq!(sink.records.len(), 3);
    }

    #[test]
    fn authorize_operation_not_granted() {
        let mut table = GrantTable::new();
        let p = principal(4);
        table.upsert(Grant::new(
            rref("default", "svc"),
            p.clone(),
            vec![ResourceOperation::Use],
            None,
        ));
        let mut sink = VecAuditSink::new();
        let d = table.authorize(
            &req("default", "svc", p, ResourceOperation::Manage),
            1000,
            &mut sink,
        );
        assert_eq!(
            d,
            AuthorizationDecision::Deny(DenyReason::OperationNotGranted {
                operation: ResourceOperation::Manage
            })
        );
    }

    #[test]
    fn upsert_overwrites_grant() {
        let mut table = GrantTable::new();
        let p = principal(5);
        table.upsert(Grant::new(
            rref("default", "svc"),
            p.clone(),
            vec![ResourceOperation::Use],
            None,
        ));
        table.upsert(Grant::new(
            rref("default", "svc"),
            p.clone(),
            vec![ResourceOperation::Manage],
            None,
        ));
        let mut sink = VecAuditSink::new();
        // 旧 operations 被覆盖：Use 不再被授予。
        let d = table.authorize(
            &req("default", "svc", p, ResourceOperation::Use),
            1000,
            &mut sink,
        );
        assert!(matches!(
            d,
            AuthorizationDecision::Deny(DenyReason::OperationNotGranted { .. })
        ));
    }

    #[test]
    fn trust_store_never_learns_silently() {
        let mut store = TrustStore::new();
        let id = NodeId::new("abc123");
        // 首次见：UnknownFirstSeen，不自动信任。
        assert_eq!(
            store.check(&id, &[1u8; 32]),
            TrustVerdict::UnknownFirstSeen {
                node_id: id.clone()
            }
        );
        // 未经 trust 再次 check：仍然未知。
        assert!(matches!(
            store.check(&id, &[1u8; 32]),
            TrustVerdict::UnknownFirstSeen { .. }
        ));
        // 用户确认后显式 trust。
        store.trust(id.clone(), vec![1u8; 32]);
        assert_eq!(store.check(&id, &[1u8; 32]), TrustVerdict::Trusted);
        // 公钥变化 → IdentityChanged（拒绝）。
        assert_eq!(store.check(&id, &[2u8; 32]), TrustVerdict::IdentityChanged);
    }

    #[test]
    fn legacy_psk_gate_still_frozen() {
        // N1 remote-host 冻结契约保持可用（daemon-real-host-* 场景依赖）。
        let ok = verify_token(
            &PreSharedToken("tk-ok".into()),
            &PreSharedToken("tk-ok".into()),
        );
        assert!(ok.is_ok());
        let err = verify_token(
            &PreSharedToken("tk-wrong".into()),
            &PreSharedToken("tk-ok".into()),
        );
        assert_eq!(err, Err(AuthError::Unauthorized));
    }
}
