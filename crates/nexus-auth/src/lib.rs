//! nexus-auth
//!
//! 定义 Resource Authorization、Principal 与类型化权限判定。
//!
//! remote P0 冻结契约：预共享 Token 门控（scenarios/product/remote_service_access_flow.toml）；
//! 认证门控发生在业务帧转发之前（W7：未认证帧不得进入业务处理）。
//! 本模块纯校验、无 I/O、保持 portable（harness.toml `[portable_core]` WASI check 覆盖）。
//!
//! 详细边界见同目录 `MODULE.md`。

#![forbid(unsafe_code)]

use std::fmt;

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
