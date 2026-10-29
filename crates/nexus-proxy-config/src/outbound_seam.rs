//! 出站身份/离线交接词汇（spec §2.2 接缝 ②，2026-10-28 P2 自 nexus-connectivity 下沉）。
//!
//! 本模块只承载"出站是谁 + 能否离线承接某个 locator"的身份语义：
//! 不选择出站、不发起任何网络 I/O、不持有 socket。数据面拨号属 daemon 侧
//! `OutboundDialer`（`nexusd` 本地、`pub(crate)`），与本模块分层不同、不得合并。

/// 出站交接结果（离线 DTO，零真实网络）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundHandoff {
    /// 出站 kind 标签（"direct" / "relay" / "shadowsocks"）。
    pub kind: String,
    /// 出站 tag。
    pub tag: String,
    /// 物理目标 locator。
    pub locator: String,
}

/// 出站交接错误（本接缝自有错误面；不引用任何运行时错误类型）。
///
/// `InvalidLocator` 为签名预留的稳定变体：当前 6 个实现均不产生错误
/// （离线交接不校验可达性），保留变体以保证错误面稳定，不做静默删除。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboundHandoffError {
    /// 目标 locator 无效/为空。
    InvalidLocator {
        /// 目标 locator。
        locator: String,
    },
}

/// 出站 adapter：一种真实出站协议实现的领域中立接缝。
///
/// Deletion Test（AGENTS.md §12）：Shadowsocks 是首个带真实 AEAD 加解密的出站，
/// 与仅做可达性探测的 Direct/Relay 构成独立变化维度。
pub trait OutboundAdapter {
    /// 稳定出站 kind 标签。
    fn outbound_kind(&self) -> &'static str;
    /// 出站标识 tag。
    fn tag(&self) -> &str;
    /// 离线交接：确认该 adapter 可承接目标 locator（不发起真实网络）。
    fn handoff(&self, locator: &str) -> Result<OutboundHandoff, OutboundHandoffError>;
}
