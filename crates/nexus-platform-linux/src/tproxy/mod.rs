//! TPROXY 透明前端（Linux adapter）。
//!
//! 本模块是 `IP_TRANSPARENT` / `IP_RECVORIGDSTADDR` / `IP_PKTINFO` 的唯一
//! 落点（spec §9.1 / §12.1 AC-LAYER-01）。core（`nexus-projection`）只接收
//! 已 accept 的流/数据报与原始目的地，不出现任何 unsafe 或系统调用。

pub mod sockaddr;
pub mod tcp;

pub use tcp::{TproxyTcpConfig, TproxyTcpListener};

/// Linux `IP_TRANSPARENT`（uapi/linux/in.h；libc 未导出）。
pub(crate) const IP_TRANSPARENT: libc::c_int = 19;
/// Linux `IP_ORIGDSTADDR`（ancillary cmsg type）。
pub(crate) const IP_ORIGDSTADDR: libc::c_int = 20;
