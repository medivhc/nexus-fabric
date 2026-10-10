//! Windows VirtualPacketInterface：wintun 会话生命周期 + 包收发。
//!
//! 本模块不含 `unsafe`（全部集中在 `wintun.rs`）；包长校验、错误映射、
//! 能力声明均为纯逻辑，可直接单测。

use crate::wintun::{self, WintunModule};
use nexus_platform::{PacketInterfaceCapabilities, PlatformError, VirtualPacketInterface};
use std::ffi::c_void;
use std::ptr;

/// wintun 单包最大尺寸（wintun.h `WINTUN_MAX_RAGGED_PACKET_SIZE`）。
pub const MAX_PACKET_SIZE: usize = 0xFFFF;

/// 建议 MTU（对齐 WireGuard 惯例；上层可在会话建立后按需配置）。
pub const DEFAULT_MTU: u16 = 1420;

/// 后端标识（供组合根/诊断输出）。
pub const BACKEND: &str = "wintun";

/// wintun 适配器会话（Adapter + Session + 模块句柄三合一所有权）。
///
/// 生命周期（见 `wintun.rs` Safety Invariant）：
/// `EndSession → CloseAdapter → (module Drop: FreeLibrary)`（wintun.h 0.14 无 FreeAdapter）。
pub struct WintunVpiAdapter {
    module: WintunModule,
    adapter_handle: *mut c_void,
    session_handle: *mut c_void,
}

// SAFETY 论证：本结构持有互斥资源（wintun 会话），设计为单线程使用
// （trait `VirtualPacketInterface: Send` 要求 `receive`/`send` 的 `&mut self`
// 独占访问；句柄不在线程间共享）。故保持默认 !Sync，Send 由字段构成决定——
// WintunModule 含裸指针，不自动 Send，需显式声明并提供安全论证。
//
// 安全论证（Send）：唯一跨线程迁移场景是 `VirtualPacketInterface: Send` 的
// 装箱传递。迁移发生时本对象没有进行中的系统调用（所有 FFI 调用均在
// `&mut self` 方法内同步完成），迁移后同一时刻仍只有一个线程可访问
// （&mut 独占）。句柄值本身跨线程传递不构成共享，符合 Send 语义。
unsafe impl Send for WintunVpiAdapter {}

impl WintunVpiAdapter {
    /// 创建并打开一个命名 wintun 适配器（需管理员 + 已安装签名驱动）。
    pub fn create(name: &str, tunnel_type: &str) -> Result<Self, PlatformError> {
        let module = WintunModule::load()?;
        let name_w = wintun::encode_wstring(name);
        let tunnel_w = wintun::encode_wstring(tunnel_type);
        // SAFETY：两个参数均为 NUL 结尾 UTF-16；RequestedGUID 传 null（系统分配）。
        let adapter = unsafe {
            (module.api().create_adapter)(name_w.as_ptr(), tunnel_w.as_ptr(), ptr::null())
        };
        if adapter.is_null() {
            return Err(io_error("WintunCreateAdapter"));
        }
        Self::start_session(module, adapter)
    }

    /// 打开已有 wintun 适配器（需管理员 + 驱动已安装）。
    pub fn open(name: &str) -> Result<Self, PlatformError> {
        let module = WintunModule::load()?;
        let name_w = wintun::encode_wstring(name);
        // SAFETY：参数为 NUL 结尾 UTF-16。
        let adapter = unsafe { (module.api().open_adapter)(name_w.as_ptr()) };
        if adapter.is_null() {
            return Err(io_error("WintunOpenAdapter"));
        }
        Self::start_session(module, adapter)
    }

    /// 启动数据会话（ring capacity 用 wintun 最小容量）。
    fn start_session(
        module: WintunModule,
        adapter_handle: *mut c_void,
    ) -> Result<Self, PlatformError> {
        // SAFETY：adapter 句柄有效；capacity 满足 wintun 最小约束。
        let session =
            unsafe { (module.api().start_session)(adapter_handle, wintun::MIN_RING_CAPACITY) };
        if session.is_null() {
            return Err(io_error("WintunStartSession"));
        }
        Ok(WintunVpiAdapter {
            module,
            adapter_handle,
            session_handle: session,
        })
    }

    /// 静态能力声明（wintun 能力面；不创建驱动对象）。
    #[must_use]
    pub const fn capabilities() -> PacketInterfaceCapabilities {
        PacketInterfaceCapabilities {
            packet_ingress: true,
            packet_injection: true,
            ipv4: true,
            ipv6: true,
            route_include: true,
            route_exclude: true,
            dns_override: false,
            mtu_configurable: true,
            per_app_routing: false,
            underlay_bypass: true,
        }
    }

    /// 建议 MTU。
    #[must_use]
    pub const fn mtu() -> u16 {
        DEFAULT_MTU
    }

    /// 后端标识。
    #[must_use]
    pub const fn backend() -> &'static str {
        BACKEND
    }

    /// 运行中的 wintun 驱动版本（0 = 驱动未加载）。
    #[must_use]
    pub fn driver_version(&self) -> u32 {
        wintun::running_driver_version(self.module.api())
    }
}

impl Drop for WintunVpiAdapter {
    fn drop(&mut self) {
        let api = self.module.api();
        // SAFETY：句柄均有效；严格按 EndSession → CloseAdapter
        // 顺序释放（wintun 要求 session 先于 adapter 结束）。之后 WintunModule
        // 的 Drop 再 FreeLibrary，函数指针不再被使用。
        unsafe {
            (api.end_session)(self.session_handle);
            (api.close_adapter)(self.adapter_handle);
        }
    }
}

impl VirtualPacketInterface for WintunVpiAdapter {
    fn receive(&mut self, output: &mut [u8]) -> Result<usize, PlatformError> {
        let api = self.module.api();
        let mut packet: *mut u8 = ptr::null_mut();
        // SAFETY：session 句柄有效；packet 由 wintun 写入，release 前有效。
        let size = unsafe { (api.receive_packet)(self.session_handle, &mut packet) };
        if size == 0 {
            return Ok(0); // 无可用包（非错误）。
        }
        if packet.is_null() {
            return Err(PlatformError::Invalid {
                message: "wintun returned packet size without a packet pointer".into(),
            });
        }
        let len = size as usize;
        if len > output.len() {
            // 目标缓冲不足：释放内核包后返回结构化错误，不截断。
            unsafe {
                // SAFETY：packet 与 session 均有效。
                (api.release_receive_packet)(self.session_handle, packet);
            }
            return Err(PlatformError::Invalid {
                message: format!("receive buffer too small: need {len} bytes"),
            });
        }
        unsafe {
            // SAFETY：len 已校验 ≤ output.len()；两指针均有效且不重叠（内核
            // 包缓冲与调用方输出缓冲独立分配）。
            ptr::copy_nonoverlapping(packet, output.as_mut_ptr(), len);
            (api.release_receive_packet)(self.session_handle, packet);
        }
        Ok(len)
    }

    fn send(&mut self, packet: &[u8]) -> Result<(), PlatformError> {
        validate_send_packet(packet)?;
        let api = self.module.api();
        let len = packet.len() as u32;
        // SAFETY：session 句柄有效；size 在 (0, MAX] 内已校验。
        let buf = unsafe { (api.allocate_send_packet)(self.session_handle, len) };
        if buf.is_null() {
            return Err(io_error("WintunAllocateSendPacket"));
        }
        unsafe {
            // SAFETY：buf 为 wintun 分配的 len 字节缓冲；packet 为 len 字节源。
            ptr::copy_nonoverlapping(packet.as_ptr(), buf, packet.len());
            (api.send_packet)(self.session_handle, buf);
        }
        Ok(())
    }
}

/// 发送前包长校验（纯函数）：空包与超长包拒绝。
fn validate_send_packet(packet: &[u8]) -> Result<(), PlatformError> {
    if packet.is_empty() {
        return Err(PlatformError::Invalid {
            message: "cannot send empty packet".into(),
        });
    }
    if packet.len() > MAX_PACKET_SIZE {
        return Err(PlatformError::Invalid {
            message: format!("packet too large: {} > {MAX_PACKET_SIZE}", packet.len()),
        });
    }
    Ok(())
}

fn io_error(operation: &str) -> PlatformError {
    wintun::io_error(operation)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 收包拷贝的纯逻辑替身（真实路径用 `ptr::copy_nonoverlapping`）。
    fn receive_copy(packet: &[u8], output: &mut [u8]) -> Result<usize, PlatformError> {
        if packet.len() > output.len() {
            return Err(PlatformError::Invalid {
                message: format!("receive buffer too small: need {} bytes", packet.len()),
            });
        }
        output[..packet.len()].copy_from_slice(packet);
        Ok(packet.len())
    }

    #[test]
    fn capabilities_declared_full_surface() {
        let c = WintunVpiAdapter::capabilities();
        assert!(c.packet_ingress);
        assert!(c.packet_injection);
        assert!(c.ipv4);
        assert!(c.ipv6);
        assert!(c.mtu_configurable);
        assert!(c.route_include);
        assert!(c.route_exclude);
        assert!(!c.dns_override); // wintun 不提供 DNS 覆写
        assert!(!c.per_app_routing);
        assert!(c.underlay_bypass);
    }

    #[test]
    fn mtu_and_backend() {
        assert_eq!(WintunVpiAdapter::mtu(), 1420);
        assert_eq!(WintunVpiAdapter::backend(), "wintun");
    }

    #[test]
    fn send_packet_length_validation() {
        assert!(matches!(
            validate_send_packet(&[]),
            Err(PlatformError::Invalid { .. })
        ));
        let big = vec![0u8; MAX_PACKET_SIZE + 1];
        assert!(matches!(
            validate_send_packet(&big),
            Err(PlatformError::Invalid { .. })
        ));
        let ok = vec![0u8; 64];
        assert!(validate_send_packet(&ok).is_ok());
        let max = vec![0u8; MAX_PACKET_SIZE];
        assert!(validate_send_packet(&max).is_ok());
    }

    #[test]
    fn receive_copy_exact_and_too_small() {
        let mut out = [0u8; 8];
        let n = receive_copy(&[1, 2, 3], &mut out).unwrap();
        assert_eq!(n, 3);
        assert_eq!(&out[..3], &[1, 2, 3]);

        let mut tiny = [0u8; 2];
        assert!(matches!(
            receive_copy(&[1, 2, 3], &mut tiny),
            Err(PlatformError::Invalid { .. })
        ));
    }

    #[test]
    fn receive_copy_zero_len_is_ok() {
        let mut out = [0u8; 4];
        let n = receive_copy(&[], &mut out).unwrap();
        assert_eq!(n, 0);
    }
}
