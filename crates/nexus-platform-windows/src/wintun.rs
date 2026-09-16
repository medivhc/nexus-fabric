//! # wintun.dll 窄 C ABI 绑定（本 crate 唯一的 unsafe 模块）
//!
//! 设计（吸收三标杆报告 W3）：
//! - 运行时动态加载 `wintun.dll`（`LoadLibraryW`/`GetProcAddress`），不静态
//!   链接、不提交二进制；签名 dll 由部署环境自 wintun.net 提供。
//! - 函数指针表按 wintun.h 0.14 ABI 声明；只解析本模块需要的最小函数集，
//!   缺任一必需符号即整体失败（结构化 `PlatformError::Io`）。
//! - **Safety Invariant**：`WintunModule` 持有 `HMODULE` 所有权；其 Drop
//!   （`FreeLibrary`）必须在所有借用该模块函数指针的句柄（Adapter/Session）
//!   释放之后发生。`WintunVpiAdapter` 以字段顺序保证：
//!   `EndSession → CloseAdapter → FreeAdapter → (module Drop: FreeLibrary)`。
//! - 本模块之外不扩散 unsafe；包长校验、错误映射等逻辑为纯函数，可单测。

use nexus_platform::PlatformError;
use std::ffi::c_void;
use std::io;

/// Windows `HANDLE` / `HMODULE`。
type Handle = *mut c_void;

// --- 窄系统绑定：仅 kernel32 的三个动态加载函数（手写 extern，不引入第三方） ---

unsafe extern "system" {
    /// kernel32!LoadLibraryW：加载 DLL 并返回模块句柄；失败返回 NULL。
    fn LoadLibraryW(lp_file_name: *const u16) -> Handle;
    /// kernel32!GetProcAddress：按名称解析导出函数；失败返回 NULL。
    fn GetProcAddress(h_module: Handle, lp_proc_name: *const u8) -> *mut c_void;
    /// kernel32!FreeLibrary：释放模块引用；返回 0 表示失败（模块仍被引用）。
    fn FreeLibrary(h_lib_module: Handle) -> i32;
}

// --- wintun.h 0.14 窄 ABI：函数指针类型（WINAPI = stdcall） ---

/// `WintunCreateAdapter(LPCWSTR Name, LPCWSTR TunnelType, const GUID* RequestedGUID)`。
type CreateAdapterFn = unsafe extern "system" fn(*const u16, *const u16, *const c_void) -> Handle;
/// `WintunOpenAdapter(LPCWSTR Name)`。
type OpenAdapterFn = unsafe extern "system" fn(*const u16) -> Handle;
/// `WintunCloseAdapter(HANDLE Adapter)`。
type CloseAdapterFn = unsafe extern "system" fn(Handle);
/// `WintunFreeAdapter(HANDLE Adapter) -> DWORD`（0 成功）。
type FreeAdapterFn = unsafe extern "system" fn(Handle) -> u32;
/// `WintunStartSession(HANDLE Adapter, DWORD Capacity) -> HANDLE`。
type StartSessionFn = unsafe extern "system" fn(Handle, u32) -> Handle;
/// `WintunEndSession(HANDLE Session)`。
type EndSessionFn = unsafe extern "system" fn(Handle);
/// `WintunReceivePacket(HANDLE Session, BYTE** Packet) -> DWORD`（0 = 无包）。
type ReceivePacketFn = unsafe extern "system" fn(Handle, *mut *mut u8) -> u32;
/// `WintunReleaseReceivePacket(HANDLE Session, BYTE* Packet)`。
type ReleaseReceivePacketFn = unsafe extern "system" fn(Handle, *mut u8);
/// `WintunAllocateSendPacket(HANDLE Session, DWORD PacketSize) -> BYTE*`。
type AllocateSendPacketFn = unsafe extern "system" fn(Handle, u32) -> *mut u8;
/// `WintunSendPacket(HANDLE Session, BYTE* Packet)`。
type SendPacketFn = unsafe extern "system" fn(Handle, *mut u8);
/// `WintunGetRunningDriverVersion() -> DWORD`（0 = 驱动未加载）。
type GetRunningDriverVersionFn = unsafe extern "system" fn() -> u32;

/// 已解析的 wintun 函数指针表（全部为必需符号，构造时保证非空）。
#[derive(Clone, Copy, Debug)]
pub(crate) struct WintunApi {
    pub create_adapter: CreateAdapterFn,
    pub open_adapter: OpenAdapterFn,
    pub close_adapter: CloseAdapterFn,
    pub free_adapter: FreeAdapterFn,
    pub start_session: StartSessionFn,
    pub end_session: EndSessionFn,
    pub receive_packet: ReceivePacketFn,
    pub release_receive_packet: ReleaseReceivePacketFn,
    pub allocate_send_packet: AllocateSendPacketFn,
    pub send_packet: SendPacketFn,
    pub get_running_driver_version: GetRunningDriverVersionFn,
}

/// wintun 会话最小环形缓冲容量（wintun.h `WINTUN_MIN_RING_CAPACITY`）。
pub(crate) const MIN_RING_CAPACITY: u32 = 0x20000;

/// 已加载的 wintun 模块（持有 `HMODULE`，Drop 时 `FreeLibrary`）。
pub(crate) struct WintunModule {
    handle: Handle,
    api: WintunApi,
}

// SAFETY：WintunApi 是纯函数指针（可 Send）；WintunModule 只用于同一线程的
// 会话生命周期，FreeLibrary 与句柄使用由 WintunVpiAdapter 的 Drop 顺序保证。
// 因此不实现 Send/Sync（默认 !Send/!Sync 正确：句柄不得跨线程并发使用）。
impl WintunModule {
    /// 加载 wintun.dll 并解析必需符号。
    pub(crate) fn load() -> Result<Self, PlatformError> {
        let handle = load_library()?;
        let api = match build_api(|name| unsafe {
            // SAFETY: handle 为有效模块句柄；GetProcAddress 仅读取导出表。
            GetProcAddress(handle, name.as_ptr())
        }) {
            Ok(api) => api,
            Err(e) => {
                unsafe {
                    // SAFETY: handle 有效；释放本次加载的模块引用。
                    FreeLibrary(handle);
                }
                return Err(e);
            }
        };
        Ok(WintunModule { handle, api })
    }

    /// 只读访问函数指针表。
    pub(crate) fn api(&self) -> &WintunApi {
        &self.api
    }
}

impl Drop for WintunModule {
    fn drop(&mut self) {
        // SAFETY: 本模块持有句柄所有权；调用方（WintunVpiAdapter::drop）保证
        // 所有 Adapter/Session 句柄已先行释放，此后不再使用这些函数指针。
        unsafe {
            FreeLibrary(self.handle);
        }
    }
}

/// 加载 wintun.dll（从系统 DLL 搜索路径）。
fn load_library() -> Result<Handle, PlatformError> {
    let name: Vec<u16> = "wintun.dll\0".encode_utf16().collect();
    let handle = unsafe {
        // SAFETY: name 为 NUL 结尾的 UTF-16 字面量；返回值要么有效要么 NULL。
        LoadLibraryW(name.as_ptr())
    };
    if handle.is_null() {
        return Err(io_error("LoadLibraryW(wintun.dll)"));
    }
    Ok(handle)
}

/// 从模块句柄逐项解析必需符号；任一缺失返回 `PlatformError::Io`。
/// 独立为纯函数（注入加载器）以便单测：`loader` 只做按名查址。
fn build_api(loader: impl Fn(&[u8]) -> *mut c_void) -> Result<WintunApi, PlatformError> {
    macro_rules! resolve {
        ($field:ident, $symbol:literal) => {{
            let ptr = loader(concat!($symbol, "\0").as_bytes());
            if ptr.is_null() {
                return Err(PlatformError::Io {
                    operation: concat!("GetProcAddress(", $symbol, ")").to_string(),
                    message: "required wintun export missing".to_string(),
                });
            }
            unsafe {
                // SAFETY: 指针来自 GetProcAddress 且非空；按 wintun.h 声明的
                // stdcall 函数类型转写。符号存在性由上述检查保证。
                std::mem::transmute::<*mut c_void, $field>(ptr)
            }
        }};
    }
    Ok(WintunApi {
        create_adapter: resolve!(CreateAdapterFn, "WintunCreateAdapter"),
        open_adapter: resolve!(OpenAdapterFn, "WintunOpenAdapter"),
        close_adapter: resolve!(CloseAdapterFn, "WintunCloseAdapter"),
        free_adapter: resolve!(FreeAdapterFn, "WintunFreeAdapter"),
        start_session: resolve!(StartSessionFn, "WintunStartSession"),
        end_session: resolve!(EndSessionFn, "WintunEndSession"),
        receive_packet: resolve!(ReceivePacketFn, "WintunReceivePacket"),
        release_receive_packet: resolve!(ReleaseReceivePacketFn, "WintunReleaseReceivePacket"),
        allocate_send_packet: resolve!(AllocateSendPacketFn, "WintunAllocateSendPacket"),
        send_packet: resolve!(SendPacketFn, "WintunSendPacket"),
        get_running_driver_version: resolve!(
            GetRunningDriverVersionFn,
            "WintunGetRunningDriverVersion"
        ),
    })
}

/// 将最后一次 Windows 错误映射为结构化 `PlatformError::Io`。
pub(crate) fn io_error(operation: &str) -> PlatformError {
    PlatformError::Io {
        operation: operation.to_string(),
        message: io::Error::last_os_error().to_string(),
    }
}

/// 把宽字符名编码为 NUL 结尾的 UTF-16（纯函数，供 create/open 使用）。
pub(crate) fn encode_wstring(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// 运行中的驱动版本（0 = 驱动未加载；纯只读探测）。
pub(crate) fn running_driver_version(api: &WintunApi) -> u32 {
    unsafe {
        // SAFETY: api 为已解析有效指针；无参数，返回 DWORD。
        (api.get_running_driver_version)()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vpi::MAX_PACKET_SIZE;
    use std::ffi::c_void;

    /// 合成可寻址假指针（非空即可，测试不调用）。
    fn fake_ptr() -> *mut c_void {
        std::ptr::dangling_mut::<c_void>()
    }

    /// 全部符号可解析 → Ok。
    #[test]
    fn build_api_all_symbols_ok() {
        let api = build_api(|_| fake_ptr()).expect("all symbols resolve");
        assert_eq!(
            std::mem::size_of::<WintunApi>(),
            std::mem::size_of::<[usize; 11]>()
        );
        let _ = api.create_adapter;
    }

    /// 任一必需符号缺失 → Err(Io) 且不 panic。
    #[test]
    fn build_api_missing_symbol_fails() {
        let err = build_api(|name| {
            if name.starts_with(b"WintunReceivePacket") {
                std::ptr::null_mut()
            } else {
                fake_ptr()
            }
        })
        .expect_err("missing export must fail");
        match err {
            PlatformError::Io { operation, .. } => {
                assert!(operation.contains("WintunReceivePacket"))
            }
            other => panic!("expected Io, got {other:?}"),
        }
    }

    /// 空 loader（模块加载失败路径的符号侧）→ Err。
    #[test]
    fn build_api_null_loader_fails() {
        let _ = build_api(|_| std::ptr::null_mut()).expect_err("no symbols");
    }

    #[test]
    fn encode_wstring_nul_terminated() {
        let w = encode_wstring("wg0");
        assert_eq!(w, vec![b'w' as u16, b'g' as u16, b'0' as u16, 0]);
    }

    #[test]
    fn ring_capacity_and_packet_size_constants() {
        // 与 wintun.h 常量一致（防 ABI 回归）。
        assert_eq!(MIN_RING_CAPACITY, 0x20000);
        assert_eq!(MAX_PACKET_SIZE, 0xFFFF);
    }
}
