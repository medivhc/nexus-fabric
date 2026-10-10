//! # WinINET 系统代理窄 FFI（PRODUCT §13）
//!
//! 读写 `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`：
//! `ProxyEnable`(DWORD) / `ProxyServer`(REG_SZ)，并经 wininet 的
//! `InternetSetOptionW` 广播设置变更（否则注册表改了不生效）。
//!
//! - **Safety Invariant**：本模块是 crate 内第二个允许 `unsafe` 的模块（与
//!   `wintun.rs` 并列）。所有 `unsafe` 都集中在对 advapi32/wininet 的窄 extern
//!   调用点；入参指针由本模块持有其背后的 Rust 缓冲生命周期，句柄在每处调用后
//!   立即 `RegCloseKey`（不跨函数传播裸 HKEY）。
//! - 错误映射：非 0 `LSTATUS` / `FALSE` 返回 `PlatformError::Io`（保留 win32 错误码）。
//! - 业务逻辑（宽字符串转换、DWORD→bool、读回比较）为纯函数，可单测，不碰注册表。

use nexus_platform::{PlatformError, SystemProxyController, SystemProxyState};
#[cfg(windows)]
use std::ffi::c_void;

// --- 类型与常量（winreg.h / wininet.h 窄子集） ---

#[cfg(windows)]
type HKey = *mut c_void;
#[cfg(windows)]
type LStatus = i32;
#[cfg(windows)]
/// `HKEY_CURRENT_USER` 伪句柄。
const HKEY_CURRENT_USER: HKey = 0x8000_0001usize as HKey;
#[cfg(windows)]
const KEY_SET_VALUE: u32 = 0x0002;
#[cfg(windows)]
const KEY_READ: u32 = 0x20019;
#[cfg(windows)]
const REG_SZ: u32 = 1;
#[cfg(windows)]
const ERROR_SUCCESS: i32 = 0;
#[cfg(windows)]
const INTERNET_OPTION_SETTINGS_CHANGED: u32 = 39;
#[cfg(windows)]
const INTERNET_OPTION_REFRESH: u32 = 37;

#[cfg(windows)]
/// Internet Settings 子键（相对 HKCU）。
const SUBKEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

#[cfg(windows)]
#[link(name = "advapi32")]
unsafe extern "system" {
    fn RegOpenKeyExW(
        h_key: HKey,
        lp_sub_key: *const u16,
        ul_options: u32,
        sam_desired: u32,
        phk_result: *mut HKey,
    ) -> LStatus;
    fn RegQueryValueExW(
        h_key: HKey,
        lp_value_name: *const u16,
        lp_reserved: *mut u32,
        lp_type: *mut u32,
        lp_data: *mut u8,
        lpcb_data: *mut u32,
    ) -> LStatus;
    fn RegSetValueExW(
        h_key: HKey,
        lp_value_name: *const u16,
        reserved: u32,
        dw_type: u32,
        lp_data: *const u8,
        cb_data: u32,
    ) -> LStatus;
    fn RegCloseKey(h_key: HKey) -> LStatus;
}

#[cfg(windows)]
#[link(name = "wininet")]
unsafe extern "system" {
    fn InternetSetOptionW(
        h_internet: HKey,
        dw_option: u32,
        lp_buffer: *mut c_void,
        dw_buffer_length: u32,
    ) -> i32;
}

#[cfg(any(windows, test))]
/// 把 Rust 字符串转为以 NUL 结尾的宽字符向量。
fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(any(windows, test))]
/// 把 `Vec<u16>`（可能含末尾 NUL）转成 Rust String，丢弃尾部 NUL。
fn from_wide_nul(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

#[cfg(windows)]
fn reg_error(op: &str, code: LStatus) -> PlatformError {
    PlatformError::Io {
        operation: op.to_string(),
        message: format!("winerror {code}"),
    }
}

/// Windows 注册表 + WinINET 通知实现的 `SystemProxyController`。
#[derive(Debug, Default, Clone, Copy)]
pub struct WinInetSystemProxy;

#[cfg(windows)]
impl WinInetSystemProxy {
    /// 创建一个控制器（无内部状态；每次调用都直接读写注册表）。
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// 打开 Internet Settings 键（按所需权限）。调用方负责 CloseKey。
    fn open_key(sam: u32) -> Result<HKey, PlatformError> {
        let subkey = to_wide(SUBKEY);
        let mut hkey: HKey = std::ptr::null_mut();
        // SAFETY: HKEY_CURRENT_USER 是合法伪句柄；subkey 是 NUL 结尾宽串；
        // phk_result 指向本栈变量。失败时不写 phk_result。
        let status =
            unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, subkey.as_ptr(), 0, sam, &mut hkey) };
        if status != ERROR_SUCCESS {
            return Err(reg_error("RegOpenKeyExW", status));
        }
        Ok(hkey)
    }

    /// 读一个 DWORD 值；不存在返回 None。
    fn query_dword(hkey: HKey, name: &str) -> Result<Option<u32>, PlatformError> {
        let wname = to_wide(name);
        let mut ty: u32 = 0;
        let mut value: u32 = 0;
        let mut size: u32 = std::mem::size_of::<u32>() as u32;
        // SAFETY: hkey 由 open_key 持有；wname NUL 结尾；value/size 是本栈变量。
        let status = unsafe {
            RegQueryValueExW(
                hkey,
                wname.as_ptr(),
                std::ptr::null_mut(),
                &mut ty,
                &mut value as *mut u32 as *mut u8,
                &mut size,
            )
        };
        const ERROR_FILE_NOT_FOUND: LStatus = 2;
        match status {
            ERROR_SUCCESS => Ok(Some(value)),
            ERROR_FILE_NOT_FOUND => Ok(None),
            other => Err(reg_error("RegQueryValueExW", other)),
        }
    }

    /// 读一个 REG_SZ 值；不存在返回 None。
    fn query_string(hkey: HKey, name: &str) -> Result<Option<String>, PlatformError> {
        let wname = to_wide(name);
        let mut ty: u32 = 0;
        let mut size: u32 = 0;
        // 第一次调用取所需缓冲大小。
        // SAFETY: hkey 有效；其余参数 NULL/栈变量。
        let status = unsafe {
            RegQueryValueExW(
                hkey,
                wname.as_ptr(),
                std::ptr::null_mut(),
                &mut ty,
                std::ptr::null_mut(),
                &mut size,
            )
        };
        const ERROR_FILE_NOT_FOUND: LStatus = 2;
        match status {
            ERROR_FILE_NOT_FOUND => return Ok(None),
            ERROR_SUCCESS => {}
            other => return Err(reg_error("RegQueryValueExW", other)),
        }
        let len_chars = (size as usize) / 2;
        let mut buf = vec![0u16; len_chars.max(1)];
        let mut actual = size;
        // SAFETY: hkey 有效；buf 容量 >= actual/2 个 u16；wname NUL 结尾。
        let status = unsafe {
            RegQueryValueExW(
                hkey,
                wname.as_ptr(),
                std::ptr::null_mut(),
                &mut ty,
                buf.as_mut_ptr().cast(),
                &mut actual,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(reg_error("RegQueryValueExW", status));
        }
        let s = from_wide_nul(&buf);
        Ok(if s.is_empty() { None } else { Some(s) })
    }

    /// 写 DWORD 值。
    fn set_dword(hkey: HKey, name: &str, value: u32) -> Result<(), PlatformError> {
        let wname = to_wide(name);
        // SAFETY: hkey 有效；wname NUL 结尾；value 是 u32 所有权数据。
        let status = unsafe {
            RegSetValueExW(
                hkey,
                wname.as_ptr(),
                0,
                4, // REG_DWORD
                &value as *const u32 as *const u8,
                std::mem::size_of::<u32>() as u32,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(reg_error("RegSetValueExW(DWORD)", status));
        }
        Ok(())
    }

    /// 写 REG_SZ 值（None 时不写，由调用方决定语义）。
    fn set_string(hkey: HKey, name: &str, value: &str) -> Result<(), PlatformError> {
        let wname = to_wide(name);
        let wvalue = to_wide(value); // 含末尾 NUL
        // SAFETY: hkey 有效；wname/wvalue NUL 结尾；cb 含末尾 NUL 字节数。
        let status = unsafe {
            RegSetValueExW(
                hkey,
                wname.as_ptr(),
                0,
                REG_SZ,
                wvalue.as_ptr().cast(),
                (wvalue.len() * 2) as u32,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(reg_error("RegSetValueExW(SZ)", status));
        }
        Ok(())
    }
}

#[cfg(windows)]
impl SystemProxyController for WinInetSystemProxy {
    fn snapshot(&self) -> Result<SystemProxyState, PlatformError> {
        let hkey = Self::open_key(KEY_READ)?;
        let result = (|| {
            let enabled = Self::query_dword(hkey, "ProxyEnable")?.unwrap_or(0) != 0;
            let server = Self::query_string(hkey, "ProxyServer")?;
            Ok::<_, PlatformError>(SystemProxyState { enabled, server })
        })();
        // SAFETY: hkey 来自 open_key，必须成对关闭。
        let _ = unsafe { RegCloseKey(hkey) };
        result
    }

    fn apply(&self, enabled: bool, server: Option<&str>) -> Result<(), PlatformError> {
        let hkey = Self::open_key(KEY_READ | KEY_SET_VALUE)?;
        let result = (|| {
            Self::set_dword(hkey, "ProxyEnable", u32::from(enabled))?;
            // 仅在提供 server 时写 ProxyServer；clear 路径保留既有 server 值。
            if let Some(srv) = server {
                Self::set_string(hkey, "ProxyServer", srv)?;
            }
            Ok::<_, PlatformError>(())
        })();
        // SAFETY: hkey 来自 open_key，必须成对关闭。
        let _ = unsafe { RegCloseKey(hkey) };
        result?;
        self.refresh()
    }

    fn refresh(&self) -> Result<(), PlatformError> {
        // SAFETY: NULL hInternet 表示系统级设置；dwOption 为固定常量；
        // lpBuffer=NULL/length=0 对这两个 option 合法。
        let ok1 = unsafe {
            InternetSetOptionW(
                std::ptr::null_mut(),
                INTERNET_OPTION_SETTINGS_CHANGED,
                std::ptr::null_mut(),
                0,
            )
        };
        let ok2 = unsafe {
            InternetSetOptionW(
                std::ptr::null_mut(),
                INTERNET_OPTION_REFRESH,
                std::ptr::null_mut(),
                0,
            )
        };
        if ok1 == 0 || ok2 == 0 {
            return Err(PlatformError::Io {
                operation: "InternetSetOptionW".to_string(),
                message: format!("settings_changed={ok1} refresh={ok2}"),
            });
        }
        Ok(())
    }
}

#[cfg(not(windows))]
static MOCK_PROXY_STATE: std::sync::Mutex<Option<SystemProxyState>> = std::sync::Mutex::new(None);

#[cfg(not(windows))]
impl WinInetSystemProxy {
    /// 创建一个控制器（非 Windows 模拟）。
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

#[cfg(not(windows))]
impl SystemProxyController for WinInetSystemProxy {
    fn snapshot(&self) -> Result<SystemProxyState, PlatformError> {
        let guard = MOCK_PROXY_STATE.lock().unwrap();
        Ok(guard.clone().unwrap_or(SystemProxyState {
            enabled: false,
            server: None,
        }))
    }

    fn apply(&self, enabled: bool, server: Option<&str>) -> Result<(), PlatformError> {
        let mut guard = MOCK_PROXY_STATE.lock().unwrap();
        let cur_server = guard.as_ref().and_then(|s| s.server.clone());
        let new_server = match server {
            Some(s) => Some(s.to_string()),
            None => cur_server,
        };
        *guard = Some(SystemProxyState {
            enabled,
            server: new_server,
        });
        Ok(())
    }

    fn refresh(&self) -> Result<(), PlatformError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wide_roundtrip_strips_nul() {
        let w = to_wide("127.0.0.1:7898");
        assert_eq!(from_wide_nul(&w), "127.0.0.1:7898");
        // 额外的中间 NUL 之后被截断。
        let mut buf = to_wide("abc");
        buf.push(0);
        buf.extend_from_slice(&to_wide("ignored"));
        assert_eq!(from_wide_nul(&buf), "abc");
    }

    #[test]
    fn empty_string_reads_as_none() {
        // 与 query_string 的语义一致：空串归一为 None。
        let w = to_wide("");
        let s = from_wide_nul(&w);
        assert!(s.is_empty());
    }
}
