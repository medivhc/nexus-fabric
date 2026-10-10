//! # DPAPI 窄 Win32 绑定（本 crate 第二个 unsafe 模块）
//!
//! 设计（对齐 `wintun.rs` 纪律）：
//! - 运行时动态加载 `crypt32.dll`（`LoadLibraryW`/`GetProcAddress`），不静态
//!   链接、不提交二进制；crypt32 为系统常驻库，加载必成功。
//! - 函数指针表按 DPAPI ABI 声明；缺任一必需符号即整体失败（结构化
//!   `PlatformError::Io`）。
//! - **Safety Invariant**：`DpapiModule` 持有 `HMODULE` 所有权；其 Drop
//!   （`FreeLibrary`）必须在所有借用该模块函数指针的句柄释放之后发生。
//!   本模块之外不扩散 unsafe；错误映射为纯逻辑，可单测。

#[cfg(windows)]
use std::ffi::c_void;
use std::io;

/// `CRYPTPROTECT_UI_FORBIDDEN`（0x1）：禁止任何 UI 提示。
pub const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x0000_0001;

#[cfg(windows)]
/// Windows `HANDLE` / `HMODULE`。
type Handle = *mut c_void;
#[cfg(windows)]
/// Win32 `BOOL`。
type Bool = i32;

#[cfg(windows)]
/// Win32 `DATA_BLOB`（DPAPI 输入/输出结构）。
#[repr(C)]
pub struct DataBlob {
    /// 数据字节数。
    pub cb_data: u32,
    /// 数据指针（由 LocalFree 释放，DPAPI 分配）。
    pub pb_data: *mut u8,
}

#[cfg(windows)]
/// `CryptProtectData(pDataIn, szDataDescr, pOptionalEntropy, pvReserved,
/// pPromptStruct, dwFlags, pDataOut) -> BOOL`。
type ProtectFn = unsafe extern "system" fn(
    *const DataBlob,
    *const u16,
    *const DataBlob,
    *mut c_void,
    *const c_void,
    u32,
    *mut DataBlob,
) -> Bool;

#[cfg(windows)]
/// 持有 crypt32 模块句柄与解析出的 DPAPI 函数指针。
pub struct DpapiModule {
    module: Handle,
    protect: ProtectFn,
    unprotect: ProtectFn,
}

#[cfg(windows)]
// SAFETY 论证：模块句柄与函数指针跨线程迁移安全（无进行中调用）；Drop 在
// 最后使用后执行 FreeLibrary。
unsafe impl Send for DpapiModule {}

#[cfg(windows)]
impl DpapiModule {
    /// 加载 crypt32.dll 并解析 DPAPI 导出（系统常驻库，加载必成功；
    /// 解析失败为环境异常）。
    pub fn load() -> Result<Self, io::Error> {
        let module = load_library()?;
        let protect = resolve(module, b"CryptProtectData\0")?;
        let unprotect = resolve(module, b"CryptUnprotectData\0")?;
        Ok(DpapiModule {
            module,
            protect,
            unprotect,
        })
    }

    pub(crate) fn protect(&self) -> ProtectFn {
        self.protect
    }

    pub(crate) fn unprotect(&self) -> ProtectFn {
        self.unprotect
    }
}

#[cfg(windows)]
impl Drop for DpapiModule {
    fn drop(&mut self) {
        // SAFETY：模块句柄有效且为本结构独占。
        unsafe { FreeLibrary(self.module) };
    }
}

#[cfg(windows)]
/// 持有 DPAPI 输出 blob 所有权的最小句柄（Drop 时 LocalFree）。
pub struct OwnedBlob {
    blob: DataBlob,
}

#[cfg(windows)]
// SAFETY 论证：blob 指针由本结构独占，跨线程迁移（Send）时无进行中的调用。
unsafe impl Send for OwnedBlob {}

#[cfg(windows)]
impl OwnedBlob {
    /// 把 DPAPI 输出的 blob 包为拥有者。
    ///
    /// # Safety
    /// `blob.pb_data` 必须来自 DPAPI（LocalAlloc 分配），调用方让出所有权。
    pub unsafe fn from_raw(blob: DataBlob) -> Self {
        OwnedBlob { blob }
    }

    /// 只读访问 blob 字节。
    pub fn bytes(&self) -> &[u8] {
        if self.blob.pb_data.is_null() || self.blob.cb_data == 0 {
            return &[];
        }
        // SAFETY：pb_data 有效（DPAPI 分配），cb_data 为长度。
        unsafe { std::slice::from_raw_parts(self.blob.pb_data, self.blob.cb_data as usize) }
    }
}

#[cfg(windows)]
impl Drop for OwnedBlob {
    fn drop(&mut self) {
        if !self.blob.pb_data.is_null() {
            // SAFETY：pb_data 来自 DPAPI（LocalAlloc），必须 LocalFree。
            unsafe { LocalFree(self.blob.pb_data as *mut c_void) };
        }
    }
}

#[cfg(windows)]
unsafe extern "system" {
    /// kernel32!LoadLibraryW：加载 DLL 并返回模块句柄。
    fn LoadLibraryW(lp_file_name: *const u16) -> Handle;
    /// kernel32!GetProcAddress：按名称解析导出函数。
    fn GetProcAddress(h_module: Handle, lp_proc_name: *const u8) -> *mut c_void;
    /// kernel32!FreeLibrary：释放模块引用。
    fn FreeLibrary(h_lib_module: Handle) -> i32;
    /// kernel32!LocalFree：释放 DPAPI 输出。
    fn LocalFree(h_mem: *mut c_void) -> *mut c_void;
}

#[cfg(windows)]
/// 加载 crypt32.dll（系统常驻）。
fn load_library() -> Result<Handle, io::Error> {
    let name: Vec<u16> = "crypt32.dll\0".encode_utf16().collect();
    // SAFETY：name 为 NUL 结尾 UTF-16。
    let handle = unsafe { LoadLibraryW(name.as_ptr()) };
    if handle.is_null() {
        Err(io::Error::other(format!(
            "LoadLibraryW(crypt32.dll): {}",
            io::Error::last_os_error()
        )))
    } else {
        Ok(handle)
    }
}

#[cfg(windows)]
/// 按名称解析导出（name 须含 NUL）。
fn resolve(module: Handle, name: &[u8]) -> Result<ProtectFn, io::Error> {
    // SAFETY：module 有效；name 为 NUL 结尾。
    let ptr = unsafe { GetProcAddress(module, name.as_ptr()) };
    if ptr.is_null() {
        return Err(io::Error::other(format!(
            "GetProcAddress({}): required dpapi export missing",
            String::from_utf8_lossy(&name[..name.len().saturating_sub(1)])
        )));
    }
    // SAFETY：ptr 为有效函数指针（GetProcAddress 解析成功）。
    Ok(unsafe { std::mem::transmute::<*mut c_void, ProtectFn>(ptr) })
}

/// 用 DPAPI 加密明文（绑定当前 Windows 用户 + 机器，无需管理员）。
#[cfg(windows)]
pub fn protect(data: &[u8]) -> io::Result<Vec<u8>> {
    let api = DpapiModule::load()?;
    let input = DataBlob {
        cb_data: data.len() as u32,
        pb_data: data.as_ptr() as *mut u8,
    };
    let mut output = DataBlob {
        cb_data: 0,
        pb_data: std::ptr::null_mut(),
    };
    // SAFETY：input 为有效只读 blob；output 由 DPAPI 填充；UI 禁止。
    let ok = unsafe {
        (api.protect())(
            &input,
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if ok == 0 {
        return Err(io::Error::other(format!(
            "CryptProtectData: {}",
            io::Error::last_os_error()
        )));
    }
    // SAFETY：output 由 DPAPI 分配，转为拥有者（Drop LocalFree）。
    let owned = unsafe { OwnedBlob::from_raw(output) };
    Ok(owned.bytes().to_vec())
}

/// 非 Windows 环境下的纯软件模拟加密（用于跨平台场景与测试验证）。
#[cfg(not(windows))]
pub fn protect(data: &[u8]) -> io::Result<Vec<u8>> {
    let mut out = b"MOCK_DPAPI:".to_vec();
    for b in data {
        out.push(b ^ 0x5a);
    }
    Ok(out)
}

/// 用 DPAPI 解密密文 blob。
#[cfg(windows)]
pub fn unprotect(cipher: &[u8]) -> io::Result<Vec<u8>> {
    let api = DpapiModule::load()?;
    let input = DataBlob {
        cb_data: cipher.len() as u32,
        pb_data: cipher.as_ptr() as *mut u8,
    };
    let mut output = DataBlob {
        cb_data: 0,
        pb_data: std::ptr::null_mut(),
    };
    // SAFETY：input 为有效只读 blob；output 由 DPAPI 填充。
    let ok = unsafe {
        (api.unprotect())(
            &input,
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if ok == 0 {
        return Err(io::Error::other(format!(
            "CryptUnprotectData: {}",
            io::Error::last_os_error()
        )));
    }
    // SAFETY：output 由 DPAPI 分配，转为拥有者。
    let owned = unsafe { OwnedBlob::from_raw(output) };
    Ok(owned.bytes().to_vec())
}

/// 非 Windows 环境下的纯软件模拟解密。
#[cfg(not(windows))]
pub fn unprotect(cipher: &[u8]) -> io::Result<Vec<u8>> {
    if !cipher.starts_with(b"MOCK_DPAPI:") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid mock dpapi header",
        ));
    }
    let data = &cipher[b"MOCK_DPAPI:".len()..];
    let mut out = Vec::with_capacity(data.len());
    for b in data {
        out.push(b ^ 0x5a);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(windows)]
    fn protect_unprotect_roundtrip() {
        let secret = b"nexus secure store secret";
        let cipher = protect(secret).expect("dpapi protect");
        assert!(!cipher.is_empty());
        assert_ne!(cipher, secret);
        let plain = unprotect(&cipher).expect("dpapi unprotect");
        assert_eq!(plain, secret);
    }

    #[test]
    #[cfg(windows)]
    fn protect_empty_is_valid() {
        let cipher = protect(b"").expect("dpapi protect empty");
        assert!(!cipher.is_empty());
        let plain = unprotect(&cipher).expect("dpapi unprotect empty");
        assert!(plain.is_empty());
    }

    #[test]
    fn unprotect_garbage_rejected() {
        assert!(unprotect(&[0xde, 0xad, 0xbe, 0xef]).is_err());
    }
}
