//! # /dev/net/tun 窄 POSIX FFI 绑定（本 crate 唯一的 unsafe 模块）
//!
//! 设计（对齐 `nexus-platform-windows/src/wintun.rs` 纪律）：
//! - 手写 `extern "C"` 窄绑定（open/close/read/write/ioctl），不引入第三方
//!   FFI crate；常量（O_RDWR/O_NONBLOCK、TUNSETIFF、IFF_TUN/IFF_NO_PI）按
//!   Linux UAPI 字面量声明。
//! - **Safety Invariant**：`TunFd` 持有 fd 所有权，其 Drop 必须 `close`；
//!   所有系统调用在 `&mut self` 方法内同步完成，fd 不跨线程共享。
//! - 本模块之外不扩散 unsafe；名称/参数校验、错误映射为纯函数，可单测。

use std::ffi::{c_char, c_int, c_long, c_void};
use std::io;

/// `open(2)` 标志：`O_RDWR`（Linux UAPI `0x0002`）。
pub const O_RDWR: c_int = 0x0002;
/// `open(2)` 标志：`O_NONBLOCK`（Linux 所有架构 `0x0800`）。
pub const O_NONBLOCK: c_int = 0x0800;
/// `ioctl` 请求：`TUNSETIFF`（`_IOW('T', 202, int)`）。
pub const TUNSETIFF: c_long = 0x4004_54ca;
/// `TUNSETIFF` 标志：`IFF_TUN`（虚拟点对点 TUN 设备）。
pub const IFF_TUN: u16 = 0x0001;
/// `TUNSETIFF` 标志：`IFF_NO_PI`（省略每包 4 字节 PI 头）。
pub const IFF_NO_PI: u16 = 0x1000;
/// TUN 设备节点。
pub const TUN_DEVICE: &str = "/dev/net/tun";
/// `ifreq.ifr_name` 长度（Linux UAPI `IFNAMSIZ`）。
pub const IFNAMSIZ: usize = 16;

unsafe extern "C" {
    // `open(2)` 实为 variadic（`int open(const char *, int, ...)`）；
    // 声明需带 `...` 以匹配标准符号签名（rustc 1.99 `invalid_runtime_symbol_definitions`）。
    fn open(pathname: *const c_char, flags: c_int, ...) -> c_int;
    fn close(fd: c_int) -> c_int;
    fn read(fd: c_int, buf: *mut c_void, count: usize) -> isize;
    fn write(fd: c_int, buf: *const c_void, count: usize) -> isize;
    fn ioctl(fd: c_int, request: c_long, arg: *mut c_void) -> c_int;
}

/// Linux `struct ifreq`（TUNSETIFF 参数的最小布局）。
#[repr(C)]
pub struct IfReq {
    /// 接口名（NUL 结尾，≤15 字节）。
    pub ifr_name: [u8; IFNAMSIZ],
    /// `IFF_*` 标志。
    pub ifr_flags: u16,
    /// 对齐填充。
    pub _pad: [u8; 2],
}

/// 持有 TUN fd 所有权的最小句柄。
pub struct TunFd {
    fd: c_int,
}

// SAFETY 论证：本结构持有互斥的 fd，设计为单线程使用（`&mut self` 独占）；
// 迁移（Send 装箱）时无进行中的系统调用。fd 值跨线程传递不构成共享。
unsafe impl Send for TunFd {}

impl TunFd {
    /// 打开 `/dev/net/tun` 并设置 IFF_TUN|IFF_NO_PI（非阻塞）。
    ///
    /// 调用方需 root 或 `CAP_NET_ADMIN`。
    pub fn open_tun(name: &[u8]) -> io::Result<Self> {
        let device = cstr(TUN_DEVICE)?;
        // SAFETY：device 为 NUL 结尾；flags 为 O_RDWR|O_NONBLOCK。
        let fd = unsafe { open(device.as_ptr(), O_RDWR | O_NONBLOCK) };
        if fd < 0 {
            return Err(last_io_error("open /dev/net/tun"));
        }
        let mut ifreq = IfReq {
            ifr_name: [0u8; IFNAMSIZ],
            ifr_flags: IFF_TUN | IFF_NO_PI,
            _pad: [0u8; 2],
        };
        if name.len() >= IFNAMSIZ {
            unsafe { close(fd) };
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "tun name too long: {} bytes (max {})",
                    name.len(),
                    IFNAMSIZ - 1
                ),
            ));
        }
        ifreq.ifr_name[..name.len()].copy_from_slice(name);
        // SAFETY：fd 有效；ifreq 为有效指针；TUNSETIFF 语义为设置接口参数。
        let rc = unsafe { ioctl(fd, TUNSETIFF, &mut ifreq as *mut IfReq as *mut c_void) };
        if rc < 0 {
            let err = last_io_error("ioctl TUNSETIFF");
            unsafe { close(fd) };
            return Err(err);
        }
        Ok(TunFd { fd })
    }

    /// 读取一帧 IP 包；无可用数据返回 `Ok(0)`（非阻塞 EAGAIN 映射）。
    pub fn read_frame(&self, output: &mut [u8]) -> io::Result<usize> {
        // SAFETY：output 为有效可变缓冲；fd 有效。
        let n = unsafe { read(self.fd, output.as_mut_ptr() as *mut c_void, output.len()) };
        if n >= 0 {
            Ok(n as usize)
        } else {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock {
                Ok(0)
            } else {
                Err(err)
            }
        }
    }

    /// 写入一帧 IP 包；部分写入视为错误（TUN 整帧语义）。
    pub fn write_frame(&self, packet: &[u8]) -> io::Result<()> {
        // SAFETY：packet 为有效只读缓冲；fd 有效。
        let n = unsafe { write(self.fd, packet.as_ptr() as *const c_void, packet.len()) };
        if n as usize == packet.len() {
            Ok(())
        } else if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Err(io::Error::new(
                io::ErrorKind::WriteZero,
                format!("tun partial write: {n}/{}", packet.len()),
            ))
        }
    }
}

impl Drop for TunFd {
    fn drop(&mut self) {
        // SAFETY：fd 有效且为本结构独占。
        unsafe { close(self.fd) };
    }
}

/// 构造 NUL 结尾 C 字符串（拒绝内部 NUL）。
fn cstr(s: &str) -> io::Result<Vec<c_char>> {
    if s.as_bytes().contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "nul byte in string",
        ));
    }
    let mut v: Vec<c_char> = s.as_bytes().iter().map(|&b| b as c_char).collect();
    v.push(0);
    Ok(v)
}

/// 读取最后一个 OS 错误并附加操作名。
fn last_io_error(operation: &str) -> io::Error {
    io::Error::other(format!("{operation}: {}", io::Error::last_os_error()))
}
