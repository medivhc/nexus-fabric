//! 混淆传输插件机制（DESIGN §7 首期）。
//!
//! 进程内 trait + 接口版本化 + 编译期静态注册。
//! 首期只开放混淆传输插件点（S1）；版本硬校验（S2）；全同步 std（S5）。

use std::error::Error;
use std::fmt;
use std::io::{Read, Write};
use std::net::TcpStream;

pub mod builtin;
pub mod registry;

pub use registry::PluginRegistry;

/// 混淆传输接口版本。`register()` 时硬校验（S2）。
pub const OBFUSCATE_API_VERSION: u32 = 1;

/// 插件参数。`xor` 用 `key`；`plain` 忽略。
pub struct ObfsParams<'a> {
    pub key: &'a [u8],
}

/// 注册/插件错误。
#[derive(Debug, PartialEq, Eq)]
pub enum PluginError {
    /// 插件声明的接口版本与当前不兼容（S2）。
    IncompatibleApiVersion {
        name: &'static str,
        got: u32,
        expected: u32,
    },
    /// 同名插件已注册（S2）。
    DuplicatePlugin(&'static str),
}

impl fmt::Display for PluginError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PluginError::IncompatibleApiVersion {
                name,
                got,
                expected,
            } => write!(
                f,
                "plugin '{name}' api_version {got} incompatible with expected {expected}"
            ),
            PluginError::DuplicatePlugin(name) => {
                write!(f, "plugin '{name}' already registered")
            }
        }
    }
}

impl Error for PluginError {}

/// 混淆传输插件：把一条已建立的 `TcpStream` 包装成混淆后的字节流（S1）。
///
/// `Send + Sync`：注册表可在线程间共享；trait object 安全
/// （所有方法无泛型、无 `Self` 返回）。
pub trait ObfuscateTransport: Send + Sync {
    fn name(&self) -> &'static str;
    fn api_version(&self) -> u32;
    fn wrap(
        &self,
        stream: TcpStream,
        params: &ObfsParams,
    ) -> std::io::Result<Box<dyn ObfuscatedStream>>;
}

/// 混淆后的字节流：仍是同一条 TCP 连接的字节流，只是字节被变换（S4）。
pub trait ObfuscatedStream: Read + Write + Send {}
