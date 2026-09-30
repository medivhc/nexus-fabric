//! 插件拨号接线（P1–P5）：TCP connect + 全局注册表 wrap。
//!
//! 统一接线点（P1）：出站 dial 站点从 `OutboundConfig` 取出 `(obfs, obfs_key)`
//! 后调这里；本模块不感知 `OutboundConfig`（依赖倒置）。
//!
//! 失败语义（P3）：connect / 未知插件 / wrap 任一步失败 → 整个 dial 返回
//! `io::Error`，不自动回退到 plain（S4 延续，防降级攻击）。

use crate::builtin;
use crate::{ObfsParams, ObfuscatedStream, PluginRegistry};
use std::collections::HashMap;
use std::io;
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{Mutex, OnceLock};

// ---------------------------------------------------------------------------
// P4：全局注册表单例
// ---------------------------------------------------------------------------

/// 全局插件注册表（P4）。
static GLOBAL: OnceLock<Mutex<PluginRegistry>> = OnceLock::new();

/// 返回全局注册表；首次调用时懒初始化并注册 builtin（plain/xor）。
pub fn global_registry() -> &'static Mutex<PluginRegistry> {
    GLOBAL.get_or_init(|| {
        let mut reg = PluginRegistry::new();
        builtin::register_all(&mut reg);
        Mutex::new(reg)
    })
}

/// 显式初始化 builtin 插件（幂等；二进制可在启动时调用）。
pub fn init_builtin_plugins() {
    let _ = global_registry();
}

fn lock_global() -> std::sync::MutexGuard<'static, PluginRegistry> {
    global_registry()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

// ---------------------------------------------------------------------------
// P5：拨号可观测
// ---------------------------------------------------------------------------

/// 拨号失败原因（P5 `obfs_dial_err{plugin,reason}` 的 reason 维度）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DialFailReason {
    /// TCP connect 失败（此时尚无插件名，`plugin="-"`）。
    Connect,
    /// 未知插件名（硬校验，P2）。
    UnknownPlugin,
    /// 插件 `wrap` 失败。
    Wrap,
}

impl DialFailReason {
    /// 稳定的 reason 标签。
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Connect => "connect",
            Self::UnknownPlugin => "unknown_plugin",
            Self::Wrap => "wrap",
        }
    }
}

static DIAL_OK: OnceLock<Mutex<HashMap<String, u64>>> = OnceLock::new();
static DIAL_ERR: OnceLock<Mutex<HashMap<(String, String), u64>>> = OnceLock::new();

fn dial_ok_map() -> &'static Mutex<HashMap<String, u64>> {
    DIAL_OK.get_or_init(|| Mutex::new(HashMap::new()))
}

fn dial_err_map() -> &'static Mutex<HashMap<(String, String), u64>> {
    DIAL_ERR.get_or_init(|| Mutex::new(HashMap::new()))
}

fn lock_map<K, V>(m: &'static Mutex<HashMap<K, V>>) -> std::sync::MutexGuard<'static, HashMap<K, V>> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn incr_dial_ok(plugin: &str) {
    *lock_map(dial_ok_map())
        .entry(plugin.to_string())
        .or_insert(0) += 1;
}

fn incr_dial_err(plugin: &str, reason: DialFailReason) {
    *lock_map(dial_err_map())
        .entry((plugin.to_string(), reason.as_str().to_string()))
        .or_insert(0) += 1;
}

/// P5：`obfs_dial_ok{plugin}` 计数。
#[must_use]
pub fn dial_ok_count(plugin: &str) -> u64 {
    lock_map(dial_ok_map()).get(plugin).copied().unwrap_or(0)
}

/// P5：`obfs_dial_err{plugin,reason}` 计数。
#[must_use]
pub fn dial_err_count(plugin: &str, reason: DialFailReason) -> u64 {
    lock_map(dial_err_map())
        .get(&(plugin.to_string(), reason.as_str().to_string()))
        .copied()
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// P1：统一接线点
// ---------------------------------------------------------------------------

/// 建 TCP 连接并按配置做插件 wrap（P1）。
///
/// - `obfs=None` → `plain` 直通（P6 零回归）。
/// - 未知插件名 → `io::ErrorKind::NotFound`（P2 硬校验）。
/// - 任一步失败 → 返回 `Err`，不回退（P3）。
///
/// # Errors
///
/// TCP connect 失败、未知插件名、`wrap` 失败时返回 `io::Error`。
pub fn dial_with_obfs(
    addr: impl ToSocketAddrs,
    obfs: Option<&str>,
    params: &ObfsParams,
) -> io::Result<Box<dyn ObfuscatedStream>> {
    let stream = TcpStream::connect(addr)
        .inspect_err(|_| incr_dial_err("-", DialFailReason::Connect))?;
    wrap_stream(stream, obfs, params)
}

/// 对一条已建立的流做插件 wrap（P1）。
///
/// 供需要方向独立 handle 的拨号点使用：先 `try_clone` 出独立的 raw handle，
/// 再各自 `wrap_stream`（写方向的所有字节走同一个 wrapped handle，读方向走
/// 另一个；见 S7）。
///
/// # Errors
///
/// 未知插件名（`NotFound`）、`wrap` 失败时返回 `io::Error`；不回退（P3）。
/// 注意 `stream` 是 move 进来的，失败时调用方拿不回原流（与 `Registry::wrap`
/// 一致；dial 场景下流随 drop 关闭，无泄漏）。
pub fn wrap_stream(
    stream: TcpStream,
    obfs: Option<&str>,
    params: &ObfsParams,
) -> io::Result<Box<dyn ObfuscatedStream>> {
    let name = obfs.unwrap_or("plain");
    let mut reg = lock_global();
    match reg.wrap(name, stream, params) {
        Ok(s) => {
            incr_dial_ok(name);
            Ok(s)
        }
        Err(e) => {
            let reason = if e.kind() == io::ErrorKind::NotFound {
                DialFailReason::UnknownPlugin
            } else {
                DialFailReason::Wrap
            };
            incr_dial_err(name, reason);
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    fn loopback() -> (TcpListener, std::net::SocketAddr) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let a = l.local_addr().unwrap();
        (l, a)
    }

    #[test]
    fn dial_plain_is_passthrough() {
        let (listener, addr) = loopback();
        let params = ObfsParams { key: b"" };
        // None → plain（P6）。
        let mut c = dial_with_obfs(addr, None, &params).unwrap();
        let (mut server, _) = listener.accept().unwrap();
        c.write_all(b"hello-plain-dial").unwrap();
        c.flush().unwrap();
        let mut buf = [0u8; 16];
        server.read_exact(&mut buf).unwrap();
        // plain 零变换：线字节 == 明文。
        assert_eq!(&buf, b"hello-plain-dial");
        assert!(dial_ok_count("plain") >= 1);
    }

    #[test]
    fn dial_unknown_plugin_is_not_found() {
        let (_listener, addr) = loopback();
        let params = ObfsParams { key: b"" };
        let before = dial_err_count("no-such-plugin", DialFailReason::UnknownPlugin);
        let err = dial_with_obfs(addr, Some("no-such-plugin"), &params)
            .err()
            .unwrap();
        // P2/P3：硬校验，不回退。
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        assert_eq!(
            dial_err_count("no-such-plugin", DialFailReason::UnknownPlugin),
            before + 1
        );
    }

    #[test]
    fn dial_xor_obfuscates_wire() {
        let (listener, addr) = loopback();
        let key = b"dial-test-key";
        let params = ObfsParams { key };
        let mut c = dial_with_obfs(addr, Some("xor"), &params).unwrap();
        let (mut server, _) = listener.accept().unwrap();
        let msg = b"AAAAAAAAAAAAAAAA"; // 16 字节相同明文
        c.write_all(msg).unwrap();
        c.flush().unwrap();
        let mut wire = vec![0u8; msg.len()];
        server.read_exact(&mut wire).unwrap();
        // 线字节被混淆。
        assert_ne!(&wire, msg);
    }

    #[test]
    fn dial_connect_failure_counts() {
        // 找一个已关闭的端口：bind 后 drop listener。
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        drop(l);
        let params = ObfsParams { key: b"" };
        let before = dial_err_count("-", DialFailReason::Connect);
        let err = dial_with_obfs(addr, None, &params).err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionRefused);
        assert_eq!(dial_err_count("-", DialFailReason::Connect), before + 1);
    }

    #[test]
    fn wrap_stream_explicit_plain() {
        // wrap_stream 直接 wrap（供方向独立 handle 的拨号点）。
        let (listener, addr) = loopback();
        let params = ObfsParams { key: b"" };
        let raw = TcpStream::connect(addr).unwrap();
        let mut w = wrap_stream(raw, Some("plain"), &params).unwrap();
        let (mut server, _) = listener.accept().unwrap();
        w.write_all(b"wrap-stream").unwrap();
        w.flush().unwrap();
        let mut buf = [0u8; 11];
        server.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"wrap-stream");
    }

    #[test]
    fn init_is_idempotent() {
        init_builtin_plugins();
        init_builtin_plugins();
        // builtin 仍在（重复初始化不 panic、不重复注册）。
        assert!(global_registry()
            .lock()
            .unwrap()
            .names()
            .contains(&"xor"));
    }
}
