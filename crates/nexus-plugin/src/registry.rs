//! 插件注册表：版本硬校验（S2）+ 静态注册（S3）+ 可观测计数（S6）。

use crate::{ObfsParams, ObfuscateTransport, ObfuscatedStream, PluginError, OBFUSCATE_API_VERSION};
use std::collections::HashMap;
use std::io;
use std::net::TcpStream;
use std::sync::Arc;

/// 混淆传输插件注册表（S3：编译期静态注册，由二进制启动时显式调用）。
///
/// - `register()`：先做版本硬校验（S2），再查重名；失败的插件不进表。
/// - 计数 `wrap_ok` / `wrap_err` 按插件名（S6）。
pub struct PluginRegistry {
    plugins: HashMap<&'static str, Arc<dyn ObfuscateTransport>>,
    wrap_ok: HashMap<&'static str, u64>,
    wrap_err: HashMap<&'static str, u64>,
}

impl PluginRegistry {
    pub fn new() -> Self {
        PluginRegistry {
            plugins: HashMap::new(),
            wrap_ok: HashMap::new(),
            wrap_err: HashMap::new(),
        }
    }

    /// 注册一个插件。
    ///
    /// S2：先检查 `api_version()`，不兼容 → `IncompatibleApiVersion`；
    /// 再检查重名 → `DuplicatePlugin`。任一失败都不改变注册表状态。
    pub fn register(&mut self, plugin: Arc<dyn ObfuscateTransport>) -> Result<(), PluginError> {
        let name = plugin.name();
        let got = plugin.api_version();
        if got != OBFUSCATE_API_VERSION {
            return Err(PluginError::IncompatibleApiVersion {
                name,
                got,
                expected: OBFUSCATE_API_VERSION,
            });
        }
        if self.plugins.contains_key(name) {
            return Err(PluginError::DuplicatePlugin(name));
        }
        self.plugins.insert(name, plugin);
        Ok(())
    }

    /// 按名查找插件。
    pub fn get(&self, name: &str) -> Option<Arc<dyn ObfuscateTransport>> {
        self.plugins.get(name).cloned()
    }

    /// 已注册插件名（排序，确定性顺序）。
    pub fn names(&self) -> Vec<&'static str> {
        let mut v: Vec<&'static str> = self.plugins.keys().copied().collect();
        v.sort_unstable();
        v
    }

    /// 用指定插件 `wrap` 一条流，并按插件名计数成功/失败（S6）。
    ///
    /// 失败时返回 `io::Error`，本层不自动回退（S4）；计数 `wrap_err` +1。
    pub fn wrap(
        &mut self,
        name: &str,
        stream: TcpStream,
        params: &ObfsParams,
    ) -> io::Result<Box<dyn ObfuscatedStream>> {
        let plugin = match self.plugins.get(name) {
            Some(p) => Arc::clone(p),
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("no such obfuscation plugin: '{name}'"),
                ))
            }
        };
        // `plugins.get` 的不可变借用已结束，现在可变借用计数器。
        let key: &'static str = plugin.name();
        match plugin.wrap(stream, params) {
            Ok(s) => {
                *self.wrap_ok.entry(key).or_insert(0) += 1;
                Ok(s)
            }
            Err(e) => {
                *self.wrap_err.entry(key).or_insert(0) += 1;
                Err(e)
            }
        }
    }

    /// `wrap` 成功次数（按插件名，S6）。
    pub fn wrap_ok(&self, name: &str) -> u64 {
        self.wrap_ok.get(name).copied().unwrap_or(0)
    }

    /// `wrap` 失败次数（按插件名，S6）。
    pub fn wrap_err(&self, name: &str) -> u64 {
        self.wrap_err.get(name).copied().unwrap_or(0)
    }
}

impl Default for PluginRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ObfsParams, ObfuscateTransport, ObfuscatedStream, PluginError, OBFUSCATE_API_VERSION,
    };
    use std::io;
    use std::net::TcpStream;
    use std::sync::Arc;

    struct FakePlugin {
        name: &'static str,
        api_version: u32,
    }

    impl ObfuscateTransport for FakePlugin {
        fn name(&self) -> &'static str {
            self.name
        }
        fn api_version(&self) -> u32 {
            self.api_version
        }
        fn wrap(
            &self,
            _stream: TcpStream,
            _params: &ObfsParams,
        ) -> io::Result<Box<dyn ObfuscatedStream>> {
            Err(io::Error::other("fake"))
        }
    }

    fn fake(name: &'static str, api_version: u32) -> Arc<dyn ObfuscateTransport> {
        Arc::new(FakePlugin { name, api_version })
    }

    #[test]
    fn rejects_incompatible_api_version() {
        let mut reg = PluginRegistry::new();
        let err = reg
            .register(fake("future", OBFUSCATE_API_VERSION + 999))
            .unwrap_err();
        assert_eq!(
            err,
            PluginError::IncompatibleApiVersion {
                name: "future",
                got: OBFUSCATE_API_VERSION + 999,
                expected: OBFUSCATE_API_VERSION,
            }
        );
        // 被拒绝的插件不得进表（S2 + Recovery）。
        assert!(reg.get("future").is_none());
        assert!(!reg.names().contains(&"future"));
    }

    #[test]
    fn rejects_duplicate_name() {
        let mut reg = PluginRegistry::new();
        reg.register(fake("dup", OBFUSCATE_API_VERSION)).unwrap();
        let err = reg
            .register(fake("dup", OBFUSCATE_API_VERSION))
            .unwrap_err();
        assert_eq!(err, PluginError::DuplicatePlugin("dup"));
        // 原插件不受影响。
        assert!(reg.get("dup").is_some());
    }

    #[test]
    fn version_check_runs_before_duplicate_check() {
        // 同名但版本不兼容 → 应报版本错误（S2：版本检查是前置条件）。
        let mut reg = PluginRegistry::new();
        reg.register(fake("x", OBFUSCATE_API_VERSION)).unwrap();
        let err = reg.register(fake("x", 999)).unwrap_err();
        assert!(matches!(err, PluginError::IncompatibleApiVersion { .. }));
    }

    #[test]
    fn names_lists_registered() {
        let mut reg = PluginRegistry::new();
        assert!(reg.names().is_empty());
        reg.register(fake("b", OBFUSCATE_API_VERSION)).unwrap();
        reg.register(fake("a", OBFUSCATE_API_VERSION)).unwrap();
        // 确定性顺序（排序），与注册顺序无关。
        assert_eq!(reg.names(), vec!["a", "b"]);
    }

    #[test]
    fn wrap_counts_ok_and_err() {
        use std::net::TcpListener;

        let mut reg = PluginRegistry::new();
        // FakePlugin::wrap 总是失败 → wrap_err 计数。
        reg.register(fake("fakep", OBFUSCATE_API_VERSION)).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let params = ObfsParams { key: b"" };

        let client = TcpStream::connect(addr).unwrap();
        let (_server, _) = listener.accept().unwrap();
        assert!(reg.wrap("fakep", client, &params).is_err());
        assert_eq!(reg.wrap_ok("fakep"), 0);
        assert_eq!(reg.wrap_err("fakep"), 1);

        // 未知插件名 → NotFound，不计入任何插件的计数器。
        let client2 = TcpStream::connect(addr).unwrap();
        let (_server2, _) = listener.accept().unwrap();
        let e = reg.wrap("nope", client2, &params).err().unwrap();
        assert_eq!(e.kind(), io::ErrorKind::NotFound);
        assert_eq!(reg.wrap_err("nope"), 0);
    }
}
