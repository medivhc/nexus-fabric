//! 组合根：订阅节点在线更新拉取器（§11.17）。
//!
//! 决策/解析内核在 `nexus-proxy-config`（纯内存、离线、可移植）；本模块只做
//! 进程侧装配：
//!
//! - [`http_get`]：明文 `http://` HTTP/1.1 GET（带自定义 User-Agent 与附加请求头）；
//!   `https://` 复用 §11.14 rustls 栈。
//! - [`SubscriptionUpdater`]：后台拉取器 Owner——持有 `CancellationToken`
//!   （`cancel: Arc<AtomicBool>`）与 worker `JoinHandle`（Drop 时协作式取消并 join，
//!   即 Reaper）；`poll_once` 执行一次「拉取 -> 解析 -> 整体替换订阅节点集 ->
//!   成功才经 `HotReloadManager.propose_reload` 热生效」。
//!
//! worker 只通过 `apply_body` 产生事件，不直接写 TerminalOutcome。

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use nexus_connectivity::config_hot_reload::{HotReloadConfig, HotReloadManager};
use nexus_proxy_config::{OutboundConfig, SubscriptionRuntime, SubscriptionSourceConfig};

/// 极简 HTTP/1.1 GET（明文 `http://`；§11.17 在线订阅拉取传输层）。
///
/// 带自定义 `User-Agent` 与附加请求头；`Connection: close` 后读全量响应体。
/// 非 200 状态码 / 连接失败 / 畸形响应返回 `Err`（调用方保留旧订阅节点集）。
pub(crate) fn http_get(
    url: &str,
    user_agent: &str,
    headers: &[(String, String)],
) -> Result<String, String> {
    let rest = url.strip_prefix("http://").ok_or_else(|| {
        format!("subscription url must be http:// (got {url}); https uses the §11.14 rustls stack")
    })?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rfind(':') {
        Some(i) => {
            let port: u16 = authority[i + 1..]
                .parse()
                .map_err(|e| format!("bad port: {e}"))?;
            (&authority[..i], port)
        }
        None => (authority, 80u16),
    };
    if host.is_empty() {
        return Err("empty host".to_string());
    }
    let mut stream =
        TcpStream::connect((host, port)).map_err(|e| format!("connect {host}:{port}: {e}"))?;
    stream.set_read_timeout(Some(Duration::from_secs(10))).ok();

    let mut req = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {user_agent}\r\n");
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("Connection: close\r\n\r\n");
    stream
        .write_all(req.as_bytes())
        .map_err(|e| format!("write: {e}"))?;

    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .map_err(|e| format!("read: {e}"))?;
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = text
        .split_once("\r\n\r\n")
        .ok_or_else(|| "malformed http response".to_string())?;
    let status = head.lines().next().unwrap_or("");
    if !(status.starts_with("HTTP/1.1 200") || status.starts_with("HTTP/1.0 200")) {
        return Err(format!("bad status: {status}"));
    }
    Ok(body.to_string())
}

/// Owner 持有的可变状态（运行时 + 热生效门控 + 已生效 revision）。
struct Inner {
    runtime: SubscriptionRuntime,
    reload: HotReloadManager,
    revision: u64,
}

/// 订阅在线更新拉取器（Owner）。
///
/// 结构化并发：
/// - `cancel` 是协作式停止信号；
/// - `worker` 收集后台线程的 `JoinHandle`，Drop 时设置 cancel 并 join（Reaper）；
/// - worker 不被 spawn 后丢弃。
pub struct SubscriptionUpdater {
    source: SubscriptionSourceConfig,
    inner: Arc<Mutex<Inner>>,
    cancel: Arc<AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl SubscriptionUpdater {
    /// 用订阅源配置与本地手写 outbounds 构造 Owner（本地节点恒定保留）。
    #[must_use]
    pub fn new(source: SubscriptionSourceConfig, local_outbounds: Vec<OutboundConfig>) -> Self {
        let reload_cfg = HotReloadConfig::new(1_000, true).expect("hot reload interval > 0");
        let tag = source.tag.clone();
        Self {
            source,
            inner: Arc::new(Mutex::new(Inner {
                runtime: SubscriptionRuntime::new(tag, local_outbounds),
                reload: HotReloadManager::new(reload_cfg),
                revision: 0,
            })),
            cancel: Arc::new(AtomicBool::new(false)),
            worker: None,
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// 当前已生效的热加载 revision。
    #[must_use]
    pub fn current_revision(&self) -> u64 {
        self.lock().reload.current_revision()
    }

    /// 当前有效节点数（本地 ++ 订阅）。
    #[must_use]
    pub fn effective_node_count(&self) -> usize {
        self.lock().runtime.effective_node_count()
    }

    /// 执行一次拉取 + 解析 + 合并 + 热生效（前台确定性调用；E4 驱动入口）。
    ///
    /// 成功才经 `HotReloadManager.propose_reload` 推进 revision；失败不推进、不清空节点。
    pub fn poll_once(&self) -> nexus_proxy_config::SubscriptionUpdateEvent {
        let started = Instant::now();
        let body = http_get(
            &self.source.url,
            &self.source.user_agent,
            &self.source.headers,
        );
        let latency_ms = started.elapsed().as_millis() as u64;
        let mut g = self.lock();
        let event = g.runtime.apply_body(body, latency_ms);
        if event.ok {
            g.revision += 1;
            let rev = g.revision;
            // 拉取成功才热生效（§11.17：失败不推进、不重启进程）。
            let _ = g.reload.propose_reload(rev, true);
        }
        event
    }

    /// 起后台拉取循环（结构化并发）：按 `interval_secs` 轮询，直到 `cancel` 置位。
    pub fn spawn_background(&mut self) {
        if self.worker.is_some() {
            return;
        }
        let cancel = self.cancel.clone();
        let inner = self.inner.clone();
        let source = self.source.clone();
        let tick = Duration::from_secs(source.interval_secs.max(1));
        let handle = std::thread::spawn(move || {
            loop {
                if cancel.load(Ordering::Acquire) {
                    break;
                }
                let started = Instant::now();
                let body = http_get(&source.url, &source.user_agent, &source.headers);
                let latency_ms = started.elapsed().as_millis() as u64;
                {
                    let mut g = match inner.lock() {
                        Ok(g) => g,
                        Err(e) => e.into_inner(),
                    };
                    let event = g.runtime.apply_body(body, latency_ms);
                    if event.ok {
                        g.revision += 1;
                        let rev = g.revision;
                        let _ = g.reload.propose_reload(rev, true);
                    }
                }
                // 分段睡眠以响应 cancel。
                let deadline = Instant::now() + tick;
                loop {
                    if cancel.load(Ordering::Acquire) {
                        break;
                    }
                    let remain = deadline.saturating_duration_since(Instant::now());
                    if remain.is_zero() {
                        break;
                    }
                    std::thread::sleep(remain.min(Duration::from_millis(50)));
                }
            }
        });
        self.worker = Some(handle);
    }
}

impl Drop for SubscriptionUpdater {
    fn drop(&mut self) {
        // Reaper：协作式取消并确认 worker 真正结束，不丢 JoinHandle。
        self.cancel.store(true, Ordering::Release);
        if let Some(handle) = self.worker.take() {
            let _ = handle.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_proxy_config::OutboundKind;
    use std::net::TcpListener;
    use std::sync::Arc;

    fn local_direct() -> Vec<OutboundConfig> {
        vec![OutboundConfig {
            tag: "direct".to_string(),
            kind: OutboundKind::Direct,
            locator: Some(String::new()),
            method: None,
            password: None,
            alpn: None,
            skip_cert_verify: None,
            header_format: None,
            obfs: None,
            obfs_key: None,
            uuid: None,
            flow: None,
            tls: None,
            servername: None,
            sni: None,
            ports: None,
            up: None,
            down: None,
            obfs_password: None,
            fallback_guard: None,
            ready_window_ms: None,
            credential_probe: None,
        }]
    }

    #[test]
    fn http_get_rejects_non_http_scheme() {
        assert!(http_get("https://127.0.0.1:1/x", "ua", &[]).is_err());
    }

    #[test]
    fn updater_spawn_background_cancels_and_joins_cleanly() {
        // 指向一个不存在的端口：worker 立即拉取失败（保留空订阅集），随后阻塞在分段睡眠。
        let source =
            SubscriptionSourceConfig::new("sub", "http://127.0.0.1:1/nope", 3600).expect("valid");
        let mut updater = SubscriptionUpdater::new(source, local_direct());
        updater.spawn_background();
        // 立即 drop：cancel 置位，worker 必须被 join 回收（不丢 JoinHandle、不泄漏）。
        drop(updater);
    }

    #[test]
    fn poll_once_against_loopback_server_applies_and_revision_advances() {
        // 起一个单连接 loopback server 返回固定 base64 订阅。
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let body = "c3M6Ly9ZMmhoWTJoaE1qQXRhV1YwWmkxd2IyeDVNVE13TlRwa1pXMXZMWEJoYzNOM2IzSmtAc3MuZXhhbXBsZS5jb206ODM4OCNTUy1Ob2RlCg==";
        let arc = Arc::new(body.to_string());
        let jh = std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                use std::io::{Read, Write};
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf);
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    arc.len(),
                    arc
                );
                let _ = stream.write_all(resp.as_bytes());
            }
        });
        let source =
            SubscriptionSourceConfig::new("sub", format!("http://127.0.0.1:{port}/sub"), 60)
                .expect("valid");
        let updater = SubscriptionUpdater::new(source, local_direct());
        let ev = updater.poll_once();
        assert!(ev.ok);
        assert_eq!(ev.node_count_after, 2); // 1 local + 1 sub
        assert_eq!(updater.current_revision(), 1);
        let _ = jh.join();
    }
}
