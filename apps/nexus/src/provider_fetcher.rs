//! 组合根：rule-provider 内容拉取实现（§11.12）。
//!
//! - [`FileProviderFetcher`]：纯本地文件（无 `url`，§11.11 语义）。
//! - [`CachedHttpProviderFetcher`]：`http://` 在线源 + 本地缓存回退
//!   （§11.12；`https://` 需 TLS 客户端依赖评审，P1）。
//!
//! 二者都实现 [`nexus_proxy::ProviderFetcher`]——决策内核不感知拉取来源。

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use nexus_proxy::{FetchedProvider, ProviderFetcher, ProviderSource};
use nexus_proxy_config::RuleProviderConfig;

/// 纯本地文件 provider（无 `url`；§11.11 语义不变）。
#[derive(Debug, Clone, Default)]
pub struct FileProviderFetcher;

impl ProviderFetcher for FileProviderFetcher {
    fn load(&mut self, cfg: &RuleProviderConfig) -> Result<FetchedProvider, String> {
        load_file(&cfg.path, ProviderSource::Local)
    }
}

/// `http://` 在线 provider（可选 `url`；§11.12）。
///
/// 命中策略：
/// 1. 缓存文件存在且未超过 `refresh_interval_secs`（默认 86400）→ `Cached`；
/// 2. 否则拉取 `url` → 成功则写缓存并返回 `Online`；
/// 3. 拉取失败 → 回退过期缓存（存在时）→ `Cached`；否则报错。
#[derive(Debug, Clone, Default)]
pub struct CachedHttpProviderFetcher;

impl ProviderFetcher for CachedHttpProviderFetcher {
    fn load(&mut self, cfg: &RuleProviderConfig) -> Result<FetchedProvider, String> {
        let Some(url) = cfg.url.as_deref() else {
            return load_file(&cfg.path, ProviderSource::Local);
        };
        let interval = cfg.refresh_interval_secs.unwrap_or(86_400);
        // 1) 新鲜缓存。
        if let Ok(meta) = std::fs::metadata(&cfg.path) {
            if let Ok(modified) = meta.modified() {
                if modified
                    .elapsed()
                    .map(|e| e.as_secs() < interval)
                    .unwrap_or(false)
                {
                    return load_file(&cfg.path, ProviderSource::Cached);
                }
            }
        }
        // 2) 在线拉取。
        match http_get(url) {
            Ok(text) => {
                if let Err(e) = std::fs::write(&cfg.path, &text) {
                    eprintln!("nexus: cache write failed (non-fatal): {e}");
                }
                Ok(FetchedProvider {
                    lines: text.lines().map(str::to_string).collect(),
                    source: ProviderSource::Online,
                })
            }
            // 3) 回退过期缓存。
            Err(e) => load_file(&cfg.path, ProviderSource::Cached)
                .map_err(|_| format!("fetch {url}: {e}")),
        }
    }
}

fn load_file(path: &str, source: ProviderSource) -> Result<FetchedProvider, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
    Ok(FetchedProvider {
        lines: text.lines().map(str::to_string).collect(),
        source,
    })
}

/// 极简 HTTP/1.1 GET（`http://` 明文；P1 才引入 TLS）。
fn http_get(url: &str) -> Result<String, String> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| "only http:// URLs supported (https is P1)".to_string())?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rfind(':') {
        Some(i) => (
            &authority[..i],
            authority[i + 1..]
                .parse::<u16>()
                .map_err(|e| format!("bad port: {e}"))?,
        ),
        None => (authority, 80u16),
    };
    if host.is_empty() {
        return Err("empty host".to_string());
    }
    let mut stream =
        TcpStream::connect((host, port)).map_err(|e| format!("connect {host}:{port}: {e}"))?;
    stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
    let request = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .map_err(|e| format!("write: {e}"))?;
    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .map_err(|e| format!("read: {e}"))?;
    let raw = String::from_utf8_lossy(&raw);
    let (head, body) = raw
        .split_once("\r\n\r\n")
        .ok_or_else(|| "malformed http response".to_string())?;
    let status = head.lines().next().unwrap_or("");
    if !status.starts_with("HTTP/1.1 200") && !status.starts_with("HTTP/1.0 200") {
        return Err(format!("bad status: {status}"));
    }
    Ok(body.to_string())
}
