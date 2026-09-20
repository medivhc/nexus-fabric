//! 组合根：rule-provider 内容拉取实现（§11.12 / §11.14）。
//!
//! - [`FileProviderFetcher`]：纯本地文件（无 `url`，§11.11 语义）。
//! - [`CachedHttpProviderFetcher`]：`http://` 明文 + `https://` TLS 在线源 +
//!   本地缓存回退（§11.12 / §11.14；TLS 用 rustls，默认 Mozilla 根，可注入
//!   自定义 root store）。
//!
//! 二者都实现 [`nexus_proxy::ProviderFetcher`]——决策内核不感知拉取来源。

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use nexus_proxy::{FetchedProvider, ProviderFetcher, ProviderSource};
use nexus_proxy_config::RuleProviderConfig;
use rustls::pki_types::{CertificateDer, ServerName};

/// 纯本地文件 provider（无 `url`；§11.11 语义不变）。
#[derive(Debug, Clone, Default)]
pub struct FileProviderFetcher;

impl ProviderFetcher for FileProviderFetcher {
    fn load(&mut self, cfg: &RuleProviderConfig) -> Result<FetchedProvider, String> {
        load_file(&cfg.path, ProviderSource::Local)
    }
}

/// `http:// | https://` 在线 provider（可选 `url`；§11.12 / §11.14）。
///
/// 命中策略：
/// 1. 缓存文件存在且未超过 `refresh_interval_secs`（默认 86400）→ `Cached`；
/// 2. 否则拉取 `url` → 成功则写缓存并返回 `Online`；
/// 3. 拉取失败 → 回退过期缓存（存在时）→ `Cached`；否则报错。
///
/// TLS（`https://`）：默认信任系统根证书库（`rustls-native-certs`）；测试/自签场景经
/// [`Self::with_tls_roots`] 注入自定义 root store（§11.14）。
#[derive(Debug, Clone, Default)]
pub struct CachedHttpProviderFetcher {
    tls_roots: Option<Vec<CertificateDer<'static>>>,
}

impl CachedHttpProviderFetcher {
    /// 注入自定义 TLS root store（自签/私有 CA 场景；空则用 Mozilla 根）。
    #[must_use]
    pub fn with_tls_roots(roots: Vec<CertificateDer<'static>>) -> Self {
        Self {
            tls_roots: Some(roots),
        }
    }
}

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
        // 2) 在线拉取（http 明文 / https TLS）。
        let fetched = if let Some(rest) = url.strip_prefix("https://") {
            https_get(rest, self.tls_roots.as_deref())
        } else if let Some(rest) = url.strip_prefix("http://") {
            http_get(rest)
        } else {
            Err(format!("unsupported url scheme: {url}"))
        };
        match fetched {
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

/// 解析 `authority + path` 片段（scheme 已剥除）。
///
/// 返回 `(host, port, path)`；`authority` 可带 `:port`（缺省 `default_port`）。
fn parse_authority(authority: &str, default_port: u16) -> Result<(&str, u16, &str), String> {
    let (authority, path) = match authority.find('/') {
        Some(i) => (&authority[..i], &authority[i..]),
        None => (authority, "/"),
    };
    let (host, port) = match authority.rfind(':') {
        Some(i) => (
            &authority[..i],
            authority[i + 1..]
                .parse::<u16>()
                .map_err(|e| format!("bad port: {e}"))?,
        ),
        None => (authority, default_port),
    };
    if host.is_empty() {
        return Err("empty host".to_string());
    }
    Ok((host, port, path))
}

/// 极简 HTTP/1.1 GET（`http://` 明文；§11.12）。
fn http_get(rest: &str) -> Result<String, String> {
    let (host, port, path) = parse_authority(rest, 80)?;
    let mut stream =
        TcpStream::connect((host, port)).map_err(|e| format!("connect {host}:{port}: {e}"))?;
    stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
    http_request(&mut stream, host, path)
}

/// 极简 HTTPS GET（`https://`，rustls TLS 1.3；§11.14）。
///
/// `roots` 为 `Some` 时只信任给定 CA（自签/私有场景）；`None` 用 Mozilla 根。
fn https_get(rest: &str, roots: Option<&[CertificateDer<'static>]>) -> Result<String, String> {
    let (host, port, path) = parse_authority(rest, 443)?;
    let config = tls_client_config(roots)?;
    let server_name = ServerName::try_from(host.to_string())
        .map_err(|_| format!("invalid server name: {host}"))?;
    let tcp =
        TcpStream::connect((host, port)).map_err(|e| format!("connect {host}:{port}: {e}"))?;
    tcp.set_read_timeout(Some(Duration::from_secs(10))).ok();
    let conn = rustls::ClientConnection::new(Arc::new(config), server_name)
        .map_err(|e| format!("tls init: {e}"))?;
    let mut stream = rustls::StreamOwned::new(conn, tcp);
    http_request(&mut stream, host, path)
}

/// 构建 rustls 客户端配置：`roots` 注入或系统根证书库。
fn tls_client_config(
    roots: Option<&[CertificateDer<'static>]>,
) -> Result<rustls::ClientConfig, String> {
    let mut store = rustls::RootCertStore::empty();
    match roots {
        Some(list) => {
            for cert in list {
                store
                    .add(cert.clone())
                    .map_err(|e| format!("add root cert: {e}"))?;
            }
        }
        None => {
            let native = rustls_native_certs::load_native_certs();
            for cert in native.certs {
                store
                    .add(cert)
                    .map_err(|e| format!("add native root cert: {e}"))?;
            }
        }
    }
    Ok(rustls::ClientConfig::builder()
        .with_root_certificates(store)
        .with_no_client_auth())
}

/// HTTP/1.1 请求-响应公共层（`Connection: close` 后读全量响应体）。
fn http_request<S: Read + Write>(stream: &mut S, host: &str, path: &str) -> Result<String, String> {
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
