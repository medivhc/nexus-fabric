//! 回环自检（AC-20）：直连目标（不经协议/参照端）验证可达性与字节一致性。
//!
//! 失败一律视为工具错误（退出码 3），不得进入 cell。

use serde::Serialize;
use std::io::{Read, Write};
use std::net::{TcpStream, UdpSocket};
use std::time::Duration;

use crate::config::{InteropProbeConfig, TargetKind};
use crate::targets::{HTTP_PORT, SINK_PORT, UDP_PORT};
use crate::util;

#[derive(Debug, Clone, Serialize)]
pub struct Check {
    pub name: String,
    pub ok: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SelfCheckReport {
    pub ok: bool,
    pub skipped: bool,
    pub target_kind: TargetKind,
    pub checks: Vec<Check>,
}

/// 按配置的 target.kind 做一次直连自检。
pub fn run(cfg: &InteropProbeConfig) -> Result<SelfCheckReport, String> {
    let kind = cfg.target.kind;
    let mut checks = Vec::new();
    match kind {
        TargetKind::TcpEcho => checks.push(check_echo(&cfg.target.host, cfg.target.port)?),
        TargetKind::TcpSink | TargetKind::TcpSource => {
            checks.extend(check_sink(&cfg.target.host, SINK_PORT)?);
        }
        TargetKind::UdpEcho => checks.push(check_udp(&cfg.target.host, UDP_PORT)?),
        TargetKind::HttpFallback => checks.push(check_http(&cfg.target.host, HTTP_PORT)?),
    }
    let ok = checks.iter().all(|c| c.ok);
    Ok(SelfCheckReport {
        ok,
        skipped: false,
        target_kind: kind,
        checks,
    })
}

/// 合成格（无目标连接）：自检显式跳过并写原因。
pub fn skipped(kind: TargetKind, reason: &str) -> SelfCheckReport {
    SelfCheckReport {
        ok: true,
        skipped: true,
        target_kind: kind,
        checks: vec![Check {
            name: "synthetic".into(),
            ok: true,
            detail: reason.to_string(),
        }],
    }
}

fn check_echo(host: &str, port: u16) -> Result<Check, String> {
    let payload = util::payload_with_seed(util::PAYLOAD_SEED ^ 0x11, 1);
    let mut stream = TcpStream::connect((host, port))
        .map_err(|e| format!("selfcheck echo connect {host}:{port}: {e}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;
    stream.write_all(&payload).map_err(|e| e.to_string())?;
    let mut back = vec![0u8; payload.len()];
    stream.read_exact(&mut back).map_err(|e| e.to_string())?;
    let ok = back == payload;
    Ok(Check {
        name: "tcp-echo-roundtrip".into(),
        ok,
        detail: format!("echoed={} expected={}", back.len(), payload.len()),
    })
}

fn check_sink(host: &str, port: u16) -> Result<Vec<Check>, String> {
    let mut stream = TcpStream::connect((host, port))
        .map_err(|e| format!("selfcheck sink connect {host}:{port}: {e}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| e.to_string())?;
    let up = util::payload_with_seed(util::PAYLOAD_SEED ^ 0x22, 1024);
    stream.write_all(&[0x55]).map_err(|e| e.to_string())?;
    stream
        .write_all(&(up.len() as u64).to_be_bytes())
        .map_err(|e| e.to_string())?;
    stream.write_all(&up).map_err(|e| e.to_string())?;
    let mut digest = [0u8; 32];
    stream.read_exact(&mut digest).map_err(|e| e.to_string())?;
    let upload_ok = util::to_hex(&digest) == util::sha256_hex(&up);

    let down_len = 4096usize;
    stream.write_all(&[0x44]).map_err(|e| e.to_string())?;
    stream
        .write_all(&(down_len as u64).to_be_bytes())
        .map_err(|e| e.to_string())?;
    let mut down = vec![0u8; down_len];
    stream.read_exact(&mut down).map_err(|e| e.to_string())?;
    let download_ok = down == util::source_payload(down_len);
    Ok(vec![
        Check {
            name: "tcp-sink-upload-sha256".into(),
            ok: upload_ok,
            detail: format!("digest_match={upload_ok}"),
        },
        Check {
            name: "tcp-source-download-sha256".into(),
            ok: download_ok,
            detail: format!("len={down_len}"),
        },
    ])
}

fn check_udp(host: &str, port: u16) -> Result<Check, String> {
    let sock = UdpSocket::bind(("127.0.0.1", 0)).map_err(|e| e.to_string())?;
    sock.set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;
    let payload = util::udp_payload(util::PAYLOAD_SEED ^ 0x33, 7, 64);
    sock.send_to(&payload, (host, port))
        .map_err(|e| e.to_string())?;
    let mut buf = vec![0u8; 2048];
    let (n, _) = sock.recv_from(&mut buf).map_err(|e| e.to_string())?;
    let ok = buf[..n] == payload;
    Ok(Check {
        name: "udp-echo-roundtrip".into(),
        ok,
        detail: format!("received={n}"),
    })
}

fn check_http(host: &str, port: u16) -> Result<Check, String> {
    let mut stream = TcpStream::connect((host, port))
        .map_err(|e| format!("selfcheck http connect {host}:{port}: {e}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;
    stream
        .write_all(b"GET /interop HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .map_err(|e| e.to_string())?;
    let mut buf = [0u8; 512];
    let n = stream.read(&mut buf).map_err(|e| e.to_string())?;
    let text = String::from_utf8_lossy(&buf[..n]);
    Ok(Check {
        name: "http-fallback-404".into(),
        ok: text.starts_with("HTTP/1.1 404"),
        detail: text.lines().next().unwrap_or("").to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unreachable_target_is_an_error() {
        // 端口 9 无监听：必须返回 Err，而不是伪装成功。
        assert!(check_echo("127.0.0.1", 9).is_err());
    }
}
