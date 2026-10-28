//! 目标端服务（B9）：TcpEcho/TcpSink+Source/UdpEcho/HttpFallback。
//!
//! 端口按 run 冻结值（§18）：26200 echo / 26201 sink+source / 26202 udp / 26203 http。
//! 所有服务在本进程内以线程运行，供「不过协议」的回环自检与协议矩阵共用。

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

use crate::config::{Cell, InteropProbeConfig, TargetKind};
use crate::util;

pub const ECHO_PORT: u16 = 26200;
pub const SINK_PORT: u16 = 26201;
pub const UDP_PORT: u16 = 26202;
pub const HTTP_PORT: u16 = 26203;

const OP_UPLOAD: u8 = 0x55;
const OP_DOWNLOAD: u8 = 0x44;
const HTTP_BODY: &[u8] = b"interop-404-body";

/// 目标端计数（写入 target.json，并进入 notes）。
#[derive(Debug, Default)]
pub struct Stats {
    pub tcp_connections: AtomicU64,
    pub tcp_bytes_up: AtomicU64,
    pub tcp_bytes_down: AtomicU64,
    pub udp_datagrams: AtomicU64,
    pub udp_bytes: AtomicU64,
}

impl Stats {
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "tcp_connections": self.tcp_connections.load(Ordering::Relaxed),
            "tcp_bytes_up": self.tcp_bytes_up.load(Ordering::Relaxed),
            "tcp_bytes_down": self.tcp_bytes_down.load(Ordering::Relaxed),
            "udp_datagrams": self.udp_datagrams.load(Ordering::Relaxed),
            "udp_bytes": self.udp_bytes.load(Ordering::Relaxed),
        })
    }
}

/// 已启动的目标端集合。
#[allow(dead_code)]
pub struct TargetSet {
    pub echo_port: u16,
    pub sink_port: u16,
    pub udp_port: u16,
    pub http_port: u16,
    pub stats: Arc<Stats>,
    handles: Vec<thread::JoinHandle<()>>,
}

impl TargetSet {
    /// 端口对应的服务是否都按冻结值启动。
    pub fn assert_ports(cfg_kind: TargetKind, cfg_port: u16) -> Result<(), String> {
        let expected = match cfg_kind {
            TargetKind::TcpEcho => ECHO_PORT,
            TargetKind::TcpSink | TargetKind::TcpSource => SINK_PORT,
            TargetKind::UdpEcho => UDP_PORT,
            TargetKind::HttpFallback => HTTP_PORT,
        };
        if cfg_port != expected {
            return Err(format!(
                "target.port {cfg_port} != frozen port {expected} for {cfg_kind:?}"
            ));
        }
        Ok(())
    }

    /// 启动四类目标服务（127.0.0.1）。
    ///
    /// echo 目标按 cell 的预期字节数在回显完成后主动关闭，让产品中继能读到 EOF
    /// 并返回 JSON（否则长连接下 proxy 线程会一直等目标侧 EOF）。
    pub fn start(cfg: &InteropProbeConfig) -> Result<Self, String> {
        let stats = Arc::new(Stats::default());
        let mut handles = Vec::new();

        let echo_close_after = match cfg.cell {
            Cell::Handshake | Cell::Reconnect => 1,
            Cell::TcpSmall => cfg.workload.small_bytes,
            Cell::TcpThroughput => cfg.workload.throughput_bytes,
            Cell::LongLived => cfg.workload.long_lived_heartbeats as usize,
            Cell::BadCredential | Cell::BadConfig => 16,
            Cell::UdpEcho | Cell::UdpEchoCrate | Cell::QpackDiag | Cell::PaddingDiag => 16,
        };
        let sink_close_after = if cfg.cell == Cell::TcpThroughput {
            2 + 2 * cfg.workload.throughput_repeats as usize
        } else {
            2
        };
        let echo = TcpListener::bind(("127.0.0.1", ECHO_PORT))
            .map_err(|e| format!("bind echo {ECHO_PORT}: {e}"))?;
        let st = Arc::clone(&stats);
        handles.push(thread::spawn(move || {
            for stream in echo.incoming() {
                let Ok(stream) = stream else { continue };
                let st = Arc::clone(&st);
                thread::spawn(move || echo_conn(stream, &st, echo_close_after));
            }
        }));

        let sink = TcpListener::bind(("127.0.0.1", SINK_PORT))
            .map_err(|e| format!("bind sink {SINK_PORT}: {e}"))?;
        let st = Arc::clone(&stats);
        handles.push(thread::spawn(move || {
            for stream in sink.incoming() {
                let Ok(stream) = stream else { continue };
                let st = Arc::clone(&st);
                thread::spawn(move || sink_conn(stream, &st, sink_close_after));
            }
        }));

        let udp = UdpSocket::bind(("127.0.0.1", UDP_PORT))
            .map_err(|e| format!("bind udp {UDP_PORT}: {e}"))?;
        let st = Arc::clone(&stats);
        handles.push(thread::spawn(move || {
            let mut buf = vec![0u8; 65535];
            while let Ok((n, peer)) = udp.recv_from(&mut buf) {
                st.udp_datagrams.fetch_add(1, Ordering::Relaxed);
                st.udp_bytes.fetch_add(n as u64, Ordering::Relaxed);
                let _ = udp.send_to(&buf[..n], peer);
            }
        }));

        let http = TcpListener::bind(("127.0.0.1", HTTP_PORT))
            .map_err(|e| format!("bind http {HTTP_PORT}: {e}"))?;
        let st = Arc::clone(&stats);
        handles.push(thread::spawn(move || {
            for stream in http.incoming() {
                let Ok(mut stream) = stream else { continue };
                st.tcp_connections.fetch_add(1, Ordering::Relaxed);
                thread::spawn(move || {
                    let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
                    let mut buf = [0u8; 1024];
                    let _ = stream.read(&mut buf);
                    let mut resp = format!(
                        "HTTP/1.1 404 Not Found\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        HTTP_BODY.len()
                    )
                    .into_bytes();
                    resp.extend_from_slice(HTTP_BODY);
                    let _ = stream.write_all(&resp);
                    let _ = stream.flush();
                });
            }
        }));

        Ok(Self {
            echo_port: ECHO_PORT,
            sink_port: SINK_PORT,
            udp_port: UDP_PORT,
            http_port: HTTP_PORT,
            stats,
            handles,
        })
    }

    /// 目标端在进程退出前保持运行；显式 drop 只丢弃句柄（线程随进程结束）。
    pub fn handles_len(&self) -> usize {
        self.handles.len()
    }
}

fn echo_conn(mut stream: TcpStream, stats: &Stats, close_after: usize) {
    stats.tcp_connections.fetch_add(1, Ordering::Relaxed);
    let mut buf = vec![0u8; 64 * 1024];
    let mut total = 0usize;
    loop {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                stats.tcp_bytes_up.fetch_add(n as u64, Ordering::Relaxed);
                if stream.write_all(&buf[..n]).is_err() {
                    break;
                }
                stats.tcp_bytes_down.fetch_add(n as u64, Ordering::Relaxed);
                total += n;
                if total >= close_after {
                    graceful_close(&mut stream);
                    break;
                }
            }
        }
    }
}

/// 优雅收尾：先发 FIN 让已写数据全部送达，再等对端关闭（最多 2s）。
///
/// 直接 `shutdown(Both)` 会在尾部数据仍在途时发 RST，导致客户端在 32 MiB
/// 级下载的最后几 MB 看到 EOF（T2 证据被工具自身截断）。
fn graceful_close(stream: &mut TcpStream) {
    let _ = stream.shutdown(std::net::Shutdown::Write);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let mut sink = [0u8; 1024];
    loop {
        match stream.read(&mut sink) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
    }
}

fn sink_conn(mut stream: TcpStream, stats: &Stats, close_after: usize) {
    stats.tcp_connections.fetch_add(1, Ordering::Relaxed);
    let mut ops = 0usize;
    loop {
        if ops >= close_after {
            graceful_close(&mut stream);
            break;
        }
        let mut op = [0u8; 1];
        if stream.read_exact(&mut op).is_err() {
            break;
        }
        let mut len_buf = [0u8; 8];
        if stream.read_exact(&mut len_buf).is_err() {
            break;
        }
        let len = u64::from_be_bytes(len_buf);
        let Ok(len) = usize::try_from(len) else { break };
        ops += 1;
        eprintln!("[target-sink] op#{ops} kind={:#04x} len={len}", op[0]);
        match op[0] {
            OP_UPLOAD => {
                let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
                let mut remaining = len;
                let mut buf = vec![0u8; 64 * 1024];
                while remaining > 0 {
                    let want = remaining.min(buf.len());
                    match stream.read_exact(&mut buf[..want]) {
                        Ok(()) => {
                            ctx.update(&buf[..want]);
                            stats.tcp_bytes_up.fetch_add(want as u64, Ordering::Relaxed);
                            remaining -= want;
                        }
                        Err(_) => return,
                    }
                }
                let digest = ctx.finish();
                if stream.write_all(digest.as_ref()).is_err() {
                    break;
                }
                stats.tcp_bytes_down.fetch_add(32, Ordering::Relaxed);
            }
            OP_DOWNLOAD => {
                let data = util::source_payload(len);
                if stream.write_all(&data).is_err() {
                    break;
                }
                stats
                    .tcp_bytes_down
                    .fetch_add(len as u64, Ordering::Relaxed);
            }
            _ => break,
        }
    }
}
