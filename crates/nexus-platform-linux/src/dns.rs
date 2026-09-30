//! 内置 DNS server 接线（O-DNS）。
//!
//! - 只服务 TUN 网段的查询（静态记录）；不匹配 → REFUSED；
//! - **不碰 `/etc/resolv.conf`** 全局文件；不做上游转发；
//! - `start()` / `stop()`：线程所有权明确（AGENTS.md §13 结构化并发）。

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread::JoinHandle;
use std::time::Duration;

use nexus_platform::PlatformError;

/// DNS 默认端口。
pub const DNS_PORT: u16 = 53;

/// DNS server 配置。
#[derive(Debug, Clone)]
pub struct DnsConfig {
    /// 绑定地址（TUN 地址）。
    pub bind_ip: Ipv4Addr,
    /// 静态记录：小写域名（去尾点）→ IPv4。
    pub records: HashMap<String, Ipv4Addr>,
}

/// 解析 DNS 查询的 QNAME（纯函数）：返回 (qname, qtype)。
/// 失败返回 None（调用方按"非 DNS"处理，不 panic）。
fn parse_query_name(packet: &[u8]) -> Option<(String, u16)> {
    if packet.len() < 12 {
        return None;
    }
    // QDCOUNT 必须为 1。
    if u16::from_be_bytes([packet[4], packet[5]]) != 1 {
        return None;
    }
    let mut pos = 12;
    let mut labels = Vec::new();
    loop {
        if pos >= packet.len() {
            return None;
        }
        let len = packet[pos] as usize;
        // 不支持压缩指针（查询不应有压缩）。
        if len & 0xC0 != 0 {
            return None;
        }
        if len == 0 {
            pos += 1;
            break;
        }
        pos += 1;
        if pos + len > packet.len() || labels.len() > 10 {
            return None;
        }
        let label = std::str::from_utf8(&packet[pos..pos + len]).ok()?;
        labels.push(label.to_lowercase());
        pos += len;
    }
    if pos + 4 > packet.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
    let name = labels.join(".");
    Some((name, qtype))
}

/// 构造 DNS 响应（纯函数）：拷贝 query 的 header+question，附加 answer 或 REFUSED。
fn build_response(query: &[u8], qname: &str, answer_ip: Option<Ipv4Addr>) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    // 找到 question 结束位置（复用解析逻辑定位）。
    let mut pos = 12;
    loop {
        if pos >= query.len() {
            return None;
        }
        let len = query[pos] as usize;
        if len & 0xC0 != 0 || len > 63 {
            return None;
        }
        if len == 0 {
            pos += 1;
            break;
        }
        pos += 1 + len;
        if pos > query.len() {
            return None;
        }
    }
    let qend = pos + 4;
    if qend > query.len() {
        return None;
    }

    let mut resp = Vec::with_capacity(qend + 16);
    // Header：拷贝 ID；flags = QR(0x8000) | RD拷贝 | RA(0x0080)；RCODE 按结果。
    resp.extend_from_slice(&query[0..2]);
    let rd = u16::from_be_bytes([query[2], query[3]]) & 0x0100;
    let flags: u16 = 0x8000 | rd | 0x0080 | if answer_ip.is_some() { 0 } else { 5 };
    resp.extend_from_slice(&flags.to_be_bytes());
    resp.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    resp.extend_from_slice(&(if answer_ip.is_some() { 1u16 } else { 0u16 }).to_be_bytes()); // ANCOUNT
    resp.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    resp.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    // Question 原样拷贝。
    resp.extend_from_slice(&query[12..qend]);
    // Answer（A 记录）：NAME 用压缩指针指向 question（0xC00C），TYPE=A，CLASS=IN，TTL=60，RDLENGTH=4。
    if let Some(ip) = answer_ip {
        resp.extend_from_slice(&[0xC0, 0x0C]);
        resp.extend_from_slice(&1u16.to_be_bytes()); // A
        resp.extend_from_slice(&1u16.to_be_bytes()); // IN
        resp.extend_from_slice(&60u32.to_be_bytes()); // TTL
        resp.extend_from_slice(&4u16.to_be_bytes());
        resp.extend_from_slice(&ip.octets());
    }
    let _ = qname;
    Some(resp)
}

/// 内置 DNS server（UDP）。
///
/// 线程模型：`start()` 产出工作线程 + `stop()` join 回收；
/// `running` 原子标志做协作式停止（AGENTS.md §13）。
pub struct DnsServer {
    config: DnsConfig,
    running: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
    /// 计数器（O6 可观测）。
    pub queries_total: Arc<std::sync::atomic::AtomicU64>,
    pub answers_total: Arc<std::sync::atomic::AtomicU64>,
    pub refused_total: Arc<std::sync::atomic::AtomicU64>,
}

impl DnsServer {
    /// 创建（不启动）。
    pub fn new(config: DnsConfig) -> Self {
        DnsServer {
            config,
            running: Arc::new(AtomicBool::new(false)),
            handle: None,
            queries_total: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            answers_total: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            refused_total: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    /// 启动服务线程（幂等：已启动则直接返回）。
    pub fn start(&mut self) -> Result<(), PlatformError> {
        if self.handle.is_some() {
            return Ok(());
        }
        let addr = SocketAddr::from((self.config.bind_ip, DNS_PORT));
        let socket = UdpSocket::bind(addr).map_err(|e| PlatformError::Io {
            operation: format!("dns bind {addr}"),
            message: e.to_string(),
        })?;
        socket
            .set_read_timeout(Some(Duration::from_millis(200)))
            .map_err(|e| PlatformError::Io {
                operation: "dns set_read_timeout".into(),
                message: e.to_string(),
            })?;

        self.running.store(true, Ordering::SeqCst);
        let running = Arc::clone(&self.running);
        let records = self.config.records.clone();
        let queries = Arc::clone(&self.queries_total);
        let answers = Arc::clone(&self.answers_total);
        let refused = Arc::clone(&self.refused_total);

        let handle = std::thread::Builder::new()
            .name("nexus-dns-server".into())
            .spawn(move || {
                let mut buf = [0u8; 512];
                while running.load(Ordering::SeqCst) {
                    let (n, src) = match socket.recv_from(&mut buf) {
                        Ok(x) => x,
                        Err(e)
                            if e.kind() == std::io::ErrorKind::TimedOut
                                || e.kind() == std::io::ErrorKind::WouldBlock =>
                        {
                            continue;
                        }
                        Err(_) => continue,
                    };
                    queries.fetch_add(1, Ordering::Relaxed);
                    let packet = &buf[..n];
                    let (qname, qtype) = match parse_query_name(packet) {
                        Some(x) => x,
                        None => continue, // 非法查询直接丢弃，不响应
                    };
                    // 只服务 A 查询且命中静态记录；其余 REFUSED。
                    let answer = if qtype == 1 {
                        records.get(&qname).copied()
                    } else {
                        None
                    };
                    if let Some(resp) = build_response(packet, &qname, answer) {
                        let _ = socket.send_to(&resp, src);
                        if answer.is_some() {
                            answers.fetch_add(1, Ordering::Relaxed);
                        } else {
                            refused.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            })
            .map_err(|e| PlatformError::Io {
                operation: "dns spawn thread".into(),
                message: e.to_string(),
            })?;
        self.handle = Some(handle);
        Ok(())
    }

    /// 停止并 join 回收工作线程（幂等）。
    pub fn stop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }

    /// 是否在运行。
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.handle.is_some()
    }
}

impl Drop for DnsServer {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造一个最小 DNS A 查询（example.com）。
    fn sample_query() -> Vec<u8> {
        let mut q = vec![
            0x12, 0x34, // ID
            0x01, 0x00, // flags: RD
            0x00, 0x01, // QDCOUNT=1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        for label in ["example", "com"] {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&1u16.to_be_bytes()); // QTYPE=A
        q.extend_from_slice(&1u16.to_be_bytes()); // QCLASS=IN
        q
    }

    #[test]
    fn parse_query_extracts_name_and_type() {
        let q = sample_query();
        let (name, qtype) = parse_query_name(&q).unwrap();
        assert_eq!(name, "example.com");
        assert_eq!(qtype, 1);
    }

    #[test]
    fn parse_query_rejects_truncated() {
        assert!(parse_query_name(&[1, 2, 3]).is_none());
        assert!(parse_query_name(&sample_query()[..20]).is_none());
    }

    #[test]
    fn build_response_hit_has_answer() {
        let q = sample_query();
        let resp = build_response(&q, "example.com", Some(Ipv4Addr::new(10, 99, 0, 5))).unwrap();
        // ANCOUNT=1, RCODE=0
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 1);
        assert_eq!(resp[3] & 0x0F, 0);
        // 答案 IP 在尾部
        assert_eq!(&resp[resp.len() - 4..], &[10, 99, 0, 5]);
        // ID 回显
        assert_eq!(&resp[0..2], &[0x12, 0x34]);
    }

    #[test]
    fn build_response_miss_is_refused() {
        let q = sample_query();
        let resp = build_response(&q, "example.com", None).unwrap();
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 0);
        assert_eq!(resp[3] & 0x0F, 5); // REFUSED
    }

    #[test]
    fn server_start_stop_is_idempotent() {
        let mut server = DnsServer::new(DnsConfig {
            bind_ip: Ipv4Addr::LOCALHOST,
            records: HashMap::new(),
        });
        // 沙箱可能无权限绑 53？localhost:53 通常可绑（>1024 才需特权，53 需 root）。
        // 若失败则跳过（环境相关，非逻辑错误）。
        if server.start().is_err() {
            return;
        }
        assert!(server.is_running());
        server.start().expect("second start is idempotent");
        server.stop();
        assert!(!server.is_running());
        server.stop(); // 幂等
    }
}
