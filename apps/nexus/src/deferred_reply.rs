//! CONNECT 应答暂存（fail-closed 的前置机制）。
//!
//! 现状（修复前）在入站握手循环里就把 `Established` 步的 success 应答写给客户端，
//! 之后才去建出站连接；对 Trojan 这类「无握手确认信号」的协议，这意味着客户端会先
//! 拿到「隧道已建立」，再看服务端到底是不是真的接受了凭据。
//!
//! 本模块把 `Established` 步的应答从握手循环里「暂存」出来，由调用方在既有逻辑点
//! （非 trojan arm）或出站就绪点（trojan arm）写出：
//!
//! - 非 trojan arm：route 之后、出站建连之前立即写出（时机与字节与修复前一致）；
//! - trojan arm：TLS 握手 + Trojan 头 + seed 写完后再决定写 success 还是失败应答。
//!
//! 字节形状（失败应答）见 spec §5.5 / §7.3：SOCKS5 固定 10B（`ATYP=0x01`、BND 全零），
//! HTTP CONNECT 固定 `502 Bad Gateway`。

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Instant;

/// 入站握手类型（决定暂存应答与失败应答的字节形状）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClientReplyKind {
    /// SOCKS5 CONNECT：success 10B，失败 10B（REP 由调用方给）。
    Socks5,
    /// HTTP 代理：CONNECT 为 `200 Connection Established`，失败固定 502。
    Http,
}

/// 暂存的 CONNECT 应答。
///
/// `success_bytes` 为空是合法形态：HTTP 绝对形式转发（non-CONNECT）不写本地应答
/// （§11 / R-6，保持既有行为），`send_success` 因此不写任何字节。
pub(crate) struct DeferredConnectReply {
    kind: ClientReplyKind,
    success_bytes: Vec<u8>,
    sent: bool,
    created_at: Instant,
    deferred_ms: Option<u64>,
}

impl DeferredConnectReply {
    pub(crate) fn new(kind: ClientReplyKind, success_bytes: Vec<u8>) -> Self {
        Self {
            kind,
            success_bytes,
            sent: false,
            created_at: Instant::now(),
            deferred_ms: None,
        }
    }

    /// 写出（或按空字节跳过）成功应答。重复调用不重复写。
    pub(crate) fn send_success(&mut self, client: &mut TcpStream) -> std::io::Result<()> {
        if self.sent {
            return Ok(());
        }
        if !self.success_bytes.is_empty() {
            client.write_all(&self.success_bytes)?;
        }
        self.mark_sent();
        Ok(())
    }

    /// 写出失败应答：SOCKS5 = `05 <rep> 00 01 00000000 0000`；HTTP = 固定 502。
    ///
    /// 失败应答本身不计入隧道字节（AC-1.2）；重复调用不重复写。
    #[allow(dead_code)] // 步骤 1 只定义/测试；产品失败路径在步骤 2 接入。
    pub(crate) fn send_failure(&mut self, client: &mut TcpStream, rep: u8) -> std::io::Result<()> {
        if self.sent {
            return Ok(());
        }
        let bytes: [u8; 10] = match self.kind {
            ClientReplyKind::Socks5 => [0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0],
            ClientReplyKind::Http => {
                client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")?;
                self.mark_sent();
                return Ok(());
            }
        };
        client.write_all(&bytes)?;
        self.mark_sent();
        Ok(())
    }

    pub(crate) fn is_sent(&self) -> bool {
        self.sent
    }

    /// 本地 CONNECT 应答从暂存到写出之间的毫秒数（未写出时为 `None`）。
    pub(crate) fn deferred_ms(&self) -> Option<u64> {
        self.deferred_ms
    }

    /// 该会话是否有「本地成功应答」形态（HTTP 转发型为空 → false）。
    #[allow(dead_code)] // 步骤 1 只定义/测试；产品失败路径在步骤 2 接入。
    pub(crate) fn has_success_reply(&self) -> bool {
        !self.success_bytes.is_empty()
    }

    fn mark_sent(&mut self) {
        self.sent = true;
        self.deferred_ms = Some(self.created_at.elapsed().as_millis() as u64);
    }
}

/// 有界 drain：读掉节点侧数据后丢弃（拒绝路径收尾用）。
///
/// 目的（AC-6）：避免「带未读数据关闭」触发 RST，让节点侧看到的是正常 FIN。
/// 上限 = `max_bytes` 或 `max_ms`，先到者；`WouldBlock` 视为暂时无数据，继续等到
/// 上限或 EOF。任何读错误都按「已关闭」处理（收尾阶段不改变判定结果）。
#[allow(dead_code)] // 步骤 1 只定义/测试；拒绝路径在步骤 2 接入。
pub(crate) fn bounded_drain<R: Read>(node: &mut R, max_bytes: usize, max_ms: u64) -> (usize, bool) {
    let deadline = Instant::now() + std::time::Duration::from_millis(max_ms);
    let mut buf = [0u8; 8192];
    let mut total = 0usize;
    let mut eof = false;
    while total < max_bytes {
        let want = (max_bytes - total).min(buf.len());
        match node.read(&mut buf[..want]) {
            Ok(0) => {
                eof = true;
                break;
            }
            Ok(n) => total += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => {
                if Instant::now() >= deadline {
                    break;
                }
            }
            Err(_) => {
                eof = true;
                break;
            }
        }
        if Instant::now() >= deadline {
            break;
        }
    }
    (total, eof)
}
