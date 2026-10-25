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
#[cfg(test)]
mod tests {
    use super::*;

    /// 用 loopback 对端记录写入字节（不依赖真实代理）。
    fn pair() -> (TcpStream, TcpStream) {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let addr = listener.local_addr().expect("addr");
        let client = TcpStream::connect(addr).expect("connect");
        let (server, _) = listener.accept().expect("accept");
        (client, server)
    }

    fn read_all(stream: &mut TcpStream, expect: usize) -> Vec<u8> {
        stream
            .set_read_timeout(Some(std::time::Duration::from_millis(500)))
            .expect("timeout");
        let mut out = vec![0u8; expect];
        let mut got = 0;
        while got < expect {
            match stream.read(&mut out[got..]) {
                Ok(0) => break,
                Ok(n) => got += n,
                Err(_) => break,
            }
        }
        out.truncate(got);
        out
    }

    #[test]
    fn socks5_success_bytes_are_the_established_reply() {
        let (mut client, mut peer) = pair();
        let success = vec![0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        let mut reply = DeferredConnectReply::new(ClientReplyKind::Socks5, success.clone());
        assert!(!reply.is_sent());
        reply.send_success(&mut client).expect("write success");
        assert!(reply.is_sent());
        assert!(reply.deferred_ms().is_some());
        assert_eq!(read_all(&mut peer, success.len()), success);
    }

    #[test]
    fn http_success_bytes_are_connection_established() {
        let (mut client, mut peer) = pair();
        let success = b"HTTP/1.1 200 Connection Established\r\n\r\n".to_vec();
        let mut reply = DeferredConnectReply::new(ClientReplyKind::Http, success.clone());
        reply.send_success(&mut client).expect("write success");
        assert_eq!(read_all(&mut peer, success.len()), success);
    }

    #[test]
    fn empty_success_bytes_write_nothing() {
        let (mut client, mut peer) = pair();
        let mut reply = DeferredConnectReply::new(ClientReplyKind::Http, Vec::new());
        reply.send_success(&mut client).expect("no bytes");
        assert!(reply.is_sent(), "空应答也算已写（不再等待）");
        assert!(read_all(&mut peer, 1).is_empty());
    }

    #[test]
    fn socks5_failure_bytes_are_fixed_shape() {
        let (mut client, mut peer) = pair();
        let mut reply = DeferredConnectReply::new(ClientReplyKind::Socks5, vec![0x05, 0x00]);
        reply
            .send_failure(&mut client, 0x01)
            .expect("write failure");
        assert_eq!(
            read_all(&mut peer, 10),
            vec![0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn sock50_failure_uses_refused_rep() {
        let (mut client, mut peer) = pair();
        let mut reply = DeferredConnectReply::new(ClientReplyKind::Socks5, vec![0x05, 0x00]);
        reply
            .send_failure(&mut client, 0x05)
            .expect("write failure");
        assert_eq!(read_all(&mut peer, 10)[1], 0x05);
    }

    #[test]
    fn http_failure_is_502() {
        let (mut client, mut peer) = pair();
        let mut reply = DeferredConnectReply::new(ClientReplyKind::Http, vec![b'2']);
        reply
            .send_failure(&mut client, 0x01)
            .expect("write failure");
        assert_eq!(
            read_all(&mut peer, 40),
            b"HTTP/1.1 502 Bad Gateway\r\n\r\n".to_vec()
        );
    }

    #[test]
    fn failure_and_success_are_mutually_exclusive_single_write() {
        let (mut client, mut peer) = pair();
        let mut reply = DeferredConnectReply::new(ClientReplyKind::Socks5, vec![0x05, 0x00]);
        reply.send_failure(&mut client, 0x01).expect("first write");
        reply.send_failure(&mut client, 0x01).expect("no-op");
        reply.send_success(&mut client).expect("no-op");
        let got = read_all(&mut peer, 32);
        assert_eq!(got.len(), 10, "只允许写出一次");
        assert_eq!(got[1], 0x01);
    }

    #[test]
    fn bounded_drain_stops_at_eof() {
        let data = vec![7u8; 1024];
        let mut cursor = std::io::Cursor::new(data);
        let (total, eof) = bounded_drain(&mut cursor, 65_536, 50);
        assert_eq!(total, 1024);
        assert!(eof);
    }

    #[test]
    fn bounded_drain_stops_at_byte_cap() {
        let data = vec![7u8; 10_000];
        let mut cursor = std::io::Cursor::new(data);
        let (total, _) = bounded_drain(&mut cursor, 4096, 50);
        assert_eq!(total, 4096, "上限是精确字节数，不得超读");
    }
}
