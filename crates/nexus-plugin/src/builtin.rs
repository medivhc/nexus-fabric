//! 内置插件：`plain`（直通，默认）/ `xor`（演示混淆）。
//!
//! `register_all` 供二进制在启动时显式调用（S3）。

use crate::{
    ObfsParams, ObfuscateTransport, ObfuscatedStream, PluginRegistry, OBFUSCATE_API_VERSION,
};
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// plain：零开销直通
// ---------------------------------------------------------------------------

/// `plain` 插件：直接透传，无变换（默认插件）。
pub struct PlainTransport;

struct PlainStream(TcpStream);

impl Read for PlainStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl Write for PlainStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl ObfuscatedStream for PlainStream {}

impl ObfuscateTransport for PlainTransport {
    fn name(&self) -> &'static str {
        "plain"
    }

    fn api_version(&self) -> u32 {
        OBFUSCATE_API_VERSION
    }

    fn wrap(
        &self,
        stream: TcpStream,
        _params: &ObfsParams,
    ) -> io::Result<Box<dyn ObfuscatedStream>> {
        Ok(Box::new(PlainStream(stream)))
    }
}

// ---------------------------------------------------------------------------
// xor：演示混淆（key 来自 params）
// ---------------------------------------------------------------------------

/// `xor` 插件：按 `key[(pos+i) % key.len()]` 异或，读写位置独立计数。
pub struct XorTransport;

pub struct XorStream {
    inner: TcpStream,
    key: Vec<u8>,
    rpos: u64,
    wpos: u64,
}

impl XorStream {
    /// 对 `buf` 做原地异或，起始流位置为 `pos`。
    fn xor_in_place(&self, pos: u64, buf: &mut [u8]) {
        let klen = self.key.len() as u64;
        for (i, b) in buf.iter_mut().enumerate() {
            let ki = ((pos + i as u64) % klen) as usize;
            *b ^= self.key[ki];
        }
    }
}

impl Read for XorStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.xor_in_place(self.rpos, &mut buf[..n]);
        self.rpos += n as u64;
        Ok(n)
    }
}

impl Write for XorStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // `buf` 不可变：经栈上 4KiB 块中转做变换（无堆分配）。
        // 语义：要么全部写出，要么返回 Err（阻塞流包装器的常规做法）。
        let mut tmp = [0u8; 4096];
        let mut done = 0;
        while done < buf.len() {
            let end = (done + tmp.len()).min(buf.len());
            let chunk_len = end - done;
            tmp[..chunk_len].copy_from_slice(&buf[done..end]);
            self.xor_in_place(self.wpos + done as u64, &mut tmp[..chunk_len]);
            self.inner.write_all(&tmp[..chunk_len])?;
            done = end;
        }
        self.wpos += done as u64;
        Ok(done)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl ObfuscatedStream for XorStream {}

impl ObfuscateTransport for XorTransport {
    fn name(&self) -> &'static str {
        "xor"
    }

    fn api_version(&self) -> u32 {
        OBFUSCATE_API_VERSION
    }

    fn wrap(
        &self,
        stream: TcpStream,
        params: &ObfsParams,
    ) -> io::Result<Box<dyn ObfuscatedStream>> {
        // S4：空 key 是调用方错误，显式失败，不自动回退到 plain。
        if params.key.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "xor obfuscator requires a non-empty key",
            ));
        }
        Ok(Box::new(XorStream {
            inner: stream,
            key: params.key.to_vec(),
            rpos: 0,
            wpos: 0,
        }))
    }
}

// ---------------------------------------------------------------------------
// 静态注册入口（S3）
// ---------------------------------------------------------------------------

/// 注册全部内置插件（`plain` + `xor`）。
///
/// 在全新注册表上调用恒成功；内置插件的 `api_version` 与
/// `OBFUSCATE_API_VERSION` 一致（自己不能违反 S2）。
/// 重复调用会 panic（注册两次是编程错误，fail-fast）。
pub fn register_all(registry: &mut PluginRegistry) {
    registry
        .register(Arc::new(PlainTransport))
        .expect("builtin 'plain' registration must succeed");
    registry
        .register(Arc::new(XorTransport))
        .expect("builtin 'xor' registration must succeed");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ObfsParams, PluginRegistry};
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};

    /// 建立一条 loopback TCP 对，返回 (client, server) 两端。
    fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).unwrap();
        let (server, _) = listener.accept().unwrap();
        (client, server)
    }

    #[test]
    fn names_lists_registered() {
        let mut reg = PluginRegistry::new();
        register_all(&mut reg);
        assert_eq!(reg.names(), vec!["plain", "xor"]);
    }

    #[test]
    fn wrap_plain_passthrough() {
        let mut reg = PluginRegistry::new();
        register_all(&mut reg);
        let plain = reg.get("plain").unwrap();
        let (client, mut server) = tcp_pair();
        let params = ObfsParams { key: b"" };
        let mut wrapped = plain.wrap(client, &params).unwrap();
        wrapped.write_all(b"hello-plain").unwrap();
        wrapped.flush().unwrap();
        let mut buf = [0u8; 11];
        server.read_exact(&mut buf).unwrap();
        // plain 零变换：线字节 == 明文（S4 直通语义）。
        assert_eq!(&buf, b"hello-plain");
    }

    #[test]
    fn xor_roundtrip() {
        let mut reg = PluginRegistry::new();
        register_all(&mut reg);
        let xor = reg.get("xor").unwrap();
        let key = b"test-key-123";
        let (client, server) = tcp_pair();
        let mut c = xor.wrap(client, &ObfsParams { key }).unwrap();
        let mut s = xor.wrap(server, &ObfsParams { key }).unwrap();

        // client → server。
        let msg = b"the quick brown fox jumps over the lazy dog";
        c.write_all(msg).unwrap();
        c.flush().unwrap();
        let mut buf = vec![0u8; msg.len()];
        s.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, msg);

        // server → client（读写位置独立计数，双向正确）。
        s.write_all(msg).unwrap();
        s.flush().unwrap();
        let mut back = vec![0u8; msg.len()];
        c.read_exact(&mut back).unwrap();
        assert_eq!(&back, msg);
    }

    #[test]
    fn xor_empty_key_rejected() {
        let mut reg = PluginRegistry::new();
        register_all(&mut reg);
        let xor = reg.get("xor").unwrap();
        let (client, _server) = tcp_pair();
        // 空 key → wrap 失败，不自动回退（S4）。
        let err = xor.wrap(client, &ObfsParams { key: b"" }).err().unwrap();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn xor_wire_bytes_differ_from_plaintext() {
        // 线字节确实被混淆（E4 断言的单元级版本）。
        let mut reg = PluginRegistry::new();
        register_all(&mut reg);
        let xor = reg.get("xor").unwrap();
        let key = b"wire-test-key";
        let (client, mut server) = tcp_pair();
        let mut c = xor.wrap(client, &ObfsParams { key }).unwrap();
        let msg = b"AAAAAAAAAAAAAAAA"; // 16 字节相同明文
        c.write_all(msg).unwrap();
        c.flush().unwrap();
        let mut wire = vec![0u8; msg.len()];
        server.read_exact(&mut wire).unwrap();
        assert_ne!(&wire, msg);
        // 且不是全零/全同：异或 key 产生了变化。
        assert!(wire.windows(2).any(|w| w[0] != w[1]) || wire[0] != msg[0]);
    }
}
