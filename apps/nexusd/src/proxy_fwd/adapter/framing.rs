//! 增量帧读取工具（spec §2.1；步骤 2 的 VLESS / AnyTLS 消费）。
//!
//! 关键约束：**禁止在超时上做 `read_exact`**。中继读超时是 100ms，`read_exact`
//! 会在超时时丢弃已读字节并截断响应。本工具把已读字节保存在内部缓冲里，
//! 超时（`WouldBlock` / `TimedOut`）原样返回给调用方，缓冲不丢。
//!
//! 步骤 1 只落工具（生产消费在步骤 2），因此整体 `allow(dead_code)`。

use std::io::{self, Read};

/// 带内部缓冲的增量读取器。
#[allow(dead_code)]
pub(super) struct BufferedReader<R> {
    inner: R,
    buf: Vec<u8>,
    /// 已消费前缀（避免每次读取都移动剩余字节）。
    start: usize,
}

/// 从字节流前缀切出全部完整的 `u16 BE 长度 + 数据` 数据报（VLESS UDP / AnyTLS UoT 共用）；
/// 返回数据报与消耗的字节数，残缺的尾部留给下一次。
pub(super) fn split_u16_datagrams(bytes: &[u8]) -> (Vec<Vec<u8>>, usize) {
    let mut datagrams = Vec::new();
    let mut used = 0;
    while let Some(header) = bytes.get(used..used + 2) {
        let len = usize::from(u16::from_be_bytes([header[0], header[1]]));
        let Some(body) = bytes.get(used + 2..used + 2 + len) else {
            break;
        };
        datagrams.push(body.to_vec());
        used += 2 + len;
    }
    (datagrams, used)
}

#[allow(dead_code)]
impl<R: Read> BufferedReader<R> {
    pub(super) fn new(inner: R) -> Self {
        Self {
            inner,
            buf: Vec::new(),
            start: 0,
        }
    }

    /// 当前已缓冲、尚未消费的字节。
    pub(super) fn buffered(&self) -> &[u8] {
        &self.buf[self.start..]
    }

    /// 消费前 `n` 字节（调用方须保证 `n <= buffered().len()`）。
    pub(super) fn consume(&mut self, n: usize) {
        debug_assert!(n <= self.buffered().len());
        self.start = (self.start + n).min(self.buf.len());
        if self.start == self.buf.len() {
            self.buf.clear();
            self.start = 0;
        } else if self.start >= 4096 && self.start * 2 >= self.buf.len() {
            self.buf.drain(..self.start);
            self.start = 0;
        }
    }

    /// 至少再读一次底层流；返回本次读到的字节数（0 = EOF）。
    ///
    /// 超时/`WouldBlock` 以 `Err` 返回，**已缓冲字节保留**。
    pub(super) fn fill(&mut self) -> io::Result<usize> {
        let mut chunk = [0u8; 4096];
        loop {
            match self.inner.read(&mut chunk) {
                Ok(read) => {
                    self.compact();
                    self.buf.extend_from_slice(&chunk[..read]);
                    return Ok(read);
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
    }

    /// 读取直到缓冲中至少 `n` 字节；返回是否满足（`false` = EOF）。
    ///
    /// 不丢弃已有缓冲；底层超时/`WouldBlock` 原样返回。
    pub(super) fn fill_at_least(&mut self, n: usize) -> io::Result<bool> {
        while self.buffered().len() < n {
            if self.fill()? == 0 {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// 底层读取器的可变引用（写方向 / 超时设置；不触碰读缓冲）。
    pub(super) fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }

    /// 取回底层读取器（丢弃未消费缓冲）。
    pub(super) fn into_inner(self) -> R {
        self.inner
    }

    fn compact(&mut self) {
        if self.start > 0 {
            self.buf.drain(..self.start);
            self.start = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 每次 `read` 最多返回 2 字节，用于验证增量缓冲不丢数据。
    struct ChunkedReader {
        data: &'static [u8],
        pos: usize,
        max: usize,
    }

    impl Read for ChunkedReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.pos >= self.data.len() {
                return Ok(0);
            }
            let n = (self.data.len() - self.pos).min(buf.len()).min(self.max);
            buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
            self.pos += n;
            Ok(n)
        }
    }

    fn chunked(data: &'static [u8]) -> BufferedReader<ChunkedReader> {
        BufferedReader::new(ChunkedReader {
            data,
            pos: 0,
            max: 2,
        })
    }

    #[test]
    fn fill_at_least_keeps_partial_data_across_short_reads() {
        let mut reader = chunked(b"abcdef");
        assert!(reader.fill_at_least(4).expect("fill"));
        assert_eq!(reader.buffered(), b"abcd");
        reader.consume(2);
        assert_eq!(reader.buffered(), b"cd");
        assert!(reader.fill_at_least(4).expect("fill"));
        assert_eq!(reader.buffered(), b"cdef");
    }

    #[test]
    fn eof_reports_false_without_dropping_buffered_bytes() {
        let mut reader = chunked(b"ab");
        assert!(!reader.fill_at_least(3).expect("eof"));
        assert_eq!(reader.buffered(), b"ab");
    }

    #[test]
    fn consume_all_resets_buffer() {
        let mut reader = chunked(b"xyz");
        assert!(reader.fill_at_least(3).expect("fill"));
        reader.consume(3);
        assert!(reader.buffered().is_empty());
    }

    #[test]
    fn split_u16_datagrams_keeps_partial_tail() {
        let bytes = [0, 2, b'a', b'b', 0, 0, 0, 3, b'x'];
        let (datagrams, used) = split_u16_datagrams(&bytes);
        assert_eq!(datagrams, vec![b"ab".to_vec(), Vec::new()]);
        assert_eq!(used, 6);
        assert_eq!(split_u16_datagrams(&[0]), (Vec::new(), 0));
        assert_eq!(split_u16_datagrams(&[]), (Vec::new(), 0));
    }
}
